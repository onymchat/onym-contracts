//! Mobile-FFI for the SEP-OneOnOne contract type.
//!
//! Single-tier (depth=5) two-party "founding" circuit. See
//! `plonk/FFI-DESIGN.md` and per-crate doc on sep-anarchy-ffi for the
//! ABI conventions and helper-inlining rationale.

use std::ffi::{c_char, CString};
use std::mem;
use std::ptr;
use std::slice;

use ark_bls12_381_v05::Fr;
use ark_ff_v05::{BigInteger, PrimeField};
use ark_serialize_v05::CanonicalSerialize;
use jf_relation::PlonkCircuit;
use rand_chacha::rand_core::SeedableRng;

use onym_plonk_prover::circuit::plonk::baker::bake_oneonone_create_vk;
use onym_plonk_prover::circuit::plonk::oneonone_create::{
    synthesize_oneonone_create, OneOnOneCreateWitness, DEPTH,
};
use onym_plonk_prover::circuit::plonk::poseidon::{
    poseidon_hash_one_v05, poseidon_hash_two_v05,
};
use onym_plonk_prover::circuit::plonk::proof_format::PROOF_LEN;
use onym_plonk_prover::prover::plonk;

const FR_BYTES: usize = 32;
const SALT_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// FFI byte-buffer + helpers (inlined per-crate)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct OnymByteBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

fn buffer_from_vec(mut bytes: Vec<u8>) -> OnymByteBuffer {
    bytes.shrink_to_fit();
    let buffer = OnymByteBuffer {
        ptr: bytes.as_mut_ptr(),
        len: bytes.len(),
    };
    mem::forget(bytes);
    buffer
}

fn write_buffer(out: *mut OnymByteBuffer, bytes: Vec<u8>) -> Result<(), String> {
    if out.is_null() {
        return Err("output buffer pointer was null".to_string());
    }
    unsafe {
        *out = buffer_from_vec(bytes);
    }
    Ok(())
}

fn write_error(out_error: *mut *mut c_char, message: &str) {
    if out_error.is_null() {
        return;
    }
    let sanitized = message.replace('\0', " ");
    let c_string =
        CString::new(sanitized).expect("CString::new should succeed after sanitising");
    unsafe {
        *out_error = c_string.into_raw();
    }
}

fn run_ffi<F>(out_error: *mut *mut c_char, f: F) -> bool
where
    F: FnOnce() -> Result<(), String>,
{
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)) {
        Ok(Ok(())) => {
            if !out_error.is_null() {
                unsafe {
                    *out_error = ptr::null_mut();
                }
            }
            true
        }
        Ok(Err(message)) => {
            write_error(out_error, &message);
            false
        }
        Err(_) => {
            write_error(out_error, "Rust panic crossed FFI boundary");
            false
        }
    }
}

fn read_bytes<'a>(ptr: *const u8, len: usize, label: &str) -> Result<&'a [u8], String> {
    if ptr.is_null() {
        return Err(format!("{label} pointer was null"));
    }
    Ok(unsafe { slice::from_raw_parts(ptr, len) })
}

fn require_len(label: &str, actual: usize, expected: usize) -> Result<(), String> {
    if actual == expected {
        Ok(())
    } else {
        Err(format!("{label} must be {expected} bytes, got {actual}"))
    }
}

fn fr_from_be(bytes: &[u8], label: &str) -> Result<Fr, String> {
    require_len(label, bytes.len(), FR_BYTES)?;
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

fn fr_to_be_bytes(fr: &Fr) -> Vec<u8> {
    fr.into_bigint().to_bytes_be()
}

/// Native Poseidon root over the 2-active-leaf depth-5 tree —
/// positions 0 and 1 occupied; positions 2..32 hardwired zero.
fn build_2of_depth5_root(sk_0: &Fr, sk_1: &Fr) -> Fr {
    let leaf_0 = poseidon_hash_one_v05(sk_0);
    let leaf_1 = poseidon_hash_one_v05(sk_1);
    let num_leaves = 1usize << DEPTH;
    let mut nodes = vec![Fr::from(0u64); 2 * num_leaves];
    nodes[num_leaves] = leaf_0;
    nodes[num_leaves + 1] = leaf_1;
    for i in (1..num_leaves).rev() {
        nodes[i] = poseidon_hash_two_v05(&nodes[2 * i], &nodes[2 * i + 1]);
    }
    nodes[1]
}

fn poseidon_create_commitment(root: &Fr, salt_bytes: &[u8]) -> Fr {
    // Epoch is hardwired to 0 at create time.
    let salt_fr = Fr::from_le_bytes_mod_order(salt_bytes);
    let inner = poseidon_hash_two_v05(root, &Fr::from(0u64));
    poseidon_hash_two_v05(&inner, &salt_fr)
}

// ---------------------------------------------------------------------------
// Bake VK
// ---------------------------------------------------------------------------

/// Bake the (single-tier, depth=5) oneonone create VK. Output: 3002 B.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_oneonone_bake_create_vk(
    out_vk: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let bytes = bake_oneonone_create_vk()
            .map_err(|e| format!("bake_oneonone_create_vk: {e:?}"))?;
        write_buffer(out_vk, bytes)
    })
}

// ---------------------------------------------------------------------------
// Prove create
// ---------------------------------------------------------------------------

/// Generate a TurboPlonk oneonone-create proof.
///
/// Inputs:
///   * `secret_key_0`, `secret_key_1` — the two members' BLS12-381
///     scalars (32 BE each).
///   * `salt` — 32 bytes, LE-mod-r in-circuit.
///
/// Outputs:
///   * `out_proof` — 1601-byte uncompressed proof.
///   * `out_commitment` — 32 BE Fr (the public input
///     `Poseidon(Poseidon(root, 0), salt_fr)`). Bit-identical to a
///     membership commitment computed against the same `(root, 0,
///     salt)` triple — so a 1v1 group is membership-verifiable later
///     against the depth-5 anarchy/democracy/oligarchy membership VK.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_oneonone_prove_create(
    secret_key_0_ptr: *const u8,
    secret_key_0_len: usize,
    secret_key_1_ptr: *const u8,
    secret_key_1_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    out_proof: *mut OnymByteBuffer,
    out_commitment: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let sk_0 = fr_from_be(
            read_bytes(secret_key_0_ptr, secret_key_0_len, "secret_key_0")?,
            "secret_key_0",
        )?;
        let sk_1 = fr_from_be(
            read_bytes(secret_key_1_ptr, secret_key_1_len, "secret_key_1")?,
            "secret_key_1",
        )?;
        let salt_bytes = read_bytes(salt_ptr, salt_len, "salt")?;
        require_len("salt", salt_bytes.len(), SALT_BYTES)?;
        let mut salt: [u8; SALT_BYTES] = [0; SALT_BYTES];
        salt.copy_from_slice(salt_bytes);

        let root = build_2of_depth5_root(&sk_0, &sk_1);
        let commitment = poseidon_create_commitment(&root, &salt);

        let witness = OneOnOneCreateWitness {
            commitment,
            secret_key_0: sk_0,
            secret_key_1: sk_1,
            salt,
        };

        let mut circuit = PlonkCircuit::<Fr>::new_turbo_plonk();
        synthesize_oneonone_create(&mut circuit, &witness)
            .map_err(|e| format!("synthesize_oneonone_create: {e:?}"))?;
        circuit
            .finalize_for_arithmetization()
            .map_err(|e| format!("finalize_for_arithmetization: {e:?}"))?;

        let keys = plonk::preprocess(&circuit).map_err(|e| format!("preprocess: {e:?}"))?;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([0u8; 32]);
        let proof =
            plonk::prove(&mut rng, &keys.pk, &circuit).map_err(|e| format!("prove: {e:?}"))?;

        let mut proof_bytes = Vec::with_capacity(PROOF_LEN);
        proof
            .serialize_uncompressed(&mut proof_bytes)
            .map_err(|e| format!("serialise proof: {e:?}"))?;
        if proof_bytes.len() != PROOF_LEN {
            return Err(format!(
                "unexpected proof length {} (expected {PROOF_LEN})",
                proof_bytes.len()
            ));
        }

        // Self-verify: 2 PIs (commitment, Fr::from(0)).
        plonk::verify(&keys.vk, &[commitment, Fr::from(0u64)], &proof).map_err(|e| {
            format!("self-verify rejected proof — witness or circuit shape is wrong: {e:?}")
        })?;

        write_buffer(out_proof, proof_bytes)?;
        write_buffer(out_commitment, fr_to_be_bytes(&commitment))?;
        Ok(())
    })
}
