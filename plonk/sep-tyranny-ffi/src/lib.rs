//! Mobile-FFI for the SEP-Tyranny contract type.
//!
//! Single-admin per-group governance: only the pinned admin can advance
//! a group's commitment. Both create and update circuits add admin
//! binding (`admin_pubkey_commitment = Poseidon(Poseidon(admin_sk),
//! group_id_fr)`) on top of the shared anarchy membership/update
//! circuits. See `circuit::plonk::tyranny` for the full constraint
//! list and `plonk/FFI-DESIGN.md` for ABI.
//!
//! ## Witness inputs (leaf-hash + admin-secret-key shape)
//!
//! Mobile callers supply:
//!
//!   * `member_leaf_hashes` — packed 32-byte BE Fr scalars
//!     (`Poseidon(member_sk)` per member). Public-ish derived values
//!     that the SDK already maintains. **Only the admin's own secret
//!     key crosses the FFI**, not other members'.
//!   * `admin_secret_key` — the admin's own 32-byte BE Fr scalar.
//!     The FFI sanity-checks `Poseidon(admin_secret_key) ==
//!     member_leaf_hashes[admin_index]` before invoking the prover,
//!     so a mismatch surfaces here as a clear error rather than as
//!     `WrongProof` from in-circuit constraint failure.

use std::ffi::{c_char, CString};
use std::ptr;
use std::slice;

use ark_bls12_381_v05::Fr;
use ark_ff_v05::{BigInteger, PrimeField};
use ark_serialize_v05::CanonicalSerialize;
use jf_relation::PlonkCircuit;
use rand_chacha::rand_core::SeedableRng;

use onym_plonk_prover::circuit::plonk::baker::{
    bake_tyranny_create_vk, bake_tyranny_update_vk,
    pinned_tyranny_create_vk_sha256_hex, pinned_tyranny_update_vk_sha256_hex,
};
use onym_plonk_prover::circuit::plonk::poseidon::{
    poseidon_hash_one_v05, poseidon_hash_two_v05,
};
use onym_plonk_prover::circuit::plonk::proof_format::PROOF_LEN;
use onym_plonk_prover::circuit::plonk::tyranny::{
    synthesize_tyranny_create, synthesize_tyranny_update, TyrannyCreateWitness,
    TyrannyUpdateWitness,
};
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

fn buffer_from_vec(bytes: Vec<u8>) -> OnymByteBuffer {
    // See sep-common-ffi/src/lib.rs for the full rationale: round-trip
    // via Box<[u8]> so the freeing side (sep-common-ffi's
    // onym_byte_buffer_free) doesn't need to guess at capacity. The
    // previous Vec::from_raw_parts(ptr, len, len) shape was UB
    // whenever shrink_to_fit left capacity > len.
    let boxed: Box<[u8]> = bytes.into_boxed_slice();
    let len = boxed.len();
    let ptr = Box::into_raw(boxed) as *mut u8;
    OnymByteBuffer { ptr, len }
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

fn parse_leaf_hashes(packed: &[u8], label: &str) -> Result<Vec<Fr>, String> {
    if packed.len() % FR_BYTES != 0 {
        return Err(format!(
            "{label} length {} is not a multiple of {FR_BYTES}",
            packed.len()
        ));
    }
    Ok(packed
        .chunks_exact(FR_BYTES)
        .map(Fr::from_be_bytes_mod_order)
        .collect())
}

fn check_depth(depth: usize) -> Result<(), String> {
    if depth >= 32 {
        return Err(format!(
            "depth {depth} out of supported range (5/8/11 in production)"
        ));
    }
    Ok(())
}

fn build_tree_from_leaves(leaves: &[Fr], depth: usize) -> (Fr, Vec<Fr>) {
    let num_leaves = 1usize << depth;
    let mut nodes = vec![Fr::from(0u64); 2 * num_leaves];
    for (i, leaf) in leaves.iter().enumerate() {
        nodes[num_leaves + i] = *leaf;
    }
    for i in (1..num_leaves).rev() {
        nodes[i] = poseidon_hash_two_v05(&nodes[2 * i], &nodes[2 * i + 1]);
    }
    (nodes[1], nodes)
}

fn merkle_path(nodes: &[Fr], num_leaves: usize, leaf_index: usize, depth: usize) -> Vec<Fr> {
    let mut path = Vec::with_capacity(depth);
    let mut cur = num_leaves + leaf_index;
    for _ in 0..depth {
        let sib = if cur % 2 == 0 { cur + 1 } else { cur - 1 };
        path.push(nodes[sib]);
        cur /= 2;
    }
    path
}

fn poseidon_commitment(root: &Fr, epoch: u64, salt_bytes: &[u8]) -> Fr {
    let salt_fr = Fr::from_le_bytes_mod_order(salt_bytes);
    let inner = poseidon_hash_two_v05(root, &Fr::from(epoch));
    poseidon_hash_two_v05(&inner, &salt_fr)
}

fn admin_pubkey_commitment(admin_sk: &Fr, group_id_fr: &Fr) -> Fr {
    let admin_pk = poseidon_hash_one_v05(admin_sk);
    poseidon_hash_two_v05(&admin_pk, group_id_fr)
}

fn check_prover_leaf(
    prover_sk: &Fr,
    leaves: &[Fr],
    prover_index: usize,
    label: &str,
) -> Result<(), String> {
    if prover_index >= leaves.len() {
        return Err(format!(
            "admin_index {prover_index} out of range for {} {label}",
            leaves.len()
        ));
    }
    let expected = poseidon_hash_one_v05(prover_sk);
    if expected != leaves[prover_index] {
        return Err(format!(
            "admin_secret_key does not match {label}[{prover_index}]: \
             Poseidon(admin_secret_key) ≠ supplied leaf hash"
        ));
    }
    Ok(())
}

fn pinned_hex_to_buffer(
    hex: Option<&'static str>,
    out_hex: *mut OnymByteBuffer,
    label: &str,
    depth: usize,
) -> Result<(), String> {
    match hex {
        Some(s) => write_buffer(out_hex, s.as_bytes().to_vec()),
        None => Err(format!(
            "no pinned tyranny {label} VK SHA-256 for depth {depth}; supported tiers: 5, 8, 11"
        )),
    }
}

// ---------------------------------------------------------------------------
// Bake VK
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_tyranny_bake_create_vk(
    depth: usize,
    out_vk: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let bytes = bake_tyranny_create_vk(depth)
            .map_err(|e| format!("bake_tyranny_create_vk(depth={depth}): {e:?}"))?;
        write_buffer(out_vk, bytes)
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_tyranny_bake_update_vk(
    depth: usize,
    out_vk: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let bytes = bake_tyranny_update_vk(depth)
            .map_err(|e| format!("bake_tyranny_update_vk(depth={depth}): {e:?}"))?;
        write_buffer(out_vk, bytes)
    })
}

// ---------------------------------------------------------------------------
// Pinned VK SHA-256 hex
// ---------------------------------------------------------------------------

#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_tyranny_pinned_create_vk_sha256_hex(
    depth: usize,
    out_hex: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        pinned_hex_to_buffer(
            pinned_tyranny_create_vk_sha256_hex(depth),
            out_hex,
            "create",
            depth,
        )
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_tyranny_pinned_update_vk_sha256_hex(
    depth: usize,
    out_hex: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        pinned_hex_to_buffer(
            pinned_tyranny_update_vk_sha256_hex(depth),
            out_hex,
            "update",
            depth,
        )
    })
}

// ---------------------------------------------------------------------------
// Prove create
// ---------------------------------------------------------------------------

/// Generate a TurboPlonk tyranny-create proof.
///
/// Inputs:
///   * `member_leaf_hashes` — initial group's leaf hashes (32 BE Fr
///     each, ≤ 2^depth). The admin's own leaf is at `admin_index`.
///   * `admin_secret_key` — admin's own secret key (32 BE Fr).
///   * `admin_index` — admin's leaf position in the roster.
///   * `group_id_fr` — 32 BE Fr; per-group binding scalar
///     contract-derived (typically `Fr::from_be_bytes_mod_order(
///     group_id_bytes)`).
///   * `salt` — 32-byte salt; LE-mod-r in-circuit.
///
/// Outputs:
///   * `out_proof` — 1601-byte proof.
///   * `out_public_inputs` — 128 B = `commitment(32) || Fr(0)(32)
///     || admin_pubkey_commitment(32) || group_id_fr(32)`. Epoch=0
///     at create.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_tyranny_prove_create(
    depth: usize,
    member_leaf_hashes_ptr: *const u8,
    member_leaf_hashes_len: usize,
    admin_secret_key_ptr: *const u8,
    admin_secret_key_len: usize,
    admin_index: usize,
    group_id_fr_ptr: *const u8,
    group_id_fr_len: usize,
    salt_ptr: *const u8,
    salt_len: usize,
    out_proof: *mut OnymByteBuffer,
    out_public_inputs: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        check_depth(depth)?;
        let leaves_packed = read_bytes(
            member_leaf_hashes_ptr,
            member_leaf_hashes_len,
            "member_leaf_hashes",
        )?;
        let leaves = parse_leaf_hashes(leaves_packed, "member_leaf_hashes")?;

        let num_leaves = 1usize << depth;
        if leaves.is_empty() {
            return Err("member_leaf_hashes is empty".to_string());
        }
        if leaves.len() > num_leaves {
            return Err(format!(
                "{} leaf hashes exceed depth-{depth} tree capacity {num_leaves}",
                leaves.len()
            ));
        }

        let admin_sk = fr_from_be(
            read_bytes(admin_secret_key_ptr, admin_secret_key_len, "admin_secret_key")?,
            "admin_secret_key",
        )?;
        check_prover_leaf(&admin_sk, &leaves, admin_index, "member_leaf_hashes")?;

        let group_id_fr = fr_from_be(
            read_bytes(group_id_fr_ptr, group_id_fr_len, "group_id_fr")?,
            "group_id_fr",
        )?;
        let salt_bytes = read_bytes(salt_ptr, salt_len, "salt")?;
        require_len("salt", salt_bytes.len(), SALT_BYTES)?;
        let mut salt: [u8; SALT_BYTES] = [0; SALT_BYTES];
        salt.copy_from_slice(salt_bytes);

        let (member_root, nodes) = build_tree_from_leaves(&leaves, depth);
        let merkle_path_v = merkle_path(&nodes, num_leaves, admin_index, depth);
        let admin_comm = admin_pubkey_commitment(&admin_sk, &group_id_fr);
        // Tyranny create: epoch=0.
        let commitment = poseidon_commitment(&member_root, 0, &salt);

        let witness = TyrannyCreateWitness {
            commitment,
            admin_pubkey_commitment: admin_comm,
            group_id_fr,
            admin_secret_key: admin_sk,
            member_root,
            salt,
            merkle_path: merkle_path_v,
            leaf_index: admin_index,
            depth,
        };

        let mut circuit = PlonkCircuit::<Fr>::new_turbo_plonk();
        synthesize_tyranny_create(&mut circuit, &witness)
            .map_err(|e| format!("synthesize_tyranny_create: {e:?}"))?;
        circuit
            .finalize_for_arithmetization()
            .map_err(|e| format!("finalize_for_arithmetization: {e:?}"))?;

        let keys = plonk::preprocess(&circuit).map_err(|e| format!("preprocess: {e:?}"))?;
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
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

        let public_inputs = vec![commitment, Fr::from(0u64), admin_comm, group_id_fr];
        plonk::verify(&keys.vk, &public_inputs, &proof).map_err(|e| {
            format!("self-verify rejected proof — witness or circuit shape is wrong: {e:?}")
        })?;

        let mut pi_concat = Vec::with_capacity(4 * FR_BYTES);
        for fr in &public_inputs {
            pi_concat.extend_from_slice(&fr_to_be_bytes(fr));
        }

        write_buffer(out_proof, proof_bytes)?;
        write_buffer(out_public_inputs, pi_concat)?;
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Prove update
// ---------------------------------------------------------------------------

/// Generate a TurboPlonk tyranny-update proof.
///
/// Inputs:
///   * `member_leaf_hashes_old` — old-tree leaf hashes (32 BE Fr each).
///     The admin's leaf must be at `admin_index_old`.
///   * `admin_secret_key` — admin's own secret key (32 BE Fr).
///   * `admin_index_old` — admin's leaf position in the old roster.
///   * `epoch_old` — old commitment's epoch (the only epoch PI; new
///     epoch is implicit `epoch_old + 1`, enforced in-circuit).
///   * `member_root_new` — 32 BE Fr; the new tree's root, supplied
///     directly because the admin may not know the full new roster
///     (binding-only, see circuit's "new-tree binding is
///     commitment-only" note).
///   * `group_id_fr` — 32 BE Fr; per-group binding scalar.
///   * `salt_old`, `salt_new` — 32 each, LE-mod-r in-circuit.
///
/// Outputs:
///   * `out_proof` — 1601-byte proof.
///   * `out_public_inputs` — 160 B = `c_old(32) || Fr(epoch_old)(32)
///     || c_new(32) || admin_pubkey_commitment(32) || group_id_fr(32)`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_tyranny_prove_update(
    depth: usize,
    member_leaf_hashes_old_ptr: *const u8,
    member_leaf_hashes_old_len: usize,
    admin_secret_key_ptr: *const u8,
    admin_secret_key_len: usize,
    admin_index_old: usize,
    epoch_old: u64,
    member_root_new_ptr: *const u8,
    member_root_new_len: usize,
    group_id_fr_ptr: *const u8,
    group_id_fr_len: usize,
    salt_old_ptr: *const u8,
    salt_old_len: usize,
    salt_new_ptr: *const u8,
    salt_new_len: usize,
    out_proof: *mut OnymByteBuffer,
    out_public_inputs: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        check_depth(depth)?;
        let leaves_packed = read_bytes(
            member_leaf_hashes_old_ptr,
            member_leaf_hashes_old_len,
            "member_leaf_hashes_old",
        )?;
        let leaves_old = parse_leaf_hashes(leaves_packed, "member_leaf_hashes_old")?;

        let num_leaves = 1usize << depth;
        if leaves_old.is_empty() {
            return Err("member_leaf_hashes_old is empty".to_string());
        }
        if leaves_old.len() > num_leaves {
            return Err(format!(
                "{} leaf hashes exceed depth-{depth} tree capacity {num_leaves}",
                leaves_old.len()
            ));
        }

        let admin_sk = fr_from_be(
            read_bytes(admin_secret_key_ptr, admin_secret_key_len, "admin_secret_key")?,
            "admin_secret_key",
        )?;
        check_prover_leaf(
            &admin_sk,
            &leaves_old,
            admin_index_old,
            "member_leaf_hashes_old",
        )?;

        let group_id_fr = fr_from_be(
            read_bytes(group_id_fr_ptr, group_id_fr_len, "group_id_fr")?,
            "group_id_fr",
        )?;
        let member_root_new = fr_from_be(
            read_bytes(
                member_root_new_ptr,
                member_root_new_len,
                "member_root_new",
            )?,
            "member_root_new",
        )?;

        let salt_old_bytes = read_bytes(salt_old_ptr, salt_old_len, "salt_old")?;
        let salt_new_bytes = read_bytes(salt_new_ptr, salt_new_len, "salt_new")?;
        require_len("salt_old", salt_old_bytes.len(), SALT_BYTES)?;
        require_len("salt_new", salt_new_bytes.len(), SALT_BYTES)?;
        let mut salt_old: [u8; SALT_BYTES] = [0; SALT_BYTES];
        let mut salt_new: [u8; SALT_BYTES] = [0; SALT_BYTES];
        salt_old.copy_from_slice(salt_old_bytes);
        salt_new.copy_from_slice(salt_new_bytes);

        let (member_root_old, nodes_old) = build_tree_from_leaves(&leaves_old, depth);
        let path_old = merkle_path(&nodes_old, num_leaves, admin_index_old, depth);
        let admin_comm = admin_pubkey_commitment(&admin_sk, &group_id_fr);

        let c_old = poseidon_commitment(&member_root_old, epoch_old, &salt_old);
        let c_new = poseidon_commitment(&member_root_new, epoch_old + 1, &salt_new);

        let witness = TyrannyUpdateWitness {
            c_old,
            epoch_old,
            c_new,
            admin_pubkey_commitment: admin_comm,
            group_id_fr,
            admin_secret_key: admin_sk,
            member_root_old,
            member_root_new,
            salt_old,
            salt_new,
            merkle_path_old: path_old,
            leaf_index_old: admin_index_old,
            depth,
        };

        let mut circuit = PlonkCircuit::<Fr>::new_turbo_plonk();
        synthesize_tyranny_update(&mut circuit, &witness)
            .map_err(|e| format!("synthesize_tyranny_update: {e:?}"))?;
        circuit
            .finalize_for_arithmetization()
            .map_err(|e| format!("finalize_for_arithmetization: {e:?}"))?;

        let keys = plonk::preprocess(&circuit).map_err(|e| format!("preprocess: {e:?}"))?;
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();
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

        let public_inputs = vec![
            c_old,
            Fr::from(epoch_old),
            c_new,
            admin_comm,
            group_id_fr,
        ];
        plonk::verify(&keys.vk, &public_inputs, &proof).map_err(|e| {
            format!("self-verify rejected proof — witness or circuit shape is wrong: {e:?}")
        })?;

        let mut pi_concat = Vec::with_capacity(5 * FR_BYTES);
        for fr in &public_inputs {
            pi_concat.extend_from_slice(&fr_to_be_bytes(fr));
        }

        write_buffer(out_proof, proof_bytes)?;
        write_buffer(out_public_inputs, pi_concat)?;
        Ok(())
    })
}
