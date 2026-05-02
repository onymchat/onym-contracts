//! Mobile-FFI for the SEP-Anarchy contract type.
//!
//! Wraps `onym_plonk_prover`'s anarchy entry points (which reuse the
//! shared `synthesize_membership` + `synthesize_update` circuits) for
//! consumption from `onym-sdk-swift` / `onym-sdk-kotlin`.
//!
//! See `plonk/FFI-DESIGN.md` for ABI contract; this crate is a per-type
//! FFI under that design and intentionally inlines the small helper
//! layer (run_ffi, write_buffer, OnymByteBuffer struct) so its cdylib
//! exports only `onym_anarchy_*` symbols. Clients link
//! `sep-common-ffi` for `onym_byte_buffer_free`, `onym_string_free`,
//! and the shared hashing/commitment primitives.
//!
//! ## Witness inputs (leaf-hash + per-prover-secret-key shape)
//!
//! Mobile callers supply:
//!
//!   * `member_leaf_hashes` — packed 32-byte BE Fr scalars, one per
//!     member, ≤ 2^depth entries. These are public-ish derived values
//!     (`Poseidon(member_secret_key)`) that an SDK already maintains
//!     to know the visible member tree state. **No member's secret
//!     key crosses the FFI except the prover's own.**
//!   * `prover_secret_key` — the prover's own 32-byte BE Fr scalar.
//!     The FFI sanity-checks `Poseidon(prover_secret_key) ==
//!     member_leaf_hashes[prover_index]` before invoking the prover,
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
    bake_membership_vk, bake_update_vk, pinned_update_vk_sha256_hex, pinned_vk_sha256_hex,
};
use onym_plonk_prover::circuit::plonk::membership::{synthesize_membership, MembershipWitness};
use onym_plonk_prover::circuit::plonk::poseidon::{
    poseidon_hash_one_v05, poseidon_hash_two_v05,
};
use onym_plonk_prover::circuit::plonk::proof_format::PROOF_LEN;
use onym_plonk_prover::circuit::plonk::update::{synthesize_update, UpdateWitness};
use onym_plonk_prover::prover::plonk;

const FR_BYTES: usize = 32;
const SALT_BYTES: usize = 32;

// ---------------------------------------------------------------------------
// FFI byte-buffer + helpers (inlined per-crate; see module doc-comment)
// ---------------------------------------------------------------------------

/// Caller-owned byte buffer. Free via `onym_byte_buffer_free` from
/// sep-common-ffi.
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

fn fr_to_be_bytes(fr: &Fr) -> Vec<u8> {
    fr.into_bigint().to_bytes_be()
}

fn check_depth(depth: usize) -> Result<(), String> {
    // 32 is the prover-crate's hard ceiling. Real consumers stick to
    // 5/8/11; bigger trees are rejected to surface accidental misuse
    // early.
    if depth >= 32 {
        return Err(format!(
            "depth {depth} out of supported range (5/8/11 in production)"
        ));
    }
    Ok(())
}

/// Build a fully-populated Poseidon Merkle tree from a roster of
/// leaf hashes. Returns (`root`, `node_array_2N_indexed_from_1`).
/// Padding leaves (where the roster is shorter than 2^depth) are
/// `Fr::ZERO`.
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

/// Verify the supplied prover secret key matches the leaf hash at
/// the supplied index. Surfaces a clear error before invoking the
/// prover, instead of waiting for an in-circuit `WrongProof`.
fn check_prover_leaf(
    prover_sk: &Fr,
    leaves: &[Fr],
    prover_index: usize,
    label: &str,
) -> Result<(), String> {
    if prover_index >= leaves.len() {
        return Err(format!(
            "prover_index {prover_index} out of range for {} {label}",
            leaves.len()
        ));
    }
    let expected = poseidon_hash_one_v05(prover_sk);
    if expected != leaves[prover_index] {
        return Err(format!(
            "prover_secret_key does not match {label}[{prover_index}]: \
             Poseidon(prover_secret_key) ≠ supplied leaf hash"
        ));
    }
    Ok(())
}

/// Reject a null output-buffer pointer at the top of a multi-output
/// prove function, BEFORE any allocation. Pairs with the
/// "build-then-publish" pattern in `prove_*` so a `false` return
/// never leaks a partially-written first output.
fn check_output_ptr(ptr: *mut OnymByteBuffer, label: &str) -> Result<(), String> {
    if ptr.is_null() {
        return Err(format!("{label} pointer was null"));
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
            "no pinned {label} VK SHA-256 for depth {depth}; supported tiers: 5, 8, 11"
        )),
    }
}

// ---------------------------------------------------------------------------
// Bake VK
// ---------------------------------------------------------------------------

/// Bake the per-tier membership VK and return the canonical-uncompressed
/// VK bytes (3002 B per `vk_format::VK_LEN`).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_anarchy_bake_membership_vk(
    depth: usize,
    out_vk: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let bytes = bake_membership_vk(depth)
            .map_err(|e| format!("bake_membership_vk(depth={depth}): {e:?}"))?;
        write_buffer(out_vk, bytes)
    })
}

/// Bake the per-tier update VK and return the canonical-uncompressed
/// VK bytes (3002 B).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_anarchy_bake_update_vk(
    depth: usize,
    out_vk: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let bytes = bake_update_vk(depth)
            .map_err(|e| format!("bake_update_vk(depth={depth}): {e:?}"))?;
        write_buffer(out_vk, bytes)
    })
}

// ---------------------------------------------------------------------------
// Pinned VK SHA-256 hex accessors
// ---------------------------------------------------------------------------

/// Return the static SHA-256 hex string the prover crate has pinned for
/// the per-tier membership VK at `depth` (64 ASCII hex chars). Errors
/// out if `depth` is not a supported tier.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_anarchy_pinned_membership_vk_sha256_hex(
    depth: usize,
    out_hex: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        pinned_hex_to_buffer(pinned_vk_sha256_hex(depth), out_hex, "membership", depth)
    })
}

/// Return the static SHA-256 hex string for the per-tier update VK.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_anarchy_pinned_update_vk_sha256_hex(
    depth: usize,
    out_hex: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        pinned_hex_to_buffer(
            pinned_update_vk_sha256_hex(depth),
            out_hex,
            "update",
            depth,
        )
    })
}

// ---------------------------------------------------------------------------
// Prove membership
// ---------------------------------------------------------------------------

/// Generate a TurboPlonk anarchy-membership proof.
///
/// Inputs:
///   * `member_leaf_hashes` — tightly-packed 32-byte BE Fr scalars
///     (`Poseidon(member_sk)` per member, ≤ 2^depth entries).
///   * `prover_secret_key` — the prover's own 32-byte BE Fr scalar.
///   * `prover_index` — the prover's leaf position in the roster.
///   * `epoch` — group epoch (the public input bound by the commitment).
///   * `salt` — 32 bytes, LE-mod-r interpreted in-circuit.
///
/// Outputs:
///   * `out_proof` — 1601-byte uncompressed proof.
///   * `out_commitment` — 32-byte BE Fr (the public input
///     `Poseidon(Poseidon(root, epoch), salt_fr)`).
///
/// Self-verifies the freshly-baked VK before returning so a malformed
/// witness is surfaced here, not after the proof ships to a contract.
///
/// Re-runs `preprocess()` on every call. Caching is a follow-up if
/// mobile profiling flags it as the bottleneck (almost certainly will).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_anarchy_prove_membership(
    depth: usize,
    member_leaf_hashes_ptr: *const u8,
    member_leaf_hashes_len: usize,
    prover_secret_key_ptr: *const u8,
    prover_secret_key_len: usize,
    prover_index: usize,
    epoch: u64,
    salt_ptr: *const u8,
    salt_len: usize,
    out_proof: *mut OnymByteBuffer,
    out_commitment: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        // Pre-validate output pointers BEFORE any allocation happens.
        // The build-then-publish pattern below relies on these checks
        // succeeding so the trailing publish step is infallible — a
        // failed second publish would otherwise leak the first
        // already-published buffer to a caller that ignores outputs
        // on `false`.
        check_output_ptr(out_proof, "out_proof")?;
        check_output_ptr(out_commitment, "out_commitment")?;

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

        let prover_sk = fr_from_be(
            read_bytes(
                prover_secret_key_ptr,
                prover_secret_key_len,
                "prover_secret_key",
            )?,
            "prover_secret_key",
        )?;
        check_prover_leaf(&prover_sk, &leaves, prover_index, "member_leaf_hashes")?;

        let salt_bytes = read_bytes(salt_ptr, salt_len, "salt")?;
        require_len("salt", salt_bytes.len(), SALT_BYTES)?;
        let mut salt: [u8; SALT_BYTES] = [0; SALT_BYTES];
        salt.copy_from_slice(salt_bytes);

        let (root, nodes) = build_tree_from_leaves(&leaves, depth);
        let path = merkle_path(&nodes, num_leaves, prover_index, depth);
        let commitment = poseidon_commitment(&root, epoch, &salt);

        let witness = MembershipWitness {
            commitment,
            epoch,
            secret_key: prover_sk,
            poseidon_root: root,
            salt,
            merkle_path: path,
            leaf_index: prover_index,
            depth,
        };

        let mut circuit = PlonkCircuit::<Fr>::new_turbo_plonk();
        synthesize_membership(&mut circuit, &witness)
            .map_err(|e| format!("synthesize_membership: {e:?}"))?;
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

        // Self-verify against the freshly-baked VK to catch witness /
        // circuit-shape mismatches before the proof ships.
        let public_inputs = vec![commitment, Fr::from(epoch)];
        plonk::verify(&keys.vk, &public_inputs, &proof).map_err(|e| {
            format!("self-verify rejected proof — witness or circuit shape is wrong: {e:?}")
        })?;

        // Atomic publish: both output pointers were validated at the
        // top, so these assignments are infallible (modulo allocator
        // OOM panics in `into_boxed_slice`, which catch_unwind handles).
        let commitment_bytes = fr_to_be_bytes(&commitment);
        unsafe {
            *out_proof = buffer_from_vec(proof_bytes);
            *out_commitment = buffer_from_vec(commitment_bytes);
        }
        Ok(())
    })
}

// ---------------------------------------------------------------------------
// Prove update
// ---------------------------------------------------------------------------

/// Generate a TurboPlonk anarchy-update proof.
///
/// Inputs:
///   * `member_leaf_hashes_old` — old-tree leaf hashes (32 BE Fr each,
///     ≤ 2^depth).
///   * `member_leaf_hashes_new` — new-tree leaf hashes. Pass {NULL, 0}
///     to reuse the old-tree leaves (no roster change). The circuit
///     doesn't constrain new-tree membership (see
///     `circuit::plonk::update`'s "new-tree binding is commitment-only"
///     note); only the new root binds.
///   * `prover_secret_key` — prover's own secret key (32 BE Fr).
///   * `prover_index_old` — prover's slot in the old roster.
///   * `epoch_old` — the public-input epoch bound by the old commitment.
///   * `salt_old`, `salt_new` — 32-byte salts; LE-mod-r in-circuit.
///
/// Outputs:
///   * `out_proof` — 1601-byte proof.
///   * `out_public_inputs` — 96 bytes = `c_old ++ Fr::from(epoch_old)
///     ++ c_new`, all BE 32-byte Fr scalars (the exact vector the
///     plonk verifier consumes).
///
/// Convention: `epoch_new = epoch_old + 1` (matches the canonical
/// witness builder; the circuit doesn't constrain new-epoch).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_anarchy_prove_update(
    depth: usize,
    member_leaf_hashes_old_ptr: *const u8,
    member_leaf_hashes_old_len: usize,
    member_leaf_hashes_new_ptr: *const u8,
    member_leaf_hashes_new_len: usize,
    prover_secret_key_ptr: *const u8,
    prover_secret_key_len: usize,
    prover_index_old: usize,
    epoch_old: u64,
    salt_old_ptr: *const u8,
    salt_old_len: usize,
    salt_new_ptr: *const u8,
    salt_new_len: usize,
    out_proof: *mut OnymByteBuffer,
    out_public_inputs: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        check_output_ptr(out_proof, "out_proof")?;
        check_output_ptr(out_public_inputs, "out_public_inputs")?;

        check_depth(depth)?;
        let leaves_old_packed = read_bytes(
            member_leaf_hashes_old_ptr,
            member_leaf_hashes_old_len,
            "member_leaf_hashes_old",
        )?;
        let leaves_old = parse_leaf_hashes(leaves_old_packed, "member_leaf_hashes_old")?;
        let leaves_new: Vec<Fr> = if member_leaf_hashes_new_len == 0
            || member_leaf_hashes_new_ptr.is_null()
        {
            leaves_old.clone()
        } else {
            let leaves_new_packed = read_bytes(
                member_leaf_hashes_new_ptr,
                member_leaf_hashes_new_len,
                "member_leaf_hashes_new",
            )?;
            parse_leaf_hashes(leaves_new_packed, "member_leaf_hashes_new")?
        };

        let num_leaves = 1usize << depth;
        if leaves_old.is_empty() {
            return Err("member_leaf_hashes_old is empty".to_string());
        }
        if leaves_old.len() > num_leaves || leaves_new.len() > num_leaves {
            return Err(format!(
                "leaf-hash roster exceeds depth-{depth} capacity {num_leaves} \
                 (old={}, new={})",
                leaves_old.len(),
                leaves_new.len()
            ));
        }

        let prover_sk = fr_from_be(
            read_bytes(
                prover_secret_key_ptr,
                prover_secret_key_len,
                "prover_secret_key",
            )?,
            "prover_secret_key",
        )?;
        check_prover_leaf(&prover_sk, &leaves_old, prover_index_old, "member_leaf_hashes_old")?;

        let salt_old_bytes = read_bytes(salt_old_ptr, salt_old_len, "salt_old")?;
        let salt_new_bytes = read_bytes(salt_new_ptr, salt_new_len, "salt_new")?;
        require_len("salt_old", salt_old_bytes.len(), SALT_BYTES)?;
        require_len("salt_new", salt_new_bytes.len(), SALT_BYTES)?;
        let mut salt_old: [u8; SALT_BYTES] = [0; SALT_BYTES];
        let mut salt_new: [u8; SALT_BYTES] = [0; SALT_BYTES];
        salt_old.copy_from_slice(salt_old_bytes);
        salt_new.copy_from_slice(salt_new_bytes);

        let (root_old, nodes_old) = build_tree_from_leaves(&leaves_old, depth);
        let (root_new, _) = build_tree_from_leaves(&leaves_new, depth);
        let path_old = merkle_path(&nodes_old, num_leaves, prover_index_old, depth);

        let c_old = poseidon_commitment(&root_old, epoch_old, &salt_old);
        let c_new = poseidon_commitment(&root_new, epoch_old + 1, &salt_new);

        let witness = UpdateWitness {
            c_old,
            epoch_old,
            c_new,
            secret_key: prover_sk,
            poseidon_root_old: root_old,
            salt_old,
            merkle_path_old: path_old,
            leaf_index_old: prover_index_old,
            poseidon_root_new: root_new,
            salt_new,
            depth,
        };

        let mut circuit = PlonkCircuit::<Fr>::new_turbo_plonk();
        synthesize_update(&mut circuit, &witness)
            .map_err(|e| format!("synthesize_update: {e:?}"))?;
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

        let public_inputs = vec![c_old, Fr::from(epoch_old), c_new];
        plonk::verify(&keys.vk, &public_inputs, &proof).map_err(|e| {
            format!("self-verify rejected proof — witness or circuit shape is wrong: {e:?}")
        })?;

        // 3 × 32 BE Fr concat — matches the verify() input exactly.
        let mut pi_concat = Vec::with_capacity(3 * FR_BYTES);
        pi_concat.extend_from_slice(&fr_to_be_bytes(&c_old));
        pi_concat.extend_from_slice(&fr_to_be_bytes(&Fr::from(epoch_old)));
        pi_concat.extend_from_slice(&fr_to_be_bytes(&c_new));

        // Atomic publish — see prove_membership for rationale.
        unsafe {
            *out_proof = buffer_from_vec(proof_bytes);
            *out_public_inputs = buffer_from_vec(pi_concat);
        }
        Ok(())
    })
}
