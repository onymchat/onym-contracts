//! Shared mobile-FFI primitives for the onym-contracts sep-* family.
//!
//! Wraps the off-chain prover's hashing/serialisation primitives behind
//! a stable C ABI consumed by `onym-sdk-swift` / `onym-sdk-kotlin`. See
//! `plonk/FFI-DESIGN.md` for the full ABI contract — symbol naming,
//! byte-buffer ownership, error model, and scalar/point encoding rules
//! pinned there are part of the public surface and must not drift.
//!
//! All Rust panics that would otherwise unwind across the FFI boundary
//! are caught and reported as `"Rust panic crossed FFI boundary"` —
//! keeping the boundary `extern "C"` correct under
//! `panic = "unwind"`.

use std::ffi::{c_char, CString};
use std::ptr;
use std::slice;

use ark_bls12_381_v05::{Fr, G1Affine, G1Projective};
use ark_ec_v05::{CurveGroup, PrimeGroup};
use ark_ff_v05::{BigInteger, PrimeField};
use ark_serialize_v05::CanonicalSerialize;

use sha2::{Digest, Sha256};

use k256::schnorr::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};

use onym_plonk_prover::circuit::plonk::poseidon::{
    poseidon_hash_one_v05, poseidon_hash_two_v05,
};
use onym_plonk_prover::circuit::plonk::proof_format::PROOF_LEN;

/// Length of a BE-encoded BLS12-381 `Fr` scalar.
const FR_BYTES: usize = 32;

/// Length of a BLS12-381 G1Affine compressed point (used for member
/// public keys).
const COMPRESSED_G1_LEN: usize = 48;

/// Length of an x-only secp256k1 schnorr public key (BIP340 / Nostr).
const NOSTR_PUBKEY_LEN: usize = 32;

/// Length of a secp256k1 schnorr signature (BIP340).
const NOSTR_SIG_LEN: usize = 64;

// ---------------------------------------------------------------------------
// FFI byte-buffer + helpers
// ---------------------------------------------------------------------------

/// Caller-owned byte buffer. Freed via `onym_byte_buffer_free`.
#[repr(C)]
pub struct OnymByteBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

fn buffer_from_vec(bytes: Vec<u8>) -> OnymByteBuffer {
    // Round-trip via Box<[u8]> so the freeing side doesn't need a
    // capacity field. `into_boxed_slice` shrinks the allocation to
    // exactly `len`; `Box::into_raw` hands ownership to C as a fat
    // pointer that we decompose into (ptr, len). The free function
    // reattaches the slice metadata via `slice_from_raw_parts_mut`
    // and reclaims via `Box::from_raw` — no capacity ambiguity.
    //
    // The previous Vec-based round-trip relied on `shrink_to_fit`
    // setting capacity == len, which the allocator does NOT
    // guarantee — `Vec::from_raw_parts(ptr, len, len)` then handed
    // a wrong-capacity Vec to the allocator at drop time, which is
    // UB.
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

fn fr_from_be_bytes(label: &str, bytes: &[u8]) -> Result<Fr, String> {
    require_len(label, bytes.len(), FR_BYTES)?;
    Ok(Fr::from_be_bytes_mod_order(bytes))
}

fn fr_to_be_bytes(fr: &Fr) -> Vec<u8> {
    let bytes = fr.into_bigint().to_bytes_be();
    debug_assert_eq!(bytes.len(), FR_BYTES);
    bytes
}

// ---------------------------------------------------------------------------
// Memory-management exports
// ---------------------------------------------------------------------------

/// Free a buffer previously written by any `onym_*` function.
///
/// # Safety
/// `buffer.ptr` must have been allocated by this library via
/// `buffer_from_vec` (i.e. ultimately a `Box<[u8]>::into_raw`).
/// Passing a zero-len buffer (the `{ NULL, 0 }` shape callers use to
/// indicate "no output") is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_byte_buffer_free(buffer: OnymByteBuffer) {
    if buffer.ptr.is_null() || buffer.len == 0 {
        return;
    }
    // Reattach the slice metadata and reclaim. Matches the
    // `into_boxed_slice` allocation in `buffer_from_vec`: the
    // allocator sees exactly the (ptr, len) it originally returned,
    // no capacity guesswork.
    let slice_ptr = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
    let _ = unsafe { Box::from_raw(slice_ptr) };
}

/// Free a C string previously returned via `out_error`.
///
/// # Safety
/// `ptr` must have been allocated by this library. NULL is a no-op.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    let _ = unsafe { CString::from_raw(ptr) };
}

// ---------------------------------------------------------------------------
// Hashing primitives
// ---------------------------------------------------------------------------

/// Compute the Poseidon leaf hash `Poseidon(sk_fr)`.
///
/// Output is a 32-byte BE-encoded `Fr` scalar, suitable as a member
/// leaf in any sep-* Poseidon Merkle tree.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_compute_leaf_hash(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    out_leaf_hash: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let sk_bytes = read_bytes(secret_key_ptr, secret_key_len, "secret_key")?;
        let sk = fr_from_be_bytes("secret_key", sk_bytes)?;
        let leaf = poseidon_hash_one_v05(&sk);
        write_buffer(out_leaf_hash, fr_to_be_bytes(&leaf))
    })
}

/// Compute the BLS12-381 G1 compressed public key `[sk] · G` (48 bytes).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_compute_public_key(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    out_public_key: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let sk_bytes = read_bytes(secret_key_ptr, secret_key_len, "secret_key")?;
        let sk = fr_from_be_bytes("secret_key", sk_bytes)?;
        let projective: G1Projective = G1Projective::generator() * sk;
        let affine: G1Affine = projective.into_affine();
        let mut out = Vec::with_capacity(COMPRESSED_G1_LEN);
        affine
            .serialize_compressed(&mut out)
            .map_err(|e| format!("compressed pubkey serialise: {e}"))?;
        debug_assert_eq!(out.len(), COMPRESSED_G1_LEN);
        write_buffer(out_public_key, out)
    })
}

/// Compute the Poseidon Merkle root over `leaf_hashes` padded with
/// `Fr::ZERO` to a complete tree of `depth`.
///
/// `leaf_hashes` is a tightly-packed array of 32-byte BE Fr scalars
/// (length must be a multiple of 32; ≤ 2^depth scalars). The output is
/// a 32-byte BE Fr scalar (the root).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_compute_merkle_root(
    leaf_hashes_ptr: *const u8,
    leaf_hashes_len: usize,
    depth: usize,
    out_root: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let leaf_bytes = read_bytes(leaf_hashes_ptr, leaf_hashes_len, "leaf_hashes")?;
        if leaf_bytes.len() % FR_BYTES != 0 {
            return Err(format!(
                "leaf_hashes length {} is not a multiple of {FR_BYTES}",
                leaf_bytes.len()
            ));
        }
        if depth >= 32 {
            return Err(format!("depth {depth} exceeds supported maximum (32)"));
        }
        let num_leaves = 1usize << depth;
        let supplied = leaf_bytes.len() / FR_BYTES;
        if supplied > num_leaves {
            return Err(format!(
                "{supplied} leaves exceed depth-{depth} tree capacity {num_leaves}"
            ));
        }

        let mut nodes = vec![Fr::from(0u64); 2 * num_leaves];
        for i in 0..supplied {
            let chunk = &leaf_bytes[i * FR_BYTES..(i + 1) * FR_BYTES];
            nodes[num_leaves + i] = Fr::from_be_bytes_mod_order(chunk);
        }
        for i in (1..num_leaves).rev() {
            nodes[i] = poseidon_hash_two_v05(&nodes[2 * i], &nodes[2 * i + 1]);
        }
        write_buffer(out_root, fr_to_be_bytes(&nodes[1]))
    })
}

// ---------------------------------------------------------------------------
// Commitment primitives
// ---------------------------------------------------------------------------

/// SHA-256 commitment: `SHA256(root_be32 || epoch_be8 || salt)` → 32 B.
///
/// The legacy v1 commitment shape; preserved here for client code that
/// still talks to v1 sep-xxxx Soroban contracts during the migration.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_compute_sha256_commitment(
    poseidon_root_ptr: *const u8,
    poseidon_root_len: usize,
    epoch: u64,
    salt_ptr: *const u8,
    salt_len: usize,
    out_commitment: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let root = read_bytes(poseidon_root_ptr, poseidon_root_len, "poseidon_root")?;
        require_len("poseidon_root", root.len(), FR_BYTES)?;
        let salt = read_bytes(salt_ptr, salt_len, "salt")?;
        let mut h = Sha256::new();
        h.update(root);
        h.update(epoch.to_be_bytes());
        h.update(salt);
        let digest = h.finalize();
        write_buffer(out_commitment, digest.to_vec())
    })
}

/// Poseidon commitment: `Poseidon(Poseidon(root, Fr::from(epoch)), salt_fr)`.
///
/// `salt` is interpreted as little-endian and reduced mod r — matching
/// the in-circuit encoding the prover uses for every sep-* commitment.
/// Output is the resulting `Fr` BE-encoded (32 B).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_compute_poseidon_commitment(
    poseidon_root_ptr: *const u8,
    poseidon_root_len: usize,
    epoch: u64,
    salt_ptr: *const u8,
    salt_len: usize,
    out_commitment: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let root_bytes = read_bytes(poseidon_root_ptr, poseidon_root_len, "poseidon_root")?;
        let root_fr = fr_from_be_bytes("poseidon_root", root_bytes)?;
        let salt = read_bytes(salt_ptr, salt_len, "salt")?;
        require_len("salt", salt.len(), FR_BYTES)?;
        let salt_fr = Fr::from_le_bytes_mod_order(salt);
        let inner = poseidon_hash_two_v05(&root_fr, &Fr::from(epoch));
        let commitment = poseidon_hash_two_v05(&inner, &salt_fr);
        write_buffer(out_commitment, fr_to_be_bytes(&commitment))
    })
}

// ---------------------------------------------------------------------------
// Plonk proof parser
// ---------------------------------------------------------------------------

// Per the wire-format pinned in
// `onym_plonk_prover::circuit::plonk::proof_format` (PROOF_LEN = 1601):
//
//   wires_poly_comms.len() (u64 LE)         | 0    .. 8
//   wires_poly_comms[0..5]   (5×G1, 96 each)| 8    .. 488
//   prod_perm_poly_comm      (G1, 96)       | 488  .. 584
//   split_quot_poly_comms.len() (u64 LE)    | 584  .. 592
//   split_quot_poly_comms[0..5] (5×G1, 96)  | 592  .. 1072
//   opening_proof            (G1, 96)       | 1072 .. 1168
//   shifted_opening_proof    (G1, 96)       | 1168 .. 1264
//   wires_evals.len() (u64 LE)              | 1264 .. 1272
//   wires_evals[0..5] (5×Fr, 32 each)       | 1272 .. 1432
//   wire_sigma_evals.len() (u64 LE)         | 1432 .. 1440
//   wire_sigma_evals[0..4] (4×Fr, 32 each)  | 1440 .. 1568
//   perm_next_eval (Fr, 32)                 | 1568 .. 1600
//   plookup_proof: Option<…> (None=0x00)    | 1600 .. 1601
const COMPONENTS_LEN: usize = 480 + 96 + 480 + 96 + 96 + 160 + 128 + 32; // 1568

/// Strip the four `len()` u64 prefixes and the trailing
/// `plookup_proof: Option = None` byte from a 1601-byte uncompressed
/// jf-plonk proof, returning the 1568-byte concat:
///
///   wires(5×96) ++ prod_perm(96) ++ split_quot(5×96) ++
///   opening(96) ++ shifted_opening(96) ++ wires_evals(5×32) ++
///   wire_sigma_evals(4×32) ++ perm_next_eval(32)
///
/// Caller slices into named regions per the offset table above.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_parse_plonk_proof(
    proof_ptr: *const u8,
    proof_len: usize,
    out_components_concat: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let proof = read_bytes(proof_ptr, proof_len, "proof")?;
        require_len("proof", proof.len(), PROOF_LEN)?;
        let mut out = Vec::with_capacity(COMPONENTS_LEN);
        out.extend_from_slice(&proof[8..488]);
        out.extend_from_slice(&proof[488..584]);
        out.extend_from_slice(&proof[592..1072]);
        out.extend_from_slice(&proof[1072..1168]);
        out.extend_from_slice(&proof[1168..1264]);
        out.extend_from_slice(&proof[1272..1432]);
        out.extend_from_slice(&proof[1440..1568]);
        out.extend_from_slice(&proof[1568..1600]);
        debug_assert_eq!(out.len(), COMPONENTS_LEN);
        write_buffer(out_components_concat, out)
    })
}

// ---------------------------------------------------------------------------
// Nostr secp256k1 schnorr (BIP340)
// ---------------------------------------------------------------------------

fn parse_signing_key(sk_bytes: &[u8]) -> Result<SigningKey, String> {
    require_len("nostr secret_key", sk_bytes.len(), NOSTR_PUBKEY_LEN)?;
    SigningKey::from_bytes(sk_bytes).map_err(|e| format!("invalid nostr secret key: {e}"))
}

fn parse_verifying_key(pk_bytes: &[u8]) -> Result<VerifyingKey, String> {
    require_len("nostr public_key", pk_bytes.len(), NOSTR_PUBKEY_LEN)?;
    VerifyingKey::from_bytes(pk_bytes).map_err(|e| format!("invalid nostr public key: {e}"))
}

/// Derive the 32-byte BIP340 x-only public key from a 32-byte secret.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_nostr_derive_public_key(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    out_public_key: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let sk_bytes = read_bytes(secret_key_ptr, secret_key_len, "nostr secret_key")?;
        let sk = parse_signing_key(sk_bytes)?;
        let pk_bytes: [u8; NOSTR_PUBKEY_LEN] = sk.verifying_key().to_bytes().into();
        write_buffer(out_public_key, pk_bytes.to_vec())
    })
}

/// Sign a 32-byte event id (BIP340 Schnorr) — Nostr `id` field.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_nostr_sign_event_id(
    secret_key_ptr: *const u8,
    secret_key_len: usize,
    event_id_ptr: *const u8,
    event_id_len: usize,
    out_signature: *mut OnymByteBuffer,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let sk_bytes = read_bytes(secret_key_ptr, secret_key_len, "nostr secret_key")?;
        let event_id = read_bytes(event_id_ptr, event_id_len, "event_id")?;
        require_len("event_id", event_id.len(), 32)?;
        let sk = parse_signing_key(sk_bytes)?;
        let sig: Signature = sk
            .sign_prehash(event_id)
            .map_err(|e| format!("schnorr sign: {e}"))?;
        let sig_bytes: [u8; NOSTR_SIG_LEN] = sig.to_bytes();
        write_buffer(out_signature, sig_bytes.to_vec())
    })
}

/// Verify a BIP340 Schnorr signature over a 32-byte event id.
///
/// On success: returns `true`, `*out_error = NULL`. On verification
/// failure: returns `false` with a populated `out_error`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn onym_nostr_verify_event_signature(
    public_key_ptr: *const u8,
    public_key_len: usize,
    event_id_ptr: *const u8,
    event_id_len: usize,
    signature_ptr: *const u8,
    signature_len: usize,
    out_error: *mut *mut c_char,
) -> bool {
    run_ffi(out_error, || {
        let pk_bytes = read_bytes(public_key_ptr, public_key_len, "nostr public_key")?;
        let event_id = read_bytes(event_id_ptr, event_id_len, "event_id")?;
        let sig_bytes = read_bytes(signature_ptr, signature_len, "signature")?;
        require_len("event_id", event_id.len(), 32)?;
        require_len("signature", sig_bytes.len(), NOSTR_SIG_LEN)?;
        let vk = parse_verifying_key(pk_bytes)?;
        let sig = Signature::try_from(sig_bytes)
            .map_err(|e| format!("invalid signature bytes: {e}"))?;
        vk.verify_prehash(event_id, &sig)
            .map_err(|e| format!("schnorr verify: {e}"))
    })
}
