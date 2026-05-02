//! End-to-end FFI round trips for sep-anarchy-ffi.
//!
//! Each prove_* test runs: bake the VK natively, prove via the FFI,
//! verify the returned proof against the freshly-baked VK using the
//! prover crate's `verify`. A green test guarantees the FFI can hand
//! a contract a proof that the (separately-built) Soroban verifier
//! will accept.

use std::ffi::CStr;
use std::ptr;

use ark_bls12_381_v05::Fr;
use ark_ff_v05::{BigInteger, PrimeField};
use ark_serialize_v05::CanonicalDeserialize;
use jf_plonk::proof_system::structs::{Proof, VerifyingKey};

use onym_plonk_prover::circuit::plonk::baker::{
    bake_membership_vk, bake_update_vk, pinned_update_vk_sha256_hex, pinned_vk_sha256_hex,
};
use onym_plonk_prover::circuit::plonk::poseidon::poseidon_hash_one_v05;
use onym_plonk_prover::prover::plonk;

use onym_sep_anarchy_ffi::{
    onym_anarchy_bake_membership_vk, onym_anarchy_bake_update_vk,
    onym_anarchy_pinned_membership_vk_sha256_hex,
    onym_anarchy_pinned_update_vk_sha256_hex, onym_anarchy_prove_membership,
    onym_anarchy_prove_update, OnymByteBuffer,
};
use sha2::{Digest, Sha256};

const TEST_DEPTH: usize = 5;

fn drain(buf: OnymByteBuffer) -> Vec<u8> {
    assert!(!buf.ptr.is_null(), "FFI buffer.ptr is null");
    let copy = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) }.to_vec();
    let _ = unsafe { Vec::from_raw_parts(buf.ptr, buf.len, buf.len) };
    copy
}

fn assert_no_error(err: *mut std::os::raw::c_char, ctx: &str) {
    if !err.is_null() {
        let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        let _ = unsafe { std::ffi::CString::from_raw(err) };
        panic!("{ctx}: {msg}");
    }
}

fn fr_from_be(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

fn fr_be(fr: &Fr) -> Vec<u8> {
    fr.into_bigint().to_bytes_be()
}

/// SDK-side: derive packed leaf hashes from a roster of secret keys.
/// Real callers either compute these locally for new groups or
/// receive them from the visible tree state for existing groups.
fn pack_leaf_hashes_from_secret_keys(secret_keys: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(secret_keys.len() * 32);
    for sk in secret_keys {
        let leaf = poseidon_hash_one_v05(sk);
        out.extend_from_slice(&fr_be(&leaf));
    }
    out
}

#[test]
fn bake_membership_vk_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe { onym_anarchy_bake_membership_vk(TEST_DEPTH, &mut out, &mut err) };
    assert!(ok);
    assert_no_error(err, "bake_membership_vk");
    let ffi_bytes = drain(out);

    let native = bake_membership_vk(TEST_DEPTH).expect("native bake");
    assert_eq!(ffi_bytes, native);
}

#[test]
fn bake_update_vk_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe { onym_anarchy_bake_update_vk(TEST_DEPTH, &mut out, &mut err) };
    assert!(ok);
    assert_no_error(err, "bake_update_vk");
    let ffi_bytes = drain(out);

    let native = bake_update_vk(TEST_DEPTH).expect("native bake");
    assert_eq!(ffi_bytes, native);
}

#[test]
fn pinned_membership_vk_hex_matches_baked_sha256() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_anarchy_pinned_membership_vk_sha256_hex(TEST_DEPTH, &mut out, &mut err)
    };
    assert!(ok);
    assert_no_error(err, "pinned_membership_vk_sha256_hex");
    let bytes = drain(out);
    let hex = std::str::from_utf8(&bytes).expect("ASCII hex");
    assert_eq!(hex.len(), 64, "SHA-256 hex must be 64 chars, got {hex:?}");
    assert_eq!(hex, pinned_vk_sha256_hex(TEST_DEPTH).expect("pinned"));

    // And the pinned hex is the SHA-256 of the freshly-baked VK bytes.
    let vk = bake_membership_vk(TEST_DEPTH).expect("bake");
    let mut h = Sha256::new();
    h.update(&vk);
    let computed: [u8; 32] = h.finalize().into();
    let computed_hex: String = computed.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(hex, computed_hex);
}

#[test]
fn pinned_update_vk_hex_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_anarchy_pinned_update_vk_sha256_hex(TEST_DEPTH, &mut out, &mut err)
    };
    assert!(ok);
    assert_no_error(err, "pinned_update_vk_sha256_hex");
    let hex = String::from_utf8(drain(out)).unwrap();
    assert_eq!(hex, pinned_update_vk_sha256_hex(TEST_DEPTH).expect("pinned"));
}

#[test]
fn pinned_membership_vk_unsupported_depth_errors() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_anarchy_pinned_membership_vk_sha256_hex(7, &mut out, &mut err)
    };
    assert!(!ok, "depth=7 should not be a supported tier");
    assert!(!err.is_null());
    let _ = unsafe { std::ffi::CString::from_raw(err) };
}

#[test]
fn prove_membership_then_verify_against_baked_vk() {
    let secret_keys: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let prover_index = 3usize;
    let prover_sk_be = fr_be(&secret_keys[prover_index]);
    let epoch = 1234u64;
    let salt = [0xEEu8; 32];

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut commit_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_anarchy_prove_membership(
            TEST_DEPTH,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            prover_sk_be.as_ptr(),
            prover_sk_be.len(),
            prover_index,
            epoch,
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            &mut commit_buf,
            &mut err,
        )
    };
    assert!(ok);
    assert_no_error(err, "prove_membership");

    let proof_bytes = drain(proof_buf);
    let commitment_bytes = drain(commit_buf);
    assert_eq!(proof_bytes.len(), 1601);
    assert_eq!(commitment_bytes.len(), 32);
    let commitment = fr_from_be(&commitment_bytes);

    // Verify the FFI proof against the prover-baked VK.
    let vk_bytes = bake_membership_vk(TEST_DEPTH).expect("bake");
    let vk: VerifyingKey<ark_bls12_381_v05::Bls12_381> =
        VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).expect("deserialise vk");
    let proof: Proof<ark_bls12_381_v05::Bls12_381> =
        Proof::deserialize_uncompressed(&proof_bytes[..]).expect("deserialise proof");
    plonk::verify(&vk, &[commitment, Fr::from(epoch)], &proof)
        .expect("FFI proof must verify under freshly-baked anarchy VK");
}

#[test]
fn prove_update_then_verify_against_baked_vk() {
    let secret_keys: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let prover_index_old = 3usize;
    let prover_sk_be = fr_be(&secret_keys[prover_index_old]);
    let epoch_old = 1234u64;
    let salt_old = [0xEEu8; 32];
    let salt_new = [0xFFu8; 32];

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut pi_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_anarchy_prove_update(
            TEST_DEPTH,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            // Pass NULL+0 to reuse the old leaf hashes.
            ptr::null(),
            0,
            prover_sk_be.as_ptr(),
            prover_sk_be.len(),
            prover_index_old,
            epoch_old,
            salt_old.as_ptr(),
            salt_old.len(),
            salt_new.as_ptr(),
            salt_new.len(),
            &mut proof_buf,
            &mut pi_buf,
            &mut err,
        )
    };
    assert!(ok);
    assert_no_error(err, "prove_update");

    let proof_bytes = drain(proof_buf);
    let pi_bytes = drain(pi_buf);
    assert_eq!(proof_bytes.len(), 1601);
    assert_eq!(pi_bytes.len(), 96);

    let c_old = fr_from_be(&pi_bytes[0..32]);
    let pi_epoch = fr_from_be(&pi_bytes[32..64]);
    let c_new = fr_from_be(&pi_bytes[64..96]);
    assert_eq!(pi_epoch, Fr::from(epoch_old));

    let vk_bytes = bake_update_vk(TEST_DEPTH).expect("bake");
    let vk: VerifyingKey<ark_bls12_381_v05::Bls12_381> =
        VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).expect("deserialise vk");
    let proof: Proof<ark_bls12_381_v05::Bls12_381> =
        Proof::deserialize_uncompressed(&proof_bytes[..]).expect("deserialise proof");
    plonk::verify(&vk, &[c_old, pi_epoch, c_new], &proof)
        .expect("FFI update proof must verify under freshly-baked anarchy update VK");
}

#[test]
fn prove_membership_rejects_out_of_range_prover_index() {
    let secret_keys: Vec<Fr> = (1u64..=4).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let prover_sk_be = fr_be(&secret_keys[0]);
    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut commit_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let salt = [0u8; 32];
    let ok = unsafe {
        onym_anarchy_prove_membership(
            TEST_DEPTH,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            prover_sk_be.as_ptr(),
            prover_sk_be.len(),
            10, // > 4 leaf hashes
            0,
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            &mut commit_buf,
            &mut err,
        )
    };
    assert!(!ok);
    assert!(!err.is_null());
    let _ = unsafe { std::ffi::CString::from_raw(err) };
}

#[test]
fn prove_membership_rejects_unsupported_tier() {
    // Audit Finding 1 regression: prove_* must restrict depth to the
    // three tiers an on-chain VK exists for (5/8/11). Otherwise an
    // SDK can get a self-verified proof for e.g. depth=7 that no
    // contract will accept.
    let secret_keys: Vec<Fr> = (1u64..=4).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let prover_sk_be = fr_be(&secret_keys[0]);
    let salt = [0u8; 32];

    for bad_depth in [0usize, 1, 4, 6, 7, 9, 10, 12, 16, 31] {
        let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
        let mut commit_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
        let mut err: *mut std::os::raw::c_char = ptr::null_mut();
        let ok = unsafe {
            onym_anarchy_prove_membership(
                bad_depth,
                leaves_packed.as_ptr(),
                leaves_packed.len(),
                prover_sk_be.as_ptr(),
                prover_sk_be.len(),
                0,
                0,
                salt.as_ptr(),
                salt.len(),
                &mut proof_buf,
                &mut commit_buf,
                &mut err,
            )
        };
        assert!(
            !ok,
            "depth={bad_depth} should be rejected — only 5/8/11 have on-chain VKs"
        );
        assert!(!err.is_null(), "depth={bad_depth} should populate out_error");
        let _ = unsafe { std::ffi::CString::from_raw(err) };
    }
}

#[test]
fn prove_membership_null_second_output_does_not_publish_first() {
    // Audit Finding 3 regression test: when one of the two output
    // pointers is null, the function must fail BEFORE writing to
    // the other output. Previously, write_buffer(out_proof, ...)
    // succeeded then write_buffer(out_commitment, ...) failed,
    // leaking the proof allocation to a caller that ignores
    // outputs on `false`.
    let secret_keys: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let prover_sk_be = fr_be(&secret_keys[3]);
    let salt = [0u8; 32];

    // Pre-fill out_proof with a recognisable sentinel; the FFI must
    // not touch it because the second output (out_commitment) is null.
    let sentinel_ptr = 0xDEADBEEFusize as *mut u8;
    let sentinel_len = 0x99999999usize;
    let mut proof_buf = OnymByteBuffer {
        ptr: sentinel_ptr,
        len: sentinel_len,
    };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_anarchy_prove_membership(
            5,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            prover_sk_be.as_ptr(),
            prover_sk_be.len(),
            3,
            0,
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            ptr::null_mut(), // out_commitment NULL — pre-validation must catch this
            &mut err,
        )
    };
    assert!(!ok, "expected failure when out_commitment pointer is null");
    assert_eq!(
        proof_buf.ptr, sentinel_ptr,
        "out_proof was published before pre-validation rejected the call — partial-leak bug"
    );
    assert_eq!(proof_buf.len, sentinel_len);
    assert!(!err.is_null());
    let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
    assert!(
        msg.contains("out_commitment") || msg.contains("null"),
        "expected null-output error, got: {msg}"
    );
    let _ = unsafe { std::ffi::CString::from_raw(err) };
}

#[test]
fn prove_membership_rejects_mismatched_prover_secret_key() {
    // Sanity check: prover_secret_key MUST hash to leaf at prover_index.
    // A wrong sk surfaces here before the prover gets invoked, so the
    // error message is clear instead of an opaque WrongProof.
    let secret_keys: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    // Lie: claim to be prover_index=3 but supply secret_keys[5].
    let wrong_sk_be = fr_be(&secret_keys[5]);
    let prover_index = 3usize;
    let salt = [0u8; 32];

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut commit_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_anarchy_prove_membership(
            TEST_DEPTH,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            wrong_sk_be.as_ptr(),
            wrong_sk_be.len(),
            prover_index,
            0,
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            &mut commit_buf,
            &mut err,
        )
    };
    assert!(!ok);
    assert!(!err.is_null());
    let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
    assert!(
        msg.contains("does not match"),
        "expected leaf-mismatch error, got: {msg}"
    );
    let _ = unsafe { std::ffi::CString::from_raw(err) };
}
