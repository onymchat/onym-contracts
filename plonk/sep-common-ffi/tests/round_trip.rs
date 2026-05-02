//! End-to-end FFI round trips. Each test exercises the public C ABI
//! through the Rust-side `extern "C"` symbols (re-exported via
//! `onym_sep_common_ffi`). Failures here mean a behavioural regression
//! visible to mobile clients.

use std::ffi::CStr;
use std::ptr;

use ark_bls12_381_v05::Fr;
use ark_ff_v05::PrimeField;

use onym_plonk_prover::circuit::plonk::poseidon::{
    poseidon_hash_one_v05, poseidon_hash_two_v05,
};

use onym_sep_common_ffi::{
    onym_byte_buffer_free, onym_compute_leaf_hash, onym_compute_merkle_root,
    onym_compute_poseidon_commitment, onym_compute_public_key,
    onym_compute_sha256_commitment, onym_nostr_derive_public_key,
    onym_nostr_sign_event_id, onym_nostr_verify_event_signature,
    onym_parse_plonk_proof, onym_string_free, OnymByteBuffer,
};

/// Helper: copy a buffer's bytes into a Vec<u8>, then free it via the
/// FFI deallocator. Catches the common bug of leaking allocations and
/// keeps each test's payload-extraction noise to one line.
fn drain(buf: OnymByteBuffer) -> Vec<u8> {
    assert!(!buf.ptr.is_null(), "FFI buffer.ptr is null");
    let copy = unsafe { std::slice::from_raw_parts(buf.ptr, buf.len) }.to_vec();
    unsafe { onym_byte_buffer_free(buf) };
    copy
}

/// Helper: assert no error was set, freeing it if (somehow) present.
fn assert_no_error(err: *mut std::os::raw::c_char, ctx: &str) {
    if !err.is_null() {
        let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
        unsafe { onym_string_free(err) };
        panic!("{ctx}: {msg}");
    }
}

fn fr_from_be(bytes: &[u8]) -> Fr {
    Fr::from_be_bytes_mod_order(bytes)
}

#[test]
fn leaf_hash_matches_native_poseidon() {
    let sk_fr = Fr::from(0x1234567890abcdefu64);
    let sk_be = ark_ff_v05::BigInteger::to_bytes_be(&sk_fr.into_bigint());
    let expected = poseidon_hash_one_v05(&sk_fr);

    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_compute_leaf_hash(sk_be.as_ptr(), sk_be.len(), &mut out, &mut err)
    };
    assert!(ok);
    assert_no_error(err, "leaf_hash");
    let bytes = drain(out);
    assert_eq!(bytes.len(), 32);
    assert_eq!(fr_from_be(&bytes), expected);
}

#[test]
fn merkle_root_matches_native_pad_to_full_tree() {
    // 3 leaves at depth 5 (capacity 32). Padding leaves must be
    // Fr::ZERO so the root matches the prover-side computation.
    let depth = 5;
    let leaves: Vec<Fr> = (1..=3).map(|i| Fr::from(i as u64)).collect();
    let leaf_hashes: Vec<Fr> = leaves.iter().map(poseidon_hash_one_v05).collect();

    // Pack as concatenated 32-byte BE Frs.
    let mut packed = Vec::with_capacity(leaf_hashes.len() * 32);
    for h in &leaf_hashes {
        let bytes = ark_ff_v05::BigInteger::to_bytes_be(&h.into_bigint());
        assert_eq!(bytes.len(), 32);
        packed.extend_from_slice(&bytes);
    }

    // Native expected root.
    let num_leaves = 1usize << depth;
    let mut nodes = vec![Fr::from(0u64); 2 * num_leaves];
    for (i, h) in leaf_hashes.iter().enumerate() {
        nodes[num_leaves + i] = *h;
    }
    for i in (1..num_leaves).rev() {
        nodes[i] = poseidon_hash_two_v05(&nodes[2 * i], &nodes[2 * i + 1]);
    }
    let expected = nodes[1];

    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_compute_merkle_root(packed.as_ptr(), packed.len(), depth, &mut out, &mut err)
    };
    assert!(ok);
    assert_no_error(err, "merkle_root");
    let bytes = drain(out);
    assert_eq!(fr_from_be(&bytes), expected);
}

#[test]
fn public_key_is_48_bytes_and_deterministic() {
    let sk_fr = Fr::from(7u64);
    let sk_be = ark_ff_v05::BigInteger::to_bytes_be(&sk_fr.into_bigint());

    let mut out_a = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_compute_public_key(sk_be.as_ptr(), sk_be.len(), &mut out_a, &mut err)
    });
    assert_no_error(err, "public_key A");
    let pk_a = drain(out_a);

    let mut out_b = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_compute_public_key(sk_be.as_ptr(), sk_be.len(), &mut out_b, &mut err)
    });
    assert_no_error(err, "public_key B");
    let pk_b = drain(out_b);

    assert_eq!(pk_a.len(), 48);
    assert_eq!(pk_a, pk_b, "compressed pubkey is non-deterministic");
}

#[test]
fn sha256_commitment_matches_legacy_layout() {
    let root = [0xAAu8; 32];
    let salt = [0xBBu8; 32];
    let epoch = 0x0102030405060708u64;

    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_compute_sha256_commitment(
            root.as_ptr(),
            root.len(),
            epoch,
            salt.as_ptr(),
            salt.len(),
            &mut out,
            &mut err,
        )
    };
    assert!(ok);
    assert_no_error(err, "sha256_commitment");
    let bytes = drain(out);

    // Hand-roll the expected digest.
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(root);
    h.update(epoch.to_be_bytes());
    h.update(salt);
    let expected: [u8; 32] = h.finalize().into();
    assert_eq!(bytes, expected.to_vec());
}

#[test]
fn poseidon_commitment_matches_native() {
    let root_fr = Fr::from(123u64);
    let root_be = ark_ff_v05::BigInteger::to_bytes_be(&root_fr.into_bigint());
    let salt = [0x33u8; 32];
    let epoch = 42u64;

    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_compute_poseidon_commitment(
            root_be.as_ptr(),
            root_be.len(),
            epoch,
            salt.as_ptr(),
            salt.len(),
            &mut out,
            &mut err,
        )
    };
    assert!(ok);
    assert_no_error(err, "poseidon_commitment");
    let bytes = drain(out);

    let salt_fr = Fr::from_le_bytes_mod_order(&salt);
    let inner = poseidon_hash_two_v05(&root_fr, &Fr::from(epoch));
    let expected = poseidon_hash_two_v05(&inner, &salt_fr);
    assert_eq!(fr_from_be(&bytes), expected);
}

#[test]
fn nostr_sign_then_verify_round_trip() {
    let sk = [0x42u8; 32];
    // Derive pubkey.
    let mut pk_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_nostr_derive_public_key(sk.as_ptr(), sk.len(), &mut pk_buf, &mut err)
    });
    assert_no_error(err, "derive_pk");
    let pk = drain(pk_buf);
    assert_eq!(pk.len(), 32);

    // Sign event id.
    let event_id = [0x55u8; 32];
    let mut sig_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_nostr_sign_event_id(
            sk.as_ptr(),
            sk.len(),
            event_id.as_ptr(),
            event_id.len(),
            &mut sig_buf,
            &mut err,
        )
    });
    assert_no_error(err, "sign");
    let sig = drain(sig_buf);
    assert_eq!(sig.len(), 64);

    // Verify accepts the valid signature.
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_nostr_verify_event_signature(
            pk.as_ptr(),
            pk.len(),
            event_id.as_ptr(),
            event_id.len(),
            sig.as_ptr(),
            sig.len(),
            &mut err,
        )
    });
    assert_no_error(err, "verify_valid");

    // Verify rejects a tampered event id.
    let mut tampered = event_id;
    tampered[0] ^= 0x01;
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_nostr_verify_event_signature(
            pk.as_ptr(),
            pk.len(),
            tampered.as_ptr(),
            tampered.len(),
            sig.as_ptr(),
            sig.len(),
            &mut err,
        )
    };
    assert!(!ok, "tampered event_id verified — verifier is broken");
    assert!(!err.is_null(), "expected error message on verify failure");
    unsafe { onym_string_free(err) };
}

#[test]
fn parse_plonk_proof_strips_length_prefixes() {
    // Build a synthetic 1601-byte buffer with distinctive byte patterns
    // per region; verify the slicer extracts the right ranges.
    let mut proof = vec![0u8; 1601];
    // Length prefix at offset 0 (8 bytes) — would be 5_u64 LE in real proof.
    proof[0] = 5;
    // Wires region — fill with 0x11.
    for b in &mut proof[8..488] {
        *b = 0x11;
    }
    // Prod_perm — 0x22.
    for b in &mut proof[488..584] {
        *b = 0x22;
    }
    // Split_quot prefix.
    proof[584] = 5;
    // Split_quot region — 0x33.
    for b in &mut proof[592..1072] {
        *b = 0x33;
    }
    for b in &mut proof[1072..1168] {
        *b = 0x44;
    }
    for b in &mut proof[1168..1264] {
        *b = 0x55;
    }
    proof[1264] = 5;
    for b in &mut proof[1272..1432] {
        *b = 0x66;
    }
    proof[1432] = 4;
    for b in &mut proof[1440..1568] {
        *b = 0x77;
    }
    for b in &mut proof[1568..1600] {
        *b = 0x88;
    }
    proof[1600] = 0; // plookup_proof: None

    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_parse_plonk_proof(proof.as_ptr(), proof.len(), &mut out, &mut err)
    });
    assert_no_error(err, "parse_proof");
    let bytes = drain(out);
    assert_eq!(bytes.len(), 1568);
    assert!(bytes[0..480].iter().all(|&b| b == 0x11));
    assert!(bytes[480..576].iter().all(|&b| b == 0x22));
    assert!(bytes[576..1056].iter().all(|&b| b == 0x33));
    assert!(bytes[1056..1152].iter().all(|&b| b == 0x44));
    assert!(bytes[1152..1248].iter().all(|&b| b == 0x55));
    assert!(bytes[1248..1408].iter().all(|&b| b == 0x66));
    assert!(bytes[1408..1536].iter().all(|&b| b == 0x77));
    assert!(bytes[1536..1568].iter().all(|&b| b == 0x88));
}

#[test]
fn null_pointer_returns_error_not_panic() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe { onym_compute_leaf_hash(ptr::null(), 32, &mut out, &mut err) };
    assert!(!ok);
    assert!(!err.is_null(), "expected error message for null ptr");
    unsafe { onym_string_free(err) };
}
