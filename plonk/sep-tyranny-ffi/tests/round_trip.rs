use std::ffi::CStr;
use std::ptr;

use ark_bls12_381_v05::Fr;
use ark_ff_v05::{BigInteger, PrimeField};
use ark_serialize_v05::CanonicalDeserialize;
use jf_plonk::proof_system::structs::{Proof, VerifyingKey};

use onym_plonk_prover::circuit::plonk::baker::{
    bake_tyranny_create_vk, bake_tyranny_update_vk,
    pinned_tyranny_create_vk_sha256_hex, pinned_tyranny_update_vk_sha256_hex,
};
use onym_plonk_prover::circuit::plonk::poseidon::{
    poseidon_hash_one_v05, poseidon_hash_two_v05,
};
use onym_plonk_prover::prover::plonk;

use onym_sep_tyranny_ffi::{
    onym_tyranny_bake_create_vk, onym_tyranny_bake_update_vk,
    onym_tyranny_pinned_create_vk_sha256_hex,
    onym_tyranny_pinned_update_vk_sha256_hex, onym_tyranny_prove_create,
    onym_tyranny_prove_update, OnymByteBuffer,
};

const TEST_DEPTH: usize = 5;

fn drain(buf: OnymByteBuffer) -> Vec<u8> {
    assert!(!buf.ptr.is_null());
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

fn pack_leaf_hashes_from_secret_keys(secret_keys: &[Fr]) -> Vec<u8> {
    let mut out = Vec::with_capacity(secret_keys.len() * 32);
    for sk in secret_keys {
        out.extend_from_slice(&fr_be(&poseidon_hash_one_v05(sk)));
    }
    out
}

#[test]
fn bake_create_vk_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe { onym_tyranny_bake_create_vk(TEST_DEPTH, &mut out, &mut err) });
    assert_no_error(err, "bake_create_vk");
    let ffi = drain(out);
    let native = bake_tyranny_create_vk(TEST_DEPTH).expect("native bake");
    assert_eq!(ffi, native);
}

#[test]
fn bake_update_vk_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe { onym_tyranny_bake_update_vk(TEST_DEPTH, &mut out, &mut err) });
    assert_no_error(err, "bake_update_vk");
    let ffi = drain(out);
    let native = bake_tyranny_update_vk(TEST_DEPTH).expect("native bake");
    assert_eq!(ffi, native);
}

#[test]
fn pinned_create_vk_hex_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_tyranny_pinned_create_vk_sha256_hex(TEST_DEPTH, &mut out, &mut err)
    });
    assert_no_error(err, "pinned_create_vk_hex");
    let hex = String::from_utf8(drain(out)).unwrap();
    assert_eq!(
        hex,
        pinned_tyranny_create_vk_sha256_hex(TEST_DEPTH).expect("pinned")
    );
}

#[test]
fn pinned_update_vk_hex_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe {
        onym_tyranny_pinned_update_vk_sha256_hex(TEST_DEPTH, &mut out, &mut err)
    });
    assert_no_error(err, "pinned_update_vk_hex");
    let hex = String::from_utf8(drain(out)).unwrap();
    assert_eq!(
        hex,
        pinned_tyranny_update_vk_sha256_hex(TEST_DEPTH).expect("pinned")
    );
}

#[test]
fn prove_create_then_verify_against_baked_vk() {
    let secret_keys: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let admin_index = 0usize;
    let admin_sk_be = fr_be(&secret_keys[admin_index]);
    let group_id_fr = Fr::from(0x7777u64);
    let group_id_be = fr_be(&group_id_fr);
    let salt = [0xEEu8; 32];

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut pi_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_tyranny_prove_create(
            TEST_DEPTH,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            admin_sk_be.as_ptr(),
            admin_sk_be.len(),
            admin_index,
            group_id_be.as_ptr(),
            group_id_be.len(),
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            &mut pi_buf,
            &mut err,
        )
    };
    assert!(ok);
    assert_no_error(err, "prove_create");

    let proof_bytes = drain(proof_buf);
    let pi_bytes = drain(pi_buf);
    assert_eq!(proof_bytes.len(), 1601);
    assert_eq!(pi_bytes.len(), 128);

    let commitment = fr_from_be(&pi_bytes[0..32]);
    let pi_epoch = fr_from_be(&pi_bytes[32..64]);
    let admin_comm = fr_from_be(&pi_bytes[64..96]);
    let group_id_pi = fr_from_be(&pi_bytes[96..128]);
    assert_eq!(pi_epoch, Fr::from(0u64));
    assert_eq!(group_id_pi, group_id_fr);

    // Sanity: admin_comm = Poseidon(Poseidon(admin_sk), group_id_fr).
    let expected_admin_comm = poseidon_hash_two_v05(
        &poseidon_hash_one_v05(&secret_keys[admin_index]),
        &group_id_fr,
    );
    assert_eq!(admin_comm, expected_admin_comm);

    let vk_bytes = bake_tyranny_create_vk(TEST_DEPTH).expect("bake");
    let vk: VerifyingKey<ark_bls12_381_v05::Bls12_381> =
        VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).expect("vk");
    let proof: Proof<ark_bls12_381_v05::Bls12_381> =
        Proof::deserialize_uncompressed(&proof_bytes[..]).expect("proof");
    plonk::verify(
        &vk,
        &[commitment, pi_epoch, admin_comm, group_id_pi],
        &proof,
    )
    .expect("FFI tyranny-create proof must verify under freshly-baked VK");
}

#[test]
fn prove_update_then_verify_against_baked_vk() {
    let secret_keys: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let admin_index_old = 0usize;
    let admin_sk_be = fr_be(&secret_keys[admin_index_old]);
    let epoch_old = 1234u64;
    let group_id_fr = Fr::from(0x7777u64);
    let group_id_be = fr_be(&group_id_fr);
    let salt_old = [0xEEu8; 32];
    let salt_new = [0xFFu8; 32];

    // Compute member_root_new natively (here = old root, since roster
    // unchanged).
    let leaves: Vec<Fr> = secret_keys.iter().map(poseidon_hash_one_v05).collect();
    let num_leaves = 1usize << TEST_DEPTH;
    let mut nodes = vec![Fr::from(0u64); 2 * num_leaves];
    for (i, leaf) in leaves.iter().enumerate() {
        nodes[num_leaves + i] = *leaf;
    }
    for i in (1..num_leaves).rev() {
        nodes[i] = poseidon_hash_two_v05(&nodes[2 * i], &nodes[2 * i + 1]);
    }
    let member_root_new = nodes[1];
    let member_root_new_be = fr_be(&member_root_new);

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut pi_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_tyranny_prove_update(
            TEST_DEPTH,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            admin_sk_be.as_ptr(),
            admin_sk_be.len(),
            admin_index_old,
            epoch_old,
            member_root_new_be.as_ptr(),
            member_root_new_be.len(),
            group_id_be.as_ptr(),
            group_id_be.len(),
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
    assert_eq!(pi_bytes.len(), 160);

    let c_old = fr_from_be(&pi_bytes[0..32]);
    let pi_epoch = fr_from_be(&pi_bytes[32..64]);
    let c_new = fr_from_be(&pi_bytes[64..96]);
    let admin_comm = fr_from_be(&pi_bytes[96..128]);
    let group_id_pi = fr_from_be(&pi_bytes[128..160]);
    assert_eq!(pi_epoch, Fr::from(epoch_old));
    assert_eq!(group_id_pi, group_id_fr);

    let vk_bytes = bake_tyranny_update_vk(TEST_DEPTH).expect("bake");
    let vk: VerifyingKey<ark_bls12_381_v05::Bls12_381> =
        VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).expect("vk");
    let proof: Proof<ark_bls12_381_v05::Bls12_381> =
        Proof::deserialize_uncompressed(&proof_bytes[..]).expect("proof");
    plonk::verify(
        &vk,
        &[c_old, pi_epoch, c_new, admin_comm, group_id_pi],
        &proof,
    )
    .expect("FFI tyranny-update proof must verify under freshly-baked VK");
}

#[test]
fn prove_create_rejects_unsupported_tier() {
    // Audit Finding 1 regression: prove_* must restrict depth to the
    // three tiers an on-chain VK exists for (5/8/11). See
    // sep-anarchy-ffi's analogous test for the full rationale.
    let secret_keys: Vec<Fr> = (1u64..=4).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    let admin_sk_be = fr_be(&secret_keys[0]);
    let group_id_be = fr_be(&Fr::from(0x7777u64));
    let salt = [0u8; 32];

    for bad_depth in [0usize, 1, 4, 6, 7, 9, 10, 12, 16, 31] {
        let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
        let mut pi_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
        let mut err: *mut std::os::raw::c_char = ptr::null_mut();
        let ok = unsafe {
            onym_tyranny_prove_create(
                bad_depth,
                leaves_packed.as_ptr(),
                leaves_packed.len(),
                admin_sk_be.as_ptr(),
                admin_sk_be.len(),
                0,
                group_id_be.as_ptr(),
                group_id_be.len(),
                salt.as_ptr(),
                salt.len(),
                &mut proof_buf,
                &mut pi_buf,
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
fn prove_create_rejects_mismatched_admin_secret_key() {
    let secret_keys: Vec<Fr> = (1u64..=8).map(Fr::from).collect();
    let leaves_packed = pack_leaf_hashes_from_secret_keys(&secret_keys);
    // Lie: claim to be admin_index=0 but supply secret_keys[3].
    let wrong_sk_be = fr_be(&secret_keys[3]);
    let group_id_be = fr_be(&Fr::from(0x7777u64));
    let salt = [0u8; 32];

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut pi_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_tyranny_prove_create(
            TEST_DEPTH,
            leaves_packed.as_ptr(),
            leaves_packed.len(),
            wrong_sk_be.as_ptr(),
            wrong_sk_be.len(),
            0, // admin_index
            group_id_be.as_ptr(),
            group_id_be.len(),
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            &mut pi_buf,
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
