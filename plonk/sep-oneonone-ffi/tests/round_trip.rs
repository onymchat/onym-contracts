use std::ffi::CStr;
use std::ptr;

use ark_bls12_381_v05::Fr;
use ark_ff_v05::{BigInteger, PrimeField};
use ark_serialize_v05::CanonicalDeserialize;
use jf_plonk::proof_system::structs::{Proof, VerifyingKey};

use onym_plonk_prover::circuit::plonk::baker::bake_oneonone_create_vk;
use onym_plonk_prover::prover::plonk;

use onym_sep_oneonone_ffi::{
    onym_oneonone_bake_create_vk, onym_oneonone_prove_create, OnymByteBuffer,
};

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

#[test]
fn bake_create_vk_matches_native() {
    let mut out = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    assert!(unsafe { onym_oneonone_bake_create_vk(&mut out, &mut err) });
    assert_no_error(err, "bake_create_vk");
    let ffi = drain(out);
    let native = bake_oneonone_create_vk().expect("native bake");
    assert_eq!(ffi, native);
}

#[test]
fn prove_create_rejects_identical_secret_keys() {
    // Audit Finding 2 regression: 1v1 founding requires two distinct
    // members. The upstream circuit doesn't enforce this — a single
    // member could supply sk_0 == sk_1 and produce a valid
    // proof/commitment for a "1v1 group" with one member in both
    // slots. The FFI must reject up-front.
    let same_sk_be = Fr::from(42u64).into_bigint().to_bytes_be();
    let salt = [0xEEu8; 32];

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut commit_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_oneonone_prove_create(
            same_sk_be.as_ptr(),
            same_sk_be.len(),
            same_sk_be.as_ptr(), // same secret key in both slots
            same_sk_be.len(),
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            &mut commit_buf,
            &mut err,
        )
    };
    assert!(!ok, "prove_create must reject sk_0 == sk_1");
    assert!(!err.is_null());
    let msg = unsafe { CStr::from_ptr(err) }.to_string_lossy().into_owned();
    assert!(
        msg.contains("distinct") || msg.contains("=="),
        "expected distinct-members error, got: {msg}"
    );
    let _ = unsafe { std::ffi::CString::from_raw(err) };
}

#[test]
fn prove_create_then_verify_against_baked_vk() {
    let sk_0_be = Fr::from(1u64).into_bigint().to_bytes_be();
    let sk_1_be = Fr::from(2u64).into_bigint().to_bytes_be();
    let salt = [0xEEu8; 32];

    let mut proof_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut commit_buf = OnymByteBuffer { ptr: ptr::null_mut(), len: 0 };
    let mut err: *mut std::os::raw::c_char = ptr::null_mut();
    let ok = unsafe {
        onym_oneonone_prove_create(
            sk_0_be.as_ptr(),
            sk_0_be.len(),
            sk_1_be.as_ptr(),
            sk_1_be.len(),
            salt.as_ptr(),
            salt.len(),
            &mut proof_buf,
            &mut commit_buf,
            &mut err,
        )
    };
    assert!(ok);
    assert_no_error(err, "prove_create");

    let proof_bytes = drain(proof_buf);
    let commitment_bytes = drain(commit_buf);
    assert_eq!(proof_bytes.len(), 1601);
    assert_eq!(commitment_bytes.len(), 32);
    let commitment = Fr::from_be_bytes_mod_order(&commitment_bytes);

    let vk_bytes = bake_oneonone_create_vk().expect("bake");
    let vk: VerifyingKey<ark_bls12_381_v05::Bls12_381> =
        VerifyingKey::deserialize_uncompressed(&vk_bytes[..]).expect("deserialise vk");
    let proof: Proof<ark_bls12_381_v05::Bls12_381> =
        Proof::deserialize_uncompressed(&proof_bytes[..]).expect("deserialise proof");
    plonk::verify(&vk, &[commitment, Fr::from(0u64)], &proof)
        .expect("FFI proof must verify under freshly-baked oneonone VK");
}
