//! BN254 scalar field — the verifier's canonical field type.
//!
//! ## Why BN254
//!
//! Production-ready PQ-shape FRI on Soroban is constrained by the
//! host primitive surface: `env.crypto().poseidon2_permutation(...)`
//! supports only `BLS12_381` and `BN254` fields. BabyBear (the
//! Plonky3-canonical choice for FRI) has no host primitive — pure
//! WASM Poseidon2 over BabyBear is computable but un-host-accelerated
//! and would never approach production cost. BN254 gives us:
//!
//! - host-accelerated `fr_add` / `fr_sub` / `fr_mul` / `fr_pow` /
//!   `fr_inv` (one host call per op vs. tens of WASM instructions),
//! - host-accelerated Poseidon2 with vendored Horizen Labs constants
//!   (one host call per permutation vs. hundreds of WASM instructions),
//! - a 254-bit field, so soundness is ~127 bits without an extension
//!   tower (compare to BabyBear, which needs `BabyBear^4` for the
//!   same security floor).
//!
//! The trade-off is element width: each `Fr` is 32 bytes vs. 4 bytes
//! for BabyBear. Proofs are ~8x larger byte-for-byte, but the host
//! primitives are roughly the same per-op latency regardless of
//! field size, so total verifier time is dominated by the host-call
//! count rather than the per-element work.
//!
//! ## Encoding
//!
//! All `Fr` byte serialisation is **big-endian** to match
//! `Fr::from_bytes` / `Fr::to_bytes` in the soroban SDK and the
//! host's BN254 surface. Public-input slices in the contract layer
//! are `BytesN<32>` BE — same convention as the PLONK flavor's
//! existing PI shape, so client code that already targets the PLONK
//! contracts can target the FRI flavor without re-encoding.

pub use soroban_sdk::crypto::bn254::Fr;
use soroban_sdk::{Bytes, BytesN, Env, U256};

/// Construct the canonical zero element.
///
/// `Fr::from(U256::from_u32(env, 0))` — host call to construct U256,
/// then host call to reduce mod r. Cheap but not free; cache when
/// reused across many ops.
#[inline]
pub fn zero(env: &Env) -> Fr {
    Fr::from(U256::from_u32(env, 0))
}

/// Construct the canonical one element.
#[inline]
pub fn one(env: &Env) -> Fr {
    Fr::from(U256::from_u32(env, 1))
}

/// Construct an `Fr` from a small `u32`. Useful for round indices,
/// shape constants, etc.
#[inline]
pub fn from_u32(env: &Env, v: u32) -> Fr {
    Fr::from(U256::from_u32(env, v))
}

/// Decode 32 BE bytes into an `Fr`. Inputs `>= r` are silently
/// reduced modulo r by `From<U256>`. The contract layer should
/// reject non-canonical PIs before calling here so callers never
/// observe the reduction case (otherwise two distinct on-the-wire
/// values would collide to the same field element).
#[inline]
pub fn from_be_bytes(env: &Env, bytes: &[u8; 32]) -> Fr {
    Fr::from_bytes(BytesN::from_array(env, bytes))
}

/// Encode an `Fr` to 32 BE bytes.
#[inline]
pub fn to_be_bytes(fr: &Fr) -> [u8; 32] {
    fr.to_bytes().to_array()
}

/// Test whether the BE-encoded value `bytes` is canonical (`< r`).
/// The contract surface uses this to reject non-canonical PIs at
/// the boundary so the verifier can assume in-range elements.
pub fn is_canonical_be(env: &Env, bytes: &[u8; 32]) -> bool {
    let v = U256::from_be_bytes(env, &Bytes::from_array(env, bytes));
    v < BN254_FR_MODULUS_U256(env)
}

/// BN254 scalar field modulus r in big-endian bytes.
/// `r = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001`.
pub const BN254_FR_MODULUS_BE: [u8; 32] = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
    0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91,
    0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

#[allow(non_snake_case)]
#[inline]
fn BN254_FR_MODULUS_U256(env: &Env) -> U256 {
    U256::from_be_bytes(env, &Bytes::from_array(env, &BN254_FR_MODULUS_BE))
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    #[test]
    fn zero_one_distinct() {
        let env = Env::default();
        assert_ne!(zero(&env), one(&env));
    }

    #[test]
    fn zero_plus_one_is_one() {
        let env = Env::default();
        assert_eq!(zero(&env) + one(&env), one(&env));
    }

    #[test]
    fn one_times_one_is_one() {
        let env = Env::default();
        assert_eq!(one(&env) * one(&env), one(&env));
    }

    #[test]
    fn round_trip_be_bytes() {
        let env = Env::default();
        let mut bytes = [0u8; 32];
        bytes[31] = 0x42;
        bytes[30] = 0x13;
        let fr = from_be_bytes(&env, &bytes);
        assert_eq!(to_be_bytes(&fr), bytes);
    }

    #[test]
    fn modulus_minus_one_is_canonical() {
        let env = Env::default();
        let mut bytes = BN254_FR_MODULUS_BE;
        bytes[31] = 0x00; // r - 1 still has the same high bits.
        assert!(is_canonical_be(&env, &bytes));
    }

    #[test]
    fn modulus_itself_is_not_canonical() {
        let env = Env::default();
        assert!(!is_canonical_be(&env, &BN254_FR_MODULUS_BE));
    }

    #[test]
    fn pow_zero_is_one() {
        let env = Env::default();
        let v = from_u32(&env, 12345);
        assert_eq!(v.pow(0), one(&env));
    }

    #[test]
    fn inverse_round_trip() {
        let env = Env::default();
        let v = from_u32(&env, 7);
        assert_eq!(v.clone() * v.inv(), one(&env));
    }
}
