//! Verifying-key byte layout for the BN254-based FRI flavor.
//!
//! ## Layout (all big-endian, packed)
//!
//! ```text
//!   offset  size   field
//!   ------  ----   --------------------------------------------------
//!     0      4     log_n              u32 LE   initial domain log-size
//!     4      4     num_layers         u32 LE   FRI fold-step count
//!     8      4     num_queries        u32 LE   FRI query count
//!    12      4     num_pi             u32 LE   public-input count
//!    16      4     blowup_log         u32 LE   log2(rate^-1) = blowup
//!    20     32     pcs_pinned_root    BN254 Fr BE — preprocessed-trace root
//!    52     32     omega_0            BN254 Fr BE — domain generator
//!    84     32     omega_0_inv        BN254 Fr BE — precomputed ω₀⁻¹
//!   116     32     two_inv            BN254 Fr BE — precomputed ½
//!   ----    ----
//!   148           VK_LEN
//! ```
//!
//! Field elements are 32-byte big-endian, matching the BN254 Fr
//! `to_bytes` convention. The header u32s are little-endian for
//! parser cheapness.
//!
//! `pcs_pinned_root` is the preprocessed-trace Merkle root — for
//! the FRI-only verifier today it's mixed into the transcript as
//! domain separation; once the PCS layer lands it'll bind the
//! verifier to a specific circuit.

use crate::field::{self, Fr};
use crate::merkle::Digest;
use soroban_sdk::Env;

pub const VK_LEN: usize = 148;
const FR_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedVerifyingKey {
    pub log_n: u32,
    pub num_layers: u32,
    pub num_queries: u32,
    pub num_pi: u32,
    pub blowup_log: u32,
    pub pcs_pinned_root: Digest,
    pub omega_0: Fr,
    pub omega_0_inv: Fr,
    pub two_inv: Fr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum VkParseError {
    BadLength,
    NonCanonicalField,
    BadParam,
}

pub fn parse_vk_bytes(env: &Env, bytes: &[u8]) -> Result<ParsedVerifyingKey, VkParseError> {
    if bytes.len() != VK_LEN {
        return Err(VkParseError::BadLength);
    }
    let log_n = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let num_layers = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let num_queries = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let num_pi = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let blowup_log = u32::from_le_bytes(bytes[16..20].try_into().unwrap());

    // Sanity: log_n ≥ num_layers, bounded counts so a malformed VK
    // can't make the verifier loop forever or allocate enormous Vecs.
    if log_n > 32 || num_layers > log_n || num_queries > 256 || num_pi > 64 {
        return Err(VkParseError::BadParam);
    }

    let pcs_pinned_root = decode_fr(env, &bytes[20..52])?;
    let omega_0 = decode_fr(env, &bytes[52..84])?;
    let omega_0_inv = decode_fr(env, &bytes[84..116])?;
    let two_inv = decode_fr(env, &bytes[116..148])?;

    Ok(ParsedVerifyingKey {
        log_n,
        num_layers,
        num_queries,
        num_pi,
        blowup_log,
        pcs_pinned_root,
        omega_0,
        omega_0_inv,
        two_inv,
    })
}

fn decode_fr(env: &Env, bytes: &[u8]) -> Result<Fr, VkParseError> {
    let arr: [u8; FR_LEN] = bytes
        .try_into()
        .map_err(|_| VkParseError::BadLength)?;
    if !field::is_canonical_be(env, &arr) {
        return Err(VkParseError::NonCanonicalField);
    }
    Ok(field::from_be_bytes(env, &arr))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_vk_bytes(env: &Env) -> [u8; VK_LEN] {
        let mut b = [0u8; VK_LEN];
        b[0..4].copy_from_slice(&15u32.to_le_bytes());
        b[4..8].copy_from_slice(&10u32.to_le_bytes());
        b[8..12].copy_from_slice(&80u32.to_le_bytes());
        b[12..16].copy_from_slice(&2u32.to_le_bytes());
        b[16..20].copy_from_slice(&1u32.to_le_bytes());
        // pcs_pinned_root: small canonical Fr (BE-encoded `1`)
        b[51] = 0x01;
        // omega_0 = 3
        b[83] = 0x03;
        // omega_0_inv = 3^-1 mod r — derive at test time
        let three_inv = field::from_u32(env, 3).inv();
        let three_inv_bytes = field::to_be_bytes(&three_inv);
        b[84..116].copy_from_slice(&three_inv_bytes);
        // two_inv
        let two_inv = field::from_u32(env, 2).inv();
        let two_inv_bytes = field::to_be_bytes(&two_inv);
        b[116..148].copy_from_slice(&two_inv_bytes);
        b
    }

    #[test]
    fn parses_canonical_vk() {
        let env = Env::default();
        let bytes = synthetic_vk_bytes(&env);
        let vk = parse_vk_bytes(&env, &bytes).expect("parse");
        assert_eq!(vk.log_n, 15);
        assert_eq!(vk.num_layers, 10);
        assert_eq!(vk.num_queries, 80);
        assert_eq!(vk.num_pi, 2);
        assert_eq!(vk.omega_0, field::from_u32(&env, 3));
    }

    #[test]
    fn rejects_wrong_length() {
        let env = Env::default();
        assert_eq!(
            parse_vk_bytes(&env, &[0u8; 16]),
            Err(VkParseError::BadLength),
        );
    }

    #[test]
    fn rejects_log_n_over_max() {
        let env = Env::default();
        let mut b = synthetic_vk_bytes(&env);
        b[0..4].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(parse_vk_bytes(&env, &b), Err(VkParseError::BadParam));
    }

    #[test]
    fn rejects_num_layers_exceeding_log_n() {
        let env = Env::default();
        let mut b = synthetic_vk_bytes(&env);
        b[4..8].copy_from_slice(&20u32.to_le_bytes());
        b[0..4].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(parse_vk_bytes(&env, &b), Err(VkParseError::BadParam));
    }

    #[test]
    fn rejects_non_canonical_omega() {
        let env = Env::default();
        let mut b = synthetic_vk_bytes(&env);
        // Modulus itself is non-canonical.
        b[52..84].copy_from_slice(&field::BN254_FR_MODULUS_BE);
        assert_eq!(parse_vk_bytes(&env, &b), Err(VkParseError::NonCanonicalField));
    }
}
