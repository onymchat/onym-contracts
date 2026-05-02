//! Verifying-key byte layout for the FRI flavor.
//!
//! ## Layout (all little-endian, packed)
//!
//! ```text
//!   offset  size  field
//!   ------  ----  --------------------------------------------------
//!     0      4    log_n               u32   initial domain log-size
//!     4      4    num_layers          u32   FRI fold-step count
//!     8      4    num_queries         u32   FRI query count
//!    12      4    num_pi              u32   public-input count
//!    16      4    blowup_log          u32   log2(rate^-1) = blowup
//!    20     32    pcs_pinned_root     [Fr;8] preprocessed-trace root
//!    52      4    omega_0             u32   domain generator
//!    56      4    omega_0_inv         u32   precomputed ω₀⁻¹
//!    60      4    two_inv             u32   precomputed 1/2 mod P
//!   ----    ----
//!    64           VK_LEN
//! ```
//!
//! `pcs_pinned_root` is the per-circuit preprocessed-poly Merkle root
//! (the constant pre-committed columns of the AIR — a stable function
//! of the constraint system, baked at circuit-design time). When the
//! batched-PCS layer lands on top of this verifier, that layer mixes
//! `pcs_pinned_root` into the transcript so a proof for one circuit
//! cannot be replayed against another's VK with the same `log_n`.

use crate::field::{Fr, P};
use crate::merkle::{Digest, DIGEST_LEN};

pub const VK_LEN: usize = 64;

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

/// Parse the canonical 64-byte VK.
pub fn parse_vk_bytes(bytes: &[u8]) -> Result<ParsedVerifyingKey, VkParseError> {
    if bytes.len() != VK_LEN {
        return Err(VkParseError::BadLength);
    }
    let log_n = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
    let num_layers = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
    let num_queries = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let num_pi = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
    let blowup_log = u32::from_le_bytes(bytes[16..20].try_into().unwrap());

    // Sanity gates: log_n ≥ num_layers (cannot fold more times than
    // the domain halves to size 1); num_queries / num_layers / log_n
    // bounded so a malformed VK can't make the verifier loop forever.
    if log_n > 32 || num_layers > log_n || num_queries > 256 || num_pi > 64 {
        return Err(VkParseError::BadParam);
    }

    let mut pcs_pinned_root: Digest = [Fr::ZERO; DIGEST_LEN];
    for i in 0..DIGEST_LEN {
        let off = 20 + i * 4;
        let v = u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
        if v >= P {
            return Err(VkParseError::NonCanonicalField);
        }
        pcs_pinned_root[i] = Fr(v);
    }

    let omega_0 = decode_fr(&bytes[52..56])?;
    let omega_0_inv = decode_fr(&bytes[56..60])?;
    let two_inv = decode_fr(&bytes[60..64])?;

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

fn decode_fr(bytes: &[u8]) -> Result<Fr, VkParseError> {
    let v = u32::from_le_bytes(bytes.try_into().unwrap());
    if v >= P {
        return Err(VkParseError::NonCanonicalField);
    }
    Ok(Fr(v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn synthetic_vk_bytes() -> [u8; VK_LEN] {
        let mut b = [0u8; VK_LEN];
        b[0..4].copy_from_slice(&15u32.to_le_bytes()); // log_n
        b[4..8].copy_from_slice(&10u32.to_le_bytes()); // num_layers
        b[8..12].copy_from_slice(&80u32.to_le_bytes()); // num_queries
        b[12..16].copy_from_slice(&2u32.to_le_bytes()); // num_pi
        b[16..20].copy_from_slice(&1u32.to_le_bytes()); // blowup_log
        // pcs_pinned_root: 8 small Fr values
        for i in 0..DIGEST_LEN {
            let off = 20 + i * 4;
            b[off..off + 4].copy_from_slice(&((i as u32) + 1).to_le_bytes());
        }
        b[52..56].copy_from_slice(&3u32.to_le_bytes()); // omega_0
        b[56..60].copy_from_slice(&Fr::new(3).inverse().0.to_le_bytes());
        b[60..64].copy_from_slice(&Fr::new(2).inverse().0.to_le_bytes());
        b
    }

    #[test]
    fn parses_canonical_vk() {
        let bytes = synthetic_vk_bytes();
        let vk = parse_vk_bytes(&bytes).expect("parse");
        assert_eq!(vk.log_n, 15);
        assert_eq!(vk.num_layers, 10);
        assert_eq!(vk.num_queries, 80);
        assert_eq!(vk.num_pi, 2);
        assert_eq!(vk.omega_0, Fr::new(3));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(
            parse_vk_bytes(&[0u8; 16]),
            Err(VkParseError::BadLength),
        );
    }

    #[test]
    fn rejects_log_n_over_max() {
        let mut b = synthetic_vk_bytes();
        b[0..4].copy_from_slice(&64u32.to_le_bytes());
        assert_eq!(parse_vk_bytes(&b), Err(VkParseError::BadParam));
    }

    #[test]
    fn rejects_num_layers_exceeding_log_n() {
        let mut b = synthetic_vk_bytes();
        b[4..8].copy_from_slice(&20u32.to_le_bytes());
        b[0..4].copy_from_slice(&10u32.to_le_bytes());
        assert_eq!(parse_vk_bytes(&b), Err(VkParseError::BadParam));
    }

    #[test]
    fn rejects_non_canonical_omega() {
        let mut b = synthetic_vk_bytes();
        b[52..56].copy_from_slice(&P.to_le_bytes());
        assert_eq!(parse_vk_bytes(&b), Err(VkParseError::NonCanonicalField));
    }
}
