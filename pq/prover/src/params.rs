//! Bench-scope FRI parameters. **Must match** the constants in
//! `pq/sep-anarchy/src/lib.rs::build_vk_bytes`.
//!
//! If these drift apart, every proof this prover emits will fail the
//! on-chain verifier's `BadShape` / transcript-divergence check.

use fri_verifier::field::Fr;
use fri_verifier::merkle::Digest;
use fri_verifier::vk_format::VK_LEN;

pub const LOG_N: u32 = 6;
pub const NUM_LAYERS: u32 = 3;
pub const NUM_QUERIES: u32 = 8;
pub const BLOWUP_LOG: u32 = 1;

/// Initial domain size: 2^LOG_N.
pub const N_INITIAL: usize = 1 << LOG_N;
/// Final-layer domain size: 2^(LOG_N - NUM_LAYERS).
pub const N_FINAL: usize = 1 << (LOG_N - NUM_LAYERS);

/// Membership circuit: `(commitment, epoch)` × 8 BabyBear lanes per PI.
pub const MEMBERSHIP_NUM_PI: u32 = 16;
/// Update circuit: `(c_old, epoch_old, c_new)` × 8 lanes per PI.
pub const UPDATE_NUM_PI: u32 = 24;

/// `omega_0` — primitive 2^LOG_N-th root of unity in BabyBear:
/// `31^((p-1)/64) mod p` for LOG_N=6.
pub const OMEGA_0: Fr = Fr(0x669D6090);
/// `omega_0^{-1} mod p`.
pub const OMEGA_0_INV: Fr = Fr(0x27785FBF);
/// `2^{-1} mod p = (p+1)/2`.
pub const TWO_INV: Fr = Fr(0x3C000001);

/// 8-lane `pcs_pinned_root` placeholder, identical to the contract's
/// embedded VK: `{1, 2, …, 8}`.
pub const PCS_PINNED_ROOT: Digest = [
    Fr(1), Fr(2), Fr(3), Fr(4), Fr(5), Fr(6), Fr(7), Fr(8),
];

/// Build the 64-byte VK exactly as the contract does. Used by the
/// prover to reconstruct the same bytes the verifier sees, so the
/// transcript binding agrees on both sides.
pub fn vk_bytes(num_pi: u32) -> [u8; VK_LEN] {
    let mut b = [0u8; VK_LEN];
    b[0..4].copy_from_slice(&LOG_N.to_le_bytes());
    b[4..8].copy_from_slice(&NUM_LAYERS.to_le_bytes());
    b[8..12].copy_from_slice(&NUM_QUERIES.to_le_bytes());
    b[12..16].copy_from_slice(&num_pi.to_le_bytes());
    b[16..20].copy_from_slice(&BLOWUP_LOG.to_le_bytes());
    for (i, lane) in PCS_PINNED_ROOT.iter().enumerate() {
        let off = 20 + i * 4;
        b[off..off + 4].copy_from_slice(&lane.to_le_bytes());
    }
    b[52..56].copy_from_slice(&OMEGA_0.to_le_bytes());
    b[56..60].copy_from_slice(&OMEGA_0_INV.to_le_bytes());
    b[60..64].copy_from_slice(&TWO_INV.to_le_bytes());
    b
}

/// Sanity tests so a typo in any constant fails at build time, not
/// silently at proof-verify time.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omega_0_has_order_64() {
        assert_eq!(OMEGA_0.pow(N_INITIAL as u64), Fr::ONE);
        // Not order 32 — strict primitive 64-th root.
        assert_ne!(OMEGA_0.pow((N_INITIAL / 2) as u64), Fr::ONE);
    }

    #[test]
    fn omega_0_inv_inverts() {
        assert_eq!(OMEGA_0 * OMEGA_0_INV, Fr::ONE);
    }

    #[test]
    fn two_inv_inverts() {
        assert_eq!(Fr::new(2) * TWO_INV, Fr::ONE);
    }

    #[test]
    fn vk_bytes_round_trips_through_verifier_parser() {
        let bytes = vk_bytes(MEMBERSHIP_NUM_PI);
        let vk = fri_verifier::vk_format::parse_vk_bytes(&bytes).expect("parse vk");
        assert_eq!(vk.log_n, LOG_N);
        assert_eq!(vk.num_layers, NUM_LAYERS);
        assert_eq!(vk.num_queries, NUM_QUERIES);
        assert_eq!(vk.num_pi, MEMBERSHIP_NUM_PI);
        assert_eq!(vk.blowup_log, BLOWUP_LOG);
        assert_eq!(vk.omega_0, OMEGA_0);
        assert_eq!(vk.omega_0_inv, OMEGA_0_INV);
        assert_eq!(vk.two_inv, TWO_INV);
        assert_eq!(vk.pcs_pinned_root, PCS_PINNED_ROOT);
    }
}
