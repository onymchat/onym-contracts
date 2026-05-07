//! Bench-scope FRI parameters. **Must match** the constants in
//! `pq/sep-anarchy/src/lib.rs::build_vk_bytes` exactly — if these
//! drift, every proof this prover emits will fail the verifier's
//! transcript-divergence check.

use fri_verifier::field::{self, Fr};
use fri_verifier::merkle::Digest;
use fri_verifier::vk_format::VK_LEN;
use soroban_sdk::Env;

pub const LOG_N: u32 = 6;
pub const NUM_LAYERS: u32 = 3;
pub const NUM_QUERIES: u32 = 8;
pub const BLOWUP_LOG: u32 = 1;

pub const N_INITIAL: usize = 1 << LOG_N;
pub const N_FINAL: usize = 1 << (LOG_N - NUM_LAYERS);

pub const MEMBERSHIP_NUM_PI: u32 = 2;
pub const UPDATE_NUM_PI: u32 = 3;

/// `omega_0` BE: primitive 64-th root of unity in BN254
/// (= `5^((r-1)/64) mod r`).
pub const OMEGA_0_BE: [u8; 32] = [
    0x14, 0x18, 0x14, 0x4d, 0x5b, 0x08, 0x0f, 0xca,
    0xc2, 0x4c, 0xdb, 0x76, 0x49, 0xbd, 0xad, 0xf2,
    0x46, 0xa6, 0xcb, 0x24, 0x26, 0xe3, 0x24, 0xbe,
    0xdb, 0x94, 0xfb, 0x05, 0x11, 0x8f, 0x02, 0x3a,
];
pub const OMEGA_0_INV_BE: [u8; 32] = [
    0x26, 0x17, 0x7c, 0xf2, 0xb2, 0xa1, 0x3d, 0x3a,
    0x03, 0x5c, 0xdc, 0x75, 0x67, 0xa8, 0xa6, 0x76,
    0xd8, 0x03, 0x96, 0xec, 0x1d, 0x32, 0x13, 0xee,
    0x78, 0xce, 0x6a, 0x0b, 0x76, 0x3d, 0x69, 0x8f,
];
pub const TWO_INV_BE: [u8; 32] = [
    0x18, 0x32, 0x27, 0x39, 0x70, 0x98, 0xd0, 0x14,
    0xdc, 0x28, 0x22, 0xdb, 0x40, 0xc0, 0xac, 0x2e,
    0x94, 0x19, 0xf4, 0x24, 0x3c, 0xdc, 0xb8, 0x48,
    0xa1, 0xf0, 0xfa, 0xc9, 0xf8, 0x00, 0x00, 0x01,
];

/// `pcs_pinned_root` placeholder — must match the contract.
pub const PCS_PINNED_ROOT_BE: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

pub fn omega_0(env: &Env) -> Fr {
    field::from_be_bytes(env, &OMEGA_0_BE)
}
pub fn omega_0_inv(env: &Env) -> Fr {
    field::from_be_bytes(env, &OMEGA_0_INV_BE)
}
pub fn two_inv(env: &Env) -> Fr {
    field::from_be_bytes(env, &TWO_INV_BE)
}
pub fn pcs_pinned_root(env: &Env) -> Digest {
    field::from_be_bytes(env, &PCS_PINNED_ROOT_BE)
}

/// Build the 148-byte VK exactly as the contract does. Used by the
/// prover to reconstruct the same bytes the verifier sees, so the
/// transcript binding agrees on both sides.
pub fn vk_bytes(num_pi: u32) -> [u8; VK_LEN] {
    let mut b = [0u8; VK_LEN];
    b[0..4].copy_from_slice(&LOG_N.to_le_bytes());
    b[4..8].copy_from_slice(&NUM_LAYERS.to_le_bytes());
    b[8..12].copy_from_slice(&NUM_QUERIES.to_le_bytes());
    b[12..16].copy_from_slice(&num_pi.to_le_bytes());
    b[16..20].copy_from_slice(&BLOWUP_LOG.to_le_bytes());
    b[20..52].copy_from_slice(&PCS_PINNED_ROOT_BE);
    b[52..84].copy_from_slice(&OMEGA_0_BE);
    b[84..116].copy_from_slice(&OMEGA_0_INV_BE);
    b[116..148].copy_from_slice(&TWO_INV_BE);
    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn omega_0_has_order_64() {
        let env = Env::default();
        let one = field::one(&env);
        let w = omega_0(&env);
        assert_eq!(w.pow(N_INITIAL as u64), one);
        assert_ne!(w.pow((N_INITIAL / 2) as u64), one);
    }

    #[test]
    fn omega_0_inv_inverts() {
        let env = Env::default();
        assert_eq!(omega_0(&env) * omega_0_inv(&env), field::one(&env));
    }

    #[test]
    fn two_inv_inverts() {
        let env = Env::default();
        assert_eq!(field::from_u32(&env, 2) * two_inv(&env), field::one(&env));
    }

    #[test]
    fn vk_bytes_round_trips_through_verifier_parser() {
        let env = Env::default();
        let bytes = vk_bytes(MEMBERSHIP_NUM_PI);
        let vk = fri_verifier::vk_format::parse_vk_bytes(&env, &bytes).expect("parse vk");
        assert_eq!(vk.log_n, LOG_N);
        assert_eq!(vk.num_layers, NUM_LAYERS);
        assert_eq!(vk.num_queries, NUM_QUERIES);
        assert_eq!(vk.num_pi, MEMBERSHIP_NUM_PI);
        assert_eq!(vk.blowup_log, BLOWUP_LOG);
        assert_eq!(vk.omega_0, omega_0(&env));
        assert_eq!(vk.omega_0_inv, omega_0_inv(&env));
        assert_eq!(vk.two_inv, two_inv(&env));
        assert_eq!(vk.pcs_pinned_root, pcs_pinned_root(&env));
    }
}
