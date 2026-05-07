//! Single point of contact with the Soroban Poseidon2 host primitive.
//!
//! Routes through `env.crypto().poseidon2_permutation(...)` with the
//! canonical Horizen Labs BN254 t=3 instance vendored in
//! `super::poseidon2_params`. Soroban Protocol 26 ships this host fn
//! for BN254 and BLS12-381; we pin BN254.
//!
//! ## Why t=3 (not t=16)
//!
//! Plonky3-style FRI on BabyBear uses a width-16 sponge — 8 absorbed
//! per permutation. The Soroban host primitive supports widths
//! `{2, 3, 4, 8, 12, 16, 20, 24}` but only ships *canonical* params
//! at t=3 (the Horizen Labs reference instance). Wider Poseidon2-BN254
//! instances exist in academic literature, but the t=3 set is what
//! the host's own validation tests use, which makes it the
//! production-trustworthy choice for Soroban today.
//!
//! At t=3 (rate=2, capacity=1) the sponge absorbs 2 elements per
//! permutation. Compared to a hypothetical t=16 (rate=8) instance,
//! that's 4x more host calls per absorbed element — but each
//! permutation runs in 64 host-internal rounds, which is comparable
//! cost regardless of t. Net effect on the verifier: somewhat more
//! permutations than a t=16 design, all host-accelerated.
//!
//! ## Constants caching
//!
//! Each call to the host primitive needs `mat_internal_diag_m_1`
//! and `round_constants` as `Vec<U256>` / `Vec<Vec<U256>>`. The
//! `Poseidon2Ctx` struct constructed at the top of `verifier::verify`
//! caches these — re-building from byte literals on every permutation
//! would dominate the host-call cost. One construction at verifier
//! entry, ~hundreds of permutations during the FRI loop, all sharing
//! the same `Vec<U256>` references.

use crate::poseidon2_params::{
    MAT_INTERNAL_DIAG_M_1, ROUND_CONSTANTS, ROUNDS_F, ROUNDS_P, T, D,
};
use soroban_sdk::{Bytes, BytesN, Env, Symbol, U256, Vec};

/// State width — matches the t=3 Horizen Labs instance.
pub const WIDTH: usize = T as usize;

/// Pre-built host-call arguments for the BN254 t=3 Poseidon2 instance.
///
/// Construct once at the top of `verifier::verify`; re-use for every
/// permutation downstream. Without this caching, each permutation
/// would rebuild the 192-element `round_constants` `Vec<Vec<U256>>`,
/// which is itself ~hundreds of host calls.
pub struct Poseidon2Ctx {
    field_symbol: Symbol,
    mat_internal_diag_m_1: Vec<U256>,
    round_constants: Vec<Vec<U256>>,
}

impl Poseidon2Ctx {
    pub fn new(env: &Env) -> Self {
        let field_symbol = Symbol::new(env, "BN254");

        let mut diag = Vec::new(env);
        for be in MAT_INTERNAL_DIAG_M_1.iter() {
            diag.push_back(U256::from_be_bytes(env, &Bytes::from_array(env, be)));
        }

        let mut rc = Vec::new(env);
        for round in ROUND_CONSTANTS.iter() {
            let mut row = Vec::new(env);
            for lane in round.iter() {
                row.push_back(U256::from_be_bytes(env, &Bytes::from_array(env, lane)));
            }
            rc.push_back(row);
        }

        Poseidon2Ctx {
            field_symbol,
            mat_internal_diag_m_1: diag,
            round_constants: rc,
        }
    }

    /// In-place Poseidon2-BN254-t3 permutation.
    ///
    /// `state` must hold exactly `WIDTH = 3` elements. The host
    /// primitive returns a fresh `Vec<U256>` of the same length,
    /// which we copy back into `state`.
    pub fn permute(&self, env: &Env, state: &mut [crate::field::Fr; WIDTH]) {
        let mut input: Vec<U256> = Vec::new(env);
        for fr in state.iter() {
            input.push_back(fr.to_u256());
        }

        let result: Vec<U256> = env.crypto_hazmat().poseidon2_permutation(
            &input,
            self.field_symbol.clone(),
            T,
            D,
            ROUNDS_F,
            ROUNDS_P,
            &self.mat_internal_diag_m_1,
            &self.round_constants,
        );

        // Copy the host-returned U256s back into the state. The host
        // returns canonical Fr-shaped values (already reduced mod r),
        // so `Fr::from(U256)`'s reduction path is a no-op here.
        for i in 0..WIDTH {
            state[i] = crate::field::Fr::from(result.get(i as u32).unwrap());
        }
    }
}

/// Convenience: a single-shot permutation. Use only when you don't
/// have a `Poseidon2Ctx` already in scope (the caching wins matter).
pub fn permute(env: &Env, state: &mut [crate::field::Fr; WIDTH]) {
    let ctx = Poseidon2Ctx::new(env);
    ctx.permute(env, state);
}

/// `BytesN<32>` view of a single Fr — used by the contract layer to
/// emit / accept commitments.
pub fn fr_to_bytesn(fr: &crate::field::Fr) -> BytesN<32> {
    fr.to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field;
    use soroban_sdk::Env;

    /// Determinism: two calls on identical input produce identical
    /// output. This is the absolute minimum guarantee any sponge
    /// transcript built atop this primitive depends on.
    #[test]
    fn permutation_is_deterministic() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut a = [field::zero(&env), field::zero(&env), field::zero(&env)];
        let mut b = [field::zero(&env), field::zero(&env), field::zero(&env)];
        for i in 0..WIDTH {
            a[i] = field::from_u32(&env, (i as u32) * 7 + 3);
            b[i] = a[i].clone();
        }
        ctx.permute(&env, &mut a);
        ctx.permute(&env, &mut b);
        for i in 0..WIDTH {
            assert_eq!(a[i], b[i]);
        }
    }

    /// Non-trivial: permuting a non-zero state must change at least
    /// one element (rules out a misconfigured-as-identity primitive).
    #[test]
    fn permutation_is_not_identity() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut state = [field::zero(&env), field::zero(&env), field::zero(&env)];
        for i in 0..WIDTH {
            state[i] = field::from_u32(&env, 1 + i as u32);
        }
        let original = [state[0].clone(), state[1].clone(), state[2].clone()];
        ctx.permute(&env, &mut state);
        let mut any_changed = false;
        for i in 0..WIDTH {
            if state[i] != original[i] {
                any_changed = true;
                break;
            }
        }
        assert!(any_changed);
    }

    /// Avalanche: flipping a single input lane should change every
    /// output lane (with overwhelming probability for the canonical
    /// Horizen instance). Pinned so a future param drift would fire.
    #[test]
    fn permutation_avalanche() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut a = [field::zero(&env), field::zero(&env), field::zero(&env)];
        let mut b = [field::zero(&env), field::zero(&env), field::zero(&env)];
        for i in 0..WIDTH {
            a[i] = field::from_u32(&env, 1 + i as u32);
            b[i] = a[i].clone();
        }
        b[1] = b[1].clone() + field::one(&env);
        ctx.permute(&env, &mut a);
        ctx.permute(&env, &mut b);
        for i in 0..WIDTH {
            assert_ne!(a[i], b[i], "lane {i} did not change after input perturbation");
        }
    }

    /// Pin the canonical input → output mapping for a known seed,
    /// matching the host's own validation test
    /// (`poseidon2_instance_bn254` reference: input = [0, 1, 2]).
    #[test]
    fn known_answer_zero_one_two() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut state = [
            field::from_u32(&env, 0),
            field::from_u32(&env, 1),
            field::from_u32(&env, 2),
        ];
        ctx.permute(&env, &mut state);
        // Expected values from `soroban-env-host` test
        // `test_poseidon2_bn254_hostfn_success`.
        let expected_be: [[u8; 32]; 3] = [
            // 0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033
            [
                0x0b, 0xb6, 0x1d, 0x24, 0xda, 0xca, 0x55, 0xee,
                0xbc, 0xb1, 0x92, 0x9a, 0x82, 0x65, 0x0f, 0x32,
                0x81, 0x34, 0x33, 0x4d, 0xa9, 0x8e, 0xa4, 0xf8,
                0x47, 0xf7, 0x60, 0x05, 0x4f, 0x4a, 0x30, 0x33,
            ],
            // 0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570
            [
                0x30, 0x3b, 0x6f, 0x7c, 0x86, 0xd0, 0x43, 0xbf,
                0xcb, 0xcc, 0x80, 0x21, 0x4f, 0x26, 0xa3, 0x02,
                0x77, 0xa1, 0x5d, 0x3f, 0x74, 0xca, 0x65, 0x49,
                0x92, 0xde, 0xfe, 0x7f, 0xf8, 0xd0, 0x35, 0x70,
            ],
            // 0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8
            [
                0x1e, 0xd2, 0x51, 0x94, 0x54, 0x2b, 0x12, 0xee,
                0xf8, 0x61, 0x73, 0x61, 0xc3, 0xba, 0x7c, 0x52,
                0xe6, 0x60, 0xb1, 0x45, 0x99, 0x44, 0x27, 0xcc,
                0x86, 0x29, 0x62, 0x42, 0xcf, 0x76, 0x6e, 0xc8,
            ],
        ];
        for i in 0..WIDTH {
            assert_eq!(
                field::to_be_bytes(&state[i]),
                expected_be[i],
                "lane {i} diverged from host KAT — params or host primitive drift"
            );
        }
    }
}
