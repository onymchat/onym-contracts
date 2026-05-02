//! Single point of contact with the Soroban Poseidon2-BabyBear-W16
//! host primitive.
//!
//! ## Why isolated here
//!
//! The host primitive's exact `env.crypto()` surface name is the only
//! thing about this verifier that depends on the *current* Soroban SDK
//! release. Concentrating every host call in this module means a
//! future SDK rename ripples through one wrapper, not the whole
//! crate.
//!
//! ## Surface
//!
//! Plonky3's canonical Poseidon2 over BabyBear runs at width 16 with
//! 8 external full rounds and 13 internal partial rounds. We expose
//! exactly one operation:
//!
//! ```ignore
//!   permute(env, &mut state)   // state: [Fr; 16]
//! ```
//!
//! Everything else (sponge transcript, Merkle compression) builds on
//! this single permutation.
//!
//! ## Host vs software path
//!
//! The contract build calls `env.crypto().poseidon2_babybear_w16(...)`
//! — when that host primitive is bound, every permutation is a single
//! host crossing (≈ a few thousand pre-metered VM instructions, the
//! same pattern as `bls12_381().pairing_check`).
//!
//! The `cfg(any(test, not(target_family = "wasm")))` build path
//! falls through to a deterministic software reference. The reference
//! is byte-equivalent to the host primitive *by construction* (it IS
//! the same algorithm), so off-chain unit tests, fixture regen, and
//! prover-side oracle tests all see identical hashes.
//!
//! When the host primitive's actual SDK name lands, swap the body of
//! `host_permute` and delete the software path — every other module
//! in this crate stays untouched.

use crate::field::Fr;
use soroban_sdk::Env;

/// Poseidon2-BabyBear-W16 state width.
pub const WIDTH: usize = 16;

/// External (full) round count. Plonky3 default: 8 — split 4 before,
/// 4 after the internal partial-round block.
pub const ROUNDS_F: usize = 8;
pub const HALF_F: usize = ROUNDS_F / 2;
/// Internal (partial) round count. Plonky3 default for BabyBear-W16: 13.
pub const ROUNDS_P: usize = 13;

/// In-place Poseidon2-BabyBear-W16 permutation.
///
/// On-chain: routes through `env.crypto()` once the host primitive
/// is wired. Off-chain (tests, prover-side oracle, fixture regen):
/// computes the permutation in software using the constants in
/// `super::poseidon2_constants`. Both paths produce identical bytes.
pub fn permute(env: &Env, state: &mut [Fr; WIDTH]) {
    #[cfg(target_family = "wasm")]
    {
        host_permute(env, state);
    }
    #[cfg(not(target_family = "wasm"))]
    {
        let _ = env;
        super::poseidon2_software::permute(state);
    }
}

/// Soroban host primitive call site.
///
/// **TODO(host-fn-bind):** when the Soroban host exposes Poseidon2-
/// BabyBear-W16, replace the body below with the real call. Today the
/// SDK does not yet expose this, so we route to the software reference
/// — which is the algorithm spec, so swap-in is byte-equivalent.
///
/// The expected host surface (one of):
///   `env.crypto().poseidon2_babybear_w16(state) -> [Fr; 16]`
///   `env.crypto().poseidon2().permute_babybear_w16(state) -> [Fr; 16]`
///
/// Either flavour ingests / emits 16 little-endian 4-byte BabyBear
/// elements, identical to the byte form `Fr::to_le_bytes` produces.
#[cfg(target_family = "wasm")]
fn host_permute(_env: &Env, state: &mut [Fr; WIDTH]) {
    // Software reference for the duration of the host-fn rollout.
    // When the SDK ships Poseidon2-BabyBear-W16, swap the next line
    // for the host call and delete the `poseidon2_software` module.
    super::poseidon2_software::permute(state);
}

#[cfg(test)]
mod tests {
    use super::*;
    use soroban_sdk::Env;

    /// Determinism: two calls on identical input produce identical
    /// output. This is the absolute minimum guarantee any sponge
    /// transcript built atop this primitive depends on.
    #[test]
    fn permutation_is_deterministic() {
        let env = Env::default();
        let mut a = [Fr::ZERO; WIDTH];
        let mut b = [Fr::ZERO; WIDTH];
        for i in 0..WIDTH {
            a[i] = Fr::new((i as u32) * 7 + 3);
            b[i] = a[i];
        }
        permute(&env, &mut a);
        permute(&env, &mut b);
        assert_eq!(a, b);
    }

    /// Non-trivial: permuting a non-zero state must change at least
    /// some elements (rules out the world where the primitive is
    /// silently the identity).
    #[test]
    fn permutation_is_not_identity() {
        let env = Env::default();
        let mut state = [Fr::ZERO; WIDTH];
        for i in 0..WIDTH {
            state[i] = Fr::new(1 + i as u32);
        }
        let original = state;
        permute(&env, &mut state);
        assert_ne!(state, original);
    }
}
