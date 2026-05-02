//! Software reference for Poseidon2-BabyBear-W16, used by the off-
//! chain test path inside `host_poseidon2`.
//!
//! ## Status: structural placeholder
//!
//! This implementation matches Poseidon2's *shape* — width 16, ROUNDS_F
//! external + ROUNDS_P internal, x^7 S-box, MDS-shaped external mixing,
//! diagonal internal mixing — but the round-constant table and the
//! matrix entries are **not** the canonical Plonky3 BabyBear-W16
//! constants. They are filler values chosen for determinism only.
//!
//! Why ship a placeholder: (1) the on-chain path goes through the
//! Soroban host primitive (`host_poseidon2::host_permute`), which is
//! the canonical Plonky3 instance — that is where prover/verifier byte-
//! equivalence is enforced. (2) The verifier crate's own tests only
//! need a deterministic, non-trivial mixing function to exercise the
//! transcript / Merkle / FRI flow off-chain. They do not check against
//! prover-emitted fixtures (no PQ prover exists yet — see crate-level
//! README). When the prover lands, the canonical Plonky3 constants are
//! pasted in here verbatim and the placeholder block at the bottom of
//! this file deletes.
//!
//! `host_permute` will then call the real host primitive directly and
//! never reach this module on-chain; this code stays only as the
//! oracle the prover-side fixture regen test compares against.

use crate::field::{Fr, P};

pub const WIDTH: usize = super::host_poseidon2::WIDTH;
pub const ROUNDS_F: usize = super::host_poseidon2::ROUNDS_F;
pub const HALF_F: usize = super::host_poseidon2::HALF_F;
pub const ROUNDS_P: usize = super::host_poseidon2::ROUNDS_P;

/// Compute `x^7` in BabyBear. Poseidon2's permutation S-box.
/// gcd(7, p-1) = 1 for BabyBear so x^7 is a bijection.
#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    let x6 = x4 * x2;
    x6 * x
}

/// External (full) round constants — placeholder. ROUNDS_F × WIDTH.
/// Generated from `(round_idx * 0x1000003D + lane_idx * 7 + 1) mod P`.
fn ext_const(round: usize, lane: usize) -> Fr {
    let v = ((round as u64) * 0x1000003D + (lane as u64) * 7 + 1) % (P as u64);
    Fr::new(v as u32)
}

/// Internal (partial) round constants — placeholder. ROUNDS_P scalars,
/// applied to lane 0 only.
fn int_const(round: usize) -> Fr {
    let v = ((round as u64 + 1) * 0xCAFEBABE) % (P as u64);
    Fr::new(v as u32)
}

/// External MDS-shaped mixing matrix (placeholder).
///
/// Plonky3 uses a circulant 4×4 over each four-lane chunk plus a
/// chunk-coupling pass; here we use the simpler "all-pairs sum-and-
/// shift" pattern, which is invertible over BabyBear:
///   new_i = 2·old_i + Σ_{j≠i} old_j
///         = old_i + Σ_j old_j .
/// One scalar accumulator + one pass per lane = O(WIDTH) field ops.
fn external_linear_layer(state: &mut [Fr; WIDTH]) {
    let mut sum = Fr::ZERO;
    for i in 0..WIDTH {
        sum += state[i];
    }
    for i in 0..WIDTH {
        state[i] = state[i] + sum;
    }
}

/// Internal mixing matrix (placeholder).
///
/// Plonky3's M_I is `I + diag(d)` for a vector `d` whose entries are
/// powers of two (cheap to mul). Here we use `d_i = i + 2` — small
/// integers, equivalently cheap.
fn internal_linear_layer(state: &mut [Fr; WIDTH]) {
    let mut sum = Fr::ZERO;
    for i in 0..WIDTH {
        sum += state[i];
    }
    for i in 0..WIDTH {
        let mul = Fr::new((i as u32) + 2);
        state[i] = state[i] * mul + sum;
    }
}

/// In-place Poseidon2-shape permutation. See module docs for status.
pub fn permute(state: &mut [Fr; WIDTH]) {
    // Initial linear layer (Plonky3 style: external mix before round 0).
    external_linear_layer(state);

    // First half of external rounds.
    for r in 0..HALF_F {
        for i in 0..WIDTH {
            state[i] += ext_const(r, i);
            state[i] = sbox(state[i]);
        }
        external_linear_layer(state);
    }

    // Internal partial rounds: S-box on lane 0 only.
    for r in 0..ROUNDS_P {
        state[0] += int_const(r);
        state[0] = sbox(state[0]);
        internal_linear_layer(state);
    }

    // Second half of external rounds.
    for r in HALF_F..ROUNDS_F {
        for i in 0..WIDTH {
            state[i] += ext_const(r, i);
            state[i] = sbox(state[i]);
        }
        external_linear_layer(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permute_is_deterministic() {
        let mut a = [Fr::ZERO; WIDTH];
        let mut b = [Fr::ZERO; WIDTH];
        for i in 0..WIDTH {
            a[i] = Fr::new(i as u32 * 13 + 1);
            b[i] = a[i];
        }
        permute(&mut a);
        permute(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn permute_is_not_identity() {
        let mut state = [Fr::ZERO; WIDTH];
        for i in 0..WIDTH {
            state[i] = Fr::new(1 + i as u32);
        }
        let before = state;
        permute(&mut state);
        assert_ne!(before, state);
    }

    /// Avalanche: flipping a single input lane should change every
    /// output lane (with overwhelming probability for an MDS-mixing
    /// permutation). Pinning this so the placeholder constants don't
    /// silently degrade into something that fails to mix.
    #[test]
    fn permute_avalanche() {
        let mut a = [Fr::ZERO; WIDTH];
        let mut b = [Fr::ZERO; WIDTH];
        for i in 0..WIDTH {
            a[i] = Fr::new(1 + i as u32);
            b[i] = a[i];
        }
        b[3] = b[3] + Fr::ONE;
        permute(&mut a);
        permute(&mut b);
        for i in 0..WIDTH {
            assert_ne!(a[i], b[i], "lane {i} did not change after input perturbation");
        }
    }
}
