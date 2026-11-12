//! Poseidon2 over BabyBear, width 16, S-box `x⁷`, 8 external + 13
//! internal rounds (the round counts Plonky3 uses for this field/width).
//!
//! Every step is generic over [`Algebra`], so the AIR evaluates the
//! exact same round functions symbolically at the OOD point that the
//! witness generator runs natively.
//!
//! This is Plonky3's canonical BabyBear width-16 instance
//! (`p3_baby_bear::default_babybear_poseidon2_16`), checked bit for bit
//! by `tests::matches_plonky3`:
//!
//! - External linear layer: `circ(2·M4, M4, M4, M4)` with Plonky3's
//!   `MDSMat4 = [[2,3,1,1],[1,2,3,1],[1,1,2,3],[3,1,1,2]]`.
//! - Internal linear layer: `y_i = μ_i·x_i + Σ_j x_j`.
//! - Round constants and `μ`: [`crate::poseidon2_constants`].
//!
//! Hashing conventions used by the membership AIR:
//! - `compress(l, r)` = first 8 lanes of `permute([l ‖ r])`.
//! - Digests are 8 elements (~248 bits).

use crate::field::{Algebra, F};
use crate::poseidon2_constants::{INTERNAL_DIAG, RC_EXT, RC_INT};

pub const WIDTH: usize = 16;
pub const DIGEST: usize = 8;
pub const ROUNDS_EXT_HALF: usize = 4;
pub const ROUNDS_INT: usize = 13;

#[inline]
pub fn sbox<A: Algebra>(x: A) -> A {
    let x2 = x * x;
    let x3 = x2 * x;
    let x6 = x3 * x3;
    x6 * x
}

/// Plonky3's `MDSMat4` addition chain (7 additions, 2 doublings).
#[inline]
fn m4<A: Algebra>(x: [A; 4]) -> [A; 4] {
    let t01 = x[0] + x[1];
    let t23 = x[2] + x[3];
    let t0123 = t01 + t23;
    let t01123 = t0123 + x[1];
    let t01233 = t0123 + x[3];
    [
        t01123 + t01,         // 2·x0 + 3·x1 +   x2 +   x3
        t01123 + x[2] + x[2], //   x0 + 2·x1 + 3·x2 +   x3
        t01233 + t23,         //   x0 +   x1 + 2·x2 + 3·x3
        t01233 + x[0] + x[0], // 3·x0 +   x1 +   x2 + 2·x3
    ]
}

pub fn external_linear<A: Algebra>(s: &mut [A; WIDTH]) {
    for c in 0..4 {
        let y = m4([s[4 * c], s[4 * c + 1], s[4 * c + 2], s[4 * c + 3]]);
        s[4 * c..4 * c + 4].copy_from_slice(&y);
    }
    let mut sums = [A::ZERO; 4];
    for i in 0..WIDTH {
        sums[i % 4] = sums[i % 4] + s[i];
    }
    for i in 0..WIDTH {
        s[i] = s[i] + sums[i % 4];
    }
}

pub fn internal_linear<A: Algebra>(s: &mut [A; WIDTH]) {
    let mut sum = A::ZERO;
    for x in s.iter() {
        sum = sum + *x;
    }
    for i in 0..WIDTH {
        s[i] = s[i].mul_f(F::from_u64(INTERNAL_DIAG[i] as u64)) + sum;
    }
}

/// External round with explicit round constants `rc`.
pub fn external_round<A: Algebra>(s: &[A; WIDTH], rc: &[A; WIDTH]) -> [A; WIDTH] {
    let mut out = [A::ZERO; WIDTH];
    for i in 0..WIDTH {
        out[i] = sbox(s[i] + rc[i]);
    }
    external_linear(&mut out);
    out
}

/// Internal round; only `rc0` (lane 0) is used.
pub fn internal_round<A: Algebra>(s: &[A; WIDTH], rc0: A) -> [A; WIDTH] {
    let mut out = *s;
    out[0] = sbox(out[0] + rc0);
    internal_linear(&mut out);
    out
}

pub fn rc_ext(round: usize) -> [F; WIDTH] {
    RC_EXT[round].map(|c| F::from_u64(c as u64))
}

pub fn rc_int(round: usize) -> F {
    F::from_u64(RC_INT[round] as u64)
}

/// The full permutation, returning the state after every round so the
/// AIR trace generator can lay it out row by row. `states[0]` is the
/// raw input; `states[21]` is the output.
pub fn permute_trace(input: [F; WIDTH]) -> [[F; WIDTH]; 2 * ROUNDS_EXT_HALF + ROUNDS_INT + 1] {
    let mut states = [[F::ZERO; WIDTH]; 2 * ROUNDS_EXT_HALF + ROUNDS_INT + 1];
    states[0] = input;
    let mut s = input;
    external_linear(&mut s);
    let mut row = 1;
    for r in 0..ROUNDS_EXT_HALF {
        s = external_round(&s, &rc_ext(r));
        states[row] = s;
        row += 1;
    }
    for r in 0..ROUNDS_INT {
        s = internal_round(&s, rc_int(r));
        states[row] = s;
        row += 1;
    }
    for r in ROUNDS_EXT_HALF..2 * ROUNDS_EXT_HALF {
        s = external_round(&s, &rc_ext(r));
        states[row] = s;
        row += 1;
    }
    states
}

pub fn permute(input: [F; WIDTH]) -> [F; WIDTH] {
    permute_trace(input)[2 * ROUNDS_EXT_HALF + ROUNDS_INT]
}

pub fn compress(l: &[F; DIGEST], r: &[F; DIGEST]) -> [F; DIGEST] {
    let mut input = [F::ZERO; WIDTH];
    input[..DIGEST].copy_from_slice(l);
    input[DIGEST..].copy_from_slice(r);
    let out = permute(input);
    out[..DIGEST].try_into().unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn m4_matches_matrix() {
        let m = [[2u64, 3, 1, 1], [1, 2, 3, 1], [1, 1, 2, 3], [3, 1, 1, 2]];
        let x = [F::from_u64(3), F::from_u64(10), F::from_u64(77), F::from_u64(1234)];
        let y = m4(x);
        for i in 0..4 {
            let mut e = F::ZERO;
            for j in 0..4 {
                e = e + F::from_u64(m[i][j]) * x[j];
            }
            assert_eq!(y[i], e);
        }
    }

    #[test]
    fn sbox_is_a_permutation_exponent() {
        // gcd(7, p − 1) = 1 since p − 1 = 2²⁷·3·5.
        assert_eq!((crate::field::P as u64 - 1) % 7 != 0, true);
    }

    #[test]
    fn internal_matrix_is_invertible() {
        // diag(μ) + J is invertible iff all μ_i ≠ 0 and 1 + Σ 1/μ_i ≠ 0.
        let mut acc = F::ONE;
        for &mu in INTERNAL_DIAG.iter() {
            let mu = F::from_u64(mu as u64);
            assert_ne!(mu, F::ZERO);
            acc = acc + mu.inv();
        }
        assert_ne!(acc, F::ZERO);
    }

    /// Bit-for-bit equality with Plonky3's canonical instance on random
    /// inputs, plus the all-zero and counting vectors.
    #[test]
    fn matches_plonky3() {
        use p3_baby_bear::{default_babybear_poseidon2_16, BabyBear};
        use p3_field::{PrimeCharacteristicRing, PrimeField32};
        use p3_symmetric::Permutation;
        let p3 = default_babybear_poseidon2_16();
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut inputs: alloc::vec::Vec<[u32; WIDTH]> =
            alloc::vec![[0; WIDTH], core::array::from_fn(|i| i as u32)];
        for _ in 0..64 {
            inputs.push(core::array::from_fn(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed % crate::field::P as u64) as u32
            }));
        }
        for input in inputs {
            let ours = permute(input.map(|v| F::from_u64(v as u64)));
            let mut theirs = input.map(BabyBear::from_u32);
            p3.permute_mut(&mut theirs);
            for i in 0..WIDTH {
                assert_eq!(ours[i].value(), theirs[i].as_canonical_u32(), "lane {i} for input {input:?}");
            }
        }
    }

    #[test]
    fn permutation_diffuses() {
        let a = permute([F::ZERO; WIDTH]);
        let mut input = [F::ZERO; WIDTH];
        input[15] = F::ONE;
        let b = permute(input);
        for i in 0..WIDTH {
            assert_ne!(a[i], b[i], "lane {i}");
        }
    }
}
