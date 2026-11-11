//! Poseidon2 over BabyBear, width 16, S-box `x⁷`, 8 external + 13
//! internal rounds (the round counts Plonky3 uses for this field/width).
//!
//! Every step is generic over [`Algebra`], so the AIR evaluates the
//! exact same round functions symbolically at the OOD point that the
//! witness generator runs natively.
//!
//! - External linear layer: `circ(2·M4, M4, M4, M4)` with the
//!   Poseidon2-paper `M4 = [[5,7,1,3],[4,6,1,1],[1,3,5,7],[1,1,4,6]]`.
//! - Internal linear layer: `y_i = μ_i·x_i + Σ_j x_j`.
//! - Constants: see [`crate::poseidon2_constants`] (**prototype only**).
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

/// Addition chain for the Poseidon2-paper M4 (no multiplications).
#[inline]
fn m4<A: Algebra>(x: [A; 4]) -> [A; 4] {
    let t0 = x[0] + x[1];
    let t1 = x[2] + x[3];
    let t2 = x[1] + x[1] + t1;
    let t3 = x[3] + x[3] + t0;
    let t1_4 = t1 + t1 + t1 + t1;
    let t0_4 = t0 + t0 + t0 + t0;
    let t4 = t1_4 + t3;
    let t5 = t0_4 + t2;
    let t6 = t3 + t5;
    let t7 = t2 + t4;
    [t6, t5, t7, t4]
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
        let m = [[5u64, 7, 1, 3], [4, 6, 1, 1], [1, 3, 5, 7], [1, 1, 4, 6]];
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
