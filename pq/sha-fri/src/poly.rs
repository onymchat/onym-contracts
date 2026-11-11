//! Radix-2 NTT and polynomial evaluation helpers, shared by prover and
//! verifier (the verifier only interpolates the 32-row periodic columns).

use crate::field::{Algebra, F};
use alloc::vec::Vec;

/// Coset shift for every LDE domain: `31` generates the full group, so
/// `31·⟨ω⟩` is disjoint from every two-adic subgroup, including the
/// trace domain. Revealed LDE values therefore never sit on trace rows.
pub const SHIFT: F = F::from_u64(crate::field::GENERATOR as u64);

fn bit_reverse<T>(a: &mut [T]) {
    let n = a.len();
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - bits);
        if i < j {
            a.swap(i, j);
        }
    }
}

/// In place: `a[i] ← Σⱼ a[j]·ωⁱʲ` (coefficients → evaluations on ⟨ω⟩).
pub fn ntt<A: Algebra>(a: &mut [A], omega: F) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    bit_reverse(a);
    let mut len = 2;
    while len <= n {
        let w_len = omega.pow((n / len) as u64);
        for start in (0..n).step_by(len) {
            let mut w = F::ONE;
            for j in 0..len / 2 {
                let u = a[start + j];
                let v = a[start + j + len / 2].mul_f(w);
                a[start + j] = u + v;
                a[start + j + len / 2] = u - v;
                w = w * w_len;
            }
        }
        len <<= 1;
    }
}

/// Evaluations on ⟨ω⟩ → coefficients.
pub fn intt<A: Algebra>(a: &mut [A], omega: F) {
    ntt(a, omega.inv());
    let n_inv = F::from_u64(a.len() as u64).inv();
    for x in a.iter_mut() {
        *x = x.mul_f(n_inv);
    }
}

/// Coefficients (any length ≤ n) → evaluations on `shift·⟨ω⟩`, size `n`.
pub fn coset_lde<A: Algebra>(coeffs: &[A], log_n: u32, shift: F) -> Vec<A> {
    let n = 1usize << log_n;
    let mut v: Vec<A> = alloc::vec![A::ZERO; n];
    let mut s = F::ONE;
    for (i, c) in coeffs.iter().enumerate() {
        v[i] = c.mul_f(s);
        s = s * shift;
    }
    ntt(&mut v, F::two_adic_generator(log_n));
    v
}

/// Evaluations on `shift·⟨ω⟩` → coefficients.
pub fn coset_interpolate<A: Algebra>(evals: &[A], shift: F) -> Vec<A> {
    let log_n = evals.len().trailing_zeros();
    let mut v = evals.to_vec();
    intt(&mut v, F::two_adic_generator(log_n));
    let s_inv = shift.inv();
    let mut s = F::ONE;
    for c in v.iter_mut() {
        *c = c.mul_f(s);
        s = s * s_inv;
    }
    v
}

/// Horner: `Σ cᵢ·xⁱ` with base coefficients at an algebra point.
pub fn eval_base<A: Algebra>(coeffs: &[F], x: A) -> A {
    coeffs.iter().rev().fold(A::ZERO, |acc, &c| acc * x + A::from(c))
}
