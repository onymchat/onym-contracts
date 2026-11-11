//! Coset folding, shared verbatim by prover and verifier.
//!
//! A leaf of arity `m = 2^a` at a layer with domain generator `ω`
//! (order `n`) and `s = n/m` leaves holds the values at
//! `x₀·ζᵗ`, `t < m`, where `x₀ = ω^l` and `ζ = ω^s` has order `m`.
//! Since `ζ^(m/2) = −1`, slots `t` and `t + m/2` are a `±x` pair, and
//! one binary fold step is
//!
//! ```text
//!   g(x²) = ½·(f(x) + f(−x)) + β·(f(x) − f(−x))/(2x)
//! ```
//!
//! The `m/2` results sit at `(x₀ζᵗ)² = x₀²·(ζ²)ᵗ`, the same coset
//! shape one level down, so the step repeats `a` times with challenges
//! `β, β², β⁴, …` and lands on the value at `ω^(m·l)`: position `l`
//! of the next layer's domain.

use crate::field::{E, F};

/// Folds `vals` in place and returns the single folded value.
/// `x0_inv = ω^(−l)`, `zeta_inv = ζ⁻¹`, `two_inv = ½`.
pub fn fold_leaf(vals: &mut [E], mut x0_inv: F, mut zeta_inv: F, mut beta: E, two_inv: F) -> E {
    let mut m = vals.len();
    while m > 1 {
        let h = m / 2;
        let mut x_inv = x0_inv;
        for t in 0..h {
            let a = vals[t];
            let b = vals[t + h];
            vals[t] = ((a + b) + beta * (a - b).mul_base(x_inv)).mul_base(two_inv);
            x_inv = x_inv * zeta_inv;
        }
        x0_inv = x0_inv * x0_inv;
        zeta_inv = zeta_inv * zeta_inv;
        beta = beta * beta;
        m = h;
    }
    vals[0]
}
