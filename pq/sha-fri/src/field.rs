//! BabyBear base field and its degree-4 binomial extension.
//!
//! ## Base field
//!
//! `p = 2³¹ − 2²⁷ + 1 = 15·2²⁷ + 1`. Elements are canonical `u32 < p`;
//! products go through `u64` and a single `%`. Two-adicity 27, so
//! evaluation domains up to 2²⁷ exist. `31` generates the full
//! multiplicative group.
//!
//! ## Extension field
//!
//! `E = F[X]/(X^D − 11)` with `D = EXT_DEG`: 4 by default (~124 bits),
//! 8 with the `ext8` feature (~248 bits). `X^D − 11` is irreducible for
//! `D ∈ {4, 8}` because `11` is a quadratic non-residue mod `p` and
//! `D | p − 1` (pinned by `tests::eleven_is_non_residue`). Every verifier
//! challenge lives here, so soundness isn't capped by the 31-bit base.
//!
//! **Why `ext8` exists:** the algebraic soundness error (DEEP/ALI, FRI
//! folding) is about `degree / |E|`. A quantum adversary can search
//! Fiat–Shamir transcripts quadratically faster, which caps post-quantum
//! security near `log₂|E| / 2` minus the degree term: about 55 bits for
//! `D = 4` whatever the query count, about 117 for `D = 8`.
//!
//! Inversion uses the norm: `a⁻¹ = (Π_{k=1}^{D−1} φᵏ(a)) / N(a)`, where
//! `φ` is Frobenius. For a binomial extension `φ(X) = X^p = c·X` with
//! `c = 11^((p−1)/D)`, so each Frobenius map is `D − 1` base multiplies.

use core::ops::{Add, Mul, Neg, Sub};

/// BabyBear modulus.
pub const P: u32 = 0x7800_0001;
const P64: u64 = P as u64;

/// log₂ of the largest power-of-two subgroup.
pub const TWO_ADICITY: u32 = 27;

/// Generator of the full multiplicative group.
pub const GENERATOR: u32 = 31;

/// Extension non-residue: `X⁴ = W`.
pub const W: u32 = 11;

const fn mul_mod(a: u32, b: u32) -> u32 {
    ((a as u64 * b as u64) % P64) as u32
}

const fn pow_mod(mut b: u32, mut e: u64) -> u32 {
    let mut r = 1u32;
    while e > 0 {
        if e & 1 == 1 {
            r = mul_mod(r, b);
        }
        b = mul_mod(b, b);
        e >>= 1;
    }
    r
}

/// Extension degree.
#[cfg(not(feature = "ext8"))]
pub const EXT_DEG: usize = 4;
#[cfg(feature = "ext8")]
pub const EXT_DEG: usize = 8;

/// `FROB_POW[i] = c^i` with `c = W^((p−1)/D)`, so `c^D = 1`.
const FROB_C: u32 = pow_mod(W, ((P - 1) / EXT_DEG as u32) as u64);
const FROB_POW: [u32; EXT_DEG] = {
    let mut t = [1u32; EXT_DEG];
    let mut i = 1;
    while i < EXT_DEG {
        t[i] = mul_mod(t[i - 1], FROB_C);
        i += 1;
    }
    t
};

/// Base-field element, always canonical (`< P`).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct F(u32);

impl F {
    pub const ZERO: F = F(0);
    pub const ONE: F = F(1);

    /// `None` when `x` is not canonical. Proof parsers use this so a
    /// prover can't smuggle two encodings of one element.
    pub const fn from_canonical(x: u32) -> Option<F> {
        if x < P {
            Some(F(x))
        } else {
            None
        }
    }

    pub const fn from_u64(x: u64) -> F {
        F((x % P64) as u32)
    }

    pub const fn value(self) -> u32 {
        self.0
    }

    pub fn pow(self, e: u64) -> F {
        F(pow_mod(self.0, e))
    }

    /// Fermat inverse. `inv(0)` returns 0; callers never invert zero
    /// on an honest path, and a malicious zero only makes checks fail.
    pub fn inv(self) -> F {
        self.pow(P64 - 2)
    }

    /// Generator of the order-`2^log_n` subgroup.
    pub fn two_adic_generator(log_n: u32) -> F {
        assert!(log_n <= TWO_ADICITY);
        F(pow_mod(GENERATOR, ((P - 1) >> log_n) as u64))
    }
}

impl Add for F {
    type Output = F;
    #[inline]
    fn add(self, rhs: F) -> F {
        // Both operands < 2³¹, so the sum fits in u32.
        let s = self.0 + rhs.0;
        F(if s >= P { s - P } else { s })
    }
}

impl Sub for F {
    type Output = F;
    #[inline]
    fn sub(self, rhs: F) -> F {
        F(if self.0 >= rhs.0 { self.0 - rhs.0 } else { self.0 + P - rhs.0 })
    }
}

impl Neg for F {
    type Output = F;
    #[inline]
    fn neg(self) -> F {
        F(if self.0 == 0 { 0 } else { P - self.0 })
    }
}

impl Mul for F {
    type Output = F;
    #[inline]
    fn mul(self, rhs: F) -> F {
        F(mul_mod(self.0, rhs.0))
    }
}

/// Extension-field element `Σ aᵢ·Xⁱ`, `i < EXT_DEG`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct E(pub [F; EXT_DEG]);

/// Serialized size of one [`E`]: `EXT_DEG` little-endian `u32`s.
pub const E_BYTES: usize = 4 * EXT_DEG;

impl E {
    pub const ZERO: E = E([F::ZERO; EXT_DEG]);
    pub const ONE: E = E::from_base(F::ONE);

    pub const fn from_base(f: F) -> E {
        let mut c = [F::ZERO; EXT_DEG];
        c[0] = f;
        E(c)
    }

    #[inline]
    pub fn mul_base(self, f: F) -> E {
        E(self.0.map(|c| c * f))
    }

    /// `φᵏ(a)`: coefficient `i` scales by `c^(k·i mod D)`.
    fn frobenius(self, k: usize) -> E {
        let mut out = self;
        for i in 1..EXT_DEG {
            out.0[i] = self.0[i] * F(FROB_POW[(k * i) % EXT_DEG]);
        }
        out
    }

    pub fn inv(self) -> E {
        let mut b = self.frobenius(1);
        for k in 2..EXT_DEG {
            b = b * self.frobenius(k);
        }
        // a·b is the norm, which lies in the base field.
        let norm = (self * b).0[0];
        b.mul_base(norm.inv())
    }

    pub fn to_bytes(self) -> [u8; E_BYTES] {
        let mut out = [0u8; E_BYTES];
        for i in 0..EXT_DEG {
            out[4 * i..4 * i + 4].copy_from_slice(&self.0[i].0.to_le_bytes());
        }
        out
    }

    /// `None` on a short slice or any non-canonical coefficient.
    pub fn from_bytes(b: &[u8]) -> Option<E> {
        if b.len() != E_BYTES {
            return None;
        }
        let mut out = E::ZERO;
        for i in 0..EXT_DEG {
            let v = u32::from_le_bytes([b[4 * i], b[4 * i + 1], b[4 * i + 2], b[4 * i + 3]]);
            out.0[i] = F::from_canonical(v)?;
        }
        Some(out)
    }
}

impl Add for E {
    type Output = E;
    #[inline]
    fn add(self, rhs: E) -> E {
        let mut out = self;
        for i in 0..EXT_DEG {
            out.0[i] = self.0[i] + rhs.0[i];
        }
        out
    }
}

impl Sub for E {
    type Output = E;
    #[inline]
    fn sub(self, rhs: E) -> E {
        let mut out = self;
        for i in 0..EXT_DEG {
            out.0[i] = self.0[i] - rhs.0[i];
        }
        out
    }
}

/// Generic schoolbook product for `ext8`: each partial product is reduced
/// before summing (eight unreduced `p²` terms would overflow `u64`).
#[cfg(feature = "ext8")]
impl Mul for E {
    type Output = E;
    fn mul(self, rhs: E) -> E {
        let mut lo = [0u64; EXT_DEG];
        let mut hi = [0u64; EXT_DEG];
        for i in 0..EXT_DEG {
            let a = self.0[i].0 as u64;
            for j in 0..EXT_DEG {
                let t = (a * rhs.0[j].0 as u64) % P64;
                if i + j < EXT_DEG {
                    lo[i + j] += t;
                } else {
                    hi[i + j - EXT_DEG] += t;
                }
            }
        }
        let w = W as u64;
        E(core::array::from_fn(|k| F::from_u64(lo[k] % P64 + w * (hi[k] % P64))))
    }
}

#[cfg(not(feature = "ext8"))]
impl Mul for E {
    type Output = E;
    fn mul(self, rhs: E) -> E {
        let a = [self.0[0].0 as u64, self.0[1].0 as u64, self.0[2].0 as u64, self.0[3].0 as u64];
        let b = [rhs.0[0].0 as u64, rhs.0[1].0 as u64, rhs.0[2].0 as u64, rhs.0[3].0 as u64];
        // Each product < p² < 2⁶²; at most four are summed, < 2⁶⁴.
        let lo = [
            a[0] * b[0],
            a[0] * b[1] + a[1] * b[0],
            a[0] * b[2] + a[1] * b[1] + a[2] * b[0],
            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
        ];
        // Terms with i + j ≥ 4 wrap around with a factor of W.
        let hi = [
            a[1] * b[3] + a[2] * b[2] + a[3] * b[1],
            a[2] * b[3] + a[3] * b[2],
            a[3] * b[3],
        ];
        let w = W as u64;
        E([
            F::from_u64(lo[0] % P64 + w * (hi[0] % P64)),
            F::from_u64(lo[1] % P64 + w * (hi[1] % P64)),
            F::from_u64(lo[2] % P64 + w * (hi[2] % P64)),
            F::from_u64(lo[3]),
        ])
    }
}

impl From<F> for E {
    fn from(f: F) -> E {
        E::from_base(f)
    }
}

/// Ring operations shared by `F` and `E`, so one AIR constraint
/// implementation serves both the prover (base-field points of the LDE
/// coset) and the verifier (extension-field OOD point `z`).
pub trait Algebra: Copy + Add<Output = Self> + Sub<Output = Self> + Mul<Output = Self> + From<F> {
    const ZERO: Self;
    const ONE: Self;
    fn mul_f(self, f: F) -> Self;
}

impl Algebra for F {
    const ZERO: F = F::ZERO;
    const ONE: F = F::ONE;
    #[inline]
    fn mul_f(self, f: F) -> F {
        self * f
    }
}

impl Algebra for E {
    const ZERO: E = E::ZERO;
    const ONE: E = E::ONE;
    #[inline]
    fn mul_f(self, f: F) -> E {
        self.mul_base(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(seed: &mut u64) -> F {
        *seed ^= *seed << 13;
        *seed ^= *seed >> 7;
        *seed ^= *seed << 17;
        F::from_u64(*seed)
    }

    #[test]
    fn eleven_is_non_residue() {
        assert_eq!(F(W).pow(((P - 1) / 2) as u64), -F::ONE);
        assert_eq!((P - 1) % EXT_DEG as u32, 0);
    }

    #[test]
    fn generator_has_full_order() {
        // p − 1 = 2²⁷·3·5.
        for q in [2u64, 3, 5] {
            assert_ne!(F(GENERATOR).pow((P64 - 1) / q), F::ONE);
        }
    }

    #[test]
    fn two_adic_generator_has_exact_order() {
        for log_n in [1u32, 5, 16, 27] {
            let w = F::two_adic_generator(log_n);
            assert_eq!(w.pow(1 << log_n), F::ONE);
            assert_ne!(w.pow(1 << (log_n - 1)), F::ONE);
        }
    }

    #[test]
    fn base_inverse_round_trips() {
        let mut s = 0x1234_5678_9abc_def0;
        for _ in 0..100 {
            let a = sample(&mut s);
            if a != F::ZERO {
                assert_eq!(a * a.inv(), F::ONE);
            }
        }
    }

    #[test]
    fn ext_inverse_round_trips_and_norm_is_base() {
        let mut s = 0xdead_beef_cafe_f00d;
        for _ in 0..100 {
            let a = E(core::array::from_fn(|_| sample(&mut s)));
            let mut b = a.frobenius(1);
            for k in 2..EXT_DEG {
                b = b * a.frobenius(k);
            }
            let n = a * b;
            assert_eq!(&n.0[1..], &[F::ZERO; EXT_DEG - 1]);
            assert_eq!(a * a.inv(), E::ONE);
        }
    }

    #[test]
    fn ext_mul_matches_schoolbook() {
        // X · X^(D−1) = X^D = W.
        let mut x = E::ZERO;
        x.0[1] = F::ONE;
        let mut xd1 = E::ZERO;
        xd1.0[EXT_DEG - 1] = F::ONE;
        assert_eq!(x * xd1, E::from_base(F(W)));
        // Associativity + distributivity on random elements.
        let mut s = 0x0123_4567_89ab_cdef;
        let r = |s: &mut u64| E(core::array::from_fn(|_| sample(s)));
        let (a, b, c) = (r(&mut s), r(&mut s), r(&mut s));
        assert_eq!((a * b) * c, a * (b * c));
        assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn ext_bytes_reject_non_canonical() {
        let mut b = E::ONE.to_bytes();
        assert_eq!(E::from_bytes(&b), Some(E::ONE));
        b[0..4].copy_from_slice(&P.to_le_bytes());
        assert_eq!(E::from_bytes(&b), None);
    }
}
