//! BabyBear (p = 2^31 - 2^27 + 1 = 2 013 265 921) prime field, no_std.
//!
//! BabyBear is the canonical Plonky3 small-prime field for FRI-based
//! PQ proof systems: 31-bit prime, single-`u32` storage, products fit
//! in `u64` so reduction never crosses 128-bit ALU boundaries — which
//! matters in WASM, where there is no native 64×64→128 multiply and
//! `i64.mul` truncates. Goldilocks (2^64 − 2^32 + 1) would force
//! manual schoolbook multiplication on every mul; BabyBear keeps mul
//! within a single host instruction at the WASM level.
//!
//! ## Form
//!
//! Elements are stored in canonical (non-Montgomery) form as `u32`
//! values in `[0, P)`. Multiplications produce a 62-bit `u64` product
//! and reduce with native `% P` — WASM exposes `i64.rem_u` as a
//! single instruction, and (P-1)^2 < 2^62 fits comfortably in `u64`.
//! We deliberately avoid Montgomery form here so byte-level interop
//! with the on-chain Poseidon2 host primitive (which consumes/returns
//! canonical 4-byte BabyBear elements) needs no `to_montgomery` /
//! `from_montgomery` plumbing on every host crossing.
//!
//! ## Byte encoding
//!
//! Field elements are serialised little-endian in 4 bytes (`u32`
//! LE bytes) — matches Plonky3 prover-side `BabyBear::as_canonical_u32`
//! followed by `to_le_bytes`. A 32-byte `BytesN<32>` carrying 8
//! BabyBear elements (used as commitments / public-input hashes by
//! the contract layer) packs them in index-ascending order:
//! `[el0_LE | el1_LE | ... | el7_LE]`.

use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

/// BabyBear modulus.
pub const P: u32 = 0x78000001;

/// One element of `F_p`. Always in `[0, P)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default, Hash)]
pub struct Fr(pub u32);

impl Fr {
    pub const ZERO: Fr = Fr(0);
    pub const ONE: Fr = Fr(1);

    #[inline(always)]
    pub fn new(v: u32) -> Self {
        // Reduce on the way in. Cheap relative to a single mul.
        Fr(v % P)
    }

    /// Decode from canonical 4-byte little-endian. Returns `None` if
    /// `value >= P` (not canonical).
    #[inline]
    pub fn from_canonical_le_bytes(bytes: &[u8; 4]) -> Option<Self> {
        let v = u32::from_le_bytes(*bytes);
        if v >= P {
            None
        } else {
            Some(Fr(v))
        }
    }

    /// Encode to canonical 4-byte little-endian.
    #[inline]
    pub fn to_le_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }

    #[inline]
    pub fn as_u32(self) -> u32 {
        self.0
    }

    /// `self^exp` by square-and-multiply.
    pub fn pow(mut self, mut exp: u64) -> Self {
        let mut acc = Fr::ONE;
        while exp > 0 {
            if exp & 1 == 1 {
                acc = acc * self;
            }
            self = self * self;
            exp >>= 1;
        }
        acc
    }

    /// Multiplicative inverse via Fermat's little theorem.
    /// Panics on zero (callers must guard).
    pub fn inverse(self) -> Self {
        debug_assert!(self.0 != 0, "Fr::inverse called on zero");
        // p - 2 = 2_013_265_919
        self.pow((P - 2) as u64)
    }
}

#[inline(always)]
fn add_mod(a: u32, b: u32) -> u32 {
    let s = a.wrapping_add(b);
    // s ∈ [0, 2P). Subtract P if s ≥ P.
    let s2 = s.wrapping_sub(P);
    if (s2 as i32) >= 0 {
        s2
    } else {
        s
    }
}

#[inline(always)]
fn sub_mod(a: u32, b: u32) -> u32 {
    let (d, borrow) = a.overflowing_sub(b);
    if borrow {
        d.wrapping_add(P)
    } else {
        d
    }
}

#[inline(always)]
fn neg_mod(a: u32) -> u32 {
    if a == 0 {
        0
    } else {
        P - a
    }
}

/// Reduce a 62-bit product into `[0, P)`.
///
/// `(P-1)^2 = (2^31 - 2^27)^2 < 2^62`, so the full product fits in
/// `u64`. WASM exposes `i64.rem_u` natively (one instruction), so a
/// straight `%` is the cheapest path with no constants to keep in sync.
#[inline(always)]
fn mul_reduce(a: u32, b: u32) -> u32 {
    let t: u64 = (a as u64) * (b as u64);
    (t % (P as u64)) as u32
}

impl Add for Fr {
    type Output = Fr;
    #[inline]
    fn add(self, rhs: Fr) -> Fr {
        Fr(add_mod(self.0, rhs.0))
    }
}

impl AddAssign for Fr {
    #[inline]
    fn add_assign(&mut self, rhs: Fr) {
        self.0 = add_mod(self.0, rhs.0);
    }
}

impl Sub for Fr {
    type Output = Fr;
    #[inline]
    fn sub(self, rhs: Fr) -> Fr {
        Fr(sub_mod(self.0, rhs.0))
    }
}

impl SubAssign for Fr {
    #[inline]
    fn sub_assign(&mut self, rhs: Fr) {
        self.0 = sub_mod(self.0, rhs.0);
    }
}

impl Neg for Fr {
    type Output = Fr;
    #[inline]
    fn neg(self) -> Fr {
        Fr(neg_mod(self.0))
    }
}

impl Mul for Fr {
    type Output = Fr;
    #[inline]
    fn mul(self, rhs: Fr) -> Fr {
        Fr(mul_reduce(self.0, rhs.0))
    }
}

impl MulAssign for Fr {
    #[inline]
    fn mul_assign(&mut self, rhs: Fr) {
        self.0 = mul_reduce(self.0, rhs.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_sub_roundtrip() {
        let a = Fr::new(0x12345678);
        let b = Fr::new(0x71000000);
        let c = a + b;
        assert_eq!(c - b, a);
        assert_eq!(c - a, b);
    }

    #[test]
    fn mul_zero() {
        let a = Fr::new(12345);
        assert_eq!(a * Fr::ZERO, Fr::ZERO);
        assert_eq!(Fr::ZERO * a, Fr::ZERO);
    }

    #[test]
    fn mul_one() {
        let a = Fr::new(0x12345);
        assert_eq!(a * Fr::ONE, a);
    }

    #[test]
    fn neg_addition() {
        let a = Fr::new(123456789);
        assert_eq!(a + (-a), Fr::ZERO);
    }

    #[test]
    fn inverse_roundtrip() {
        let a = Fr::new(0x1234567);
        let inv = a.inverse();
        assert_eq!(a * inv, Fr::ONE);
    }

    #[test]
    fn pow_matches_repeated_mul() {
        let a = Fr::new(7);
        // 7^5 = 16807, well under P
        assert_eq!(a.pow(5), Fr::new(16807));
    }

    #[test]
    fn from_canonical_le_bytes_rejects_oversized() {
        // P = 0x78000001 — encode P itself, must reject.
        let bytes = P.to_le_bytes();
        assert!(Fr::from_canonical_le_bytes(&bytes).is_none());
        // P-1 must accept.
        let bytes = (P - 1).to_le_bytes();
        assert_eq!(
            Fr::from_canonical_le_bytes(&bytes),
            Some(Fr(P - 1))
        );
    }

    #[test]
    fn to_from_le_bytes_roundtrip() {
        let a = Fr::new(0x77ffff00);
        let bytes = a.to_le_bytes();
        assert_eq!(Fr::from_canonical_le_bytes(&bytes), Some(a));
    }

    /// Pin `P` against the spec: BabyBear is 2^31 - 2^27 + 1.
    #[test]
    fn p_constant() {
        assert_eq!(P, (1u32 << 31) - (1u32 << 27) + 1);
        assert_eq!(P, 2_013_265_921);
    }
}
