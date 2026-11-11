//! Verifier parameters (the VK-equivalent for the membership AIR).
//!
//! ## Degrees
//!
//! - Trace: `n = 32·blocks` rows (see [`crate::air::Shape`]).
//! - Zero-knowledge: each trace column is `T + Z_H·R` with `R` random of
//!   degree `< h` (`mask_degree`), so trace polynomials have degree
//!   `< n + h ≤ 2n`. Quotient chunks get telescoping randomizers of the
//!   same degree. FRI therefore tests degree `< 2n`, and the LDE domain is
//!   `n₀ = 2n · blowup`.
//! - Hiding needs `h` above the number of evaluations revealed per
//!   column: `num_queries · 2^log_arities[0]` coset points plus 2 OOD
//!   points.
//! - The round constraint has degree `≤ 7(n + h − 1) + 31·n/32` (S-box ×
//!   periodic selector). Dividing by `xⁿ − 1` leaves the quotient, split
//!   into `num_quotient_chunks()` pieces of `n` coefficients.
//!
//! ## Wire format
//!
//! `[version=1, depth, mask_degree: u16 LE, log_blowup,
//!   num_queries: u16 LE, grind_bits, cap_height, k, log_arities[k]]`

use crate::air::{Shape, BLOCK};
use alloc::vec::Vec;

const VERSION: u8 = 1;
const HEADER_LEN: usize = 10;
const MAX_LOG_ARITY: u8 = 4;
const MAX_DEPTH: u8 = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub depth: u8,
    pub mask_degree: u16,
    pub log_blowup: u8,
    pub num_queries: u16,
    pub grind_bits: u8,
    pub cap_height: u8,
    pub log_arities: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct BadParams;

impl Params {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.log_arities.len());
        out.push(VERSION);
        out.push(self.depth);
        out.extend_from_slice(&self.mask_degree.to_le_bytes());
        out.push(self.log_blowup);
        out.extend_from_slice(&self.num_queries.to_le_bytes());
        out.push(self.grind_bits);
        out.push(self.cap_height);
        out.push(self.log_arities.len() as u8);
        out.extend_from_slice(&self.log_arities);
        out
    }

    pub fn from_bytes(b: &[u8]) -> Result<Params, BadParams> {
        if b.len() < HEADER_LEN || b[0] != VERSION {
            return Err(BadParams);
        }
        let k = b[9] as usize;
        if b.len() != HEADER_LEN + k {
            return Err(BadParams);
        }
        let p = Params {
            depth: b[1],
            mask_degree: u16::from_le_bytes([b[2], b[3]]),
            log_blowup: b[4],
            num_queries: u16::from_le_bytes([b[5], b[6]]),
            grind_bits: b[7],
            cap_height: b[8],
            log_arities: b[HEADER_LEN..].to_vec(),
        };
        p.validate()?;
        Ok(p)
    }

    pub fn validate(&self) -> Result<(), BadParams> {
        if !(1..=MAX_DEPTH).contains(&self.depth)
            || self.log_blowup < 1
            || self.num_queries < 1
            || self.grind_bits > 32
            || self.log_arities.is_empty()
            || !self.log_arities.iter().all(|&a| (1..=MAX_LOG_ARITY).contains(&a))
        {
            return Err(BadParams);
        }
        let folded: u32 = self.log_arities.iter().map(|&a| a as u32).sum();
        let h = self.mask_degree as usize;
        let revealed = self.num_queries as usize * (1 << self.log_arities[0]) + 2;
        let ok = self.log_n0() <= crate::field::TWO_ADICITY
            && folded + self.log_blowup as u32 <= self.log_n0()
            && h >= revealed
            && h <= self.n()
            && self.max_constraint_degree() < self.n0()
            && self.num_quotient_chunks() * self.n() <= self.n0();
        if ok {
            Ok(())
        } else {
            Err(BadParams)
        }
    }

    pub fn shape(&self) -> Shape {
        Shape::new(self.depth as usize)
    }

    pub fn n(&self) -> usize {
        self.shape().n()
    }

    pub fn log_n(&self) -> u32 {
        self.shape().log_n()
    }

    /// FRI degree bound `2n` (trace + mask degree fits under it).
    pub fn log_fri_bound(&self) -> u32 {
        self.log_n() + 1
    }

    pub fn log_n0(&self) -> u32 {
        self.log_fri_bound() + self.log_blowup as u32
    }

    pub fn n0(&self) -> usize {
        1 << self.log_n0()
    }

    pub fn max_constraint_degree(&self) -> usize {
        let n = self.n();
        let periodic = (n / BLOCK) * (BLOCK - 1);
        7 * (n + self.mask_degree as usize - 1) + periodic
    }

    pub fn num_quotient_chunks(&self) -> usize {
        let n = self.n();
        let q_deg = self.max_constraint_degree() - n;
        (q_deg + 1).div_ceil(n)
    }

    /// Columns in the quotient tree: `4 × chunks` (each extension-valued
    /// chunk as four base polynomials) + 4 for the FRI mask polynomial.
    pub fn quotient_cols(&self) -> usize {
        4 * self.num_quotient_chunks() + 4
    }

    pub fn num_layers(&self) -> usize {
        self.log_arities.len()
    }

    /// log₂ of the evaluation-domain size at FRI layer `j` (`j ≤ k`).
    pub fn log_layer(&self, j: usize) -> u32 {
        self.log_n0() - self.log_arities[..j].iter().map(|&a| a as u32).sum::<u32>()
    }

    /// log₂ of the number of Merkle leaves (= cosets) at layer `j < k`.
    pub fn log_leaves(&self, j: usize) -> u32 {
        self.log_layer(j) - self.log_arities[j] as u32
    }

    /// Effective cap height at layer `j`: never taller than the tree.
    pub fn cap_height_at(&self, j: usize) -> u32 {
        core::cmp::min(self.cap_height as u32, self.log_leaves(j))
    }

    pub fn final_poly_len(&self) -> usize {
        1 << (self.log_layer(self.num_layers()) - self.log_blowup as u32)
    }

    /// Conjectured soundness under the up-to-capacity proximity-gap
    /// conjecture: `log_blowup` bits per query, plus grinding.
    pub fn conjectured_security_bits(&self) -> u32 {
        self.num_queries as u32 * self.log_blowup as u32 + self.grind_bits as u32
    }

    /// Conservative estimate in the Johnson-bound regime: about half
    /// the bits per query, plus grinding.
    pub fn johnson_security_bits(&self) -> u32 {
        self.num_queries as u32 * self.log_blowup as u32 / 2 + self.grind_bits as u32
    }
}
