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
//! `[version=2, kind, depth, mask_degree: u16 LE, log_blowup,
//!   num_queries: u16 LE, grind_bits, cap_height, k, log_arities[k]]`

use crate::air::{Kind, Shape, BLOCK};
use alloc::vec::Vec;

const VERSION: u8 = 2;
const HEADER_LEN: usize = 11;
const MAX_LOG_ARITY: u8 = 4;
const MAX_DEPTH: u8 = 20;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub kind: Kind,
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
        out.push(self.kind as u8);
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
        let k = b[10] as usize;
        if b.len() != HEADER_LEN + k {
            return Err(BadParams);
        }
        let p = Params {
            kind: Kind::from_u8(b[1]).ok_or(BadParams)?,
            depth: b[2],
            mask_degree: u16::from_le_bytes([b[3], b[4]]),
            log_blowup: b[5],
            num_queries: u16::from_le_bytes([b[6], b[7]]),
            grind_bits: b[8],
            cap_height: b[9],
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
        Shape::new(self.depth as usize, self.kind)
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

/// Security profile for a deployment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Profile {
    /// ~100 bits counting half of `log₂(blowup)` per query (Johnson-bound
    /// regime) plus 20 grinding bits: 40 queries at blowup 16.
    Johnson100,
    /// ~100 bits under the up-to-capacity proximity-gap conjecture:
    /// 20 queries at blowup 16 plus 20 grinding bits.
    Conjectured100,
}

/// The parameters a deployed contract pins for `(kind, depth)`. Single
/// source of truth for the contract and the prover.
pub fn deployment_params(kind: Kind, depth: u8, profile: Profile) -> Params {
    let num_queries: u16 = match profile {
        Profile::Johnson100 => 40,
        Profile::Conjectured100 => 20,
    };
    let log_blowup = 4u8;
    let mut p = Params {
        kind,
        depth,
        // Hiding: covers num_queries × 2 coset points + 2 OOD points.
        mask_degree: num_queries * 2 + 2,
        log_blowup,
        num_queries,
        grind_bits: 20,
        cap_height: 4,
        log_arities: Vec::new(),
    };
    // Arity 2 at layer 0 (trace rows per leaf), then 8 until the final
    // polynomial is a constant.
    let mut rem = p.log_n0() - 1 - log_blowup as u32;
    p.log_arities.push(1);
    while rem > 0 {
        let a = rem.min(3);
        p.log_arities.push(a as u8);
        rem -= a;
    }
    p
}
