//! Verifier parameters (the VK-equivalent for this prototype).
//!
//! ## Domains
//!
//! The trace has `2^log_trace_rows` rows and `num_cols` base-field
//! columns, low-degree-extended to `n₀ = 2^(log_trace_rows +
//! log_blowup)`. Layer `j` folds a domain of size `n_j` by arity
//! `2^log_arities[j]`. Layer 0 is the trace commitment itself (the
//! DEEP quotient is computed from opened trace rows, not committed);
//! layers `1..k` commit FRI codewords. After the last fold the prover
//! sends the final polynomial's `n_k / blowup` coefficients.
//!
//! ## Wire format
//!
//! `[version=0, log_trace_rows, num_cols: u16 LE, log_blowup,
//!   num_queries: u16 LE, grind_bits, cap_height, k, log_arities[k]]`

use alloc::vec::Vec;

const VERSION: u8 = 0;
const HEADER_LEN: usize = 10;
const MAX_LOG_ARITY: u8 = 4;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Params {
    pub log_trace_rows: u8,
    pub num_cols: u16,
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
        out.push(self.log_trace_rows);
        out.extend_from_slice(&self.num_cols.to_le_bytes());
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
            log_trace_rows: b[1],
            num_cols: u16::from_le_bytes([b[2], b[3]]),
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
        let folded: u32 = self.log_arities.iter().map(|&a| a as u32).sum();
        let ok = self.num_cols >= 1
            && self.log_blowup >= 1
            && self.num_queries >= 1
            && self.grind_bits <= 32
            && !self.log_arities.is_empty()
            && self.log_arities.iter().all(|&a| (1..=MAX_LOG_ARITY).contains(&a))
            && self.log_n0() <= crate::field::TWO_ADICITY
            // The final polynomial must keep at least one coefficient.
            && folded + self.log_blowup as u32 <= self.log_n0();
        if ok {
            Ok(())
        } else {
            Err(BadParams)
        }
    }

    pub fn num_layers(&self) -> usize {
        self.log_arities.len()
    }

    pub fn log_n0(&self) -> u32 {
        self.log_trace_rows as u32 + self.log_blowup as u32
    }

    /// log₂ of the evaluation-domain size at layer `j` (`j ≤ k`).
    pub fn log_n(&self, j: usize) -> u32 {
        self.log_n0() - self.log_arities[..j].iter().map(|&a| a as u32).sum::<u32>()
    }

    /// log₂ of the number of Merkle leaves (= cosets) at layer `j < k`.
    pub fn log_leaves(&self, j: usize) -> u32 {
        self.log_n(j) - self.log_arities[j] as u32
    }

    /// Effective cap height at layer `j`: never taller than the tree.
    pub fn cap_height_at(&self, j: usize) -> u32 {
        core::cmp::min(self.cap_height as u32, self.log_leaves(j))
    }

    pub fn final_poly_len(&self) -> usize {
        1 << (self.log_n(self.num_layers()) - self.log_blowup as u32)
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
