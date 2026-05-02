//! FRI-flavor proof byte layout.
//!
//! ## Layout
//!
//! Variable-length, length-prefixed sections. Every count is `u32`
//! little-endian; field elements are `u32` little-endian; digests
//! are 8 × `u32` LE = 32 bytes. The on-chain entry surface accepts
//! a `Bytes` blob (Soroban variable byte arg); this parser slices it
//! into the structured `ParsedProof` the verifier consumes.
//!
//! ```text
//!   [num_layers: u32]
//!   [layer_root[0]: 32 B]
//!   …
//!   [layer_root[num_layers]: 32 B]      // num_layers + 1 commitments
//!
//!   [final_poly_len: u32]
//!   [final_poly_coeff[0..final_poly_len]: 4 B each]
//!
//!   [num_queries: u32]
//!   for q in 0..num_queries:
//!       for i in 0..=num_layers:
//!           [pos_value: 4 B]
//!           [neg_value: 4 B]            // (only the first num_layers
//!                                         layers carry a neg parent
//!                                         in the fold; the final
//!                                         layer's neg slot is unused
//!                                         and parsed as zero)
//!       for i in 0..=num_layers:
//!           [path_len: u32]
//!           [pos_siblings[0..path_len]: 32 B each]
//!           [neg_siblings[0..path_len]: 32 B each]
//! ```
//!
//! ## Size budget
//!
//! For a depth-15 trace with 80 queries, ~10 fold layers, depth-15
//! Merkle paths, the proof is roughly:
//!
//! ```text
//!   layer_roots :  11 × 32     ≈    352 B
//!   final_poly  :  ~16 × 4     ≈     64 B
//!   per query   :  11 × 8 +
//!                  11 × (32 × 15 × 2) ≈   ≈ 10.5 KB
//!   80 queries  :              ≈   840 KB
//! ```
//!
//! That's at the upper edge of Soroban's per-tx blob caps, so future
//! tuning should consider folding factor 4 (cuts query work ~4×) and
//! merkle-cap optimisations (cap at depth 4 → omit the first 4 levels
//! of every path). Both are out of scope for this skeleton.

use crate::field::{Fr, P};
use crate::merkle::{Digest, DIGEST_LEN};
use alloc::vec::Vec;

extern crate alloc;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedProof {
    pub layer_roots: Vec<Digest>,
    pub final_poly: Vec<Fr>,
    /// Per query: (pos, neg) value pairs at each of the `num_layers + 1`
    /// commitments. The neg slot at the final commitment is unused
    /// (folding has terminated) and parsed as `Fr::ZERO`.
    pub query_values: Vec<Vec<(Fr, Fr)>>,
    /// Per query: positive-parent Merkle authentication paths.
    pub query_paths_pos: Vec<Vec<Vec<Digest>>>,
    /// Per query: negative-parent Merkle authentication paths.
    pub query_paths_neg: Vec<Vec<Vec<Digest>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProofParseError {
    /// Ran out of bytes mid-parse (truncated proof).
    Truncated,
    /// A field-element byte sequence was ≥ P (not canonical).
    NonCanonicalField,
    /// A length prefix exceeded the verifier's hard caps.
    OutOfRange,
}

/// Hard caps used to bound the parser's work. The verifier itself
/// enforces tighter shape checks against the VK; these are
/// resource-protection limits.
const MAX_LAYERS: usize = 32;
const MAX_QUERIES: usize = 256;
const MAX_PATH_LEN: usize = 32;
const MAX_FINAL_POLY: usize = 64;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn read_u32(&mut self) -> Result<u32, ProofParseError> {
        if self.pos + 4 > self.buf.len() {
            return Err(ProofParseError::Truncated);
        }
        let v = u32::from_le_bytes(self.buf[self.pos..self.pos + 4].try_into().unwrap());
        self.pos += 4;
        Ok(v)
    }

    fn read_fr(&mut self) -> Result<Fr, ProofParseError> {
        let v = self.read_u32()?;
        if v >= P {
            return Err(ProofParseError::NonCanonicalField);
        }
        Ok(Fr(v))
    }

    fn read_digest(&mut self) -> Result<Digest, ProofParseError> {
        let mut d = [Fr::ZERO; DIGEST_LEN];
        for i in 0..DIGEST_LEN {
            d[i] = self.read_fr()?;
        }
        Ok(d)
    }
}

pub fn parse_proof_bytes(bytes: &[u8]) -> Result<ParsedProof, ProofParseError> {
    let mut c = Cursor::new(bytes);

    let num_layers_plus_1 = c.read_u32()? as usize;
    if num_layers_plus_1 == 0 || num_layers_plus_1 > MAX_LAYERS + 1 {
        return Err(ProofParseError::OutOfRange);
    }
    let num_layers = num_layers_plus_1 - 1;

    let mut layer_roots = Vec::with_capacity(num_layers_plus_1);
    for _ in 0..num_layers_plus_1 {
        layer_roots.push(c.read_digest()?);
    }

    let final_poly_len = c.read_u32()? as usize;
    if final_poly_len > MAX_FINAL_POLY {
        return Err(ProofParseError::OutOfRange);
    }
    let mut final_poly = Vec::with_capacity(final_poly_len);
    for _ in 0..final_poly_len {
        final_poly.push(c.read_fr()?);
    }

    let num_queries = c.read_u32()? as usize;
    if num_queries == 0 || num_queries > MAX_QUERIES {
        return Err(ProofParseError::OutOfRange);
    }

    let mut query_values: Vec<Vec<(Fr, Fr)>> = Vec::with_capacity(num_queries);
    let mut query_paths_pos: Vec<Vec<Vec<Digest>>> = Vec::with_capacity(num_queries);
    let mut query_paths_neg: Vec<Vec<Vec<Digest>>> = Vec::with_capacity(num_queries);

    for _ in 0..num_queries {
        let mut values: Vec<(Fr, Fr)> = Vec::with_capacity(num_layers_plus_1);
        for _ in 0..num_layers_plus_1 {
            let pos = c.read_fr()?;
            let neg = c.read_fr()?;
            values.push((pos, neg));
        }
        query_values.push(values);

        let mut paths_pos: Vec<Vec<Digest>> = Vec::with_capacity(num_layers_plus_1);
        let mut paths_neg: Vec<Vec<Digest>> = Vec::with_capacity(num_layers_plus_1);
        for _ in 0..num_layers_plus_1 {
            let path_len = c.read_u32()? as usize;
            if path_len > MAX_PATH_LEN {
                return Err(ProofParseError::OutOfRange);
            }
            let mut sibs_pos: Vec<Digest> = Vec::with_capacity(path_len);
            for _ in 0..path_len {
                sibs_pos.push(c.read_digest()?);
            }
            let mut sibs_neg: Vec<Digest> = Vec::with_capacity(path_len);
            for _ in 0..path_len {
                sibs_neg.push(c.read_digest()?);
            }
            paths_pos.push(sibs_pos);
            paths_neg.push(sibs_neg);
        }
        query_paths_pos.push(paths_pos);
        query_paths_neg.push(paths_neg);
    }

    let _ = num_layers; // num_layers derived above; kept named for clarity.

    Ok(ParsedProof {
        layer_roots,
        final_poly,
        query_values,
        query_paths_pos,
        query_paths_neg,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Truncated bytes return `Truncated`.
    #[test]
    fn rejects_truncated() {
        assert_eq!(
            parse_proof_bytes(&[0u8; 2]),
            Err(ProofParseError::Truncated),
        );
    }

    /// `num_layers + 1 == 0` is rejected (cannot decrement to a valid
    /// num_layers).
    #[test]
    fn rejects_zero_layers() {
        let mut buf = [0u8; 4];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_proof_bytes(&buf),
            Err(ProofParseError::OutOfRange),
        );
    }
}
