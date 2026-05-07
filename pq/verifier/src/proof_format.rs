//! BN254-flavor FRI proof byte layout.
//!
//! ## Layout
//!
//! Variable-length, length-prefixed sections. Counts are `u32` LE;
//! field elements are 32-byte BN254 Fr **big-endian** (matching the
//! SDK's `Fr::to_bytes` / `Fr::from_bytes` convention); digests are
//! single Fr (32 bytes).
//!
//! ```text
//!   [num_layers_plus_1: u32_le]
//!   [layer_root[i]: 32 B]                  * (num_layers_plus_1)
//!
//!   [final_poly_len: u32_le]
//!   [final_poly_coef[k]: 32 B]             * (final_poly_len)
//!
//!   [num_queries: u32_le]
//!   for q in 0..num_queries:
//!       for i in 0..=num_layers:
//!           [pos_value: 32 B]
//!           [neg_value: 32 B]
//!       for i in 0..=num_layers:
//!           [path_len: u32_le]
//!           [pos_path[k]: 32 B]            * path_len
//!           [neg_path[k]: 32 B]            * path_len
//! ```
//!
//! Bench-scope params (log_n=6, num_layers=3, num_queries=8) produce
//! ~10 KB proofs. Production parameters (log_n≥20, num_queries≈80)
//! give proofs in the ~MB range; that's where the batched-PCS layer
//! becomes essential, since a single FRI invocation under those
//! parameters times 1 polynomial is comparable in cost to a single
//! invocation times N polynomials when batched.

use crate::field::{self, Fr};
use crate::merkle::Digest;
use alloc::vec::Vec;
use soroban_sdk::Env;

extern crate alloc;

const FR_LEN: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedProof {
    pub layer_roots: Vec<Digest>,
    pub final_poly: Vec<Fr>,
    pub query_values: Vec<Vec<(Fr, Fr)>>,
    pub query_paths_pos: Vec<Vec<Vec<Digest>>>,
    pub query_paths_neg: Vec<Vec<Vec<Digest>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ProofParseError {
    Truncated,
    NonCanonicalField,
    OutOfRange,
}

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

    fn read_fr(&mut self, env: &Env) -> Result<Fr, ProofParseError> {
        if self.pos + FR_LEN > self.buf.len() {
            return Err(ProofParseError::Truncated);
        }
        let arr: [u8; FR_LEN] = self.buf[self.pos..self.pos + FR_LEN]
            .try_into()
            .unwrap();
        if !field::is_canonical_be(env, &arr) {
            return Err(ProofParseError::NonCanonicalField);
        }
        self.pos += FR_LEN;
        Ok(field::from_be_bytes(env, &arr))
    }

    fn read_digest(&mut self, env: &Env) -> Result<Digest, ProofParseError> {
        self.read_fr(env)
    }
}

pub fn parse_proof_bytes(env: &Env, bytes: &[u8]) -> Result<ParsedProof, ProofParseError> {
    let mut c = Cursor::new(bytes);

    let num_layers_plus_1 = c.read_u32()? as usize;
    if num_layers_plus_1 == 0 || num_layers_plus_1 > MAX_LAYERS + 1 {
        return Err(ProofParseError::OutOfRange);
    }

    let mut layer_roots = Vec::with_capacity(num_layers_plus_1);
    for _ in 0..num_layers_plus_1 {
        layer_roots.push(c.read_digest(env)?);
    }

    let final_poly_len = c.read_u32()? as usize;
    if final_poly_len > MAX_FINAL_POLY {
        return Err(ProofParseError::OutOfRange);
    }
    let mut final_poly = Vec::with_capacity(final_poly_len);
    for _ in 0..final_poly_len {
        final_poly.push(c.read_fr(env)?);
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
            let pos = c.read_fr(env)?;
            let neg = c.read_fr(env)?;
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
                sibs_pos.push(c.read_digest(env)?);
            }
            let mut sibs_neg: Vec<Digest> = Vec::with_capacity(path_len);
            for _ in 0..path_len {
                sibs_neg.push(c.read_digest(env)?);
            }
            paths_pos.push(sibs_pos);
            paths_neg.push(sibs_neg);
        }
        query_paths_pos.push(paths_pos);
        query_paths_neg.push(paths_neg);
    }

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

    #[test]
    fn rejects_truncated() {
        let env = Env::default();
        assert_eq!(
            parse_proof_bytes(&env, &[0u8; 2]),
            Err(ProofParseError::Truncated),
        );
    }

    #[test]
    fn rejects_zero_layers() {
        let env = Env::default();
        let mut buf = [0u8; 4];
        buf[0..4].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            parse_proof_bytes(&env, &buf),
            Err(ProofParseError::OutOfRange),
        );
    }
}
