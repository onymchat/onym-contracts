//! Serialise a `ProofWitness` into bytes that round-trip through
//! `fri_verifier::proof_format::parse_proof_bytes`.
//!
//! Layout (must match the parser exactly — header u32s little-
//! endian, field elements 32-byte BN254 BE, digests = single Fr):
//!
//! ```text
//!   [num_layers_plus_1: u32_le]
//!   [layer_root[i]: 32 B BE]   * (num_layers_plus_1)
//!   [final_poly_len: u32_le]
//!   [final_poly[k]: 32 B BE]   * (final_poly_len)
//!   [num_queries: u32_le]
//!   for q in 0..num_queries:
//!       for i in 0..num_layers_plus_1:
//!           [pos_value: 32 B BE]
//!           [neg_value: 32 B BE]
//!       for i in 0..num_layers_plus_1:
//!           [path_len: u32_le]
//!           [pos_path[k]: 32 B BE] * path_len
//!           [neg_path[k]: 32 B BE] * path_len
//! ```

use crate::fri_prover::ProofWitness;
use fri_verifier::field::{self, Fr};
use fri_verifier::merkle::Digest;

extern crate alloc;
use alloc::vec::Vec;

pub fn serialize_proof(witness: &ProofWitness) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(16 * 1024);

    // num_layers_plus_1
    out.extend_from_slice(&(witness.layer_roots.len() as u32).to_le_bytes());
    // layer roots
    for root in witness.layer_roots.iter() {
        write_digest(&mut out, root);
    }

    // final_poly
    out.extend_from_slice(&(witness.final_poly.len() as u32).to_le_bytes());
    for c in witness.final_poly.iter() {
        write_fr(&mut out, c);
    }

    // num_queries
    out.extend_from_slice(&(witness.query_openings.len() as u32).to_le_bytes());
    for query in witness.query_openings.iter() {
        for opening in query.iter() {
            write_fr(&mut out, &opening.pos_value);
            write_fr(&mut out, &opening.neg_value);
        }
        for opening in query.iter() {
            assert_eq!(
                opening.pos_path.len(),
                opening.neg_path.len(),
                "pos/neg paths must share length"
            );
            out.extend_from_slice(&(opening.pos_path.len() as u32).to_le_bytes());
            for d in opening.pos_path.iter() {
                write_digest(&mut out, d);
            }
            for d in opening.neg_path.iter() {
                write_digest(&mut out, d);
            }
        }
    }

    out
}

fn write_fr(out: &mut Vec<u8>, x: &Fr) {
    out.extend_from_slice(&field::to_be_bytes(x));
}

fn write_digest(out: &mut Vec<u8>, d: &Digest) {
    write_fr(out, d);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fri_prover::prove;
    use fri_verifier::proof_format::parse_proof_bytes;
    use soroban_sdk::Env;

    #[test]
    fn serialised_proof_parses() {
        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();
        let pi: [[u8; 32]; 2] = [[0u8; 32]; 2];
        let witness = prove(&env, &pi);
        let bytes = serialize_proof(&witness);
        let parsed = parse_proof_bytes(&env, &bytes).expect("parser should accept");
        assert_eq!(parsed.layer_roots.len(), witness.layer_roots.len());
        assert_eq!(parsed.final_poly.len(), witness.final_poly.len());
        assert_eq!(parsed.query_values.len(), witness.query_openings.len());
    }
}
