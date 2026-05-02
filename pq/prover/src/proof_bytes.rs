//! Serialise a `ProofWitness` into bytes that round-trip through
//! `fri_verifier::proof_format::parse_proof_bytes`.
//!
//! Layout (must match the parser exactly):
//!
//! ```text
//!   [num_layers_plus_1: u32_le]
//!   [layer_root[i]: Digest]   * (num_layers_plus_1)
//!   [final_poly_len: u32_le]
//!   [final_poly[k]: Fr]       * (final_poly_len)
//!   [num_queries: u32_le]
//!   for q in 0..num_queries:
//!       for i in 0..num_layers_plus_1:
//!           [pos_value: Fr]
//!           [neg_value: Fr]
//!       for i in 0..num_layers_plus_1:
//!           [pos_path_len: u32_le]
//!           [pos_path[k]: Digest] * pos_path_len
//!           [neg_path[k]: Digest] * pos_path_len  (same length as pos)
//! ```
//!
//! The parser's per-path-pair format is "one path_len header followed
//! by `path_len` pos digests then `path_len` neg digests" — pos and
//! neg share the length field. The prover guarantees the two paths
//! have the same length (they live in the same Merkle tree at the
//! same layer).

use crate::fri_prover::ProofWitness;
use fri_verifier::field::Fr;
use fri_verifier::merkle::Digest;

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
        write_fr(&mut out, *c);
    }

    // num_queries
    out.extend_from_slice(&(witness.query_openings.len() as u32).to_le_bytes());
    for query in witness.query_openings.iter() {
        // (pos, neg) values, layer 0 .. num_layers_plus_1-1
        for opening in query.iter() {
            write_fr(&mut out, opening.pos_value);
            write_fr(&mut out, opening.neg_value);
        }
        // (pos_path, neg_path) for each layer.
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

fn write_fr(out: &mut Vec<u8>, x: Fr) {
    out.extend_from_slice(&x.to_le_bytes());
}

fn write_digest(out: &mut Vec<u8>, d: &Digest) {
    for lane in d.iter() {
        write_fr(out, *lane);
    }
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
        let pi: [[u8; 4]; 16] = [[0u8; 4]; 16];
        let witness = prove(&env, &pi);
        let bytes = serialize_proof(&witness);
        let parsed = parse_proof_bytes(&bytes).expect("parser should accept");
        assert_eq!(parsed.layer_roots.len(), witness.layer_roots.len());
        assert_eq!(parsed.final_poly.len(), witness.final_poly.len());
        assert_eq!(parsed.query_values.len(), witness.query_openings.len());
    }
}
