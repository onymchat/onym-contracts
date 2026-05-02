//! Top-level FRI verifier glue.
//!
//! ## Flow
//!
//! 1. Parse VK + proof bytes.
//! 2. Match the public-input count against the VK's declared `num_pi`.
//! 3. Initialise a Poseidon2-BN254-t3 sponge transcript and bind:
//!    - the VK's `pcs_pinned_root` (binds verifier to circuit-shape),
//!    - `(log_n, num_layers, num_queries, blowup_log)`,
//!    - the public inputs.
//! 4. Hand off to `fri::verify_fri`.
//!
//! ## What's missing vs. a complete STARK verifier
//!
//! `verify_fri` proves "the prover committed to a low-degree
//! polynomial". A real STARK verifier *also* checks the polynomial
//! satisfies AIR constraints at the out-of-domain challenge `zeta`,
//! via a batched-PCS layer of trace + quotient + aux openings. That
//! layer is the **next** verifier file (`verifier_pcs.rs`) and is
//! not yet built. Until it lands, do not deploy the contract behind
//! this verifier — the FRI low-degree test alone does not bind
//! to any circuit.

use crate::field::{self, Fr};
use crate::fri::{verify_fri, CommittedLayer, FriProof, FriVerifierParams, LayerOpening};
use crate::host_poseidon2::Poseidon2Ctx;
use crate::merkle::Digest;
use crate::proof_format::{parse_proof_bytes, ProofParseError};
use crate::transcript::Transcript;
use crate::vk_format::{parse_vk_bytes, VkParseError};
use alloc::vec::Vec;
use soroban_sdk::Env;

extern crate alloc;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadVk,
    BadProof,
    PublicInputsMismatch { expected: u32, actual: u32 },
    NonCanonicalPi,
    FriRejected,
}

impl From<VkParseError> for VerifyError {
    fn from(_: VkParseError) -> Self {
        VerifyError::BadVk
    }
}

impl From<ProofParseError> for VerifyError {
    fn from(_: ProofParseError) -> Self {
        VerifyError::BadProof
    }
}

/// Verify a FRI-flavor proof.
///
/// `public_inputs_be` is `[[u8; 32]]` — each PI is one canonical BN254
/// Fr in big-endian. The contract layer above passes
/// `Vec<BytesN<32>>` directly through.
pub fn verify(
    env: &Env,
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_be: &[[u8; 32]],
) -> Result<(), VerifyError> {
    let vk = parse_vk_bytes(env, vk_bytes)?;
    let proof = parse_proof_bytes(env, proof_bytes)?;

    if public_inputs_be.len() as u32 != vk.num_pi {
        return Err(VerifyError::PublicInputsMismatch {
            expected: vk.num_pi,
            actual: public_inputs_be.len() as u32,
        });
    }

    // ---- Build the FRI-shaped view of the parsed proof. ----------
    let layers: Vec<CommittedLayer> = proof
        .layer_roots
        .iter()
        .map(|r| CommittedLayer { root: r.clone() })
        .collect();

    let mut openings_pos: Vec<Vec<LayerOpening>> = Vec::with_capacity(proof.query_values.len());
    let mut openings_neg: Vec<Vec<LayerOpening>> = Vec::with_capacity(proof.query_values.len());
    for q in 0..proof.query_values.len() {
        let mut row_pos: Vec<LayerOpening> = Vec::with_capacity(proof.query_values[q].len());
        let mut row_neg: Vec<LayerOpening> = Vec::with_capacity(proof.query_values[q].len());
        for i in 0..proof.query_values[q].len() {
            let (pos, neg) = proof.query_values[q][i].clone();
            row_pos.push(LayerOpening {
                leaf: leaf_digest_for(pos),
                siblings: &proof.query_paths_pos[q][i],
            });
            row_neg.push(LayerOpening {
                leaf: leaf_digest_for(neg),
                siblings: &proof.query_paths_neg[q][i],
            });
        }
        openings_pos.push(row_pos);
        openings_neg.push(row_neg);
    }

    let openings_pos_refs: Vec<&[LayerOpening]> =
        openings_pos.iter().map(|v| v.as_slice()).collect();
    let openings_neg_refs: Vec<&[LayerOpening]> =
        openings_neg.iter().map(|v| v.as_slice()).collect();
    let query_values_refs: Vec<&[(Fr, Fr)]> =
        proof.query_values.iter().map(|v| v.as_slice()).collect();

    let fri_proof = FriProof {
        layers: &layers,
        queries: &openings_pos_refs,
        queries_neg: &openings_neg_refs,
        query_values: &query_values_refs,
        final_poly: &proof.final_poly,
    };

    let params = FriVerifierParams {
        log_n: vk.log_n,
        num_layers: vk.num_layers,
        num_queries: vk.num_queries,
        omega_0: vk.omega_0,
        omega_0_inv: vk.omega_0_inv,
        two_inv: vk.two_inv,
    };

    // ---- Initialise the Poseidon2 ctx + transcript. --------------
    let ctx = Poseidon2Ctx::new(env);
    let mut transcript = Transcript::new(env, &ctx, b"onym-pq-fri-v2");

    // Bind the circuit identity (preprocessed-trace root).
    transcript.observe(vk.pcs_pinned_root);
    // Bind the FRI shape parameters.
    transcript.observe(field::from_u32(env, vk.log_n));
    transcript.observe(field::from_u32(env, vk.num_layers));
    transcript.observe(field::from_u32(env, vk.num_queries));
    transcript.observe(field::from_u32(env, vk.blowup_log));
    // Bind the public claim.
    for pi in public_inputs_be.iter() {
        if !field::is_canonical_be(env, pi) {
            return Err(VerifyError::NonCanonicalPi);
        }
        transcript.observe(field::from_be_bytes(env, pi));
    }

    verify_fri(env, &ctx, &mut transcript, &fri_proof, &params)
        .map_err(|_| VerifyError::FriRejected)?;
    Ok(())
}

/// Build a Merkle leaf digest from a single `Fr`. With t=3 + capacity 1
/// the leaf hash is the value itself — the first compression layer
/// of the tree handles the (sibling, sibling) pair.
fn leaf_digest_for(v: Fr) -> Digest {
    v
}

/// Used by the contract layer for its compile-time assertions.
pub const FR_LEN: usize = 32;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_vk_length() {
        let env = Env::default();
        let vk_bytes = [0u8; 16];
        let proof_bytes = [0u8; 16];
        let pi: [[u8; 32]; 0] = [];
        assert_eq!(
            verify(&env, &vk_bytes, &proof_bytes, &pi),
            Err(VerifyError::BadVk),
        );
    }
}
