//! Top-level FRI verifier glue. Mirrors `plonk_verifier::verifier`'s
//! `verify` shape so the contract layer can swap flavors with only
//! its `include_bytes!` paths and proof-arg width changing.
//!
//! ## Flow
//!
//! 1. Parse the VK + proof bytes.
//! 2. Match the public-input count against the VK's declared `num_pi`.
//! 3. Initialise a Poseidon2 sponge transcript with a domain separator
//!    that pins:
//!    - the VK's `pcs_pinned_root` (binds verifier to circuit),
//!    - `(log_n, num_layers, num_queries, blowup_log)` (binds verifier
//!      to FRI parameters),
//!    - the `public_inputs` (binds verifier to claim).
//! 4. Hand off to `fri::verify_fri`.
//!
//! ## What's missing vs. a complete STARK verifier
//!
//! `verify_fri` proves "the prover committed to a polynomial of bounded
//! degree." A real STARK verifier *also* checks that the polynomial
//! satisfies the AIR constraints at the out-of-domain challenge `zeta`
//! — which requires a batched-PCS layer (random linear combination of
//! trace, quotient, and aux openings) on top of FRI. That layer is
//! deferred to a follow-up `verifier_pcs.rs`. Without it, this
//! verifier will accept FRI proofs whose underlying polynomial is
//! low-degree but unrelated to any constraint system; do **not** ship
//! the contracts behind this verifier without it.

use crate::field::Fr;
use crate::fri::{verify_fri, CommittedLayer, FriProof, FriVerifierParams, LayerOpening};
use crate::merkle::{Digest, DIGEST_LEN};
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

/// Verify a FRI-flavor proof. Mirrors the shape of `plonk_verifier::
/// verifier::verify`: bytes in, `Result<(), _>` out.
///
/// `public_inputs` is `[[u8; 4]]` — each PI is one canonical BabyBear
/// element little-endian. The contract layer above accepts the wider
/// `BytesN<32>` PI form (for shape parity with the PLONK flavor) and
/// reduces each PI down to its first 4 bytes here.
pub fn verify(
    env: &Env,
    vk_bytes: &[u8],
    proof_bytes: &[u8],
    public_inputs_le: &[[u8; 4]],
) -> Result<(), VerifyError> {
    let vk = parse_vk_bytes(vk_bytes)?;
    let proof = parse_proof_bytes(proof_bytes)?;

    if public_inputs_le.len() as u32 != vk.num_pi {
        return Err(VerifyError::PublicInputsMismatch {
            expected: vk.num_pi,
            actual: public_inputs_le.len() as u32,
        });
    }

    // Build the FRI-shaped view of the parsed proof. This is a pure
    // re-shape of the bytes already validated by the parser; the
    // verifier itself runs over the borrowed `FriProof<'_>`.
    let layers: Vec<CommittedLayer> = proof
        .layer_roots
        .iter()
        .map(|r| CommittedLayer { root: *r })
        .collect();

    // Per-query openings: pair each query's `query_values` slot with
    // the corresponding `query_paths_pos[q][i].leaf` (the Merkle leaf
    // is the value digest). The leaf for layer `i` of query `q` is
    // the 8-element padding of the `(pos, neg)` pair into a digest;
    // see `leaf_digest_for` below.
    let mut openings_pos: Vec<Vec<LayerOpening>> = Vec::with_capacity(proof.query_values.len());
    let mut openings_neg: Vec<Vec<LayerOpening>> = Vec::with_capacity(proof.query_values.len());
    for q in 0..proof.query_values.len() {
        let mut row_pos: Vec<LayerOpening> =
            Vec::with_capacity(proof.query_values[q].len());
        let mut row_neg: Vec<LayerOpening> =
            Vec::with_capacity(proof.query_values[q].len());
        for i in 0..proof.query_values[q].len() {
            let (pos, neg) = proof.query_values[q][i];
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

    // ---- Initialise the transcript --------------------------------
    let mut transcript = Transcript::new(env, b"onym-pq-fri-v1");
    // Bind the circuit identity (preprocessed-trace root).
    transcript.observe_slice(env, &vk.pcs_pinned_root);
    // Bind the FRI shape parameters.
    transcript.observe(env, Fr::new(vk.log_n));
    transcript.observe(env, Fr::new(vk.num_layers));
    transcript.observe(env, Fr::new(vk.num_queries));
    transcript.observe(env, Fr::new(vk.blowup_log));
    // Bind the public claim.
    for pi in public_inputs_le.iter() {
        let v = u32::from_le_bytes(*pi);
        if v >= crate::field::P {
            return Err(VerifyError::BadProof);
        }
        transcript.observe(env, Fr(v));
    }

    verify_fri(env, &mut transcript, &fri_proof, &params)
        .map_err(|_| VerifyError::FriRejected)?;
    Ok(())
}

/// Build a Merkle leaf digest from a single `Fr` value. Pads the lone
/// value into a `DIGEST_LEN`-wide block: `[v, 0, 0, 0, 0, 0, 0, 0]`.
/// The prover-side commitment must use the same padding for these
/// authentication paths to verify.
///
/// (Plonky3's prover commits row-batches — multiple polynomials at
/// each row coordinate — so its leaves are wider; the single-poly
/// FRI here uses one-element rows.)
fn leaf_digest_for(v: Fr) -> Digest {
    let mut d = [Fr::ZERO; DIGEST_LEN];
    d[0] = v;
    d
}

/// Used by the contract layer for its compile-time const-assert.
pub const FR_LEN: usize = 4;

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrong VK length short-circuits at `BadVk` before any other work.
    #[test]
    fn rejects_bad_vk_length() {
        let env = Env::default();
        let vk_bytes = [0u8; 16];
        let proof_bytes = [0u8; 16];
        let pi: [[u8; 4]; 0] = [];
        assert_eq!(
            verify(&env, &vk_bytes, &proof_bytes, &pi),
            Err(VerifyError::BadVk),
        );
    }
}
