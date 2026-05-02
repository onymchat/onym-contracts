//! FRI low-degree test verifier (folding factor 2).
//!
//! ## Scope
//!
//! This module verifies a *single-polynomial* FRI proof: given a
//! Merkle commitment to a codeword `f: D → F` over a coset `D` of
//! size `n = 2^log_n`, and a sequence of fold challenges and
//! commitments, attest that `f` is δ-close to a polynomial of degree
//! `< n / blowup`.
//!
//! Plonky3's full PCS verifier batches multiple polynomial openings
//! into a single FRI invocation via a random linear combination at
//! an out-of-domain point `zeta`. That batching layer is **not** in
//! this module — see crate-level README. A future `verifier_pcs.rs`
//! will sit between contract entry and `verify_fri`, taking the
//! per-polynomial trace/quotient/aux commitments and reducing them
//! to a single codeword commitment that this routine consumes.
//!
//! ## Folding equation
//!
//! With folding factor 2 and a multiplicative subgroup domain whose
//! `i`-th element is `ω^i`:
//!
//! ```text
//!   f_{i+1}(x^2) = (f_i(x) + f_i(-x))/2 + β_i · (f_i(x) - f_i(-x))/(2x)
//! ```
//!
//! At a query index `q` in layer `i+1`, the consistency check pulls
//! the two parents `(p, p_neg) = (f_i(q), f_i(q + n_i/2))` and tests:
//!
//! ```text
//!   f_{i+1}(q) ?= (p + p_neg)/2 + β_i · (p - p_neg) / (2 · ω_i^q)
//! ```
//!
//! `ω_i` is the layer-`i` domain generator: `ω_0` is the order-`n_0`
//! root of unity, `ω_i = ω_0^(2^i)`.

use crate::field::Fr;
use crate::merkle::{verify_path, Digest, MerkleError};
use crate::transcript::Transcript;
use soroban_sdk::Env;

/// A single Merkle authentication-path opening at one query index.
/// Same shape as `merkle::Digest` for the leaf, plus the sibling chain.
#[derive(Clone, Debug)]
pub struct LayerOpening<'a> {
    pub leaf: Digest,
    pub siblings: &'a [Digest],
}

/// One layer of the FRI proof: a Merkle root of the codeword
/// `f_i: D_i → F`, where the prover squeezed `β_{i-1}` from the
/// transcript before committing.
#[derive(Clone, Debug)]
pub struct CommittedLayer {
    pub root: Digest,
}

/// Complete FRI proof in verifier-consumable form. Constructed by the
/// proof-bytes parser; this struct is the verifier's view.
#[derive(Clone, Debug)]
pub struct FriProof<'a> {
    /// Initial codeword commitment. `layers[0].root` commits to
    /// `f_0: D_0 → F`, |D_0| = 2^log_n.
    pub layers: &'a [CommittedLayer],
    /// Per-query openings: queries[q][i] is the opening of `f_i` at
    /// query `q`'s level-i index. Length: num_queries × num_layers.
    pub queries: &'a [&'a [LayerOpening<'a>]],
    /// Per-query "negative" openings: same shape; openings of
    /// `f_i(x + n_i/2)` (the other parent in the fold).
    pub queries_neg: &'a [&'a [LayerOpening<'a>]],
    /// Field-element values at each query / layer / parent. The
    /// Merkle leaves *commit* to these values; this slice carries
    /// them in unhashed form so the fold equation can be evaluated.
    /// Shape: num_queries × num_layers × 2 (positive parent, then
    /// negative parent).
    pub query_values: &'a [&'a [(Fr, Fr)]],
    /// Final-polynomial coefficients (degree < final_poly_degree).
    /// In typical FRI, log_n - num_layers is small enough that the
    /// final polynomial fits in a handful of field elements and is
    /// shipped in the clear.
    pub final_poly: &'a [Fr],
}

/// Verifier-side parameters that pin the proof's expected shape.
#[derive(Clone, Debug)]
pub struct FriVerifierParams {
    /// log2 of the initial domain size. n_0 = 2^log_n.
    pub log_n: u32,
    /// Number of fold layers (each halves the domain).
    pub num_layers: u32,
    /// Number of independent queries.
    pub num_queries: u32,
    /// Generator `ω_0` of the order-`2^log_n` subgroup.
    pub omega_0: Fr,
    /// `omega_0^{-1}` precomputed (avoids one inversion at verify time).
    pub omega_0_inv: Fr,
    /// Two-inverse `1/2 mod P` precomputed (used in the fold equation).
    pub two_inv: Fr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FriError {
    /// Proof shape doesn't match params (layer count, query count,
    /// or per-query opening count diverged).
    BadShape,
    /// A Merkle authentication path failed to verify.
    Merkle(MerkleError),
    /// The fold equation rejected at some (query, layer) pair.
    FoldMismatch,
    /// The final-layer evaluation didn't match the polynomial the
    /// prover shipped in the clear.
    FinalLayerMismatch,
}

impl From<MerkleError> for FriError {
    fn from(e: MerkleError) -> Self {
        FriError::Merkle(e)
    }
}

/// Verify a FRI proof against a transcript that has already absorbed
/// any preceding context (PCS commitments, public inputs, …).
///
/// The transcript MUST be in absorb mode at entry; this routine
/// drives the absorb-then-squeeze pattern itself: it absorbs each
/// layer's root, squeezes that layer's β, then squeezes the query
/// indices after the final layer is absorbed.
pub fn verify_fri(
    env: &Env,
    transcript: &mut Transcript,
    proof: &FriProof,
    params: &FriVerifierParams,
) -> Result<(), FriError> {
    // ---- Shape gates --------------------------------------------------
    if proof.layers.len() as u32 != params.num_layers + 1 {
        // layers[0] is the initial commitment; layers[1..] are post-
        // fold commitments, one per fold step → num_layers + 1 total.
        return Err(FriError::BadShape);
    }
    if proof.queries.len() as u32 != params.num_queries
        || proof.queries_neg.len() as u32 != params.num_queries
        || proof.query_values.len() as u32 != params.num_queries
    {
        return Err(FriError::BadShape);
    }
    for q in 0..(params.num_queries as usize) {
        // Per-query openings count: one per layer (each layer has its
        // own Merkle commitment, so its own opening).
        if proof.queries[q].len() as u32 != params.num_layers + 1
            || proof.queries_neg[q].len() as u32 != params.num_layers + 1
            || proof.query_values[q].len() as u32 != params.num_layers + 1
        {
            return Err(FriError::BadShape);
        }
    }

    // ---- Reconstruct β challenges from the transcript ---------------
    //
    // Verifier mirrors prover: absorb layer i's root, squeeze β_i, then
    // expect the prover's layer i+1 root in the next absorb step.
    let mut betas: alloc::vec::Vec<Fr> =
        alloc::vec::Vec::with_capacity(params.num_layers as usize);
    {
        // Absorb the initial commitment.
        for x in proof.layers[0].root.iter() {
            transcript.observe(env, *x);
        }
        for i in 0..(params.num_layers as usize) {
            let beta = transcript.challenge_nonzero(env);
            betas.push(beta);
            // Absorb f_{i+1}'s commitment.
            for x in proof.layers[i + 1].root.iter() {
                transcript.observe(env, *x);
            }
        }
    }

    // ---- Absorb the final polynomial, then squeeze query indices ----
    transcript.observe_slice(env, proof.final_poly);
    let n_initial = 1usize << params.log_n;

    // ---- Per-query check --------------------------------------------
    for q in 0..(params.num_queries as usize) {
        // Random initial index in `[0, n_0)`.
        let idx0 = transcript.challenge_index(env, n_initial);

        let mut idx = idx0;
        let mut layer_size = n_initial;
        // Generator of the layer-i domain. ω_0 = params.omega_0;
        // ω_{i+1} = ω_i^2.
        let mut omega = params.omega_0;
        let mut omega_inv = params.omega_0_inv;

        for i in 0..(params.num_layers as usize) {
            let half = layer_size / 2;
            let pos_idx = idx % half;
            let neg_idx = pos_idx + half;

            // Verify Merkle openings (positive + negative parent).
            let opening_pos = &proof.queries[q][i];
            let opening_neg = &proof.queries_neg[q][i];
            verify_path(
                env,
                &opening_pos.leaf,
                pos_idx as u64,
                opening_pos.siblings,
                &proof.layers[i].root,
            )?;
            verify_path(
                env,
                &opening_neg.leaf,
                neg_idx as u64,
                opening_neg.siblings,
                &proof.layers[i].root,
            )?;

            // The leaf bytes commit to the (Fr, Fr) value pair the
            // prover shipped in `query_values`. Tying the two together
            // is the parser's job (via leaf-hash recomputation) — this
            // verifier expects them already linked. See `proof_format`.
            let (p, p_neg) = proof.query_values[q][i];

            // Fold equation:
            //   f_{i+1}(x^2) = (p + p_neg)/2 + β_i · (p - p_neg)/(2 · ω_i^pos_idx)
            //
            // ω_i^pos_idx is the x-coordinate at the positive parent.
            let omega_at_pos = omega.pow(pos_idx as u64);
            let omega_at_pos_inv = omega_at_pos.inverse();

            let sum = p + p_neg;
            let diff = p - p_neg;
            let beta = betas[i];
            let folded = (sum * params.two_inv)
                + beta * (diff * params.two_inv * omega_at_pos_inv);

            // The next-layer parent at this query: `query_values[q][i+1].0`.
            let next_pos = proof.query_values[q][i + 1].0;
            if folded != next_pos {
                return Err(FriError::FoldMismatch);
            }

            // Step to the next layer.
            idx = pos_idx;
            layer_size = half;
            omega = omega * omega;
            omega_inv = omega_inv * omega_inv;
        }

        // Final-layer check: at this point `idx ∈ [0, layer_size)`,
        // and `proof.query_values[q][num_layers].0` should equal
        // the final polynomial evaluated at `ω_final^idx`.
        let final_x = omega.pow(idx as u64);
        let mut acc = Fr::ZERO;
        // Horner's evaluation.
        for c in proof.final_poly.iter().rev() {
            acc = acc * final_x + *c;
        }
        let claimed = proof.query_values[q][params.num_layers as usize].0;
        if acc != claimed {
            return Err(FriError::FinalLayerMismatch);
        }
        let _ = omega_inv; // omega_inv isn't strictly needed here —
                           // kept in scope for future batched-PCS work
                           // that will need ω_i^{-1} to reuse this loop.
    }

    Ok(())
}

extern crate alloc;

#[cfg(test)]
mod tests {
    use super::*;

    /// `BadShape` short-circuits before any Merkle / fold work.
    #[test]
    fn rejects_wrong_layer_count() {
        let env = Env::default();
        let mut t = Transcript::new(&env, b"fri");
        let layers: alloc::vec::Vec<CommittedLayer> = alloc::vec::Vec::new();
        let queries: alloc::vec::Vec<&[LayerOpening]> = alloc::vec::Vec::new();
        let queries_neg: alloc::vec::Vec<&[LayerOpening]> = alloc::vec::Vec::new();
        let query_values: alloc::vec::Vec<&[(Fr, Fr)]> = alloc::vec::Vec::new();
        let proof = FriProof {
            layers: &layers,
            queries: &queries,
            queries_neg: &queries_neg,
            query_values: &query_values,
            final_poly: &[],
        };
        let params = FriVerifierParams {
            log_n: 4,
            num_layers: 2,
            num_queries: 1,
            omega_0: Fr::new(2),
            omega_0_inv: Fr::new(2).inverse(),
            two_inv: Fr::new(2).inverse(),
        };
        assert_eq!(verify_fri(&env, &mut t, &proof, &params), Err(FriError::BadShape));
    }
}
