//! FRI low-degree test verifier (folding factor 2) over BN254.
//!
//! ## Scope
//!
//! Same algorithm and same fold-equation as the BabyBear-based draft;
//! the only field-specific change is that all arithmetic now happens
//! through host-accelerated `BN254 Fr` operations and digests are
//! single 32-byte field elements.
//!
//! ## What this proves
//!
//! Given a Merkle commitment to a codeword `f: D → F` over a coset
//! `D` of size `n = 2^log_n`, plus fold challenges and per-layer
//! commitments, this verifies that `f` is δ-close to a polynomial
//! of degree `< n / blowup`.
//!
//! ## Production note
//!
//! Standalone FRI does NOT prove circuit-binding. The verifier-PCS
//! layer (forthcoming) reduces a multi-polynomial AIR-quotient claim
//! to a single FRI invocation via random linear combination, and
//! that's where AIR constraints get enforced. Until that layer
//! lands, contracts using `verify_fri` directly should be considered
//! research / bench, not production.
//!
//! ## Folding equation
//!
//! With folding factor 2 and a multiplicative subgroup domain whose
//! `i`-th element is `ω^i`, at a query position `q` in layer `i`:
//!
//! ```text
//!   pos_idx = q mod (|D_i|/2)
//!   neg_idx = pos_idx + |D_i|/2
//!   p     = f_i[pos_idx]
//!   p_neg = f_i[neg_idx]
//!   f_{i+1}[pos_idx] = (p + p_neg) / 2
//!                    + β_i · (p - p_neg) / (2 · ω_i^pos_idx)
//! ```
//!
//! At layer i+1, the "carried" position is `pos_idx`. If `pos_idx <
//! |D_{i+1}| / 2`, the value lives in layer i+1's lower half (slot
//! `.0`); otherwise upper half (slot `.1`). Verifier picks the slot
//! accordingly.

use crate::field::{self, Fr};
use crate::host_poseidon2::Poseidon2Ctx;
use crate::merkle::{verify_path, Digest, MerkleError};
use crate::transcript::Transcript;
use soroban_sdk::Env;

/// One layer of the FRI proof: a Merkle root of `f_i: D_i → F`.
#[derive(Clone, Debug)]
pub struct CommittedLayer {
    pub root: Digest,
}

/// Per-query, per-layer Merkle authentication-path opening.
#[derive(Clone, Debug)]
pub struct LayerOpening<'a> {
    pub leaf: Digest,
    pub siblings: &'a [Digest],
}

/// Complete FRI proof in verifier-consumable form.
pub struct FriProof<'a> {
    pub layers: &'a [CommittedLayer],
    pub queries: &'a [&'a [LayerOpening<'a>]],
    pub queries_neg: &'a [&'a [LayerOpening<'a>]],
    pub query_values: &'a [&'a [(Fr, Fr)]],
    pub final_poly: &'a [Fr],
}

/// Verifier-side parameters that pin the proof's expected shape.
#[derive(Clone, Debug)]
pub struct FriVerifierParams {
    pub log_n: u32,
    pub num_layers: u32,
    pub num_queries: u32,
    pub omega_0: Fr,
    pub omega_0_inv: Fr,
    pub two_inv: Fr,
}

#[derive(Debug, PartialEq, Eq)]
pub enum FriError {
    BadShape,
    Merkle(MerkleError),
    FoldMismatch,
    FinalLayerMismatch,
}

impl From<MerkleError> for FriError {
    fn from(e: MerkleError) -> Self {
        FriError::Merkle(e)
    }
}

/// Verify a FRI proof against a transcript that has already absorbed
/// any preceding context (PCS commitments, public inputs, …).
pub fn verify_fri(
    env: &Env,
    ctx: &Poseidon2Ctx,
    transcript: &mut Transcript<'_>,
    proof: &FriProof,
    params: &FriVerifierParams,
) -> Result<(), FriError> {
    // ---- Shape gates --------------------------------------------------
    if proof.layers.len() as u32 != params.num_layers + 1 {
        return Err(FriError::BadShape);
    }
    if proof.queries.len() as u32 != params.num_queries
        || proof.queries_neg.len() as u32 != params.num_queries
        || proof.query_values.len() as u32 != params.num_queries
    {
        return Err(FriError::BadShape);
    }
    for q in 0..(params.num_queries as usize) {
        if proof.queries[q].len() as u32 != params.num_layers + 1
            || proof.queries_neg[q].len() as u32 != params.num_layers + 1
            || proof.query_values[q].len() as u32 != params.num_layers + 1
        {
            return Err(FriError::BadShape);
        }
    }

    // ---- Reconstruct β challenges from the transcript ---------------
    let mut betas: alloc::vec::Vec<Fr> =
        alloc::vec::Vec::with_capacity(params.num_layers as usize);
    {
        // Absorb the initial commitment.
        transcript.observe(proof.layers[0].root.clone());
        for i in 0..(params.num_layers as usize) {
            let beta = transcript.challenge_nonzero();
            betas.push(beta);
            // Absorb f_{i+1}'s commitment.
            transcript.observe(proof.layers[i + 1].root.clone());
        }
    }

    // ---- Absorb final polynomial, then squeeze query indices --------
    transcript.observe_slice(proof.final_poly);
    let n_initial = 1usize << params.log_n;

    // ---- Per-query check --------------------------------------------
    for q in 0..(params.num_queries as usize) {
        let idx0 = transcript.challenge_index(n_initial);

        let mut idx = idx0;
        let mut layer_size = n_initial;
        let mut omega = params.omega_0.clone();
        let mut omega_inv = params.omega_0_inv.clone();

        for i in 0..(params.num_layers as usize) {
            let half = layer_size / 2;
            let pos_idx = idx % half;
            let neg_idx = pos_idx + half;

            // Verify Merkle openings (positive + negative parent).
            let opening_pos = &proof.queries[q][i];
            let opening_neg = &proof.queries_neg[q][i];
            verify_path(
                env,
                ctx,
                &opening_pos.leaf,
                pos_idx as u64,
                opening_pos.siblings,
                &proof.layers[i].root,
            )?;
            verify_path(
                env,
                ctx,
                &opening_neg.leaf,
                neg_idx as u64,
                opening_neg.siblings,
                &proof.layers[i].root,
            )?;

            // Fold equation:
            //   f_{i+1}(x²) = (p + p_neg)/2 + β·(p - p_neg)/(2·ω_i^pos_idx)
            // The formula is correct for queries in either half:
            // when the query is in the upper half, the negation
            // `-x = ω_i^(pos_idx + half)` cancels the `-1` from
            // `1/-x`, leaving the same expression in pos_idx terms.
            let (p, p_neg) = proof.query_values[q][i].clone();

            let omega_at_pos = omega.pow(pos_idx as u64);
            let omega_at_pos_inv = omega_at_pos.inv();

            let sum = p.clone() + p_neg.clone();
            let diff = p - p_neg;
            let beta = betas[i].clone();
            let folded = (sum * params.two_inv.clone())
                + beta * (diff * params.two_inv.clone() * omega_at_pos_inv);

            // Pick layer-i+1 slot based on whether pos_idx lands in
            // the lower or upper half of layer i+1.
            let half_next = half / 2;
            let next_value = if pos_idx < half_next {
                proof.query_values[q][i + 1].0.clone()
            } else {
                proof.query_values[q][i + 1].1.clone()
            };
            if folded != next_value {
                return Err(FriError::FoldMismatch);
            }

            // Step to the next layer.
            idx = pos_idx;
            layer_size = half;
            omega = omega.clone() * omega;
            omega_inv = omega_inv.clone() * omega_inv;
        }

        // Final-layer check: idx is the carried position. Pick `.0`
        // or `.1` based on which half it lands in, then Horner-eval
        // `final_poly` at `ω_final^idx`.
        let final_x = omega.pow(idx as u64);
        let mut acc = field::zero(env);
        for c in proof.final_poly.iter().rev() {
            acc = acc * final_x.clone() + c.clone();
        }
        let half_final = layer_size / 2;
        let claimed = if idx < half_final {
            proof.query_values[q][params.num_layers as usize].0.clone()
        } else {
            proof.query_values[q][params.num_layers as usize].1.clone()
        };
        if acc != claimed {
            return Err(FriError::FinalLayerMismatch);
        }
        let _ = omega_inv; // kept for future PCS-batched-FRI use
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
        let ctx = Poseidon2Ctx::new(&env);
        let mut t = Transcript::new(&env, &ctx, b"fri");
        let layers: alloc::vec::Vec<CommittedLayer> = alloc::vec::Vec::new();
        let queries: alloc::vec::Vec<&[LayerOpening]> = alloc::vec::Vec::new();
        let queries_neg: alloc::vec::Vec<&[LayerOpening]> = alloc::vec::Vec::new();
        let query_values: alloc::vec::Vec<&[(Fr, Fr)]> = alloc::vec::Vec::new();
        let final_poly: alloc::vec::Vec<Fr> = alloc::vec::Vec::new();
        let proof = FriProof {
            layers: &layers,
            queries: &queries,
            queries_neg: &queries_neg,
            query_values: &query_values,
            final_poly: &final_poly,
        };
        let three = field::from_u32(&env, 3);
        let params = FriVerifierParams {
            log_n: 4,
            num_layers: 2,
            num_queries: 1,
            omega_0: three.clone(),
            omega_0_inv: three.inv(),
            two_inv: field::from_u32(&env, 2).inv(),
        };
        assert_eq!(
            verify_fri(&env, &ctx, &mut t, &proof, &params),
            Err(FriError::BadShape),
        );
    }
}
