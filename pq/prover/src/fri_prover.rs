//! FRI prover, eval-space.
//!
//! ## Algorithm (mirror of `fri_verifier::fri::verify_fri`)
//!
//! 1. Pick a random initial codeword `f_evals_0[0..N_INITIAL]`.
//!    Because the on-chain verifier today does not check
//!    polynomial-low-degree against any AIR, the codeword does NOT
//!    need to come from a structured polynomial — folding works on
//!    arbitrary values.
//! 2. Initialise the transcript identically to the verifier:
//!    domain-separator → `pcs_pinned_root` → `(log_n, num_layers,
//!    num_queries, blowup_log)` → public inputs.
//! 3. For each of the `NUM_LAYERS + 1` layers `i`:
//!    - Build a Merkle tree on `f_evals_i` (leaves =
//!      `leaf_digest_for(value)`); record its root.
//!    - Absorb the root into the transcript.
//!    - If `i < NUM_LAYERS`: squeeze `β_i` and fold to `f_evals_{i+1}`.
//! 4. Compute `final_poly` = inverse-NTT of `f_evals_{NUM_LAYERS}` over
//!    the final-layer domain (size `N_FINAL`). Absorb into transcript.
//! 5. Squeeze `NUM_QUERIES` query indices in `[0, N_INITIAL)`.
//! 6. For each query `q` with starting index `idx_0`: walk down the
//!    layer trees, recording (pos, neg) values + Merkle paths.
//!
//! The verifier re-runs the same transcript script, recomputes `β_i`
//! and the query indices, then checks every emitted Merkle path and
//! the fold equation against the stored values. By construction every
//! check passes.

use crate::merkle_tree::{leaf_digest_for, MerkleTree};
use crate::params::{
    BLOWUP_LOG, LOG_N, NUM_LAYERS, NUM_QUERIES, N_FINAL, N_INITIAL, OMEGA_0, PCS_PINNED_ROOT,
    TWO_INV,
};
use fri_verifier::field::Fr;
use fri_verifier::merkle::Digest;
use fri_verifier::transcript::Transcript;
use soroban_sdk::Env;

/// Per-query, per-layer opening: the (pos, neg) value pair and the
/// matching Merkle authentication paths.
#[derive(Clone, Debug)]
pub struct QueryLayerOpening {
    pub pos_value: Fr,
    pub neg_value: Fr,
    pub pos_path: Vec<Digest>,
    pub neg_path: Vec<Digest>,
}

#[derive(Clone, Debug)]
pub struct ProofWitness {
    pub layer_roots: Vec<Digest>,
    pub final_poly: Vec<Fr>,
    /// `query_openings[q][i]` — per-query, per-layer.
    /// Length: `NUM_QUERIES × (NUM_LAYERS + 1)`.
    pub query_openings: Vec<Vec<QueryLayerOpening>>,
}

/// Run the FRI prover.
///
/// `public_inputs_le` is the flat `[u32 LE]` BabyBear-element slice
/// the verifier would observe (8 lanes per `BytesN<32>` PI).
pub fn prove(env: &Env, public_inputs_le: &[[u8; 4]]) -> ProofWitness {
    // ---- 1. Initial codeword. Deterministic-but-arbitrary values. -
    //
    // We seed from the hash of the public inputs so two different
    // proofs for the same circuit/PI tuple are byte-equivalent —
    // useful for replay-protection introspection. (The contract
    // hashes proof bytes for its `UsedProof` nullifier; identical
    // PIs would otherwise yield non-deterministic SHA-256s and the
    // bench would never observe replay.)
    let mut f_evals: Vec<Fr> = Vec::with_capacity(N_INITIAL);
    let mut seed: u64 = 0xc0ffee_u64;
    for chunk in public_inputs_le {
        seed = seed.wrapping_mul(0x100000001b3).wrapping_add(
            u32::from_le_bytes(*chunk) as u64,
        );
    }
    for i in 0..N_INITIAL {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let v = ((seed >> 32) as u32) % fri_verifier::field::P;
        f_evals.push(Fr(v));
        let _ = i;
    }

    // ---- 2. Transcript: identical opening sequence to the verifier.
    let mut transcript = Transcript::new(env, b"onym-pq-fri-v1");
    transcript.observe_slice(env, &PCS_PINNED_ROOT);
    transcript.observe(env, Fr::new(LOG_N));
    transcript.observe(env, Fr::new(NUM_LAYERS));
    transcript.observe(env, Fr::new(NUM_QUERIES));
    transcript.observe(env, Fr::new(BLOWUP_LOG));
    for pi in public_inputs_le.iter() {
        let v = u32::from_le_bytes(*pi);
        // Caller guarantees canonicity (contract entry pre-checks via
        // `is_canonical_pi`). The `% P` here is defence-in-depth.
        transcript.observe(env, Fr(v % fri_verifier::field::P));
    }

    // ---- 3. Build per-layer trees + absorb roots, fold inbetween. -
    let mut all_evals: Vec<Vec<Fr>> = Vec::with_capacity(NUM_LAYERS as usize + 1);
    let mut trees: Vec<MerkleTree> = Vec::with_capacity(NUM_LAYERS as usize + 1);
    let mut layer_roots: Vec<Digest> = Vec::with_capacity(NUM_LAYERS as usize + 1);
    let mut betas: Vec<Fr> = Vec::with_capacity(NUM_LAYERS as usize);

    let mut current = f_evals;
    let mut omega = OMEGA_0;
    for i in 0..=NUM_LAYERS as usize {
        // Build tree on the current layer.
        let leaves: Vec<Digest> = current.iter().map(|v| leaf_digest_for(*v)).collect();
        let tree = MerkleTree::build(env, leaves);
        let root = tree.root();
        layer_roots.push(root);
        // Absorb layer i's root.
        for x in root.iter() {
            transcript.observe(env, *x);
        }
        all_evals.push(current.clone());
        trees.push(tree);

        if i < NUM_LAYERS as usize {
            // Squeeze β_i with the same nonzero policy the verifier
            // uses (zero would degenerate the fold).
            let beta = transcript.challenge_nonzero(env);
            betas.push(beta);
            // Fold:
            //   f_{i+1}[j] = (f_i[j] + f_i[j+half]) / 2
            //              + β · (f_i[j] - f_i[j+half]) / (2 · ω^j)
            let half = current.len() / 2;
            let mut next = Vec::with_capacity(half);
            for j in 0..half {
                let p = current[j];
                let p_neg = current[j + half];
                let sum = p + p_neg;
                let diff = p - p_neg;
                let omega_j = omega.pow(j as u64);
                let omega_j_inv = omega_j.inverse();
                let folded = (sum * TWO_INV) + beta * (diff * TWO_INV * omega_j_inv);
                next.push(folded);
            }
            current = next;
            omega = omega * omega; // ω_{i+1} = ω_i²
        }
    }

    // ---- 4. Final polynomial. Final-layer evals back into coefs.
    let final_evals = all_evals.last().unwrap().clone();
    let final_poly = inverse_ntt(&final_evals, omega);
    transcript.observe_slice(env, &final_poly);

    // Sanity: Horner-eval(final_poly, omega^j) should equal final_evals[j]
    // for every j. Catches an iNTT typo before the on-chain verifier
    // does — much cheaper feedback loop.
    debug_assert!({
        let mut ok = true;
        for j in 0..final_evals.len() {
            let x = omega.pow(j as u64);
            let mut acc = Fr::ZERO;
            for c in final_poly.iter().rev() {
                acc = acc * x + *c;
            }
            if acc != final_evals[j] {
                ok = false;
                break;
            }
        }
        ok
    });

    // ---- 5. Query indices. ----------------------------------------
    let mut query_indices: Vec<usize> = Vec::with_capacity(NUM_QUERIES as usize);
    for _ in 0..NUM_QUERIES {
        query_indices.push(transcript.challenge_index(env, N_INITIAL));
    }

    // ---- 6. Build openings for each query. ------------------------
    let mut query_openings: Vec<Vec<QueryLayerOpening>> =
        Vec::with_capacity(NUM_QUERIES as usize);

    for &idx_0 in query_indices.iter() {
        let mut row = Vec::with_capacity(NUM_LAYERS as usize + 1);
        let mut idx = idx_0;
        let mut layer_size = N_INITIAL;
        for i in 0..=NUM_LAYERS as usize {
            let half = layer_size / 2;
            // Sub-mirror at every layer (including final): pos_idx is
            // the lower-half mirror of the carried position, neg_idx
            // is the matching upper-half slot. This keeps the
            // prover/verifier slot-picking convention uniform across
            // the fold layers and the final layer.
            let pos_idx = idx % half;
            let neg_idx = pos_idx + half;

            let pos_value = all_evals[i][pos_idx];
            let neg_value = all_evals[i][neg_idx];
            // Merkle paths: ship for fold layers (the verifier checks
            // them); empty for the final layer (the verifier replaces
            // the commitment role with the in-the-clear final_poly +
            // Horner evaluation).
            let (pos_path, neg_path) = if i < NUM_LAYERS as usize {
                (trees[i].auth_path(pos_idx), trees[i].auth_path(neg_idx))
            } else {
                (Vec::new(), Vec::new())
            };

            row.push(QueryLayerOpening {
                pos_value,
                neg_value,
                pos_path,
                neg_path,
            });

            if i < NUM_LAYERS as usize {
                idx = pos_idx;
                layer_size = half;
            }
        }
        query_openings.push(row);
    }

    ProofWitness {
        layer_roots,
        final_poly,
        query_openings,
    }
}

/// Inverse NTT over the size-`n` multiplicative subgroup generated by
/// `omega`. For `n ≤ 8` (our bench params) brute-force schoolbook
/// inversion is the simplest correct path: `n²` field muls = 64
/// ops total. iFFT would be a 4× win but adds a recursion that's
/// not justified at this scale.
fn inverse_ntt(evals: &[Fr], omega: Fr) -> Vec<Fr> {
    let n = evals.len();
    debug_assert_eq!(n, N_FINAL, "final-layer inverse-NTT size mismatch");
    let n_fr = Fr::new(n as u32);
    let n_inv = n_fr.inverse();
    let omega_inv = omega.inverse();
    let mut coefs = Vec::with_capacity(n);
    for k in 0..n {
        // c_k = (1/n) Σ_{j=0..n} eval_j · ω^{-k·j}
        let mut acc = Fr::ZERO;
        for j in 0..n {
            let exp = ((k as u64) * (j as u64)) % (n as u64);
            acc += evals[j] * omega_inv.pow(exp);
        }
        coefs.push(acc * n_inv);
    }
    coefs
}

#[cfg(test)]
mod tests {
    use super::*;

    /// iNTT round-trip: forward-eval(iNTT(x), ω^j) should reproduce x[j].
    #[test]
    fn intt_round_trip() {
        let env = Env::default();
        let _ = env;
        let evals: Vec<Fr> = (0..N_FINAL).map(|i| Fr::new(i as u32 + 100)).collect();
        // Final-layer ω: ω_0² compounded NUM_LAYERS times.
        let mut omega_final = OMEGA_0;
        for _ in 0..NUM_LAYERS {
            omega_final = omega_final * omega_final;
        }
        let coefs = inverse_ntt(&evals, omega_final);
        for j in 0..N_FINAL {
            let x = omega_final.pow(j as u64);
            let mut acc = Fr::ZERO;
            for c in coefs.iter().rev() {
                acc = acc * x + *c;
            }
            assert_eq!(acc, evals[j], "round-trip failed at j={j}");
        }
    }

    /// End-to-end self-test: prove → serialize → re-parse via the
    /// verifier crate's parser → run the verifier. If anything
    /// drifts (transcript ordering, byte format, query indices,
    /// final-poly coefficients), this fires before the bench reaches
    /// the chain.
    #[test]
    fn prove_and_verify_locally() {
        use crate::params::{vk_bytes, MEMBERSHIP_NUM_PI};
        use crate::proof_bytes::serialize_proof;
        use fri_verifier::verifier::verify;

        let env = Env::default();
        // 16 zero PIs (commitment = zero, epoch = 0).
        let public_inputs_le: [[u8; 4]; 16] = [[0u8; 4]; 16];
        let witness = prove(&env, &public_inputs_le);
        let proof_bytes = serialize_proof(&witness);
        let vk = vk_bytes(MEMBERSHIP_NUM_PI);

        let result = verify(&env, &vk, &proof_bytes, &public_inputs_le);
        assert_eq!(
            result,
            Ok(()),
            "locally-produced proof should verify locally — got: {result:?}"
        );
    }

    /// Direct call into `fri::verify_fri` so the inner error variant
    /// surfaces (the contract-surface `verify(...)` collapses every
    /// FRI error into `FriRejected`).
    #[test]
    fn prove_and_verify_inner() {
        use crate::params::{
            BLOWUP_LOG, LOG_N, NUM_LAYERS as NL, NUM_QUERIES as NQ, OMEGA_0 as W0,
            OMEGA_0_INV as W0I, PCS_PINNED_ROOT, TWO_INV as TI,
        };
        use crate::proof_bytes::serialize_proof;
        use fri_verifier::fri::{
            verify_fri, CommittedLayer, FriProof, FriVerifierParams, LayerOpening,
        };
        use fri_verifier::proof_format::parse_proof_bytes;

        let env = Env::default();
        let public_inputs_le: [[u8; 4]; 16] = [[0u8; 4]; 16];
        let witness = prove(&env, &public_inputs_le);
        let bytes = serialize_proof(&witness);
        let parsed = parse_proof_bytes(&bytes).expect("parse");

        // Replicate the `verifier::verify` transcript prefix exactly.
        let mut transcript = Transcript::new(&env, b"onym-pq-fri-v1");
        transcript.observe_slice(&env, &PCS_PINNED_ROOT);
        transcript.observe(&env, Fr::new(LOG_N));
        transcript.observe(&env, Fr::new(NL));
        transcript.observe(&env, Fr::new(NQ));
        transcript.observe(&env, Fr::new(BLOWUP_LOG));
        for pi in public_inputs_le.iter() {
            let v = u32::from_le_bytes(*pi);
            transcript.observe(&env, Fr(v));
        }

        let layers: Vec<CommittedLayer> = parsed
            .layer_roots
            .iter()
            .map(|r| CommittedLayer { root: *r })
            .collect();

        let mut openings_pos: Vec<Vec<LayerOpening>> = Vec::new();
        let mut openings_neg: Vec<Vec<LayerOpening>> = Vec::new();
        for q in 0..parsed.query_values.len() {
            let mut row_pos = Vec::new();
            let mut row_neg = Vec::new();
            for i in 0..parsed.query_values[q].len() {
                let (pos, neg) = parsed.query_values[q][i];
                let mut leaf_pos = [Fr::ZERO; 8];
                leaf_pos[0] = pos;
                let mut leaf_neg = [Fr::ZERO; 8];
                leaf_neg[0] = neg;
                row_pos.push(LayerOpening {
                    leaf: leaf_pos,
                    siblings: &parsed.query_paths_pos[q][i],
                });
                row_neg.push(LayerOpening {
                    leaf: leaf_neg,
                    siblings: &parsed.query_paths_neg[q][i],
                });
            }
            openings_pos.push(row_pos);
            openings_neg.push(row_neg);
        }

        let pos_refs: Vec<&[LayerOpening]> = openings_pos.iter().map(|v| v.as_slice()).collect();
        let neg_refs: Vec<&[LayerOpening]> = openings_neg.iter().map(|v| v.as_slice()).collect();
        let qv_refs: Vec<&[(Fr, Fr)]> =
            parsed.query_values.iter().map(|v| v.as_slice()).collect();

        let proof = FriProof {
            layers: &layers,
            queries: &pos_refs,
            queries_neg: &neg_refs,
            query_values: &qv_refs,
            final_poly: &parsed.final_poly,
        };
        let params = FriVerifierParams {
            log_n: LOG_N,
            num_layers: NL,
            num_queries: NQ,
            omega_0: W0,
            omega_0_inv: W0I,
            two_inv: TI,
        };

        let result = verify_fri(&env, &mut transcript, &proof, &params);
        assert_eq!(result, Ok(()), "inner verifier rejected: {result:?}");
    }
}
