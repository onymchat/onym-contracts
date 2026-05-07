//! FRI prover, eval-space, BN254 + host Poseidon2-t3.
//!
//! ## Algorithm (mirror of `fri_verifier::fri::verify_fri`)
//!
//! 1. Pick a random initial codeword `f_evals_0[0..N_INITIAL]`.
//!    Because the on-chain verifier today does not check polynomial
//!    low-degree against any AIR, the codeword is arbitrary —
//!    folding works on any values.
//! 2. Initialise the transcript identically to the verifier:
//!    domain-separator → `pcs_pinned_root` → `(log_n, num_layers,
//!    num_queries, blowup_log)` → public inputs.
//! 3. For each of the `NUM_LAYERS + 1` layers `i`:
//!    - Build a Merkle tree on `f_evals_i` (leaves =
//!      `leaf_digest_for(value)`); record its root.
//!    - Absorb the root into the transcript.
//!    - If `i < NUM_LAYERS`: squeeze `β_i` and fold to
//!      `f_evals_{i+1}`.
//! 4. Compute `final_poly` = inverse-NTT of `f_evals_{NUM_LAYERS}`
//!    over the final-layer domain. Absorb into transcript.
//! 5. Squeeze `NUM_QUERIES` query indices in `[0, N_INITIAL)`.
//! 6. For each query: walk down the layer trees, recording (pos,
//!    neg) values + Merkle paths.
//!
//! All field ops route through `fri_verifier::field` (BN254 host
//! arithmetic). All hashes route through
//! `fri_verifier::host_poseidon2::Poseidon2Ctx` (host primitive
//! with vendored Horizen Labs constants). Prover and verifier are
//! byte-equivalent by construction.

use crate::merkle_tree::{leaf_digest_for, MerkleTree};
use crate::params::{
    self, BLOWUP_LOG, LOG_N, NUM_LAYERS, NUM_QUERIES, N_FINAL, N_INITIAL,
};
use fri_verifier::field::{self, Fr};
use fri_verifier::host_poseidon2::Poseidon2Ctx;
use fri_verifier::merkle::Digest;
use fri_verifier::transcript::Transcript;
use soroban_sdk::Env;

extern crate alloc;
use alloc::vec::Vec;

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
    pub query_openings: Vec<Vec<QueryLayerOpening>>,
}

/// Run the FRI prover.
pub fn prove(env: &Env, public_inputs_be: &[[u8; 32]]) -> ProofWitness {
    let ctx = Poseidon2Ctx::new(env);

    // ---- 1. Initial codeword. Deterministic from PIs.
    //
    // Seed from a SHA-256-style mix of the public inputs so two
    // proofs for the same circuit / PI tuple are byte-equivalent
    // (matters for the contract's `UsedProof` nullifier — distinct
    // PIs must give distinct proof bytes).
    let mut f_evals: Vec<Fr> = Vec::with_capacity(N_INITIAL);
    let mut seed: u64 = 0xc0ffee_u64;
    for chunk in public_inputs_be {
        for b in chunk.iter() {
            seed = seed.wrapping_mul(0x100000001b3).wrapping_add(*b as u64);
        }
    }
    for _ in 0..N_INITIAL {
        // Linear-congruential mixing → 32-byte BE → BN254 Fr (host
        // reduces mod r if needed).
        seed = seed
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        let mut bytes = [0u8; 32];
        bytes[24..32].copy_from_slice(&seed.to_be_bytes());
        f_evals.push(field::from_be_bytes(env, &bytes));
    }

    // ---- 2. Transcript.
    let mut transcript = Transcript::new(env, &ctx, b"onym-pq-fri-v2");
    transcript.observe(params::pcs_pinned_root(env));
    transcript.observe(field::from_u32(env, LOG_N));
    transcript.observe(field::from_u32(env, NUM_LAYERS));
    transcript.observe(field::from_u32(env, NUM_QUERIES));
    transcript.observe(field::from_u32(env, BLOWUP_LOG));
    for pi in public_inputs_be.iter() {
        transcript.observe(field::from_be_bytes(env, pi));
    }

    // ---- 3. Per-layer trees + roots + folds.
    let mut all_evals: Vec<Vec<Fr>> = Vec::with_capacity(NUM_LAYERS as usize + 1);
    let mut trees: Vec<MerkleTree> = Vec::with_capacity(NUM_LAYERS as usize + 1);
    let mut layer_roots: Vec<Digest> = Vec::with_capacity(NUM_LAYERS as usize + 1);
    let mut betas: Vec<Fr> = Vec::with_capacity(NUM_LAYERS as usize);

    let mut current = f_evals;
    let mut omega = params::omega_0(env);
    let two_inv = params::two_inv(env);

    for i in 0..=NUM_LAYERS as usize {
        let leaves: Vec<Digest> = current.iter().map(|v| leaf_digest_for(v.clone())).collect();
        let tree = MerkleTree::build(env, &ctx, leaves);
        let root = tree.root();
        layer_roots.push(root.clone());
        transcript.observe(root);
        all_evals.push(current.clone());
        trees.push(tree);

        if i < NUM_LAYERS as usize {
            let beta = transcript.challenge_nonzero();
            betas.push(beta.clone());
            // Fold:
            //   f_{i+1}[j] = (f_i[j] + f_i[j+half])/2
            //              + β · (f_i[j] - f_i[j+half])/(2 · ω^j)
            let half = current.len() / 2;
            let mut next: Vec<Fr> = Vec::with_capacity(half);
            for j in 0..half {
                let p = current[j].clone();
                let p_neg = current[j + half].clone();
                let sum = p.clone() + p_neg.clone();
                let diff = p - p_neg;
                let omega_j = omega.pow(j as u64);
                let omega_j_inv = omega_j.inv();
                let folded = (sum * two_inv.clone())
                    + beta.clone() * (diff * two_inv.clone() * omega_j_inv);
                next.push(folded);
            }
            current = next;
            omega = omega.clone() * omega; // ω_{i+1} = ω_i²
        }
    }

    // ---- 4. Final polynomial. iNTT over final-layer domain.
    let final_evals = all_evals.last().unwrap().clone();
    let final_poly = inverse_ntt(env, &final_evals, omega.clone());
    transcript.observe_slice(&final_poly);

    // Sanity: Horner-eval(final_poly, omega^j) reproduces final_evals[j].
    debug_assert!({
        let mut ok = true;
        for j in 0..final_evals.len() {
            let x = omega.pow(j as u64);
            let mut acc = field::zero(env);
            for c in final_poly.iter().rev() {
                acc = acc * x.clone() + c.clone();
            }
            if acc != final_evals[j] {
                ok = false;
                break;
            }
        }
        ok
    });

    // ---- 5. Query indices.
    let mut query_indices: Vec<usize> = Vec::with_capacity(NUM_QUERIES as usize);
    for _ in 0..NUM_QUERIES {
        query_indices.push(transcript.challenge_index(N_INITIAL));
    }

    // ---- 6. Build openings for each query.
    let mut query_openings: Vec<Vec<QueryLayerOpening>> =
        Vec::with_capacity(NUM_QUERIES as usize);

    for &idx_0 in query_indices.iter() {
        let mut row: Vec<QueryLayerOpening> = Vec::with_capacity(NUM_LAYERS as usize + 1);
        let mut idx = idx_0;
        let mut layer_size = N_INITIAL;
        for i in 0..=NUM_LAYERS as usize {
            let half = layer_size / 2;
            let pos_idx = idx % half;
            let neg_idx = pos_idx + half;

            let pos_value = all_evals[i][pos_idx].clone();
            let neg_value = all_evals[i][neg_idx].clone();
            // Merkle paths: ship for fold layers; empty for the final
            // layer (the verifier doesn't check Merkle there — replaced
            // by in-the-clear final_poly + Horner evaluation).
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

/// Inverse NTT over the size-`n` multiplicative subgroup generated
/// by `omega`. For `n ≤ 8` (bench) brute-force schoolbook is the
/// simplest correct path.
fn inverse_ntt(env: &Env, evals: &[Fr], omega: Fr) -> Vec<Fr> {
    let n = evals.len();
    debug_assert_eq!(n, N_FINAL, "final-layer inverse-NTT size mismatch");
    let n_fr = field::from_u32(env, n as u32);
    let n_inv = n_fr.inv();
    let omega_inv = omega.inv();
    let mut coefs: Vec<Fr> = Vec::with_capacity(n);
    for k in 0..n {
        // c_k = (1/n) Σ_j eval_j · ω^{-k·j}
        let mut acc = field::zero(env);
        for j in 0..n {
            let exp = ((k as u64) * (j as u64)) % (n as u64);
            acc = acc + evals[j].clone() * omega_inv.pow(exp);
        }
        coefs.push(acc * n_inv.clone());
    }
    coefs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intt_round_trip() {
        let env = Env::default();
        let evals: Vec<Fr> = (0..N_FINAL)
            .map(|i| field::from_u32(&env, i as u32 + 100))
            .collect();
        let mut omega_final = params::omega_0(&env);
        for _ in 0..NUM_LAYERS {
            omega_final = omega_final.clone() * omega_final;
        }
        let coefs = inverse_ntt(&env, &evals, omega_final.clone());
        for j in 0..N_FINAL {
            let x = omega_final.pow(j as u64);
            let mut acc = field::zero(&env);
            for c in coefs.iter().rev() {
                acc = acc * x.clone() + c.clone();
            }
            assert_eq!(acc, evals[j], "round-trip failed at j={j}");
        }
    }

    /// End-to-end self-test: prove → serialize → re-parse → verify.
    /// If anything drifts (transcript ordering, byte format, query
    /// indices, final-poly coefficients), this fires before the
    /// bench reaches the chain.
    ///
    /// `Env::default()` ships with the production CPU/mem budgets;
    /// our test exercises ~hundreds of Poseidon2 host calls plus
    /// thousands of BN254 Fr ops, which exceeds the production
    /// per-tx CPU budget by several factors. Off-chain bench-prep
    /// runs unmetered (the prover is an external binary), so we
    /// `reset_unlimited` the test env to mirror that — the
    /// production-budget question is for the on-chain side, which
    /// the contract bench measures separately.
    #[test]
    fn prove_and_verify_locally() {
        use crate::params::{vk_bytes, MEMBERSHIP_NUM_PI};
        use crate::proof_bytes::serialize_proof;
        use fri_verifier::verifier::verify;

        let env = Env::default();
        env.cost_estimate().budget().reset_unlimited();

        // 2 zero PIs (commitment = zero, epoch = 0).
        let public_inputs_be: [[u8; 32]; 2] = [[0u8; 32]; 2];
        let witness = prove(&env, &public_inputs_be);
        let proof_bytes = serialize_proof(&witness);
        let vk = vk_bytes(MEMBERSHIP_NUM_PI);

        let result = verify(&env, &vk, &proof_bytes, &public_inputs_be);
        assert_eq!(
            result,
            Ok(()),
            "locally-produced proof should verify locally — got: {result:?}"
        );
    }
}
