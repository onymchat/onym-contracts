//! Bench prover: emits proofs the verifier accepts, with exactly the
//! production byte layout and transcript.
//!
//! The trace is `num_cols` random polynomials of degree
//! `< 2^log_trace_rows`, a stand-in for a real AIR trace plus quotient
//! chunks. Proof size and verifier cost depend only on the shape
//! (rows × columns × FRI parameters), not on what the columns encode,
//! so the bench numbers carry over to a real circuit of the same shape.
//!
//! The final-layer interpolation asserts that every coefficient past
//! `final_poly_len` is zero. That only holds if NTT, DEEP quotient and
//! every fold agree with the verifier's maths, so a passing prove is
//! itself an end-to-end consistency check.

use crate::field::{E, F};
use crate::fold::fold_leaf;
use crate::hash::{Digest, Hasher};
use crate::merkle::{leaf_hash, node_hash};
use crate::params::Params;
use crate::transcript::Transcript;
use crate::verifier::TRANSCRIPT_LABEL;
use std::vec;
use std::vec::Vec;

struct Tree {
    /// `levels[0]` = leaf hashes, last = root.
    levels: Vec<Vec<Digest>>,
}

impl Tree {
    fn build<H: Hasher>(h: &H, leaves: &[Vec<u8>]) -> Tree {
        let mut levels = vec![leaves.iter().map(|l| leaf_hash(h, l)).collect::<Vec<_>>()];
        while levels.last().unwrap().len() > 1 {
            let prev = levels.last().unwrap();
            let next = prev.chunks_exact(2).map(|p| node_hash(h, &p[0], &p[1])).collect();
            levels.push(next);
        }
        Tree { levels }
    }

    fn depth(&self) -> u32 {
        (self.levels.len() - 1) as u32
    }

    fn cap_bytes(&self, height: u32) -> Vec<u8> {
        self.levels[(self.depth() - height) as usize].concat()
    }

    fn path(&self, mut idx: usize, height: u32) -> Vec<u8> {
        let mut out = Vec::new();
        for level in &self.levels[..(self.depth() - height) as usize] {
            out.extend_from_slice(&level[idx ^ 1]);
            idx >>= 1;
        }
        out
    }
}

fn bit_reverse(a: &mut [F]) {
    let n = a.len();
    let bits = n.trailing_zeros();
    for i in 0..n {
        let j = i.reverse_bits() >> (usize::BITS - bits);
        if i < j {
            a.swap(i, j);
        }
    }
}

/// In place: `a[i] ← Σⱼ a[j]·ωⁱʲ` (coefficients → evaluations).
fn ntt(a: &mut [F], omega: F) {
    let n = a.len();
    if n <= 1 {
        return;
    }
    bit_reverse(a);
    let mut len = 2;
    while len <= n {
        let w_len = omega.pow((n / len) as u64);
        for start in (0..n).step_by(len) {
            let mut w = F::ONE;
            for j in 0..len / 2 {
                let u = a[start + j];
                let v = a[start + j + len / 2] * w;
                a[start + j] = u + v;
                a[start + j + len / 2] = u - v;
                w = w * w_len;
            }
        }
        len <<= 1;
    }
}

/// Evaluations over `⟨ω⟩` → coefficients, per extension component.
fn intt_ext(evals: &[E], omega: F) -> Vec<E> {
    let n = evals.len();
    let n_inv = F::from_u64(n as u64).inv();
    let mut out = vec![E::ZERO; n];
    for comp in 0..4 {
        let mut v: Vec<F> = evals.iter().map(|e| e.0[comp]).collect();
        ntt(&mut v, omega.inv());
        for i in 0..n {
            out[i].0[comp] = v[i] * n_inv;
        }
    }
    out
}

fn fold_layer(cw: &[E], log_n: u32, log_arity: u8, beta: E) -> Vec<E> {
    let n = 1usize << log_n;
    let m = 1usize << log_arity;
    let s = n / m;
    let omega = F::two_adic_generator(log_n);
    let omega_inv = omega.inv();
    let zeta_inv = omega.pow(s as u64).inv();
    let two_inv = F::from_u64(2).inv();
    let mut out = Vec::with_capacity(s);
    let mut x0_inv = F::ONE;
    let mut vals = vec![E::ZERO; m];
    for l in 0..s {
        for t in 0..m {
            vals[t] = cw[l + t * s];
        }
        out.push(fold_leaf(&mut vals, x0_inv, zeta_inv, beta, two_inv));
        x0_inv = x0_inv * omega_inv;
    }
    out
}

fn coset_leaf_bytes(cw: &[E], idx: usize, leaves: usize, arity: usize) -> Vec<u8> {
    (0..arity).flat_map(|t| cw[idx + t * leaves].to_bytes()).collect()
}

fn next_rand(state: &mut u64) -> u64 {
    // xorshift64* — deterministic bench data, not secrets.
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    state.wrapping_mul(0x2545_f491_4f6c_dd1d)
}

pub fn prove<H: Hasher>(h: &H, p: &Params, public_inputs: &[u8], seed: u64) -> Vec<u8> {
    prove_inner(h, p, public_inputs, seed, 1usize << p.log_trace_rows, true)
}

/// `trace_degree` above `2^log_trace_rows` with `check_final = false`
/// models a cheating prover that commits a too-high-degree trace and
/// truncates the final polynomial.
fn prove_inner<H: Hasher>(
    h: &H,
    p: &Params,
    public_inputs: &[u8],
    seed: u64,
    n_trace: usize,
    check_final: bool,
) -> Vec<u8> {
    p.validate().expect("invalid params");
    let k = p.num_layers();
    let w = p.num_cols as usize;
    let n0 = 1usize << p.log_n0();
    let params_bytes = p.to_bytes();

    // ---- Trace: random low-degree columns, LDE, commit --------------
    let mut rng = seed | 1;
    let coeffs: Vec<Vec<F>> = (0..w)
        .map(|_| (0..n_trace).map(|_| F::from_u64(next_rand(&mut rng))).collect())
        .collect();
    let omega0 = F::two_adic_generator(p.log_n0());
    let lde: Vec<Vec<F>> = coeffs
        .iter()
        .map(|c| {
            let mut v = c.clone();
            v.resize(n0, F::ZERO);
            ntt(&mut v, omega0);
            v
        })
        .collect();

    let s0 = 1usize << p.log_leaves(0);
    let m0 = 1usize << p.log_arities[0];
    let trace_leaves: Vec<Vec<u8>> = (0..s0)
        .map(|l| {
            let mut b = Vec::with_capacity(m0 * w * 4);
            for t in 0..m0 {
                for col in &lde {
                    b.extend_from_slice(&col[l + t * s0].value().to_le_bytes());
                }
            }
            b
        })
        .collect();
    let trace_tree = Tree::build(h, &trace_leaves);

    let mut proof = Vec::new();
    let mut tr = Transcript::new(h, TRANSCRIPT_LABEL);
    tr.observe(&params_bytes);
    tr.observe(public_inputs);

    let cap0 = trace_tree.cap_bytes(p.cap_height_at(0));
    proof.extend_from_slice(&cap0);
    tr.observe(&cap0);
    let z = tr.challenge_ext();

    // ---- OOD evaluations, DEEP quotient -----------------------------
    let ood: Vec<E> = coeffs
        .iter()
        .map(|c| c.iter().rev().fold(E::ZERO, |acc, &ci| acc * z + E::from_base(ci)))
        .collect();
    let ood_bytes: Vec<u8> = ood.iter().flat_map(|e| e.to_bytes()).collect();
    proof.extend_from_slice(&ood_bytes);
    tr.observe(&ood_bytes);
    let alpha = tr.challenge_ext();

    let mut alpha_pows = Vec::with_capacity(w);
    let mut acc = E::ONE;
    for _ in 0..w {
        alpha_pows.push(acc);
        acc = acc * alpha;
    }
    let ood_combo = (0..w).fold(E::ZERO, |s, c| s + alpha_pows[c] * ood[c]);
    let mut cur: Vec<E> = Vec::with_capacity(n0);
    let mut x = F::ONE;
    for i in 0..n0 {
        let combo = (0..w).fold(E::ZERO, |s, c| s + alpha_pows[c].mul_base(lde[c][i]));
        cur.push((combo - ood_combo) * (E::from_base(x) - z).inv());
        x = x * omega0;
    }

    // ---- FRI folding + commitments ----------------------------------
    let mut fri_trees: Vec<Tree> = Vec::new();
    let mut fri_cws: Vec<Vec<E>> = Vec::new();
    for j in 0..k {
        let beta = tr.challenge_ext();
        cur = fold_layer(&cur, p.log_n(j), p.log_arities[j], beta);
        if j + 1 < k {
            let leaves = 1usize << p.log_leaves(j + 1);
            let arity = 1usize << p.log_arities[j + 1];
            let leaf_bytes: Vec<Vec<u8>> =
                (0..leaves).map(|l| coset_leaf_bytes(&cur, l, leaves, arity)).collect();
            let tree = Tree::build(h, &leaf_bytes);
            let cap = tree.cap_bytes(p.cap_height_at(j + 1));
            proof.extend_from_slice(&cap);
            tr.observe(&cap);
            fri_trees.push(tree);
            fri_cws.push(cur.clone());
        }
    }

    let coeffs_final = intt_ext(&cur, F::two_adic_generator(p.log_n(k)));
    let final_len = p.final_poly_len();
    assert!(
        !check_final || coeffs_final[final_len..].iter().all(|c| *c == E::ZERO),
        "prover bug: final codeword is not low-degree"
    );
    let final_bytes: Vec<u8> = coeffs_final[..final_len].iter().flat_map(|e| e.to_bytes()).collect();
    proof.extend_from_slice(&final_bytes);
    tr.observe(&final_bytes);

    // ---- Grinding ---------------------------------------------------
    let bits = p.grind_bits as u32;
    let nonce = (0u64..).find(|&n| tr.clone().check_pow(n, bits)).unwrap();
    assert!(tr.check_pow(nonce, bits));
    proof.extend_from_slice(&nonce.to_le_bytes());

    // ---- Query openings ---------------------------------------------
    for _ in 0..p.num_queries {
        let mut pos = tr.challenge_index(p.log_leaves(0));
        proof.extend_from_slice(&trace_leaves[pos]);
        proof.extend_from_slice(&trace_tree.path(pos, p.cap_height_at(0)));
        for j in 1..k {
            let leaves = 1usize << p.log_leaves(j);
            let idx = pos % leaves;
            let arity = 1usize << p.log_arities[j];
            proof.extend_from_slice(&coset_leaf_bytes(&fri_cws[j - 1], idx, leaves, arity));
            proof.extend_from_slice(&fri_trees[j - 1].path(idx, p.cap_height_at(j)));
            pos = idx;
        }
    }
    proof
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::Sha2Hasher;
    use crate::verifier::{verify, VerifyError};

    fn small() -> Params {
        Params {
            log_trace_rows: 6,
            num_cols: 5,
            log_blowup: 2,
            num_queries: 6,
            grind_bits: 4,
            cap_height: 2,
            log_arities: vec![1, 2, 2],
        }
    }

    #[test]
    fn ntt_round_trips() {
        let omega = F::two_adic_generator(4);
        let orig: Vec<F> = (0..16u64).map(|i| F::from_u64(i * 7 + 1)).collect();
        let mut v = orig.clone();
        ntt(&mut v, omega);
        let back = intt_ext(&v.iter().map(|&f| E::from_base(f)).collect::<Vec<_>>(), omega);
        assert_eq!(back.iter().map(|e| e.0[0]).collect::<Vec<_>>(), orig);
    }

    #[test]
    fn prove_then_verify_accepts() {
        for arities in [vec![1], vec![1, 1, 1], vec![2, 3], vec![1, 2, 2]] {
            let p = Params { log_arities: arities, ..small() };
            let proof = prove(&Sha2Hasher, &p, b"pi", 7);
            assert_eq!(verify(&Sha2Hasher, &p.to_bytes(), &proof, b"pi"), Ok(()), "{:?}", p.log_arities);
        }
    }

    #[test]
    fn rejects_wrong_public_inputs() {
        let p = small();
        let proof = prove(&Sha2Hasher, &p, b"pi", 7);
        assert!(verify(&Sha2Hasher, &p.to_bytes(), &proof, b"other").is_err());
    }

    #[test]
    fn rejects_any_single_byte_flip() {
        let p = small();
        let proof = prove(&Sha2Hasher, &p, b"pi", 7);
        let pb = p.to_bytes();
        // Stride keeps the test fast while touching every section.
        for i in (0..proof.len()).step_by(37) {
            let mut bad = proof.clone();
            bad[i] ^= 0x01;
            assert!(verify(&Sha2Hasher, &pb, &bad, b"pi").is_err(), "byte {i} flip accepted");
        }
    }

    #[test]
    fn rejects_truncated_and_extended() {
        let p = small();
        let proof = prove(&Sha2Hasher, &p, b"pi", 7);
        let pb = p.to_bytes();
        assert_eq!(verify(&Sha2Hasher, &pb, &proof[..proof.len() - 1], b"pi"), Err(VerifyError::BadProof));
        let mut longer = proof.clone();
        longer.push(0);
        assert_eq!(verify(&Sha2Hasher, &pb, &longer, b"pi"), Err(VerifyError::BadProof));
    }

    #[test]
    fn rejects_high_degree_trace() {
        // Same params, but the committed columns have degree 2× the
        // bound. FRI must catch it at some fold or at the final poly.
        let p = small();
        let proof = prove_inner(&Sha2Hasher, &p, b"pi", 7, 2 << p.log_trace_rows, false);
        let err = verify(&Sha2Hasher, &p.to_bytes(), &proof, b"pi").unwrap_err();
        assert!(
            matches!(err, VerifyError::FoldMismatch { .. } | VerifyError::FinalPolyMismatch),
            "{err:?}"
        );
    }
}
