//! Prover for the membership AIR, matching `verifier` byte for byte.
//!
//! Zero-knowledge ingredients (see `params` for the degree budget):
//! - Trace columns `T + Z_H·R`, `R` random of degree `< h`.
//! - Quotient chunks `Q_j + xⁿ·b_j − b_{j−1}` (telescoping, sum unchanged).
//! - A random mask polynomial `r` of degree `< 2n` added to the DEEP
//!   codeword, so FRI layer openings reveal nothing about the trace.
//! - 16-byte random salt in every trace / quotient Merkle leaf, so
//!   unopened leaf hashes don't commit to guessable values.
//!
//! **Bench randomness**: masks and salts come from a seeded xorshift so
//! runs are reproducible. A production prover must draw them from a
//! CSPRNG; with a predictable seed the proof is not zero-knowledge.
//!
//! Self-checks (panics on failure, so a passing prove is itself an
//! end-to-end consistency test): the quotient numerator divides exactly
//! (the AIR holds on the trace), the AIR identity holds at `z`, and the
//! final FRI codeword is low-degree.

use crate::air::{self, Shape, Witness, NUM_COLS};
use crate::field::{E, F};
use crate::fold::fold_leaf;
use crate::hash::{Digest, Hasher};
use crate::merkle::{leaf_hash, node_hash};
use crate::params::Params;
use crate::poly::{coset_interpolate, coset_lde, eval_base, intt, SHIFT};
use crate::transcript::Transcript;
use crate::verifier::{
    air_check_at_z, combine_constraints, deep_coeffs, periodic_coeffs, LEAF_SALT, TRANSCRIPT_LABEL,
};
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

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*: reproducible bench data, NOT a CSPRNG.
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn f(&mut self) -> F {
        F::from_u64(self.next())
    }
    fn e(&mut self) -> E {
        E([self.f(), self.f(), self.f(), self.f()])
    }
    fn salt(&mut self) -> [u8; LEAF_SALT] {
        let mut s = [0u8; LEAF_SALT];
        s[..8].copy_from_slice(&self.next().to_le_bytes());
        s[8..].copy_from_slice(&self.next().to_le_bytes());
        s
    }
}

/// Merkle leaves for column-major LDE data grouped by layer-0 cosets:
/// `salt ‖ rows l + t·s for t < m`.
fn salted_row_leaves(cols: &[Vec<F>], log_leaves: u32, m: usize, rng: &mut Rng) -> Vec<Vec<u8>> {
    let s = 1usize << log_leaves;
    (0..s)
        .map(|l| {
            let mut b = Vec::with_capacity(LEAF_SALT + m * cols.len() * 4);
            b.extend_from_slice(&rng.salt());
            for t in 0..m {
                for col in cols {
                    b.extend_from_slice(&col[l + t * s].value().to_le_bytes());
                }
            }
            b
        })
        .collect()
}

fn fold_layer(cw: &[E], log_n: u32, log_arity: u8, beta: E, shift: F) -> Vec<E> {
    let n = 1usize << log_n;
    let m = 1usize << log_arity;
    let s = n / m;
    let omega = F::two_adic_generator(log_n);
    let omega_inv = omega.inv();
    let zeta_inv = omega.pow(s as u64).inv();
    let two_inv = F::from_u64(2).inv();
    let mut out = Vec::with_capacity(s);
    let mut x0_inv = shift.inv();
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

pub fn prove<H: Hasher>(h: &H, p: &Params, w: &Witness, seed: u64) -> Vec<u8> {
    prove_trace(h, p, &w.public_inputs(), w.trace(&p.shape()), seed)
}

/// Proves an explicit trace against explicit public inputs. Panics if the
/// trace doesn't satisfy the AIR for those inputs.
fn prove_trace<H: Hasher>(
    h: &H,
    p: &Params,
    pi: &air::PublicInputs,
    rows: Vec<[F; NUM_COLS]>,
    seed: u64,
) -> Vec<u8> {
    p.validate().expect("invalid params");
    let shape: Shape = p.shape();
    let k = p.num_layers();
    let n = p.n();
    let log_n0 = p.log_n0();
    let n0 = p.n0();
    let hdeg = p.mask_degree as usize;
    let chunks = p.num_quotient_chunks();
    let m0 = 1usize << p.log_arities[0];
    let params_bytes = p.to_bytes();
    assert_eq!(p.kind, shape.kind);
    let pi_bytes = pi.to_bytes();
    let mut rng = Rng(seed | 1);
    let g = F::two_adic_generator(p.log_n());

    // ---- Trace: interpolate, mask with Z_H·R, LDE on the coset -------
    let t_coeffs: Vec<Vec<F>> = (0..NUM_COLS)
        .map(|c| {
            let mut v: Vec<F> = rows.iter().map(|r| r[c]).collect();
            intt(&mut v, g);
            v.resize(n + hdeg, F::ZERO);
            for i in 0..hdeg {
                let r = rng.f();
                v[i] = v[i] - r;
                v[n + i] = v[n + i] + r;
            }
            v
        })
        .collect();
    let t_lde: Vec<Vec<F>> = t_coeffs.iter().map(|c| coset_lde(c, log_n0, SHIFT)).collect();
    let t_leaves = salted_row_leaves(&t_lde, p.log_leaves(0), m0, &mut rng);
    let t_tree = Tree::build(h, &t_leaves);

    let mut proof = Vec::new();
    let mut tr = Transcript::new(h, TRANSCRIPT_LABEL);
    tr.observe(&params_bytes);
    tr.observe(&pi_bytes);
    let cap = t_tree.cap_bytes(p.cap_height_at(0));
    proof.extend_from_slice(&cap);
    tr.observe(&cap);
    let alpha = tr.challenge_ext();

    // ---- Quotient on the LDE coset ----------------------------------
    let count = air::num_constraints(shape.kind);
    let mut alpha_pows = Vec::with_capacity(count);
    let mut a = E::ONE;
    for _ in 0..count {
        alpha_pows.push(a);
        a = a * alpha;
    }
    let per_coeffs = periodic_coeffs();
    let omega0 = F::two_adic_generator(log_n0);
    let step = n0 / n; // g = ω₀^step
    let mut q_evals = Vec::with_capacity(n0);
    let mut nums: Vec<F> = Vec::with_capacity(count);
    let mut local = [F::ZERO; NUM_COLS];
    let mut next = [F::ZERO; NUM_COLS];
    let mut x = SHIFT;
    for i in 0..n0 {
        for c in 0..NUM_COLS {
            local[c] = t_lde[c][i];
            next[c] = t_lde[c][(i + step) % n0];
        }
        let y = x.pow(shape.blocks() as u64);
        let per: Vec<F> = per_coeffs.iter().map(|c| eval_base(c, y)).collect();
        air::eval(&shape, &local, &next, &per, pi, &mut nums);
        let div_invs = air::divisors(&shape, x, x.pow(n as u64), g).map(|d| d.inv());
        q_evals.push(combine_constraints(&shape, &nums, &alpha_pows, &div_invs));
        x = x * omega0;
    }
    let q_coeffs = coset_interpolate(&q_evals, SHIFT);
    assert!(
        q_coeffs[chunks * n..].iter().all(|c| *c == E::ZERO),
        "AIR not satisfied by the trace (quotient is not a polynomial of the expected degree)"
    );

    // Split into chunks of n coefficients, add telescoping randomizers.
    let mut q_chunks: Vec<Vec<E>> = (0..chunks)
        .map(|j| {
            let mut v = q_coeffs[j * n..(j + 1) * n].to_vec();
            v.resize(n + hdeg, E::ZERO);
            v
        })
        .collect();
    for j in 0..chunks - 1 {
        for i in 0..hdeg {
            let b = rng.e();
            q_chunks[j][n + i] = q_chunks[j][n + i] + b;
            q_chunks[j + 1][i] = q_chunks[j + 1][i] - b;
        }
    }
    // Base-field coefficient columns: 4 per chunk, then 4 for the mask.
    let mut q_col_coeffs: Vec<Vec<F>> = Vec::with_capacity(p.quotient_cols());
    for chunk in &q_chunks {
        for comp in 0..4 {
            q_col_coeffs.push(chunk.iter().map(|e| e.0[comp]).collect());
        }
    }
    for _ in 0..4 {
        q_col_coeffs.push((0..2 * n).map(|_| rng.f()).collect());
    }
    let q_lde: Vec<Vec<F>> = q_col_coeffs.iter().map(|c| coset_lde(c, log_n0, SHIFT)).collect();
    let q_leaves = salted_row_leaves(&q_lde, p.log_leaves(0), m0, &mut rng);
    let q_tree = Tree::build(h, &q_leaves);
    let cap = q_tree.cap_bytes(p.cap_height_at(0));
    proof.extend_from_slice(&cap);
    tr.observe(&cap);
    let z = tr.challenge_ext();

    // ---- OOD values -------------------------------------------------
    let gz = z.mul_base(g);
    let chunk_cols = 4 * chunks;
    let ood_z: Vec<E> = t_coeffs.iter().map(|c| eval_base(c, z)).collect();
    let ood_gz: Vec<E> = t_coeffs.iter().map(|c| eval_base(c, gz)).collect();
    let ood_q: Vec<E> = q_col_coeffs[..chunk_cols].iter().map(|c| eval_base(c, z)).collect();
    let (lhs, rhs) = air_check_at_z(p, pi, z, alpha, &ood_z, &ood_gz, &ood_q);
    assert_eq!(lhs, rhs, "prover bug: AIR identity fails at z");
    let ood_bytes: Vec<u8> = ood_z.iter().chain(&ood_gz).chain(&ood_q).flat_map(|e| e.to_bytes()).collect();
    proof.extend_from_slice(&ood_bytes);
    tr.observe(&ood_bytes);
    let gamma = tr.challenge_ext();

    // ---- DEEP codeword ----------------------------------------------
    let deep = deep_coeffs(gamma, &ood_z, &ood_gz, &ood_q);
    let mut cur: Vec<E> = Vec::with_capacity(n0);
    let mut trace_row = [F::ZERO; NUM_COLS];
    let mut quot_row = vec![F::ZERO; chunk_cols];
    let mut x = SHIFT;
    for i in 0..n0 {
        for c in 0..NUM_COLS {
            trace_row[c] = t_lde[c][i];
        }
        for c in 0..chunk_cols {
            quot_row[c] = q_lde[c][i];
        }
        let mask = [q_lde[chunk_cols][i], q_lde[chunk_cols + 1][i], q_lde[chunk_cols + 2][i], q_lde[chunk_cols + 3][i]];
        cur.push(deep.eval(x, z, gz, &trace_row, &quot_row, mask));
        x = x * omega0;
    }

    // ---- FRI --------------------------------------------------------
    let mut fri_trees: Vec<Tree> = Vec::new();
    let mut fri_cws: Vec<Vec<E>> = Vec::new();
    let mut shift = SHIFT;
    for j in 0..k {
        let beta = tr.challenge_ext();
        cur = fold_layer(&cur, p.log_layer(j), p.log_arities[j], beta, shift);
        shift = shift.pow(1 << p.log_arities[j]);
        if j + 1 < k {
            let leaves = 1usize << p.log_leaves(j + 1);
            let arity = 1usize << p.log_arities[j + 1];
            let leaf_bytes: Vec<Vec<u8>> = (0..leaves).map(|l| coset_leaf_bytes(&cur, l, leaves, arity)).collect();
            let tree = Tree::build(h, &leaf_bytes);
            let cap = tree.cap_bytes(p.cap_height_at(j + 1));
            proof.extend_from_slice(&cap);
            tr.observe(&cap);
            fri_trees.push(tree);
            fri_cws.push(cur.clone());
        }
    }
    let final_coeffs = coset_interpolate(&cur, shift);
    let final_len = p.final_poly_len();
    assert!(
        final_coeffs[final_len..].iter().all(|c| *c == E::ZERO),
        "prover bug: final codeword is not low-degree"
    );
    let final_bytes: Vec<u8> = final_coeffs[..final_len].iter().flat_map(|e| e.to_bytes()).collect();
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
        proof.extend_from_slice(&t_leaves[pos]);
        proof.extend_from_slice(&t_tree.path(pos, p.cap_height_at(0)));
        proof.extend_from_slice(&q_leaves[pos]);
        proof.extend_from_slice(&q_tree.path(pos, p.cap_height_at(0)));
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

/// Random membership witness for benches and tests: random key, path,
/// salt; `epoch` as given.
pub fn random_witness(depth: usize, seed: u64, epoch: u64) -> Witness {
    let mut rng = Rng(seed | 1);
    let mut digest = || -> [F; 8] { core::array::from_fn(|_| F::from_u64(rng.next())) };
    let sk = digest();
    let salt = digest();
    let path = (0..depth).map(|_| digest()).collect();
    let index = (seed as usize) & ((1 << depth) - 1);
    Witness { sk, path, index, salt, epoch, update: None }
}

/// The same member's update from `w`'s state to a random new root/salt.
pub fn with_random_update(mut w: Witness, seed: u64) -> Witness {
    let mut rng = Rng(seed.rotate_left(17) | 1);
    let mut digest = || -> [F; 8] { core::array::from_fn(|_| F::from_u64(rng.next())) };
    w.update = Some(air::UpdateWitness { root_new: digest(), salt_new: digest() });
    w
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::{Kind, PublicInputs};
    use crate::hash::Sha2Hasher;
    use crate::verifier::{verify, VerifyError};

    fn small(kind: Kind) -> Params {
        Params {
            kind,
            depth: 3,
            mask_degree: 26,
            log_blowup: 3,
            num_queries: 12,
            grind_bits: 4,
            cap_height: 2,
            log_arities: vec![1, 2, 2],
        }
    }

    fn witness(kind: Kind) -> Witness {
        let w = random_witness(3, 5, 0x0000_1234_5678_9abc);
        match kind {
            Kind::Membership => w,
            Kind::Update => with_random_update(w, 6),
        }
    }

    const KINDS: [Kind; 2] = [Kind::Membership, Kind::Update];

    #[test]
    fn constants_match_derivation() {
        use sha2::{Digest as _, Sha256};
        let derive = |i: u32| {
            let mut h = Sha256::new();
            h.update(b"onym-poseidon2-babybear-w16-v0");
            h.update(i.to_le_bytes());
            let d = h.finalize();
            (u64::from_le_bytes(d[..8].try_into().unwrap()) % crate::field::P as u64) as u32
        };
        for r in 0..8 {
            for l in 0..16 {
                assert_eq!(crate::poseidon2_constants::RC_EXT[r][l], derive((16 * r + l) as u32));
            }
        }
        for r in 0..13 {
            assert_eq!(crate::poseidon2_constants::RC_INT[r], derive(128 + r as u32));
        }
    }

    #[test]
    fn trace_satisfies_air_on_trace_domain() {
        for kind in KINDS {
            let p = small(kind);
            let shape = p.shape();
            let w = witness(kind);
            let pi = w.public_inputs();
            let rows = w.trace(&shape);
            let g = F::two_adic_generator(shape.log_n());
            let mut nums = Vec::new();
            for r in 0..shape.n() {
                let per = air::periodic_row(r % air::BLOCK);
                air::eval(&shape, &rows[r], &rows[(r + 1) % shape.n()], &per, &pi, &mut nums);
                let x = g.pow(r as u64);
                let divs = air::divisors(&shape, x, x.pow(shape.n() as u64), g);
                for (gi, &(s, e)) in air::groups(kind).iter().enumerate() {
                    if divs[gi] == F::ZERO {
                        for i in s..e {
                            assert_eq!(nums[i], F::ZERO, "{kind:?} row {r} group {gi} constraint {i}");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn periodic_coeffs_reproduce_rows() {
        let coeffs = periodic_coeffs();
        let w32 = F::two_adic_generator(air::LOG_BLOCK);
        for r in 0..air::BLOCK {
            let row = air::periodic_row(r);
            for c in 0..air::NUM_PERIODIC {
                assert_eq!(eval_base::<F>(&coeffs[c], w32.pow(r as u64)), row[c]);
            }
        }
    }

    #[test]
    fn prove_then_verify_accepts() {
        for kind in KINDS {
            for arities in [vec![1, 2, 2], vec![2, 3], vec![1, 1, 1, 1]] {
                // Hiding needs mask degree ≥ queries · 2^a₀ + 2.
                let h = 12 * (1u16 << arities[0]) + 2;
                let p = Params { mask_degree: h, log_arities: arities, ..small(kind) };
                let w = witness(kind);
                let proof = prove(&Sha2Hasher, &p, &w, 99);
                let pi = w.public_inputs().to_bytes();
                assert_eq!(verify(&Sha2Hasher, &p.to_bytes(), &proof, &pi), Ok(()), "{kind:?} {:?}", p.log_arities);
            }
        }
    }

    #[test]
    fn deployment_params_are_valid_for_every_tier() {
        use crate::params::{deployment_params, Profile};
        for kind in KINDS {
            for depth in [5u8, 8, 11] {
                for profile in [Profile::Johnson100, Profile::Conjectured100] {
                    let p = deployment_params(kind, depth, profile);
                    assert_eq!(p.validate(), Ok(()), "{kind:?} d{depth} {profile:?}");
                    assert_eq!(p.final_poly_len(), 1);
                    let bits = match profile {
                        Profile::Johnson100 => p.johnson_security_bits(),
                        Profile::Conjectured100 => p.conjectured_security_bits(),
                    };
                    assert!(bits >= 100, "{kind:?} d{depth} {profile:?}: {bits} bits");
                }
            }
        }
    }

    #[test]
    fn rejects_wrong_public_inputs() {
        for kind in KINDS {
            let p = small(kind);
            let w = witness(kind);
            let proof = prove(&Sha2Hasher, &p, &w, 99);
            let pi = w.public_inputs();
            let pb = p.to_bytes();
            let wrong_epoch = PublicInputs { epoch: pi.epoch + 1, ..w.public_inputs() };
            assert!(verify(&Sha2Hasher, &pb, &proof, &wrong_epoch.to_bytes()).is_err());
            let mut c = pi.commitment;
            c[3] = c[3] + F::ONE;
            let wrong_commit = PublicInputs { commitment: c, ..w.public_inputs() };
            assert!(verify(&Sha2Hasher, &pb, &proof, &wrong_commit.to_bytes()).is_err());
            if kind == Kind::Update {
                let mut c_new = pi.c_new.unwrap();
                c_new[0] = c_new[0] + F::ONE;
                let wrong_new = PublicInputs { c_new: Some(c_new), ..w.public_inputs() };
                assert!(verify(&Sha2Hasher, &pb, &proof, &wrong_new.to_bytes()).is_err());
            }
        }
    }

    #[test]
    fn rejects_proof_of_the_other_kind() {
        let w = witness(Kind::Update);
        let proof = prove(&Sha2Hasher, &small(Kind::Update), &w, 99);
        let mut pi = w.public_inputs();
        pi.c_new = None;
        assert!(verify(&Sha2Hasher, &small(Kind::Membership).to_bytes(), &proof, &pi.to_bytes()).is_err());
    }

    #[test]
    fn rejects_any_single_byte_flip() {
        for kind in KINDS {
            let p = small(kind);
            let w = witness(kind);
            let proof = prove(&Sha2Hasher, &p, &w, 99);
            let pb = p.to_bytes();
            let pi = w.public_inputs().to_bytes();
            for i in (0..proof.len()).step_by(41) {
                let mut bad = proof.clone();
                bad[i] ^= 0x01;
                assert!(verify(&Sha2Hasher, &pb, &bad, &pi).is_err(), "{kind:?} byte {i} flip accepted");
            }
        }
    }

    #[test]
    fn rejects_truncated_and_extended() {
        let p = small(Kind::Membership);
        let w = witness(Kind::Membership);
        let proof = prove(&Sha2Hasher, &p, &w, 99);
        let pb = p.to_bytes();
        let pi = w.public_inputs().to_bytes();
        assert_eq!(verify(&Sha2Hasher, &pb, &proof[..proof.len() - 1], &pi), Err(VerifyError::BadProof));
        let mut longer = proof.clone();
        longer.push(0);
        assert_eq!(verify(&Sha2Hasher, &pb, &longer, &pi), Err(VerifyError::BadProof));
    }

    #[test]
    #[should_panic(expected = "AIR not satisfied")]
    fn prover_refuses_non_member() {
        // Someone holding a different key tries to prove against the
        // real group commitment: the commitment boundary can't hold.
        let p = small(Kind::Membership);
        let mut w = witness(Kind::Membership);
        let real = w.public_inputs();
        w.sk[0] = w.sk[0] + F::ONE;
        prove_trace(&Sha2Hasher, &p, &real, w.trace(&p.shape()), 1);
    }

    #[test]
    #[should_panic(expected = "AIR not satisfied")]
    fn prover_refuses_update_by_non_member() {
        let p = small(Kind::Update);
        let mut w = witness(Kind::Update);
        let real = w.public_inputs();
        w.sk[0] = w.sk[0] + F::ONE;
        prove_trace(&Sha2Hasher, &p, &real, w.trace(&p.shape()), 1);
    }

    #[test]
    fn rejects_proof_for_different_params() {
        let p = small(Kind::Membership);
        let w = witness(Kind::Membership);
        let proof = prove(&Sha2Hasher, &p, &w, 99);
        let other = Params { num_queries: 13, mask_degree: 28, ..small(Kind::Membership) };
        let pi = w.public_inputs().to_bytes();
        assert!(verify(&Sha2Hasher, &other.to_bytes(), &proof, &pi).is_err());
    }
}
