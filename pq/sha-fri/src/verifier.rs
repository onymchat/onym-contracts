//! Verifier: DEEP trace opening + multi-arity FRI.
//!
//! ## Proof layout (byte order = transcript order)
//!
//! ```text
//!   trace_cap        2^cap₀ digests
//!   ood              num_cols × E          T_c(z) per column
//!   fri_caps[1..k]   2^cap_j digests each
//!   final_poly       final_poly_len × E    coefficients, low first
//!   pow_nonce        u64 LE
//!   queries × num_queries:
//!     trace_leaf     2^a₀ rows × num_cols × u32 LE
//!     trace_path     (log_leaves₀ − cap₀) digests
//!     for j in 1..k:
//!       fri_leaf     2^a_j × E
//!       fri_path     (log_leaves_j − cap_j) digests
//! ```
//!
//! ## Transcript
//!
//! `params ‖ public_inputs`, trace cap → `z`; OOD values → `α`; then
//! for each layer `β_j` followed by the next layer's cap; final poly;
//! PoW nonce; then one query index per query.
//!
//! ## Per query
//!
//! 1. Open the trace leaf at coset `pos` and compute the DEEP quotient
//!    `f₀(x) = Σ_c αᶜ·(T_c(x) − T_c(z)) / (x − z)` at each of its
//!    `2^a₀` points. Fold to one value.
//! 2. For each FRI layer, open the leaf containing the carried
//!    position, check the carried value sits in the expected slot,
//!    fold again.
//! 3. Evaluate the final polynomial at the carried point and compare.

use crate::field::{E, E_BYTES, F};
use crate::fold::fold_leaf;
use crate::hash::{Digest, Hasher};
use crate::merkle::verify_path;
use crate::params::Params;
use crate::transcript::Transcript;
use alloc::vec::Vec;

pub const TRANSCRIPT_LABEL: &[u8] = b"onym-pq-sha-fri-v0";

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadParams,
    /// Truncated, trailing bytes, or a non-canonical field element.
    BadProof,
    PowFailed,
    MerkleMismatch { layer: usize },
    FoldMismatch { layer: usize },
    FinalPolyMismatch,
}

struct Reader<'p> {
    buf: &'p [u8],
    pos: usize,
}

impl<'p> Reader<'p> {
    fn take(&mut self, n: usize) -> Result<&'p [u8], VerifyError> {
        let end = self.pos.checked_add(n).ok_or(VerifyError::BadProof)?;
        let out = self.buf.get(self.pos..end).ok_or(VerifyError::BadProof)?;
        self.pos = end;
        Ok(out)
    }

    fn digests(&mut self, n: usize) -> Result<Vec<Digest>, VerifyError> {
        let raw = self.take(n * 32)?;
        Ok(raw.chunks_exact(32).map(|c| c.try_into().unwrap()).collect())
    }

    fn exts(raw: &[u8]) -> Result<Vec<E>, VerifyError> {
        raw.chunks_exact(E_BYTES).map(|c| E::from_bytes(c).ok_or(VerifyError::BadProof)).collect()
    }

    fn u64(&mut self) -> Result<u64, VerifyError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

fn base_at(row: &[u8], col: usize) -> Result<F, VerifyError> {
    let b = &row[4 * col..4 * col + 4];
    F::from_canonical(u32::from_le_bytes([b[0], b[1], b[2], b[3]])).ok_or(VerifyError::BadProof)
}

fn digest_bytes(ds: &[Digest]) -> Vec<u8> {
    let mut out = Vec::with_capacity(ds.len() * 32);
    for d in ds {
        out.extend_from_slice(d);
    }
    out
}

pub fn verify<H: Hasher>(
    h: &H,
    params_bytes: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<(), VerifyError> {
    let p = Params::from_bytes(params_bytes).map_err(|_| VerifyError::BadParams)?;
    let k = p.num_layers();
    let w = p.num_cols as usize;
    let mut r = Reader { buf: proof, pos: 0 };
    let mut t = Transcript::new(h, TRANSCRIPT_LABEL);
    t.observe(params_bytes);
    t.observe(public_inputs);

    // ---- Commitments and challenges ---------------------------------
    let trace_cap = r.digests(1 << p.cap_height_at(0))?;
    t.observe(&digest_bytes(&trace_cap));
    let z = t.challenge_ext();

    let ood_raw = r.take(w * E_BYTES)?;
    let ood = Reader::exts(ood_raw)?;
    t.observe(ood_raw);
    let alpha = t.challenge_ext();

    let mut betas = Vec::with_capacity(k);
    let mut fri_caps: Vec<Vec<Digest>> = Vec::with_capacity(k.saturating_sub(1));
    for j in 0..k {
        betas.push(t.challenge_ext());
        if j + 1 < k {
            let cap = r.digests(1 << p.cap_height_at(j + 1))?;
            t.observe(&digest_bytes(&cap));
            fri_caps.push(cap);
        }
    }

    let final_raw = r.take(p.final_poly_len() * E_BYTES)?;
    let final_poly = Reader::exts(final_raw)?;
    t.observe(final_raw);

    let nonce = r.u64()?;
    if !t.check_pow(nonce, p.grind_bits as u32) {
        return Err(VerifyError::PowFailed);
    }

    // ---- Query-independent precomputation ---------------------------
    let two_inv = F::from_u64(2).inv();
    let mut alpha_pows = Vec::with_capacity(w);
    let mut acc = E::ONE;
    for _ in 0..w {
        alpha_pows.push(acc);
        acc = acc * alpha;
    }
    // Σ αᶜ·T_c(z), subtracted from every row's combination.
    let mut ood_combo = E::ZERO;
    for c in 0..w {
        ood_combo = ood_combo + alpha_pows[c] * ood[c];
    }
    let omega: Vec<F> = (0..=k).map(|j| F::two_adic_generator(p.log_n(j))).collect();
    let omega_inv: Vec<F> = omega.iter().map(|o| o.inv()).collect();
    // ζ_j = ω_j^(#leaves) has order 2^a_j.
    let zeta: Vec<F> = (0..k).map(|j| omega[j].pow(1 << p.log_leaves(j))).collect();
    let zeta_inv: Vec<F> = zeta.iter().map(|z| z.inv()).collect();

    let m0 = 1usize << p.log_arities[0];
    let row_bytes = 4 * w;
    let mut vals: Vec<E> = Vec::with_capacity(1 << 4);

    // ---- Queries ----------------------------------------------------
    for _ in 0..p.num_queries {
        let mut pos = t.challenge_index(p.log_leaves(0));

        // Layer 0: trace rows → DEEP quotient → fold.
        let leaf = r.take(m0 * row_bytes)?;
        let path = r.digests((p.log_leaves(0) - p.cap_height_at(0)) as usize)?;
        if !verify_path(h, leaf, pos, &path, &trace_cap) {
            return Err(VerifyError::MerkleMismatch { layer: 0 });
        }
        vals.clear();
        let mut x = omega[0].pow(pos as u64);
        for row in leaf.chunks_exact(row_bytes) {
            let mut combo = E::ZERO;
            for c in 0..w {
                combo = combo + alpha_pows[c].mul_base(base_at(row, c)?);
            }
            vals.push((combo - ood_combo) * (E::from_base(x) - z).inv());
            x = x * zeta[0];
        }
        let mut folded = fold_leaf(&mut vals, omega_inv[0].pow(pos as u64), zeta_inv[0], betas[0], two_inv);

        // Layers 1..k: committed FRI codewords.
        for j in 1..k {
            let leaves = 1usize << p.log_leaves(j);
            let (idx, slot) = (pos % leaves, pos / leaves);
            let leaf = r.take((1 << p.log_arities[j]) * E_BYTES)?;
            let path = r.digests((p.log_leaves(j) - p.cap_height_at(j)) as usize)?;
            if !verify_path(h, leaf, idx, &path, &fri_caps[j - 1]) {
                return Err(VerifyError::MerkleMismatch { layer: j });
            }
            vals = Reader::exts(leaf)?;
            if vals[slot] != folded {
                return Err(VerifyError::FoldMismatch { layer: j });
            }
            folded = fold_leaf(&mut vals, omega_inv[j].pow(idx as u64), zeta_inv[j], betas[j], two_inv);
            pos = idx;
        }

        // Final polynomial at ω_k^pos, Horner.
        let x = omega[k].pow(pos as u64);
        let mut eval = E::ZERO;
        for c in final_poly.iter().rev() {
            eval = eval.mul_base(x) + *c;
        }
        if eval != folded {
            return Err(VerifyError::FinalPolyMismatch);
        }
    }

    if r.pos != proof.len() {
        return Err(VerifyError::BadProof);
    }
    Ok(())
}
