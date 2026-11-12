//! Verifier: membership AIR + DEEP-ALI + multi-arity FRI, zero-knowledge.
//!
//! ## Proof layout (byte order = transcript order)
//!
//! ```text
//!   trace_cap          2^cap₀ digests                       → α
//!   quotient_cap       2^cap₀ digests                       → z
//!   ood_trace_z        NUM_COLS × E      T_c(z)
//!   ood_trace_gz       NUM_COLS × E      T_c(g·z)
//!   ood_quotient       4C × E            Q_{j,k}(z)          → γ
//!   fri_caps[1..k]     2^cap_j digests each (β_j before each)
//!   final_poly         final_poly_len × E
//!   pow_nonce          u64 LE
//!   queries × num_queries:
//!     trace_leaf       salt(16) ‖ 2^a₀ rows × NUM_COLS × u32
//!     trace_path       (log_leaves₀ − cap₀) digests
//!     quotient_leaf    salt(16) ‖ 2^a₀ rows × quotient_cols × u32
//!     quotient_path    (log_leaves₀ − cap₀) digests
//!     for j in 1..k:   fri_leaf (2^a_j × E) ‖ fri_path
//! ```
//!
//! ## Checks
//!
//! 1. **AIR at z.** `Σ_groups (Σ αⁱ·Cᵢ(z)) / D_group(z) = Σ_j z^(jn)·Q_j(z)`,
//!    with the periodic columns evaluated by the verifier itself.
//! 2. **DEEP.** For each opened LDE point `x`:
//!    `f(x) = (Σ γ·T(x) + Σ γ·Q(x) − A_z)/(x − z) + (Σ γ·T(x) − A_gz)/(x − gz) + r(x)`,
//!    where `r` is the committed random mask polynomial that keeps FRI
//!    layers hiding.
//! 3. **FRI** on `f` with degree bound `2n` (multi-arity folding), on
//!    the coset `SHIFT·⟨ω⟩`.

use crate::air::{self, PublicInputs, Shape, NUM_PERIODIC};
use crate::field::{Algebra, E, E_BYTES, EXT_DEG, F};
use crate::fold::fold_leaf;
use crate::hash::{Digest, Hasher};
use crate::merkle::verify_path;
use crate::params::Params;
use crate::poly::{eval_base, intt, SHIFT};
use crate::transcript::Transcript;
use alloc::vec::Vec;

pub const TRANSCRIPT_LABEL: &[u8] = b"onym-pq-sha-fri-membership-v1";
pub const LEAF_SALT: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    BadParams,
    BadPublicInputs,
    /// Truncated, trailing bytes, or a non-canonical field element.
    BadProof,
    ConstraintMismatch,
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

    fn u64(&mut self) -> Result<u64, VerifyError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

pub(crate) fn exts(raw: &[u8]) -> Result<Vec<E>, VerifyError> {
    raw.chunks_exact(E_BYTES).map(|c| E::from_bytes(c).ok_or(VerifyError::BadProof)).collect()
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

/// `Xᵏ·e` in the extension basis.
fn times_x_pow(e: E, k: usize) -> E {
    let mut basis = E::ZERO;
    basis.0[k] = F::ONE;
    basis * e
}

/// Coefficients of the 20 periodic columns as polynomials in `y = x^blocks`.
pub fn periodic_coeffs() -> Vec<[F; air::BLOCK]> {
    let omega32 = F::two_adic_generator(air::LOG_BLOCK);
    (0..NUM_PERIODIC)
        .map(|col| {
            let mut v: [F; air::BLOCK] = core::array::from_fn(|r| air::periodic_row(r)[col]);
            intt(&mut v, omega32);
            v
        })
        .collect()
}

/// `Σ_groups (Σ αⁱ·Cᵢ(x)) / D_group(x)`; shared with the prover's
/// pointwise quotient computation.
pub fn combine_constraints<A: Algebra>(
    shape: &Shape,
    numerators: &[A],
    alpha_pows: &[E],
    divisor_invs: &[A; air::NUM_DIVISORS],
) -> E
where
    E: From<A>,
{
    let mut total = E::ZERO;
    for &(start, end, div) in air::groups(shape.kind) {
        let mut acc = E::ZERO;
        for i in start..end {
            acc = acc + alpha_pows[i] * E::from(numerators[i]);
        }
        total = total + acc * E::from(divisor_invs[div]);
    }
    total
}

/// The AIR identity at `z`: returns `Σ (combined constraints)/divisors`
/// and the reconstructed `Q(z)`, which must agree.
pub fn air_check_at_z(
    p: &Params,
    pi: &PublicInputs,
    z: E,
    alpha: E,
    ood_z: &[E],
    ood_gz: &[E],
    ood_q: &[E],
) -> (E, E) {
    let shape = p.shape();
    let n = p.n();
    let g = F::two_adic_generator(p.log_n());

    let y = pow_e(z, shape.blocks() as u64);
    let per: Vec<E> = periodic_coeffs().iter().map(|c| eval_base(c, y)).collect();

    let count = air::num_constraints(shape.kind);
    let mut numerators = Vec::with_capacity(count);
    air::eval(&shape, ood_z, ood_gz, &per, pi, &mut numerators);

    let mut alpha_pows = Vec::with_capacity(count);
    let mut a = E::ONE;
    for _ in 0..count {
        alpha_pows.push(a);
        a = a * alpha;
    }
    let z_n = pow_e(z, n as u64);
    let divs = air::divisors(&shape, z, z_n, g);
    let divs_inv = divs.map(|d| d.inv());
    let lhs = combine_constraints(&shape, &numerators, &alpha_pows, &divs_inv);

    let mut rhs = E::ZERO;
    let mut zjn = E::ONE;
    for j in 0..p.num_quotient_chunks() {
        let mut chunk = E::ZERO;
        for k in 0..EXT_DEG {
            chunk = chunk + times_x_pow(ood_q[EXT_DEG * j + k], k);
        }
        rhs = rhs + zjn * chunk;
        zjn = zjn * z_n;
    }
    (lhs, rhs)
}

pub fn pow_e(mut b: E, mut e: u64) -> E {
    let mut r = E::ONE;
    while e > 0 {
        if e & 1 == 1 {
            r = r * b;
        }
        b = b * b;
        e >>= 1;
    }
    r
}

/// γ-weighted sums the DEEP quotient subtracts at every point.
pub struct DeepCoeffs {
    pub gamma_pows: Vec<E>,
    pub a_z: E,
    pub a_gz: E,
    pub num_cols: usize,
}

/// `ood_z` / `ood_gz` hold one value per trace column (their length is
/// the statement's column count).
pub fn deep_coeffs(gamma: E, ood_z: &[E], ood_gz: &[E], ood_q: &[E]) -> DeepCoeffs {
    let num_cols = ood_z.len();
    let count = 2 * num_cols + ood_q.len();
    let mut gamma_pows = Vec::with_capacity(count);
    let mut g = E::ONE;
    for _ in 0..count {
        gamma_pows.push(g);
        g = g * gamma;
    }
    let mut a_z = E::ZERO;
    let mut a_gz = E::ZERO;
    for c in 0..num_cols {
        a_z = a_z + gamma_pows[2 * c] * ood_z[c];
        a_gz = a_gz + gamma_pows[2 * c + 1] * ood_gz[c];
    }
    for (q, v) in ood_q.iter().enumerate() {
        a_z = a_z + gamma_pows[2 * num_cols + q] * *v;
    }
    DeepCoeffs { gamma_pows, a_z, a_gz, num_cols }
}

impl DeepCoeffs {
    /// DEEP value at LDE point `x` from that point's trace row, quotient
    /// chunk columns and mask columns.
    pub fn eval(&self, x: F, z: E, gz: E, trace: &[F], quot: &[F], mask: [F; EXT_DEG]) -> E {
        let mut sum_z = E::ZERO;
        let mut sum_gz = E::ZERO;
        for c in 0..self.num_cols {
            sum_z = sum_z + self.gamma_pows[2 * c].mul_base(trace[c]);
            sum_gz = sum_gz + self.gamma_pows[2 * c + 1].mul_base(trace[c]);
        }
        for (q, v) in quot.iter().enumerate() {
            sum_z = sum_z + self.gamma_pows[2 * self.num_cols + q].mul_base(*v);
        }
        let xe = E::from_base(x);
        (sum_z - self.a_z) * (xe - z).inv() + (sum_gz - self.a_gz) * (xe - gz).inv() + E(mask)
    }
}

pub fn verify<H: Hasher>(
    h: &H,
    params_bytes: &[u8],
    proof: &[u8],
    public_inputs: &[u8],
) -> Result<(), VerifyError> {
    let p = Params::from_bytes(params_bytes).map_err(|_| VerifyError::BadParams)?;
    let pi = PublicInputs::from_bytes(p.kind, public_inputs).ok_or(VerifyError::BadPublicInputs)?;
    let k = p.num_layers();
    let num_cols = p.shape().num_cols();
    let qcols = p.quotient_cols();
    let chunk_cols = EXT_DEG * p.num_quotient_chunks();
    let mut r = Reader { buf: proof, pos: 0 };
    let mut t = Transcript::new(h, TRANSCRIPT_LABEL);
    t.observe(params_bytes);
    t.observe(public_inputs);

    // ---- Commitments, OOD values, AIR check -------------------------
    let trace_cap = r.digests(1 << p.cap_height_at(0))?;
    t.observe(&digest_bytes(&trace_cap));
    let alpha = t.challenge_ext();
    let quot_cap = r.digests(1 << p.cap_height_at(0))?;
    t.observe(&digest_bytes(&quot_cap));
    let z = t.challenge_ext();

    let ood_raw = r.take((2 * num_cols + chunk_cols) * E_BYTES)?;
    let ood = exts(ood_raw)?;
    t.observe(ood_raw);
    let (ood_z, rest) = ood.split_at(num_cols);
    let (ood_gz, ood_q) = rest.split_at(num_cols);

    let (lhs, rhs) = air_check_at_z(&p, &pi, z, alpha, ood_z, ood_gz, ood_q);
    if lhs != rhs {
        return Err(VerifyError::ConstraintMismatch);
    }
    let gamma = t.challenge_ext();

    // ---- FRI commitments --------------------------------------------
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
    let final_poly = exts(final_raw)?;
    t.observe(final_raw);
    let nonce = r.u64()?;
    if !t.check_pow(nonce, p.grind_bits as u32) {
        return Err(VerifyError::PowFailed);
    }

    // ---- Query-independent precomputation ---------------------------
    let g = F::two_adic_generator(p.log_n());
    let gz = z.mul_base(g);
    let deep = deep_coeffs(gamma, ood_z, ood_gz, ood_q);
    let two_inv = F::from_u64(2).inv();
    let omega: Vec<F> = (0..=k).map(|j| F::two_adic_generator(p.log_layer(j))).collect();
    let omega_inv: Vec<F> = omega.iter().map(|o| o.inv()).collect();
    let zeta: Vec<F> = (0..k).map(|j| omega[j].pow(1 << p.log_leaves(j))).collect();
    let zeta_inv: Vec<F> = zeta.iter().map(|z| z.inv()).collect();
    // Coset shift per layer: SHIFT^(product of arities so far).
    let mut shift = Vec::with_capacity(k + 1);
    shift.push(SHIFT);
    for j in 0..k {
        shift.push(shift[j].pow(1 << p.log_arities[j]));
    }
    let shift_inv: Vec<F> = shift.iter().map(|s| s.inv()).collect();

    let m0 = 1usize << p.log_arities[0];
    let path0 = (p.log_leaves(0) - p.cap_height_at(0)) as usize;
    let mut vals: Vec<E> = Vec::with_capacity(1 << 4);
    let mut trace_row = alloc::vec![F::ZERO; num_cols];
    let mut quot_row: Vec<F> = alloc::vec![F::ZERO; qcols];

    // ---- Queries ----------------------------------------------------
    for _ in 0..p.num_queries {
        let mut pos = t.challenge_index(p.log_leaves(0));

        let t_leaf = r.take(LEAF_SALT + m0 * num_cols * 4)?;
        let t_path = r.digests(path0)?;
        if !verify_path(h, t_leaf, pos, &t_path, &trace_cap) {
            return Err(VerifyError::MerkleMismatch { layer: 0 });
        }
        let q_leaf = r.take(LEAF_SALT + m0 * qcols * 4)?;
        let q_path = r.digests(path0)?;
        if !verify_path(h, q_leaf, pos, &q_path, &quot_cap) {
            return Err(VerifyError::MerkleMismatch { layer: 0 });
        }

        vals.clear();
        let mut x = shift[0] * omega[0].pow(pos as u64);
        let t_rows = t_leaf[LEAF_SALT..].chunks_exact(num_cols * 4);
        let q_rows = q_leaf[LEAF_SALT..].chunks_exact(qcols * 4);
        for (t_row, q_row) in t_rows.zip(q_rows) {
            for c in 0..num_cols {
                trace_row[c] = base_at(t_row, c)?;
            }
            for c in 0..qcols {
                quot_row[c] = base_at(q_row, c)?;
            }
            let mask: [F; EXT_DEG] = quot_row[chunk_cols..].try_into().unwrap();
            vals.push(deep.eval(x, z, gz, &trace_row, &quot_row[..chunk_cols], mask));
            x = x * zeta[0];
        }
        let x0_inv = shift_inv[0] * omega_inv[0].pow(pos as u64);
        let mut folded = fold_leaf(&mut vals, x0_inv, zeta_inv[0], betas[0], two_inv);

        for j in 1..k {
            let leaves = 1usize << p.log_leaves(j);
            let (idx, slot) = (pos % leaves, pos / leaves);
            let leaf = r.take((1 << p.log_arities[j]) * E_BYTES)?;
            let path = r.digests((p.log_leaves(j) - p.cap_height_at(j)) as usize)?;
            if !verify_path(h, leaf, idx, &path, &fri_caps[j - 1]) {
                return Err(VerifyError::MerkleMismatch { layer: j });
            }
            vals = exts(leaf)?;
            if vals[slot] != folded {
                return Err(VerifyError::FoldMismatch { layer: j });
            }
            let x0_inv = shift_inv[j] * omega_inv[j].pow(idx as u64);
            folded = fold_leaf(&mut vals, x0_inv, zeta_inv[j], betas[j], two_inv);
            pos = idx;
        }

        let x = shift[k] * omega[k].pow(pos as u64);
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
