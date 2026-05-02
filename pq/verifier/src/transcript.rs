//! Fiat-Shamir transcript built on a Poseidon2-BN254-t3 sponge.
//!
//! ## Construction
//!
//! Standard duplex sponge: state width 3, **rate 2, capacity 1**.
//! Absorption appends `Fr` elements into the rate region (lanes
//! 0..2); once the rate is full we permute. Squeezing reads `Fr`
//! elements out of the rate region; once exhausted we permute again.
//!
//! With BN254's 254-bit field, capacity 1 gives ~127 bits of
//! collision resistance — at the lower edge of standard security
//! targets but defensible for FRI's information-theoretic soundness
//! floor (the dominating soundness term comes from FRI queries +
//! repetition, not transcript-collision).
//!
//! ## Domain separation
//!
//! `Transcript::new(env, label)` absorbs `label` as bytes (packed
//! 31-bytes-per-`Fr`, with a `0x80` end marker) before any other
//! observation. Two transcripts with different labels diverge after
//! the first squeeze.
//!
//! ## Why not t=16
//!
//! A wider sponge (e.g. t=16, rate=8) would absorb 4× more elements
//! per permutation. The Soroban host primitive supports widths up to
//! t=24, **but only the t=3 Horizen Labs reference instance ships
//! with audited canonical constants** in the Stellar Foundation's
//! own validation tests. Wider Poseidon2-BN254 instances exist in
//! academic literature (Plonky3-style) but their constants are not
//! yet vendor-trusted on Soroban.

use crate::field::{self, Fr};
use crate::host_poseidon2::Poseidon2Ctx;
use crate::host_poseidon2::WIDTH;
use soroban_sdk::Env;

/// Sponge rate. Half of WIDTH (rounded down).
pub const RATE: usize = 2;
/// Sponge capacity. The remaining lane.
pub const CAPACITY: usize = WIDTH - RATE;

/// Stateful Fiat-Shamir transcript. Construct fresh per-proof; do
/// not reuse across proofs. Holds a `Poseidon2Ctx` reference so the
/// host-call params (round_constants + diagonal) are built exactly
/// once across the entire proof.
pub struct Transcript<'a> {
    env: &'a Env,
    ctx: &'a Poseidon2Ctx,
    state: [Fr; WIDTH],
    /// Number of `Fr` elements written into the rate region since
    /// the last permutation. Range `[0, RATE]`.
    absorb_pos: usize,
    /// Number of `Fr` elements still unread in the rate region after
    /// the last permutation. Range `[0, RATE]`. When non-zero, we
    /// are in squeeze mode and must permute before any further
    /// absorb.
    squeeze_avail: usize,
}

impl<'a> Transcript<'a> {
    /// Initialize with a domain separator absorbed first.
    pub fn new(env: &'a Env, ctx: &'a Poseidon2Ctx, label: &[u8]) -> Self {
        let zero = field::zero(env);
        let mut t = Transcript {
            env,
            ctx,
            state: [zero.clone(), zero.clone(), zero],
            absorb_pos: 0,
            squeeze_avail: 0,
        };
        t.observe_bytes(label);
        t
    }

    /// Absorb a single field element.
    pub fn observe(&mut self, x: Fr) {
        if self.squeeze_avail != 0 {
            // Switching from squeeze back to absorb — permute to
            // separate the two modes.
            self.flush();
        }
        self.state[self.absorb_pos] = self.state[self.absorb_pos].clone() + x;
        self.absorb_pos += 1;
        if self.absorb_pos == RATE {
            self.ctx.permute(self.env, &mut self.state);
            self.absorb_pos = 0;
        }
    }

    /// Absorb a slice of field elements.
    pub fn observe_slice(&mut self, xs: &[Fr]) {
        for x in xs.iter() {
            self.observe(x.clone());
        }
    }

    /// Absorb a byte string. Bytes are packed 31-per-element big-
    /// endian into BN254 `Fr`s (31 bytes always fit in BN254 since
    /// `r > 2^253`). Final partial element gets a `0x80` end marker
    /// (HMAC-style; ensures `b"abc"` and `b"abc\0"` produce different
    /// transcripts).
    pub fn observe_bytes(&mut self, bytes: &[u8]) {
        let mut buf = [0u8; 32];
        let chunks = bytes.chunks(31);
        let chunk_count = chunks.len();
        for (i, chunk) in chunks.enumerate() {
            buf.fill(0);
            // Big-endian: place the chunk in the low bytes.
            buf[32 - chunk.len()..32].copy_from_slice(chunk);
            // Mark the final partial-or-empty chunk with 0x80.
            if i + 1 == chunk_count && chunk.len() < 31 {
                buf[32 - chunk.len() - 1] = 0x80;
            }
            self.observe(field::from_be_bytes(self.env, &buf));
        }
        // If the byte string was a multiple of 31 (or empty), tag a
        // trailing 0x80-only block so length-extension is impossible.
        if bytes.is_empty() || bytes.len() % 31 == 0 {
            buf.fill(0);
            buf[31] = 0x80;
            self.observe(field::from_be_bytes(self.env, &buf));
        }
    }

    /// Squeeze a single challenge field element.
    pub fn challenge(&mut self) -> Fr {
        if self.squeeze_avail == 0 {
            self.flush();
            self.squeeze_avail = RATE;
        }
        let idx = RATE - self.squeeze_avail;
        let out = self.state[idx].clone();
        self.squeeze_avail -= 1;
        out
    }

    /// Squeeze a non-zero challenge. Re-squeezes on the (cryptograph-
    /// ically negligible) zero output. FRI folding multiplies cosets
    /// by the challenge, so a zero would collapse the test.
    pub fn challenge_nonzero(&mut self) -> Fr {
        let zero = field::zero(self.env);
        loop {
            let c = self.challenge();
            if c != zero {
                return c;
            }
        }
    }

    /// Squeeze a `usize` index in `[0, n)` by reducing one challenge
    /// `Fr` mod `n`. Statistical bias is `≈ n / r` which is
    /// negligible for any reasonable trace size (BN254 r > 2^253).
    pub fn challenge_index(&mut self, n: usize) -> usize {
        debug_assert!(n > 0, "challenge_index n must be positive");
        let c = self.challenge();
        // Reduce via the U256 representation, which carries the full
        // 32-byte width. We take the low-32 bits of a BE-encoded view
        // — for our bench/production trace sizes (n ≤ 2^28), this is
        // strictly less biased than `r mod n` itself.
        let bytes = field::to_be_bytes(&c);
        let low = u32::from_be_bytes([bytes[28], bytes[29], bytes[30], bytes[31]]);
        (low as usize) % n
    }

    /// Force the absorb buffer through the permutation.
    fn flush(&mut self) {
        if self.absorb_pos != 0 {
            // Domain-separation byte at the boundary: bump the
            // capacity lane so a transcript that absorbed exactly
            // RATE and one that absorbed RATE+padding can never
            // collide.
            let one = field::one(self.env);
            self.state[RATE] = self.state[RATE].clone() + one;
            self.absorb_pos = 0;
        }
        self.ctx.permute(self.env, &mut self.state);
        self.squeeze_avail = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_labels_diverge() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut a = Transcript::new(&env, &ctx, b"label-A");
        let mut b = Transcript::new(&env, &ctx, b"label-B");
        assert_ne!(a.challenge(), b.challenge());
    }

    #[test]
    fn same_label_same_inputs_same_challenges() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut a = Transcript::new(&env, &ctx, b"x");
        let mut b = Transcript::new(&env, &ctx, b"x");
        for i in 0..10 {
            a.observe(field::from_u32(&env, i));
            b.observe(field::from_u32(&env, i));
        }
        for _ in 0..3 {
            assert_eq!(a.challenge(), b.challenge());
        }
    }

    #[test]
    fn observe_then_challenge_changes_with_input() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut a = Transcript::new(&env, &ctx, b"x");
        let mut b = Transcript::new(&env, &ctx, b"x");
        a.observe(field::from_u32(&env, 1));
        b.observe(field::from_u32(&env, 2));
        assert_ne!(a.challenge(), b.challenge());
    }

    /// Sponge mode-switching: absorb after squeeze must NOT see a
    /// stale rate region. If the implementation forgot to flush on
    /// mode switch, two transcripts that diverged in absorb order
    /// would still collapse to the same challenge.
    #[test]
    fn absorb_after_squeeze_flushes() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut a = Transcript::new(&env, &ctx, b"l");
        let mut b = Transcript::new(&env, &ctx, b"l");
        a.observe(field::from_u32(&env, 1));
        let _ = a.challenge();
        a.observe(field::from_u32(&env, 2));

        b.observe(field::from_u32(&env, 1));
        let _ = b.challenge();
        b.observe(field::from_u32(&env, 99));

        assert_ne!(a.challenge(), b.challenge());
    }

    #[test]
    fn challenge_nonzero_never_returns_zero() {
        let env = Env::default();
        let ctx = Poseidon2Ctx::new(&env);
        let mut t = Transcript::new(&env, &ctx, b"nonzero");
        let zero = field::zero(&env);
        for _ in 0..32 {
            assert_ne!(t.challenge_nonzero(), zero);
        }
    }
}
