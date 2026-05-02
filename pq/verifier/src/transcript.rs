//! Fiat-Shamir transcript built on a Poseidon2-W16 sponge.
//!
//! ## Construction
//!
//! Standard duplex sponge: state width 16 lanes, rate 8, capacity 8.
//! Absorption appends `Fr` elements into the rate region; once the
//! rate is full we permute. Squeezing reads `Fr` elements out of the
//! rate region; once exhausted we permute again. A pending bit
//! (`absorb_pos == 0` after the last permutation, or `squeeze_pos`
//! tracking unread output) tracks which mode we are in.
//!
//! Domain-separation between sections of the proof (commitments,
//! evaluations, FRI layers) is implemented by clients calling
//! `observe_label(env, &[label_bytes])` at section boundaries — the
//! label is absorbed as a sequence of `Fr` elements (4 bytes packed
//! per element, padded with `0x80` then zero bytes — a HMAC-style
//! end-of-block marker).
//!
//! ## Why sponge over hash-then-feedback
//!
//! A hash-and-update transcript needs WIDTH^2 host calls to absorb a
//! large stream; a duplex sponge does it in one host call per RATE
//! elements absorbed. For FRI verifiers that absorb hundreds of
//! commitments and evaluations, this is the difference between
//! ~hundreds of `permute` calls and ~thousands.

use crate::field::Fr;
use crate::host_poseidon2::{permute, WIDTH};
use soroban_sdk::Env;

/// Sponge rate. Half the width — standard for Poseidon2 sponge use.
pub const RATE: usize = 8;
/// Sponge capacity. The other half. Determines the security parameter
/// (≈ capacity * log2(p) bits = 8 * 31 = 248 bits ≥ 128-bit security).
pub const CAPACITY: usize = WIDTH - RATE;

/// Stateful Fiat-Shamir transcript. Construct fresh per-proof; do not
/// reuse across proofs.
pub struct Transcript {
    state: [Fr; WIDTH],
    /// Number of `Fr` elements written into the rate region since the
    /// last permutation. Range `[0, RATE]`.
    absorb_pos: usize,
    /// Number of `Fr` elements still unread in the rate region after
    /// the last permutation. Range `[0, RATE]`. When non-zero, we are
    /// in squeeze mode and must permute before any further absorb.
    squeeze_avail: usize,
}

impl Transcript {
    /// Initialize with a domain separator absorbed first. Two
    /// transcripts with different labels diverge after one permutation,
    /// so distinct circuits / proof systems cannot be confused even if
    /// the prover-side absorbs are otherwise byte-identical.
    pub fn new(env: &Env, label: &[u8]) -> Self {
        let mut t = Transcript {
            state: [Fr::ZERO; WIDTH],
            absorb_pos: 0,
            squeeze_avail: 0,
        };
        t.observe_bytes(env, label);
        t
    }

    /// Absorb a single field element.
    pub fn observe(&mut self, env: &Env, x: Fr) {
        if self.squeeze_avail != 0 {
            // Switching from squeeze back to absorb — permute to
            // separate the two modes.
            self.flush(env);
        }
        self.state[self.absorb_pos] += x;
        self.absorb_pos += 1;
        if self.absorb_pos == RATE {
            permute(env, &mut self.state);
            self.absorb_pos = 0;
        }
    }

    /// Absorb a byte string. Bytes are packed 4-per-element little-
    /// endian into BabyBear `Fr`s. The final partial element gets a
    /// `0x80` end marker followed by zero padding (HMAC-style; ensures
    /// "abc" and "abc\0" produce different transcripts).
    pub fn observe_bytes(&mut self, env: &Env, bytes: &[u8]) {
        let chunks = bytes.chunks_exact(4);
        let rem_len = bytes.len() - chunks.len() * 4;
        let rem_start = chunks.len() * 4;
        for c in chunks {
            // Each 4-byte chunk fits in `[0, 2^32)`. Reduce mod P.
            let v = u32::from_le_bytes([c[0], c[1], c[2], c[3]]) % crate::field::P;
            self.observe(env, Fr(v));
        }
        // Final element: pack remaining bytes + 0x80 sentinel + zeros.
        let mut tail = [0u8; 4];
        for i in 0..rem_len {
            tail[i] = bytes[rem_start + i];
        }
        tail[rem_len] = 0x80;
        let v = u32::from_le_bytes(tail) % crate::field::P;
        self.observe(env, Fr(v));
    }

    /// Absorb a slice of field elements.
    pub fn observe_slice(&mut self, env: &Env, xs: &[Fr]) {
        for x in xs.iter() {
            self.observe(env, *x);
        }
    }

    /// Squeeze a single challenge field element.
    pub fn challenge(&mut self, env: &Env) -> Fr {
        if self.squeeze_avail == 0 {
            self.flush(env);
            self.squeeze_avail = RATE;
        }
        let idx = RATE - self.squeeze_avail;
        let out = self.state[idx];
        self.squeeze_avail -= 1;
        out
    }

    /// Squeeze a non-zero challenge. Re-squeezes on the (cryptographi-
    /// cally negligible) zero output. FRI folding multiplies cosets by
    /// the challenge so a zero would collapse the test.
    pub fn challenge_nonzero(&mut self, env: &Env) -> Fr {
        loop {
            let c = self.challenge(env);
            if c.0 != 0 {
                return c;
            }
        }
    }

    /// Squeeze a `usize` index in `[0, n)` by reading one challenge
    /// `Fr` and reducing mod `n`. `n` must be small enough that `Fr`
    /// is statistically uniform (n ≤ 2^16 keeps the bias at < 2^-15
    /// of full security; FRI query indices satisfy this for any
    /// reasonable trace length).
    pub fn challenge_index(&mut self, env: &Env, n: usize) -> usize {
        debug_assert!(n > 0, "challenge_index n must be positive");
        let c = self.challenge(env);
        (c.0 as usize) % n
    }

    /// Force the absorb buffer through the permutation, so subsequent
    /// squeezes / observes can't see uncommitted lanes.
    fn flush(&mut self, env: &Env) {
        if self.absorb_pos != 0 {
            // Domain-separation byte at the boundary: bump the next
            // capacity lane so a transcript that absorbed exactly RATE
            // and one that absorbed RATE+padding can never collide.
            self.state[RATE + (self.absorb_pos - 1) % CAPACITY] += Fr::ONE;
            self.absorb_pos = 0;
        }
        permute(env, &mut self.state);
        self.squeeze_avail = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn distinct_labels_diverge() {
        let env = Env::default();
        let mut a = Transcript::new(&env, b"label-A");
        let mut b = Transcript::new(&env, b"label-B");
        let ca = a.challenge(&env);
        let cb = b.challenge(&env);
        assert_ne!(ca, cb);
    }

    #[test]
    fn same_label_same_inputs_same_challenges() {
        let env = Env::default();
        let mut a = Transcript::new(&env, b"x");
        let mut b = Transcript::new(&env, b"x");
        for i in 0..20 {
            a.observe(&env, Fr::new(i));
            b.observe(&env, Fr::new(i));
        }
        for _ in 0..5 {
            assert_eq!(a.challenge(&env), b.challenge(&env));
        }
    }

    #[test]
    fn observe_then_challenge_changes_with_input() {
        let env = Env::default();
        let mut a = Transcript::new(&env, b"x");
        let mut b = Transcript::new(&env, b"x");
        a.observe(&env, Fr::new(1));
        b.observe(&env, Fr::new(2));
        assert_ne!(a.challenge(&env), b.challenge(&env));
    }

    /// Sponge mode-switching: absorb after squeeze must NOT see a
    /// stale rate region. If the implementation forgot to flush on
    /// mode switch, two transcripts that diverged in absorb order
    /// would still collapse to the same challenge.
    #[test]
    fn absorb_after_squeeze_flushes() {
        let env = Env::default();
        let mut a = Transcript::new(&env, b"l");
        let mut b = Transcript::new(&env, b"l");
        a.observe(&env, Fr::new(1));
        let _ = a.challenge(&env);
        a.observe(&env, Fr::new(2));

        b.observe(&env, Fr::new(1));
        let _ = b.challenge(&env);
        b.observe(&env, Fr::new(99));

        assert_ne!(a.challenge(&env), b.challenge(&env));
    }

    #[test]
    fn challenge_nonzero_never_returns_zero() {
        let env = Env::default();
        let mut t = Transcript::new(&env, b"nonzero");
        for _ in 0..256 {
            let c = t.challenge_nonzero(&env);
            assert_ne!(c.0, 0);
        }
    }
}
