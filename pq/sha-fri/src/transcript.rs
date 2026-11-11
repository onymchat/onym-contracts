//! SHA-256 Fiat–Shamir transcript.
//!
//! `observe` buffers bytes; `squeeze` sets
//! `state = SHA256(state ‖ buffered)` and returns it. Each challenge
//! costs exactly one hash, and consecutive squeezes chain.

use crate::field::{E, F};
use crate::hash::{Digest, Hasher};
use alloc::vec::Vec;

pub struct Transcript<'a, H: Hasher> {
    h: &'a H,
    state: Digest,
    buf: Vec<u8>,
}

impl<'a, H: Hasher> Clone for Transcript<'a, H> {
    fn clone(&self) -> Self {
        Transcript { h: self.h, state: self.state, buf: self.buf.clone() }
    }
}

impl<'a, H: Hasher> Transcript<'a, H> {
    pub fn new(h: &'a H, label: &[u8]) -> Self {
        let state = h.hash_parts(&[b"onym-sha-fri/init", label]);
        Transcript { h, state, buf: Vec::new() }
    }

    pub fn observe(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn squeeze(&mut self) -> Digest {
        self.state = self.h.hash_parts(&[&self.state, &self.buf]);
        self.buf.clear();
        self.state
    }

    /// Four 64-bit chunks, each reduced mod p. The reduction bias is
    /// ~2⁻³³ per coefficient: negligible.
    pub fn challenge_ext(&mut self) -> E {
        // 4 coefficients per squeeze (32 bytes = 4 × u64).
        let mut out = E::ZERO;
        let mut d = [0u8; 32];
        for i in 0..crate::field::EXT_DEG {
            if i % 4 == 0 {
                d = self.squeeze();
            }
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&d[8 * (i % 4)..8 * (i % 4) + 8]);
            out.0[i] = F::from_u64(u64::from_le_bytes(chunk));
        }
        out
    }

    /// Uniform index in `[0, 2^bits)`.
    pub fn challenge_index(&mut self, bits: u32) -> usize {
        let d = self.squeeze();
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&d[..8]);
        let mask = if bits >= 64 { u64::MAX } else { (1u64 << bits) - 1 };
        (u64::from_le_bytes(chunk) & mask) as usize
    }

    /// Absorb `nonce` and accept iff the next state has `bits` leading
    /// zero bits. One hash for the verifier, ~2^bits for the prover;
    /// each grinding bit buys one bit of soundness without queries.
    pub fn check_pow(&mut self, nonce: u64, bits: u32) -> bool {
        self.observe(&nonce.to_le_bytes());
        let d = self.squeeze();
        let mut head = [0u8; 8];
        head.copy_from_slice(&d[..8]);
        u64::from_be_bytes(head).leading_zeros() >= bits
    }
}
