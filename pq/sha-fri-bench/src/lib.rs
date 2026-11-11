//! Bench wrapper around `sha_fri::verifier::verify`.
//!
//! The only Soroban-specific piece is [`HostSha256`]: every hash the
//! verifier asks for becomes one `env.crypto().sha256` host call over
//! a single `Bytes` built from the concatenated parts. Field arithmetic
//! stays in WASM.

#![no_std]

extern crate alloc;

use alloc::vec::Vec;
use sha_fri::hash::{Digest, Hasher};
use soroban_sdk::{contract, contractimpl, Bytes, Env};

struct HostSha256<'a>(&'a Env);

impl Hasher for HostSha256<'_> {
    fn hash_parts(&self, parts: &[&[u8]]) -> Digest {
        // One guest-side concat + one Bytes object keeps it to two host
        // calls per hash instead of one per part.
        let mut buf = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
        for p in parts {
            buf.extend_from_slice(p);
        }
        self.0.crypto().sha256(&Bytes::from_slice(self.0, &buf)).to_array()
    }
}

#[contract]
pub struct ShaFriBench;

#[contractimpl]
impl ShaFriBench {
    /// `true` iff the proof verifies. Returns instead of panicking so
    /// the runner can bench rejection paths too.
    pub fn verify(env: Env, params: Bytes, proof: Bytes, public_inputs: Bytes) -> bool {
        let params = params.to_alloc_vec();
        let proof = proof.to_alloc_vec();
        let public_inputs = public_inputs.to_alloc_vec();
        sha_fri::verifier::verify(&HostSha256(&env), &params, &proof, &public_inputs).is_ok()
    }
}
