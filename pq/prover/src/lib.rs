//! Off-chain FRI prover for the `pq-sep-*` contract suite.
//!
//! ## Status: bench-only
//!
//! This prover produces FRI proofs that satisfy the on-chain
//! verifier's checks: Merkle paths reconstruct to the committed
//! roots, the fold equation holds at every queried position, and
//! the final-poly Horner evaluation matches the queried final-layer
//! values. Because the on-chain verifier today does NOT have a
//! batched-PCS layer (no AIR-constraint check at an out-of-domain
//! point), this prover does not need to encode any circuit witness
//! — it picks a random initial codeword, folds it deterministically,
//! and ships the resulting consistency proof. Real circuit-binding
//! security requires the PCS layer landing on top of `verify_fri`.
//!
//! Use this crate ONLY to measure on-chain gas cost. Do not deploy
//! a real `pq-sep-*` contract behind a verifier that has no PCS
//! layer in front of FRI.

#![allow(clippy::needless_range_loop)]

pub mod merkle_tree;
pub mod fri_prover;
pub mod proof_bytes;
pub mod params;

pub use fri_verifier::field::{Fr, P};
pub use fri_verifier::merkle::{Digest, DIGEST_LEN};
