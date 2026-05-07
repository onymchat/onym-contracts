//! Off-chain FRI prover for the `pq-sep-*` contract suite.
//!
//! ## Status: bench-only
//!
//! This prover produces BN254 FRI proofs that satisfy the on-chain
//! verifier's checks: Merkle paths reconstruct to the committed
//! roots, the fold equation holds at every queried position, and
//! the final-poly Horner evaluation matches the queried final-layer
//! values.
//!
//! All cryptography here is **production-grade primitives**:
//! - BN254 scalar field, native host arithmetic.
//! - Poseidon2 t=3 via Soroban Protocol 26 host primitive with the
//!   canonical Horizen Labs round constants vendored from the host's
//!   own validation tests.
//! - Sponge transcript (rate 2, capacity 1) and binary Merkle paths
//!   exactly as the verifier consumes them — byte-equivalent end to
//!   end.
//!
//! What's still not production:
//! - **No AIR layer.** The proofs are self-consistent but encode no
//!   circuit witness — a malicious caller can fabricate any
//!   `(commitment, epoch)` claim. Production deployment is gated on
//!   the batched-PCS verifier (`pq/verifier/src/verifier_pcs.rs`,
//!   forthcoming) landing on top of `verify_fri`.
//! - **Bench-scope FRI parameters.** log_n=6, num_layers=3,
//!   num_queries=8 → 8-bit soundness only. Production targets
//!   ~80 queries with log_n≥20.

#![allow(clippy::needless_range_loop)]

pub mod merkle_tree;
pub mod fri_prover;
pub mod proof_bytes;
pub mod params;

pub use fri_verifier::field::Fr;
pub use fri_verifier::merkle::Digest;
