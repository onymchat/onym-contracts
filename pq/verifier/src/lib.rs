//! Soroban-portable post-quantum FRI verifier shared by `pq/sep-*`
//! contracts.
//!
//! ## Status
//!
//! **Phase 1 (crypto primitives) complete; Phase 2 (AIR + batched-PCS
//! layer) outstanding.** The verifier today proves "the prover
//! committed to a low-degree polynomial via FRI" using the canonical
//! Soroban Poseidon2 host primitive over BN254. That is the
//! foundation for a production-grade STARK verifier on Soroban, but
//! it is **not by itself** a circuit-binding verifier — landing a
//! production contract behind it requires the batched-PCS layer that
//! ties FRI to an AIR (next phase).
//!
//! What's done:
//! - BN254 scalar field via `soroban_sdk::crypto::bn254::Fr` (host-
//!   accelerated `fr_add`/`mul`/`pow`/`inv`).
//! - Poseidon2 t=3 via `env.crypto().poseidon2_permutation` with the
//!   canonical Horizen Labs constants vendored from
//!   `soroban-env-host`'s own validation tests.
//! - Sponge transcript (rate=2, capacity=1).
//! - Binary Merkle path verifier (2-to-1 compression).
//! - FRI low-degree test (folding factor 2).
//!
//! What's outstanding (`pq/verifier_pcs.rs` follow-up):
//! - Batched polynomial commitment with out-of-domain opening at
//!   `zeta`, random-linear-combination of trace + quotient + aux
//!   openings, then dispatch to `verify_fri` on the combined
//!   polynomial.
//! - A real AIR for the membership / update circuits (Merkle-path-
//!   verify under Poseidon2-BN254-t3).
//! - Production FRI parameters (log_n ≥ 20, ~80 queries).
//! - Prover-side fixtures + drift-detector test (mirroring the PLONK
//!   flavor's `STELLAR_REGEN_FIXTURES` pattern).
//!
//! ## Layout
//!
//! ```text
//!   field             BN254 Fr facade over `soroban_sdk::crypto::bn254`
//!   poseidon2_params  canonical Horizen Labs t=3 round constants +
//!                     internal-diagonal matrix (vendored verbatim)
//!   host_poseidon2    `Poseidon2Ctx` cache + thin call into
//!                     `env.crypto().poseidon2_permutation`
//!   transcript        Fiat-Shamir sponge (rate=2, capacity=1)
//!   merkle            binary Merkle authentication path verifier
//!                     (2-to-1 compression via t=3 Poseidon2)
//!   fri               FRI low-degree test (folding factor 2)
//!   vk_format         verifying-key byte parser
//!   proof_format      proof byte parser
//!   verifier          top-level `verify(env, vk, proof, pi)` glue
//! ```

#![no_std]

extern crate alloc;

pub mod field;
pub mod fri;
pub mod host_poseidon2;
pub mod merkle;
pub mod poseidon2_params;
pub mod proof_format;
pub mod transcript;
pub mod verifier;
pub mod vk_format;
