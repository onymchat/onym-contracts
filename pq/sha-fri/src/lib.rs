//! Prototype post-quantum FRI verifier for Soroban.
//!
//! ## Why this crate exists
//!
//! `pq/verifier` routes every Merkle compression and transcript step
//! through the BN254 Poseidon2 host primitive. Measured under the
//! soroban-sdk 26 budget model, one t=3 permutation costs ~707K CPU
//! instructions, while one SHA-256 of 64 bytes costs ~8.4K: ~84×
//! cheaper. A STARK verifier's commitments don't need an arithmetic-
//! friendly hash (that only matters for recursion), so this crate
//! swaps the hash and the field:
//!
//! - **Field**: BabyBear (p = 15·2²⁷ + 1) in plain `u32`/`u64` WASM
//!   arithmetic, with a degree-4 binomial extension for challenges.
//!   No host objects per field element.
//! - **Hash**: SHA-256 for Merkle trees and Fiat–Shamir, via the
//!   [`hash::Hasher`] trait (host fn on-chain, `sha2` off-chain).
//! - **PCS shape**: a committed W-column trace opened via a DEEP
//!   quotient at an out-of-domain point, then FRI with configurable
//!   per-layer folding arity, Merkle caps, and PoW grinding.
//!
//! ## What is NOT here (prototype scope)
//!
//! - No AIR constraint evaluation at `z`. The verifier checks the
//!   claimed OOD values are consistent with the committed trace, but
//!   not that they satisfy any circuit. Constraint evaluation is pure
//!   extension-field arithmetic at one point, so it adds CPU but no
//!   hashing and only a few OOD values to the proof.
//! - Only one OOD point (`z`); a real AIR also opens at `z·g`.
//! - No Merkle multi-proof de-duplication across queries.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod field;
pub mod fold;
pub mod hash;
pub mod merkle;
pub mod params;
pub mod transcript;
pub mod verifier;

#[cfg(feature = "prover")]
pub mod prover;
