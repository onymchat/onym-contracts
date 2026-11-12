//! Post-quantum zero-knowledge STARK verifier (and prover) for Soroban.
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
//! - **Statement**: the membership AIR in [`air`], the PQ analogue of
//!   the PLONK `MembershipCircuit` (key ownership, private-root Merkle
//!   opening, epoch + salt commitment), over Poseidon2-BabyBear-16 with
//!   one trace row per round.
//! - **Proof system**: DEEP-ALI over a committed trace and quotient
//!   (SHA-256 Merkle trees with caps and salted leaves), FRI with
//!   per-layer folding arity, PoW grinding.
//! - **Zero-knowledge**: masked trace columns, telescoping quotient-chunk
//!   randomizers, a random FRI mask polynomial and salted leaves (see
//!   [`prover`]).
//!
//! ## Primitives
//!
//! - Poseidon2 is Plonky3's canonical BabyBear-16 instance, checked bit
//!   for bit against `p3-baby-bear` (`poseidon2::tests::matches_plonky3`).
//! - Prover randomness is ChaCha20 seeded from OS entropy, with
//!   exactly-uniform field sampling (see [`prover`]).
//!
//! ## Open items
//!
//! - Security figures come from `Params::{conjectured,johnson,pq}_security_bits`,
//!   which are standard estimates, not a formal soundness proof for this
//!   exact construction.
//! - No external audit. Verified on-chain by `pq/sep-anarchy` and
//!   `pq/sep-tyranny`.

#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod field;
pub mod fold;
pub mod hash;
pub mod air;
pub mod merkle;
pub mod params;
pub mod poly;
pub mod poseidon2;
pub mod poseidon2_constants;
pub mod transcript;
pub mod verifier;

#[cfg(feature = "prover")]
pub mod prover;
