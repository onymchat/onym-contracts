//! Shared Soroban interface types for onym.chat governance contracts.
//!
//! ## Why this crate exists
//!
//! Each governance contract (`sep-anarchy`, `sep-democracy`, `sep-oligarchy`,
//! `sep-oneonone`, `sep-tyranny`) ships in **multiple verifier flavors** —
//! today only `plonk/`, eventually a `pq/` flavor (post-quantum, e.g. STARK
//! or lattice-based) and an `ffi/` flavor for whatever the next-gen proving
//! system turns out to be.
//!
//! The contract entrypoint signatures (`create_*_group`, `update_commitment`,
//! `verify_membership`, `set_restricted_mode`, `bump_group_ttl`) are
//! verifier-agnostic: they all take an opaque proof bytes blob + a `Vec` of
//! public-input scalars and return the same `Result<_, Error>`. Only the
//! proof-bytes width and the VK encoding differ across flavors.
//!
//! This crate is the schelling point for that shared interface — Error
//! variants, storage shapes, and (eventually) trait signatures that every
//! flavor's contract crate implements.
//!
//! ## Status
//!
//! **Placeholder for the initial migration.** The five contracts in
//! `plonk/` ship their own `Error` enums today; this crate is a stub
//! reserved for the refactor that consolidates them. PQ / FFI flavors
//! landing later are expected to populate this crate first.
//!
//! ## What goes here
//!
//! - `Error` — a superset of every flavor's error variants, with reserved
//!   slots so adding a flavor doesn't shift the discriminants.
//! - `CommitmentEntry` — storage-layout type for `Group(group_id)`.
//! - `DataKey` — storage-key enum.
//! - `Sep<G: GroupShape>` — Soroban trait wrapping the entrypoint
//!   signatures. Generic over the per-contract group shape (anarchy has
//!   no admin, oligarchy has K-of-N, etc).
//!
//! All of the above are TBD; this stub exists so the directory layout is
//! in place when the next flavor lands.

#![no_std]
