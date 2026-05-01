//! Off-chain TurboPlonk prover + per-tier VK baker + canonical-fixture
//! regen for the onym-contracts sep-* family.
//!
//! Vendored from `rinat-enikeev/stellar-mls` so onym-contracts is
//! self-contained. The two trees will drift until the upstream prover
//! split rewires stellar-mls's mobile clients to consume from here;
//! during that window, treat this crate as the canonical source for
//! circuit shape (VK SHAs are pinned anchor tests in
//! `circuit::plonk::baker`).
//!
//! Module hierarchy mirrors upstream verbatim (`circuit::plonk::*`,
//! `prover::{plonk, srs}`) so the source files copy across without
//! `use` rewrites.

pub mod circuit;
pub mod prover;
