//! TurboPlonk-flavoured circuits + gadgets, built on `jf-relation` over
//! `arkworks` 0.5.
//!
//! Vendored from `rinat-enikeev/stellar-mls`. The upstream
//! `feature = "plonk"` gate is dropped here — this crate is plonk-only.

pub mod poseidon;
pub mod merkle;
pub mod democracy;
pub mod membership;
pub mod oligarchy;
pub mod oneonone_create;
pub mod tyranny;
pub mod update;
pub mod proof_format;
pub mod vk_format;
pub mod baker;
pub mod transcript;
pub mod verifier_challenges;
pub mod verifier_polys;
pub mod verifier_lin_poly;
pub mod verifier_aggregate;
pub mod verifier_aggregate_evals;
pub mod verifier;

#[cfg(test)]
mod test_vectors;
