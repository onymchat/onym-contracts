//! Off-chain prover pipeline. Upstream stellar-mls also routes the
//! Groth16 setup/prove/verify flow through this module; this vendored
//! copy keeps only the plonk + srs sub-modules — the Groth16 pipeline
//! is not part of the contracts deliverable.

pub mod plonk;
pub mod srs;
