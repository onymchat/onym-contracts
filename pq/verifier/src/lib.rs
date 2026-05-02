//! Soroban-portable post-quantum FRI verifier shared by `pq/sep-*`
//! contracts.
//!
//! ## Status
//!
//! **Skeleton.** This crate compiles and exercises the verifier
//! shape end-to-end, but it is **not** yet sufficient to ship behind
//! a sep-* contract:
//!
//! 1. **No batched-PCS layer.** The on-chain `verify(...)` runs the
//!    FRI low-degree test alone — it attests "this prover committed
//!    to a polynomial of bounded degree" but does not check that
//!    polynomial against any AIR constraint system. A future
//!    `verifier_pcs` module will do the constraint-quotient batching
//!    on top of `fri::verify_fri`.
//!
//! 2. **No prover-side fixtures.** `plonk-verifier` ships
//!    `tests/fixtures/*.bin` produced by an off-chain prover whose
//!    test, run with `STELLAR_REGEN_FIXTURES=1`, double-acts as a
//!    drift detector. The PQ flavor has no analogous prover yet, so
//!    no `accepts_canonical_proof` test exists. `cargo test` covers
//!    field arithmetic, transcript determinism, Merkle path verify,
//!    proof/VK byte parsing, and `BadShape` / `BadVk` reject paths
//!    only.
//!
//! 3. **Software Poseidon2 fallback uses placeholder constants.**
//!    `host_poseidon2::permute` routes to the Soroban host primitive
//!    on-chain; off-chain test paths fall through to
//!    `poseidon2_software`, which has the right round shape but
//!    filler round constants. When the host primitive's SDK surface
//!    is finalised — the wrapper in `host_poseidon2.rs` is the only
//!    file that needs editing — the on-chain path becomes byte-
//!    equivalent to the Plonky3 prover; the software fallback can
//!    be replaced with the canonical Plonky3 BabyBear-W16 constants
//!    so that off-chain unit tests match prover-emitted bytes too.
//!
//! See `README.md` for the planned roadmap to closing all three.
//!
//! ## Layout
//!
//! ```text
//!   field            BabyBear (p = 2^31 - 2^27 + 1) prime field
//!   host_poseidon2   single point of contact with the Soroban
//!                    Poseidon2-W16 host primitive (one wrapper
//!                    function; falls through to a software
//!                    reference in non-wasm builds)
//!   poseidon2_software   off-chain reference for the host primitive
//!   transcript       Fiat-Shamir sponge (rate 8, capacity 8)
//!   merkle           binary Merkle authentication path verifier
//!                    (Poseidon2 2-to-1 compression)
//!   fri              FRI low-degree test (folding factor 2)
//!   vk_format        verifying-key byte parser
//!   proof_format     proof byte parser
//!   verifier         top-level `verify(env, vk, proof, pi)` glue
//! ```

#![no_std]

extern crate alloc;

pub mod field;
pub mod fri;
pub mod host_poseidon2;
pub mod merkle;
pub mod poseidon2_software;
pub mod proof_format;
pub mod transcript;
pub mod verifier;
pub mod vk_format;
