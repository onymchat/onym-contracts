# `plonk/`

TurboPlonk + BLS12-381 + EF KZG 2023 SRS for the onym-contracts
sep-* family. The off-chain prover bakes verifying keys and
generates proofs; the on-chain verifier crate runs them inside
Soroban; the five sep-* contracts are the deployable WASMs that
wire it all together.

```
                       LAYOUT
                       ══════

  plonk/
  │
  ├── prover/         off-chain TurboPlonk prover + per-tier
  │                   VK baker + canonical-fixture regen.
  │                   Vendored from rinat-enikeev/stellar-mls.
  │                   Bakes the VK bytes the verifier consumes
  │                   and produces the canonical π + PI
  │                   fixtures that ship under verifier/.
  │
  ├── verifier/       on-chain verifier crate. #![no_std],
  │                   targets wasm32v1-none. 2 BLS12-381
  │                   pairings in a single pairing_check
  │                   host call per verification.
  │                   Path-dep'd by every sep-*.
  │
  ├── sep-anarchy/    ≤ 2¹¹ members, no group admin. Any
  │                   member advances state — 1 membership π.
  │
  ├── sep-oneonone/   exactly 2 members, immutable post-
  │                   create. No update entrypoint.
  │
  ├── sep-democracy/  K-of-N member quorum, enforced
  │                   in-circuit (K ≤ 2 today; K_MAX raises,
  │                   ratio thresholds, and tier-2 writes
  │                   are deferred).
  │
  ├── sep-tyranny/    single pinned admin per group. Cross-
  │                   group unlinkability via fresh group_id.
  │                   1 admin π per update.
  │
  └── sep-oligarchy/  K-of-N admin quorum (K ≤ 2 today; K_MAX
                      raises planned). Separate hidden admin
                      tree; admins distinct from members. At
                      threshold = 2 this is a multi-admin
                      co-sign — not "any single admin updates
                      the tree".
```

Every sep-* contract additionally stores a deployment-time
**operator admin** (constructor argument) whose only capability is
`set_restricted_mode` — gating group *creation* to the operator.
The operator can never advance or modify existing group state.
See each contract's README for details.

```
                       PIPELINE
                       ════════

       ┌──────────────────────────────────────────────────────┐
       │                  prover/  (off-chain)                │
       │                                                      │
       │   * VK baker             →  per-tier VK bytes        │
       │   * gen_membership_proof →  membership π             │
       │   * gen_update_proof     →  state-advance π          │
       └──────────────────────────┬───────────────────────────┘
                                  │
                       π + PI vector + VK bytes
                                  │
                                  ▼
       ┌──────────────────────────────────────────────────────┐
       │                  verifier/  (on-chain)               │
       │                                                      │
       │   #![no_std], wasm32v1-none.                         │
       │   2 BLS12-381 pairings via a single Soroban          │
       │   pairing_check host call per verification.          │
       └──────────────────────────┬───────────────────────────┘
                                  │
                                  │  consumed by ×5 sep-*
                                  ▼
                    sep-anarchy    (any member updates)
                    sep-oneonone   (immutable post-create)
                    sep-democracy  (K-of-N members, K ≤ 2)
                    sep-tyranny    (single pinned admin)
                    sep-oligarchy  (K-of-N admins, K ≤ 2)
```

## Where to look next

- **Per-flavor walkthrough** — open `sep-*/README.md`. Each one
  walks through the create → update → verify lifecycle with
  ASCII Merkle diagrams and per-circuit public-input shapes.
- **Generating / regenerating proofs** — `prover/README.md`.
- **Reading the verifier** — `verifier/src/verifier.rs` is the
  `verify()` entry point; `verifier/src/verifier_challenges.rs`
  holds the Fiat-Shamir challenge schedule (`transcript.rs` is
  the underlying transcript primitive); `verifier/src/vk_format.rs`
  documents the on-chain VK byte layout.

## Drift control

Per-tier VK SHA-256 anchors are pinned in
`prover/src/circuit/plonk/baker.rs`. The assert-mode test
`plonk_verifier_fixtures_match_or_regenerate` re-bakes and
byte-compares against the committed `.bin` fixtures under
`verifier/tests/fixtures/`. CI runs this on every PR
([`.github/workflows/pr.yml`](../.github/workflows/pr.yml)),
so prover-side drift fails the build before it merges.

For broader context — release flow, family table, provenance —
see the [repo root README](../README.md).
