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
  │                   pairings via Soroban host functions
  │                   ≈ 12M instructions per verification.
  │                   Path-dep'd by every sep-*.
  │
  ├── sep-anarchy/    ≤ 2¹¹ members, no admin. Any member
  │                   advances state — 1 membership π.
  │
  ├── sep-oneonone/   exactly 2 members, immutable post-
  │                   create. No update entrypoint.
  │
  ├── sep-democracy/  K-of-N member quorum (in-circuit goal).
  │                   Not shipping today — the threshold gate
  │                   is deferred until the K_MAX > 2 prover
  │                   work lands.
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
       │   2 BLS12-381 pairings via Soroban host functions    │
       │   ≈ 12M instructions per verification.               │
       └──────────────────────────┬───────────────────────────┘
                                  │
                                  │  consumed by ×5 sep-*
                                  ▼
                    sep-anarchy    (any member updates)
                    sep-oneonone   (immutable post-create)
                    sep-democracy  (K-of-N members — deferred)
                    sep-tyranny    (single pinned admin)
                    sep-oligarchy  (K-of-N admins, K ≤ 2)
```

## Where to look next

- **Capacity and TTL** — see the [Capacity and TTL](#capacity-and-ttl)
  section below for group-count limits, tier shapes, and inactivity
  thresholds across all five contract types.
- **Per-flavor walkthrough** — open `sep-*/README.md`. Each one
  walks through the create → update → verify lifecycle with
  ASCII Merkle diagrams and per-circuit public-input shapes.
- **Generating / regenerating proofs** — `prover/README.md`.
- **Reading the verifier** — `verifier/src/verifier.rs` is the
  `verify()` entry point; `verifier/src/transcript.rs` holds
  the Fiat-Shamir ordering; `verifier/src/vk_format.rs`
  documents the on-chain VK byte layout.

## Capacity and TTL

### Capacity by contract type

| Contract type | Create entrypoint        | Allowed tiers | Group limit per instance           | Counter in instance storage             |
|---------------|--------------------------|---------------|------------------------------------|-----------------------------------------|
| anarchy       | `create_group`           | 0, 1, 2       | 10,000 per tier ~ 30,000 total     | `GroupCount(tier)`                      |
| tyranny       | `create_group`           | 0, 1, 2       | 10,000 per tier ~ 30,000 total     | `GroupCount(tier)`                      |
| oligarchy     | `create_oligarchy_group` | 0, 1, 2       | 10,000 per tier ~ 30,000 total     | `GroupCount(member_tier)`               |
| democracy     | `create_group`           | 0, 1          | 10,000 per tier ~ 20,000 total     | `GroupCount(tier)`; tier 2 rejected     |
| oneonone      | `create_group`           | none (d=5)    | 10,000 total                       | `GroupCount` (no tier dimension)        |

Source constants: `MAX_GROUPS_PER_TIER = 10_000` in sep-anarchy,
sep-democracy, sep-oligarchy, sep-tyranny; `MAX_GROUPS = 10_000` in
sep-oneonone. `MAX_DEMOCRACY_QUORUM_TIER = 1` gates tier 2 in democracy.

### Tier shape / member capacity

| Tier | Tree depth | Nominal member slots | Applies to                                                           |
|------|------------|----------------------|----------------------------------------------------------------------|
| 0    | 5          | 32                   | anarchy, tyranny, oligarchy, democracy                               |
| 1    | 8          | 256                  | anarchy, tyranny, oligarchy, democracy                               |
| 2    | 11         | 2,048                | anarchy, tyranny, oligarchy; democracy membership VK present but create/update disabled |
| n/a  | 5 (fixed)  | 2 (exactly)          | oneonone 1v1 create semantics; positions 2..31 are structural zeros |

### Inactivity / TTL behavior

All TTL values are in ledgers; at a nominal 5-second ledger cadence
the threshold is ~1 day and the bump is ~30 days.

`LEDGER_THRESHOLD = 17_280`, `LEDGER_BUMP = 518_400` across all five
contract types.

| Storage item                  | TTL threshold | TTL bump    | Approx wall-clock at 5 s ledgers       | Refreshed by                                                              |
|-------------------------------|---------------|-------------|----------------------------------------|---------------------------------------------------------------------------|
| Group state                   | 17,280        | 518,400     | threshold ~1 day, bump ~30 days        | `create_group`, `update_commitment`, `bump_group_ttl`                     |
| Group history                 | 17,280        | 518,400     | threshold ~1 day, bump ~30 days        | `create_group`, `update_commitment`, `bump_group_ttl` (history-bearing types) |
| Tyranny admin commitment      | 17,280        | 518,400     | threshold ~1 day, bump ~30 days        | `create_group`, `update_commitment`, `bump_group_ttl`                     |
| Used-proof nullifier          | 17,280        | 518,400     | threshold ~1 day, bump ~30 days        | Successful state-changing proof recording only                            |

`HISTORY_WINDOW = 64` entries retained per group for history-bearing
contract types (anarchy, tyranny, oligarchy, democracy).

### Monotonic capacity - important caveat

The group-count limits are **monotonic**. There is no
`deactivate_group` / remove path that decrements `GroupCount(tier)` or
`GroupCount`, and TTL expiry does **not** decrement the instance
counter. The effective meaning of the limit is therefore *groups ever
created by this contract instance*, not *reusable live slots*.

A contract instance can become unable to create new groups even after
old group storage has expired, because the counter remains at its
maximum. Decide whether this is intended protocol policy or an
implementation artifact before wiring the relayer allowlist. If the
behaviour is intentional, document it in the public relayer docs; if
not, design an explicit cleanup/reclaim mechanism rather than relying
on TTL expiration alone.

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
