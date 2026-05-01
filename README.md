# onym-contracts

Family of per-governance-type Soroban smart contracts for onym.chat —
**five flavors of group state**, sharing the same Soroban call shape across
verifier-flavor sub-trees so client code can target any contract address
without branching on the underlying SNARK.

```
                       FAMILY  —  pick by who can update
                       ═════════════════════════════════════════════════

  contract        members  admins   who can advance state?    auth shape
  ───────────     ───────  ───────  ──────────────────────    ───────────
  sep-anarchy     ≤ 2¹¹    none     any group member          1 membership π
  sep-oneonone    exactly  none     nobody — immutable        (no update)
                  2
  sep-democracy   ≤ 2¹¹    no       K-of-N admin quorum,      K admin πs
                           separate hidden member counts;     batched in 1 π
                           tier     count delta only
  sep-oligarchy   ≤ 2¹¹    ≤ 32     K-of-N admin quorum,      K admin πs
                                    hidden member + admin     batched in 1 π
                                    counts; admin tree
                                    fully hidden post-create
  sep-tyranny     ≤ 2¹¹    1        single pinned admin       single admin π
                           (fixed)  with cross-group
                                    unlinkability
```

```
                       FLAVOR MODEL
                       ════════════

  Each flavor is an independent Soroban contract suite — different
  addresses on-chain, different proof shapes, different VK bytes.
  Group state does NOT migrate across flavors; flavor is a deployment-
  time choice. The `traits/` crate keeps the public Soroban call shape
  uniform so clients don't branch on it.

         ┌─────────────────────────────────────────────────┐
         │   traits/    shared Error / DataKey /           │
         │              entrypoint signatures              │
         └────────────────────┬────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              │               │               │
              ▼               ▼               ▼
     ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
     │   plonk/     │ │     pq/      │ │    ffi/      │
     │              │ │              │ │              │
     │  TurboPlonk  │ │ post-quantum │ │  alternative │
     │  + BLS12-381 │ │ (planned —   │ │  SNARK       │
     │  + EF KZG    │ │  STARK or    │ │  (planned)   │
     │    2023 SRS  │ │  lattice-    │ │              │
     │    n=32 768  │ │  based)      │ │              │
     │              │ │              │ │              │
     │  ┌─────────┐ │ │              │ │              │
     │  │ prover  │ │ │              │ │              │
     │  └────┬────┘ │ │              │ │              │
     │       │ bake │ │              │ │              │
     │       ▼      │ │              │ │              │
     │  ┌─────────┐ │ │              │ │              │
     │  │verifier │ │ │              │ │              │
     │  └────┬────┘ │ │              │ │              │
     │       │ ×5   │ │              │ │              │
     │  ┌────┴────┐ │ │              │ │              │
     │  │ sep-*   │ │ │              │ │              │
     │  │ (5)     │ │ │              │ │              │
     │  └─────────┘ │ │              │ │              │
     └──────────────┘ └──────────────┘ └──────────────┘
        TODAY            PLANNED          PLANNED
```

```
                       RELEASE FLOW
                       ════════════

      git tag v*.*.*                          Stellar testnet
              │                              ┌──────────────┐
              ▼                              │              │
      ┌─────────────────────┐                │   live RPC   │
      │  .github/workflows/ │                │              │
      │  release.yml        │                └──────┬───────┘
      └──────┬──────────────┘                       │
             │                                      │ (deploy +
   ┌─────────┴─────────────┐                        │  invoke
   │                       │                        │  per op)
   │ 5 × build (parallel)  │                        │
   │   stellar-expert/     │                        │
   │   soroban-build-      │                        │
   │   workflow            │                        │
   │   ↓                   │                        │
   │ source-attested       │                        │
   │ WASMs registered      │                        │
   │ under home_domain     │                        │
   │ 'onym.chat' →         │                        │
   │ stellar.expert        │                        │
   │ contract pages link   │                        │
   │ back to this tag      │                        │
   │                       │                        │
   └────────┬──────────────┘                        │
            │ (needs: all 5)                        │
            ▼                                       │
   ┌─────────────────────────────────────┐          │
   │ bench-gas job                       │          │
   │   scripts/bench-gas/run.sh ────────────────────┘
   │   ↓
   │   per-op fees (real WASM, captured  │
   │   from `stellar tx fetch fee`)      │
   │   ↓                                 │
   │   render → markdown table           │
   │   ↓                                 │
   │   overwrite GitHub release body     │
   └─────────────────────────────────────┘
              │
              ▼
       Release page carries:
         • 5 source-attested WASM assets
         • per-contract testnet gas table
         • stellar.expert addresses for each deployment
```

```
                       LAYOUT
                       ══════

  onym-contracts/
  ├── README.md                    (this file)
  ├── LICENSE
  ├── traits/                      shared Soroban interface types
  │   └── Cargo.toml               (placeholder; populated when PQ
  │                                 flavor lands)
  ├── plonk/                       TurboPlonk + EF KZG flavor (today)
  │   ├── prover/                  off-chain TurboPlonk prover +
  │   │                             per-tier VK baker + canonical-
  │   │                             fixture regen (vendored from
  │   │                             rinat-enikeev/stellar-mls)
  │   ├── verifier/                on-chain verifier crate
  │   │                            (Soroban-portable, BLS12-381 host
  │   │                             fns)
  │   ├── sep-anarchy/    + README + tests + test_snapshots/
  │   ├── sep-democracy/  + README + tests + test_snapshots/
  │   ├── sep-oligarchy/  + README + tests + test_snapshots/
  │   ├── sep-oneonone/   + README + tests + test_snapshots/
  │   ├── sep-tyranny/    + README + tests + test_snapshots/
  │   └── tests/fixtures/          baked VK + canonical proof + PI
  │                                 byte fixtures (committed)
  ├── pq/                          (planned)
  ├── ffi/                         (planned)
  ├── scripts/bench-gas/           testnet gas-cost bench driver
  │   ├── run.sh                   orchestrator
  │   ├── setup.sh                 identity, friendbot, builds
  │   ├── lib.sh                   encoding, deploy, fee capture
  │   ├── render.py                JSONL → markdown table
  │   └── contracts/sep-*.sh       per-contract drivers
  └── .github/workflows/
      ├── release.yml              tag push → 5× source-attested
      │                            build + bench-gas
      └── pr.yml                   per-flavor build+test on PRs
```

## Build

Each contract is its own Cargo crate (`rust-toolchain.toml` pins 1.91.0,
matching `soroban-sdk = "=26.0.0-rc.1"`). From a contract directory:

```
cargo build --release --target wasm32v1-none
```

Tests:

```
cargo test --lib
```

Or use the upstream `stellar-expert/soroban-build-workflow` action — that's
what `release.yml` invokes on tag push, with source-code attestation under
`home_domain: 'onym.chat'`.

## Testnet gas bench

`scripts/bench-gas/run.sh` deploys each contract to Stellar testnet and
measures per-op fees via `stellar contract invoke`. Triggered automatically
on tag push from `release.yml` after the build matrix completes; the
rendered table replaces the GitHub release body.

## Per-contract

Read each contract's `README.md` for the full sk → π → on-chain flow with
ASCII Merkle walk-throughs and per-circuit constraint dumps:

- [`plonk/sep-anarchy/`](plonk/sep-anarchy/README.md) — single-signer membership
- [`plonk/sep-oneonone/`](plonk/sep-oneonone/README.md) — immutable two-party
- [`plonk/sep-democracy/`](plonk/sep-democracy/README.md) — K-of-N quorum + count delta
- [`plonk/sep-oligarchy/`](plonk/sep-oligarchy/README.md) — K-of-N + admin tree + count delta
- [`plonk/sep-tyranny/`](plonk/sep-tyranny/README.md) — single-admin + cross-group unlinkability

## Provenance

Both contract crates AND the off-chain prover were extracted from the
[`stellar-mls`](https://github.com/rinat-enikeev/stellar-mls) monorepo;
the prover lives at [`plonk/prover/`](plonk/prover/) and is the
canonical source for circuit shape (per-tier VK SHA-256 anchors live
in `circuit::plonk::baker`'s pinned constants + anchor tests).

Regenerate the committed `*.bin` fixtures in `plonk/verifier/tests/fixtures/`:

```
cd plonk/prover && STELLAR_REGEN_FIXTURES=1 cargo test --release --lib \
  plonk_verifier_fixtures_match_or_regenerate
```

Without the env var the same test runs in **assert** mode — re-bake
+ byte-compare against what's checked in. CI runs assert mode on
every PR so any drift between the prover and the on-chain bytes
fails the build immediately. Cross-platform clients (mobile SDKs)
verify against the same SHA pins so a divergence here surfaces
across all consumers.

Drift-window note: the upstream stellar-mls copy of this prover
remains in service until the kotlin / swift SDKs split out into
their own repos and rewire to consume from this crate. During that
window, treat this crate as the canonical source — any prover-shape
change here must propagate upstream (or vice-versa) before the
fixtures cut a new release.
