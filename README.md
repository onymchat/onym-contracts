# onym-contracts

Soroban smart contracts for onym.chat — five per-governance-type membership / state contracts (`sep-anarchy`, `sep-democracy`, `sep-oligarchy`, `sep-oneonone`, `sep-tyranny`), structured to host multiple verifier flavors side-by-side.

## Layout

```
onym-contracts/
├── traits/              shared Soroban interface types (Error / DataKey / CommitmentEntry)
├── plonk/               PLONK + EF KZG SRS flavor (TurboPlonk via jf-plonk on BLS12-381)
│   ├── verifier/        on-chain verifier crate (Soroban-portable, BLS12-381 host fns)
│   ├── sep-anarchy/
│   ├── sep-democracy/
│   ├── sep-oligarchy/
│   ├── sep-oneonone/
│   ├── sep-tyranny/
│   └── tests/fixtures/  baked VK + canonical proof + PI byte fixtures (committed)
├── pq/                  (planned) post-quantum flavor — STARK / lattice-based
├── ffi/                 (planned) alternative-SNARK flavor
├── scripts/bench-gas/   testnet gas-cost bench driver (shell + python)
└── .github/workflows/
    ├── release.yml      tag push → stellar-expert source-attested build + testnet bench
    └── pr.yml           per-flavor build+test on PRs
```

## Flavor model

Each flavor in this repo produces **independent Soroban contracts** — different addresses on-chain, different proof shapes, different VKs. Contracts within a flavor share a single `verifier/` crate; the trait definitions in `traits/` keep entrypoint signatures uniform across flavors so client code can target any address by the same calling convention.

There is **no in-place migration** between flavors: a group created against the PLONK contracts cannot move to the (future) PQ contracts. Flavor is a deployment-time choice.

## Build

Each contract is its own Cargo crate. From a contract directory:

```
cargo build --release --target wasm32v1-none
```

Or use the upstream stellar-expert build workflow (what `release.yml` runs on tag push).

## Testnet gas bench

`scripts/bench-gas/run.sh` deploys each contract to Stellar testnet and measures per-op fees via simulation. Triggered automatically on tag push (see `release.yml`); the rendered table replaces the GitHub release body.

## Source-code attestation

`release.yml`'s contract-build jobs delegate to `stellar-expert/soroban-build-workflow`, which registers the WASM build under `home_domain: 'onym.chat'`. Each deployed contract page on stellar.expert links back to the source tag in this repo.

## Provenance

Contract crates were extracted from the [`stellar-mls`](https://github.com/rinat-enikeev/stellar-mls) monorepo as the migration to a stand-alone contracts repo. Until the prover side splits too, fixtures are regenerated via a path-dep on `stellar-mls` during local development; the committed `*.bin` files in `plonk/verifier/tests/fixtures/` are the canonical artifacts CI consumes.
