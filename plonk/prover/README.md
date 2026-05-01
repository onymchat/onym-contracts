# onym-plonk-prover

Off-chain TurboPlonk prover + per-tier VK baker + canonical-fixture
regen for the `plonk/sep-*` contract family. Vendored from
[`rinat-enikeev/stellar-mls`](https://github.com/rinat-enikeev/stellar-mls)
so this repo is self-contained.

```
                       PIPELINE
                       ════════

  src/circuit/plonk/                src/prover/
  ─────────────────                 ──────────
   poseidon  ┐                       plonk.rs   ┐
   merkle    │ gadgets               srs.rs     │ proving / verifying
   ...       │                       srs/       │ machinery + EF KZG
   democracy │ circuits per          ef-kzg-2023│ 2023 SRS bytes
   tyranny   │ governance type       .bin       │ (3.2 MiB, n=32768)
   ...       ┘                                  ┘
       │                                  │
       └─────────────┬────────────────────┘
                     ▼
                  baker.rs
                  ────────
              bake_*_vk(depth)
              build_canonical_*_witness(depth)
                     │
                     │ pinned VK SHA-256 anchors per tier
                     │ (anchor tests fail first on drift)
                     ▼
                 verifier.rs
                  ──────────
        plonk_verifier_fixtures_match_or_regenerate
                     │
        ┌────────────┴────────────┐
        │                         │
        ▼ default (assert)        ▼ STELLAR_REGEN_FIXTURES=1
   byte-compare against     write fresh bytes to
   ../verifier/tests/       ../verifier/tests/
   fixtures/*.bin           fixtures/*.bin
```

## Usage

Run the full suite (CI does this on every PR):

```
cargo test --release --lib
```

Re-bake fixtures the on-chain verifier crate and the sep-* contract
test snapshots consume:

```
STELLAR_REGEN_FIXTURES=1 cargo test --release --lib \
  plonk_verifier_fixtures_match_or_regenerate
```

The regen test re-derives every fixture (`vk-d{N}.bin`,
`update-{vk,proof,pi}-d{N}.bin`, `tyranny-{create,update}-*-d{N}.bin`,
`democracy-update-*-d{N}.bin`, `oligarchy-membership-*-d{N}.bin`,
`oneonone-create-*.bin`) and writes them into the sibling
`../verifier/tests/fixtures/` directory.

## Provenance

Vendored from rinat-enikeev/stellar-mls (commit `c71174a`, 2026-05-01).
Module hierarchy mirrors upstream verbatim — `circuit::plonk::*` for
gadgets + circuits, `prover::{plonk, srs}` for proving machinery — so
the byte-identical regen test is the load-bearing acceptance gate.

Differences vs. upstream:

- No Groth16 module — upstream's `prover::mod` carries a full Groth16
  setup/prove/verify pipeline; this crate is plonk-only.
- No FFI / JNI surface — upstream ships a `jni`-feature bridge for
  the kotlin / swift SDKs; that lives upstream until the SDK split.
- No `extract-ef-kzg` / `bake-vk` / `gen-*-proof` operator binaries —
  the SRS is already extracted (`src/prover/srs/ef-kzg-2023.bin`) and
  fixtures bake via the regen test, not standalone CLIs.
- Plain `ark-*` 0.5 deps without the `_v05` package-rename dance
  upstream needed for arkworks 0.4 + 0.5 coexistence (kept as
  Cargo.toml aliases so vendored source compiles without `use`
  rewrites).

The upstream stellar-mls copy stays in service until the kotlin / swift
SDKs split out into their own repos and rewire to consume from this
crate. Any prover-shape change here must propagate upstream (or
vice-versa) before the fixtures cut a new release; the per-tier VK
SHA-256 anchors in `circuit::plonk::baker` are how we detect drift.
