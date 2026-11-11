# sha-fri: SHA-256 FRI feasibility prototype

`pq/verifier` hashes with the BN254 Poseidon2 host primitive. One
permutation costs about 707K CPU instructions under the soroban-sdk 26
cost model. At toy parameters (about 8 bits of security) its FRI ops
already use about 282M CPU and about 60 MB of memory, over the 40 MiB
cap. This crate tests the alternative: **BabyBear arithmetic in plain
WASM plus SHA-256 commitments** (about 8.4K CPU per host call).

```
  pq/sha-fri/          no_std verifier + `prover` feature (bench prover)
  pq/sha-fri-bench/    Soroban contract: verify(params, proof, pi) -> bool
  pq/sha-fri-runner/   proves presets, runs the WASM under host metering
```

## Run

```
cd pq/sha-fri && cargo test --release --features prover
cd ../sha-fri-bench && cargo build --release --target wasm32v1-none
cd ../sha-fri-runner && cargo run --release -- \
  ../sha-fri-bench/target/wasm32v1-none/release/pq_sha_fri_bench_contract.wasm
```

## Results (2026-11-11, soroban-sdk 26.0.0 testutils, unoptimized 13.9 KB WASM)

Caps: 400M instructions, 40 MiB memory, 132,096-byte tx (live futurenet
and testnet values). Tx size = proof + params + PI + 1 KB of overhead.

| Preset | Trace | Blowup | Queries | Grind | Security (conj / Johnson) | Proof | % tx | CPU | % CPU | Mem | % mem |
|---|---|---|---|---|---|---|---|---|---|---|---|
| membership d11, conjectured | 2^9 × 48 | 16 | 20 | 20 | 100 / 60 | 24.8 KB | 19.6% | 28.3M | 7.1% | 1.5 MB | 3.6% |
| membership d11, Johnson | 2^9 × 48 | 16 | 40 | 20 | 180 / 100 | 47.2 KB | 36.5% | 54.9M | 13.7% | 1.7 MB | 4.1% |
| 4× circuit, Johnson | 2^11 × 48 | 16 | 40 | 20 | 180 / 100 | 61.7 KB | 47.5% | 70.2M | 17.5% | 1.9 MB | 4.5% |
| 32× circuit, Johnson | 2^14 × 48 | 16 | 40 | 20 | 180 / 100 | 84.0 KB | 64.4% | 92.6M | 23.1% | 2.2 MB | 5.1% |
| rate 1/2, conjectured | 2^9 × 48 | 2 | 80 | 20 | 100 / 60 | 71.2 KB | 54.7% | 88.9M | 22.2% | 1.8 MB | 4.4% |
| wide trace, Johnson | 2^5 × 400 | 16 | 40 | 20 | 180 / 100 | 147 KB | **112%** | 157.6M | 39.4% | 1.9 MB | 4.5% |

Takeaways:
- **Proof size is the binding constraint, not CPU or memory.** The
  trace leaf (`arity × columns × 4 B`) dominates, so the AIR must stay
  narrow (tens of columns, not Plonky3's one-row-per-permutation width).
- High blowup (16) beats rate 1/2 on every axis.

## Not covered (needed before this is a real verifier)

- **No AIR constraint check at `z`.** The verifier binds the OOD values
  to the committed trace but not to a circuit. That check is
  extension-field arithmetic only (adds CPU, no hashes, about `W × 16 B`
  of proof), and it needs a second OOD point `z·g`.
- **Not zero-knowledge.** The trace is not randomized, so openings leak
  witness values. Membership privacy needs a hiding STARK (trace
  blinding rows plus a masked FRI batch).
- Security columns are heuristics: `q·log₂(blowup) + grind` (conjectured)
  and half the per-query bits (Johnson regime). A real parameter choice
  needs a proper soundness calculator.
- Measured with testutils metering (same cost model as the network), not
  on a live network.
