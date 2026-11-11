# sha-fri: post-quantum membership STARK for Soroban

`pq/verifier` hashes with the BN254 Poseidon2 host primitive. One
permutation costs about 707K CPU instructions under the soroban-sdk 26
cost model. At toy parameters (about 8 bits of security) its FRI ops
already use about 282M CPU and about 60 MB of memory, over the 40 MiB
cap. This crate uses **BabyBear arithmetic in plain WASM plus SHA-256
commitments** (about 8.4K CPU per host call) instead.

```
  pq/sha-fri/          no_std verifier + `prover` feature
    air.rs             membership AIR (Poseidon2-BabyBear-16, one row per round)
    poseidon2*.rs      permutation, generic over F / E; prototype constants
    verifier.rs        AIR check at z, DEEP, FRI
    prover.rs          ZK prover (masking, randomizers, salted leaves)
  pq/sha-fri-bench/    Soroban contract: verify(params, proof, pi) -> bool
  pq/sha-fri-runner/   proves random members, runs the WASM under metering
```

## Statements

The PQ analogues of `plonk/prover`'s `MembershipCircuit` and
`UpdateCircuit`. **Membership** (used by `create_group` and
`verify_membership`):

```
  public:  commitment (8 × BabyBear), epoch (u64)
  private: sk, Merkle path + index bits, salt

  leaf       = H(sk ‖ 0⁸)
  root       = MerkleOpen(leaf, path, bits)          (root stays private)
  commitment = H(H(root ‖ epoch limbs ‖ 0⁵) ‖ salt)
```

**Update** (`update_commitment`): the membership statement for
`(c_old, epoch_old)`, plus `c_new = H(H(root_new ‖ (epoch_old+1) limbs) ‖
salt_new)` with `root_new` and `salt_new` private. As in the PLONK
circuit, new-tree binding is commitment-only. Two more Poseidon2 blocks,
so the trace is 512 rows at every tier.

## Deployment

`pq/sep-anarchy` verifies these proofs on-chain. `params::deployment_params`
is the single source of the per-tier parameters for both the contract
and the prover, with two profiles:

- **`Johnson100`** (default build): 40 queries, ~70-76 KB proofs.
- **`Conjectured100`** (`--features conjectured`): 20 queries, ~36-39 KB proofs.

Both use blowup 16 and 20 grinding bits. `gen-pq-anarchy-bundle`
(`--features prover`) emits a chained create → update bundle for the
testnet bench (`gh workflow run bench_testnet.yml -f contracts=pq-sep-anarchy`).

## Run

```
cd pq/sha-fri && cargo test --release --features prover
cd ../sha-fri-bench && cargo build --release --target wasm32v1-none
cd ../sha-fri-runner && cargo run --release -- \
  ../sha-fri-bench/target/wasm32v1-none/release/pq_sha_fri_bench_contract.wasm
```

## Results (2026-11-11, soroban-sdk 26.0.0 testutils metering, unoptimized 24.6 KB WASM)

Caps: 400M instructions, 40 MiB memory, 132,096-byte tx (live futurenet
and testnet values). Tx size = proof + params + PI + 1 KB of overhead.
All proofs are zero-knowledge (mask degree = queries × 2 + 2).

| Preset | Rows | Quotient chunks | Queries | Security (conj / Johnson) | Proof | % tx | CPU | % CPU | Mem | % mem | Prove |
|---|---|---|---|---|---|---|---|---|---|---|---|
| d5, blowup 16 | 256 | 9 | 20 | 100 / 60 | 36.1 KB | 28% | 67.2M | 17% | 1.6 MB | 4% | 1.1 s |
| d8, blowup 16 | 512 | 8 | 20 | 100 / 60 | 39.3 KB | 31% | 70.1M | 18% | 1.7 MB | 4% | 0.3 s |
| d11, blowup 16 | 512 | 8 | 20 | 100 / 60 | 39.3 KB | 31% | 70.1M | 18% | 1.7 MB | 4% | 0.7 s |
| d5, blowup 16 | 256 | 10 | 40 | 180 / 100 | 69.6 KB | 54% | 116.6M | 29% | 2.0 MB | 5% | 0.3 s |
| d8, blowup 16 | 512 | 9 | 40 | 180 / 100 | 76.0 KB | 58% | 122.4M | 31% | 2.1 MB | 5% | 0.3 s |
| **d11, blowup 16** | 512 | 9 | 40 | 180 / **100** | **76.0 KB** | **58%** | **122.4M** | **31%** | 2.1 MB | 5% | 0.3 s |
| d11, blowup 8 | 512 | 9 | 54 | 182 / 101 | 94.0 KB | 72% | 151.7M | 38% | 2.2 MB | 5% | 0.1 s |

Prove times are single-threaded on an Apple Silicon desktop.

Takeaways:
- **The full ZK membership proof fits one transaction** at all three PLONK
  tiers. Proof size is the tightest limit.
- The quotient tree is the biggest opening: 8–10 chunks (32–40 columns)
  come from the degree-7 S-box multiplied by degree-~n periodic
  selectors. Degree-3 auxiliary S-box columns would cut that roughly
  in half.
- Rejecting a wrong epoch costs about 18.5M CPU: the AIR check at `z` and
  setup run before any query work.

## Not covered (needed before production)

- **Poseidon2 constants are not canonical.** Swap in Plonky3's
  BabyBear-16 set (round constants and internal diagonal) and add KATs.
- **The bench prover's randomness is seeded xorshift.** Production must
  use a CSPRNG, or the proof is not zero-knowledge.
- Security figures are heuristics. A real parameter choice needs a
  soundness calculator (FRI + DEEP-ALI + grinding).
- Measured with testutils metering (same cost model as the network), not
  on a live network.
- No audit.
