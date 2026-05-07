# SEP MLS testnet gas benchmarks (PQ) — (untagged)

- **Network:** local
- **Captured:** 2026-05-07T15:01:19Z
- **Op rows:** 7    **Contracts deployed:** 1

## Deployed contracts

| Contract | Address |
|---|---|
| `pq-sep-anarchy` | [`CDX55N…XIWXO4`](https://stellar.expert/explorer/testnet/contract/CDX55NBEUDKO4H6IV3NPJNIPGQMJ2ZPFJCM3TZLAAOAM5L2JADXIWXO4) |

## Per-op gas costs

| Contract | Operation | Tier | Fee (XLM) | Stroops | CPU Insns | % of cap | Resource | Non-refundable | Refundable | Inclusion |
|---|---|---|---|---|---|---|---|---|---|---|
| `pq-sep-anarchy` | `deploy` | — | 0.0033053 | 33,053 | — | — | 32,953 | 29,736 | 3,217 | 100 |
| `pq-sep-anarchy` | `create_group` | — | 0.2962800 | 2,962,800 | 281,984,553 | 281.98% | 2,962,700 | 2,952,975 | 9,725 | 100 |
| `pq-sep-anarchy` | `verify_membership` | — | 0.2860738 | 2,860,738 | 280,092,494 | 280.09% | 2,860,638 | 2,860,635 | 3 | 100 |
| `pq-sep-anarchy` | `update_commitment` | — | 0.2900581 | 2,900,581 | 282,426,719 | 282.43% | 2,900,481 | 2,897,166 | 3,315 | 100 |
| `pq-sep-anarchy` | `set_restricted_mode` | — | 0.0024145 | 24,145 | 1,642,232 | 1.64% | 24,045 | 23,975 | 70 | 100 |
| `pq-sep-anarchy` | `set_restricted_mode` | — | 0.0024244 | 24,244 | 1,653,197 | 1.65% | 24,144 | 24,084 | 60 | 100 |
| `pq-sep-anarchy` | `bump_group_ttl` | — | 0.0022326 | 22,326 | 1,753,532 | 1.75% | 22,226 | 22,224 | 2 | 100 |

## Notes

- Stroops are testnet stroops; 1 XLM = 10,000,000 stroops.
- `CPU Insns` is the host instruction count from a pre-flight `simulateTransaction` (the value metered against `tx_max_instructions = 100,000,000` on testnet/mainnet). `% of cap` is `CPU Insns / tx_max_instructions`.
- `create_group` / `verify_membership` / `update_commitment` rows are real on-chain FRI verifications: the off-chain `gen-pq-proof` binary in `pq/prover/` produces self-consistent FRI proofs the on-chain verifier accepts at bench-scope parameters (log_n=6, num_layers=3, num_queries=8, blowup=2). Proof size: ~8 KB.
- These numbers are **bench-scope only**: the on-chain verifier today runs the FRI low-degree test alone, with no batched-PCS layer tying FRI to an AIR. So the proofs prove "prover committed to a low-degree polynomial" and nothing more — they do not encode any circuit witness. Do **not** deploy the contract behind this verifier for production; the `verifier_pcs` follow-up is the gating dependency.
- `set_restricted_mode` second toggle is cheaper than the first because the storage slot already exists by then (the second write skips creation overhead).
- `verify_membership` is read-only and does not consume the global nullifier — the same proof bytes can be re-submitted without burning `UsedProof` storage. Same convention as the PLONK flavor.
- See `pq/verifier/src/lib.rs` for the open-work list: batched PCS layer, prover-side fixtures from a real circuit, canonical Plonky3 Poseidon2 round constants.
