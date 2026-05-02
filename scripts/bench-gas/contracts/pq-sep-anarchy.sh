#!/usr/bin/env bash
# pq/sep-anarchy gas bench driver (skeleton).
#
# Coverage today:
#   * `deploy`                         — full deploy fee.
#   * `set_restricted_mode(true|false)` — admin op, no proof needed.
#   * `bump_group_ttl(<unknown_id>)`   — revert-mode (GroupNotFound);
#                                         captures storage-read floor.
#   * `create_group` (revert mode)     — malformed proof bytes; the
#                                         FRI verifier parser rejects
#                                         at its first length gate.
#                                         Captures the early-rejection
#                                         floor: deserialise + replay-
#                                         check + parser entry.
#   * `verify_membership` (revert)     — revert-mode (GroupNotFound).
#
# Coverage explicitly NOT here yet:
#   * Real-proof `create_group` / `update_commitment` /
#     `verify_membership`. The PQ prover (off-chain Plonky3-shape
#     polynomial commit + FRI prover) does not exist yet, so the
#     contract has no proof bytes that would clear `verify_fri`. As
#     soon as the PQ prover lands, the matching `bench_gen_*_proof`
#     wrappers go into `lib.sh` and this driver picks up the same
#     `run_tier`-style real-proof rows the PLONK driver has.
#
# State: no group ever gets successfully created in this run, so all
# group-state reads return `GroupNotFound`. That is intentional —
# revert-mode rows are useful as the floor cost for those entrypoints.

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LIB="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)/lib.sh"
# shellcheck source=../lib.sh
. "$LIB"

export BENCH_CURRENT_CONTRACT="pq-sep-anarchy"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bench-gas-pq-anarchy.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

WASM="$BENCH_ARTIFACT_DIR/pq_sep_anarchy_contract.wasm"
test -f "$WASM" || { echo "expected WASM at $WASM" >&2; exit 1; }

echo "==> [$BENCH_CURRENT_CONTRACT] deploy"
CID="$(bench_deploy \
    "bench-gas-pq-anarchy" \
    "$WASM" \
    --admin "$BENCH_DEPLOYER_ADDRESS")"
if [ -z "$CID" ]; then
    echo "    deploy failed — skipping further ops" >&2
    exit 0
fi

# ---------- admin-only, no proof ----------

echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(true)"
bench_invoke "$CID" "set_restricted_mode" "n/a" "set_restricted_mode" \
    --restricted true

echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(false)"
# Toggle back so the bench is idempotent across re-runs against the
# same testnet account state. The bench identity is admin, so the
# call clears restricted mode for any subsequent op.
bench_invoke "$CID" "set_restricted_mode" "n/a" "set_restricted_mode" \
    --restricted false

# ---------- revert-mode rows (no group exists) ----------

# Distinct group_id, never created — exercises the GroupNotFound
# revert path on the read-only and TTL-bump entrypoints. High byte
# 0x50 keeps the bytes canonical-Fr-shaped at every 4-byte chunk.
GROUP_ID_HEX="50$(printf '00%.0s' $(seq 1 31))"

echo "==> [$BENCH_CURRENT_CONTRACT] bump_group_ttl (revert: GroupNotFound)"
bench_invoke "$CID" "bump_group_ttl" "n/a" "bump_group_ttl" \
    --group-id "$GROUP_ID_HEX"

# Commitment = 32 zero bytes: every 4-byte LE chunk is `0 < P`, so
# `is_canonical_pi` accepts. The PI vector mirrors what the contract
# expects for membership: `(commitment, epoch_be=0)` — both are
# 32-byte all-zero values, which the on-chain checker accepts.
COMMITMENT_HEX="$(printf '00%.0s' $(seq 1 32))"
EPOCH_ZERO_HEX="$COMMITMENT_HEX"
PI_JSON="[\"$COMMITMENT_HEX\",\"$EPOCH_ZERO_HEX\"]"

# Malformed proof: 4 bytes whose `num_layers_plus_1 = u32_le` exceeds
# the parser's `MAX_LAYERS + 1` cap. The contract clears length / hash
# / replay gates and reaches `verify_fri_proof`, which rejects at the
# parser's `OutOfRange` arm. Captured fee = "minimum cost to land at
# the verifier and bounce" — the floor below which no successful
# create_group can run.
MALFORMED_PROOF_HEX="deadbeef"

echo "==> [$BENCH_CURRENT_CONTRACT] create_group (revert: InvalidProof, malformed bytes)"
bench_invoke "$CID" "create_group" "n/a" "create_group" \
    --caller "$BENCH_DEPLOYER_ADDRESS" \
    --group-id "$GROUP_ID_HEX" \
    --commitment "$COMMITMENT_HEX" \
    --tier 0 \
    --member-count 0 \
    --proof "$MALFORMED_PROOF_HEX" \
    --public-inputs "$PI_JSON"

echo "==> [$BENCH_CURRENT_CONTRACT] verify_membership (revert: GroupNotFound)"
bench_invoke "$CID" "verify_membership" "n/a" "verify_membership" \
    --group-id "$GROUP_ID_HEX" \
    --proof "$MALFORMED_PROOF_HEX" \
    --public-inputs "$PI_JSON"

echo "==> [$BENCH_CURRENT_CONTRACT] done"
