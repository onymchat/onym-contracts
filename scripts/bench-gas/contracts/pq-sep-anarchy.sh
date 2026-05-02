#!/usr/bin/env bash
# pq/sep-anarchy gas bench driver.
#
# Coverage:
#   * deploy
#   * set_restricted_mode (true / false)
#   * create_group        — real FRI proof from `gen-pq-proof`
#   * verify_membership   — same proof, group exists post-create
#   * update_commitment   — fresh update proof (c_old / c_new)
#   * bump_group_ttl      — TTL extend on the post-create group
#
# State chain (single group_id throughout):
#   1. create_group at epoch=0 with commitment Cm, member_count=8.
#   2. verify_membership re-uses the same membership proof + PI;
#      contract checks PI against stored state — matches.
#   3. update_commitment with epoch_old=0, c_old=Cm, c_new=Cn.
#   4. bump_group_ttl extends the post-update group's TTL.
#
# Bench-only safety: the FRI prover behind `gen-pq-proof` produces
# self-consistent proofs the on-chain verifier accepts, but does NOT
# prove anything about an underlying circuit (no batched-PCS layer
# yet). These rows measure on-chain verifier+storage cost; they say
# nothing about the security of any real PQ flavor — see
# `pq/verifier/src/lib.rs` for the open-work list.

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
bench_invoke "$CID" "set_restricted_mode" "n/a" "set_restricted_mode" \
    --restricted false

# ---------- per-group state chain with real FRI proofs ----------

# group_id: high byte 0x50 keeps every 4-byte LE chunk canonical Fr.
GROUP_ID_HEX="50$(printf '00%.0s' $(seq 1 31))"

# Commitment Cm and Cn — both must satisfy `is_canonical_pi`: each
# 4-byte LE chunk < BabyBear P (0x78000001). The contract reads each
# chunk as `u32::from_le_bytes(bytes[off..off+4])`, so byte
# `off + 3` is the chunk's MSB and must be `<= 0x77` for the chunk
# to land strictly below P.
#
# Pattern below: each 4-byte chunk = `LL 00 00 00` LE = `0x000000LL`
# = LL (small integer). 8 chunks of 4 bytes = 32 bytes total. Cm and
# Cn use distinct LSB-byte values so they decode to different Fr
# vectors.
mk_commitment() {
    local lsb="$1"  # two hex chars: chunk LSB
    local chunk="${lsb}000000"
    printf '%s%s%s%s%s%s%s%s' "$chunk" "$chunk" "$chunk" "$chunk" \
                              "$chunk" "$chunk" "$chunk" "$chunk"
}
COMMITMENT_HEX="$(mk_commitment 10)"
COMMITMENT_NEW_HEX="$(mk_commitment 20)"

echo "==> [$BENCH_CURRENT_CONTRACT] generating membership proof (epoch=0)"
bench_gen_pq_membership_proof "$COMMITMENT_HEX" 0 "$WORK/membership"
mp_proof_hex="$(bench_gen_proof_hex "$WORK/membership")"
mp_pi_json="$(bench_gen_pi_json "$WORK/membership")"

echo "==> [$BENCH_CURRENT_CONTRACT] create_group"
bench_invoke "$CID" "create_group" "n/a" "create_group" \
    --caller "$BENCH_DEPLOYER_ADDRESS" \
    --group-id "$GROUP_ID_HEX" \
    --commitment "$COMMITMENT_HEX" \
    --tier 0 \
    --member-count 8 \
    --proof "$mp_proof_hex" \
    --public-inputs "$mp_pi_json"

echo "==> [$BENCH_CURRENT_CONTRACT] verify_membership (read-only; same proof)"
# Note: the contract's `check_proof_replay` only fires for state-
# changing entrypoints (create_group / update_commitment).
# verify_membership is read-only and re-uses the same proof bytes
# without consuming the global nullifier.
bench_invoke "$CID" "verify_membership" "n/a" "verify_membership" \
    --group-id "$GROUP_ID_HEX" \
    --proof "$mp_proof_hex" \
    --public-inputs "$mp_pi_json"

echo "==> [$BENCH_CURRENT_CONTRACT] generating update proof (c_old → c_new, epoch_old=0)"
bench_gen_pq_update_proof "$COMMITMENT_HEX" 0 "$COMMITMENT_NEW_HEX" "$WORK/update"
up_proof_hex="$(bench_gen_proof_hex "$WORK/update")"
up_pi_json="$(bench_gen_pi_json "$WORK/update")"

echo "==> [$BENCH_CURRENT_CONTRACT] update_commitment"
bench_invoke "$CID" "update_commitment" "n/a" "update_commitment" \
    --group-id "$GROUP_ID_HEX" \
    --proof "$up_proof_hex" \
    --public-inputs "$up_pi_json"

echo "==> [$BENCH_CURRENT_CONTRACT] bump_group_ttl"
bench_invoke "$CID" "bump_group_ttl" "n/a" "bump_group_ttl" \
    --group-id "$GROUP_ID_HEX"

echo "==> [$BENCH_CURRENT_CONTRACT] done"
