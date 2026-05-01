#!/usr/bin/env bash
# sep-democracy gas bench driver.
#
# Coverage (per-tier d=5/8 only — tier 2 / d=11 is contract-blocked
# at create + update by `MAX_DEMOCRACY_QUORUM_TIER = 1` in PR #20):
#   deploy, set_restricted_mode, plus per-tier:
#     create_group     — democracy-create-{proof,pi}-d{N}.bin (3-PI:
#                        commitment, epoch=0, occupancy_commitment).
#     verify_membership — democracy-membership-{proof,pi}-d{N}.bin (2-PI:
#                        commitment, epoch=0; occupancy is private).
#
# Both committed fixtures derive from canonical witnesses that share
# `(secret_keys, prover_index, salt, occupancy_commitment, epoch=0)` —
# so the c stored at create time is byte-identical to the c the
# membership proof binds. PR #11 (issue #5) ships the lifecycle test
# pinning this round-trip.
#
# Out of scope (V3):
#   update_commitment — the committed `democracy-update-{proof,pi}-d{N}.bin`
#   was baked under an independent canonical witness (epoch_old=1234,
#   c_old != post-create commitment), so passing it after create_group
#   trips the contract's `c_old == state.commitment` gate. Needs either
#   a chained `democracy-update` fixture (epoch_old=0, c_old=post-
#   create c) or a runtime `gen-democracy-update-proof` binary.
#
#   tier 2 / d=11 — re-enable once a real d11 K-of-N quorum update
#   circuit replaces the simplified fallback and PR #20's
#   `MAX_DEMOCRACY_QUORUM_TIER` gate is lifted. verify_membership at
#   d=11 stays contract-allowed but the bench can't reach it without
#   first creating a tier-2 group, which the contract rejects.

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LIB="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)/lib.sh"
# shellcheck source=../lib.sh
. "$LIB"

REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)"
FIXTURE_DIR="$REPO_ROOT/plonk/verifier/tests/fixtures"

export BENCH_CURRENT_CONTRACT="sep-democracy"

echo "==> [$BENCH_CURRENT_CONTRACT] deploy"
CID="$(bench_deploy \
    "bench-gas-democracy" \
    "$BENCH_ARTIFACT_DIR/sep_democracy_contract.wasm" \
    --admin "$BENCH_DEPLOYER_ADDRESS")"
if [ -z "$CID" ]; then
    echo "    deploy failed — skipping further ops" >&2
    exit 0
fi

run_tier() {
    local tier="$1"
    local depth="$2"
    local group_id_hex
    group_id_hex="$(printf '%02x%s' $(( 0x60 + tier )) "$(printf '00%.0s' $(seq 1 31))")"

    # ---- create_group: democracy-create fixture (3-PI) ----
    local create_proof_hex create_pi_json create_commitment_hex create_occ_hex
    create_proof_hex="$(bin_hex "$FIXTURE_DIR/democracy-create-proof-d${depth}.bin")"
    create_pi_json="$(pi_concat_json_array "$FIXTURE_DIR/democracy-create-pi-d${depth}.bin" 3)"
    create_commitment_hex="$(read_pi_field_hex "$FIXTURE_DIR/democracy-create-pi-d${depth}.bin" 0)"
    create_occ_hex="$(read_pi_field_hex          "$FIXTURE_DIR/democracy-create-pi-d${depth}.bin" 2)"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier (d=$depth) create_group"
    bench_invoke "$CID" "create_group" "$tier" "create_group" \
        --caller "$BENCH_DEPLOYER_ADDRESS" \
        --group-id "$group_id_hex" \
        --commitment "$create_commitment_hex" \
        --tier "$tier" \
        --threshold-numerator 1 \
        --occupancy-commitment-initial "$create_occ_hex" \
        --proof "$create_proof_hex" \
        --public-inputs "$create_pi_json"

    # ---- verify_membership: democracy-membership fixture (2-PI) ----
    # Commitment is byte-identical to the create fixture's PI[0] by
    # construction (canonical witnesses share state); reading from the
    # membership-pi file would be equivalent.
    local mp_proof_hex mp_pi_json
    mp_proof_hex="$(bin_hex "$FIXTURE_DIR/democracy-membership-proof-d${depth}.bin")"
    mp_pi_json="$(pi_concat_json_array "$FIXTURE_DIR/democracy-membership-pi-d${depth}.bin" 2)"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier verify_membership"
    bench_invoke "$CID" "verify_membership" "$tier" "verify_membership" \
        --group-id "$group_id_hex" \
        --proof "$mp_proof_hex" \
        --public-inputs "$mp_pi_json"
}

run_tier 0 5
if [ "${BENCH_FULL_TIERS:-1}" = "1" ]; then
    run_tier 1 8
fi

echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(true)"
bench_invoke "$CID" "set_restricted_mode" "n/a" "set_restricted_mode" \
    --restricted true

echo "==> [$BENCH_CURRENT_CONTRACT] done"
