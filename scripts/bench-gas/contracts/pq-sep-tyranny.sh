#!/usr/bin/env bash
# pq/sep-tyranny gas bench driver (zero-knowledge SHA-256 STARKs at the
# ~100-bit post-quantum `Pq100` profile).
#
# Coverage: deploy, then per tier (d=5/8/11)
#   create_group → verify_membership → update_commitment,
# then bump_group_ttl and set_restricted_mode (true/false).
#
# Each tier uses a fresh chained bundle from `gen-pq-tyranny-bundle`: an
# admin creates group `tier+1` at epoch 0, a membership proof for that
# state, then the admin's update to epoch 1. Proofs (~84-101 KB) go in
# with `--proof-file-path`: inline hex would exceed Linux's 128 KiB
# per-argument limit.

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LIB="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)/lib.sh"
# shellcheck source=../lib.sh
. "$LIB"

export BENCH_CURRENT_CONTRACT="pq-sep-tyranny"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bench-gas-pq-tyranny.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

WASM="$BENCH_ARTIFACT_DIR/pq_sep_tyranny_contract.wasm"
test -f "$WASM" || { echo "expected WASM at $WASM" >&2; exit 1; }

echo "==> [$BENCH_CURRENT_CONTRACT] deploy"
CID="$(bench_deploy "bench-gas-pq-tyranny" "$WASM" --admin "$BENCH_DEPLOYER_ADDRESS")"
if [ -z "$CID" ]; then
    echo "    deploy failed — skipping further ops" >&2
    exit 0
fi
echo "    contract: $CID"

LAST_GROUP_ID_HEX=""
for tier in 0 1 2; do
    depth=$(( tier == 0 ? 5 : tier == 1 ? 8 : 11 ))
    [ "$tier" -eq 0 ] || [ "${BENCH_FULL_TIERS:-1}" = "1" ] || break
    dir="$WORK/d$depth"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier (d=$depth) generating proofs"
    bench_gen_pq_tyranny_bundle "$depth" "$(( tier + 1 ))" "$(( 200 + tier ))" "$dir"
    group_id_hex="$(cat "$dir/group_id.hex")"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier create_group"
    bench_invoke "$CID" "create_group" "$tier" "create_group" \
        --caller "$BENCH_DEPLOYER_ADDRESS" \
        --group-id "$group_id_hex" \
        --commitment "$(cat "$dir/commitment.hex")" \
        --tier "$tier" \
        --admin-pubkey-commitment "$(cat "$dir/admin_comm.hex")" \
        --proof-file-path "$dir/create/proof.bin" \
        --public-inputs "$(cat "$dir/create/public_inputs.json")"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier verify_membership"
    bench_invoke "$CID" "verify_membership" "$tier" "verify_membership" \
        --group-id "$group_id_hex" \
        --proof-file-path "$dir/member/proof.bin" \
        --public-inputs "$(cat "$dir/member/public_inputs.json")"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier update_commitment"
    bench_invoke "$CID" "update_commitment" "$tier" "update_commitment" \
        --group-id "$group_id_hex" \
        --proof-file-path "$dir/update/proof.bin" \
        --public-inputs "$(cat "$dir/update/public_inputs.json")"
    LAST_GROUP_ID_HEX="$group_id_hex"
done

echo "==> [$BENCH_CURRENT_CONTRACT] bump_group_ttl"
bench_invoke "$CID" "bump_group_ttl" "n/a" "bump_group_ttl" \
    --group-id "$LAST_GROUP_ID_HEX"

echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(true)"
bench_invoke "$CID" "set_restricted_mode" "n/a" "set_restricted_mode" \
    --restricted true
echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(false)"
bench_invoke_required "$CID" "set_restricted_mode(false)" "n/a" "set_restricted_mode" \
    --restricted false

echo "==> [$BENCH_CURRENT_CONTRACT] done"
