#!/usr/bin/env bash
# pq/sep-anarchy gas bench driver (zero-knowledge SHA-256 STARKs).
#
# Deploys two builds of the contract, one per security profile:
#   pq-sep-anarchy              ~100 bits, Johnson regime (40 queries, ~76 KB proofs)
#   pq-sep-anarchy-conjectured  ~100 bits, conjectured   (20 queries, ~39 KB proofs)
# and for each runs, per tier (d=5/8/11):
#   create_group → verify_membership → update_commitment
# with a fresh chained bundle from `gen-pq-anarchy-bundle` (one random
# member at epoch 0; the same member updates to epoch 1). Then
# bump_group_ttl and set_restricted_mode (true/false).
#
# Proofs go in with `--proof-file-path` (raw bytes): ~150 KB of inline
# hex would exceed Linux's 128 KiB per-argument limit.

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LIB="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)/lib.sh"
# shellcheck source=../lib.sh
. "$LIB"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/bench-gas-pq-anarchy.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

run_profile() {
    local profile="$1"   # johnson | conjectured
    local wasm="$2"
    export BENCH_CURRENT_CONTRACT="$3"
    test -f "$wasm" || { echo "expected WASM at $wasm" >&2; return 1; }

    echo "==> [$BENCH_CURRENT_CONTRACT] deploy"
    local cid
    cid="$(bench_deploy "bench-gas-$BENCH_CURRENT_CONTRACT" "$wasm" \
        --admin "$BENCH_DEPLOYER_ADDRESS")"
    if [ -z "$cid" ]; then
        echo "    deploy failed — skipping further ops" >&2
        return 0
    fi
    echo "    contract: $cid"

    local tier depth group_id_hex dir last_gid=""
    for tier in 0 1 2; do
        depth=$(( tier == 0 ? 5 : tier == 1 ? 8 : 11 ))
        [ "$tier" -eq 0 ] || [ "${BENCH_FULL_TIERS:-1}" = "1" ] || break
        # Distinct group id per tier; any 32 bytes are a valid group id.
        group_id_hex="$(printf '5%x%s' "$tier" "$(printf '00%.0s' $(seq 1 31))")"
        dir="$WORK/$profile-d$depth"

        echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier (d=$depth) generating proofs"
        bench_gen_pq_anarchy_bundle "$depth" "$profile" "$(( 100 + tier ))" "$dir"

        echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier create_group"
        bench_invoke "$cid" "create_group" "$tier" "create_group" \
            --caller "$BENCH_DEPLOYER_ADDRESS" \
            --group-id "$group_id_hex" \
            --commitment "$(cat "$dir/commitment.hex")" \
            --tier "$tier" \
            --member-count 8 \
            --proof-file-path "$dir/create/proof.bin" \
            --public-inputs "$(cat "$dir/create/public_inputs.json")"

        echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier verify_membership"
        bench_invoke "$cid" "verify_membership" "$tier" "verify_membership" \
            --group-id "$group_id_hex" \
            --proof-file-path "$dir/create/proof.bin" \
            --public-inputs "$(cat "$dir/create/public_inputs.json")"

        echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier update_commitment"
        bench_invoke "$cid" "update_commitment" "$tier" "update_commitment" \
            --group-id "$group_id_hex" \
            --proof-file-path "$dir/update/proof.bin" \
            --public-inputs "$(cat "$dir/update/public_inputs.json")"
        last_gid="$group_id_hex"
    done

    echo "==> [$BENCH_CURRENT_CONTRACT] bump_group_ttl"
    bench_invoke "$cid" "bump_group_ttl" "n/a" "bump_group_ttl" \
        --group-id "$last_gid"

    echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(true)"
    bench_invoke "$cid" "set_restricted_mode" "n/a" "set_restricted_mode" \
        --restricted true
    echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(false)"
    bench_invoke_required "$cid" "set_restricted_mode(false)" "n/a" "set_restricted_mode" \
        --restricted false

    echo "==> [$BENCH_CURRENT_CONTRACT] done"
}

run_profile johnson "$BENCH_ARTIFACT_DIR/pq_sep_anarchy_contract.wasm" "pq-sep-anarchy"
run_profile conjectured "$BENCH_ARTIFACT_DIR/conjectured/pq_sep_anarchy_contract.wasm" "pq-sep-anarchy-conjectured"
