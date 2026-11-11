#!/usr/bin/env bash
# sep-tyranny gas bench driver.
#
# Coverage: deploy, then per tier (d=5/8/11)
#   create_group → verify_membership → update_commitment,
# then bump_group_ttl and set_restricted_mode (true/false).
#
# Proofs are generated at runtime. The committed tyranny fixtures don't
# chain (update is baked at epoch_old=1234 against a different c_old)
# and all pin group_id_fr=0x7777, so one deployment could host only one
# tier. `gen-tyranny-proofs` emits a chained create/update pair for a
# caller-chosen group id; `gen-membership-proof` (canonical roster,
# epoch 0, salt 0xEE…) reproduces the post-create commitment, since the
# commitment depends only on (root, epoch, salt).

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LIB="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)/lib.sh"
# shellcheck source=../lib.sh
. "$LIB"

export BENCH_CURRENT_CONTRACT="sep-tyranny"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "==> [$BENCH_CURRENT_CONTRACT] deploy"
CID="$(bench_deploy \
    "bench-gas-tyranny" \
    "$BENCH_ARTIFACT_DIR/sep_tyranny_contract.wasm" \
    --admin "$BENCH_DEPLOYER_ADDRESS")"

if [ -z "$CID" ]; then
    echo "    deploy failed — skipping further ops" >&2
    exit 0
fi
echo "    contract: $CID"

run_tier() {
    local tier="$1"
    local depth="$2"
    # Distinct small group id per tier: canonical Fr, and the tyranny
    # proofs bind it as group_id_fr.
    local group_id
    group_id="$(printf '0x%x' $(( 0x7777 + tier )))"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier (d=$depth) generating fresh proofs"
    bench_gen_tyranny_proofs "$depth" "$group_id" "$WORK/ty-d$depth"
    bench_gen_membership_proof "$depth" "$WORK/mp-d$depth"

    local dir="$WORK/ty-d$depth"
    local group_id_hex commitment_hex admin_comm_hex
    group_id_hex="$(cat "$dir/group_id.hex")"
    commitment_hex="$(cat "$dir/commitment.hex")"
    admin_comm_hex="$(cat "$dir/admin_pubkey_commitment.hex")"

    # The membership proof must bind the commitment create stores.
    if [ "$(bench_gen_commitment_hex "$WORK/mp-d$depth")" != "$commitment_hex" ]; then
        echo "    membership commitment does not match create commitment" >&2
        return 1
    fi

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier create_group"
    bench_invoke "$CID" "create_group" "$tier" "create_group" \
        --caller "$BENCH_DEPLOYER_ADDRESS" \
        --group-id "$group_id_hex" \
        --commitment "$commitment_hex" \
        --tier "$tier" \
        --admin-pubkey-commitment "$admin_comm_hex" \
        --proof "$(cat "$dir/create/proof.hex")" \
        --public-inputs "$(cat "$dir/create/public_inputs.json")"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier verify_membership"
    bench_invoke "$CID" "verify_membership" "$tier" "verify_membership" \
        --group-id "$group_id_hex" \
        --proof "$(bench_gen_proof_hex "$WORK/mp-d$depth")" \
        --public-inputs "$(bench_gen_pi_json "$WORK/mp-d$depth")"

    echo "==> [$BENCH_CURRENT_CONTRACT] tier=$tier update_commitment"
    bench_invoke "$CID" "update_commitment" "$tier" "update_commitment" \
        --group-id "$group_id_hex" \
        --proof "$(cat "$dir/update/proof.hex")" \
        --public-inputs "$(cat "$dir/update/public_inputs.json")"

    LAST_GROUP_ID_HEX="$group_id_hex"
}

LAST_GROUP_ID_HEX=""
run_tier 0 5
if [ "${BENCH_FULL_TIERS:-1}" = "1" ]; then
    run_tier 1 8
    run_tier 2 11
fi

echo "==> [$BENCH_CURRENT_CONTRACT] bump_group_ttl"
bench_invoke "$CID" "bump_group_ttl" "n/a" "bump_group_ttl" \
    --group-id "$LAST_GROUP_ID_HEX"

echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(true)"
bench_invoke "$CID" "set_restricted_mode" "n/a" "set_restricted_mode" \
    --restricted true

# Leave the contract unrestricted so the relayer's allowlisted callers
# can actually call create_group post-release. See sep-anarchy.sh.
echo "==> [$BENCH_CURRENT_CONTRACT] set_restricted_mode(false)"
bench_invoke_required "$CID" "set_restricted_mode(false)" "n/a" "set_restricted_mode" \
    --restricted false

echo "==> [$BENCH_CURRENT_CONTRACT] done"
