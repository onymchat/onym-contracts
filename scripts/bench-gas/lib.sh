#!/usr/bin/env bash
# Shared helpers for the testnet gas benchmark suite.
#
# Encoding contract (corrected after the v1 run on testnet showed the
# CLI receiving JSON-wrapped hex as raw bytes):
#   * `--<arg>-file-path <PATH>` reads the file as **raw bytes** and
#     binds them as the arg value. Useful only for binary-shaped types
#     when you have a binary file to feed in.
#   * For `BytesN<N>` we pass `--<arg> <hex>` inline (CLI parses hex
#     into the typed BytesN). Inline length is fine for proofs at
#     1601 bytes (~3KB hex on a Linux ARG_MAX of 128KB+).
#   * For `Vec<BytesN<32>>` we pass `--<arg> '<json_array>'` inline
#     (CLI parses JSON array of hex strings into the typed Vec).
#
# Fee capture: `stellar contract invoke` (default --send=yes) prints
# the tx hash to stderr in the line `ℹ Transaction hash is <hex>`. We
# capture stderr, grep the hash, then `stellar tx fetch fee --hash`
# to get the resource + inclusion + refund breakdown.
#
# All output rows go to a JSONL sink (BENCH_JSONL env var); the
# renderer reads them post-run.

set -euo pipefail

# ---------- low-level encoders ----------
# All encoders return hex (or JSON arrays of hex) on stdout — callers
# splice the value into the CLI invocation directly. No more temp
# files holding JSON-wrapped values; the v1 run proved the CLI's
# --<arg>-file-path treats the file as raw bytes regardless of
# extension, so JSON wrappers leaked through to the contract as
# literal `"<hex>"` byte strings.

# bin_hex <input.bin>
# Echoes raw bytes hex-encoded (no `0x`, no quotes, no newline).
# Suitable for `--<arg> $(bin_hex …)` where the arg is BytesN<N>.
bin_hex() {
    xxd -p -c 99999 "$1" | tr -d '\n'
}

# pi_concat_json_array <input.bin> <num_fields>
# Splits a flat 32*N byte file into a JSON array of N hex strings.
# Suitable for `--<arg> "$(pi_concat_json_array … )"` where the arg is
# Vec<BytesN<32>>.
pi_concat_json_array() {
    local in="$1"
    local n="$2"
    local i hex
    printf '['
    for (( i=0; i<n; i++ )); do
        hex="$(dd if="$in" bs=32 skip="$i" count=1 2>/dev/null | xxd -p -c 99999 | tr -d '\n')"
        if (( i > 0 )); then printf ','; fi
        printf '"%s"' "$hex"
    done
    printf ']'
}

# read_pi_field_hex <pi.bin> <field_index>
# Echoes the hex of the i-th 32-byte chunk in a flat PI file.
read_pi_field_hex() {
    local pi="$1"
    local i="$2"
    dd if="$pi" bs=32 skip="$i" count=1 2>/dev/null | xxd -p -c 99999 | tr -d '\n'
}

# Constants used across drivers.
ZERO32_HEX="$(printf '%064d' 0)"

# ---------- proof generators ----------
# Wrappers around the `gen-membership-proof` / `gen-update-proof`
# binaries vendored at `plonk/prover/src/bin/`. setup.sh builds them
# and exports `BENCH_PROVER_BIN_DIR` pointing at
# `plonk/prover/target/release/`. Each call writes `proof.bin`,
# `proof.hex`, `commitment.hex`, `public_inputs.json` etc. into a
# fresh out-dir; callers consume the artifacts via
# `bench_gen_proof_hex` / `bench_gen_pi_json` / `bench_gen_commitment_hex`.
#
# Witness defaults are baked in below — they're shape-only fixtures
# (the VK is shape-dependent, not witness-dependent), so the same
# (secret_keys, prover_index) works at every depth.

# 8 canonical secret keys; tree pads beyond that. prover_index=3.
BENCH_GEN_SECRET_KEYS='0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08'
BENCH_GEN_PROVER_INDEX='3'
BENCH_GEN_SALT_OLD='0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'
BENCH_GEN_SALT_NEW='0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

# bench_gen_membership_proof <depth> <out_dir>
# Generates a membership proof at the given depth (5/8/11) at epoch 0
# with the canonical witness. Writes proof.bin / commitment.hex /
# public_inputs.json into out_dir.
bench_gen_membership_proof() {
    local depth="$1"
    local out_dir="$2"
    mkdir -p "$out_dir"
    "${BENCH_PROVER_BIN_DIR}/gen-membership-proof" \
        --depth "$depth" \
        --epoch 0 \
        --salt "$BENCH_GEN_SALT_OLD" \
        --secret-keys "$BENCH_GEN_SECRET_KEYS" \
        --prover-index "$BENCH_GEN_PROVER_INDEX" \
        --out-dir "$out_dir" >&2
}

# bench_gen_update_proof <depth> <out_dir>
# Generates an update proof at the given depth: c_old comes from the
# epoch=0 / salt_old witness (matches `bench_gen_membership_proof`'s
# commitment), c_new comes from the epoch=1 / salt_new witness.
# Re-using salt_old here keeps c_old aligned with the post-create
# state set by the membership-proof's create_group call.
bench_gen_update_proof() {
    local depth="$1"
    local out_dir="$2"
    mkdir -p "$out_dir"
    "${BENCH_PROVER_BIN_DIR}/gen-update-proof" \
        --depth "$depth" \
        --epoch-old 0 \
        --salt-old "$BENCH_GEN_SALT_OLD" \
        --salt-new "$BENCH_GEN_SALT_NEW" \
        --secret-keys "$BENCH_GEN_SECRET_KEYS" \
        --prover-index "$BENCH_GEN_PROVER_INDEX" \
        --out-dir "$out_dir" >&2
}

# Helpers to read out-dir artifacts back as shell-safe strings.
bench_gen_proof_hex() { cat "$1/proof.hex"; }
bench_gen_pi_json()   { cat "$1/public_inputs.json"; }
bench_gen_commitment_hex() { cat "$1/commitment.hex"; }

# ---------- PQ FRI proof generators ----------
# Wrappers around the `gen-pq-proof` binary in `pq/prover/`. The PQ
# orchestrator (`run-pq.sh`) builds the binary and exports
# `BENCH_PQ_PROVER_BIN`; these helpers shell out to it. Output
# artefacts share the layout the PLONK helpers above produce
# (proof.bin / proof.hex / commitment.hex / public_inputs.json) so
# `bench_gen_proof_hex` etc. work unchanged.
#
# Bench-only: the prover produces self-consistent FRI proofs the
# on-chain verifier accepts but does NOT prove anything about an
# underlying circuit (no batched-PCS layer yet). Use only for gas
# measurement.

# bench_gen_pq_membership_proof <commitment_hex_64> <epoch_u64> <out_dir>
bench_gen_pq_membership_proof() {
    local commitment_hex="$1"
    local epoch="$2"
    local out_dir="$3"
    mkdir -p "$out_dir"
    "$BENCH_PQ_PROVER_BIN" \
        --circuit membership \
        --commitment "$commitment_hex" \
        --epoch "$epoch" \
        --out-dir "$out_dir" >&2
}

# bench_gen_pq_update_proof <c_old_hex_64> <epoch_old_u64> <c_new_hex_64> <out_dir>
bench_gen_pq_update_proof() {
    local c_old_hex="$1"
    local epoch_old="$2"
    local c_new_hex="$3"
    local out_dir="$4"
    mkdir -p "$out_dir"
    "$BENCH_PQ_PROVER_BIN" \
        --circuit update \
        --commitment "$c_old_hex" \
        --epoch "$epoch_old" \
        --new-commitment "$c_new_hex" \
        --out-dir "$out_dir" >&2
}

# ---------- invocation + fee capture ----------

# capture_tx_hashes <stderr_logfile>
# Echoes every transaction hash the stellar CLI logged, one per line,
# in submission order.
#
# Two patterns matched, in fallback order:
#   1. stellar.expert URL — printed only AFTER the network accepts a
#      tx, so on testnet/public this filters out simulation-only
#      failures cleanly.
#   2. `Signing transaction: <hex>` — what the CLI prints on local,
#      where there's no stellar.expert explorer. This line fires for
#      both submitted and failed-to-submit txs (signing precedes
#      submission), so on local we lose the testnet's
#      "skip-failures" property — but `stellar tx fetch fee` returns
#      empty for un-submitted hashes, so emit_row falls back to null
#      fee fields, same outcome as not capturing.
#
# `stellar contract deploy` submits two txs (upload_contract_wasm +
# create_contract); a normal invoke submits one. Callers pick by
# index.
capture_tx_hashes() {
    local err="$1"
    local hashes
    hashes="$(grep -oE 'stellar\.expert/explorer/[a-z]+/tx/[0-9a-f]{64}' "$err" \
        | grep -oE '[0-9a-f]{64}')"
    if [ -n "$hashes" ]; then
        printf '%s\n' "$hashes"
        return 0
    fi
    grep -oE 'Signing transaction: [0-9a-f]{64}' "$err" \
        | grep -oE '[0-9a-f]{64}'
}

# capture_tx_hash <stderr_logfile>
# Convenience: first hash from `capture_tx_hashes`. Empty if none.
capture_tx_hash() {
    capture_tx_hashes "$1" | head -1
}

# fetch_fee_stroops <hash>
# Echoes the total fee_charged in stroops, parsed from
# `stellar tx fetch fee --output json`.
fetch_fee_stroops() {
    local hash="$1"
    local rpc_args=()
    if [ -n "${BENCH_NETWORK:-}" ]; then
        rpc_args=(--network "$BENCH_NETWORK")
    fi
    if [ -n "${BENCH_CONFIG_DIR:-}" ]; then
        rpc_args=(--config-dir "$BENCH_CONFIG_DIR" "${rpc_args[@]}")
    fi
    stellar tx fetch fee --hash "$hash" --output json "${rpc_args[@]}" \
        | jq -r '.totals.fee_charged // .fee_charged // empty'
}

# fetch_fee_full <hash>
# Echoes JSON with both fee_charged (net) + resource breakdown when
# available. Used by the JSONL emitter.
fetch_fee_full() {
    local hash="$1"
    local rpc_args=()
    if [ -n "${BENCH_NETWORK:-}" ]; then
        rpc_args=(--network "$BENCH_NETWORK")
    fi
    if [ -n "${BENCH_CONFIG_DIR:-}" ]; then
        rpc_args=(--config-dir "$BENCH_CONFIG_DIR" "${rpc_args[@]}")
    fi
    stellar tx fetch fee --hash "$hash" --output json "${rpc_args[@]}"
}

# emit_contract_address <contract> <address>
# One row per deployed contract — the renderer pulls these into the
# stellar.expert link table at the top of the release body.
emit_contract_address() {
    local contract="$1"
    local address="$2"
    if [ -z "$address" ]; then
        return 0
    fi
    jq -nc \
        --arg row_type "contract" \
        --arg contract "$contract" \
        --arg address "$address" \
        '{row_type: $row_type, contract: $contract, address: $address}' \
        >> "$BENCH_JSONL"
}

# emit_row <contract> <op> <tier> <hash> [extra_json]
# Append a JSONL row to $BENCH_JSONL with fee + cost data for the tx.
emit_row() {
    local contract="$1"
    local op="$2"
    local tier="$3"
    local hash="$4"
    # The literal `{}` default has to be assigned out-of-band: bash
    # parameter expansion `${5:-{\}}` preserves the backslash on
    # bash 3.2 (macOS), expanding to `{\}` (3 chars) which `jq
    # --argjson` rejects as invalid JSON. Escaping inside the
    # expansion isn't portable — keep it simple and assign the
    # default after the fact.
    local extra="${5:-}"
    [ -n "$extra" ] || extra='{}'

    if [ -z "$hash" ]; then
        # Fee capture failed (the tx wasn't submitted — most often the
        # CLI rejected it at simulation time, or it's a read-only
        # entrypoint that short-circuits to local sim). Emit a row
        # with null fee fields so the renderer can flag it.
        jq -nc \
            --arg row_type "op" \
            --arg contract "$contract" \
            --arg op "$op" \
            --arg tier "$tier" \
            --argjson extra "$extra" \
            '{row_type: $row_type, contract: $contract, op: $op, tier: $tier, fee_stroops: null, hash: null} + $extra' \
            >> "$BENCH_JSONL"
        return 0
    fi

    local raw
    raw="$(fetch_fee_full "$hash" 2>/dev/null || echo '{}')"
    # Race: `stellar tx fetch fee` can return non-JSON when the RPC's
    # indexer hasn't caught up to a just-submitted tx (more likely on
    # fast hardware than on a CI runner). Validate; on miss, brief
    # sleep + retry; on second miss, fall through to `{}` so the row
    # still emits with null fee fields rather than killing the bench.
    if ! printf '%s' "$raw" | jq -e . >/dev/null 2>&1; then
        sleep 3
        raw="$(fetch_fee_full "$hash" 2>/dev/null || echo '{}')"
        if ! printf '%s' "$raw" | jq -e . >/dev/null 2>&1; then
            raw='{}'
        fi
    fi

    # Post-submit host-budget metrics — the only path on Protocol 23+
    # that exposes `mem_bytes`. Same indexer-race tolerance as fees:
    # the fee retry above usually warms the cache by the time we get
    # here, but we still validate + accept `{}` on miss so a metrics
    # gap doesn't kill the row.
    local metrics
    metrics="$(fetch_metrics "$hash" 2>/dev/null || echo '{}')"
    if ! printf '%s' "$metrics" | jq -e . >/dev/null 2>&1; then
        metrics='{}'
    fi

    # `stellar tx fetch fee --output json` returns
    #   { "proposed": {fee, resource_fee, inclusion_fee},
    #     "charged":  {fee, resource_fee, inclusion_fee,
    #                  non_refundable_resource_fee, refundable_resource_fee} }
    # `charged.fee` is the net amount the source account paid; that's
    # what we surface as the headline `fee_stroops`. `proposed` is what
    # the simulator pre-allocated — useful diagnostic, kept under
    # `proposed_fee` for the renderer.
    #
    # Merge order `... + $extra + $metrics` puts post-submit metrics
    # last so they win on key conflicts (today only `mem_bytes`, but
    # leaves room for future post-submit fields without breaking
    # callers that already populate something via `simulate_cost`).
    jq -nc \
        --arg row_type "op" \
        --arg contract "$contract" \
        --arg op "$op" \
        --arg tier "$tier" \
        --arg hash "$hash" \
        --argjson raw "$raw" \
        --argjson extra "$extra" \
        --argjson metrics "$metrics" \
        '{row_type: $row_type, contract: $contract, op: $op, tier: $tier, hash: $hash,
          fee_stroops: $raw.charged.fee,
          inclusion_fee: $raw.charged.inclusion_fee,
          resource_fee: $raw.charged.resource_fee,
          non_refundable_resource_fee: $raw.charged.non_refundable_resource_fee,
          refundable_resource_fee: $raw.charged.refundable_resource_fee,
          proposed_fee: $raw.proposed.fee,
          raw: $raw} + $extra + $metrics' \
        >> "$BENCH_JSONL"
}

# ---------- deploy + invoke wrappers ----------

# bench_deploy <contract_alias> <wasm> <constructor_args...>
# Deploys and echoes the contract id on stdout. `stellar contract
# deploy` v26 batches upload + create into a single transaction
# (one tx hash, one stellar.expert URL printed) — the second 🔗
# line in the output is the lab.stellar.org **contract** URL, not
# a tx URL. So we emit a single `deploy` row with the captured
# fee.
bench_deploy() {
    local alias="$1"
    local wasm="$2"
    shift 2

    local err
    err="$(mktemp)"

    local cid
    cid="$(stellar contract deploy \
        --config-dir "$BENCH_CONFIG_DIR" \
        --network "$BENCH_NETWORK" \
        --source-account "$BENCH_DEPLOYER" \
        --alias "$alias" \
        --wasm "$wasm" \
        -- "$@" 2> "$err" | tr -d '\n')" || cid=""

    cat "$err" >&2

    local hash
    hash="$(capture_tx_hash "$err" || true)"
    rm -f "$err"

    emit_row "$BENCH_CURRENT_CONTRACT" "deploy" "n/a" "$hash"
    emit_contract_address "$BENCH_CURRENT_CONTRACT" "$cid"
    printf '%s' "$cid"
}

# ---------- pre-flight simulation + post-submit metrics ----------
#
# `simulate_cost` posts `simulateTransaction` directly to soroban-rpc
# via `rpc_simulate`. We hit the JSON-RPC endpoint instead of shelling
# out to `stellar tx simulate` because the response carries
# `transactionData` (a base64 SorobanTransactionData), which we decode
# to pull the simulator's declared CPU + IO byte counters from
# `resources` — exactly the counters the renderer surfaces.
#
# `fetch_metrics` posts `getTransaction` for a submitted tx and
# decodes its `diagnosticEventsXdr` to pull `core_metrics.mem_byte`,
# the only path that exposes memory burn on Protocol 23+. Memory is
# enforced as a runtime host budget — not declared as a tx-level
# resource — so it never appears in `transactionData.resources`, and
# soroban-rpc removed the legacy `result.cost.memBytes` field.
#
# Why pre-flight sim, not post-mortem: state-mutating ops (e.g.
# `create_group` writing the `UsedProof` nullifier) see the same
# pre-state the on-chain run will see only if we sim BEFORE
# submitting. The roundtrip cost is fine for a small bench.

# bench_rpc_url
# Echoes the soroban-rpc URL for $BENCH_NETWORK. Reads from the stellar
# CLI network config (toml at $BENCH_CONFIG_DIR/network/<name>.toml).
# Falls back to a $BENCH_RPC_URL override, then to network-name
# defaults. Empty when unresolvable.
bench_rpc_url() {
    if [ -n "${BENCH_RPC_URL:-}" ]; then
        printf '%s' "$BENCH_RPC_URL"
        return 0
    fi
    local cfg="${BENCH_CONFIG_DIR:-}/network/${BENCH_NETWORK:-}.toml"
    if [ -f "$cfg" ]; then
        local url
        url="$(grep -E '^[[:space:]]*rpc[_-]?url' "$cfg" \
            | head -1 \
            | sed -E 's/.*"([^"]*)".*/\1/')"
        if [ -n "$url" ]; then
            printf '%s' "$url"
            return 0
        fi
    fi
    case "${BENCH_NETWORK:-}" in
        testnet) printf '%s' 'https://soroban-testnet.stellar.org' ;;
        mainnet) printf '%s' 'https://soroban.stellar.org' ;;
        local)   printf '%s' 'http://localhost:8000/rpc' ;;
        *)       printf '%s' '' ;;
    esac
}

# rpc_simulate <contract_id> <fn> <fn_args...>
# Builds an unsigned tx envelope (`stellar contract invoke
# --build-only`) and POSTs it to soroban-rpc's `simulateTransaction`
# JSON-RPC endpoint. Echoes the raw JSON response on stdout, empty on
# any failure path. `simulate_cost` decodes `result.transactionData`
# (base64 SorobanTransactionData XDR) for CPU + IO byte counters.
rpc_simulate() {
    command -v curl >/dev/null 2>&1 || return 0

    local cid="$1"
    local fn="$2"
    shift 2

    local url
    url="$(bench_rpc_url)"
    [ -n "$url" ] || return 0

    local tx_xdr
    tx_xdr="$(stellar contract invoke \
        --config-dir "$BENCH_CONFIG_DIR" \
        --network "$BENCH_NETWORK" \
        --id "$cid" \
        --source-account "$BENCH_DEPLOYER" \
        --build-only \
        -- "$fn" "$@" 2>/dev/null)" || return 0
    [ -n "$tx_xdr" ] || return 0

    local payload
    payload="$(jq -nc --arg tx "$tx_xdr" \
        '{jsonrpc:"2.0",id:1,method:"simulateTransaction",params:{transaction:$tx}}')"

    local resp
    resp="$(curl -sS -X POST -H 'Content-Type: application/json' \
        --max-time 20 \
        -d "$payload" "$url" 2>/dev/null)" || return 0
    [ -n "$resp" ] || return 0
    printf '%s' "$resp" | jq -e . >/dev/null 2>&1 || return 0
    printf '%s' "$resp"
}

# simulate_cost <contract_id> <fn> <fn_args...>
# Echoes a compact JSON object on stdout for `emit_row`'s extras:
#   {"cpu_insns": N, "read_bytes": N, "write_bytes": N}
# `{}` on any failure. Pulls all three from `result.transactionData`
# (a base64-encoded SorobanTransactionData XDR; `resources` block
# carries the simulator's declared budget for the tx).
#
# What's NOT here: `mem_bytes`. Soroban-rpc removed `result.cost`
# entirely on Protocol 23+, and memory has never been a tx-declared
# resource — only a runtime host budget. The only path that exposes
# memory is the post-submit `core_metrics_event` diagnostic event on
# a real execution; `fetch_metrics` (called from `emit_row`) handles
# that.
simulate_cost() {
    local cid="$1"
    local fn="$2"
    shift 2

    local resp
    resp="$(rpc_simulate "$cid" "$fn" "$@")"
    [ -n "$resp" ] || { echo '{}'; return 0; }

    # `transactionData` is the base64-encoded SorobanTransactionData
    # XDR (NOT a TransactionEnvelope). Its `resources` block carries
    # `instructions` (the declared CPU budget), `disk_read_bytes`,
    # and `write_bytes`. On budget failures `transactionData` may be
    # absent; treat decode failure as "no data" and emit `{}`.
    local td_b64
    td_b64="$(printf '%s' "$resp" | jq -r '.result.transactionData // empty')"
    [ -n "$td_b64" ] || { echo '{}'; return 0; }

    local resources
    resources="$(stellar xdr decode \
        --type SorobanTransactionData \
        --output json "$td_b64" 2>/dev/null \
        | jq -c '.resources // {}')" || { echo '{}'; return 0; }
    [ -z "$resources" ] || [ "$resources" = "{}" ] && { echo '{}'; return 0; }

    # Field name is `disk_read_bytes` in the v1 SorobanResources XDR
    # (write_bytes keeps the unprefixed name). `// null` keeps the row
    # well-formed under future schema bumps.
    jq -nc --argjson r "$resources" '
        {
          cpu_insns:   ($r.instructions     // null),
          read_bytes:  ($r.disk_read_bytes  // null),
          write_bytes: ($r.write_bytes      // null)
        }'
}

# fetch_metrics <hash>
# Calls `getTransaction` for a submitted tx and decodes
# `diagnosticEventsXdr` to extract host runtime budget burn from
# `core_metrics` events. Echoes JSON `{"mem_bytes": N}` on success,
# `{}` on miss. This is the ONLY path that exposes `mem_bytes` on
# Protocol 23+ — `simulateTransaction.result.cost` is gone, and
# memory is enforced as a runtime host budget (not a declared tx
# resource), so it surfaces only after a real execution.
#
# We don't touch `cpu_insns` here — `simulate_cost`'s pre-submit
# value (from `transactionData.resources.instructions`) is the
# simulator's declared CPU budget and is what the renderer uses for
# the `% of cap` headroom column. The post-submit `core_metrics.cpu_insn`
# is the actual burn (typically 5–10% lower); we leave that to a
# future schema bump if useful.
fetch_metrics() {
    local hash="$1"
    [ -n "$hash" ] || { echo '{}'; return 0; }

    command -v curl >/dev/null 2>&1 || { echo '{}'; return 0; }

    local url
    url="$(bench_rpc_url)"
    [ -n "$url" ] || { echo '{}'; return 0; }

    local payload resp
    payload="$(jq -nc --arg h "$hash" \
        '{jsonrpc:"2.0",id:1,method:"getTransaction",params:{hash:$h}}')"
    resp="$(curl -sS -X POST -H 'Content-Type: application/json' --max-time 20 \
        -d "$payload" "$url" 2>/dev/null)" || { echo '{}'; return 0; }
    [ -n "$resp" ] || { echo '{}'; return 0; }
    printf '%s' "$resp" | jq -e . >/dev/null 2>&1 || { echo '{}'; return 0; }

    # Walk diagnosticEventsXdr; each entry is a base64 DiagnosticEvent.
    # core_metrics events have shape:
    #   topics = ["core_metrics", <metric_name>], data.u64 = <value>
    # We only surface mem_byte today; extending to other metrics is
    # a one-line change (add a case to the inner case statement).
    local mem_byte=
    while IFS= read -r ev_b64; do
        [ -z "$ev_b64" ] && continue
        local pair
        pair="$(stellar xdr decode --type DiagnosticEvent --output json "$ev_b64" 2>/dev/null \
            | jq -r '
                .event.body.v0 as $b |
                if ($b.topics // [] | length >= 2)
                   and (($b.topics[0].symbol // "") == "core_metrics")
                then "\($b.topics[1].symbol)=\($b.data.u64 // $b.data.u32 // "")"
                else empty end
              ')" || continue
        case "$pair" in
            mem_byte=*) mem_byte="${pair#mem_byte=}" ;;
        esac
    done < <(printf '%s' "$resp" | jq -r '.result.diagnosticEventsXdr[]? // empty')

    if [ -n "$mem_byte" ]; then
        jq -nc --arg m "$mem_byte" '{mem_bytes: ($m | tonumber)}'
    else
        echo '{}'
    fi
}

# bench_invoke <contract_id> <op> <tier> <fn> <fn_args...>
# Submits the call, captures tx hash, fetches fee, emits a JSONL row.
# Uses --send=yes so we get a real fee_charged even on revert paths.
# A non-zero CLI exit (e.g. revert) is intentional for revert-mode
# benches and does not abort the run.
bench_invoke() {
    local cid="$1"
    local op="$2"
    local tier="$3"
    local fn="$4"
    shift 4

    # Capture host CPU instructions + I/O bytes from a pre-flight sim
    # so the JSONL row records the raw counters (post-submit fee data
    # alone doesn't expose them in CLI v22+). Empty `{}` on failure —
    # `emit_row` merges it as-is.
    local cost_extra
    cost_extra="$(simulate_cost "$cid" "$fn" "$@")"

    local err
    err="$(mktemp)"

    stellar contract invoke \
        --config-dir "$BENCH_CONFIG_DIR" \
        --network "$BENCH_NETWORK" \
        --id "$cid" \
        --source-account "$BENCH_DEPLOYER" \
        --send yes \
        -- "$fn" "$@" \
        > /dev/null 2> "$err" || true

    cat "$err" >&2

    local hash
    hash="$(capture_tx_hash "$err" || true)"
    rm -f "$err"

    emit_row "$BENCH_CURRENT_CONTRACT" "$op" "$tier" "$hash" "$cost_extra"
}

# bench_invoke_required <contract_id> <op> <tier> <fn> <fn_args...>
# Same as bench_invoke, but fails the script if the CLI invocation
# fails or does not submit a transaction. Use this for release cleanup
# that determines the published contract's final state.
bench_invoke_required() {
    local cid="$1"
    local op="$2"
    local tier="$3"
    local fn="$4"
    shift 4

    local err
    err="$(mktemp)"

    local status=0
    stellar contract invoke \
        --config-dir "$BENCH_CONFIG_DIR" \
        --network "$BENCH_NETWORK" \
        --id "$cid" \
        --source-account "$BENCH_DEPLOYER" \
        --send yes \
        -- "$fn" "$@" \
        > /dev/null 2> "$err" || status=$?

    cat "$err" >&2

    local hash
    hash="$(capture_tx_hash "$err" || true)"
    rm -f "$err"

    if [ "$status" -ne 0 ]; then
        return "$status"
    fi

    emit_row "$BENCH_CURRENT_CONTRACT" "$op" "$tier" "$hash"

    if [ -z "$hash" ]; then
        echo "error: required invoke submitted no transaction: $fn" >&2
        return 1
    fi
}
