#!/usr/bin/env bash
# Top-level driver for the PQ flavor.
#
# Why a separate orchestrator vs. parameterising `run.sh`: the PLONK
# `setup.sh` builds all five PLONK contracts AND the prover-side
# `gen-membership-proof` / `gen-update-proof` binaries. The PQ flavor
# has neither additional contracts nor a prover (yet), so we keep
# the PQ flow self-contained here — no risk of breaking the PLONK
# baseline while iterating on the PQ skeleton.
#
# Emits the JSONL row stream to scripts/bench-gas/results-pq.jsonl
# and renders to results-pq.md. Different filenames so the two
# flavors can run in the same CI workspace without colliding.

set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"

BENCH_JSONL="${BENCH_JSONL:-$SCRIPT_DIR/results-pq.jsonl}"
BENCH_BODY="${BENCH_BODY:-$SCRIPT_DIR/results-pq.md}"
BENCH_NETWORK="${BENCH_NETWORK:-testnet}"
BENCH_DEPLOYER="${BENCH_DEPLOYER:-bench-gas-pq-deployer}"
BENCH_CONFIG_DIR="${BENCH_CONFIG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/bench-gas-pq-config.XXXXXX")}"
BENCH_ARTIFACT_DIR="${BENCH_ARTIFACT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/bench-gas-pq-artifacts.XXXXXX")}"

export BENCH_JSONL BENCH_NETWORK BENCH_DEPLOYER BENCH_CONFIG_DIR BENCH_ARTIFACT_DIR

: > "$BENCH_JSONL"

require_cmd() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "missing required command: $1" >&2
        exit 1
    fi
}
require_cmd cargo
require_cmd stellar
require_cmd jq
require_cmd xxd
# curl: used by lib.sh's rpc_simulate (POST simulateTransaction for
# pre-submit CPU + IO bytes) and fetch_metrics (POST getTransaction
# for post-submit mem_bytes from core_metrics events).
require_cmd curl

echo "==> bench config (PQ)"
echo "    network:      $BENCH_NETWORK"
echo "    deployer:     $BENCH_DEPLOYER"
echo "    config-dir:   $BENCH_CONFIG_DIR"
echo "    artifact-dir: $BENCH_ARTIFACT_DIR"

echo "==> deployer identity"
if stellar keys public-key "$BENCH_DEPLOYER" --config-dir "$BENCH_CONFIG_DIR" >/dev/null 2>&1; then
    echo "    reusing existing identity"
else
    stellar keys generate "$BENCH_DEPLOYER" \
        --config-dir "$BENCH_CONFIG_DIR" \
        --network "$BENCH_NETWORK" \
        --overwrite >/dev/null
    echo "    generated new identity"
fi

BENCH_DEPLOYER_ADDRESS="$(stellar keys public-key "$BENCH_DEPLOYER" --config-dir "$BENCH_CONFIG_DIR" | tr -d '\n')"
export BENCH_DEPLOYER_ADDRESS

echo "==> friendbot fund (best-effort)"
stellar keys fund "$BENCH_DEPLOYER" \
    --config-dir "$BENCH_CONFIG_DIR" \
    --network "$BENCH_NETWORK" >/dev/null 2>&1 || \
    echo "    (friendbot returned non-zero; proceeding — account may already be funded)"

# Build only what the requested drivers need (default: pq-sep-anarchy).
REQUESTED="${*:-pq-sep-anarchy}"
want() { case " $REQUESTED " in *" $1 "*) return 0 ;; esac; return 1; }
mkdir -p "$BENCH_ARTIFACT_DIR"

if want pq-sep-anarchy; then
    echo "==> building pq/sep-anarchy (default + conjectured profiles)"
    mkdir -p "$BENCH_ARTIFACT_DIR/conjectured"
    stellar contract build \
        --manifest-path "$REPO_ROOT/pq/sep-anarchy/Cargo.toml" \
        --out-dir "$BENCH_ARTIFACT_DIR" >/dev/null
    stellar contract build \
        --manifest-path "$REPO_ROOT/pq/sep-anarchy/Cargo.toml" \
        --features conjectured \
        --out-dir "$BENCH_ARTIFACT_DIR/conjectured" >/dev/null

    echo "==> building gen-pq-anarchy-bundle"
    cargo build \
        --manifest-path "$REPO_ROOT/pq/sha-fri/Cargo.toml" \
        --release \
        --features prover \
        --bin gen-pq-anarchy-bundle >/dev/null
    export BENCH_PQ_BUNDLE_BIN="$REPO_ROOT/pq/sha-fri/target/release/gen-pq-anarchy-bundle"
fi

if want pq-sep-tyranny; then
    echo "==> building pq/sep-tyranny (Pq100 profile)"
    stellar contract build \
        --manifest-path "$REPO_ROOT/pq/sep-tyranny/Cargo.toml" \
        --out-dir "$BENCH_ARTIFACT_DIR" >/dev/null

    # ext8 changes the field type, so this binary is built separately.
    echo "==> building gen-pq-tyranny-bundle"
    cargo build \
        --manifest-path "$REPO_ROOT/pq/sha-fri/Cargo.toml" \
        --release \
        --features prover,ext8 \
        --bin gen-pq-tyranny-bundle >/dev/null
    export BENCH_PQ_TYRANNY_BUNDLE_BIN="$REPO_ROOT/pq/sha-fri/target/release/gen-pq-tyranny-bundle"
fi

echo "==> setup complete"

# ---------- per-contract drivers ----------
if [ "$#" -gt 0 ]; then
    CONTRACTS=("$@")
else
    CONTRACTS=(pq-sep-anarchy)
fi

for c in "${CONTRACTS[@]}"; do
    driver="$SCRIPT_DIR/contracts/$c.sh"
    if [ ! -f "$driver" ]; then
        echo "no driver for $c at $driver" >&2
        exit 1
    fi
    bash "$driver" || echo "    [$c] driver exited non-zero — continuing"
done

echo "==> rendering markdown release body → $BENCH_BODY"
python3 "$SCRIPT_DIR/render.py" \
    --jsonl "$BENCH_JSONL" \
    --output "$BENCH_BODY" \
    --network "$BENCH_NETWORK" \
    --tag "${BENCH_TAG:-(untagged)}"

echo
echo "==> done"
echo "    jsonl: $BENCH_JSONL"
echo "    body:  $BENCH_BODY"
