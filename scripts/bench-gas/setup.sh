#!/usr/bin/env bash
# Provision the bench environment: deployer identity, friendbot fund,
# contract builds. Idempotent — safe to re-run.
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO_ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/../.." && pwd)"
BENCH_REPO_ROOT="$REPO_ROOT"

BENCH_NETWORK="${BENCH_NETWORK:-testnet}"
BENCH_DEPLOYER="${BENCH_DEPLOYER:-bench-gas-deployer}"
BENCH_CONFIG_DIR="${BENCH_CONFIG_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/bench-gas-config.XXXXXX")}"
BENCH_ARTIFACT_DIR="${BENCH_ARTIFACT_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/bench-gas-artifacts.XXXXXX")}"

export BENCH_NETWORK BENCH_DEPLOYER BENCH_CONFIG_DIR BENCH_ARTIFACT_DIR BENCH_REPO_ROOT

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

echo "==> bench config"
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

echo "==> building contracts"
mkdir -p "$BENCH_ARTIFACT_DIR"
for c in sep-anarchy sep-democracy sep-oligarchy sep-oneonone sep-tyranny; do
    echo "    $c"
    stellar contract build \
        --manifest-path "$REPO_ROOT/plonk/$c/Cargo.toml" \
        --out-dir "$BENCH_ARTIFACT_DIR" >/dev/null
done

# Runtime proof generators for the sep-anarchy chained bench
# (`create_group → verify_membership → update_commitment`). The
# committed canonical fixtures are baked at epoch=1234 — useful for
# cross-platform VK fingerprinting but unusable against `create_group`,
# which requires `PI[1] == be32(0)`. So the bench builds these two
# binaries from the in-repo prover (`plonk/prover/`) and the driver
# generates fresh epoch=0 proofs that chain end-to-end.
#
# sep-democracy uses the committed `democracy-{create,membership}-*-d{N}.bin`
# fixtures directly (their canonical witnesses already use epoch=0).
echo "==> building proof generators"
cargo build \
    --manifest-path "$REPO_ROOT/plonk/prover/Cargo.toml" \
    --release \
    --bin gen-membership-proof \
    --bin gen-update-proof >/dev/null
export BENCH_PROVER_BIN_DIR="$REPO_ROOT/plonk/prover/target/release"

echo "==> setup complete"
