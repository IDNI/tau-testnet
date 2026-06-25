#!/usr/bin/env bash
# Join the tau-testnet-v2 network from a fresh checkout.
#
#   ./networks/tau-testnet-v2/join.sh
#
# Copies the canonical genesis artifact into data/, loads the network env
# (network id + bootnode), and starts the node. Requires the CLI to be
# installed already (`pip install -e .`) and, for the real engine, the
# tau-lang native bindings built (see README "Run from source").
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

mkdir -p "$REPO/data"
cp "$HERE/genesis.json" "$REPO/data/genesis.json"
echo "[join] genesis.json -> data/genesis.json"

set -a
# shellcheck disable=SC1091
. "$HERE/env"
set +a
echo "[join] network_id=$TAU_NETWORK_ID bootnode=$TAU_BOOTSTRAP_PEERS"

cd "$REPO"
exec tau-testnet node run --no-isolated
