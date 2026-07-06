#!/usr/bin/env bash
# Idempotent setup for the 4-node stake-switch demo network.
#   - 5 BLS keypairs (node1..node4 + treasury) in demo/keys/
#   - 4 libp2p identity keys demo/node{1..4}/identity.key (+ node1 peer id)
#   - rendered stake revision demo/stake_consensus_revision.tau
#   - genesis.json (3 validators, treasury pre-funded) copied per node
#   - demo/.env with privkeys + NODE1_PEER_ID
# Re-runnable: existing keys/identities/genesis are kept.
set -euo pipefail

cd "$(dirname "$0")/.."          # repo root
DEMO="demo"
PY="venv/bin/python"

mkdir -p "$DEMO/keys"

echo "[setup] BLS keypairs (node1..node4, treasury)"
for name in node1 node2 node3 node4 treasury; do
    if [[ -s "$DEMO/keys/$name.priv" && -s "$DEMO/keys/$name.pub" ]]; then
        continue
    fi
    "$PY" - "$DEMO/keys/$name" <<'PYEOF'
import sys
from scripts.gen import generate_bls12_381_keypair
base = sys.argv[1]
_, priv_hex, pub_hex = generate_bls12_381_keypair()
open(base + ".priv", "w").write(priv_hex)
open(base + ".pub", "w").write(pub_hex)
PYEOF
    echo "  generated $name"
done

echo "[setup] libp2p identity keys"
for n in 1 2 3 4; do
    mkdir -p "$DEMO/node$n/data"
    if [[ ! -s "$DEMO/node$n/identity.key" ]]; then
        "$PY" scripts/print_peer_id.py --generate "$DEMO/node$n/identity.key" >/dev/null 2>&1
        echo "  generated node$n/identity.key"
    fi
done
# print_peer_id emits library log lines on stdout before the id; the id is the
# last line, so take only that.
NODE1_PEER_ID="$("$PY" scripts/print_peer_id.py "$DEMO/node1/identity.key" 2>/dev/null | tail -n1)"
echo "  node1 peer id: $NODE1_PEER_ID"

echo "[setup] render stake revision (threshold 100000)"
"$PY" "$DEMO/render_revision.py" --stake-threshold 100000 > "$DEMO/stake_consensus_revision.tau"

echo "[setup] genesis.json (validators = node1/2/3; treasury funded 1000000)"
"$PY" scripts/gen_genesis.py \
    --validator-key "$(cat "$DEMO/keys/node1.pub")" \
    --validator-key "$(cat "$DEMO/keys/node2.pub")" \
    --validator-key "$(cat "$DEMO/keys/node3.pub")" \
    --account "$(cat "$DEMO/keys/treasury.pub"):1000000" \
    --genesis-consensus-path "$DEMO/genesis_consensus_demo.tau" \
    --base-fee 0 --vote-quorum supermajority \
    --network-id tau-demo-stake \
    --out "$DEMO/genesis.json"

echo "[setup] distribute genesis.json to each node"
for n in 1 2 3 4; do
    cp "$DEMO/genesis.json" "$DEMO/node$n/genesis.json"
done

echo "[setup] write demo/.env"
{
    echo "NODE1_PRIVKEY=$(cat "$DEMO/keys/node1.priv")"
    echo "NODE2_PRIVKEY=$(cat "$DEMO/keys/node2.priv")"
    echo "NODE3_PRIVKEY=$(cat "$DEMO/keys/node3.priv")"
    echo "NODE4_PRIVKEY=$(cat "$DEMO/keys/node4.priv")"
    echo "NODE1_PEER_ID=$NODE1_PEER_ID"
} > "$DEMO/.env"

echo "[setup] done. Next: docker compose -f demo/docker-compose.yml --env-file demo/.env up -d --build"
