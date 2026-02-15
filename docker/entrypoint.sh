#!/usr/bin/env bash
set -euo pipefail

TAU_DATA_DIR="${TAU_DATA_DIR:-/data}"
mkdir -p "${TAU_DATA_DIR}"

: "${TAU_DB_PATH:=${TAU_DATA_DIR}/node.db}"
: "${TAU_IDENTITY_KEY_PATH:=${TAU_DATA_DIR}/identity.key}"
: "${TAU_MINER_PRIVKEY_PATH:=${TAU_DATA_DIR}/test_miner.key}"
: "${TAU_MINER_PUBKEY_PATH:=${TAU_DATA_DIR}/test_miner.pub}"

export TAU_DB_PATH
export TAU_IDENTITY_KEY_PATH
export TAU_MINER_PRIVKEY_PATH
export TAU_MINER_PUBKEY_PATH

if [[ "${TAU_MINING_ENABLED:-false}" =~ ^(1|true|TRUE|yes|YES)$ ]]; then
    if [[ ! -s "${TAU_MINER_PRIVKEY_PATH}" || ! -s "${TAU_MINER_PUBKEY_PATH}" ]]; then
        echo "[entrypoint] Miner keys not found. Generating new test miner keypair in ${TAU_DATA_DIR}."
        if ! python /app/tau-testnet/scripts/generate_miner_keys.py >/tmp/tau-miner-keygen.log 2>&1; then
            echo "[entrypoint] Miner key generation failed:"
            cat /tmp/tau-miner-keygen.log
            exit 1
        fi
        mv /app/tau-testnet/test_miner.key "${TAU_MINER_PRIVKEY_PATH}"
        mv /app/tau-testnet/test_miner.pub "${TAU_MINER_PUBKEY_PATH}"
        chmod 600 "${TAU_MINER_PRIVKEY_PATH}" || true
        chmod 644 "${TAU_MINER_PUBKEY_PATH}" || true
    fi
fi

if [[ "$#" -eq 0 ]]; then
    set -- python server.py
fi

exec "$@"
