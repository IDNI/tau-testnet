#!/usr/bin/env bash
# Smoke-test the tau-testnet packaging path: editable install, CLI surface,
# and key generation. The slow Docker build is opt-in via SMOKE_DOCKER=1.
#
# Usage:
#   bash scripts/package_smoke_test.sh                # fast path (~30s)
#   SMOKE_DOCKER=1 bash scripts/package_smoke_test.sh # also runs docker build (5-15 min)
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT_DIR}"

PYTHON="${PYTHON:-python3}"

# Resolve `tau-testnet` next to the chosen Python interpreter (so the script
# works whether or not the caller activated a virtualenv).
PYTHON_BIN_DIR="$(${PYTHON} -c 'import sys, os; print(os.path.dirname(sys.executable))')"
TAU_TESTNET="${PYTHON_BIN_DIR}/tau-testnet"

echo "[smoke] python: $(${PYTHON} --version 2>&1)"
echo "[smoke] root:   ${ROOT_DIR}"

echo "[smoke] step 1: pip install -e ."
${PYTHON} -m pip install -e . > /tmp/tau-smoke-install.log 2>&1 || {
    echo "[smoke] FAIL: pip install -e ."
    tail -20 /tmp/tau-smoke-install.log
    exit 1
}

echo "[smoke] step 2: tau-testnet --help"
"${TAU_TESTNET}" --help > /dev/null

echo "[smoke] step 3: python -m tau_testnet_cli --help"
${PYTHON} -m tau_testnet_cli --help > /dev/null

echo "[smoke] step 4: tau-testnet version"
"${TAU_TESTNET}" version

echo "[smoke] step 5: tau-testnet keys new --json (validates BLS key generation)"
TMPKEY="$(mktemp)"
trap 'rm -f "${TMPKEY}"' EXIT
"${TAU_TESTNET}" keys new --json > "${TMPKEY}"
${PYTHON} - <<PY
import json
with open("${TMPKEY}") as f:
    data = json.load(f)
assert "private_key_hex" in data and len(data["private_key_hex"]) == 64
assert "public_key_hex"  in data and len(data["public_key_hex"]) == 96
print("[smoke] keys new --json shape OK")
PY

if [[ "${SMOKE_DOCKER:-0}" == "1" ]]; then
    echo "[smoke] step 6 (SMOKE_DOCKER=1): tau-testnet node docker-build --jobs 2"
    "${TAU_TESTNET}" node docker-build --jobs 2
else
    echo "[smoke] step 6 skipped (set SMOKE_DOCKER=1 to run 'node docker-build --jobs 2', adds 5-15 minutes)"
fi

echo "[smoke] OK"
