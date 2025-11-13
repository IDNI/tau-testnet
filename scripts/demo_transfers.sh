#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")"/.. && pwd -P)"
PY="$DIR/venv/bin/python3"
WALLET="$DIR/wallet.py"

# Default node RPC endpoint (must be running separately)
HOST="127.0.0.1"
PORT="65432"
DB_PATH="$DIR/strings.db"

# Identities (from chain_state.py)
ALICE_SK="11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09"
BOB_SK="06bc6e6e15a4b40df028da6901e471fa1facc5e9fad04408ab864c7ccb036aa3"
CHARLIE_SK="856a44bee7630b40c4f91576037c8eebb729af956c608e447aa7afd6c80c3d45"

RESET="0"

usage() {
  echo "Usage: $0 [--reset] [--host HOST] [--port PORT] [--blocks N] [--tx-per-block M] [--max-amount A]"
  echo "       When --blocks/--tx-per-block are provided, runs a configurable randomized demo:"
  echo "         - --blocks N: number of blocks to create (0 means no blocks)"
  echo "         - --tx-per-block M: number of random transactions to send per block (or total if --blocks=0)"
  echo "         - --max-amount A: max random transfer amount (default 100)"
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --reset)
      RESET="1"; shift ;;
    --host)
      HOST="${2:-$HOST}"; shift 2 ;;
    --port)
      PORT="${2:-$PORT}"; shift 2 ;;
    --blocks)
      BLOCKS="${2:-}"; shift 2 ;;
    --tx-per-block)
      TX_PER_BLOCK="${2:-}"; shift 2 ;;
    --max-amount)
      MAX_AMOUNT="${2:-$MAX_AMOUNT}"; shift 2 ;;
    -h|--help)
      usage; exit 0 ;;
    *)
      echo "Unknown option: $1"; usage; exit 1 ;;
  esac
done

export TAU_DB_PATH="$DB_PATH"

if [[ "$RESET" == "1" ]]; then
  echo "[RESET] Removing DB at $DB_PATH (TAU_DB_PATH)"
  rm -f "$DB_PATH"
fi

echo "[INFO] Using node at $HOST:$PORT"

# Optional randomized demo parameters (set by flags). If unset, the script
# will run the original fixed-sequence demo below for backward compatibility.
BLOCKS="${BLOCKS:-}"
TX_PER_BLOCK="${TX_PER_BLOCK:-}"
MAX_AMOUNT="${MAX_AMOUNT:-100}"

# Derive valid (sk, pk) pair from a provided 32-byte hex. If the hex is not a valid
# private key per py_ecc, use it as IKM seed to KeyGen to derive a valid key.
derive_pair() {
  "$PY" - "$@" <<'PY'
from py_ecc.bls import G2Basic
from eth_utils import ValidationError
import sys
ikm_hex = sys.argv[1]
ikm = bytes.fromhex(ikm_hex)
sk_int = int.from_bytes(ikm, 'big')
try:
    pk = G2Basic.SkToPk(sk_int)
    sk_bytes = ikm
except ValidationError:
    # Derive from seed using KeyGen to ensure validity
    sk_int = G2Basic.KeyGen(ikm)
    sk_bytes = sk_int.to_bytes(32, 'big')
    pk = G2Basic.SkToPk(sk_int)
print(sk_bytes.hex())
print(pk.hex())
PY
}

ALICE_SK_FINAL_AND_ADDR="$(derive_pair "$ALICE_SK")"
ALICE_SK_FINAL="$(echo "$ALICE_SK_FINAL_AND_ADDR" | sed -n '1p')"
ALICE_ADDR="$(echo "$ALICE_SK_FINAL_AND_ADDR" | sed -n '2p')"

BOB_SK_FINAL_AND_ADDR="$(derive_pair "$BOB_SK")"
BOB_SK_FINAL="$(echo "$BOB_SK_FINAL_AND_ADDR" | sed -n '1p')"
BOB_ADDR="$(echo "$BOB_SK_FINAL_AND_ADDR" | sed -n '2p')"

CHARLIE_SK_FINAL_AND_ADDR="$(derive_pair "$CHARLIE_SK")"
CHARLIE_SK_FINAL="$(echo "$CHARLIE_SK_FINAL_AND_ADDR" | sed -n '1p')"
CHARLIE_ADDR="$(echo "$CHARLIE_SK_FINAL_AND_ADDR" | sed -n '2p')"

echo "[INFO] Alice  : $ALICE_ADDR"
echo "[INFO] Bob    : $BOB_ADDR"
echo "[INFO] Charlie: $CHARLIE_ADDR"

check_server() {
  set +e
  "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT" >/dev/null 2>&1
  rc=$?
  set -e
  if [[ $rc -ne 0 ]]; then
    echo "[ERROR] Could not reach node at $HOST:$PORT. Ensure server.py is running." >&2
    exit 1
  fi
}

run() {
  echo "+ $*"
  eval "$*"
}

check_server

echo "\n=== Initial Balances ==="
run "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT"
run "$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT"
run "$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT"

# Helper to send a single random transaction among Alice/Bob/Charlie
send_random_tx() {
  # Arrays of senders' private keys and corresponding addresses
  local sks=("$ALICE_SK_FINAL" "$BOB_SK_FINAL" "$CHARLIE_SK_FINAL")
  local addrs=("$ALICE_ADDR" "$BOB_ADDR" "$CHARLIE_ADDR")

  # Fetch current balances to bias towards funded senders
  local balA balB balC
  balA=$("$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT" 2>/dev/null | awk -F': ' '/BALANCE:/ {print $2}' | tr -d '\r')
  balB=$("$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT" 2>/dev/null | awk -F': ' '/BALANCE:/ {print $2}' | tr -d '\r')
  balC=$("$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT" 2>/dev/null | awk -F': ' '/BALANCE:/ {print $2}' | tr -d '\r')

  local candidates=()
  if [[ ${balA:-0} -gt 0 ]]; then candidates+=(0); fi
  if [[ ${balB:-0} -gt 0 ]]; then candidates+=(1); fi
  if [[ ${balC:-0} -gt 0 ]]; then candidates+=(2); fi

  local sidx
  if [[ ${#candidates[@]} -gt 0 ]]; then
    sidx=${candidates[$(( RANDOM % ${#candidates[@]} ))]}
  else
    sidx=0 # fallback to Alice if no one funded yet
  fi

  local tidx=$sidx
  while [[ $tidx -eq $sidx ]]; do
    tidx=$(( RANDOM % 3 ))
  done

  local amount=$(( (RANDOM % MAX_AMOUNT) + 1 ))
  local sender_sk="${sks[$sidx]}"
  local to_addr="${addrs[$tidx]}"

  run "$PY" "$WALLET" send --privkey "$sender_sk" --transfer "$to_addr:$amount" --host "$HOST" --port "$PORT"
}

# If either --blocks or --tx-per-block is provided, run configurable randomized mode.
if [[ -n "$BLOCKS" || -n "$TX_PER_BLOCK" ]]; then
  BLOCKS="${BLOCKS:-0}"
  TX_PER_BLOCK="${TX_PER_BLOCK:-1}"
  echo "\n[CONFIG] blocks=$BLOCKS, tx_per_block=$TX_PER_BLOCK, max_amount=$MAX_AMOUNT"

  if [[ "$BLOCKS" -eq 0 ]]; then
    echo "\n=== Sending $TX_PER_BLOCK random transaction(s) (no blocks will be created) ==="
    for ((i=1; i<=TX_PER_BLOCK; i++)); do
      send_random_tx
    done
  else
    for ((b=1; b<=BLOCKS; b++)); do
      echo "\n=== Block $b/$BLOCKS: sending $TX_PER_BLOCK random transaction(s) ==="
      for ((i=1; i<=TX_PER_BLOCK; i++)); do
        send_random_tx
      done
      echo "\n[BLOCK] Assembling a new block from current mempool"
      run "$PY" "$WALLET" createblock --host "$HOST" --port "$PORT"
      echo "\n=== Balances After Block $b ==="
      run "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT"
      run "$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT"
      run "$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT"
    done
  fi
else
  # Backwards-compatible fixed demo flow
  echo "\n=== Round 1: Alice -> Bob (100), Alice -> Charlie (50) ==="
  run "$PY" "$WALLET" send --privkey "$ALICE_SK_FINAL" --transfer "$BOB_ADDR:100" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" send --privkey "$ALICE_SK_FINAL" --transfer "$CHARLIE_ADDR:50" --host "$HOST" --port "$PORT"

  echo "\n[BLOCK] Assembling a new block from current mempool"
  run "$PY" "$WALLET" createblock --host "$HOST" --port "$PORT"

  echo "\n=== Balances After Block 1 ==="
  run "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT"

  echo "\n=== Round 2: Bob -> Charlie (30) ==="
  run "$PY" "$WALLET" send --privkey "$BOB_SK_FINAL" --transfer "$CHARLIE_ADDR:30" --host "$HOST" --port "$PORT"

  echo "\n[BLOCK] Assembling a new block from current mempool"
  run "$PY" "$WALLET" createblock --host "$HOST" --port "$PORT"

  echo "\n=== Balances After Block 2 ==="
  run "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT"

  echo "\n=== Round 3: Charlie -> Alice (10) ==="
  run "$PY" "$WALLET" send --privkey "$CHARLIE_SK_FINAL" --transfer "$ALICE_ADDR:10" --host "$HOST" --port "$PORT"

  echo "\n[BLOCK] Assembling a new block from current mempool"
  run "$PY" "$WALLET" createblock --host "$HOST" --port "$PORT"
fi


