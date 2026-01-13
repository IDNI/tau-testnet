#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "$0")"/.. && pwd -P)"
PY="$DIR/venv/bin/python3"
WALLET="$DIR/wallet.py"

# Default node RPC endpoint (must be running separately)
HOST="127.0.0.1"
PORT="65432"
DB_PATH="$DIR/strings.db"
ENV_FILE="$DIR/.env"
IDENTITIES=(BOB CHARLIE)
DEMO_PREFIX="DEMO_TRANSFERS"

RESET="0"
RULES_PROB="0" # percent chance per tx to include a random Tau rule (0..100)

usage() {
  echo "Usage: $0 [--reset] [--host HOST] [--port PORT] [--blocks N] [--tx-per-block M] [--max-amount A] [--with-rules] [--rules-prob PCT]"
  echo "       When --blocks/--tx-per-block are provided, runs a configurable randomized demo:"
  echo "         - --blocks N: number of blocks to create (0 means no blocks)"
  echo "         - --tx-per-block M: number of random transactions to send per block (or total if --blocks=0)"
  echo "         - --max-amount A: max random transfer amount (default 100)"
  echo "         - --with-rules: include a random simple Tau rule in every transfer tx"
  echo "         - --rules-prob PCT: include a random rule with probability PCT (0..100) per tx"
}

source_env_file() {
  if [[ -f "$ENV_FILE" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$ENV_FILE"
    set +a
  fi
}

ensure_demo_keys() {
  source_env_file

  local -a missing=()
  for ident in "${IDENTITIES[@]}"; do
    local sk_var="${DEMO_PREFIX}_${ident}_SK"
    local addr_var="${DEMO_PREFIX}_${ident}_ADDR"
    if [[ -z "${!sk_var:-}" ]] || [[ -z "${!addr_var:-}" ]]; then
      missing+=("$ident")
    fi
  done

  if (( ${#missing[@]} == 0 )); then
    return
  fi

  echo "[SETUP] Generating demo identities: ${missing[*]}"

  local python_output
  python_output="$("$PY" - "$DEMO_PREFIX" "${missing[@]}" <<'PY'
import os
import sys

try:
    from py_ecc.bls import G2ProofOfPossession as bls
except ModuleNotFoundError:
    sys.stderr.write("py_ecc is required to generate demo keys.\n")
    sys.exit(1)

prefix = sys.argv[1] if len(sys.argv) > 1 else "DEMO_TRANSFERS"
labels = sys.argv[2:] or ["ALICE", "BOB", "CHARLIE"]
for label in labels:
    seed = os.urandom(32)
    sk_int = bls.KeyGen(seed)
    print(f"{prefix}_{label}_SK={sk_int.to_bytes(32, 'big').hex()}")
    print(f"{prefix}_{label}_ADDR={bls.SkToPk(sk_int).hex()}")
PY
)"

  local regex
  regex=$(printf '%s|' "${missing[@]}")
  regex="${regex%|}"

  local tmp_existing
  tmp_existing="$(mktemp)"
  if [[ -f "$ENV_FILE" ]]; then
    grep -Ev "^${DEMO_PREFIX}_(${regex})_(SK|ADDR)=" "$ENV_FILE" > "$tmp_existing" || true
  else
    : > "$tmp_existing"
  fi

  local tmp_full
  tmp_full="$(mktemp)"
  cat "$tmp_existing" > "$tmp_full"
  if [[ -s "$tmp_full" ]]; then
    printf '\n' >> "$tmp_full"
  fi
  printf '# Demo transfer identities generated %s\n' "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" >> "$tmp_full"
  printf '%s\n' "$python_output" >> "$tmp_full"

  mv "$tmp_full" "$ENV_FILE"
  rm -f "$tmp_existing"

  source_env_file
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
    --with-rules)
      RULES_PROB="100"; shift ;;
    --rules-prob)
      RULES_PROB="${2:-$RULES_PROB}"; shift 2 ;;
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

ensure_demo_keys

ALICE_SK="11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09"
ALICE_ADDR="91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6"

BOB_SK="$DEMO_TRANSFERS_BOB_SK"
BOB_ADDR="$DEMO_TRANSFERS_BOB_ADDR"

CHARLIE_SK="$DEMO_TRANSFERS_CHARLIE_SK"
CHARLIE_ADDR="$DEMO_TRANSFERS_CHARLIE_ADDR"

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
  "$@"
}

check_server

echo "\n=== Initial Balances ==="
run "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT"
run "$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT"
run "$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT"

# Generate a random *simple* Tau rule to ship alongside transfers.
# IMPORTANT: We avoid touching `o1[t]` (transfer validation output) and we only
# reference `i1..i4` so the node already provides those inputs during transfer
# validation. This keeps rule injection "safe" while still exercising Tau's
# parser/type system with a bit of structure.
random_tau_rule() {
  local out_idx=$(( 5 + (RANDOM % 10) )) # o5..o14

  # "Broken-down" building blocks inspired by more complex SBF-style rules.
  # Here we stick to bitvectors (`:bv`) since the chain's built-in Tau rules
  # cast i1..i4 as bitvectors.
  local -a exprs=(
    "(i1[t] & i2[t] | { #b0 }:bv[64])"
    "(i3[t] | i4[t] | { #b0 }:bv[64])"
    "((i1[t] | { #b0 }:bv[64])')"
    "((i1[t] | i2[t]) & (i3[t] | { 170 }:bv[64]))"
    "((i4[t] | { 66 }:bv[64])' | (i1[t] & i2[t]))"
    "(((i1[t] | i2[t]) & i3[t]) | { #b0 }:bv[64])"
    "(((i1[t] & i2[t] | { #b0 }:bv[64]) | (i3[t] | i4[t] | { #b0 }:bv[64])))"
  )

  local expr="${exprs[$(( RANDOM % ${#exprs[@]} ))]}"

  # Pick a small family of rule shapes (simple assignment vs. small conditional).
  local shape=$(( RANDOM % 4 ))
  case "$shape" in
    0)
      # simplest: just define an unused output stream
      printf 'always (o%s[t] = %s).' "$out_idx" "$expr"
      ;;
    1)
      # conditional (mirrors examples like "cond ? o = expr : o = (expr)'")
      printf "always ((%s != { #b0 }:bv[64]) ? o%s[t] = %s : o%s[t] = (%s)')." \
        "$expr" "$out_idx" "$expr" "$out_idx" "$expr"
      ;;
    2)
      # same structure, but flip the comparator
      printf "always ((%s = { #b0 }:bv[64]) ? o%s[t] = %s : o%s[t] = (%s)')." \
        "$expr" "$out_idx" "$expr" "$out_idx" "$expr"
      ;;
    *)
      # constant output (keeps a very small/cheap option in the mix)
      local bit=$(( RANDOM % 2 )) # 0 or 1
      printf 'always (o%s[t] = { #b%s }:bv[64]).' "$out_idx" "$bit"
      ;;
  esac
}

should_include_rule() {
  local p="${RULES_PROB:-0}"
  if [[ -z "$p" ]]; then
    p="0"
  fi
  if ! [[ "$p" =~ ^[0-9]+$ ]]; then
    echo "[ERROR] --rules-prob must be an integer 0..100 (got: '$p')" >&2
    exit 1
  fi
  if (( p < 0 || p > 100 )); then
    echo "[ERROR] --rules-prob must be in range 0..100 (got: $p)" >&2
    exit 1
  fi
  (( p > 0 )) && (( (RANDOM % 100) < p ))
}

send_transfer_tx() {
  local sender_sk="$1"
  local to_addr="$2"
  local amount="$3"

  local cmd=( "$PY" "$WALLET" send --privkey "$sender_sk" --transfer "$to_addr:$amount" --host "$HOST" --port "$PORT" )
  if should_include_rule; then
    local rule
    rule="$(random_tau_rule)"
    cmd+=( --rule "$rule" )
  fi
  run "${cmd[@]}"
}

# Helper to send a single random transaction among Alice/Bob/Charlie
send_random_tx() {
  # Arrays of senders' private keys and corresponding addresses
  local sks=("$ALICE_SK" "$BOB_SK" "$CHARLIE_SK")
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

  send_transfer_tx "$sender_sk" "$to_addr" "$amount"
}

# If either --blocks or --tx-per-block is provided, run configurable randomized mode.
if [[ -n "$BLOCKS" || -n "$TX_PER_BLOCK" ]]; then
  BLOCKS="${BLOCKS:-0}"
  TX_PER_BLOCK="${TX_PER_BLOCK:-1}"
  echo "\n[CONFIG] blocks=$BLOCKS, tx_per_block=$TX_PER_BLOCK, max_amount=$MAX_AMOUNT, rules_prob=${RULES_PROB}%"

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
  send_transfer_tx "$ALICE_SK" "$BOB_ADDR" "100"
  send_transfer_tx "$ALICE_SK" "$CHARLIE_ADDR" "50"

  echo "\n[BLOCK] Assembling a new block from current mempool"
  run "$PY" "$WALLET" createblock --host "$HOST" --port "$PORT"

  echo "\n=== Balances After Block 1 ==="
  run "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT"

  echo "\n=== Round 2: Bob -> Charlie (30) ==="
  send_transfer_tx "$BOB_SK" "$CHARLIE_ADDR" "30"

  echo "\n[BLOCK] Assembling a new block from current mempool"
  run "$PY" "$WALLET" createblock --host "$HOST" --port "$PORT"

  echo "\n=== Balances After Block 2 ==="
  run "$PY" "$WALLET" balance --address "$ALICE_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$BOB_ADDR" --host "$HOST" --port "$PORT"
  run "$PY" "$WALLET" balance --address "$CHARLIE_ADDR" --host "$HOST" --port "$PORT"

  echo "\n=== Round 3: Charlie -> Alice (10) ==="
  send_transfer_tx "$CHARLIE_SK" "$ALICE_ADDR" "10"

  echo "\n[BLOCK] Assembling a new block from current mempool"
  run "$PY" "$WALLET" createblock --host "$HOST" --port "$PORT"
fi


