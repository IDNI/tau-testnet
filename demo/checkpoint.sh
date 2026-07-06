#!/usr/bin/env bash
# Snapshot / restore the demo node data dirs (abort path for the live demo).
#   demo/checkpoint.sh snapshot   # freeze current chain state
#   demo/checkpoint.sh restore    # roll back to the last snapshot
#   demo/checkpoint.sh status     # show whether a checkpoint exists
set -euo pipefail

cd "$(dirname "$0")"             # demo/
COMPOSE="docker compose -f docker-compose.yml"
CKPT=".checkpoint"

cmd="${1:-status}"
case "$cmd" in
  snapshot)
    echo "[checkpoint] stopping nodes"
    $COMPOSE stop
    rm -rf "$CKPT"
    for n in 1 2 3 4; do
        mkdir -p "$CKPT/node$n-data"
        rsync -a --delete "node$n/data/" "$CKPT/node$n-data/"
    done
    echo "[checkpoint] snapshot saved to $CKPT"
    $COMPOSE start
    ;;
  restore)
    if [[ ! -d "$CKPT" ]]; then
        echo "[checkpoint] no snapshot to restore" >&2
        exit 1
    fi
    echo "[checkpoint] stopping nodes"
    $COMPOSE stop
    for n in 1 2 3 4; do
        if [[ -d "$CKPT/node$n-data" ]]; then
            rsync -a --delete "$CKPT/node$n-data/" "node$n/data/"
        fi
    done
    echo "[checkpoint] restored from $CKPT"
    $COMPOSE start
    ;;
  status)
    if [[ -d "$CKPT" ]]; then
        echo "[checkpoint] live snapshot present in $(pwd)/$CKPT"
    else
        echo "[checkpoint] no snapshot"
    fi
    ;;
  *)
    echo "usage: $0 {snapshot|restore|status}" >&2
    exit 2
    ;;
esac
