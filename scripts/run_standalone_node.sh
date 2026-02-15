#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DATA_DIR="${TAU_NODE_DATA_DIR:-${ROOT_DIR}/data}"
IMAGE="${TAU_NODE_IMAGE:-tau-testnet-standalone:latest}"

mkdir -p "${DATA_DIR}"

docker run --rm -it \
  -p 65432:65432 \
  -p 65433:65433 \
  -p 4001:4001 \
  -v "${DATA_DIR}:/data" \
  "${IMAGE}" "$@"
