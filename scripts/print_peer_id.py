#!/usr/bin/env python3
"""Print (or generate) a libp2p identity key file's base58 peer id.

Reuses the SAME keypair/peer-id calls the node uses at boot
(network.libp2p_compat.keypair_from_seed + libp2p.peer.id.ID.from_pubkey), so
the printed id matches what the running node advertises for that key file.

Usage:
    venv/bin/python scripts/print_peer_id.py demo/node1/identity.key
    venv/bin/python scripts/print_peer_id.py --generate demo/node1/identity.key
"""
import argparse
import os
import secrets
import sys

# Import from the node repo the same way scripts/demo_governance.py does.
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from network.libp2p_compat import keypair_from_seed, IDENTITY_SEED_SIZE
from libp2p.peer.id import ID


def _peer_id_from_seed(seed: bytes) -> str:
    key_pair = keypair_from_seed(seed)
    return str(ID.from_pubkey(key_pair.public_key))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("path", help="path to the identity key file (32-byte Ed25519 seed)")
    p.add_argument("--generate", action="store_true",
                   help="create a fresh identity key file at PATH before printing its id")
    a = p.parse_args()

    if a.generate:
        if os.path.exists(a.path):
            raise SystemExit(f"refusing to overwrite existing identity key: {a.path}")
        os.makedirs(os.path.dirname(a.path) or ".", exist_ok=True)
        seed = secrets.token_bytes(IDENTITY_SEED_SIZE)
        with open(a.path, "wb") as f:
            f.write(seed)
        os.chmod(a.path, 0o600)

    with open(a.path, "rb") as f:
        seed = f.read()
    if len(seed) != IDENTITY_SEED_SIZE:
        raise SystemExit(
            f"{a.path}: identity seed must be {IDENTITY_SEED_SIZE} bytes, got {len(seed)}"
        )
    sys.stdout.write(_peer_id_from_seed(seed) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
