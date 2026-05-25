"""Backwards-compatible re-export of identity adapters.

The real implementations live in `network.libp2p_compat` (Phase A2 of the
py-libp2p unification plan). This module exists so that existing imports
of `network.identity` keep working.

New code should import from `network.libp2p_compat`.
"""
from __future__ import annotations

from .libp2p_compat import (
    IDENTITY_SEED_SIZE,
    Ed25519PrivateKeyCompat,
    Ed25519PublicKeyCompat,
    generate_seed,
    keypair_from_seed,
)

__all__ = [
    "IDENTITY_SEED_SIZE",
    "Ed25519PrivateKeyCompat",
    "Ed25519PublicKeyCompat",
    "generate_seed",
    "keypair_from_seed",
]
