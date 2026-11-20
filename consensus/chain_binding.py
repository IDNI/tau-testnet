"""Cross-network replay protection for the programmable-payment transactions.

Every programmable-payment transaction carries ``chain_id`` -- the hash of the
network's genesis block -- as a signed root field. Admission and block apply
both reject a transaction whose ``chain_id`` is not the chain's own, so a
transaction signed for one network (testnet, a fork, a local devnet) can never
be replayed on another. Older transaction types are untouched: their signing
bytes do not change.

The genesis hash is fixed for the life of a chain, so the value is cached once
known. A node that cannot read it (no genesis yet) rejects these transactions:
the check fails closed.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Optional

CHAIN_BOUND_TX_TYPES = frozenset({
    "grant_create", "grant_draw", "grant_cancel",
    "standing_payment_create", "standing_payment_execute", "standing_payment_cancel",
    "receive_route_set", "receive_route_remove",
    "payout_rule_install", "payout_execute", "payout_rule_remove",
})

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_cached: Optional[str] = None


def _lookup() -> str:
    import db
    try:
        return str(db.get_genesis_hash() or "").lower()
    except Exception:
        return ""


def current_chain_id() -> str:
    """The genesis block hash of the chain this node follows ("" if unknown)."""
    global _cached
    if _cached:
        return _cached
    value = _lookup()
    if _HASH_RE.match(value):
        _cached = value
    return value


def reset_cache() -> None:
    """Forget the cached id (a node switching database, and tests)."""
    global _cached
    _cached = None


def check_chain_id(tx: Dict[str, Any]) -> Optional[str]:
    """None when ``tx`` is bound to this chain; otherwise the reason it is not."""
    if not isinstance(tx, dict) or tx.get("tx_type") not in CHAIN_BOUND_TX_TYPES:
        return None
    given = tx.get("chain_id")
    if not isinstance(given, str) or not _HASH_RE.match(given):
        return "chain_id must be the 64-hex genesis block hash of the target network"
    own = current_chain_id()
    if not own:
        return "this node does not know its chain id yet"
    if given != own:
        return "chain_id belongs to another network (cross-network replay refused)"
    return None
