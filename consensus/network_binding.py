"""Network binding: a transaction signed for one network is refused on another.

The transaction types listed in `BOUND_TX_TYPES` carry `genesis_hash`, the hash
of block 0 of the network they are meant for, as a signed root field. Admission
and block apply refuse one whose `genesis_hash` is not this chain's own, so a
signed payment instruction cannot be replayed on a fork, a devnet or a later
testnet that knows the same key and sequence number.

Only the types listed here sign the field. Every older type signs exactly the
bytes it signed before, so no existing signature changes.

A node that has no genesis block yet refuses the bound types: the check fails
closed.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

FIELD = "genesis_hash"
APPLY_REASON_WRONG_NETWORK = "wrong_network"

# Kept as plain strings so this module imports nothing from the books it guards.
BOUND_TX_TYPES = frozenset({
    "standing_payment_create",
    "standing_payment_cancel",
    "payout_rule_set",
    "payout_rule_revoke",
    "payout_execute",
    "route_set",
    "route_revoke",
})

_HEX_DIGITS = frozenset("0123456789abcdef")
_known: Optional[str] = None


def _is_hash(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= _HEX_DIGITS


def chain_genesis_hash() -> str:
    """The hash of this chain's block 0, or "" while the node has none.

    Block 0 never changes for the life of a chain, so the value is kept once it
    has been read.
    """
    global _known
    if _known:
        return _known
    import db

    try:
        value = db.get_genesis_hash()
    except Exception:
        return ""
    if _is_hash(value):
        _known = value
        return value
    return ""


def forget() -> None:
    """Drop the kept value (a process that switches database, and tests)."""
    global _known
    _known = None


def is_bound(tx: Dict[str, Any]) -> bool:
    return isinstance(tx, dict) and tx.get("tx_type") in BOUND_TX_TYPES


def problem(tx: Dict[str, Any]) -> Optional[str]:
    """Why `tx` may not run on this network, or None.

    None for every type outside `BOUND_TX_TYPES`. The same function answers
    mempool admission and block apply.
    """
    if not is_bound(tx):
        return None
    given = tx.get(FIELD)
    if not _is_hash(given):
        return (
            f"{FIELD} must be the hash of block 0 of the network this transaction "
            "is for (64 lowercase hex characters)"
        )
    own = chain_genesis_hash()
    if not own:
        return "this node has no genesis block yet, so it cannot tell which network it is"
    if given != own:
        return (
            f"signed for another network: {FIELD} is {given[:16]}..., "
            f"this network's is {own[:16]}..."
        )
    return None
