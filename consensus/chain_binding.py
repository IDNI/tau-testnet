"""Chain binding: a transaction is signed for one Tau network only.

Every new programmable-payments transaction type (grants, standing
payments, receive routes, payout rules) carries ``chain_id`` -- the genesis
block hash of the network it was signed for. Admission and the engine
reject a transaction whose ``chain_id`` does not match this node's genesis
hash (``WRONG_CHAIN_ID``), so a grant signed on one Tau network cannot be
replayed on another: the cross-network replay protection the design
requires (1.8).

The genesis hash is pinned on the lifecycle manager (``genesis_hash``) by
chain_state at genesis load, the same way ``faucet_amount`` is pinned, and
bound into the consensus meta hash only when set, so a chain that predates
the field keeps a byte-identical hash.

Fail-closed: when the genesis hash is not loaded, or the transaction
carries no well-formed ``chain_id``, the binding check fails. A node that
has not loaded its genesis cannot judge which network a transaction
belongs to, so it admits none of the new types.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Optional

#: Admission / engine rejection code for a transaction signed for another
#: network. Mirrors the naming of the existing admission codes.
WRONG_CHAIN_ID = "WRONG_CHAIN_ID"

_CHAIN_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def check_chain_binding(tx: Dict[str, Any], genesis_hash: str) -> Optional[str]:
    """Return None when the tx's ``chain_id`` matches this node's genesis.

    Returns an error text otherwise: the genesis is unknown, the tx
    carries no well-formed ``chain_id``, or the id is for another network.
    """
    if not genesis_hash:
        return "chain id unknown (genesis not loaded)"
    chain_id = tx.get("chain_id")
    if not isinstance(chain_id, str) or _CHAIN_ID_RE.match(chain_id) is None:
        return "missing or malformed chain_id"
    if chain_id != genesis_hash:
        return "wrong chain id"
    return None
