"""An account's receive route: what it splits off, and what routes pay it (#35).

    getreceiveroute <address>

Answers the route the account owns (`installed`, `route`), the routes that pay
INTO the account (`routes_in`), and the history of both on this node, newest
first: every split with its gross, routed and net amounts, its credit class and
the payment it came from, and every set, replace, remove, release and expiry.

`semantics` is the capability report: whether the node routes, which credits
are routed and which are not, the rounding, the cap, and who pays what fee.
"""
import time

import api_response
import chain_state
import consensus.receive_route as receive_route
from consensus.receive_route import ReceiveRouteBook, describe

_CMD = "getreceiveroute"


def semantics() -> dict:
    out = dict(receive_route.SEMANTICS)
    out.update({
        "tx_types": sorted(receive_route.ROUTE_TX_TYPES),
        "share_bps_range": [1, receive_route.MAX_SHARE_BPS],
        "limits": {
            "routes_total": receive_route.MAX_RECEIVE_ROUTES_TOTAL,
            "start_delay_max_seconds": receive_route.MAX_START_DELAY_SECONDS,
            "lifetime_max_seconds": receive_route.MAX_LIFETIME_SECONDS,
            "lock_max_seconds": receive_route.MAX_LOCK_SECONDS,
        },
        "fee_by_tx_type": {
            "receive_route_set": "one fee, paid by the owner",
            "receive_route_remove": "fee-free",
            "receive_route_release": "fee-free",
        },
        "preview": "sendtx and checktx answer `receive_routes` with the split the "
                   "routes in force now would make of the transaction's credits",
    })
    return out


def _tip():
    """(head hash, route book) as one consistent read of the tip."""
    with chain_state._balance_lock, chain_state._sequence_lock, chain_state._rules_lock:
        lm = chain_state._lifecycle_manager
        head = getattr(chain_state, "_canonical_head_hash", None)
    book = getattr(lm, "receive_routes", None)
    return head, book if isinstance(book, ReceiveRouteBook) else ReceiveRouteBook()


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(_CMD, f"Usage: {_CMD} <address>", "INVALID_PARAMS")
    from consensus.approvals import ApprovalShapeError, _normalize_pubkey

    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
    import db

    try:
        owned = db.get_canonical_route_events(address, role="owner")
        received = db.get_canonical_route_events(address, role="destination")
    except Exception:
        owned, received = [], []
    head, book = _tip()
    now = int(time.time())
    terms = book.get(address)
    data = {"address": address, "block_hash": head, "installed": terms is not None}
    if terms is not None:
        data["route"] = describe(terms, now)
    data["routes_in"] = [describe(t, now) for t in book.routes_to(address)]
    data["history"] = owned
    data["history_in"] = received
    data["semantics"] = semantics()
    return api_response.success_response(_CMD, data)
