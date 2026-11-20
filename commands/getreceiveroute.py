"""Receive route of an account (issue #35), plus what this node supports.

    getreceiveroute <address> [limit]

Returns the installed route (or null) with its status at the tip, the routes
that send a share TO this address, the canonical routing history where the
address is the recipient or the destination (newest first), queued route
changes naming it (direct ones and guard-parked rule_change_requests of kinds 6
and 7), and the node's `capability` block: support, credit-class coverage, the
rounding rule and the fee semantics.

    getreceiveroute capability

returns the capability block alone.
"""
import json

import api_response
import db
import tau_defs
from consensus.facade import TipAdmissionView
from consensus.receive_routes import (
    RECEIVE_ROUTE_TX_TYPES,
    capability,
    route_spec_destination,
)

# rule_change_request kinds that park a guarded route change.
_ROUTE_REQUEST_KINDS = (
    tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE,
    tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE,
)

_CMD = "getreceiveroute"
_DEFAULT_LIMIT = 50
_MAX_LIMIT = 500


def _is_address(text: str) -> bool:
    return len(text) == 96 and all(c in "0123456789abcdef" for c in text)


def _names(tx: dict) -> set:
    """The accounts a pending route change names, or an empty set if it is not one."""
    tx_type = tx.get("tx_type")
    if tx_type in RECEIVE_ROUTE_TX_TYPES:
        return {
            str(tx.get(k, "")).lower()
            for k in ("sender_pubkey", "destination_pubkey", "route_owner_pubkey")
        }
    if tx_type == "rule_change_request" and tx.get("kind") in _ROUTE_REQUEST_KINDS:
        named = {str(tx.get("sender_pubkey", "")).lower()}
        destination = route_spec_destination(tx.get("rule_text"))
        if destination:
            named.add(destination.lower())
        return named
    return set()


def _mempool_view(address: str) -> list:
    pending = []
    try:
        payloads = db.get_mempool_receive_route_payloads()
    except Exception:
        return pending
    for blob in payloads or []:
        text = blob if isinstance(blob, str) else ""
        if text.startswith("json:"):
            text = text[len("json:"):]
        try:
            tx = json.loads(text)
        except Exception:
            continue
        if isinstance(tx, dict) and address in _names(tx):
            pending.append({k: v for k, v in tx.items() if k != "signature"})
    return pending


def _active() -> bool:
    """Whether the feature is switched on at the tip (governance patch
    `receive_routes_active`); `capability` says what this build supports."""
    try:
        return TipAdmissionView().receive_routes_active
    except Exception:
        return False


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) == 2 and parts[1].lower() == "capability":
        return api_response.success_response(
            _CMD, {"capability": capability(), "active": _active()})
    if len(parts) < 2 or len(parts) > 3:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [limit] | {_CMD} capability", "INVALID_PARAMS"
        )
    address = parts[1].strip().lower()
    if not _is_address(address):
        return api_response.error_response(
            _CMD, "address must be 96 hex characters.", "INVALID_PARAMS"
        )
    limit = _DEFAULT_LIMIT
    if len(parts) == 3:
        try:
            limit = int(parts[2])
        except ValueError:
            limit = 0
        if not 1 <= limit <= _MAX_LIMIT:
            return api_response.error_response(
                _CMD, f"limit must be in 1..{_MAX_LIMIT}", "INVALID_PARAMS"
            )

    tip = TipAdmissionView()
    try:
        book = tip.receive_route_book()
    except Exception:
        return api_response.error_response(
            _CMD, "Receive route state is unavailable on this node.",
            "RECEIVE_ROUTE_STATE_UNAVAILABLE",
        )
    now = tip.next_block_timestamp
    route = book.get(address)
    inbound = [
        r.to_dict(now) for _, r in sorted(book.routes.items())
        if r.destination_pubkey == address
    ]
    try:
        history = db.get_canonical_receive_route_events(address, limit)
    except Exception:
        history = []
    return api_response.success_response(_CMD, {
        "address": address,
        "route": route.to_dict(now) if route is not None else None,
        "routes_to_this_address": inbound,
        "history": history,
        "mempool": _mempool_view(address),
        "active": tip.receive_routes_active,
        "capability": capability(),
    })
