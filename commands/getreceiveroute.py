"""The receive route (#35) installed for an address, if any.

Usage: ``getreceiveroute <address>``. Returns the route's terms, whether it is
active and locked at the node's next-block timestamp, the rounding rule and the
credit classes it applies to.
"""
import api_response
import db
from consensus.facade import TipAdmissionView
from consensus.routes import BPS_DENOMINATOR, MAX_ROUTE_BPS, load_route_book

_CMD = "getreceiveroute"

ROUTED_CREDIT_CLASSES = ["user_tx", "approval_execution", "standing_payment", "grant_draw"]


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(_CMD, f"Usage: {_CMD} <address>", "INVALID_PARAMS")
    address = parts[1].strip().lower()
    if len(address) != 96 or any(c not in "0123456789abcdef" for c in address):
        return api_response.error_response(_CMD, "address must be 96 hex characters.", "INVALID_PARAMS")
    try:
        book = load_route_book(db.load_routes_state())
    except Exception:
        return api_response.error_response(_CMD, "stored route state is corrupt", "INTERNAL")
    now = TipAdmissionView().next_block_timestamp
    route = book.get(address)
    view = None
    if route is not None:
        view = {
            "destination_pubkey": route.destination_pubkey, "bps": route.bps,
            "min_incoming": route.min_incoming, "activate_at": route.activate_at,
            "expires_at": route.expires_at, "locked_until": route.locked_until,
            "version": route.version, "active": route.active_at(now),
            "locked": route.locked_at(now),
        }
    return api_response.success_response(_CMD, {
        "address": address, "as_of": now, "route": view,
        "semantics": {
            "rounding": "routed = floor(gross * bps / 10000); net = gross - routed",
            "bps_denominator": BPS_DENOMINATOR, "max_bps": MAX_ROUTE_BPS,
            "routed_credit_classes": ROUTED_CREDIT_CLASSES,
            "single_hop": True, "extra_fee": 0,
        },
    })
