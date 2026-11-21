"""Read receive routes (Bounty 01, Stage 4).

Usage: getreceiveroute [account_pubkey]

With an account, returns that account's route (or null when it has none).
With no argument, lists every open route. Each row is the route book's
own snapshot shape (account, destination, bps, min_incoming, activation
and expiry) plus ``is_active`` (whether the canonical head block
timestamp is inside ``[activate_at, expires_at)``). The response also
carries a ``semantics`` block (time source, period kinds, month-end rule,
caps) so a wallet can check support before offering the feature. Existing
row fields are unchanged. No role filter: one route per account, and the
direction is already visible in the row (account vs destination).
"""
import api_response

from commands.programmable_rpc_common import (
    head_timestamp,
    route_is_active,
    semantics_block,
)
from consensus.routes import MAX_BPS, MAX_ROUTES_TOTAL, MIN_BPS

_CMD = "getreceiveroute"

_SEMANTICS = semantics_block(
    "receive_route",
    {
        "max_routes_total": MAX_ROUTES_TOTAL,
        "bps_range": [MIN_BPS, MAX_BPS],
        "one_route_per_account": True,
    },
    "routed = floor(gross * bps / 10000); atomic receipt; single hop by "
    "construction.",
)


def _enrich(rows, now):
    return [dict(r, is_active=route_is_active(r, now)) for r in rows]


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 2:
        return api_response.error_response(
            _CMD, "Usage: getreceiveroute [account_pubkey]", "INVALID_PARAMS"
        )
    lm = container.chain_state._lifecycle_manager
    rows = lm.routes.snapshot_rows()
    now = head_timestamp(container)
    if len(parts) == 2:
        account = parts[1]
        rows = [r for r in rows if r["account_pubkey"] == account]
        enriched = _enrich(rows, now)
        return api_response.success_response(
            _CMD, {"route": enriched[0] if enriched else None,
                   "semantics": _SEMANTICS})
    return api_response.success_response(
        _CMD, {"routes": _enrich(rows, now), "semantics": _SEMANTICS})
