"""List open conditional grants (Bounty 01, Stage 2).

Usage: getgrants [granter_pubkey] [grantee_pubkey | in | out | all]

With no arguments, lists every open grant. With one argument, only grants
from that granter; with two pubkeys, only grants from that granter to that
grantee. The second argument may instead be a role word for the first
pubkey: ``out`` = the account granted, ``in`` = the account was granted
to, ``all`` = either side.

Each row is the grant book's own snapshot shape (hex ids, integer amounts
and caps, period terms) plus ``remaining`` (escrow left in the grant,
``amount - drawn_total``). The response also carries a ``semantics``
block (time source, period kinds, month-end rule, caps) so a wallet can
check support before offering the feature. Existing row fields are
unchanged.
"""
import api_response

from commands.programmable_rpc_common import (
    grant_remaining,
    is_role,
    semantics_block,
)
from consensus.grants import (
    MAX_OPEN_GRANTS_PER_GRANTER,
    MAX_OPEN_GRANTS_TOTAL,
)

_CMD = "getgrants"

_SEMANTICS = semantics_block(
    "grant",
    {
        "max_open_per_granter": MAX_OPEN_GRANTS_PER_GRANTER,
        "max_open_total": MAX_OPEN_GRANTS_TOTAL,
    },
    "grant_create is fee-bearing; grant_draw and grant_cancel are "
    "fee-exempt. An expired grant refunds the remainder to refund_to via "
    "the sweep.",
)


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 3:
        return api_response.error_response(
            _CMD, "Usage: getgrants [granter_pubkey] [grantee_pubkey]",
            "INVALID_PARAMS",
        )
    granter = parts[1] if len(parts) > 1 else None
    grantee = parts[2] if len(parts) > 2 else None
    role = None
    if granter is not None and is_role(granter):
        return api_response.error_response(
            _CMD,
            "Usage: getgrants [granter_pubkey] [grantee_pubkey | in | out | all]",
            "INVALID_PARAMS",
        )
    if grantee is not None and is_role(grantee):
        role = grantee
        grantee = None
    lm = container.chain_state._lifecycle_manager
    rows = lm.grants.snapshot_rows()
    if granter is not None:
        if role == "in":
            rows = [r for r in rows if r["grantee_pubkey"] == granter]
        elif role == "all":
            rows = [r for r in rows
                    if r["granter_pubkey"] == granter
                    or r["grantee_pubkey"] == granter]
        else:  # "out" or no role: the account granted.
            rows = [r for r in rows if r["granter_pubkey"] == granter]
    if grantee is not None:
        rows = [r for r in rows if r["grantee_pubkey"] == grantee]
    rows = [dict(r, remaining=grant_remaining(r)) for r in rows]
    return api_response.success_response(
        _CMD, {"grants": rows, "semantics": _SEMANTICS})
