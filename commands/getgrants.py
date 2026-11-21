"""List open conditional grants (Bounty 01, Stage 2).

Usage: getgrants [granter_pubkey] [grantee_pubkey]

With no arguments, lists every open grant. With one argument, only grants
from that granter; with two, only grants from that granter to that grantee.
Each row is the grant book's own snapshot shape (hex ids, integer amounts
and caps, period terms), so the output matches what a restart reloads.
"""
import api_response

_CMD = "getgrants"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 3:
        return api_response.error_response(
            _CMD, "Usage: getgrants [granter_pubkey] [grantee_pubkey]", "INVALID_PARAMS"
        )
    granter = parts[1] if len(parts) > 1 else None
    grantee = parts[2] if len(parts) > 2 else None
    lm = container.chain_state._lifecycle_manager
    rows = lm.grants.snapshot_rows()
    if granter is not None:
        rows = [r for r in rows if r["granter_pubkey"] == granter]
    if grantee is not None:
        rows = [r for r in rows if r["grantee_pubkey"] == grantee]
    return api_response.success_response(_CMD, {"grants": rows})
