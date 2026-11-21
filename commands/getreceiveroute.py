"""Read receive routes (Bounty 01, Stage 4).

Usage: getreceiveroute [account_pubkey]

With an account, returns that account's route (or null when it has none).
With no argument, lists every open route. Each row is the route book's own
snapshot shape (account, destination, bps, min_incoming, activation and
expiry), so the output matches what a restart reloads.
"""
import api_response

_CMD = "getreceiveroute"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 2:
        return api_response.error_response(
            _CMD, "Usage: getreceiveroute [account_pubkey]", "INVALID_PARAMS"
        )
    lm = container.chain_state._lifecycle_manager
    rows = lm.routes.snapshot_rows()
    if len(parts) == 2:
        account = parts[1]
        rows = [r for r in rows if r["account_pubkey"] == account]
        return api_response.success_response(
            _CMD, {"route": rows[0] if rows else None})
    return api_response.success_response(_CMD, {"routes": rows})
