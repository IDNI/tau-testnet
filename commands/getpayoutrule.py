"""Read payout rules (Bounty 01, Stage 5).

Usage: getpayoutrule [payout_id]

With a rule id (hex), returns that payout rule (or null when it does not
exist). With no argument, lists every open payout rule. Each row is the
payout book's own snapshot shape (hex id, recipients, clause, caps, period
terms, paid in the current period), so the output matches what a restart
reloads.
"""
import api_response

_CMD = "getpayoutrule"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 2:
        return api_response.error_response(
            _CMD, "Usage: getpayoutrule [payout_id]", "INVALID_PARAMS"
        )
    lm = container.chain_state._lifecycle_manager
    rows = lm.payouts.snapshot_rows()
    if len(parts) == 2:
        payout_id = parts[1].lower()
        rows = [r for r in rows if r["payout_id"] == payout_id]
        return api_response.success_response(
            _CMD, {"payout_rule": rows[0] if rows else None})
    return api_response.success_response(_CMD, {"payout_rules": rows})
