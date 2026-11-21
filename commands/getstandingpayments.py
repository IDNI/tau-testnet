"""List open standing payments (Bounty 01, Stage 3).

Usage: getstandingpayments [payer_pubkey] [payee_pubkey]

With no arguments, lists every open standing payment. With one argument,
only payments from that payer; with two, only payments from that payer to
that payee. Each row is the standing book's own snapshot shape (hex id,
version, amount, period terms, last executed period), so the output matches
what a restart reloads.
"""
import api_response

_CMD = "getstandingpayments"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 3:
        return api_response.error_response(
            _CMD,
            "Usage: getstandingpayments [payer_pubkey] [payee_pubkey]",
            "INVALID_PARAMS",
        )
    payer = parts[1] if len(parts) > 1 else None
    payee = parts[2] if len(parts) > 2 else None
    lm = container.chain_state._lifecycle_manager
    rows = lm.standing.snapshot_rows()
    if payer is not None:
        rows = [r for r in rows if r["payer_pubkey"] == payer]
    if payee is not None:
        rows = [r for r in rows if r["payee_pubkey"] == payee]
    return api_response.success_response(_CMD, {"standing_payments": rows})
