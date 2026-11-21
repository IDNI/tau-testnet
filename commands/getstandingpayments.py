"""List open standing payments (Bounty 01, Stage 3).

Usage: getstandingpayments [payer_pubkey] [payee_pubkey | in | out | all]

With no arguments, lists every open standing payment. With one argument,
only payments from that payer; with two pubkeys, only payments from that
payer to that payee. The second argument may instead be a role word for
the first pubkey: ``out`` = the account pays, ``in`` = the account is
paid, ``all`` = either side.

Each row is the standing book's own snapshot shape (hex id, version,
amount, period terms, last executed period) plus wallet-facing due-now
fields computed against the canonical head block timestamp: ``due_period``
(the period anyone may execute right now, or null), ``paid_this_period``,
``next_due_at`` (start of the earliest period that can execute next),
``total_executed`` (cumulative amount paid). The response also carries a
``semantics`` block (time source, period kinds, month-end rule, caps) so
a wallet can check support before offering the feature. Existing row
fields are unchanged.
"""
import api_response

from commands.programmable_rpc_common import (
    head_timestamp,
    is_role,
    semantics_block,
    standing_due_fields,
)
from consensus.standing import (
    MAX_OPEN_STANDING_PER_PAYER,
    MAX_OPEN_STANDING_TOTAL,
)

_CMD = "getstandingpayments"

_SEMANTICS = semantics_block(
    "standing_payment",
    {
        "max_open_per_payer": MAX_OPEN_STANDING_PER_PAYER,
        "max_open_total": MAX_OPEN_STANDING_TOTAL,
    },
    "Sweep primary, standing_payment_execute fallback; one execution per "
    "period, no catch-up; max_fee_per_execution is charged to the payer.",
)


def _enrich(book, rows, now):
    out = []
    for row in rows:
        enriched = dict(row)
        enriched.update(standing_due_fields(
            book, bytes.fromhex(row["standing_id"]), now))
        out.append(enriched)
    return out


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
    role = None
    if payer is not None and is_role(payer):
        return api_response.error_response(
            _CMD,
            "Usage: getstandingpayments [payer_pubkey] [payee_pubkey | in | out | all]",
            "INVALID_PARAMS",
        )
    if payee is not None and is_role(payee):
        role = payee
        payee = None
    lm = container.chain_state._lifecycle_manager
    rows = lm.standing.snapshot_rows()
    if payer is not None:
        if role == "in":
            rows = [r for r in rows if r["payee_pubkey"] == payer]
        elif role == "all":
            rows = [r for r in rows
                    if r["payer_pubkey"] == payer or r["payee_pubkey"] == payer]
        else:  # "out" or no role: the account pays.
            rows = [r for r in rows if r["payer_pubkey"] == payer]
    if payee is not None:
        rows = [r for r in rows if r["payee_pubkey"] == payee]
    now = head_timestamp(container)
    return api_response.success_response(
        _CMD, {"standing_payments": _enrich(lm.standing, rows, now),
               "semantics": _SEMANTICS})
