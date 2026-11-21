"""Read payout rules (Bounty 01, Stage 5).

Usage: getpayoutrule [payout_id | payer_or_recipient_pubkey] [in | out | all]

With a rule id (64 hex chars), returns that payout rule (or null when it
does not exist). With a pubkey (96 hex chars), lists the open rules that
involve that account: ``out`` = the account pays (default), ``in`` = the
account is a recipient, ``all`` = either side. With no argument, lists
every open payout rule. Each row is the payout book's own snapshot shape
(hex id, recipients, clause, caps, period terms, paid in the current
period) plus wallet-facing due-now fields computed against the canonical
head block timestamp: ``due_period`` (the period anyone may execute right
now, or null) and ``next_due_at`` (start of the earliest period that can
execute next). The response also carries a ``semantics`` block (time
source, period kinds, month-end rule, caps) so a wallet can check support
before offering the feature. Existing row fields are unchanged.
"""
import api_response

from commands.programmable_rpc_common import (
    head_timestamp,
    is_role,
    payout_due_fields,
    semantics_block,
)
from consensus.payouts import (
    MAX_OPEN_PAYOUTS_PER_PAYER,
    MAX_OPEN_PAYOUTS_TOTAL,
    MAX_RECIPIENTS,
)

_CMD = "getpayoutrule"

_SEMANTICS = semantics_block(
    "payout_rule",
    {
        "max_recipients": MAX_RECIPIENTS,
        "max_open_per_payer": MAX_OPEN_PAYOUTS_PER_PAYER,
        "max_open_total": MAX_OPEN_PAYOUTS_TOTAL,
    },
    "payout_execute is fee-bearing; an execute that is skipped (cap "
    "spent, clause unavailable, zero outputs) pays no fee and consumes "
    "no sequence. All legs are atomic or none.",
)


def _is_pubkey(value: str) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 96
        and all(c in "0123456789abcdef" for c in value.lower())
    )


def _enrich(book, rows, now):
    out = []
    for row in rows:
        enriched = dict(row)
        enriched.update(payout_due_fields(
            book, bytes.fromhex(row["payout_id"]), now))
        out.append(enriched)
    return out


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) > 3:
        return api_response.error_response(
            _CMD, "Usage: getpayoutrule [payout_id]", "INVALID_PARAMS"
        )
    lm = container.chain_state._lifecycle_manager
    now = head_timestamp(container)
    if len(parts) == 1:
        rows = lm.payouts.snapshot_rows()
        return api_response.success_response(
            _CMD, {"payout_rules": _enrich(lm.payouts, rows, now),
                   "semantics": _SEMANTICS})
    arg = parts[1]
    role = parts[2] if len(parts) == 3 else None
    if role is not None and not is_role(role):
        return api_response.error_response(
            _CMD, "Usage: getpayoutrule [payout_id | pubkey] [in | out | all]",
            "INVALID_PARAMS",
        )
    if _is_pubkey(arg):
        rows = lm.payouts.snapshot_rows()
        if role == "in":
            rows = [r for r in rows if arg in r["recipients"]]
        elif role == "all":
            rows = [r for r in rows
                    if r["payer_pubkey"] == arg or arg in r["recipients"]]
        else:  # "out" or no role: the account pays.
            rows = [r for r in rows if r["payer_pubkey"] == arg]
        return api_response.success_response(
            _CMD, {"payout_rules": _enrich(lm.payouts, rows, now),
                   "semantics": _SEMANTICS})
    if role is not None:
        return api_response.error_response(
            _CMD, "Usage: getpayoutrule [payout_id | pubkey] [in | out | all]",
            "INVALID_PARAMS",
        )
    payout_id = arg.lower()
    rows = [r for r in lm.payouts.snapshot_rows()
            if r["payout_id"] == payout_id]
    enriched = _enrich(lm.payouts, rows, now)
    return api_response.success_response(
        _CMD, {"payout_rule": enriched[0] if enriched else None,
               "semantics": _SEMANTICS})
