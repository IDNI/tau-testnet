"""Open standing payments for an address, with what is due now (#34).

Usage: ``getstandingpayments <address> [in|out|all]`` -- ``out`` lists payments
the address pays, ``in`` payments it receives. Each entry carries the signed
schedule, ``executions``, ``total_executed``, ``due_period`` (the period anyone
may execute right now, or null), ``paid_this_period`` and ``next_due_at``,
judged at the node's advisory next-block timestamp. ``semantics`` states the
canonical schedule rules so a wallet can check support before offering the
feature (#34).
"""
import api_response
import db
from consensus.facade import TipAdmissionView
from consensus import periods
from consensus.standing import (
    MAX_OCCURRENCES, MAX_OPEN_STANDING_PER_PAYER, MAX_OPEN_STANDING_TOTAL,
    MAX_STANDING_HORIZON_SECONDS, MIN_WINDOW_SECONDS, load_standing_book,
)

_CMD = "getstandingpayments"
_ROLES = ("in", "out", "all")

SEMANTICS = {
    "time_source": "block header timestamp (UTC seconds)",
    "period_kinds": {
        "fixed": periods.PERIOD_FIXED, "day": periods.PERIOD_DAY,
        "iso_week": periods.PERIOD_WEEK, "month": periods.PERIOD_MONTH,
    },
    "month_missing_due_day": "last calendar day of the month",
    "executions_per_period": 1,
    "missed_period": "skipped; no catch-up",
    "insufficient_funds": "execution refused; period not marked; retry inside the window",
    "end_condition_required": True,
    "executor": "anyone",
    "fee_payer": "executor",
    "payer_policy": "payer's current o5 policy, cooldown and balance checked at execution",
    "chain_bound": True,
    "min_window_seconds": MIN_WINDOW_SECONDS,
    "max_occurrences": MAX_OCCURRENCES,
    "max_horizon_seconds": MAX_STANDING_HORIZON_SECONDS,
    "max_open_per_payer": MAX_OPEN_STANDING_PER_PAYER,
    "max_open_total": MAX_OPEN_STANDING_TOTAL,
}


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) < 2 or len(parts) > 3:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [in|out|all]", "INVALID_PARAMS"
        )
    address = parts[1].strip().lower()
    if len(address) != 96 or any(c not in "0123456789abcdef" for c in address):
        return api_response.error_response(_CMD, "address must be 96 hex characters.", "INVALID_PARAMS")
    role = parts[2].lower() if len(parts) > 2 else "all"
    if role not in _ROLES:
        return api_response.error_response(
            _CMD, f"role must be one of {', '.join(_ROLES)}", "INVALID_PARAMS"
        )
    try:
        book = load_standing_book(db.load_standing_state())
    except Exception:
        return api_response.error_response(_CMD, "stored standing payment state is corrupt", "INTERNAL")
    now = TipAdmissionView().next_block_timestamp
    out = []
    for row in book.snapshot_rows():
        mine = {
            "out": row["payer_pubkey"] == address,
            "in": row["recipient_pubkey"] == address,
        }
        if not (mine["out"] or mine["in"]) or (role != "all" and not mine[role]):
            continue
        state = book.get(bytes.fromhex(row["standing_id"]))
        view = dict(row)
        view["due_period"] = state.due_period(now)
        current = state.terms.period_of(now) if now >= state.terms.start_at else None
        view["paid_this_period"] = current is not None and state.next_period > current
        view["next_due_at"] = state.next_due_at(now)
        out.append(view)
    return api_response.success_response(_CMD, {
        "address": address, "role": role, "as_of": now, "standing_payments": out,
        "semantics": SEMANTICS,
    })
