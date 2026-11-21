"""Shared wallet-facing enrichment for the Bounty 01 RPC getters.

The book ``snapshot_rows()`` shapes are the persisted consensus shapes and
must not change, so the enrichment lives here, at the RPC layer: each
getter copies its rows and adds wallet-facing fields computed against the
canonical head block timestamp. Nothing in this module touches consensus
state, and every field it adds is derived from the book plus ``now``.

Due-now semantics (identical for standing payments and payout rules):

* ``due_period`` -- the period anyone may execute right now, or null.
  For a standing payment that is the current period when it has not been
  executed yet; for a payout rule it is the current period when the
  period cap still has headroom and the rule is live.
* ``next_due_at`` -- start timestamp of the earliest period that can
  execute next. When a period is due now this is the start of that
  (already started) period; when the current period is spent it is the
  start of the next period; null when the rule can never execute again
  (expired, or the next period starts at/after expiry).
* ``paid_this_period`` (standing only) -- the amount paid in the current
  period: the fixed ``amount`` when the current period was executed,
  else 0.
* ``total_executed`` (standing only) -- cumulative amount paid,
  ``executions * amount`` (the amount is fixed per execution).
* ``remaining`` (grants only) -- escrow left in the grant,
  ``amount - drawn_total``.
* ``is_active`` (routes only) -- ``activate_at <= now < expires_at``.

``semantics`` is a per-getter block (time source, period kinds,
month-end rule, caps, fee/execution notes) so a wallet can check support
before offering the feature. Cap values are imported from the consensus
modules, never hardcoded.
"""
from __future__ import annotations

from consensus.periods import (
    PERIOD_DAY,
    PERIOD_FIXED,
    PERIOD_MONTH,
    PERIOD_WEEK,
    PeriodError,
    period_index,
    period_start,
)

ROLES = ("in", "out", "all")

PERIOD_KIND_NAMES = {
    PERIOD_FIXED: "fixed",
    PERIOD_DAY: "day",
    PERIOD_WEEK: "ISO week",
    PERIOD_MONTH: "month",
}

TIME_SOURCE = "canonical head block timestamp (seconds since Unix epoch, UTC)"
MONTH_END_RULE = (
    "month periods start on the anchor day-of-month, clamped to the last "
    "day of the month when that day does not exist"
)


def head_timestamp(container) -> int:
    """Canonical head block timestamp; 0 when no head block is readable."""
    try:
        head = container.db.get_canonical_head_block()
    except Exception:
        return 0
    if not isinstance(head, dict):
        return 0
    header = head.get("header") or {}
    ts = header.get("timestamp")
    return int(ts) if isinstance(ts, int) else 0


def is_role(value) -> bool:
    """True when `value` is a role word rather than a pubkey."""
    return isinstance(value, str) and value in ROLES


def semantics_block(obj: str, caps: dict, notes: str) -> dict:
    """The per-getter semantics block for `obj`."""
    return {
        "object": obj,
        "time_source": TIME_SOURCE,
        "period_kinds": {str(k): v for k, v in PERIOD_KIND_NAMES.items()},
        "month_end_rule": MONTH_END_RULE,
        "caps": dict(caps),
        "notes": notes,
    }


def _period_start_safe(kind, index, *, anchor, length):
    try:
        return period_start(kind, index, anchor=anchor, length=length)
    except (PeriodError, OverflowError, ValueError):
        return None


def standing_due_fields(book, standing_id: bytes, now: int) -> dict:
    """Wallet-facing due-now fields for one standing payment."""
    entry = book.get(standing_id)
    if entry is None:
        return {"due_period": None, "paid_this_period": 0,
                "next_due_at": None, "total_executed": 0}
    total_executed = book.executions(standing_id) * entry.amount
    try:
        from consensus.standing import current_period, first_period

        current = current_period(entry, now)
        first = first_period(entry)
    except PeriodError:
        return {"due_period": None, "paid_this_period": 0,
                "next_due_at": None, "total_executed": total_executed}
    last = book.last_executed_period(standing_id)
    paid_this_period = entry.amount if last == current else 0
    if now < entry.start_at or current < first:
        return {"due_period": None, "paid_this_period": paid_this_period,
                "next_due_at": _period_start_safe(
                    entry.period_kind, first, anchor=entry.period_anchor,
                    length=entry.period_length),
                "total_executed": total_executed}
    due = book.due_period(standing_id, now)
    if due is not None:
        nxt = _period_start_safe(
            entry.period_kind, due, anchor=entry.period_anchor,
            length=entry.period_length)
    else:
        # Dormant (occurrences cap reached or past the horizon): no next
        # due date at all. Otherwise the next period starts after this one.
        from consensus.standing import (
            MAX_OCCURRENCES,
            MAX_STANDING_HORIZON_SECONDS,
        )

        if (book.executions(standing_id) >= MAX_OCCURRENCES
                or now >= entry.start_at + MAX_STANDING_HORIZON_SECONDS):
            nxt = None
        else:
            nxt = _period_start_safe(
                entry.period_kind, current + 1, anchor=entry.period_anchor,
                length=entry.period_length)
    return {"due_period": due, "paid_this_period": paid_this_period,
            "next_due_at": nxt, "total_executed": total_executed}


def payout_due_fields(book, payout_id: bytes, now: int) -> dict:
    """Wallet-facing due-now fields for one payout rule."""
    entry = book.get(payout_id)
    if entry is None:
        return {"due_period": None, "next_due_at": None}
    try:
        from consensus.payouts import current_period, first_period

        current = current_period(entry, now)
        first = first_period(entry)
    except PeriodError:
        return {"due_period": None, "next_due_at": None}
    start = _period_start_safe(
        entry.period_kind, first, anchor=entry.period_anchor,
        length=entry.period_length)
    if now >= entry.expires_at:
        return {"due_period": None, "next_due_at": None}
    if now < entry.start_at or current < first:
        return {"due_period": None, "next_due_at": start}
    paid = book.paid_in_period(payout_id, current)
    if paid < entry.max_per_period:
        return {"due_period": current,
                "next_due_at": _period_start_safe(
                    entry.period_kind, current, anchor=entry.period_anchor,
                    length=entry.period_length)}
    nxt = _period_start_safe(
        entry.period_kind, current + 1, anchor=entry.period_anchor,
        length=entry.period_length)
    if nxt is not None and nxt >= entry.expires_at:
        nxt = None
    return {"due_period": None, "next_due_at": nxt}


def grant_remaining(row: dict) -> int:
    """Escrow left in a grant row (``amount - drawn_total``)."""
    return int(row["amount"]) - int(row["drawn_total"])


def route_is_active(row: dict, now: int) -> bool:
    """True when `now` is inside the route's ``[activate_at, expires_at)``."""
    expires_at = row.get("expires_at")
    if expires_at is not None and now >= int(expires_at):
        return False
    return int(row["activate_at"]) <= now
