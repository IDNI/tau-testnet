"""Programmable payments: standing orders, receive routes, payout rules, allowances.

Rules on this chain can allow or block a transfer. This module lets a signed
instruction start a payment, or constrain money after it arrives, without the
owner's key being present again.

The books live on ``ConsensusLifecycleManager`` (field ``programmable``). Their
root joins the consensus meta hash only once a book has held an entry, so a
chain that never uses them keeps a byte-identical state hash.

Design choices that every node has to share are constants and comments in this
file, and the write-up in ``docs/programmable_payments.md``.
"""
from __future__ import annotations

import copy
from typing import Any, Callable, Dict, List, Optional, Tuple

from blake3 import blake3

import tau_defs
from consensus import sender_policy
from consensus.periods import (
    DAY,
    MAX_HORIZON,
    WEEK,
    add_months,
    any_moment_allowed,
    masks_allow,
    period_index,
    period_start,
)
from consensus.serialization import canonical_json
from consensus.tx_checks import validate_bls_pubkey
from errors import BlockchainBug

# --- transaction types -------------------------------------------------------

TX_STANDING_CREATE = "standing_payment_create"
TX_STANDING_CANCEL = "standing_payment_cancel"
TX_STANDING_UPDATE = "standing_payment_update"
TX_STANDING_EXECUTE = "standing_payment_execute"
TX_ALLOWANCE_OPEN = "allowance_open"
TX_ALLOWANCE_DRAW = "allowance_draw"
TX_ALLOWANCE_RELEASE = "allowance_release"
TX_ROUTE_SET = "receive_route_set"
TX_ROUTE_REMOVE = "receive_route_remove"
TX_ROUTE_RELEASE = "receive_route_release"
TX_PAYOUT_SET = "payout_rule_set"
TX_PAYOUT_REMOVE = "payout_rule_remove"
TX_PAYOUT_EXECUTE = "payout_execute"

PAYMENT_TX_TYPES = frozenset({
    TX_STANDING_CREATE, TX_STANDING_CANCEL, TX_STANDING_UPDATE, TX_STANDING_EXECUTE,
    TX_ALLOWANCE_OPEN, TX_ALLOWANCE_DRAW, TX_ALLOWANCE_RELEASE,
    TX_ROUTE_SET, TX_ROUTE_REMOVE, TX_ROUTE_RELEASE,
    TX_PAYOUT_SET, TX_PAYOUT_REMOVE, TX_PAYOUT_EXECUTE,
})

# The submitter pays the ordinary Tau fee (o8/o9) of these transactions.
# Cancels, removals, releases and the end-of-block sweep do not: a payer must
# be able to stop an instruction, and a refund must return the whole remainder.
FEE_BEARING_PAYMENT_TYPES = frozenset({
    TX_STANDING_CREATE, TX_STANDING_UPDATE, TX_STANDING_EXECUTE,
    TX_ALLOWANCE_OPEN, TX_ALLOWANCE_DRAW,
    TX_ROUTE_SET,
    TX_PAYOUT_SET, TX_PAYOUT_EXECUTE,
})

# --- bounds (consensus-frozen) -----------------------------------------------

MAX_OPEN_STANDING_PER_PAYER = 16
MAX_OPEN_STANDING_TOTAL = 4096
MAX_OPEN_ALLOWANCES_PER_GRANTOR = 16
MAX_OPEN_ALLOWANCES_TOTAL = 4096
MAX_OCCURRENCES = 1200
MIN_INTERVAL_SECONDS = 3600
MIN_INTERVAL_BLOCKS = 128
MAX_MONTH_SPAN = 48
MAX_SWEEP_ACTIONS = 32
MAX_SKIPS_PER_ENTRY = 8
MAX_ROUTE_DESTINATIONS = 4
MAX_ROUTE_BPS = 9000  # below 100%; dust stays with the recipient
MAX_PAYOUT_LEGS = 8
MAX_CLAUSE_BYTES = 2048
MAX_EVENTS_PER_RULE = 64
MAX_PAYOUT_RULES = 4096
WEEKDAY_MASK_MAX = (1 << 7) - 1
HOUR_MASK_MAX = (1 << 24) - 1

_CHAIN_RE = set("0123456789abcdef")

CAPABILITY = {
    "programmable_payments": 1,
    "time_source": "block_header_timestamp",
    "outside_clock": False,
    "issue_62": "not consulted; a sweep has no transaction to carry an attestation",
    "day_seconds": DAY,
    "week_seconds": WEEK,
    "month": "UTC calendar month from the signed anchor; a missing day is the last day",
    "allowance_periods": "equal day/week lengths, or calendar months, counted from unlock",
    "rounding": "floor(gross * bps / 10000)",
    "route_max_destinations": MAX_ROUTE_DESTINATIONS,
    "route_max_total_bps": MAX_ROUTE_BPS,
    "route_hops": 1,
    "routable_credit_classes": ["transfer"],
    "standing_catch_up": False,
    "standing_fee": "payer pays the create/update transaction; sweep executions are fee-free; an explicit execute is paid by its submitter",
    "route_fee": "no second fee; the sender pays the one transfer fee",
    "refund_fee": "none; the full remainder returns to the grantor",
    "payout_fee": "the execute submitter pays; the owner pays the principal",
    "conditions": "AND",
    "conflict": "at expiry the refund wins and a draw is refused",
}


class PaymentShapeError(ValueError):
    def __init__(self, reason: str, detail: str):
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _u64(value: Any, name: str, lo: int, hi: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise PaymentShapeError("bad_field", f"{name} must be an integer")
    if value < lo or value > hi:
        raise PaymentShapeError("bad_field", f"{name} must be in {lo}..{hi}")
    return value


def _pubkey(value: Any, name: str) -> str:
    err = validate_bls_pubkey(value, name)
    if err:
        raise PaymentShapeError("bad_pubkey", err)
    return str(value).strip().lower()


def _chain(value: Any) -> str:
    if not isinstance(value, str):
        raise PaymentShapeError("bad_chain", "chain_id must be hex")
    text = value.strip().lower()
    if len(text) != 64 or any(c not in _CHAIN_RE for c in text):
        raise PaymentShapeError("bad_chain", "chain_id must be 64 hex characters")
    return text


def _hex32(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise PaymentShapeError("bad_field", f"{name} must be hex")
    text = value.strip().lower()
    if len(text) != 64 or any(c not in _CHAIN_RE for c in text):
        raise PaymentShapeError("bad_field", f"{name} must be 64 hex characters")
    return text


def _id(domain: str, body: dict) -> str:
    payload = canonical_json({"domain": domain, **body})
    return blake3(payload).digest().hex()


# Fields covered by the signature, in addition to the envelope. Every field
# apply will read is listed, so a proposer cannot rewrite a term.
_SIGNED: Dict[str, Tuple[str, ...]] = {
    TX_STANDING_CREATE: (
        "chain_id", "recipient_pubkey", "amount", "schedule_kind", "interval",
        "first_due", "window", "max_occurrences", "max_fee_per_execution",
    ),
    TX_STANDING_CANCEL: ("chain_id", "standing_id"),
    TX_STANDING_UPDATE: (
        "chain_id", "standing_id", "recipient_pubkey", "amount", "schedule_kind",
        "interval", "first_due", "window", "max_occurrences", "max_fee_per_execution",
    ),
    TX_STANDING_EXECUTE: ("chain_id", "standing_id", "occurrence"),
    TX_ALLOWANCE_OPEN: (
        "chain_id", "grantee_pubkey", "amount", "start_at", "hold_seconds",
        "spend_cap", "cap_period", "cap_length", "per_draw_cap", "weekday_mask",
        "hour_mask", "utc_offset_quarters", "expires_at", "refund_idle",
        "shared_key", "shared_cap", "shared_period", "shared_length", "shared_anchor",
    ),
    TX_ALLOWANCE_DRAW: ("chain_id", "allowance_id", "recipient_pubkey", "amount"),
    TX_ALLOWANCE_RELEASE: ("chain_id", "allowance_id"),
    TX_ROUTE_SET: (
        "chain_id", "destinations", "min_incoming", "activate_at", "expires_at",
        "locked_until",
    ),
    TX_ROUTE_REMOVE: ("chain_id",),
    TX_ROUTE_RELEASE: ("chain_id", "owner_pubkey"),
    TX_PAYOUT_SET: (
        "chain_id", "legs", "max_per_execution", "max_per_period", "period",
        "period_length", "period_anchor", "max_executions", "expires_at",
        "bounded_by_gross", "clause",
    ),
    TX_PAYOUT_REMOVE: ("chain_id",),
    TX_PAYOUT_EXECUTE: ("chain_id", "owner_pubkey", "event_id", "gross"),
}


def signed_fields(tx_type: str) -> Tuple[str, ...]:
    return _SIGNED.get(tx_type, ())


def signing_overlay(payload: dict) -> dict:
    tx_type = payload.get("tx_type", "")
    return {field: payload.get(field) for field in signed_fields(tx_type)}


def _check_chain(tx: dict, chain_id: str) -> str:
    signed = _chain(tx.get("chain_id"))
    expected = (chain_id or "").strip().lower()
    if not expected:
        raise PaymentShapeError("chain_unknown", "this node has no genesis hash to bind the payment to")
    if signed != expected:
        raise PaymentShapeError("wrong_chain", "chain_id does not match this network")
    return signed


def _schedule(kind: Any, interval: Any, first_due: Any, window: Any) -> dict:
    if kind not in ("blocks", "seconds", "months"):
        raise PaymentShapeError("bad_schedule", "schedule_kind must be blocks, seconds or months")
    interval_i = _u64(interval, "interval", 1, 10**12)
    first = _u64(first_due, "first_due", 0, 10**18)
    window_i = _u64(window, "window", 1, 10**12)
    if kind == "blocks":
        if interval_i < MIN_INTERVAL_BLOCKS:
            raise PaymentShapeError("bad_schedule", f"block interval must be >= {MIN_INTERVAL_BLOCKS}")
        if window_i > interval_i:
            raise PaymentShapeError("bad_schedule", "window must not exceed the interval")
    elif kind == "seconds":
        if interval_i < MIN_INTERVAL_SECONDS:
            raise PaymentShapeError("bad_schedule", f"seconds interval must be >= {MIN_INTERVAL_SECONDS}")
        if window_i > interval_i:
            raise PaymentShapeError("bad_schedule", "window must not exceed the interval")
        if interval_i > MAX_HORIZON:
            raise PaymentShapeError("bad_schedule", "interval exceeds the horizon")
    else:
        if interval_i > 12:
            raise PaymentShapeError("bad_schedule", "month interval must be 1..12")
        # A window that long would overlap the next month's due point.
        if window_i > 27 * DAY:
            raise PaymentShapeError("bad_schedule", "a monthly window must be <= 27 days")
    return {"kind": kind, "interval": interval_i, "first_due": first, "window": window_i}


def occurrence_due(schedule: dict, index: int) -> int:
    kind = schedule["kind"]
    if kind == "months":
        return add_months(schedule["first_due"], index * schedule["interval"])
    return schedule["first_due"] + index * schedule["interval"]


def _classify(schedule: dict, index: int, height: int, ts: int) -> str:
    due = occurrence_due(schedule, index)
    if schedule["kind"] == "blocks":
        if height < due:
            return "early"
        if height >= due + schedule["window"]:
            return "missed"
        return "payable"
    if ts < due:
        return "early"
    if ts >= due + schedule["window"]:
        return "missed"
    return "payable"


def _legs(raw: Any) -> List[dict]:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_PAYOUT_LEGS:
        raise PaymentShapeError("bad_legs", f"legs must be 1..{MAX_PAYOUT_LEGS} entries")
    legs = []
    seen = set()
    remainder = 0
    for item in raw:
        if not isinstance(item, dict):
            raise PaymentShapeError("bad_legs", "each leg must be an object")
        pubkey = _pubkey(item.get("pubkey"), "leg pubkey")
        if pubkey in seen:
            raise PaymentShapeError("bad_legs", "duplicate payout recipient")
        seen.add(pubkey)
        expr = item.get("expr")
        if not isinstance(expr, dict):
            raise PaymentShapeError("bad_legs", "leg expr must be an object")
        op = expr.get("op")
        if op == "bps":
            bps = _u64(expr.get("bps"), "bps", 1, 10000)
            legs.append({"pubkey": pubkey, "expr": {"op": "bps", "bps": bps}})
        elif op == "const":
            amount = _u64(expr.get("amount"), "amount", 1, tau_defs.MAX_TRANSFER_VALUE)
            legs.append({"pubkey": pubkey, "expr": {"op": "const", "amount": amount}})
        elif op == "remainder":
            remainder += 1
            if remainder > 1:
                raise PaymentShapeError("bad_legs", "only one remainder leg")
            legs.append({"pubkey": pubkey, "expr": {"op": "remainder"}})
        else:
            raise PaymentShapeError("bad_legs", "expr op must be bps, const or remainder")
    if remainder and legs[-1]["expr"]["op"] != "remainder":
        raise PaymentShapeError("bad_legs", "the remainder leg must be last")
    return legs


def leg_amounts(legs: List[dict], gross: int) -> List[Tuple[str, int]]:
    """Integer amounts for one execution. Raises PaymentShapeError on a bad mix."""
    if gross < 0 or gross > tau_defs.MAX_TRANSFER_VALUE:
        raise PaymentShapeError("bad_gross", "gross is outside the transfer range")
    out: List[Tuple[str, int]] = []
    used = 0
    for leg in legs:
        expr = leg["expr"]
        op = expr["op"]
        if op == "bps":
            amount = (gross * int(expr["bps"])) // 10000
        elif op == "const":
            amount = int(expr["amount"])
        else:
            amount = gross - used
        if amount < 0 or used + amount > tau_defs.MAX_TRANSFER_VALUE:
            raise PaymentShapeError("leg_overflow", "leg amounts exceed the transfer range")
        used += amount
        if amount > 0:
            out.append((leg["pubkey"], amount))
    return out


def _destinations(raw: Any, owner: str) -> List[dict]:
    if not isinstance(raw, list) or not raw or len(raw) > MAX_ROUTE_DESTINATIONS:
        raise PaymentShapeError(
            "bad_route", f"destinations must be 1..{MAX_ROUTE_DESTINATIONS} entries"
        )
    dests = []
    seen = set()
    total = 0
    for item in raw:
        if not isinstance(item, dict):
            raise PaymentShapeError("bad_route", "each destination must be an object")
        pubkey = _pubkey(item.get("pubkey"), "destination")
        if pubkey == owner:
            raise PaymentShapeError("self_route", "a route cannot pay its owner")
        if pubkey in seen:
            raise PaymentShapeError("bad_route", "duplicate destination")
        seen.add(pubkey)
        bps = _u64(item.get("bps"), "bps", 1, MAX_ROUTE_BPS)
        total += bps
        dests.append({"pubkey": pubkey, "bps": bps})
    if total > MAX_ROUTE_BPS:
        raise PaymentShapeError("route_over_cap", f"destination shares sum to more than {MAX_ROUTE_BPS} bps")
    return dests


def _period_kind(value: Any, name: str) -> str:
    if value not in ("day", "week", "month", "fixed"):
        raise PaymentShapeError("bad_period", f"{name} must be day, week, month or fixed")
    return value


class Stage:
    def __init__(self, ok: bool, reason: str = "", detail: str = "",
                 writes: Optional[dict] = None, commit: Optional[Callable] = None,
                 stamp: Optional[List[str]] = None, receipt: Optional[dict] = None):
        self.ok = ok
        self.reason = reason
        self.detail = detail
        self.writes = writes or {}
        self.commit = commit
        self.stamp = stamp or []
        self.receipt = receipt or {}

    @staticmethod
    def reject(reason: str, detail: str) -> "Stage":
        return Stage(False, reason, detail)


def _policy_blocks(lm, payer: str, recipient: str, amount: int, ts: int,
                   body: Optional[str] = None, extra: Optional[dict] = None) -> bool:
    """The account's current o5 clause, or an explicit payout clause.

    A clause that does not build blocks. No clause allows. Loss of the
    evaluator propagates: a guess would split the network.
    """
    if body is None:
        body = lm.rule_offers.clause_for(payer, tau_defs.USER_POLICY_STREAM_INDEX)
    if not body:
        return False
    values = {1: str(int(amount)), 5: str(int(ts)), 12: str(recipient or "0")}
    if extra:
        values.update(extra)
    blocked, _detail = sender_policy.clause_blocks(body, values, pool="apply")
    return blocked


class PaymentBooks:
    """Open instructions plus the progress a later block has to see."""

    def __init__(self) -> None:
        self.standing: Dict[str, dict] = {}
        self.resolved_standing: Dict[str, dict] = {}
        self.allowances: Dict[str, dict] = {}
        self.resolved_allowances: Dict[str, dict] = {}
        self.routes: Dict[str, dict] = {}
        self.payouts: Dict[str, dict] = {}
        self.shared: Dict[str, dict] = {}
        self._root: Optional[bytes] = None

    def is_empty(self) -> bool:
        return not (
            self.standing or self.resolved_standing or self.allowances
            or self.resolved_allowances or self.routes or self.payouts or self.shared
        )

    def escrow_total(self) -> int:
        return sum(int(row["remaining"]) for row in self.allowances.values())

    def _dirty(self) -> None:
        self._root = None

    def snapshot(self) -> dict:
        def rows(mapping: Dict[str, dict]) -> List[dict]:
            return [copy.deepcopy(mapping[key]) for key in sorted(mapping)]
        return {
            "standing": rows(self.standing),
            "resolved_standing": rows(self.resolved_standing),
            "allowances": rows(self.allowances),
            "resolved_allowances": rows(self.resolved_allowances),
            "routes": rows(self.routes),
            "payouts": rows(self.payouts),
            "shared": rows(self.shared),
        }

    def root(self) -> bytes:
        if self._root is None:
            self._root = blake3(b"tau.payments.book.v1" + canonical_json(self.snapshot())).digest()
        return self._root

    def __deepcopy__(self, memo) -> "PaymentBooks":
        clone = PaymentBooks.__new__(PaymentBooks)
        clone.standing = copy.deepcopy(self.standing, memo)
        clone.resolved_standing = copy.deepcopy(self.resolved_standing, memo)
        clone.allowances = copy.deepcopy(self.allowances, memo)
        clone.resolved_allowances = copy.deepcopy(self.resolved_allowances, memo)
        clone.routes = copy.deepcopy(self.routes, memo)
        clone.payouts = copy.deepcopy(self.payouts, memo)
        clone.shared = copy.deepcopy(self.shared, memo)
        clone._root = self._root
        return clone

    # -- standing -------------------------------------------------------------

    def _standing_terms(self, payer: str, sequence: int, chain_id: str, tx: dict,
                        version: int, replaces: str) -> dict:
        schedule = _schedule(
            tx.get("schedule_kind"), tx.get("interval"), tx.get("first_due"), tx.get("window")
        )
        amount = _u64(tx.get("amount"), "amount", 1, tau_defs.MAX_TRANSFER_VALUE)
        occurrences = _u64(tx.get("max_occurrences"), "max_occurrences", 1, MAX_OCCURRENCES)
        fee_cap = _u64(tx.get("max_fee_per_execution"), "max_fee_per_execution", 0, 0)
        recipient = _pubkey(tx.get("recipient_pubkey"), "recipient_pubkey")
        if recipient == payer:
            raise PaymentShapeError("self_pay", "a standing payment cannot pay its payer")
        if schedule["kind"] == "months" and occurrences * schedule["interval"] > MAX_MONTH_SPAN:
            raise PaymentShapeError("bad_schedule", f"a monthly authorization must end within {MAX_MONTH_SPAN} months")
        if schedule["kind"] == "seconds" and occurrences * schedule["interval"] > MAX_HORIZON:
            raise PaymentShapeError("bad_schedule", "the authorization runs past the horizon")
        body = {
            "chain_id": chain_id, "payer": payer, "recipient": recipient,
            "amount": amount, "schedule": schedule, "max_occurrences": occurrences,
            "max_fee_per_execution": fee_cap, "sequence": int(sequence),
            "version": version, "replaces": replaces,
        }
        body["id"] = _id("tau.payments.standing.v1", body)
        return body

    def _count_standing(self, payer: str) -> int:
        return sum(1 for row in self.standing.values() if row["payer"] == payer)

    def add_standing(self, payer: str, sequence: int, chain_id: str, tx: dict,
                     version: int = 1, replaces: str = "") -> dict:
        if self._count_standing(payer) >= MAX_OPEN_STANDING_PER_PAYER:
            raise PaymentShapeError("standing_cap", "too many open standing payments for this payer")
        if len(self.standing) >= MAX_OPEN_STANDING_TOTAL:
            raise PaymentShapeError("standing_cap", "the standing-payment book is full")
        terms = self._standing_terms(payer, sequence, chain_id, tx, version, replaces)
        if terms["id"] in self.standing or terms["id"] in self.resolved_standing:
            raise PaymentShapeError("duplicate", "this standing payment already exists")
        row = {
            **terms,
            "status": "open",
            "next_index": 0,
            "executions": 0,
            "total_executed": 0,
            "history": [],
        }
        self.standing[row["id"]] = row
        self._dirty()
        return row

    def _finish_standing(self, sid: str, status: str) -> dict:
        row = self.standing.pop(sid)
        row["status"] = status
        self.resolved_standing[sid] = row
        self._dirty()
        return row

    def cancel_standing(self, payer: str, sid: str) -> dict:
        row = self.standing.get(sid)
        if row is None:
            raise PaymentShapeError("standing_unknown", "unknown standing payment")
        if row["payer"] != payer:
            raise PaymentShapeError("not_payer", "only the payer can cancel")
        return self._finish_standing(sid, "cancelled")

    # -- allowances -----------------------------------------------------------

    def _allowance_terms(self, grantor: str, sequence: int, chain_id: str, tx: dict) -> dict:
        grantee = _pubkey(tx.get("grantee_pubkey"), "grantee_pubkey")
        if grantee == grantor:
            raise PaymentShapeError("self_allowance", "an allowance's grantee must differ from the grantor")
        amount = _u64(tx.get("amount"), "amount", 1, tau_defs.MAX_TRANSFER_VALUE)
        start_at = _u64(tx.get("start_at"), "start_at", 0, 10**18)
        hold = _u64(tx.get("hold_seconds"), "hold_seconds", 0, MAX_HORIZON)
        cap = _u64(tx.get("spend_cap"), "spend_cap", 1, tau_defs.MAX_TRANSFER_VALUE)
        kind = _period_kind(tx.get("cap_period"), "cap_period")
        length = _u64(tx.get("cap_length"), "cap_length", 0, MAX_HORIZON)
        if kind == "fixed" and not (MIN_FIXED <= length <= MAX_FIXED):
            raise PaymentShapeError("bad_period", f"fixed cap length must be {MIN_FIXED}..{MAX_FIXED}")
        if kind != "fixed" and length != 0:
            raise PaymentShapeError("bad_period", "cap_length is only used for a fixed period")
        per_draw = _u64(tx.get("per_draw_cap"), "per_draw_cap", 0, tau_defs.MAX_TRANSFER_VALUE)
        weekday = _u64(tx.get("weekday_mask"), "weekday_mask", 0, WEEKDAY_MASK_MAX)
        hour = _u64(tx.get("hour_mask"), "hour_mask", 0, HOUR_MASK_MAX)
        offset = _u64(tx.get("utc_offset_quarters"), "utc_offset_quarters", 0, 0)
        # The field is signed so a later offset cannot be slipped in. v1 is UTC.
        # A non-zero offset is rejected rather than ignored.
        if tx.get("utc_offset_quarters") not in (0, None) and offset != 0:
            raise PaymentShapeError("bad_offset", "utc_offset_quarters must be 0 in this version")
        # Re-read: I set hi to 0 above so non-zero already fails _u64. Good.
        expires = _u64(tx.get("expires_at"), "expires_at", 1, 10**18)
        idle = _u64(tx.get("refund_idle"), "refund_idle", 0, MAX_HORIZON)
        shared_key = tx.get("shared_key") or ""
        if not isinstance(shared_key, str) or len(shared_key) > 64:
            raise PaymentShapeError("bad_shared", "shared_key must be a string of at most 64 characters")
        shared_cap = _u64(tx.get("shared_cap"), "shared_cap", 0, tau_defs.MAX_TRANSFER_VALUE)
        shared_period = tx.get("shared_period") or ""
        shared_length = _u64(tx.get("shared_length"), "shared_length", 0, MAX_HORIZON)
        shared_anchor = _u64(tx.get("shared_anchor"), "shared_anchor", 0, 10**18)
        if shared_key:
            if shared_cap < 1:
                raise PaymentShapeError("bad_shared", "a shared allowance needs a positive cap")
            if shared_period not in ("day", "week", "month", "fixed"):
                raise PaymentShapeError("bad_shared", "shared_period must be day, week, month or fixed")
            if shared_period == "fixed" and not (MIN_FIXED <= shared_length <= MAX_FIXED):
                raise PaymentShapeError("bad_shared", "shared fixed length is out of range")
        body = {
            "chain_id": chain_id, "grantor": grantor, "grantee": grantee,
            "amount": amount, "start_at": start_at, "hold_seconds": hold,
            "spend_cap": cap, "cap_period": kind, "cap_length": length,
            "per_draw_cap": per_draw, "weekday_mask": weekday, "hour_mask": hour,
            "utc_offset_quarters": 0, "expires_at": expires, "refund_idle": idle,
            "shared_key": shared_key, "shared_cap": shared_cap,
            "shared_period": shared_period, "shared_length": shared_length,
            "shared_anchor": shared_anchor, "sequence": int(sequence),
        }
        body["id"] = _id("tau.payments.allowance.v1", body)
        return body

    def _unlock(self, row: dict) -> int:
        opened = int(row["opened_at"])
        start = int(row["start_at"])
        hold_until = opened + int(row["hold_seconds"])
        return max(start, hold_until, opened if start == 0 and row["hold_seconds"] == 0 else 0)

    def _due(self, row: dict, ts: int) -> int:
        unlock = self._unlock(row)
        expires = int(row["expires_at"])
        idle = int(row["refund_idle"])
        if idle <= 0:
            return expires
        base = int(row["last_draw_ts"]) if row["last_draw_ts"] else unlock
        return min(expires, base + idle)

    def add_allowance(self, grantor: str, sequence: int, chain_id: str, tx: dict,
                      opened_at: int) -> dict:
        if sum(1 for row in self.allowances.values() if row["grantor"] == grantor) >= MAX_OPEN_ALLOWANCES_PER_GRANTOR:
            raise PaymentShapeError("allowance_cap", "too many open allowances for this grantor")
        if len(self.allowances) >= MAX_OPEN_ALLOWANCES_TOTAL:
            raise PaymentShapeError("allowance_cap", "the allowance book is full")
        terms = self._allowance_terms(grantor, sequence, chain_id, tx)
        if terms["id"] in self.allowances or terms["id"] in self.resolved_allowances:
            raise PaymentShapeError("duplicate", "this allowance already exists")
        row = {
            **terms,
            "opened_at": int(opened_at),
            "remaining": terms["amount"],
            "spent_period": -1,
            "spent_in_period": 0,
            "total_drawn": 0,
            "last_draw_ts": 0,
            "status": "open",
        }
        unlock = self._unlock(row)
        if unlock >= row["expires_at"]:
            raise PaymentShapeError(
                "never_spendable",
                "the allowance unlocks at or after it expires",
            )
        if not any_moment_allowed(
            unlock, row["expires_at"], row["weekday_mask"], row["hour_mask"], 0
        ):
            raise PaymentShapeError(
                "never_spendable",
                "no moment between unlock and expiry falls inside the schedule",
            )
        if row["shared_key"]:
            self._bind_shared(row)
        self.allowances[row["id"]] = row
        self._dirty()
        return row

    def _shared_meter_key(self, row: dict) -> str:
        return f"{row['grantor']}|{row['grantee']}|{row['shared_key']}"

    def _bind_shared(self, row: dict) -> None:
        key = self._shared_meter_key(row)
        existing = self.shared.get(key)
        spec = {
            "cap": row["shared_cap"],
            "period": row["shared_period"],
            "length": row["shared_length"],
            "anchor": row["shared_anchor"],
        }
        if existing is None:
            if len(self.shared) >= MAX_OPEN_ALLOWANCES_TOTAL:
                raise PaymentShapeError("allowance_cap", "too many shared allowances")
            self.shared[key] = {**spec, "period_index": -1, "spent": 0, "meter_key": key}
            return
        for field, value in spec.items():
            if existing[field] != value:
                raise PaymentShapeError(
                    "shared_conflict",
                    f"shared allowance {row['shared_key']} is already defined with a different {field}",
                )

    def draw_block_reason(self, row: dict, ts: int, amount: int, recipient: str) -> str:
        """Empty string when the draw is allowed. Does not mutate."""
        if row["status"] != "open":
            return "allowance_closed"
        if recipient == row["grantor"]:
            return "refund_not_a_draw"
        if amount < 1 or amount > tau_defs.MAX_TRANSFER_VALUE:
            return "bad_amount"
        if amount > row["remaining"]:
            return "allowance_empty"
        due = self._due(row, ts)
        if ts >= due:
            return "allowance_expired"
        unlock = self._unlock(row)
        if ts < unlock:
            return "allowance_locked"
        if not masks_allow(ts, row["weekday_mask"], row["hour_mask"]):
            return "outside_schedule"
        if row["per_draw_cap"] and amount > row["per_draw_cap"]:
            return "per_draw_cap"
        index = period_index(row["cap_period"], ts, unlock, row["cap_length"])
        spent = row["spent_in_period"] if row["spent_period"] == index else 0
        if spent + amount > row["spend_cap"]:
            return "period_cap"
        if row["shared_key"]:
            meter = self.shared[self._shared_meter_key(row)]
            mindex = period_index(meter["period"], ts, meter["anchor"], meter["length"])
            shared_spent = meter["spent"] if meter["period_index"] == mindex else 0
            if shared_spent + amount > meter["cap"]:
                return "shared_cap"
        return ""

    def commit_draw(self, aid: str, ts: int, amount: int) -> dict:
        row = self.allowances[aid]
        unlock = self._unlock(row)
        index = period_index(row["cap_period"], ts, unlock, row["cap_length"])
        if row["spent_period"] != index:
            row["spent_period"] = index
            row["spent_in_period"] = 0
        row["spent_in_period"] += amount
        row["remaining"] -= amount
        row["total_drawn"] += amount
        row["last_draw_ts"] = int(ts)
        if row["shared_key"]:
            meter = self.shared[self._shared_meter_key(row)]
            mindex = period_index(meter["period"], ts, meter["anchor"], meter["length"])
            if meter["period_index"] != mindex:
                meter["period_index"] = mindex
                meter["spent"] = 0
            meter["spent"] += amount
        if row["remaining"] == 0:
            self._finish_allowance(aid, "spent")
        self._dirty()
        return row

    def _finish_allowance(self, aid: str, status: str) -> dict:
        row = self.allowances.pop(aid)
        row["status"] = status
        row["remaining"] = 0
        self.resolved_allowances[aid] = row
        if row["shared_key"] and not any(
            self._shared_meter_key(other) == self._shared_meter_key(row)
            for other in self.allowances.values()
        ):
            self.shared.pop(self._shared_meter_key(row), None)
        self._dirty()
        return row

    def refund_allowance(self, aid: str, status: str = "refunded") -> int:
        row = self.allowances[aid]
        amount = int(row["remaining"])
        self._finish_allowance(aid, status)
        return amount

    # -- routes ---------------------------------------------------------------

    def set_route(self, owner: str, chain_id: str, tx: dict, ts: int) -> dict:
        current = self.routes.get(owner)
        if current and current.get("locked_until", 0) > ts:
            raise PaymentShapeError("route_locked", "this route is locked until its term")
        dests = _destinations(tx.get("destinations"), owner)
        for dest in dests:
            other = self.routes.get(dest["pubkey"])
            if other and any(item["pubkey"] == owner for item in other["destinations"]):
                raise PaymentShapeError("route_cycle", "that destination already routes back here")
        min_in = _u64(tx.get("min_incoming"), "min_incoming", 0, tau_defs.MAX_TRANSFER_VALUE)
        activate = _u64(tx.get("activate_at"), "activate_at", 0, 10**18)
        expires = _u64(tx.get("expires_at"), "expires_at", 0, 10**18)
        locked = _u64(tx.get("locked_until"), "locked_until", 0, 10**18)
        if locked and not expires:
            raise PaymentShapeError("route_lock", "a locked route needs an expiry")
        if locked and expires < locked:
            raise PaymentShapeError("route_lock", "expiry must be at or after the lock")
        if expires and activate and expires <= activate:
            raise PaymentShapeError("bad_route", "expiry must be after activation")
        body = {
            "chain_id": chain_id, "owner": owner, "destinations": dests,
            "min_incoming": min_in, "activate_at": activate, "expires_at": expires,
            "locked_until": locked,
            "version": 1 if current is None else int(current["version"]) + 1,
        }
        body["id"] = _id("tau.payments.route.v1", body)
        body["status"] = "open"
        self.routes[owner] = body
        self._dirty()
        return body

    def remove_route(self, owner: str, ts: int, *, by_destination: bool = False,
                     actor: str = "") -> dict:
        row = self.routes.get(owner)
        if row is None:
            raise PaymentShapeError("route_unknown", "this account has no receive route")
        if by_destination:
            if actor not in {item["pubkey"] for item in row["destinations"]}:
                raise PaymentShapeError("not_destination", "only a destination can release a locked route")
        elif row.get("locked_until", 0) > ts:
            raise PaymentShapeError("route_locked", "this route is locked until its term")
        self.routes.pop(owner)
        self._dirty()
        return row

    # -- payouts --------------------------------------------------------------

    def set_payout(self, owner: str, chain_id: str, tx: dict) -> dict:
        if owner not in self.payouts and len(self.payouts) >= MAX_PAYOUT_RULES:
            raise PaymentShapeError("payout_cap", "the payout-rule book is full")
        legs = _legs(tx.get("legs"))
        if any(leg["pubkey"] == owner for leg in legs):
            raise PaymentShapeError("self_pay", "a payout leg cannot pay the owner")
        max_exec = _u64(tx.get("max_per_execution"), "max_per_execution", 1, tau_defs.MAX_TRANSFER_VALUE)
        max_period = _u64(tx.get("max_per_period"), "max_per_period", 1, tau_defs.MAX_TRANSFER_VALUE)
        kind = _period_kind(tx.get("period"), "period")
        length = _u64(tx.get("period_length"), "period_length", 0, MAX_HORIZON)
        anchor = _u64(tx.get("period_anchor"), "period_anchor", 0, 10**18)
        if kind == "fixed" and not (MIN_FIXED <= length <= MAX_FIXED):
            raise PaymentShapeError("bad_period", "payout fixed period length is out of range")
        occurrences = _u64(tx.get("max_executions"), "max_executions", 1, MAX_OCCURRENCES)
        expires = _u64(tx.get("expires_at"), "expires_at", 1, 10**18)
        if tx.get("bounded_by_gross") not in (True, False):
            raise PaymentShapeError("bad_field", "bounded_by_gross must be a boolean")
        clause = tx.get("clause") or ""
        if not isinstance(clause, str) or len(clause.encode("utf-8")) > MAX_CLAUSE_BYTES:
            raise PaymentShapeError("bad_clause", f"clause must be text of at most {MAX_CLAUSE_BYTES} bytes")
        current = self.payouts.get(owner)
        body = {
            "chain_id": chain_id, "owner": owner, "legs": legs,
            "max_per_execution": max_exec, "max_per_period": max_period,
            "period": kind, "period_length": length, "period_anchor": anchor,
            "max_executions": occurrences, "expires_at": expires,
            "bounded_by_gross": bool(tx.get("bounded_by_gross")),
            "clause": clause,
            "version": 1 if current is None else int(current["version"]) + 1,
        }
        body["id"] = _id("tau.payments.payout.v1", body)
        body.update({
            "status": "open",
            "executions": 0,
            "period_index": -1,
            "spent_in_period": 0,
            "events": [],
        })
        self.payouts[owner] = body
        self._dirty()
        return body

    def remove_payout(self, owner: str) -> dict:
        row = self.payouts.pop(owner, None)
        if row is None:
            raise PaymentShapeError("payout_unknown", "this account has no payout rule")
        self._dirty()
        return row


def restore_books(snapshot: dict) -> PaymentBooks:
    """Rebuild a book from its snapshot. A row whose id does not match its terms is refused."""
    if not isinstance(snapshot, dict):
        raise ValueError("payments snapshot is not an object")
    book = PaymentBooks()

    def take(name: str) -> List[dict]:
        rows = snapshot.get(name) or []
        if not isinstance(rows, list):
            raise ValueError(f"payments snapshot {name} is not a list")
        return rows

    for row in take("standing"):
        book.standing[row["id"]] = copy.deepcopy(row)
    for row in take("resolved_standing"):
        book.resolved_standing[row["id"]] = copy.deepcopy(row)
    for row in take("allowances"):
        book.allowances[row["id"]] = copy.deepcopy(row)
    for row in take("resolved_allowances"):
        book.resolved_allowances[row["id"]] = copy.deepcopy(row)
    for row in take("routes"):
        book.routes[row["owner"]] = copy.deepcopy(row)
    for row in take("payouts"):
        book.payouts[row["owner"]] = copy.deepcopy(row)
    for row in take("shared"):
        key = f"{row['grantor']}|{row['grantee']}|{row['key']}" if "key" in row else None
        # Shared rows are stored with their meter key.
        meter_key = row.get("meter_key")
        if not isinstance(meter_key, str):
            raise ValueError("shared allowance is missing meter_key")
        book.shared[meter_key] = copy.deepcopy(row)
    for sid, row in list(book.standing.items()) + list(book.resolved_standing.items()):
        check = dict(row)
        for mutable in ("status", "next_index", "executions", "total_executed", "history"):
            check.pop(mutable, None)
        expect = check.pop("id")
        if _id("tau.payments.standing.v1", check) != expect or expect != sid:
            raise ValueError("standing payment id does not match its terms")
    book._dirty()
    # Recompute and keep; a caller that cares compares root() to the meta hash.
    book.root()
    return book


def _fail(exc: PaymentShapeError) -> Stage:
    return Stage.reject(exc.reason, exc.detail)


def stage_tx(tx: dict, *, sender: str, sequence: int, height: int, ts: int,
             chain_id: str, lm, read_bal: Callable[[str], int]) -> Stage:
    """Decide one payment transaction. The book is unchanged until ``commit``."""
    book: PaymentBooks = lm.programmable
    tx_type = tx.get("tx_type")
    try:
        signed_chain = _check_chain(tx, chain_id)
        if tx_type == TX_STANDING_CREATE:
            # Validate fully before commit, including caps.
            preview = book._standing_terms(sender, sequence, signed_chain, tx, 1, "")
            if book._count_standing(sender) >= MAX_OPEN_STANDING_PER_PAYER:
                raise PaymentShapeError("standing_cap", "too many open standing payments for this payer")
            if len(book.standing) >= MAX_OPEN_STANDING_TOTAL:
                raise PaymentShapeError("standing_cap", "the standing-payment book is full")

            def commit(target: PaymentBooks, preview=preview, sender=sender, sequence=sequence,
                       signed_chain=signed_chain, tx=tx):
                row = target.add_standing(sender, sequence, signed_chain, tx, 1, "")
                if row["id"] != preview["id"]:
                    raise BlockchainBug("standing id changed between admit and commit")
                return {"standing_id": row["id"], "status": "open"}

            return Stage(True, commit=commit, receipt={"standing_id": preview["id"], "status": "open"})

        if tx_type == TX_STANDING_CANCEL:
            sid = _hex32(tx.get("standing_id"), "standing_id")
            row = book.standing.get(sid)
            if row is None or row["payer"] != sender:
                raise PaymentShapeError("standing_unknown", "unknown standing payment for this payer")

            def commit(target: PaymentBooks, sid=sid, sender=sender):
                target.cancel_standing(sender, sid)
                return {"standing_id": sid, "status": "cancelled"}

            return Stage(True, commit=commit, receipt={"standing_id": sid, "status": "cancelled"})

        if tx_type == TX_STANDING_UPDATE:
            sid = _hex32(tx.get("standing_id"), "standing_id")
            row = book.standing.get(sid)
            if row is None or row["payer"] != sender:
                raise PaymentShapeError("standing_unknown", "unknown standing payment for this payer")
            replacement = book._standing_terms(
                sender, sequence, signed_chain, tx, int(row["version"]) + 1, sid
            )

            def commit(target: PaymentBooks, sid=sid, sender=sender, sequence=sequence,
                       signed_chain=signed_chain, tx=tx, version=int(row["version"]) + 1):
                target.cancel_standing(sender, sid)
                # cancel frees the per-payer slot before add counts it
                created = target.add_standing(sender, sequence, signed_chain, tx, version, sid)
                # cancel stored the old row as cancelled; say replaced.
                target.resolved_standing[sid]["status"] = "replaced"
                target._dirty()
                return {"standing_id": created["id"], "replaces": sid, "status": "open"}

            return Stage(True, commit=commit, receipt={
                "standing_id": replacement["id"], "replaces": sid, "status": "open",
            })

        if tx_type == TX_STANDING_EXECUTE:
            sid = _hex32(tx.get("standing_id"), "standing_id")
            occurrence = _u64(tx.get("occurrence"), "occurrence", 0, MAX_OCCURRENCES)
            row = book.standing.get(sid)
            if row is None:
                raise PaymentShapeError("standing_unknown", "unknown standing payment")
            if occurrence != row["next_index"]:
                raise PaymentShapeError("standing_not_due", "only the open occurrence can be executed")
            state = _classify(row["schedule"], occurrence, height, ts)
            if state == "early":
                raise PaymentShapeError("standing_not_due", "this occurrence is not open yet")
            if state == "missed":
                raise PaymentShapeError("standing_missed", "this occurrence's window has closed")
            if _policy_blocks(lm, row["payer"], row["recipient"], row["amount"], ts):
                raise PaymentShapeError("user_policy_block", "the payer's current policy blocks this payment")
            have = read_bal(row["payer"])
            if have < row["amount"]:
                raise PaymentShapeError("insufficient_funds", "the payer cannot cover this occurrence")
            writes = {
                row["payer"]: have - row["amount"],
                row["recipient"]: read_bal(row["recipient"]) + row["amount"],
            }

            def commit(target: PaymentBooks, sid=sid, occurrence=occurrence, amount=row["amount"]):
                entry = target.standing[sid]
                if entry["next_index"] != occurrence:
                    raise BlockchainBug("standing occurrence moved between admit and commit")
                entry["next_index"] = occurrence + 1
                entry["executions"] += 1
                entry["total_executed"] += amount
                entry["history"].append({"index": occurrence, "result": "paid"})
                status = "open"
                if entry["next_index"] >= entry["max_occurrences"]:
                    target._finish_standing(sid, "completed")
                    status = "completed"
                else:
                    target._dirty()
                return {"standing_id": sid, "occurrence": occurrence, "result": "paid", "status": status}

            return Stage(True, writes=writes, commit=commit, stamp=[row["payer"]], receipt={
                "standing_id": sid, "occurrence": occurrence, "result": "paid",
                "amount": row["amount"], "recipient": row["recipient"],
            })

        if tx_type == TX_ALLOWANCE_OPEN:
            # Terms are checked inside add, against the block time.
            preview_id = book._allowance_terms(sender, sequence, signed_chain, tx)["id"]
            have = read_bal(sender)
            amount = _u64(tx.get("amount"), "amount", 1, tau_defs.MAX_TRANSFER_VALUE)
            if have < amount:
                raise PaymentShapeError("insufficient_funds", "the grantor cannot fund this allowance")
            # Reject a never-spendable mix before taking the coins. add_allowance
            # repeats the check on commit.
            scratch = PaymentBooks()
            scratch.shared = copy.deepcopy(book.shared)
            scratch.allowances = copy.deepcopy(book.allowances)
            scratch.add_allowance(sender, sequence, signed_chain, tx, ts)
            writes = {sender: have - amount}

            def commit(target: PaymentBooks, sender=sender, sequence=sequence,
                       signed_chain=signed_chain, tx=tx, ts=ts):
                row = target.add_allowance(sender, sequence, signed_chain, tx, ts)
                return {"allowance_id": row["id"], "status": "open", "remaining": row["remaining"]}

            return Stage(True, writes=writes, commit=commit, stamp=[sender], receipt={
                "allowance_id": preview_id, "status": "open",
            })

        if tx_type == TX_ALLOWANCE_DRAW:
            aid = _hex32(tx.get("allowance_id"), "allowance_id")
            row = book.allowances.get(aid)
            if row is None or row["grantee"] != sender:
                raise PaymentShapeError("allowance_unknown", "unknown allowance for this grantee")
            recipient = _pubkey(tx.get("recipient_pubkey"), "recipient_pubkey")
            amount = _u64(tx.get("amount"), "amount", 1, tau_defs.MAX_TRANSFER_VALUE)
            if _policy_blocks(lm, sender, recipient, amount, ts):
                raise PaymentShapeError("user_policy_block", "the grantee's current policy blocks this draw")
            reason = book.draw_block_reason(row, ts, amount, recipient)
            if reason:
                raise PaymentShapeError(reason, reason)
            writes = {recipient: read_bal(recipient) + amount}

            def commit(target: PaymentBooks, aid=aid, ts=ts, amount=amount):
                target.commit_draw(aid, ts, amount)
                return {"allowance_id": aid, "amount": amount, "result": "drawn"}

            return Stage(True, writes=writes, commit=commit, stamp=[sender], receipt={
                "allowance_id": aid, "amount": amount, "recipient": recipient, "result": "drawn",
            })

        if tx_type == TX_ALLOWANCE_RELEASE:
            aid = _hex32(tx.get("allowance_id"), "allowance_id")
            row = book.allowances.get(aid)
            if row is None or row["grantor"] != sender:
                raise PaymentShapeError("allowance_unknown", "unknown allowance for this grantor")
            if ts >= row["expires_at"]:
                raise PaymentShapeError("allowance_expired", "the allowance has reached its refund point")
            amount = int(row["remaining"])
            writes = {row["grantee"]: read_bal(row["grantee"]) + amount}

            def commit(target: PaymentBooks, aid=aid):
                target.refund_allowance(aid, "released")
                return {"allowance_id": aid, "result": "released"}

            return Stage(True, writes=writes, commit=commit, receipt={
                "allowance_id": aid, "amount": amount, "result": "released",
            })

        if tx_type == TX_ROUTE_SET:
            # Validate against a scratch copy of routes so commit cannot diverge.
            scratch = PaymentBooks()
            scratch.routes = copy.deepcopy(book.routes)
            created = scratch.set_route(sender, signed_chain, tx, ts)

            def commit(target: PaymentBooks, sender=sender, signed_chain=signed_chain, tx=tx, ts=ts):
                row = target.set_route(sender, signed_chain, tx, ts)
                return {"route_id": row["id"], "status": "open"}

            return Stage(True, commit=commit, receipt={"route_id": created["id"], "status": "open"})

        if tx_type == TX_ROUTE_REMOVE:
            if sender not in book.routes:
                raise PaymentShapeError("route_unknown", "this account has no receive route")
            if book.routes[sender].get("locked_until", 0) > ts:
                raise PaymentShapeError("route_locked", "this route is locked until its term")

            def commit(target: PaymentBooks, sender=sender, ts=ts):
                target.remove_route(sender, ts)
                return {"status": "removed"}

            return Stage(True, commit=commit, receipt={"status": "removed"})

        if tx_type == TX_ROUTE_RELEASE:
            owner = _pubkey(tx.get("owner_pubkey"), "owner_pubkey")
            row = book.routes.get(owner)
            if row is None or sender not in {item["pubkey"] for item in row["destinations"]}:
                raise PaymentShapeError("not_destination", "only a named destination can release this route")

            def commit(target: PaymentBooks, owner=owner, sender=sender, ts=ts):
                target.remove_route(owner, ts, by_destination=True, actor=sender)
                return {"status": "released", "owner": owner}

            return Stage(True, commit=commit, receipt={"status": "released", "owner": owner})

        if tx_type == TX_PAYOUT_SET:
            scratch = PaymentBooks()
            scratch.payouts = copy.deepcopy(book.payouts)
            created = scratch.set_payout(sender, signed_chain, tx)

            def commit(target: PaymentBooks, sender=sender, signed_chain=signed_chain, tx=tx):
                row = target.set_payout(sender, signed_chain, tx)
                return {"payout_id": row["id"], "status": "open"}

            return Stage(True, commit=commit, receipt={"payout_id": created["id"], "status": "open"})

        if tx_type == TX_PAYOUT_REMOVE:
            if sender not in book.payouts:
                raise PaymentShapeError("payout_unknown", "this account has no payout rule")

            def commit(target: PaymentBooks, sender=sender):
                target.remove_payout(sender)
                return {"status": "removed"}

            return Stage(True, commit=commit, receipt={"status": "removed"})

        if tx_type == TX_PAYOUT_EXECUTE:
            owner = _pubkey(tx.get("owner_pubkey"), "owner_pubkey")
            rule = book.payouts.get(owner)
            if rule is None:
                raise PaymentShapeError("payout_unknown", "this account has no payout rule")
            if ts >= rule["expires_at"]:
                raise PaymentShapeError("payout_expired", "this payout rule has expired")
            if rule["executions"] >= rule["max_executions"]:
                raise PaymentShapeError("payout_exhausted", "this payout rule has run its course")
            event = _hex32(tx.get("event_id"), "event_id")
            if event in rule["events"]:
                raise PaymentShapeError("duplicate_event", "this event was already paid")
            if len(rule["events"]) >= MAX_EVENTS_PER_RULE:
                raise PaymentShapeError("event_cap", "this rule is holding too many unsettled events")
            gross = _u64(tx.get("gross"), "gross", 0, tau_defs.MAX_TRANSFER_VALUE)
            amounts = leg_amounts(rule["legs"], gross)
            total = sum(amount for _, amount in amounts)
            if total < 1:
                raise PaymentShapeError("zero_payout", "the rule produced no payment")
            if rule["bounded_by_gross"] and total > gross:
                raise PaymentShapeError("over_gross", "the legs sum to more than the gross")
            if total > rule["max_per_execution"]:
                raise PaymentShapeError("payout_cap", "the execution exceeds its cap")
            index = period_index(rule["period"], ts, rule["period_anchor"], rule["period_length"])
            spent = rule["spent_in_period"] if rule["period_index"] == index else 0
            if spent + total > rule["max_per_period"]:
                raise PaymentShapeError("period_cap", "the execution exceeds this period's cap")
            if read_bal(owner) < total:
                raise PaymentShapeError("insufficient_funds", "the owner cannot cover this payout")
            extra = {13: str(gross), 2: str(spent)}
            if rule["clause"] and _policy_blocks(
                lm, owner, amounts[0][0], total, ts, body=rule["clause"], extra=extra
            ):
                raise PaymentShapeError("user_policy_block", "the payout clause blocks this execution")
            if _policy_blocks(lm, owner, amounts[0][0], total, ts, extra=extra):
                raise PaymentShapeError("user_policy_block", "the owner's current policy blocks this payout")
            running = {owner: read_bal(owner) - total}
            for pubkey, amount in amounts:
                base = running[pubkey] if pubkey in running else read_bal(pubkey)
                running[pubkey] = base + amount

            def commit(target: PaymentBooks, owner=owner, event=event, total=total,
                       index=index, ts=ts):
                rule_row = target.payouts[owner]
                if event in rule_row["events"]:
                    raise BlockchainBug("payout event settled twice")
                if rule_row["period_index"] != index:
                    rule_row["period_index"] = index
                    rule_row["spent_in_period"] = 0
                rule_row["spent_in_period"] += total
                rule_row["executions"] += 1
                rule_row["events"].append(event)
                target._dirty()
                return {"payout_id": rule_row["id"], "event_id": event, "total": total, "result": "paid"}

            return Stage(
                True, writes=running, commit=commit, stamp=[owner],
                receipt={
                    "owner": owner, "event_id": event, "total": total,
                    "legs": [{"pubkey": pubkey, "amount": amount} for pubkey, amount in amounts],
                    "result": "paid",
                },
            )

        raise PaymentShapeError("bad_type", f"unsupported payment type {tx_type}")
    except PaymentShapeError as exc:
        return _fail(exc)


def apply_receive_routes(book: PaymentBooks, credits: List[Tuple[str, int]], ts: int,
                         read_bal: Callable[[str], int], staged: dict) -> List[dict]:
    """Split ordinary transfer credits in place. One hop: outputs are not credits."""
    events = []
    for recipient, gross in credits:
        route = book.routes.get(recipient)
        if route is None:
            continue
        if ts < int(route["activate_at"]):
            continue
        if route["expires_at"] and ts >= int(route["expires_at"]):
            continue
        gross = int(gross)
        if gross < int(route["min_incoming"]):
            continue
        parts = []
        for dest in route["destinations"]:
            part = (gross * int(dest["bps"])) // 10000
            if part > 0:
                parts.append((dest["pubkey"], part))
        if not parts:
            continue
        routed = sum(part for _, part in parts)
        if routed > gross:
            raise BlockchainBug("receive route routed more than the gross credit")
        staged[recipient] = read_bal(recipient) - routed
        for dest, part in parts:
            staged[dest] = read_bal(dest) + part
        events.append({
            "owner": recipient,
            "gross": gross,
            "net": gross - routed,
            "routed": [{"pubkey": dest, "amount": part} for dest, part in parts],
        })
    return events


def sweep(lm, balances: dict, sequences: dict, height: int, ts: int) -> List[dict]:
    """Refund due allowances and pay due standing occurrences. Fee-free.

    Runs after the block's transactions, so a cancel or a draw in this block
    is already visible. A routed share is never produced here.
    """
    from consensus import faucet

    book: PaymentBooks = lm.programmable
    if book.is_empty():
        return []
    grant = faucet.amount(lm)
    events: List[dict] = []
    actions = 0

    def bal(addr: str) -> int:
        return faucet.spendable(balances, sequences, addr, grant)

    due_ids = sorted(
        aid for aid, row in book.allowances.items() if ts >= book._due(row, ts)
    )
    for aid in due_ids:
        if actions >= MAX_SWEEP_ACTIONS:
            break
        row = book.allowances.get(aid)
        if row is None:
            continue
        grantor = row["grantor"]
        amount = book.refund_allowance(aid, "refunded")
        if amount:
            balances[grantor] = bal(grantor) + amount
        events.append({
            "kind": "allowance_refund", "allowance_id": aid,
            "amount": amount, "to": grantor,
        })
        actions += 1

    candidates = []
    for sid, row in book.standing.items():
        state = _classify(row["schedule"], row["next_index"], height, ts)
        if state != "early":
            candidates.append((occurrence_due(row["schedule"], row["next_index"]), sid))
    candidates.sort()
    considered = 0
    for _due, sid in candidates:
        if actions >= MAX_SWEEP_ACTIONS or considered >= MAX_SWEEP_ACTIONS:
            break
        considered += 1
        skips = 0
        while actions < MAX_SWEEP_ACTIONS and skips < MAX_SKIPS_PER_ENTRY:
            row = book.standing.get(sid)
            if row is None:
                break
            index = row["next_index"]
            if index >= row["max_occurrences"]:
                book._finish_standing(sid, "completed")
                actions += 1
                break
            state = _classify(row["schedule"], index, height, ts)
            if state == "early":
                break
            blocked = False
            if state == "payable":
                blocked = _policy_blocks(lm, row["payer"], row["recipient"], row["amount"], ts)
            if state == "missed" or blocked:
                row["history"].append({"index": index, "result": "missed"})
                row["next_index"] = index + 1
                book._dirty()
                if row["next_index"] >= row["max_occurrences"]:
                    book._finish_standing(sid, "completed")
                events.append({
                    "kind": "standing_missed", "standing_id": sid, "occurrence": index,
                    "reason": "policy" if blocked else "window",
                })
                actions += 1
                skips += 1
                continue
            if bal(row["payer"]) < row["amount"]:
                events.append({
                    "kind": "standing_unfunded", "standing_id": sid, "occurrence": index,
                })
                break
            amount = row["amount"]
            recipient = row["recipient"]
            balances[row["payer"]] = bal(row["payer"]) - amount
            balances[recipient] = bal(recipient) + amount
            row["history"].append({"index": index, "result": "paid"})
            row["next_index"] = index + 1
            row["executions"] += 1
            row["total_executed"] += amount
            book._dirty()
            status = "open"
            if row["next_index"] >= row["max_occurrences"]:
                book._finish_standing(sid, "completed")
                status = "completed"
            events.append({
                "kind": "standing_paid", "standing_id": sid, "occurrence": index,
                "amount": amount, "recipient": recipient, "status": status,
            })
            actions += 1
            break
    return events


def has_due(book: PaymentBooks, height: int, ts: int) -> bool:
    for row in book.allowances.values():
        if ts >= book._due(row, ts):
            return True
    for row in book.standing.values():
        if _classify(row["schedule"], row["next_index"], height, ts) != "early":
            return True
    return False


def resolve_chain_id(snapshot) -> str:
    """The network a payment must name. A pinned test value wins; otherwise the genesis hash.

    An uninitialized database is not opened from here. A node that does not
    know its genesis fails closed.
    """
    meta = getattr(snapshot, "metadata", None) or {}
    pinned = meta.get("payments_chain_id")
    if isinstance(pinned, str) and pinned.strip():
        return pinned.strip().lower()
    import db
    if getattr(db, "_db_conn", None) is None:
        return ""
    try:
        return (db.get_genesis_hash() or "").strip().lower()
    except Exception:
        return ""


def public_views(book: PaymentBooks) -> dict:
    """What `getpayments` returns. Progress as well as the signed terms."""
    return {
        "capability": CAPABILITY,
        "standing": list(book.snapshot()["standing"]),
        "allowances": list(book.snapshot()["allowances"]),
        "routes": list(book.snapshot()["routes"]),
        "payouts": list(book.snapshot()["payouts"]),
    }
