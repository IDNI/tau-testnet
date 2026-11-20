"""Conditional grants: escrowed funds a grantee spends under signed conditions.

A grantor locks funds with ``grant_create``. The funds leave the grantor's
balance and are NOT credited to the grantee, which is what makes the
conditions enforceable: the grantee can only move them with ``grant_draw``,
and every draw is checked against the grant's signed terms:

- time lock: no draw before ``start_at``;
- spending limit: at most ``spend_cap`` per period (``consensus.periods``),
  resetting automatically when a new period starts;
- per-payment limit: at most ``per_payment_cap`` per draw;
- time window: only on the weekdays and UTC hours set in the masks;
- expiry: no draw at or after ``expires_at``; the first block that reaches it
  returns whatever is left to ``refund_to`` with no transaction from anyone.

All conditions are AND-ed. Within a block the transactions apply first and
the expiry sweep after them, so a draw (which needs ``ts < expires_at``) and the
refund can never both happen for the same grant in one block.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would make
two honest nodes disagree about admissibility, which forks. Validation lives in
pure functions shared by admission and apply, as in ``consensus.retractable``.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus import periods
from consensus.serialization import (
    compute_grant_book_root,
    compute_grant_id,
    compute_grant_resolved_acc,
)

TX_TYPE_GRANT_CREATE = "grant_create"
TX_TYPE_GRANT_DRAW = "grant_draw"
TX_TYPE_GRANT_CANCEL = "grant_cancel"

GRANT_TX_TYPES = frozenset({TX_TYPE_GRANT_CREATE, TX_TYPE_GRANT_DRAW, TX_TYPE_GRANT_CANCEL})

GRANT_STATUS_OPEN = "open"
GRANT_STATUS_EXPIRED = "expired"
GRANT_STATUS_CANCELLED = "cancelled"
GRANT_STATUS_EXHAUSTED = "exhausted"

# Folded into the resolved commitment as one byte per resolution.
OUTCOME_EXPIRED = 1
OUTCOME_CANCELLED = 2
OUTCOME_EXHAUSTED = 3

MAX_OPEN_GRANTS_PER_GRANTOR = 16
MAX_OPEN_GRANTS_TOTAL = 4096
MAX_GRANT_HORIZON_SECONDS = 31_536_000

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class GrantShapeError(ValueError):
    """A grant transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class GrantTerms:
    """Everything the grantor signed. Never changes after creation."""

    grantor_pubkey: str
    grantee_pubkey: str
    refund_to_pubkey: str
    amount: int
    sequence_number: int
    start_at: int
    expires_at: int
    spend_cap: int  # 0 = no periodic limit
    cap_period_kind: int
    cap_period_seconds: int  # only for periods.PERIOD_FIXED, else 0
    per_payment_cap: int  # 0 = no per-payment limit
    weekday_mask: int
    hour_mask: int
    revocable: bool

    def as_tuple(self) -> tuple:
        return (
            self.grantor_pubkey, self.grantee_pubkey, self.refund_to_pubkey,
            self.amount, self.sequence_number, self.start_at, self.expires_at,
            self.spend_cap, self.cap_period_kind, self.cap_period_seconds,
            self.per_payment_cap, self.weekday_mask, self.hour_mask, self.revocable,
        )

    @property
    def grant_id(self) -> bytes:
        return compute_grant_id(*self.as_tuple())

    def cap_period_index(self, ts: int) -> int:
        return periods.period_index(
            self.cap_period_kind, ts,
            anchor=self.start_at, length=self.cap_period_seconds,
        )


@dataclass(frozen=True)
class GrantState:
    """An open grant: its terms plus what has been spent so far."""

    terms: GrantTerms
    remaining: int
    cap_period_index: int
    spent_in_period: int

    def spent_this_period(self, ts: int) -> int:
        if not self.terms.spend_cap:
            return 0
        return self.spent_in_period if self.terms.cap_period_index(ts) == self.cap_period_index else 0

    def drawable_now(self, ts: int) -> int:
        """Largest single draw the terms allow at ``ts`` (0 when none)."""
        t = self.terms
        if ts < t.start_at or ts >= t.expires_at:
            return 0
        if not periods.in_time_window(ts, t.weekday_mask, t.hour_mask):
            return 0
        limit = self.remaining
        if t.per_payment_cap:
            limit = min(limit, t.per_payment_cap)
        if t.spend_cap:
            limit = min(limit, t.spend_cap - self.spent_this_period(ts))
        return max(limit, 0)


@dataclass(frozen=True)
class GrantDraw:
    grantee_pubkey: str
    grant_id: bytes
    recipient_pubkey: str
    amount: int


@dataclass(frozen=True)
class GrantCancel:
    grantor_pubkey: str
    grant_id: bytes


# --- Parsing (ROOT fields only; a nested `payload` is unsigned data) -----------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise GrantShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    value = tx.get(name, default)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise GrantShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _id_field(tx: Dict[str, Any]) -> bytes:
    raw = tx.get("grant_id")
    if not isinstance(raw, str) or not _ID_RE.match(raw):
        raise GrantShapeError("grant_id must be 64 lowercase hex characters")
    return bytes.fromhex(raw)


def parse_grant_create(tx: Dict[str, Any]) -> GrantTerms:
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    grantor = _pubkey_field(tx, "sender_pubkey")
    revocable = tx.get("revocable", False)
    if not isinstance(revocable, bool):
        raise GrantShapeError("revocable must be a boolean")
    refund_to = tx.get("refund_to_pubkey")
    refund_to = grantor if refund_to is None else _pubkey_field(tx, "refund_to_pubkey")
    return GrantTerms(
        grantor_pubkey=grantor,
        grantee_pubkey=_pubkey_field(tx, "grantee_pubkey"),
        refund_to_pubkey=refund_to,
        amount=_u64_field(tx, "amount"),
        sequence_number=_u64_field(tx, "sequence_number"),
        start_at=_u64_field(tx, "start_at", 0),
        expires_at=_u64_field(tx, "expires_at"),
        spend_cap=_u64_field(tx, "spend_cap", 0),
        cap_period_kind=_u64_field(tx, "cap_period_kind", periods.PERIOD_WEEK),
        cap_period_seconds=_u64_field(tx, "cap_period_seconds", 0),
        per_payment_cap=_u64_field(tx, "per_payment_cap", 0),
        weekday_mask=_u64_field(tx, "weekday_mask", periods.ALL_WEEKDAYS_MASK),
        hour_mask=_u64_field(tx, "hour_mask", periods.ALL_HOURS_MASK),
        revocable=revocable,
    )


def parse_grant_draw(tx: Dict[str, Any]) -> GrantDraw:
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    return GrantDraw(
        grantee_pubkey=_pubkey_field(tx, "sender_pubkey"),
        grant_id=_id_field(tx),
        recipient_pubkey=_pubkey_field(tx, "recipient_pubkey"),
        amount=_u64_field(tx, "amount"),
    )


def parse_grant_cancel(tx: Dict[str, Any]) -> GrantCancel:
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    return GrantCancel(grantor_pubkey=_pubkey_field(tx, "sender_pubkey"), grant_id=_id_field(tx))


def validate_grant_terms(terms: GrantTerms, ts: int) -> Optional[str]:
    """Stateless admissibility of a new grant at block time ``ts``. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything needing the book lives in ``GrantBook.can_admit_create``.
    """
    t = terms
    if not (1 <= t.amount <= tau_defs.MAX_TRANSFER_VALUE):
        return f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if t.grantee_pubkey == t.grantor_pubkey:
        return "grantee must differ from grantor"
    if t.expires_at <= ts:
        return "expires_at must be in the future"
    if t.expires_at > ts + MAX_GRANT_HORIZON_SECONDS:
        return f"expires_at is more than {MAX_GRANT_HORIZON_SECONDS} seconds ahead"
    if t.start_at >= t.expires_at:
        return "start_at must be before expires_at"
    if t.spend_cap > t.amount:
        return "spend_cap cannot exceed amount"
    if t.per_payment_cap > t.amount:
        return "per_payment_cap cannot exceed amount"
    try:
        periods.validate_period(t.cap_period_kind, t.cap_period_seconds)
    except periods.PeriodError as exc:
        return f"invalid cap period ({exc})"
    if not 1 <= t.weekday_mask <= periods.ALL_WEEKDAYS_MASK:
        return "weekday_mask must allow at least one day (7 bits)"
    if not 1 <= t.hour_mask <= periods.ALL_HOURS_MASK:
        return "hour_mask must allow at least one hour (24 bits)"
    return None


# --- The book -----------------------------------------------------------------

_Row = Tuple[bytes, GrantTerms, int, int, int]


class GrantBook:
    """open -> expired | cancelled | exhausted, with a constant-size resolved commitment.

    Composed as a FIELD of ConsensusLifecycleManager next to the retractable
    book, so the meta hash picks up its root.
    """

    def __init__(self) -> None:
        self.open: Dict[bytes, GrantState] = {}
        self._expiry: List[Tuple[int, bytes]] = []
        self._per_grantor: Dict[str, int] = {}
        self._escrow = 0
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    # -- copying / restoring -------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "GrantBook":
        clone = GrantBook.__new__(GrantBook)
        clone.open = dict(self.open)  # GrantState is frozen: sharing is safe
        clone._expiry = list(self._expiry)
        clone._per_grantor = dict(self._per_grantor)
        clone._escrow = self._escrow
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls, rows: Iterable[_Row], resolved_count: int, resolved_acc: bytes
    ) -> "GrantBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for stored_id, terms, remaining, period_index, spent in rows:
            gid = terms.grant_id
            if gid != bytes(stored_id):
                raise ValueError(f"stored grant id does not match its terms: {gid.hex()}")
            if gid in book.open:
                raise ValueError(f"duplicate stored grant: {gid.hex()}")
            if not (1 <= remaining <= terms.amount) or spent < 0:
                raise ValueError(f"stored grant has an impossible balance: {gid.hex()}")
            book._insert(gid, GrantState(terms, remaining, period_index, spent))
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals -----------------------------------------------------------

    def _insert(self, gid: bytes, state: GrantState) -> None:
        self.open[gid] = state
        bisect.insort(self._expiry, (state.terms.expires_at, gid))
        g = state.terms.grantor_pubkey
        self._per_grantor[g] = self._per_grantor.get(g, 0) + 1
        self._escrow += state.remaining
        self._root = None

    def _resolve(self, gid: bytes, outcome: int) -> GrantState:
        state = self.open.pop(gid)
        del self._expiry[bisect.bisect_left(self._expiry, (state.terms.expires_at, gid))]
        g = state.terms.grantor_pubkey
        left = self._per_grantor[g] - 1
        if left:
            self._per_grantor[g] = left
        else:
            del self._per_grantor[g]
        self._escrow -= state.remaining
        self.resolved_acc = compute_grant_resolved_acc(self.resolved_acc, gid, outcome)
        self.resolved_count += 1
        self._root = None
        return state

    # -- queries -------------------------------------------------------------

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_grant_book_root(
                [
                    (gid, s.terms.as_tuple(), s.remaining, s.cap_period_index, s.spent_in_period)
                    for gid, s in self.open.items()
                ],
                self.resolved_count,
                self.resolved_acc,
            )
        return self._root

    def get(self, gid: bytes) -> Optional[GrantState]:
        return self.open.get(gid)

    def open_count(self) -> int:
        return len(self.open)

    def open_count_for_grantor(self, pubkey: str) -> int:
        return self._per_grantor.get(pubkey, 0)

    def escrow_total(self) -> int:
        return self._escrow

    def has_due(self, ts: int) -> bool:
        return bool(self._expiry and self._expiry[0][0] <= ts)

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        out = []
        for gid, s in sorted(self.open.items()):
            t = s.terms
            out.append({
                "grant_id": gid.hex(),
                "grantor_pubkey": t.grantor_pubkey,
                "grantee_pubkey": t.grantee_pubkey,
                "refund_to_pubkey": t.refund_to_pubkey,
                "amount": t.amount,
                "sequence_number": t.sequence_number,
                "start_at": t.start_at,
                "expires_at": t.expires_at,
                "spend_cap": t.spend_cap,
                "cap_period_kind": t.cap_period_kind,
                "cap_period_seconds": t.cap_period_seconds,
                "per_payment_cap": t.per_payment_cap,
                "weekday_mask": t.weekday_mask,
                "hour_mask": t.hour_mask,
                "revocable": t.revocable,
                "remaining": s.remaining,
                "cap_period_index": s.cap_period_index,
                "spent_in_period": s.spent_in_period,
            })
        return out

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    # -- admission -----------------------------------------------------------

    def can_admit_create(self, terms: GrantTerms, ts: int) -> Tuple[bool, str]:
        reason = validate_grant_terms(terms, ts)
        if reason:
            return False, reason
        if terms.grant_id in self.open:
            return False, "grant already exists"
        if self.open_count_for_grantor(terms.grantor_pubkey) >= MAX_OPEN_GRANTS_PER_GRANTOR:
            return False, f"grantor already has {MAX_OPEN_GRANTS_PER_GRANTOR} open grants"
        if len(self.open) >= MAX_OPEN_GRANTS_TOTAL:
            return False, "grant book is full"
        return True, ""

    def can_admit_draw(self, draw: GrantDraw, ts: int) -> Tuple[bool, str]:
        state = self.open.get(draw.grant_id)
        if state is None:
            return False, "unknown or already resolved grant"
        t = state.terms
        if draw.grantee_pubkey != t.grantee_pubkey:
            return False, "only the grantee may draw"
        if not (1 <= draw.amount <= tau_defs.MAX_TRANSFER_VALUE):
            return False, f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
        if ts < t.start_at:
            return False, "grant is time-locked until start_at"
        if ts >= t.expires_at:
            return False, "grant has expired"
        if not periods.in_time_window(ts, t.weekday_mask, t.hour_mask):
            return False, "outside the grant's allowed days or hours"
        if draw.amount > state.remaining:
            return False, "amount exceeds the grant's remaining balance"
        if t.per_payment_cap and draw.amount > t.per_payment_cap:
            return False, "amount exceeds the per-payment cap"
        if t.spend_cap and state.spent_this_period(ts) + draw.amount > t.spend_cap:
            return False, "amount exceeds the spending cap for this period"
        return True, ""

    def can_admit_cancel(self, cancel: GrantCancel, ts: int) -> Tuple[bool, str]:
        state = self.open.get(cancel.grant_id)
        if state is None:
            return False, "unknown or already resolved grant"
        if cancel.grantor_pubkey != state.terms.grantor_pubkey:
            return False, "only the grantor may cancel"
        if not state.terms.revocable:
            return False, "grant is not revocable"
        if ts >= state.terms.expires_at:
            return False, "grant has expired"
        return True, ""

    # -- mutation ------------------------------------------------------------

    def submit(self, terms: GrantTerms, ts: int) -> bytes:
        gid = terms.grant_id
        if gid in self.open:
            raise ValueError("grant already exists")
        index = terms.cap_period_index(max(ts, terms.start_at)) if terms.spend_cap else 0
        self._insert(gid, GrantState(terms, terms.amount, index, 0))
        return gid

    def draw(self, draw: GrantDraw, ts: int) -> GrantState:
        """Debit a checked draw. Returns the state AFTER the draw.

        A draw that empties the grant resolves it as exhausted.
        """
        ok, reason = self.can_admit_draw(draw, ts)
        if not ok:
            raise ValueError(reason)
        state = self.open[draw.grant_id]
        t = state.terms
        if t.spend_cap:
            index = t.cap_period_index(ts)
            spent = state.spent_this_period(ts) + draw.amount
        else:
            index, spent = state.cap_period_index, 0
        after = replace(
            state,
            remaining=state.remaining - draw.amount,
            cap_period_index=index,
            spent_in_period=spent,
        )
        self.open[draw.grant_id] = after
        self._escrow -= draw.amount
        self._root = None
        if after.remaining == 0:
            self._resolve(draw.grant_id, OUTCOME_EXHAUSTED)
        return after

    def cancel(self, gid: bytes) -> GrantState:
        if gid not in self.open:
            raise KeyError(gid.hex())
        return self._resolve(gid, OUTCOME_CANCELLED)

    def expire_due(self, ts: int) -> List[GrantState]:
        """Resolve every grant with ``expires_at <= ts``, in ascending id order.

        Returns the resolved states; the caller credits ``remaining`` to
        ``refund_to_pubkey``.
        """
        end = bisect.bisect_right(self._expiry, (ts, b"\xff" * 33))
        due = sorted(gid for _, gid in self._expiry[:end])
        return [self._resolve(gid, OUTCOME_EXPIRED) for gid in due]


def load_grant_book(state: Dict[str, Any]) -> GrantBook:
    """Rebuild a book from its persisted form (``GrantBook.snapshot_rows`` + resolved).

    Raises ValueError/KeyError/TypeError on any malformed or tampered row.
    """
    rows = []
    for r in state.get("rows", []):
        terms = parse_grant_create({
            "sender_pubkey": r["grantor_pubkey"],
            "grantee_pubkey": r["grantee_pubkey"],
            "refund_to_pubkey": r["refund_to_pubkey"],
            "amount": r["amount"],
            "sequence_number": r["sequence_number"],
            "start_at": r["start_at"],
            "expires_at": r["expires_at"],
            "spend_cap": r["spend_cap"],
            "cap_period_kind": r["cap_period_kind"],
            "cap_period_seconds": r["cap_period_seconds"],
            "per_payment_cap": r["per_payment_cap"],
            "weekday_mask": r["weekday_mask"],
            "hour_mask": r["hour_mask"],
            "revocable": r["revocable"],
        })
        rows.append((
            bytes.fromhex(r["grant_id"]), terms, int(r["remaining"]),
            int(r["cap_period_index"]), int(r["spent_in_period"]),
        ))
    return GrantBook.restore(
        rows, int(state.get("resolved_count", 0)),
        bytes.fromhex(state.get("resolved_acc", "00" * 32)),
    )
