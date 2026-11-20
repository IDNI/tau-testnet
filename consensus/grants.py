"""Conditional grants: held money with draw conditions (#63, stages 2-5).

A grant is held money in its own book entry, not a rule on the
recipient's account: creating one debits the sender immediately into
the entry, so the recipient's own balance is never capped and a
refund never has to pull from a balance that may no longer hold it.

Conditions attach to the grant and combine by AND:

- a per-period spending cap on draws (the window is one week of
  604800 seconds from the grant's opening anchor, the same period
  arithmetic as standing payments);
- time conditions: draws open at `opens_at` and close at
  `deadline`;
- at expiry the refund wins: the end-of-block sweep returns the
  unspent remainder to the sender, fee-free like the codebase's
  other sweep movements, so the remainder is never reduced by a fee
  nobody signed for.

A combination that could never be drawn is refused at creation.
The worked example from the bounty page -- 5,000 granted, cap
500/week, draws open December 1, unspent remainder refunds at the
deadline -- is `test_grant_5000_week_cap_refund_returns_remainder`.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from consensus import periods
from consensus.serialization import canonical_json

TX_TYPE_GRANT_CREATE = "grant_create"
TX_TYPE_GRANT_DRAW = "grant_draw"
GRANT_TX_TYPES = frozenset({TX_TYPE_GRANT_CREATE, TX_TYPE_GRANT_DRAW})

MAX_GRANTS = 4096

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")


def _well_formed_pubkey(pk: str) -> bool:
    return bool(_PUBKEY_RE.match(pk or ""))


class GrantShapeError(ValueError):
    """Raised when grant terms or a draw break the book's rules."""


@dataclass(frozen=True)
class GrantTerms:
    sender: str
    recipient: str
    total: int
    cap_per_period: int
    opens_at: int
    deadline: int
    sequence_number: int = 0

    @property
    def grant_id(self) -> str:
        return compute_grant_id(self)


def compute_grant_id(terms: GrantTerms) -> str:
    payload = {
        "sender": terms.sender,
        "recipient": terms.recipient,
        "total": terms.total,
        "cap_per_period": terms.cap_per_period,
        "opens_at": terms.opens_at,
        "deadline": terms.deadline,
        "sequence_number": terms.sequence_number,
    }
    return hashlib.sha256(canonical_json(payload)).hexdigest()


def validate_grant_shape(terms: GrantTerms) -> None:
    if not _well_formed_pubkey(terms.sender):
        raise GrantShapeError("sender pubkey is not well-formed")
    if not _well_formed_pubkey(terms.recipient):
        raise GrantShapeError("recipient pubkey is not well-formed")
    if terms.sender == terms.recipient:
        raise GrantShapeError("a grant to oneself holds nothing")
    if terms.total <= 0:
        raise GrantShapeError("grant total must be positive")
    if terms.cap_per_period <= 0:
        raise GrantShapeError("the draw cap must be positive")
    if terms.opens_at >= terms.deadline:
        raise GrantShapeError(
            "a grant whose draws never open before the deadline "
            "could never be drawn")


@dataclass
class GrantState:
    terms: GrantTerms
    remaining: int = 0
    period_index: int = -1
    drawn_in_period: int = 0
    last_draw_ts: int = 0
    refunded: bool = False

    def __post_init__(self) -> None:
        if self.remaining == 0 and not self.refunded:
            self.remaining = self.terms.total

    def roll_period(self, ts: int) -> None:
        idx = periods.period_index_at(
            self.terms.opens_at, periods.PERIOD_WEEK, ts)
        if idx != self.period_index:
            self.period_index = idx
            self.drawn_in_period = 0

    def check_draw(self, amount: int, *, ts: int) -> None:
        if self.refunded:
            raise GrantShapeError("the grant is closed")
        if amount <= 0:
            raise GrantShapeError("a draw must be positive")
        if ts < self.terms.opens_at:
            raise GrantShapeError("draws have not opened yet")
        if ts >= self.terms.deadline:
            raise GrantShapeError("the grant has expired; the refund wins")
        if amount > self.remaining:
            raise GrantShapeError("draw exceeds the remaining grant")
        self.roll_period(ts)
        if self.drawn_in_period + amount > self.terms.cap_per_period:
            raise GrantShapeError("draw exceeds the per-period cap")

    def apply_draw(self, amount: int, *, ts: int) -> None:
        self.check_draw(amount, ts=ts)
        self.remaining -= amount
        self.drawn_in_period += amount
        self.last_draw_ts = ts

    def refund_due(self, *, ts: int) -> int:
        """The remainder the sweep must return at this time (0 = none)."""
        if self.refunded or ts < self.terms.deadline:
            return 0
        return self.remaining

    def apply_refund(self) -> int:
        amount = self.remaining
        self.remaining = 0
        self.refunded = True
        return amount


class GrantBook:
    """grant_id -> GrantState, with a content root over the entries."""

    def __init__(self) -> None:
        self._grants: Dict[str, GrantState] = {}
        self._root_cache: Optional[str] = None

    def __len__(self) -> int:
        return len(self._grants)

    def is_empty(self) -> bool:
        return not self._grants

    def get(self, grant_id: str) -> Optional[GrantState]:
        return self._grants.get(grant_id)

    def create(self, terms: GrantTerms) -> GrantState:
        state = GrantState(terms=terms)
        self._grants[terms.grant_id] = state
        self._root_cache = None
        return state

    def due_refunds(self, *, ts: int) -> List[Tuple[str, str, int]]:
        """(grant_id, sender, amount) for every grant the sweep settles."""
        due = []
        for grant_id in sorted(self._grants):
            st = self._grants[grant_id]
            amount = st.refund_due(ts=ts)
            if amount > 0:
                due.append((grant_id, st.terms.sender, amount))
        return due

    def root(self) -> str:
        if self._root_cache is None:
            self._root_cache = hashlib.sha256(
                canonical_json(self.snapshot_rows())).hexdigest()
        return self._root_cache

    def snapshot_rows(self) -> List[dict]:
        rows = []
        for grant_id in sorted(self._grants):
            st = self._grants[grant_id]
            rows.append({
                "grant_id": grant_id,
                "sender": st.terms.sender,
                "recipient": st.terms.recipient,
                "total": st.terms.total,
                "cap_per_period": st.terms.cap_per_period,
                "opens_at": st.terms.opens_at,
                "deadline": st.terms.deadline,
                "sequence_number": st.terms.sequence_number,
                "remaining": st.remaining,
                "period_index": st.period_index,
                "drawn_in_period": st.drawn_in_period,
                "last_draw_ts": st.last_draw_ts,
                "refunded": st.refunded,
            })
        return rows

    @classmethod
    def restore(cls, rows: Sequence[dict]) -> "GrantBook":
        book = cls()
        for row in rows:
            terms = GrantTerms(
                sender=row["sender"],
                recipient=row["recipient"],
                total=int(row["total"]),
                cap_per_period=int(row["cap_per_period"]),
                opens_at=int(row["opens_at"]),
                deadline=int(row["deadline"]),
                sequence_number=int(row["sequence_number"]),
            )
            if terms.grant_id != row["grant_id"]:
                raise ValueError("grant row id does not recompute")
            state = book.create(terms)
            state.remaining = int(row["remaining"])
            state.period_index = int(row["period_index"])
            state.drawn_in_period = int(row["drawn_in_period"])
            state.last_draw_ts = int(row["last_draw_ts"])
            state.refunded = bool(row["refunded"])
        book._root_cache = None
        return book


def parse_grant_create(data: dict) -> GrantTerms:
    return GrantTerms(
        sender=str(data.get("sender_pubkey", "")),
        recipient=str(data.get("recipient_pubkey", "")),
        total=int(data.get("total", 0)),
        cap_per_period=int(data.get("cap_per_period", 0)),
        opens_at=int(data.get("opens_at", 0)),
        deadline=int(data.get("deadline", 0)),
        sequence_number=int(data.get("sequence_number", 0)),
    )


def parse_grant_draw(data: dict) -> Tuple[str, int]:
    return str(data.get("grant_id", "")), int(data.get("amount", 0))
