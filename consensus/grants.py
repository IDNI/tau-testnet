"""Conditional grants: held money with draw conditions (#63, stages 2-5).

A grant is held money in its own book entry, not a rule on the
recipient's account: creating one debits the sender immediately into
the entry, so the recipient's own balance is never capped and a
refund never has to pull from a balance that may no longer hold it.

Conditions attach to the grant and combine by AND:

- a per-period spending cap on draws (the window is one week of
  604800 seconds from the grant's opening anchor, the same period
  arithmetic as standing payments);
- optionally, a cap shared across grants: grants naming the same
  `cap_group` (scoped to their sender) share one per-period draw
  budget on top of their own caps -- a draw must satisfy both. All
  grants in a group declare the same group cap and the same opening
  anchor, so the group's spent-in-period is exactly the sum of the
  members' own period counters in the current window: the shared
  counter lives in the same rows that feed the book root and
  persistence, never in a side channel;
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
_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


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
    # Shared cap (optional): the group this grant draws against, and
    # the group's per-period cap. Empty group = no shared cap, and the
    # grant behaves exactly as a grant always has.
    cap_group: str = ""
    cap_group_cap: int = 0

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
    if terms.cap_group:
        # Grouped terms hash their group in, so a grouped grant can
        # never collide with its ungrouped twin; ungrouped ids are
        # byte-identical to what they have always been.
        payload["cap_group"] = terms.cap_group
        payload["cap_group_cap"] = terms.cap_group_cap
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
    if not terms.cap_group:
        if terms.cap_group_cap != 0:
            raise GrantShapeError(
                "a shared cap amount without a cap group names no budget")
    else:
        if not _GROUP_RE.match(terms.cap_group):
            raise GrantShapeError("cap group name is not well-formed")
        if terms.cap_group_cap <= 0:
            raise GrantShapeError("the shared draw cap must be positive")


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

    def group_conflict(self, terms: GrantTerms) -> Optional[str]:
        """Why these terms cannot join their cap group, or None.

        A group is one budget: every member must declare the same
        group cap and open at the same anchor, or the shared window
        (and with it the shared counter) would not be well-defined.
        Groups are scoped to the sender, so another sender reusing
        the name starts an independent group.
        """
        if not terms.cap_group:
            return None
        for st in self._grants.values():
            other = st.terms
            if other.sender != terms.sender or other.cap_group != terms.cap_group:
                continue
            if other.cap_group_cap != terms.cap_group_cap:
                return "the grant declares a different cap for its group"
            if other.opens_at != terms.opens_at:
                return "the grant opens at a different anchor than its group"
        return None

    def create(self, terms: GrantTerms) -> GrantState:
        conflict = self.group_conflict(terms)
        if conflict is not None:
            raise GrantShapeError(conflict)
        state = GrantState(terms=terms)
        self._grants[terms.grant_id] = state
        self._root_cache = None
        return state

    def group_drawn_in_period(self, state: GrantState, *, ts: int) -> int:
        """The cap group's total draws in the window containing `ts`.

        Members share the opening anchor, so one period index names
        the same window for all of them; a member whose stored index
        is that index holds exactly its draws in this window, and a
        member last rolled in an older window contributes nothing.
        """
        terms = state.terms
        idx = periods.period_index_at(
            terms.opens_at, periods.PERIOD_WEEK, ts)
        total = 0
        for st in self._grants.values():
            other = st.terms
            if (other.sender == terms.sender
                    and other.cap_group == terms.cap_group
                    and st.period_index == idx):
                total += st.drawn_in_period
        return total

    def check_draw(self, grant_id: str, amount: int, *, ts: int) -> None:
        """The book's draw verdict: the grant's own conditions AND,
        for a grouped grant, the shared cap. Apply re-checks through
        here, so the two cannot disagree."""
        state = self._grants[grant_id]
        state.check_draw(amount, ts=ts)
        if state.terms.cap_group:
            drawn = self.group_drawn_in_period(state, ts=ts)
            if drawn + amount > state.terms.cap_group_cap:
                raise GrantShapeError(
                    "draw exceeds the shared per-period cap")

    def apply_draw(self, grant_id: str, amount: int, *, ts: int) -> None:
        self.check_draw(grant_id, amount, ts=ts)
        self._grants[grant_id].apply_draw(amount, ts=ts)

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
            row = {
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
            }
            if st.terms.cap_group:
                # Only grouped rows carry the group fields, so an
                # ungrouped book snapshots (and hashes) exactly as
                # it always has.
                row["cap_group"] = st.terms.cap_group
                row["cap_group_cap"] = st.terms.cap_group_cap
            rows.append(row)
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
                cap_group=str(row.get("cap_group", "") or ""),
                cap_group_cap=int(row.get("cap_group_cap", 0)),
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
        cap_group=str(data.get("cap_group") or ""),
        cap_group_cap=int(data.get("cap_group_cap") or 0),
    )


def parse_grant_draw(data: dict) -> Tuple[str, int]:
    return str(data.get("grant_id", "")), int(data.get("amount", 0))
