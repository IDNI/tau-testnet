"""Standing payment authorizations (Bounty 01, issue #34).

A payer signs an authorization once; anyone may later submit an execution
for an occurrence that is currently due, and the node -- not the
submitter -- decides whether it is due. The book in this module is the
state machine for those authorizations. It follows the RetractableBook
pattern (``consensus/retractable.py``): entries are a field of the
consensus lifecycle manager, the open set is bounded by module constants,
resolved authorizations fold into a constant-size commitment, and entry
identity is a pure hash of the signed fields.

Balance, fee and policy (o5) checks live in the engine; this book only
decides *whether an occurrence is due and unsettled* and records that it
settled. An execution that fails in the engine (insufficient funds,
current policy refusal) simply never calls :meth:`StandingBook.settle`,
so the occurrence marker does not advance and the occurrence stays due
until its window closes -- after which it lapses, unsettled. Lapsed
occurrences are skipped by default, exactly the safe default issue #34
recommends. The one extension the issue allows is opt-in and signed:
``catch_up_limit`` in the terms lets a single execution also settle up
to that many lapsed occurrences (oldest first, never past the end
condition); at the default 0 nothing changes.

Design rules that are consensus-visible and therefore live here:

- An end condition is **required**: exactly one of ``final_period``,
  ``max_occurrences`` or ``max_total`` must be set. There is no
  open-ended authorization by default.
- Update is a new version that supersedes; signed terms are never
  mutated in place. Superseding or cancelling closes the old version.
- Every settled occurrence is a fact other rules can read:
  :meth:`StandingBook.paid_for_period`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, Optional, Set, Tuple

from consensus.periods import (
    PERIOD_MONTH,
    is_within_window,
    period_index_at,
    period_start,
    validate_schedule,
    window_bounds,
)
from consensus.serialization import (
    compute_standing_book_root,
    compute_standing_id,
    compute_standing_resolved_acc,
)

TX_TYPE_STANDING_CREATE = "standing_payment_create"
TX_TYPE_STANDING_EXECUTE = "standing_payment_execute"
TX_TYPE_STANDING_CANCEL = "standing_payment_cancel"

STANDING_TX_TYPES = frozenset(
    {TX_TYPE_STANDING_CREATE, TX_TYPE_STANDING_EXECUTE, TX_TYPE_STANDING_CANCEL}
)

# An authorization may not reach further than this into the future.
MAX_HORIZON_SECONDS = 31_536_000  # 365 days

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class StandingShapeError(ValueError):
    """A standing-payment transaction does not have a recordable shape."""

MAX_OPEN_STANDING_PER_PAYER = 16
MAX_OPEN_STANDING_TOTAL = 4096

# Protocol cap on the signed catch-up allowance: one execution may
# collect at most this many lapsed occurrences on top of the due one
# (a year of monthly periods). The signed value may be lower, never
# higher; 0 keeps the issue's recommended default (skip lapsed).
MAX_CATCH_UP_LIMIT = 12

OUTCOME_CANCELLED = 1
OUTCOME_SUPERSEDED = 2
OUTCOME_COMPLETED = 3

STATUS_ACTIVE = "active"


# Identity is consensus.serialization.compute_standing_id (BLAKE3 over the
# canonical encoders, domain tau.standing.authorization.v1) -- imported
# above so this module and the wire format can never drift apart.

# End-condition kinds (exactly one per authorization).
END_FINAL_PERIOD = 0
END_MAX_OCCURRENCES = 1
END_MAX_TOTAL = 2


@dataclass(frozen=True)
class StandingTerms:
    """The signed terms of one authorization version. Never mutated.

    Pubkeys are the canonical 96-char lowercase hex strings the
    transaction layer carries (the RetractableEntry convention).
    """

    payer: str
    recipient: str
    amount: int
    kind: int  # consensus.periods period kind
    anchor_ts: int  # start of the first due period
    window_start_offset: int
    window_end_offset: int
    end_kind: int
    end_value: int  # final period index | occurrence cap | total cap
    sequence_number: int = 0
    supersedes: Optional[bytes] = None
    # Signed opt-in: how many lapsed occurrences one execution may
    # additionally settle. Part of the identity preimage -- an executor
    # can never claim a catch-up the payer did not sign for.
    catch_up_limit: int = 0

    @property
    def standing_id(self) -> bytes:
        return compute_standing_id(
            self.payer,
            self.recipient,
            self.amount,
            self.kind,
            self.anchor_ts,
            self.window_start_offset,
            self.window_end_offset,
            self.end_kind,
            self.end_value,
            self.sequence_number,
            self.supersedes,
            self.catch_up_limit,
        )


def validate_terms(terms: StandingTerms, max_transfer_value: int) -> None:
    """Stateless shape check shared by admission and apply.

    Both must reject the same inputs or the chain splits (the
    ``validate_park_shape`` rule from the retractable book).
    """
    validate_schedule(terms.anchor_ts, terms.kind)
    if terms.recipient == terms.payer:
        raise ValueError("recipient must differ from payer")
    if not (1 <= terms.amount <= max_transfer_value):
        raise ValueError("amount out of range")
    if terms.end_kind not in (END_FINAL_PERIOD, END_MAX_OCCURRENCES, END_MAX_TOTAL):
        raise ValueError("exactly one end condition is required")
    if terms.end_kind == END_FINAL_PERIOD:
        if terms.end_value < 0:
            raise ValueError("final period index must be non-negative")
    elif terms.end_value <= 0:
        raise ValueError("end condition value must be positive")
    if terms.end_kind == END_MAX_TOTAL and terms.end_value < terms.amount:
        raise ValueError("max_total below one occurrence amount")
    if not (0 <= terms.catch_up_limit <= MAX_CATCH_UP_LIMIT):
        raise ValueError("catch_up_limit out of range")
    # The window must fit inside the first and the last possible period.
    window_bounds(terms.anchor_ts, terms.kind, 0, terms.window_start_offset, terms.window_end_offset)
    if terms.end_kind == END_FINAL_PERIOD:
        window_bounds(
            terms.anchor_ts,
            terms.kind,
            terms.end_value,
            terms.window_start_offset,
            terms.window_end_offset,
        )


@dataclass
class StandingRecord:
    """An open authorization: signed terms plus settlement progress."""

    terms: StandingTerms
    executed_count: int = 0
    total_executed: int = 0
    settled_periods: Set[int] = field(default_factory=set)
    last_executed_period: int = -1

    @property
    def standing_id(self) -> bytes:
        return self.terms.standing_id

    def end_reached(self) -> bool:
        t = self.terms
        if t.end_kind == END_FINAL_PERIOD:
            return self.last_executed_period >= t.end_value
        if t.end_kind == END_MAX_OCCURRENCES:
            return self.executed_count >= t.end_value
        return self.total_executed >= t.end_value


class StandingBook:
    """Open standing authorizations plus a resolved commitment."""

    def __init__(self) -> None:
        self.open: Dict[bytes, StandingRecord] = {}
        self._per_payer: Dict[str, int] = {}
        self.resolved_count: int = 0
        self.resolved_acc: bytes = bytes(32)

    def __deepcopy__(self, memo):
        # The lifecycle manager is deep-copied per candidate block; frozen
        # terms are shared, mutable progress is copied (the RetractableBook
        # deepcopy contract).
        new = StandingBook.__new__(StandingBook)
        new.open = {
            sid: StandingRecord(
                terms=rec.terms,
                executed_count=rec.executed_count,
                total_executed=rec.total_executed,
                settled_periods=set(rec.settled_periods),
                last_executed_period=rec.last_executed_period,
            )
            for sid, rec in self.open.items()
        }
        new._per_payer = dict(self._per_payer)
        new.resolved_count = self.resolved_count
        new.resolved_acc = self.resolved_acc
        return new

    def is_empty(self) -> bool:
        """True while the feature has never been touched on this chain.

        Gates the meta-hash binding: a chain with no standing payments
        hashes exactly as it did before the feature existed.
        """
        return not self.open and self.resolved_count == 0

    def snapshot_rows(self) -> list:
        return [_standing_row(self.open[sid]) for sid in sorted(self.open)]

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    @classmethod
    def restore(cls, rows, resolved_count: int, resolved_acc: bytes) -> "StandingBook":
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not isinstance(resolved_count, int) or isinstance(resolved_count, bool) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for row in rows:
            terms = StandingTerms(
                payer=row["payer_pubkey"],
                recipient=row["recipient_pubkey"],
                amount=row["amount"],
                kind=row["period_kind"],
                anchor_ts=row["anchor_timestamp"],
                window_start_offset=row["window_start_offset"],
                window_end_offset=row["window_end_offset"],
                end_kind=row["end_kind"],
                end_value=row["end_value"],
                sequence_number=row["sequence_number"],
                supersedes=(
                    bytes.fromhex(row["supersedes_id"]) if row.get("supersedes_id") else None
                ),
                # Rows written before the field existed mean the default.
                catch_up_limit=row.get("catch_up_limit", 0),
            )
            sid = terms.standing_id
            if sid.hex() != row["standing_id"]:
                raise ValueError(f"stored standing id does not match its fields: {sid.hex()}")
            if sid in book.open:
                raise ValueError(f"duplicate stored standing authorization: {sid.hex()}")
            rec = StandingRecord(
                terms=terms,
                executed_count=row["executed_count"],
                total_executed=row["total_executed"],
                settled_periods=set(row["settled_periods"]),
                last_executed_period=row["last_executed_period"],
            )
            book.open[sid] = rec
            book._per_payer[terms.payer] = book.open_count_for_payer(terms.payer) + 1
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- commitment ----------------------------------------------------
    def _fold_resolved(self, standing_id: bytes, outcome: int) -> None:
        self.resolved_acc = compute_standing_resolved_acc(
            self.resolved_acc, standing_id, outcome
        )
        self.resolved_count += 1

    def root(self) -> bytes:
        entries = []
        for sid, rec in self.open.items():
            t = rec.terms
            entries.append(
                (
                    sid,
                    t.payer,
                    t.recipient,
                    t.amount,
                    t.kind,
                    t.anchor_ts,
                    t.window_start_offset,
                    t.window_end_offset,
                    t.end_kind,
                    t.end_value,
                    t.sequence_number,
                    t.supersedes,
                    t.catch_up_limit,
                    rec.executed_count,
                    rec.total_executed,
                    tuple(sorted(rec.settled_periods)),
                )
            )
        return compute_standing_book_root(entries, self.resolved_count, self.resolved_acc)

    # -- queries ---------------------------------------------------------
    def get(self, standing_id: bytes) -> Optional[StandingRecord]:
        return self.open.get(standing_id)

    def open_count_for_payer(self, payer: str) -> int:
        return self._per_payer.get(payer, 0)

    def next_due(self, standing_id: bytes, ts: int):
        """(period, window_start_ts) of the next executable occurrence.

        The occurrence `due_period` would accept at `ts` if its window is
        open, else the first later period whose window has not closed and
        that has not settled -- what a wallet shows as "next due". None
        when the authorization is finished or unknown.
        """
        from consensus.periods import period_start as _ps

        rec = self.open.get(standing_id)
        if rec is None or rec.end_reached():
            return None
        t = rec.terms
        index = period_index_at(t.anchor_ts, t.kind, ts)
        if index < 0:
            index = 0
        while True:
            if t.end_kind == END_FINAL_PERIOD and index > t.end_value:
                return None
            if index not in rec.settled_periods:
                start, _end = window_bounds(
                    t.anchor_ts, t.kind, index,
                    t.window_start_offset, t.window_end_offset,
                )
                if ts < _end:
                    return (index, start)
            index += 1

    def paid_for_period(self, standing_id: bytes, period: int) -> bool:
        """The membership/keep-alive fact: did this period settle?"""
        rec = self.open.get(standing_id)
        return rec is not None and period in rec.settled_periods

    def due_period(self, standing_id: bytes, ts: int) -> Optional[int]:
        """The period index currently due for execution, or None.

        Due means: ``ts`` is inside that period's signed execution
        window, the period has not settled, and no end condition has
        been reached. A period whose window has passed is lapsed and
        never becomes due again on its own; it can only be collected
        as catch-up riding on a later due execution (see
        :meth:`due_periods`), and only when the signed terms allow it.
        """
        rec = self.open.get(standing_id)
        if rec is None or rec.end_reached():
            return None
        t = rec.terms
        index = period_index_at(t.anchor_ts, t.kind, ts)
        if index < 0 or index in rec.settled_periods:
            return None
        if t.end_kind == END_FINAL_PERIOD and index > t.end_value:
            return None
        if not is_within_window(
            t.anchor_ts, t.kind, index, t.window_start_offset, t.window_end_offset, ts
        ):
            return None
        return index

    def due_periods(self, standing_id: bytes, ts: int) -> list:
        """Every period one execution at ``ts`` settles, oldest first.

        Empty when nothing is due. Otherwise the candidates are the
        lapsed (window closed, unsettled) periods -- at most the
        signed ``catch_up_limit`` oldest of them -- followed by the
        currently due period (:meth:`due_period`). Each candidate is
        admitted under the same rule a single execution has always
        used: it settles only while the end condition is still
        unreached, so the occurrence cap is a hard bound and the
        total cap stops at the same place it does today. When
        catch-up alone exhausts the end condition, the authorization
        completes on the lapsed periods and the due period is left
        out. Pure function of the record and ``ts``, so admission,
        apply and wallets all compute the same list.
        """
        current = self.due_period(standing_id, ts)
        if current is None:
            return []
        rec = self.open[standing_id]
        t = rec.terms
        lapsed = [
            index
            for index in range(current)
            if index not in rec.settled_periods
        ][: t.catch_up_limit]
        chosen: list = []
        count = rec.executed_count
        total = rec.total_executed
        for index in lapsed + [current]:
            if t.end_kind == END_MAX_OCCURRENCES and count >= t.end_value:
                break
            if t.end_kind == END_MAX_TOTAL and total >= t.end_value:
                break
            chosen.append(index)
            count += 1
            total += t.amount
        return chosen

    # -- admission -------------------------------------------------------
    def can_admit_create(self, terms: StandingTerms, max_transfer_value: int) -> bool:
        try:
            validate_terms(terms, max_transfer_value)
        except ValueError:
            return False
        if terms.standing_id in self.open:
            return False
        if self.open_count_for_payer(terms.payer) >= MAX_OPEN_STANDING_PER_PAYER:
            return False
        if len(self.open) >= MAX_OPEN_STANDING_TOTAL:
            return False
        if terms.supersedes is not None:
            prev = self.open.get(terms.supersedes)
            if prev is None or prev.terms.payer != terms.payer:
                return False
        return True

    # -- mutation --------------------------------------------------------
    def create(self, terms: StandingTerms, max_transfer_value: int) -> StandingRecord:
        if not self.can_admit_create(terms, max_transfer_value):
            raise ValueError("standing authorization not admissible")
        if terms.supersedes is not None:
            self._close(terms.supersedes, OUTCOME_SUPERSEDED)
        rec = StandingRecord(terms=terms)
        self.open[rec.standing_id] = rec
        self._per_payer[terms.payer] = self.open_count_for_payer(terms.payer) + 1
        return rec

    def _close(self, standing_id: bytes, outcome: int) -> None:
        rec = self.open.pop(standing_id)
        payer = rec.terms.payer
        remaining = self.open_count_for_payer(payer) - 1
        if remaining > 0:
            self._per_payer[payer] = remaining
        else:
            self._per_payer.pop(payer, None)
        self._fold_resolved(standing_id, outcome)

    def cancel(self, standing_id: bytes, payer: str) -> None:
        rec = self.open.get(standing_id)
        if rec is None:
            raise ValueError("no such standing authorization")
        if rec.terms.payer != payer:
            raise ValueError("only the payer can cancel")
        self._close(standing_id, OUTCOME_CANCELLED)

    def settle(self, standing_id: bytes, ts: int) -> Tuple[Tuple[int, ...], int]:
        """Record one execution as settled. Returns (periods, total).

        ``periods`` is :meth:`due_periods` at ``ts``: the due period
        plus any signed catch-up periods it collected. Call only after
        the engine has moved ``total``; the book is the record, not
        the mover. Raises when nothing is due, which is what makes a
        second execution in the same period impossible.
        """
        periods = self.due_periods(standing_id, ts)
        if not periods:
            raise ValueError("no occurrence is due")
        rec = self.open[standing_id]
        for period in periods:
            rec.settled_periods.add(period)
            rec.executed_count += 1
            rec.total_executed += rec.terms.amount
        rec.last_executed_period = periods[-1]
        total = rec.terms.amount * len(periods)
        if rec.end_reached():
            self._close(standing_id, OUTCOME_COMPLETED)
        return (tuple(periods), total)


# --- Parsing -----------------------------------------------------------------
# Root fields only; a nested `payload` is unsigned data (the retractable
# convention). The payer is the transaction's sender_pubkey.


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise StandingShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str) -> int:
    value = tx.get(name)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise StandingShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _id_field(tx: Dict[str, Any], name: str) -> bytes:
    value = tx.get(name)
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise StandingShapeError(f"{name} must be 64 lowercase hex characters")
    return bytes.fromhex(value)


@dataclass(frozen=True)
class StandingExecution:
    """A standing_payment_execute request: anyone may submit it."""

    executor_pubkey: str
    standing_id: bytes


@dataclass(frozen=True)
class StandingCancellation:
    payer_pubkey: str
    standing_id: bytes


def parse_standing_create(tx: Dict[str, Any]) -> StandingTerms:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    payer = _pubkey_field(tx, "sender_pubkey")
    recipient = _pubkey_field(tx, "recipient_pubkey")
    amount = _u64_field(tx, "amount")
    sequence = _u64_field(tx, "sequence_number")
    kind = _u64_field(tx, "period_kind")
    anchor_ts = _u64_field(tx, "anchor_timestamp")
    window_start = _u64_field(tx, "window_start_offset")
    window_end = _u64_field(tx, "window_end_offset")
    ends = [
        (END_FINAL_PERIOD, tx.get("final_period")),
        (END_MAX_OCCURRENCES, tx.get("max_occurrences")),
        (END_MAX_TOTAL, tx.get("max_total")),
    ]
    present = [(k, v) for k, v in ends if v is not None]
    if len(present) != 1:
        raise StandingShapeError(
            "exactly one end condition is required: final_period, "
            "max_occurrences or max_total"
        )
    end_kind, end_raw = present[0]
    if not _is_int(end_raw) or end_raw < 0 or end_raw > _U64_MAX:
        raise StandingShapeError("end condition must be an unsigned 64-bit integer")
    supersedes = None
    if tx.get("supersedes_id") is not None:
        supersedes = _id_field(tx, "supersedes_id")
    catch_up_limit = 0
    if tx.get("catch_up_limit") is not None:
        catch_up_limit = _u64_field(tx, "catch_up_limit")
    return StandingTerms(
        payer=payer,
        recipient=recipient,
        amount=amount,
        kind=kind,
        anchor_ts=anchor_ts,
        window_start_offset=window_start,
        window_end_offset=window_end,
        end_kind=end_kind,
        end_value=int(end_raw),
        sequence_number=sequence,
        supersedes=supersedes,
        catch_up_limit=catch_up_limit,
    )


def parse_standing_execute(tx: Dict[str, Any]) -> StandingExecution:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return StandingExecution(
        executor_pubkey=_pubkey_field(tx, "sender_pubkey"),
        standing_id=_id_field(tx, "standing_id"),
    )


def parse_standing_cancel(tx: Dict[str, Any]) -> StandingCancellation:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return StandingCancellation(
        payer_pubkey=_pubkey_field(tx, "sender_pubkey"),
        standing_id=_id_field(tx, "standing_id"),
    )


def validate_standing_shape(terms: StandingTerms, ts: int) -> Optional[str]:
    """Stateless admissibility of a create against the target block.

    Shared by admission and apply: they must reject the same inputs or
    the chain splits. Anything needing the book lives in
    `StandingBook.can_admit_create`. Returns None when fine.
    """
    import tau_defs

    try:
        validate_terms(terms, tau_defs.MAX_TRANSFER_VALUE)
    except ValueError as exc:
        return str(exc)
    if terms.anchor_ts > ts + MAX_HORIZON_SECONDS:
        return "anchor_timestamp is more than the horizon in the future"
    if terms.end_kind == END_FINAL_PERIOD:
        last_start = period_start(terms.anchor_ts, terms.kind, terms.end_value)
        if last_start > ts + MAX_HORIZON_SECONDS:
            return "final period starts beyond the horizon"
    return None


# --- Persistence ---------------------------------------------------------------
# Rows are plain dicts (the db.py convention). Restore recomputes every
# authorization id from its stored fields and refuses a mismatch, like
# RetractableBook.restore: a corrupted row must fail loudly at load,
# never silently change consensus state.


def _standing_row(rec: "StandingRecord") -> Dict[str, Any]:
    t = rec.terms
    return {
        "standing_id": rec.standing_id.hex(),
        "payer_pubkey": t.payer,
        "recipient_pubkey": t.recipient,
        "amount": t.amount,
        "period_kind": t.kind,
        "anchor_timestamp": t.anchor_ts,
        "window_start_offset": t.window_start_offset,
        "window_end_offset": t.window_end_offset,
        "end_kind": t.end_kind,
        "end_value": t.end_value,
        "sequence_number": t.sequence_number,
        "supersedes_id": t.supersedes.hex() if t.supersedes else None,
        "catch_up_limit": t.catch_up_limit,
        "executed_count": rec.executed_count,
        "total_executed": rec.total_executed,
        "settled_periods": sorted(rec.settled_periods),
        "last_executed_period": rec.last_executed_period,
    }
