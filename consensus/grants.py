"""Conditional grants: a granter funds a grantee under spending rules.

A grant is a funded promise. Alice locks ``amount`` coins for Bob; Bob draws
them down with explicit ``grant_draw`` transactions, but only inside the rules
Alice wrote at creation:

* ``spend_cap`` -- the most Bob may draw in one period (day / ISO week /
  calendar month / fixed window), from ``consensus.periods``;
* ``per_payment_cap`` -- the most Bob may draw in a single transaction;
* ``weekday_mask`` / ``hour_mask`` (UTC) -- the times draws are allowed;
* ``start_at`` -- draws are locked before this timestamp;
* ``expires_at`` -- the grant dies at this timestamp; whatever Bob has not
  drawn is refunded to ``refund_to`` (usually the granter) by the sweep.

Lifecycle: open -> exhausted | expired | cancelled. The grant is exhausted
when Bob has drawn the full amount; it expires when the sweep sees
``expires_at`` pass; the granter may cancel it at any time (a revocable
promise). A cancelled or expired grant refunds the remainder; an exhausted
grant refunds nothing.

The book is a consensus object, like ``RetractableBook``: open grants and
their drawn totals are committed into the consensus meta hash (via
``grants_root``), the draw totals are tracked per period, and the state is
restored from stored rows at startup. The grant's funds are *escrowed in the
book*, exactly like a retractable park: the create transaction debits the
granter and credits nobody (``escrow=True``); a draw credits the grantee
from the book's escrow; a cancel or an expiry refund credits ``refund_to``
from the escrow. The grantee never holds the un-drawn funds, so they cannot
spend them outside the grant's rules. The book's escrow counter is part of
the supply: ``consensus.engine._escrow_total`` sums every book that holds
escrow, so the block's supply-conservation check still holds.

Chain binding: ``grant_create`` / ``grant_draw`` / ``grant_cancel`` are
signed with ``chain_id`` (the genesis hash) so a grant signed on one Tau
network cannot be replayed on another. See ``consensus.chain_binding``.
"""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import tau_defs
from blake3 import blake3
from consensus.credits import CREDIT_GRANT_DRAW, CREDIT_GRANT_REFUND
from consensus.faucet import has_account, spendable
from consensus.periods import (
    ALL_HOURS_MASK,
    ALL_WEEKDAYS_MASK,
    hour_of_day,
    period_index,
    validate_period_spec,
    weekday,
)
from consensus.serialization import (
    encode_hash32,
    encode_pubkey48,
    encode_string,
    encode_uint32,
    encode_uint64,
)
from consensus.sweep import SweepContext, SweepDue, register_handler

TX_TYPE_GRANT_CREATE = "grant_create"
TX_TYPE_GRANT_DRAW = "grant_draw"
TX_TYPE_GRANT_CANCEL = "grant_cancel"

GRANT_TX_TYPES = frozenset(
    {TX_TYPE_GRANT_CREATE, TX_TYPE_GRANT_DRAW, TX_TYPE_GRANT_CANCEL}
)

GRANT_STATUS_OPEN = "open"
GRANT_STATUS_EXHAUSTED = "exhausted"
GRANT_STATUS_EXPIRED = "expired"
GRANT_STATUS_CANCELLED = "cancelled"

OUTCOME_EXHAUSTED = 1
OUTCOME_EXPIRED = 2
OUTCOME_CANCELLED = 3

#: Hard cap on the grants one granter may have open at once. Bounded so a
#: single account cannot flood the book (the same reason the retractable book
#: caps open parks per sender).
MAX_OPEN_GRANTS_PER_GRANTER = 16
#: Hard cap on open grants chain-wide.
MAX_OPEN_GRANTS_TOTAL = 4096
#: A grant may run at most 90 days, the same window as a retractable park.
MAX_GRANT_DURATION_SECONDS = 7_776_000
#: ``start_at`` may be at most 90 days ahead of the creation block.
MAX_GRANT_START_DELAY_SECONDS = 7_776_000

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF
#: Sentinel in encodings for "no period has been drawn yet".
_PERIOD_UNSET = _U64_MAX

DOMAIN_GRANT_V1 = "tau.grant.v1"
DOMAIN_GRANT_RESOLVED_V1 = "tau.grant.resolved.v1"
DOMAIN_GRANT_BOOK_V1 = "tau.grant.book.v1"


class GrantShapeError(ValueError):
    """A grant transaction does not have a shape the node can record."""


def _is_pubkey(value: Any) -> bool:
    return isinstance(value, str) and _PUBKEY_RE.match(value) is not None


def _is_u64(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _U64_MAX


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not _is_pubkey(value):
        raise GrantShapeError(f"{name} must be a 96-hex-char public key")
    return value


def _u64_field(tx: Dict[str, Any], name: str) -> int:
    value = tx.get(name)
    if not _is_u64(value):
        raise GrantShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _int_field(tx: Dict[str, Any], name: str) -> int:
    value = tx.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise GrantShapeError(f"{name} must be an integer")
    return value


@dataclass(frozen=True)
class GrantEntry:
    """The immutable terms of a grant, fixed at creation."""

    granter_pubkey: str
    grantee_pubkey: str
    refund_to: str
    amount: int
    sequence_number: int
    period_kind: int
    period_length: Optional[int]
    period_anchor: int
    spend_cap: int
    per_payment_cap: int
    weekday_mask: int
    hour_mask: int
    start_at: int
    expires_at: int

    @property
    def grant_id(self) -> bytes:
        return compute_grant_id(
            self.granter_pubkey,
            self.grantee_pubkey,
            self.refund_to,
            self.amount,
            self.sequence_number,
            self.period_kind,
            self.period_length,
            self.period_anchor,
            self.spend_cap,
            self.per_payment_cap,
            self.weekday_mask,
            self.hour_mask,
            self.start_at,
            self.expires_at,
        )


@dataclass(frozen=True)
class GrantDrawRequest:
    grant_id: bytes
    amount: int


@dataclass(frozen=True)
class GrantCancelRequest:
    grant_id: bytes


@dataclass
class _GrantRuntime:
    """Mutable draw state, tracked per open grant."""

    drawn_total: int = 0
    period_index: Optional[int] = None
    drawn_in_period: int = 0


def parse_grant_create(tx: Dict[str, Any]) -> GrantEntry:
    """Parse and shape-check a grant_create transaction body.

    Raises GrantShapeError on a malformed body. The semantic checks
    (caps, windows, duplicates) live in ``validate_grant_shape`` /
    ``GrantBook.can_admit_create``; this function only reads the fields.
    """
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    granter = _pubkey_field(tx, "sender_pubkey")
    grantee = _pubkey_field(tx, "grantee_pubkey")
    refund_to = _pubkey_field(tx, "refund_to")
    amount = _u64_field(tx, "amount")
    sequence_number = _u64_field(tx, "sequence_number")
    period_kind = _int_field(tx, "period_kind")
    period_length = tx.get("period_length")
    if period_length is not None and not _is_u64(period_length):
        raise GrantShapeError("period_length must be an unsigned 64-bit integer")
    period_anchor = tx.get("period_anchor", 0)
    if not _is_u64(period_anchor):
        raise GrantShapeError("period_anchor must be an unsigned 64-bit integer")
    spend_cap = _u64_field(tx, "spend_cap")
    per_payment_cap = _u64_field(tx, "per_payment_cap")
    weekday_mask = tx.get("weekday_mask", ALL_WEEKDAYS_MASK)
    if isinstance(weekday_mask, bool) or not isinstance(weekday_mask, int):
        raise GrantShapeError("weekday_mask must be an integer")
    hour_mask = tx.get("hour_mask", ALL_HOURS_MASK)
    if isinstance(hour_mask, bool) or not isinstance(hour_mask, int):
        raise GrantShapeError("hour_mask must be an integer")
    start_at = _u64_field(tx, "start_at")
    expires_at = _u64_field(tx, "expires_at")
    return GrantEntry(
        granter_pubkey=granter,
        grantee_pubkey=grantee,
        refund_to=refund_to,
        amount=amount,
        sequence_number=sequence_number,
        period_kind=period_kind,
        period_length=period_length,
        period_anchor=period_anchor,
        spend_cap=spend_cap,
        per_payment_cap=per_payment_cap,
        weekday_mask=weekday_mask,
        hour_mask=hour_mask,
        start_at=start_at,
        expires_at=expires_at,
    )


def parse_grant_draw(tx: Dict[str, Any]) -> GrantDrawRequest:
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    grant_id = tx.get("grant_id")
    if not isinstance(grant_id, str) or _ID_RE.match(grant_id) is None:
        raise GrantShapeError("grant_id must be a 64-hex-char id")
    amount = _u64_field(tx, "amount")
    return GrantDrawRequest(grant_id=bytes.fromhex(grant_id), amount=amount)


def parse_grant_cancel(tx: Dict[str, Any]) -> GrantCancelRequest:
    if not isinstance(tx, dict):
        raise GrantShapeError("transaction must be an object")
    grant_id = tx.get("grant_id")
    if not isinstance(grant_id, str) or _ID_RE.match(grant_id) is None:
        raise GrantShapeError("grant_id must be a 64-hex-char id")
    return GrantCancelRequest(grant_id=bytes.fromhex(grant_id))


def compute_grant_id(
    granter_pubkey: str,
    grantee_pubkey: str,
    refund_to: str,
    amount: int,
    sequence_number: int,
    period_kind: int,
    period_length: Optional[int],
    period_anchor: int,
    spend_cap: int,
    per_payment_cap: int,
    weekday_mask: int,
    hour_mask: int,
    start_at: int,
    expires_at: int,
) -> bytes:
    """Deterministic grant id: the blake3 of the grant's full terms.

    The sequence number is part of the id, so two grants from the same
    granter with the same terms are distinct transactions, and a replayed
    grant_create is rejected as a duplicate.
    """
    h = blake3()
    h.update(encode_string(DOMAIN_GRANT_V1))
    h.update(encode_pubkey48(granter_pubkey))
    h.update(encode_pubkey48(grantee_pubkey))
    h.update(encode_pubkey48(refund_to))
    h.update(encode_uint64(amount))
    h.update(encode_uint64(sequence_number))
    h.update(encode_uint32(period_kind))
    h.update(encode_uint64(period_length or 0))
    h.update(encode_uint64(period_anchor))
    h.update(encode_uint64(spend_cap))
    h.update(encode_uint64(per_payment_cap))
    h.update(encode_uint32(weekday_mask))
    h.update(encode_uint32(hour_mask))
    h.update(encode_uint64(start_at))
    h.update(encode_uint64(expires_at))
    return h.digest()


def validate_grant_shape(entry: GrantEntry, height: int, ts: int) -> Optional[str]:
    """Stateless shape check for a parsed grant entry.

    Returns an error text, or None when the terms are well formed. This is
    shared by admission and the engine so a node cannot admit a grant it
    would later refuse to apply (and vice versa).
    """
    if not 1 <= entry.amount <= tau_defs.MAX_TRANSFER_VALUE:
        return "amount must be in 1..MAX_TRANSFER_VALUE"
    spec_error = validate_period_spec(
        entry.period_kind, entry.period_length, entry.period_anchor
    )
    if spec_error is not None:
        return spec_error
    if not 1 <= entry.spend_cap <= entry.amount:
        return "spend_cap must be in 1..amount"
    if not 1 <= entry.per_payment_cap <= entry.spend_cap:
        return "per_payment_cap must be in 1..spend_cap"
    if not 1 <= entry.weekday_mask <= ALL_WEEKDAYS_MASK:
        return "weekday_mask must be in 1..127"
    if not 1 <= entry.hour_mask <= ALL_HOURS_MASK:
        return "hour_mask must be in 1..16777215"
    if entry.start_at >= entry.expires_at:
        return "start_at must be before expires_at"
    if entry.expires_at <= ts:
        return "expires_at must be in the future"
    if entry.expires_at - entry.start_at > MAX_GRANT_DURATION_SECONDS:
        return "grant duration exceeds 90 days"
    if entry.start_at > ts + MAX_GRANT_START_DELAY_SECONDS:
        return "start_at is more than 90 days ahead"
    return None


def _encode_grant_entry(entry: GrantEntry, runtime: _GrantRuntime) -> bytes:
    """Canonical encoding of one open grant plus its draw state."""
    parts = [
        encode_hash32(entry.grant_id),
        encode_pubkey48(entry.granter_pubkey),
        encode_pubkey48(entry.grantee_pubkey),
        encode_pubkey48(entry.refund_to),
        encode_uint64(entry.amount),
        encode_uint64(entry.sequence_number),
        encode_uint32(entry.period_kind),
        encode_uint64(entry.period_length or 0),
        encode_uint64(entry.period_anchor),
        encode_uint64(entry.spend_cap),
        encode_uint64(entry.per_payment_cap),
        encode_uint32(entry.weekday_mask),
        encode_uint32(entry.hour_mask),
        encode_uint64(entry.start_at),
        encode_uint64(entry.expires_at),
        encode_uint64(runtime.drawn_total),
        encode_uint64(
            _PERIOD_UNSET if runtime.period_index is None else runtime.period_index
        ),
        encode_uint64(runtime.drawn_in_period),
    ]
    return b"".join(parts)


def compute_grant_resolved_acc(
    previous_acc: bytes, grant_id: bytes, outcome: int
) -> bytes:
    """Fold one resolved grant into the running resolved commitment."""
    h = blake3()
    h.update(encode_string(DOMAIN_GRANT_RESOLVED_V1))
    h.update(encode_hash32(previous_acc))
    h.update(encode_hash32(grant_id))
    h.update(encode_uint32(outcome))
    return h.digest()


def compute_grant_book_root(
    open_entries: Dict[bytes, GrantEntry],
    runtimes: Dict[bytes, _GrantRuntime],
    resolved_count: int,
    resolved_acc: bytes,
) -> bytes:
    """Deterministic root over the open grants plus the resolved commitment.

    Open grants are encoded in grant-id order, so the root does not depend
    on insertion order.
    """
    h = blake3()
    h.update(encode_string(DOMAIN_GRANT_BOOK_V1))
    h.update(encode_uint64(len(open_entries)))
    for grant_id in sorted(open_entries):
        h.update(_encode_grant_entry(open_entries[grant_id], runtimes[grant_id]))
    h.update(encode_uint64(resolved_count))
    h.update(encode_hash32(resolved_acc))
    return h.digest()


class GrantBook:
    """The consensus book of open grants and their draw state.

    Mirrors ``RetractableBook``: an in-memory index (open grants, a due
    index by expiry, per-granter counts) plus an escrow counter and a
    resolved commitment, all folded into ``root()`` and bound into the
    consensus meta hash. Mutations are the engine's only; admission reads
    the same state through the ``can_admit_*`` methods.
    """

    def __init__(self) -> None:
        self.open: Dict[bytes, GrantEntry] = {}
        self._due: List[Tuple[int, bytes]] = []
        self._runtime: Dict[bytes, _GrantRuntime] = {}
        self._per_granter: Dict[str, int] = {}
        self._escrow = 0
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "GrantBook":
        clone = GrantBook.__new__(GrantBook)
        clone.open = dict(self.open)
        clone._due = list(self._due)
        clone._runtime = {
            gid: _GrantRuntime(
                drawn_total=rt.drawn_total,
                period_index=rt.period_index,
                drawn_in_period=rt.drawn_in_period,
            )
            for gid, rt in self._runtime.items()
        }
        clone._per_granter = dict(self._per_granter)
        clone._escrow = self._escrow
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        return clone

    # -- queries ---------------------------------------------------------
    def is_empty(self) -> bool:
        return not self.open and self.resolved_count == 0

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_grant_book_root(
                self.open, self._runtime, self.resolved_count, self.resolved_acc
            )
        return self._root

    def escrowed_total(self) -> int:
        """Coins still committed to open grants (funds + not-yet-refunded)."""
        return self._escrow

    def resolved_state(self) -> Tuple[int, bytes]:
        """(resolved_count, resolved_acc) for persistence."""
        return self.resolved_count, self.resolved_acc

    def open_count(self) -> int:
        return len(self.open)

    def open_count_for_granter(self, granter_pubkey: str) -> int:
        return self._per_granter.get(granter_pubkey, 0)

    def get(self, grant_id: bytes) -> Optional[GrantEntry]:
        return self.open.get(grant_id)

    def drawn_total(self, grant_id: bytes) -> int:
        rt = self._runtime.get(grant_id)
        return 0 if rt is None else rt.drawn_total

    def remaining_for(self, grant_id: bytes) -> int:
        entry = self.open.get(grant_id)
        if entry is None:
            return 0
        return entry.amount - self.drawn_total(grant_id)

    def drawn_in_period(self, grant_id: bytes, ts: int) -> int:
        """What the grantee has drawn in the period containing ``ts``."""
        entry = self.open.get(grant_id)
        if entry is None:
            return 0
        rt = self._runtime[grant_id]
        idx = period_index(
            entry.period_kind, ts, anchor=entry.period_anchor, length=entry.period_length
        )
        if rt.period_index is None or rt.period_index != idx:
            return 0
        return rt.drawn_in_period

    # -- admission -------------------------------------------------------
    def can_admit_create(
        self, entry: GrantEntry, height: int, ts: int
    ) -> Tuple[bool, str]:
        reason = validate_grant_shape(entry, height, ts)
        if reason is not None:
            return False, reason
        if entry.grant_id in self.open:
            return False, "grant already exists"
        if self.open_count_for_granter(entry.granter_pubkey) >= MAX_OPEN_GRANTS_PER_GRANTER:
            return False, "too many open grants for this granter"
        if len(self.open) >= MAX_OPEN_GRANTS_TOTAL:
            return False, "grant book is full"
        return True, ""

    def can_admit_draw(
        self,
        grant_id: bytes,
        drawer: str,
        amount: int,
        height: int,
        ts: int,
        pending_drawn: int = 0,
    ) -> Tuple[bool, str]:
        """``pending_drawn`` counts draws from the same grant already staged
        in this block, so two draws in one block cannot together exceed the
        caps (the book is only updated at the commit step)."""
        entry = self.open.get(grant_id)
        if entry is None:
            return False, "unknown or already resolved grant"
        if drawer != entry.grantee_pubkey:
            return False, "only the grantee may draw"
        if not _is_u64(amount) or amount == 0:
            return False, "draw amount must be a positive integer"
        if amount > entry.per_payment_cap:
            return False, "draw exceeds the per-payment cap"
        remaining = entry.amount - self._runtime[grant_id].drawn_total
        if amount + pending_drawn > remaining:
            return False, "draw exceeds the grant's remaining amount"
        drawn_this_period = self.drawn_in_period(grant_id, ts)
        if amount + drawn_this_period + pending_drawn > entry.spend_cap:
            return False, "draw exceeds the period spend cap"
        if ts < entry.start_at:
            return False, "grant has not started yet"
        if ts >= entry.expires_at:
            return False, "grant has expired"
        if not entry.weekday_mask & (1 << weekday(ts)):
            return False, "draws are not allowed on this weekday"
        if not entry.hour_mask & (1 << hour_of_day(ts)):
            return False, "draws are not allowed at this hour"
        return True, ""

    def can_admit_cancel(
        self, grant_id: bytes, signer: str, height: int, ts: int
    ) -> Tuple[bool, str]:
        entry = self.open.get(grant_id)
        if entry is None:
            return False, "unknown or already resolved grant"
        if signer != entry.granter_pubkey:
            return False, "only the granter may cancel"
        return True, ""

    # -- mutations -------------------------------------------------------
    def submit(self, entry: GrantEntry) -> None:
        grant_id = entry.grant_id
        if grant_id in self.open:
            raise ValueError("grant already exists")
        self.open[grant_id] = entry
        bisect.insort(self._due, (entry.expires_at, grant_id))
        self._runtime[grant_id] = _GrantRuntime()
        self._per_granter[entry.granter_pubkey] = (
            self._per_granter.get(entry.granter_pubkey, 0) + 1
        )
        self._escrow += entry.amount
        self._root = None

    def draw(self, grant_id: bytes, amount: int, ts: int) -> bool:
        """Apply a draw that admission already approved.

        Returns True when the draw exhausts the grant (it resolves as
        exhausted). Raises ValueError if the draw would violate a cap --
        that is a consensus bug, since admission plus the pending-draw
        overlay guarantee validity.
        """
        entry = self.open[grant_id]
        rt = self._runtime[grant_id]
        if amount <= 0 or amount > entry.per_payment_cap:
            raise ValueError("draw violates the per-payment cap")
        if amount > entry.amount - rt.drawn_total:
            raise ValueError("draw exceeds the grant's remaining amount")
        idx = period_index(
            entry.period_kind, ts, anchor=entry.period_anchor, length=entry.period_length
        )
        if rt.period_index is None or rt.period_index != idx:
            rt.period_index = idx
            rt.drawn_in_period = 0
        if amount + rt.drawn_in_period > entry.spend_cap:
            raise ValueError("draw exceeds the period spend cap")
        rt.drawn_total += amount
        rt.drawn_in_period += amount
        self._escrow -= amount
        self._root = None
        if rt.drawn_total >= entry.amount:
            self._resolve(grant_id, OUTCOME_EXHAUSTED)
            return True
        return False

    def cancel(self, grant_id: bytes) -> Tuple[GrantEntry, int]:
        """Cancel an open grant; returns (entry, refunded remainder)."""
        entry = self.open[grant_id]
        remaining = entry.amount - self._runtime[grant_id].drawn_total
        self._escrow -= remaining
        self._resolve(grant_id, OUTCOME_CANCELLED)
        return entry, remaining

    def expire(self, grant_id: bytes) -> Tuple[GrantEntry, int]:
        """Resolve an expired grant; returns (entry, refunded remainder)."""
        entry = self.open[grant_id]
        remaining = entry.amount - self._runtime[grant_id].drawn_total
        self._escrow -= remaining
        self._resolve(grant_id, OUTCOME_EXPIRED)
        return entry, remaining

    def refund_due(self, height: int, ts: int) -> List[Tuple[GrantEntry, int]]:
        """Resolve every grant whose expiry has passed; returns
        (entry, remainder) pairs for the sweep to refund."""
        due: List[Tuple[GrantEntry, int]] = []
        while self._due and self._due[0][0] <= ts:
            _, grant_id = self._due[0]
            if grant_id not in self.open:
                self._due.pop(0)
                continue
            due.append(self.expire(grant_id))
        return due

    def _resolve(self, grant_id: bytes, outcome: int) -> GrantEntry:
        entry = self.open.pop(grant_id)
        del self._runtime[grant_id]
        idx = bisect.bisect_left(self._due, (entry.expires_at, grant_id))
        if idx < len(self._due) and self._due[idx] == (entry.expires_at, grant_id):
            self._due.pop(idx)
        remaining = self._per_granter.get(entry.granter_pubkey, 0)
        if remaining <= 1:
            self._per_granter.pop(entry.granter_pubkey, None)
        else:
            self._per_granter[entry.granter_pubkey] = remaining - 1
        self.resolved_acc = compute_grant_resolved_acc(
            self.resolved_acc, grant_id, outcome
        )
        self.resolved_count += 1
        self._root = None
        return entry

    # -- persistence -----------------------------------------------------
    def snapshot_rows(self) -> List[Dict[str, Any]]:
        """Rows for the grants table: one per open grant, plus its runtime."""
        rows: List[Dict[str, Any]] = []
        for grant_id in sorted(self.open):
            entry = self.open[grant_id]
            rt = self._runtime[grant_id]
            rows.append(
                {
                    "grant_id": grant_id.hex(),
                    "granter_pubkey": entry.granter_pubkey,
                    "grantee_pubkey": entry.grantee_pubkey,
                    "refund_to": entry.refund_to,
                    "amount": entry.amount,
                    "sequence_number": entry.sequence_number,
                    "period_kind": entry.period_kind,
                    "period_length": entry.period_length,
                    "period_anchor": entry.period_anchor,
                    "spend_cap": entry.spend_cap,
                    "per_payment_cap": entry.per_payment_cap,
                    "weekday_mask": entry.weekday_mask,
                    "hour_mask": entry.hour_mask,
                    "start_at": entry.start_at,
                    "expires_at": entry.expires_at,
                    "drawn_total": rt.drawn_total,
                    "period_index": rt.period_index,
                    "drawn_in_period": rt.drawn_in_period,
                }
            )
        return rows

    @classmethod
    def restore(
        cls,
        rows: Iterable[Dict[str, Any]],
        resolved_count: int,
        resolved_acc: bytes,
    ) -> "GrantBook":
        """Rebuild a book from stored rows.

        A row whose id does not recompute from its fields is refused: the
        stored state is corrupt, and loading it would fork the node.
        """
        book = cls()
        for row in rows:
            entry = GrantEntry(
                granter_pubkey=row["granter_pubkey"],
                grantee_pubkey=row["grantee_pubkey"],
                refund_to=row["refund_to"],
                amount=row["amount"],
                sequence_number=row["sequence_number"],
                period_kind=row["period_kind"],
                period_length=row["period_length"],
                period_anchor=row["period_anchor"],
                spend_cap=row["spend_cap"],
                per_payment_cap=row["per_payment_cap"],
                weekday_mask=row["weekday_mask"],
                hour_mask=row["hour_mask"],
                start_at=row["start_at"],
                expires_at=row["expires_at"],
            )
            grant_id = bytes.fromhex(row["grant_id"])
            if grant_id != entry.grant_id:
                raise ValueError("stored grant id does not match its fields")
            book.open[grant_id] = entry
            bisect.insort(book._due, (entry.expires_at, grant_id))
            book._runtime[grant_id] = _GrantRuntime(
                drawn_total=row["drawn_total"],
                period_index=row["period_index"],
                drawn_in_period=row["drawn_in_period"],
            )
            book._per_granter[entry.granter_pubkey] = (
                book._per_granter.get(entry.granter_pubkey, 0) + 1
            )
            book._escrow += entry.amount - row["drawn_total"]
        book.resolved_count = resolved_count
        book.resolved_acc = resolved_acc
        return book


class _GrantSweepHandler:
    """Sweep handler: refunds the remainder of every expired grant.

    The sweep runs after the transactions of a block, so an expired grant
    is refunded in the first block whose timestamp is at or past
    ``expires_at``. The refund is paid from the book's escrow to
    ``refund_to`` and lands in the block's credit ledger as ``grant_refund``.
    """

    kind = "grant"

    def collect_due(self, lm: Any, height: int, ts: int) -> List[SweepDue]:
        book = getattr(lm, "grants", None)
        if book is None:
            return []
        return [
            SweepDue(due_ts=entry.expires_at, object_id=grant_id, kind="grant")
            for grant_id, entry in book.open.items()
            if entry.expires_at <= ts
        ]

    def execute(self, item: SweepDue, ctx: SweepContext) -> str:
        book = getattr(ctx.lm, "grants", None)
        if book is None:
            return "skipped_no_book"
        entry = book.get(item.object_id)
        if entry is None:
            return "skipped_unknown"
        if entry.expires_at > ctx.timestamp:
            return "skipped_not_due"
        remaining = book.remaining_for(item.object_id)
        if remaining > 0:
            ctx.balances[entry.refund_to] = (
                spendable(
                    ctx.balances,
                    ctx.sequences,
                    entry.refund_to,
                    ctx.faucet_grant,
                )
                + remaining
            )
            if ctx.credit_records is not None:
                ctx.credit_records.record(
                    entry.refund_to,
                    remaining,
                    CREDIT_GRANT_REFUND,
                    item.object_id.hex(),
                )
        book.expire(item.object_id)
        return "refunded" if remaining > 0 else "expired_empty"


register_handler("grant", _GrantSweepHandler())
