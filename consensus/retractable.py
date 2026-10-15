"""Retractable transfers: a parked transfer that releases at a height or time.

A sender escrows funds with `retractable_transfer`, naming exactly one release
point. Until that point the sender may take the funds back with
`retract_transfer`; from it, the first block's sweep pays the recipient.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would make
two honest nodes disagree about admissibility, which forks.

The book commits to history without storing it: resolved entries leave memory and
only a count plus an order-dependent running hash remain, so the root and the
per-block copy cost depend on the open set alone.
"""
from __future__ import annotations

import bisect
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.serialization import (
    compute_retractable_book_root,
    compute_retractable_id,
    compute_retractable_resolved_acc,
)

TX_TYPE_RETRACTABLE_TRANSFER = "retractable_transfer"
TX_TYPE_RETRACT_TRANSFER = "retract_transfer"

RETRACTABLE_TX_TYPES = frozenset(
    {TX_TYPE_RETRACTABLE_TRANSFER, TX_TYPE_RETRACT_TRANSFER}
)

KIND_HEIGHT = 0
KIND_TIME = 1

RETRACTABLE_STATUS_OPEN = "open"
RETRACTABLE_STATUS_RELEASED = "released"
RETRACTABLE_STATUS_RETRACTED = "retracted"

# Folded into the resolved commitment as one byte per resolution.
OUTCOME_RELEASED = 1
OUTCOME_RETRACTED = 2

MAX_OPEN_RETRACTABLE_PER_SENDER = 16
MAX_OPEN_RETRACTABLE_TOTAL = 4096
MAX_RELEASE_WINDOW_BLOCKS = 100_000
MAX_RELEASE_WINDOW_SECONDS = 7_776_000

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class RetractableShapeError(ValueError):
    """A retractable transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class RetractableEntry:
    sender_pubkey: str
    recipient_pubkey: str
    amount: int
    sequence_number: int
    kind: int
    release_at: int

    @property
    def retractable_id(self) -> bytes:
        return compute_retractable_id(
            self.sender_pubkey,
            self.recipient_pubkey,
            self.amount,
            self.sequence_number,
            self.kind,
            self.release_at,
        )


@dataclass(frozen=True)
class RetractRequest:
    sender_pubkey: str
    retractable_id: bytes


# --- Parsing ------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise RetractableShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str) -> int:
    value = tx.get(name)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise RetractableShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def parse_retractable_transfer(tx: Dict[str, Any]) -> RetractableEntry:
    """Read a park from ROOT fields only; a nested `payload` is unsigned data."""
    if not isinstance(tx, dict):
        raise RetractableShapeError("transaction must be an object")
    sender = _pubkey_field(tx, "sender_pubkey")
    recipient = _pubkey_field(tx, "recipient_pubkey")
    amount = _u64_field(tx, "amount")
    sequence = _u64_field(tx, "sequence_number")

    has_height = tx.get("release_at_height") is not None
    has_time = tx.get("release_at_time") is not None
    if has_height == has_time:
        raise RetractableShapeError(
            "exactly one of release_at_height and release_at_time is required"
        )
    if has_height:
        kind, release_at = KIND_HEIGHT, _u64_field(tx, "release_at_height")
    else:
        kind, release_at = KIND_TIME, _u64_field(tx, "release_at_time")
    return RetractableEntry(sender, recipient, amount, sequence, kind, release_at)


def parse_retract_transfer(tx: Dict[str, Any]) -> RetractRequest:
    if not isinstance(tx, dict):
        raise RetractableShapeError("transaction must be an object")
    sender = _pubkey_field(tx, "sender_pubkey")
    raw_id = tx.get("retractable_id")
    if not isinstance(raw_id, str) or not _ID_RE.match(raw_id):
        raise RetractableShapeError("retractable_id must be 64 lowercase hex characters")
    return RetractRequest(sender, bytes.fromhex(raw_id))


def validate_park_shape(park: RetractableEntry, height: int, ts: int) -> Optional[str]:
    """Stateless admissibility of a park against the target block. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything needing the book lives in `can_admit_park`.
    """
    if not (1 <= park.amount <= tau_defs.MAX_TRANSFER_VALUE):
        return f"amount must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if park.kind == KIND_HEIGHT:
        if park.release_at <= height:
            return "release_at_height must be in the future"
        if park.release_at > height + MAX_RELEASE_WINDOW_BLOCKS:
            return f"release_at_height is more than {MAX_RELEASE_WINDOW_BLOCKS} blocks ahead"
    elif park.kind == KIND_TIME:
        if park.release_at <= ts:
            return "release_at_time must be in the future"
        if park.release_at > ts + MAX_RELEASE_WINDOW_SECONDS:
            return f"release_at_time is more than {MAX_RELEASE_WINDOW_SECONDS} seconds ahead"
    else:
        return "unknown release kind"
    return None


# --- The book -----------------------------------------------------------------

_Row = Tuple[bytes, str, str, int, int, int, int]


class RetractableBook:
    """open -> released | retracted, with a constant-size resolved commitment.

    Entries are frozen, so copies share them and only the containers are
    duplicated. Composed as a FIELD of ConsensusLifecycleManager so the meta hash
    picks it up without a call site to forget.
    """

    def __init__(self) -> None:
        self.open: Dict[bytes, RetractableEntry] = {}
        self._due: Dict[int, List[Tuple[int, bytes]]] = {KIND_HEIGHT: [], KIND_TIME: []}
        self._per_sender: Dict[str, int] = {}
        self._out: Dict[str, int] = {}
        self._in: Dict[str, int] = {}
        self._escrow = 0
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    # -- copying / restoring -------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "RetractableBook":
        clone = RetractableBook.__new__(RetractableBook)
        clone.open = dict(self.open)
        clone._due = {kind: list(rows) for kind, rows in self._due.items()}
        clone._per_sender = dict(self._per_sender)
        clone._out = dict(self._out)
        clone._in = dict(self._in)
        clone._escrow = self._escrow
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls,
        rows: Iterable[_Row],
        resolved_count: int,
        resolved_acc: bytes,
    ) -> "RetractableBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for stored_id, sender, recipient, amount, sequence, kind, release_at in rows:
            if kind not in (KIND_HEIGHT, KIND_TIME):
                raise ValueError("stored retractable has an unknown kind")
            entry = RetractableEntry(sender, recipient, amount, sequence, kind, release_at)
            rid = entry.retractable_id
            if rid != bytes(stored_id):
                raise ValueError(f"stored retractable id does not match its fields: {rid.hex()}")
            if rid in book.open:
                raise ValueError(f"duplicate stored retractable: {rid.hex()}")
            book._insert(rid, entry)
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals -----------------------------------------------------------

    def _insert(self, rid: bytes, entry: RetractableEntry) -> None:
        self.open[rid] = entry
        bisect.insort(self._due[entry.kind], (entry.release_at, rid))
        self._per_sender[entry.sender_pubkey] = self._per_sender.get(entry.sender_pubkey, 0) + 1
        self._out[entry.sender_pubkey] = self._out.get(entry.sender_pubkey, 0) + entry.amount
        self._in[entry.recipient_pubkey] = self._in.get(entry.recipient_pubkey, 0) + entry.amount
        self._escrow += entry.amount
        self._root = None

    @staticmethod
    def _drop(counter: Dict[str, int], key: str, amount: int) -> None:
        left = counter[key] - amount
        if left:
            counter[key] = left
        else:
            del counter[key]

    def _remove(self, rid: bytes) -> RetractableEntry:
        entry = self.open.pop(rid)
        rows = self._due[entry.kind]
        del rows[bisect.bisect_left(rows, (entry.release_at, rid))]
        self._drop(self._per_sender, entry.sender_pubkey, 1)
        self._drop(self._out, entry.sender_pubkey, entry.amount)
        self._drop(self._in, entry.recipient_pubkey, entry.amount)
        self._escrow -= entry.amount
        return entry

    def _resolve(self, rid: bytes, outcome: int) -> RetractableEntry:
        entry = self._remove(rid)
        self.resolved_acc = compute_retractable_resolved_acc(self.resolved_acc, rid, outcome)
        self.resolved_count += 1
        self._root = None
        return entry

    # -- queries -------------------------------------------------------------

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_retractable_book_root(
                [
                    (rid, e.sender_pubkey, e.recipient_pubkey, e.amount,
                     e.sequence_number, e.kind, e.release_at)
                    for rid, e in self.open.items()
                ],
                self.resolved_count,
                self.resolved_acc,
            )
        return self._root

    def get(self, rid: bytes) -> Optional[RetractableEntry]:
        return self.open.get(rid)

    def knows(self, rid: bytes) -> bool:
        return rid in self.open

    def open_count(self) -> int:
        return len(self.open)

    def open_count_for_sender(self, sender_pubkey: str) -> int:
        return self._per_sender.get(sender_pubkey, 0)

    def escrow_total(self) -> int:
        return self._escrow

    def escrow_for(self, pubkey: str) -> int:
        """Escrowed funds this account sent and has not yet resolved."""
        return self._out.get(pubkey, 0)

    def escrow_to(self, pubkey: str) -> int:
        """Escrowed funds addressed to this account."""
        return self._in.get(pubkey, 0)

    def has_due(self, height: int, ts: int) -> bool:
        h_rows, t_rows = self._due[KIND_HEIGHT], self._due[KIND_TIME]
        return bool(
            (h_rows and h_rows[0][0] <= height) or (t_rows and t_rows[0][0] <= ts)
        )

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        return [
            {
                "retractable_id": rid.hex(),
                "sender_pubkey": e.sender_pubkey,
                "recipient_pubkey": e.recipient_pubkey,
                "amount": e.amount,
                "sequence_number": e.sequence_number,
                "release_kind": e.kind,
                "release_at": e.release_at,
            }
            for rid, e in sorted(self.open.items())
        ]

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    # -- admission -----------------------------------------------------------

    def can_admit_park(
        self, entry: RetractableEntry, height: int, ts: int
    ) -> Tuple[bool, str]:
        reason = validate_park_shape(entry, height, ts)
        if reason:
            return False, reason
        if entry.retractable_id in self.open:
            return False, "retractable transfer already exists"
        if self.open_count_for_sender(entry.sender_pubkey) >= MAX_OPEN_RETRACTABLE_PER_SENDER:
            return False, f"sender already has {MAX_OPEN_RETRACTABLE_PER_SENDER} open retractable transfers"
        if len(self.open) >= MAX_OPEN_RETRACTABLE_TOTAL:
            return False, "retractable transfer book is full"
        return True, ""

    def can_admit_retract(
        self, rid: bytes, signer: str, height: int, ts: int
    ) -> Tuple[bool, str]:
        entry = self.open.get(rid)
        if entry is None:
            return False, "unknown or already resolved retractable transfer"
        if signer != entry.sender_pubkey:
            return False, "only the sender may retract"
        if not self._before_release(entry, height, ts):
            return False, "release point reached; too late to retract"
        return True, ""

    @staticmethod
    def _before_release(entry: RetractableEntry, height: int, ts: int) -> bool:
        return (height if entry.kind == KIND_HEIGHT else ts) < entry.release_at

    # -- mutation ------------------------------------------------------------

    def submit(self, entry: RetractableEntry) -> bytes:
        rid = entry.retractable_id
        if rid in self.open:
            raise ValueError("retractable transfer already exists")
        self._insert(rid, entry)
        return rid

    def retract(self, rid: bytes) -> RetractableEntry:
        if rid not in self.open:
            raise KeyError(rid.hex())
        return self._resolve(rid, OUTCOME_RETRACTED)

    def release_due(self, height: int, ts: int) -> List[RetractableEntry]:
        """Resolve every due entry as released, in ascending id order."""
        due_ids: List[bytes] = []
        for kind, cutoff in ((KIND_HEIGHT, height), (KIND_TIME, ts)):
            rows = self._due[kind]
            end = bisect.bisect_right(rows, (cutoff, b"\xff" * 33))
            due_ids.extend(rid for _, rid in rows[:end])
        return [self._resolve(rid, OUTCOME_RELEASED) for rid in sorted(due_ids)]
