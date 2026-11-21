"""Standing payments: a payer pays a payee a fixed amount every period.

A standing payment is a recurring obligation. Alice pays Bob ``amount`` coins
every day / ISO week / calendar month / fixed window, starting at ``start_at``,
until she cancels it. The funds are NOT escrowed: they stay in Alice's
balance until an execution moves them, so an execution can fail for
insufficient funds -- and when it does, that period is simply skipped
(no catch-up, one execution per period).

Lifecycle: one current version, updated in place by version. A
``standing_payment_update`` never mutates the old terms: it resolves the old
version as superseded and submits a new version (same ``standing_id``,
version + 1). ``standing_payment_cancel`` resolves the standing as
cancelled. Both resolutions fold into the resolved commitment, so the book
root commits to the full history.

Execution has two paths through the SAME apply function,
``apply_standing_execution``:

* the sweep is primary: after the transactions of a block, the sweep
  executes every standing payment whose current period has started and has
  not been executed yet. The fee for the execution is measured by the
  engine (one Tau fee-query step, passed in through the sweep context) and
  charged to the payer, capped by ``max_fee_per_execution``; the fee is
  credited to the block's fee beneficiary.
* ``standing_payment_execute`` is the manual fallback: the payer submits it
  to execute the current period when the sweep has not (for example when
  the sweep hit its per-block cap). It is a fee-bearing transaction; the
  standard fee flow charges the payer, and admission enforces
  ``fee_limit <= max_fee_per_execution`` so the payer never pays more per
  execution than they declared.

Chain binding: all four standing tx types are signed with ``chain_id`` (the
genesis hash) so a standing payment signed on one Tau network cannot be
replayed on another. See ``consensus.chain_binding``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

import tau_defs
from blake3 import blake3
from consensus.credits import CREDIT_FEE_REWARD, CREDIT_STANDING_PAYMENT
from consensus.faucet import spendable
from consensus.periods import (
    PeriodError,
    period_index,
    period_start,
    validate_period_spec,
)
from consensus.serialization import (
    encode_hash32,
    encode_pubkey48,
    encode_string,
    encode_uint32,
    encode_uint64,
)
from consensus.sweep import SweepContext, SweepDue, register_handler

TX_TYPE_STANDING_PAYMENT = "standing_payment"
TX_TYPE_STANDING_PAYMENT_EXECUTE = "standing_payment_execute"
TX_TYPE_STANDING_PAYMENT_UPDATE = "standing_payment_update"
TX_TYPE_STANDING_PAYMENT_CANCEL = "standing_payment_cancel"

STANDING_TX_TYPES = frozenset(
    {
        TX_TYPE_STANDING_PAYMENT,
        TX_TYPE_STANDING_PAYMENT_EXECUTE,
        TX_TYPE_STANDING_PAYMENT_UPDATE,
        TX_TYPE_STANDING_PAYMENT_CANCEL,
    }
)

#: Fee-bearing standing tx types. Cancel is a cleanup (like a retract /
#: grant cancel) and pays no fee.
STANDING_FEE_BEARING_TX_TYPES = frozenset(
    {
        TX_TYPE_STANDING_PAYMENT,
        TX_TYPE_STANDING_PAYMENT_EXECUTE,
        TX_TYPE_STANDING_PAYMENT_UPDATE,
    }
)

STANDING_STATUS_OPEN = "open"
STANDING_STATUS_SUPERSEDED = "superseded"
STANDING_STATUS_CANCELLED = "cancelled"

OUTCOME_SUPERSEDED = 1
OUTCOME_CANCELLED = 2

#: Hard cap on the standing payments one payer may have open at once.
#: Bounded so a single account cannot flood the book (the same reason the
#: grant book caps open grants per granter).
MAX_OPEN_STANDING_PER_PAYER = 16
#: Hard cap on open standing payments chain-wide.
MAX_OPEN_STANDING_TOTAL = 4096
#: ``start_at`` may be at most 90 days ahead of the creation block, the same
#: window as a grant's start delay.
MAX_STANDING_START_DELAY_SECONDS = 7_776_000

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF
#: Sentinel in encodings for "no period has been executed yet".
_PERIOD_UNSET = _U64_MAX

DOMAIN_STANDING_V1 = "tau.standing.v1"
DOMAIN_STANDING_VERSION_V1 = "tau.standing.version.v1"
DOMAIN_STANDING_RESOLVED_V1 = "tau.standing.resolved.v1"
DOMAIN_STANDING_BOOK_V1 = "tau.standing.book.v1"

#: Outcomes that advance the schedule: the period is done, whether the money
#: moved or the execution was skipped (no catch-up).
_ADVANCING_OUTCOMES = frozenset(
    {"executed", "skipped_fee_cap", "skipped_insufficient_funds"}
)


class StandingShapeError(ValueError):
    """A standing-payment transaction does not have a shape the node can record."""


def _is_pubkey(value: Any) -> bool:
    return isinstance(value, str) and _PUBKEY_RE.match(value) is not None


def _is_u64(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= _U64_MAX


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not _is_pubkey(value):
        raise StandingShapeError(f"{name} must be a 96-hex-char public key")
    return value


def _u64_field(tx: Dict[str, Any], name: str) -> int:
    value = tx.get(name)
    if not _is_u64(value):
        raise StandingShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _int_field(tx: Dict[str, Any], name: str) -> int:
    value = tx.get(name)
    if isinstance(value, bool) or not isinstance(value, int):
        raise StandingShapeError(f"{name} must be an integer")
    return value


def _id_field(tx: Dict[str, Any], name: str) -> bytes:
    value = tx.get(name)
    if not isinstance(value, str) or _ID_RE.match(value) is None:
        raise StandingShapeError(f"{name} must be a 64-hex-char id")
    return bytes.fromhex(value)


@dataclass(frozen=True)
class StandingEntry:
    """The immutable terms of one version of a standing payment.

    ``standing_id`` is stable across versions (payer + payee + the create
    transaction's sequence number); ``version`` counts the updates. The
    funds are never escrowed: they stay in the payer's balance until an
    execution moves them.
    """

    standing_id: bytes
    version: int
    payer_pubkey: str
    payee_pubkey: str
    amount: int
    period_kind: int
    period_length: Optional[int]
    period_anchor: int
    max_fee_per_execution: int
    start_at: int
    create_sequence_number: int

    @property
    def version_id(self) -> bytes:
        return compute_standing_version_id(self)


@dataclass(frozen=True)
class StandingExecuteRequest:
    standing_id: bytes


@dataclass(frozen=True)
class StandingCancelRequest:
    standing_id: bytes


@dataclass(frozen=True)
class StandingUpdateRequest:
    standing_id: bytes
    amount: int
    period_kind: int
    period_length: Optional[int]
    period_anchor: int
    max_fee_per_execution: int
    start_at: int


@dataclass
class _StandingRuntime:
    """Mutable execution state, tracked per open standing payment."""

    last_executed_period: Optional[int] = None
    executions: int = 0


def compute_standing_id(
    payer_pubkey: str, payee_pubkey: str, create_sequence_number: int
) -> bytes:
    """Stable id of a standing payment: payer + payee + create sequence.

    The sequence number is part of the id, so two standing payments from the
    same payer to the same payee are distinct, and a replayed create is
    rejected as a duplicate.
    """
    h = blake3()
    h.update(encode_string(DOMAIN_STANDING_V1))
    h.update(encode_pubkey48(payer_pubkey))
    h.update(encode_pubkey48(payee_pubkey))
    h.update(encode_uint64(create_sequence_number))
    return h.digest()


def build_update_entry(
    current: StandingEntry, request: StandingUpdateRequest
) -> StandingEntry:
    """The new version of a standing payment under an update request.

    Same standing id, version + 1, the request's new terms. The old entry
    is never mutated; the update resolves it as SUPERSEDED and submits
    this entry as a fresh open version.
    """
    return StandingEntry(
        standing_id=current.standing_id,
        version=current.version + 1,
        payer_pubkey=current.payer_pubkey,
        payee_pubkey=current.payee_pubkey,
        amount=request.amount,
        period_kind=request.period_kind,
        period_length=request.period_length,
        period_anchor=request.period_anchor,
        max_fee_per_execution=request.max_fee_per_execution,
        start_at=request.start_at,
        create_sequence_number=current.create_sequence_number,
    )


def compute_standing_version_id(entry: StandingEntry) -> bytes:
    """Deterministic id of one version: the standing id plus its terms."""
    h = blake3()
    h.update(encode_string(DOMAIN_STANDING_VERSION_V1))
    h.update(encode_hash32(entry.standing_id))
    h.update(encode_uint64(entry.version))
    h.update(encode_pubkey48(entry.payer_pubkey))
    h.update(encode_pubkey48(entry.payee_pubkey))
    h.update(encode_uint64(entry.amount))
    h.update(encode_uint32(entry.period_kind))
    h.update(encode_uint64(entry.period_length or 0))
    h.update(encode_uint64(entry.period_anchor))
    h.update(encode_uint64(entry.max_fee_per_execution))
    h.update(encode_uint64(entry.start_at))
    h.update(encode_uint64(entry.create_sequence_number))
    return h.digest()


def parse_standing_create(tx: Dict[str, Any]) -> StandingEntry:
    """Parse and shape-check a standing_payment transaction body.

    Raises StandingShapeError on a malformed body. The semantic checks
    (caps, windows, duplicates) live in ``validate_standing_shape`` /
    ``StandingPaymentBook.can_admit_create``; this function only reads the
    fields.
    """
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    payer = _pubkey_field(tx, "sender_pubkey")
    payee = _pubkey_field(tx, "payee_pubkey")
    amount = _u64_field(tx, "amount")
    sequence_number = _u64_field(tx, "sequence_number")
    period_kind = _int_field(tx, "period_kind")
    period_length = tx.get("period_length")
    if period_length is not None and not _is_u64(period_length):
        raise StandingShapeError("period_length must be an unsigned 64-bit integer")
    period_anchor = tx.get("period_anchor", 0)
    if not _is_u64(period_anchor):
        raise StandingShapeError("period_anchor must be an unsigned 64-bit integer")
    max_fee_per_execution = _u64_field(tx, "max_fee_per_execution")
    start_at = _u64_field(tx, "start_at")
    return StandingEntry(
        standing_id=compute_standing_id(payer, payee, sequence_number),
        version=1,
        payer_pubkey=payer,
        payee_pubkey=payee,
        amount=amount,
        period_kind=period_kind,
        period_length=period_length,
        period_anchor=period_anchor,
        max_fee_per_execution=max_fee_per_execution,
        start_at=start_at,
        create_sequence_number=sequence_number,
    )


def parse_standing_execute(tx: Dict[str, Any]) -> StandingExecuteRequest:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return StandingExecuteRequest(standing_id=_id_field(tx, "standing_id"))


def parse_standing_update(tx: Dict[str, Any]) -> StandingUpdateRequest:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    standing_id = _id_field(tx, "standing_id")
    amount = _u64_field(tx, "amount")
    period_kind = _int_field(tx, "period_kind")
    period_length = tx.get("period_length")
    if period_length is not None and not _is_u64(period_length):
        raise StandingShapeError("period_length must be an unsigned 64-bit integer")
    period_anchor = tx.get("period_anchor", 0)
    if not _is_u64(period_anchor):
        raise StandingShapeError("period_anchor must be an unsigned 64-bit integer")
    max_fee_per_execution = _u64_field(tx, "max_fee_per_execution")
    start_at = _u64_field(tx, "start_at")
    return StandingUpdateRequest(
        standing_id=standing_id,
        amount=amount,
        period_kind=period_kind,
        period_length=period_length,
        period_anchor=period_anchor,
        max_fee_per_execution=max_fee_per_execution,
        start_at=start_at,
    )


def parse_standing_cancel(tx: Dict[str, Any]) -> StandingCancelRequest:
    if not isinstance(tx, dict):
        raise StandingShapeError("transaction must be an object")
    return StandingCancelRequest(standing_id=_id_field(tx, "standing_id"))


def validate_standing_shape(entry: StandingEntry, height: int, ts: int) -> Optional[str]:
    """Stateless shape check for a parsed standing entry.

    Returns an error text, or None when the terms are well formed. This is
    shared by admission and the engine so a node cannot admit a standing
    payment it would later refuse to apply (and vice versa).
    """
    if not 1 <= entry.amount <= tau_defs.MAX_TRANSFER_VALUE:
        return "amount must be in 1..MAX_TRANSFER_VALUE"
    spec_error = validate_period_spec(
        entry.period_kind, entry.period_length, entry.period_anchor
    )
    if spec_error is not None:
        return spec_error
    if entry.period_kind == 0 and entry.start_at < entry.period_anchor:
        return "start_at must be at or after the fixed period anchor"
    if not 0 <= entry.max_fee_per_execution <= tau_defs.MAX_TRANSFER_VALUE:
        return "max_fee_per_execution must be in 0..MAX_TRANSFER_VALUE"
    if entry.start_at > ts + MAX_STANDING_START_DELAY_SECONDS:
        return "start_at is more than 90 days ahead"
    return None


def first_period(entry: StandingEntry) -> int:
    """Index of the first period the standing payment is due in."""
    return period_index(
        entry.period_kind, entry.start_at,
        anchor=entry.period_anchor, length=entry.period_length,
    )


def current_period(entry: StandingEntry, ts: int) -> int:
    """Index of the period containing ``ts``."""
    return period_index(
        entry.period_kind, ts,
        anchor=entry.period_anchor, length=entry.period_length,
    )


def _encode_standing_entry(entry: StandingEntry, runtime: _StandingRuntime) -> bytes:
    """Canonical encoding of one open standing payment plus its runtime."""
    parts = [
        encode_hash32(entry.standing_id),
        encode_uint64(entry.version),
        encode_pubkey48(entry.payer_pubkey),
        encode_pubkey48(entry.payee_pubkey),
        encode_uint64(entry.amount),
        encode_uint32(entry.period_kind),
        encode_uint64(entry.period_length or 0),
        encode_uint64(entry.period_anchor),
        encode_uint64(entry.max_fee_per_execution),
        encode_uint64(entry.start_at),
        encode_uint64(entry.create_sequence_number),
        encode_uint64(
            _PERIOD_UNSET
            if runtime.last_executed_period is None
            else runtime.last_executed_period
        ),
        encode_uint64(runtime.executions),
    ]
    return b"".join(parts)


def compute_standing_resolved_acc(
    previous_acc: bytes, standing_id: bytes, outcome: int
) -> bytes:
    """Fold one resolved standing payment into the running resolved commitment."""
    h = blake3()
    h.update(encode_string(DOMAIN_STANDING_RESOLVED_V1))
    h.update(encode_hash32(previous_acc))
    h.update(encode_hash32(standing_id))
    h.update(encode_uint32(outcome))
    return h.digest()


def compute_standing_book_root(
    open_entries: Dict[bytes, StandingEntry],
    runtimes: Dict[bytes, _StandingRuntime],
    resolved_count: int,
    resolved_acc: bytes,
) -> bytes:
    """Deterministic root over the open standing payments plus the resolved commitment.

    Open payments are encoded in standing-id order, so the root does not
    depend on insertion order.
    """
    h = blake3()
    h.update(encode_string(DOMAIN_STANDING_BOOK_V1))
    h.update(encode_uint64(len(open_entries)))
    for standing_id in sorted(open_entries):
        h.update(_encode_standing_entry(open_entries[standing_id], runtimes[standing_id]))
    h.update(encode_uint64(resolved_count))
    h.update(encode_hash32(resolved_acc))
    return h.digest()


class StandingPaymentBook:
    """The consensus book of open standing payments and their execution state.

    Mirrors ``GrantBook``: an in-memory index (open payments, per-payer
    counts) plus a resolved commitment, all folded into ``root()`` and bound
    into the consensus meta hash. Mutations are the engine's only; admission
    reads the same state through the ``can_admit_*`` methods.

    Unlike a grant, a standing payment holds NO escrow: the funds stay in
    the payer's balance until an execution moves them. ``escrowed_total``
    therefore always returns 0; the supply-conservation check is unaffected.
    """

    def __init__(self) -> None:
        self.open: Dict[bytes, StandingEntry] = {}
        self._runtime: Dict[bytes, _StandingRuntime] = {}
        self._per_payer: Dict[str, int] = {}
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "StandingPaymentBook":
        clone = StandingPaymentBook.__new__(StandingPaymentBook)
        clone.open = dict(self.open)
        clone._runtime = {
            sid: _StandingRuntime(
                last_executed_period=rt.last_executed_period,
                executions=rt.executions,
            )
            for sid, rt in self._runtime.items()
        }
        clone._per_payer = dict(self._per_payer)
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        return clone

    # -- queries ---------------------------------------------------------
    def is_empty(self) -> bool:
        return not self.open and self.resolved_count == 0

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_standing_book_root(
                self.open, self._runtime, self.resolved_count, self.resolved_acc
            )
        return self._root

    def escrowed_total(self) -> int:
        """Standing payments hold no escrow; the funds stay with the payer."""
        return 0

    def resolved_state(self) -> Tuple[int, bytes]:
        """(resolved_count, resolved_acc) for persistence."""
        return self.resolved_count, self.resolved_acc

    def open_count(self) -> int:
        return len(self.open)

    def open_count_for_payer(self, payer_pubkey: str) -> int:
        return self._per_payer.get(payer_pubkey, 0)

    def get(self, standing_id: bytes) -> Optional[StandingEntry]:
        return self.open.get(standing_id)

    def last_executed_period(self, standing_id: bytes) -> Optional[int]:
        rt = self._runtime.get(standing_id)
        return None if rt is None else rt.last_executed_period

    def executions(self, standing_id: bytes) -> int:
        rt = self._runtime.get(standing_id)
        return 0 if rt is None else rt.executions

    def due_period(self, standing_id: bytes, ts: int) -> Optional[int]:
        """The period due for execution at ``ts``, or None.

        A period is due when it has started (``ts`` is in it or a later one)
        and it has not been executed yet. When several periods have passed
        since the last execution, only the CURRENT one is due: missed periods
        are skipped, never caught up.
        """
        entry = self.open.get(standing_id)
        if entry is None:
            return None
        try:
            current = current_period(entry, ts)
        except PeriodError:
            return None
        if current < first_period(entry):
            return None
        rt = self._runtime[standing_id]
        if rt.last_executed_period is not None and rt.last_executed_period >= current:
            return None
        return current

    # -- admission -------------------------------------------------------
    def can_admit_create(
        self, entry: StandingEntry, height: int, ts: int
    ) -> Tuple[bool, str]:
        reason = validate_standing_shape(entry, height, ts)
        if reason is not None:
            return False, reason
        if entry.standing_id in self.open:
            return False, "standing payment already exists"
        if self.open_count_for_payer(entry.payer_pubkey) >= MAX_OPEN_STANDING_PER_PAYER:
            return False, "too many open standing payments for this payer"
        if len(self.open) >= MAX_OPEN_STANDING_TOTAL:
            return False, "standing payment book is full"
        return True, ""

    def can_admit_execute(
        self, standing_id: bytes, executor: str, height: int, ts: int,
        fee_limit: Optional[int] = None,
    ) -> Tuple[bool, str]:
        entry = self.open.get(standing_id)
        if entry is None:
            return False, "unknown or already resolved standing payment"
        if executor != entry.payer_pubkey:
            return False, "only the payer may execute"
        if self.due_period(standing_id, ts) is None:
            return False, "no period due for execution"
        if fee_limit is not None and fee_limit > entry.max_fee_per_execution:
            return False, "fee_limit exceeds max_fee_per_execution"
        return True, ""

    def can_admit_update(
        self, standing_id: bytes, updater: str, new_entry: StandingEntry,
        height: int, ts: int,
    ) -> Tuple[bool, str]:
        entry = self.open.get(standing_id)
        if entry is None:
            return False, "unknown or already resolved standing payment"
        if updater != entry.payer_pubkey:
            return False, "only the payer may update"
        if new_entry.standing_id != standing_id:
            return False, "update must keep the same standing payment"
        if new_entry.version != entry.version + 1:
            return False, "update must advance the version by one"
        reason = validate_standing_shape(new_entry, height, ts)
        if reason is not None:
            return False, reason
        return True, ""

    def can_admit_cancel(
        self, standing_id: bytes, signer: str, height: int, ts: int
    ) -> Tuple[bool, str]:
        entry = self.open.get(standing_id)
        if entry is None:
            return False, "unknown or already resolved standing payment"
        if signer != entry.payer_pubkey:
            return False, "only the payer may cancel"
        return True, ""

    # -- mutations -------------------------------------------------------
    def submit(self, entry: StandingEntry) -> None:
        if entry.standing_id in self.open:
            raise ValueError("standing payment already exists")
        self.open[entry.standing_id] = entry
        self._runtime[entry.standing_id] = _StandingRuntime()
        self._per_payer[entry.payer_pubkey] = (
            self._per_payer.get(entry.payer_pubkey, 0) + 1
        )
        self._root = None

    def mark_executed(self, standing_id: bytes, period: int) -> None:
        """Advance the schedule past ``period`` (executed or skipped)."""
        rt = self._runtime[standing_id]
        rt.last_executed_period = period
        rt.executions += 1
        self._root = None

    def update(self, standing_id: bytes, new_entry: StandingEntry) -> StandingEntry:
        """Replace the current version with ``new_entry`` (version + 1).

        The old version is resolved as superseded -- its terms are never
        mutated, they are folded into the resolved commitment and the new
        version starts with a fresh execution schedule.
        """
        old = self.open[standing_id]
        if new_entry.standing_id != standing_id:
            raise ValueError("update must keep the same standing payment")
        if new_entry.version != old.version + 1:
            raise ValueError("update must advance the version by one")
        self._resolve(standing_id, OUTCOME_SUPERSEDED)
        self.open[standing_id] = new_entry
        self._runtime[standing_id] = _StandingRuntime()
        self._root = None
        return old

    def cancel(self, standing_id: bytes) -> StandingEntry:
        """Cancel an open standing payment; the payer keeps their funds."""
        entry = self.open[standing_id]
        self._resolve(standing_id, OUTCOME_CANCELLED)
        return entry

    def _resolve(self, standing_id: bytes, outcome: int) -> StandingEntry:
        entry = self.open.pop(standing_id)
        del self._runtime[standing_id]
        remaining = self._per_payer.get(entry.payer_pubkey, 0)
        if remaining <= 1:
            self._per_payer.pop(entry.payer_pubkey, None)
        else:
            self._per_payer[entry.payer_pubkey] = remaining - 1
        self.resolved_acc = compute_standing_resolved_acc(
            self.resolved_acc, standing_id, outcome
        )
        self.resolved_count += 1
        self._root = None
        return entry

    # -- persistence -----------------------------------------------------
    def snapshot_rows(self) -> List[Dict[str, Any]]:
        """Rows for the standing table: one per open payment, plus its runtime."""
        rows: List[Dict[str, Any]] = []
        for standing_id in sorted(self.open):
            entry = self.open[standing_id]
            rt = self._runtime[standing_id]
            rows.append(
                {
                    "standing_id": standing_id.hex(),
                    "version": entry.version,
                    "payer_pubkey": entry.payer_pubkey,
                    "payee_pubkey": entry.payee_pubkey,
                    "amount": entry.amount,
                    "period_kind": entry.period_kind,
                    "period_length": entry.period_length,
                    "period_anchor": entry.period_anchor,
                    "max_fee_per_execution": entry.max_fee_per_execution,
                    "start_at": entry.start_at,
                    "sequence_number": entry.create_sequence_number,
                    "last_executed_period": rt.last_executed_period,
                    "executions": rt.executions,
                }
            )
        return rows

    @classmethod
    def restore(
        cls,
        rows: Iterable[Dict[str, Any]],
        resolved_count: int,
        resolved_acc: bytes,
    ) -> "StandingPaymentBook":
        """Rebuild a book from stored rows.

        A row whose id does not recompute from its fields is refused: the
        stored state is corrupt, and loading it would fork the node.
        """
        book = cls()
        for row in rows:
            standing_id = bytes.fromhex(row["standing_id"])
            if standing_id != compute_standing_id(
                row["payer_pubkey"], row["payee_pubkey"], row["sequence_number"]
            ):
                raise ValueError("stored standing id does not match its fields")
            entry = StandingEntry(
                standing_id=standing_id,
                version=row["version"],
                payer_pubkey=row["payer_pubkey"],
                payee_pubkey=row["payee_pubkey"],
                amount=row["amount"],
                period_kind=row["period_kind"],
                period_length=row["period_length"],
                period_anchor=row["period_anchor"],
                max_fee_per_execution=row["max_fee_per_execution"],
                start_at=row["start_at"],
                create_sequence_number=row["sequence_number"],
            )
            book.open[standing_id] = entry
            book._runtime[standing_id] = _StandingRuntime(
                last_executed_period=row["last_executed_period"],
                executions=row["executions"],
            )
            book._per_payer[entry.payer_pubkey] = (
                book._per_payer.get(entry.payer_pubkey, 0) + 1
            )
        book.resolved_count = resolved_count
        book.resolved_acc = resolved_acc
        return book


def apply_standing_execution(
    book: StandingPaymentBook,
    standing_id: bytes,
    ts: int,
    *,
    read: Callable[[str], int],
    write: Callable[[str, int], None],
    fee: int,
    fee_beneficiary: str,
    credit_records: Optional[Any],
    route_split: Optional[Any] = None,
) -> Tuple[str, Optional[int]]:
    """Execute one due period of a standing payment. Returns (outcome, period).

    The ONE apply function both execution paths use: the sweep (primary) and
    the manual ``standing_payment_execute`` transaction (fallback). The
    caller supplies the balance access (``read`` / ``write``) so the engine
    can stage writes into its per-transaction overlay while the sweep writes
    straight into the block's overlay, and the fee (already measured -- by
    the engine's Tau fee-query step for the sweep, by the transaction's own
    fee flow for a manual execute, where it is 0 here because the fee
    settlement charges it separately).

    ``period`` is the period the outcome concerns, or None when nothing was
    due. The caller advances the schedule (``book.mark_executed``) for the
    advancing outcomes -- executed, skipped_fee_cap,
    skipped_insufficient_funds -- so a period that could not be paid is
    skipped, never caught up.
    """
    entry = book.get(standing_id)
    if entry is None:
        return "skipped_unknown", None
    try:
        current = current_period(entry, ts)
    except PeriodError:
        return "skipped_not_due", None
    if current < first_period(entry):
        return "skipped_not_due", None
    rt = book._runtime[standing_id]
    if rt.last_executed_period is not None and rt.last_executed_period >= current:
        return "already_executed", None
    if fee > entry.max_fee_per_execution:
        return "skipped_fee_cap", current
    payer_bal = read(entry.payer_pubkey)
    if payer_bal < entry.amount + fee:
        return "skipped_insufficient_funds", current
    if fee > 0 and not fee_beneficiary:
        # The fee has nowhere to go; leave the period due so the next block
        # retries it instead of silently burning the fee or skipping a paid
        # period.
        return "skipped_no_beneficiary", None
    # Debit the payer first, then credit through the (possibly staged) view,
    # so payer == payee or payer == beneficiary nets to zero -- the same
    # aliasing-safe ordering the engine's fee settlement uses.
    write(entry.payer_pubkey, payer_bal - entry.amount - fee)
    # A receive route on the payee splits the credit: the payee keeps the
    # net, the destination gets the routed share as a route output (which is
    # itself not routable, so the split is a single hop by construction).
    # The debit above is the full gross, so the split conserves supply.
    split = None
    if route_split is not None:
        try:
            _raw = route_split(
                entry.payee_pubkey, entry.amount, CREDIT_STANDING_PAYMENT, ts
            )
        except Exception:
            _raw = None
        # A malformed split degrades to no split; only a well-formed
        # (net, routed, destination) triple with positive legs applies.
        if isinstance(_raw, (tuple, list)) and len(_raw) == 3:
            _net, _routed, _dest = _raw
            if (
                isinstance(_net, int)
                and not isinstance(_net, bool)
                and isinstance(_routed, int)
                and not isinstance(_routed, bool)
                and isinstance(_dest, str)
                and _net > 0
                and _routed > 0
            ):
                split = (_net, _routed, _dest)
    if split is None:
        write(entry.payee_pubkey, read(entry.payee_pubkey) + entry.amount)
        if credit_records is not None:
            credit_records.record(
                entry.payee_pubkey,
                entry.amount,
                CREDIT_STANDING_PAYMENT,
                standing_id.hex(),
            )
    else:
        from consensus.credits import CREDIT_ROUTE_OUTPUT

        net, routed, destination = split
        write(entry.payee_pubkey, read(entry.payee_pubkey) + net)
        write(destination, read(destination) + routed)
        if credit_records is not None:
            credit_records.record(
                entry.payee_pubkey, net, CREDIT_STANDING_PAYMENT,
                standing_id.hex(),
            )
            credit_records.record(
                destination, routed, CREDIT_ROUTE_OUTPUT, standing_id.hex()
            )
    if fee > 0:
        write(fee_beneficiary, read(fee_beneficiary) + fee)
        if credit_records is not None:
            credit_records.record(
                fee_beneficiary, fee, CREDIT_FEE_REWARD, standing_id.hex()
            )
    return "executed", current


class _StandingSweepHandler:
    """Sweep handler: executes every standing payment whose period is due.

    The sweep runs after the transactions of a block, so a payment is
    executed in the first block whose timestamp falls in its period. The fee
    for the execution is measured by the engine (one Tau fee-query step,
    passed in through the sweep context) and charged to the payer, capped by
    ``max_fee_per_execution``; the fee is credited to the block's fee
    beneficiary. A period that cannot be paid (fee cap, insufficient funds)
    is skipped and the schedule advances -- never caught up.
    """

    kind = "standing"

    def collect_due(self, lm: Any, height: int, ts: int) -> List[SweepDue]:
        book = getattr(lm, "standing", None)
        if book is None:
            return []
        due: List[SweepDue] = []
        for standing_id, entry in book.open.items():
            period = book.due_period(standing_id, ts)
            if period is None:
                continue
            try:
                due_ts = period_start(
                    entry.period_kind, period,
                    anchor=entry.period_anchor, length=entry.period_length,
                )
            except PeriodError:
                continue
            due.append(SweepDue(due_ts=due_ts, object_id=standing_id, kind="standing"))
        return due

    def execute(self, item: SweepDue, ctx: SweepContext) -> str:
        book = getattr(ctx.lm, "standing", None)
        if book is None:
            return "skipped_no_book"
        entry = book.get(item.object_id)
        if entry is None:
            return "skipped_unknown"
        measure_fee = getattr(ctx, "measure_fee", None)
        fee = 0
        if measure_fee is not None:
            try:
                fee = int(measure_fee(
                    entry.payer_pubkey, entry.payee_pubkey, entry.amount, ctx.timestamp
                ))
            except Exception:
                fee = 0
        if fee < 0:
            fee = 0
        fee_beneficiary = getattr(ctx, "fee_beneficiary", "") or ""
        # The engine passes the block's resolved fee beneficiary (governance
        # beneficiary or proposer). When none is resolved and a fee is due,
        # apply_standing_execution reports skipped_no_beneficiary and the
        # period stays due for the next block.
        outcome, period = apply_standing_execution(
            book,
            item.object_id,
            ctx.timestamp,
            read=lambda pubkey: spendable(
                ctx.balances, ctx.sequences, pubkey, ctx.faucet_grant
            ),
            write=lambda pubkey, value: ctx.balances.__setitem__(pubkey, value),
            fee=fee,
            fee_beneficiary=fee_beneficiary,
            credit_records=ctx.credit_records,
            route_split=ctx.route_split,
        )
        if outcome in _ADVANCING_OUTCOMES and period is not None:
            book.mark_executed(item.object_id, period)
        return outcome


register_handler("standing", _StandingSweepHandler())
