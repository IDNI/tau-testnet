"""Payout rules (Bounty 01, Stage 5).

One payout rule pays up to eight declared recipients under ONE Tau clause.
The clause is evaluated in the isolated ``payout`` policy pool (see
``tau_policy.POOL_NAMES``) and its outputs ``o1``..``o8`` are the
per-recipient amounts: ``o1`` pays ``recipients[0]``, ``o2`` pays
``recipients[1]``, and so on. A recipient whose output is absent or zero
gets nothing; an output that is not a plain non-negative integer blocks
the whole execution (fail-closed).

Caps: ``max_per_execution`` bounds the total of one execution, and
``max_per_period`` bounds the total paid inside one period (calendar
month, ISO week, day, or fixed — see ``consensus/periods.py``). A period
that cannot be paid is skipped, never caught up.

All legs are atomic or none: the payer is debited once for the total, and
every recipient is credited in the same staged-write step, so either every
leg lands or the execution is rejected as a whole. A leg that would pay a
zero or negative amount, or a total that exceeds a cap or the payer's
balance, rejects the execution before any write is staged.

Removal is #33-aware: payout-rule removal follows the account's normal
rules (only the payer may remove) AND the #33 lock. ``locked_until`` is
the lock: while it is in the future the rule cannot be removed (and, when
protected policy administration (#33) lands, the lock integrates with it
— the removal path already consults the lock, so #33 only has to set it).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from blake3 import blake3

from consensus.credits import CREDIT_PAYOUT_LEG
from consensus.periods import (
    PERIOD_DAY,
    PERIOD_FIXED,
    PERIOD_MONTH,
    PERIOD_WEEK,
    PeriodError,
    period_index,
    period_start,
)
from consensus.serialization import (
    encode_hash32,
    encode_pubkey48,
    encode_string,
    encode_uint32,
    encode_uint64,
)

TX_TYPE_PAYOUT_CREATE = "payout_create"
TX_TYPE_PAYOUT_EXECUTE = "payout_execute"
TX_TYPE_PAYOUT_REMOVE = "payout_remove"
PAYOUT_TX_TYPES = frozenset(
    {TX_TYPE_PAYOUT_CREATE, TX_TYPE_PAYOUT_EXECUTE, TX_TYPE_PAYOUT_REMOVE}
)
# Create and execute change state and can move funds, so they pay; remove
# is fee-exempt, like a retract or a standing/grant/route cancel.
PAYOUT_FEE_BEARING_TX_TYPES = frozenset(
    {TX_TYPE_PAYOUT_CREATE, TX_TYPE_PAYOUT_EXECUTE}
)

DOMAIN_PAYOUT_V1 = "tau.payout.v1"
DOMAIN_PAYOUT_BOOK_V1 = "tau.payout.book.v1"
DOMAIN_PAYOUT_RESOLVED_V1 = "tau.payout.resolved.v1"

MAX_RECIPIENTS = 8
MAX_OPEN_PAYOUTS_PER_PAYER = 16
MAX_OPEN_PAYOUTS_TOTAL = 4096
MAX_CLAUSE_BYTES = 8192

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")


class PayoutShapeError(ValueError):
    """A payout transaction whose shape the node cannot accept."""


def _is_pubkey(value: Any) -> bool:
    return isinstance(value, str) and bool(_PUBKEY_RE.match(value))


def _u64_field(tx: Dict, name: str) -> int:
    value = tx.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PayoutShapeError(f"{name} must be a non-negative integer")
    if value > 2**64 - 1:
        raise PayoutShapeError(f"{name} exceeds uint64")
    return value


def _opt_u64_field(tx: Dict, name: str) -> Optional[int]:
    value = tx.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise PayoutShapeError(f"{name} must be a non-negative integer or null")
    if value > 2**64 - 1:
        raise PayoutShapeError(f"{name} exceeds uint64")
    return value


def first_period(entry: "PayoutEntry") -> int:
    """Index of the first period the payout rule is due in."""
    return period_index(
        entry.period_kind, entry.start_at,
        anchor=entry.period_anchor, length=entry.period_length,
    )


def current_period(entry: "PayoutEntry", ts: int) -> int:
    """Index of the period containing ``ts``."""
    return period_index(
        entry.period_kind, ts,
        anchor=entry.period_anchor, length=entry.period_length,
    )


def compute_payout_id(
    payer_pubkey: str, recipients: Tuple[str, ...], sequence_number: int
) -> bytes:
    """Stable id: payer + ordered recipients + create sequence."""
    h = blake3()
    h.update(encode_string(DOMAIN_PAYOUT_V1))
    h.update(encode_pubkey48(payer_pubkey))
    for recipient in recipients:
        h.update(encode_pubkey48(recipient))
    h.update(encode_uint64(sequence_number))
    return h.digest()


@dataclass(frozen=True)
class PayoutEntry:
    """The immutable terms of one payout rule.

    ``recipients`` is ordered: output ``o1`` pays ``recipients[0]``,
    ``o2`` pays ``recipients[1]``, and so on, up to eight. ``clause`` is
    the single Tau clause body that computes the per-recipient amounts.
    ``locked_until`` is the #33 lock: while it is in the future the rule
    cannot be removed.
    """

    payout_id: bytes
    payer_pubkey: str
    recipients: Tuple[str, ...]
    clause: str
    max_per_execution: int
    max_per_period: int
    period_kind: int
    period_length: Optional[int]
    period_anchor: int
    start_at: int
    expires_at: int
    locked_until: Optional[int]
    sequence_number: int


def parse_payout_create(tx: Dict) -> PayoutEntry:
    """Structural parse of a payout_create transaction (no state checks)."""
    sender = tx.get("sender_pubkey")
    if not _is_pubkey(sender):
        raise PayoutShapeError("sender_pubkey must be a 96-hex pubkey")
    recipients = tx.get("recipients")
    if not isinstance(recipients, list) or not 1 <= len(recipients) <= MAX_RECIPIENTS:
        raise PayoutShapeError(
            f"recipients must be a list of 1..{MAX_RECIPIENTS} pubkeys"
        )
    for recipient in recipients:
        if not _is_pubkey(recipient):
            raise PayoutShapeError("each recipient must be a 96-hex pubkey")
    clause = tx.get("clause")
    if not isinstance(clause, str) or not clause.strip():
        raise PayoutShapeError("clause must be a non-empty string")
    if len(clause.encode("utf-8")) > MAX_CLAUSE_BYTES:
        raise PayoutShapeError(f"clause exceeds {MAX_CLAUSE_BYTES} bytes")
    sequence_number = _u64_field(tx, "sequence_number")
    return PayoutEntry(
        payout_id=compute_payout_id(
            sender, tuple(recipients), sequence_number
        ),
        payer_pubkey=sender,
        recipients=tuple(recipients),
        clause=clause,
        max_per_execution=_u64_field(tx, "max_per_execution"),
        max_per_period=_u64_field(tx, "max_per_period"),
        period_kind=_u64_field(tx, "period_kind"),
        period_length=_opt_u64_field(tx, "period_length"),
        period_anchor=_u64_field(tx, "period_anchor"),
        start_at=_u64_field(tx, "start_at"),
        expires_at=_u64_field(tx, "expires_at"),
        locked_until=_opt_u64_field(tx, "locked_until"),
        sequence_number=sequence_number,
    )


@dataclass(frozen=True)
class PayoutExecuteRequest:
    payout_id: bytes


def parse_payout_execute(tx: Dict) -> PayoutExecuteRequest:
    """Structural parse of a payout_execute transaction (no state checks)."""
    payout_id = tx.get("payout_id")
    if not isinstance(payout_id, str) or len(payout_id) != 64:
        raise PayoutShapeError("payout_id must be 64 lowercase hex characters")
    try:
        raw = bytes.fromhex(payout_id)
    except ValueError:
        raise PayoutShapeError("payout_id must be 64 lowercase hex characters")
    return PayoutExecuteRequest(payout_id=raw)


@dataclass(frozen=True)
class PayoutRemoveRequest:
    payout_id: bytes


def parse_payout_remove(tx: Dict) -> PayoutRemoveRequest:
    """Structural parse of a payout_remove transaction (no state checks)."""
    payout_id = tx.get("payout_id")
    if not isinstance(payout_id, str) or len(payout_id) != 64:
        raise PayoutShapeError("payout_id must be 64 lowercase hex characters")
    try:
        raw = bytes.fromhex(payout_id)
    except ValueError:
        raise PayoutShapeError("payout_id must be 64 lowercase hex characters")
    return PayoutRemoveRequest(payout_id=raw)


def validate_payout_shape(
    entry: PayoutEntry, height: int, now: int
) -> Optional[str]:
    """Semantic shape checks for a payout rule. None when valid."""
    if not _is_pubkey(entry.payer_pubkey):
        return "payer_pubkey must be a 96-hex pubkey"
    if not 1 <= len(entry.recipients) <= MAX_RECIPIENTS:
        return f"recipients must be 1..{MAX_RECIPIENTS} pubkeys"
    if len(set(entry.recipients)) != len(entry.recipients):
        return "recipients must be distinct"
    if entry.payer_pubkey in entry.recipients:
        return "the payer cannot be one of its own recipients"
    for recipient in entry.recipients:
        if not _is_pubkey(recipient):
            return "each recipient must be a 96-hex pubkey"
    if not entry.clause or not entry.clause.strip():
        return "clause must be a non-empty string"
    if len(entry.clause.encode("utf-8")) > MAX_CLAUSE_BYTES:
        return f"clause exceeds {MAX_CLAUSE_BYTES} bytes"
    if entry.max_per_execution <= 0:
        return "max_per_execution must be positive"
    if entry.max_per_period <= 0:
        return "max_per_period must be positive"
    if entry.max_per_execution > entry.max_per_period:
        return "max_per_execution must not exceed max_per_period"
    if entry.period_kind not in (PERIOD_FIXED, PERIOD_DAY, PERIOD_WEEK, PERIOD_MONTH):
        return "period_kind is not a known period kind"
    if entry.period_kind == PERIOD_FIXED:
        if entry.period_length is None or entry.period_length <= 0:
            return "a fixed period needs a positive period_length"
        if entry.start_at < entry.period_anchor:
            return "for a fixed period, start_at must be at or after period_anchor"
    if entry.start_at >= entry.expires_at:
        return "start_at must be before expires_at"
    if entry.locked_until is not None:
        if entry.locked_until <= now:
            return "locked_until must be in the future"
        if entry.locked_until > entry.expires_at:
            return "locked_until must not exceed expires_at"
    return None


@dataclass
class _PayoutRuntime:
    """Mutable per-period payment tracking, per open payout rule."""

    period_index: Optional[int] = None
    paid_in_period: int = 0
    executions: int = 0


class PayoutBook:
    """Payout rules: one Tau clause paying up to eight recipients.

    The book is the consensus state for payout rules: deep-copied per
    candidate block (like the other programmable-payments books), bound
    into the consensus meta hash through ``root()``, and persisted by
    ``chain_state``/``db``. A removed rule folds into the resolved
    commitment, so a restart cannot resurrect it.
    """

    def __init__(self) -> None:
        self.open: Dict[bytes, PayoutEntry] = {}
        self._runtime: Dict[bytes, _PayoutRuntime] = {}
        self._resolved_count: int = 0
        self._resolved_acc: bytes = bytes(32)

    # -- queries ---------------------------------------------------------
    def get(self, payout_id: bytes) -> Optional[PayoutEntry]:
        return self.open.get(payout_id)

    def is_empty(self) -> bool:
        return not self.open

    def escrowed_total(self) -> int:
        """Coins held in escrow by this book: always 0.

        A payout rule holds no funds; the payer pays at execution time,
        so the supply-conservation check never needs to add anything
        for payouts. Present so _escrow_total can count every book
        uniformly.
        """
        return 0

    def open_count(self) -> int:
        return len(self.open)

    def resolved_state(self) -> Tuple[int, bytes]:
        return (self._resolved_count, self._resolved_acc)

    def root(self) -> bytes:
        """Deterministic commitment over the open rules + resolved."""
        h = blake3()
        h.update(encode_string(DOMAIN_PAYOUT_BOOK_V1))
        for payout_id in sorted(self.open):
            entry = self.open[payout_id]
            rt = self._runtime[payout_id]
            h.update(encode_hash32(entry.payout_id))
            h.update(encode_pubkey48(entry.payer_pubkey))
            for recipient in entry.recipients:
                h.update(encode_pubkey48(recipient))
            h.update(encode_string(entry.clause))
            h.update(encode_uint64(entry.max_per_execution))
            h.update(encode_uint64(entry.max_per_period))
            h.update(encode_uint32(entry.period_kind))
            h.update(encode_uint64(entry.period_length or 0))
            h.update(encode_uint64(entry.period_anchor))
            h.update(encode_uint64(entry.start_at))
            h.update(encode_uint64(entry.expires_at))
            h.update(encode_uint64(entry.locked_until or 0))
            h.update(encode_uint64(entry.sequence_number))
            h.update(encode_uint64(rt.period_index or 0))
            h.update(encode_uint64(rt.paid_in_period))
            h.update(encode_uint64(rt.executions))
        h.update(encode_uint64(self._resolved_count))
        h.update(self._resolved_acc)
        return h.digest()

    def due_period(self, payout_id: bytes, ts: int) -> Optional[int]:
        """The current period for a rule, or None when it is not yet live."""
        entry = self.open.get(payout_id)
        if entry is None:
            return None
        try:
            current = current_period(entry, ts)
            first = first_period(entry)
        except PeriodError:
            return None
        if current < first:
            return None
        return current

    # -- admission -------------------------------------------------------
    def can_admit_create(
        self, entry: PayoutEntry, height: int, now: int
    ) -> Tuple[bool, str]:
        """True when a payout_create may land (shape + caps + book cap)."""
        shape_error = validate_payout_shape(entry, height, now)
        if shape_error is not None:
            return (False, shape_error)
        if entry.payout_id in self.open:
            return (False, "a payout rule with this id already exists")
        if len(self.open) >= MAX_OPEN_PAYOUTS_TOTAL:
            return (False, "the payout book is full")
        payer_open = sum(
            1 for e in self.open.values() if e.payer_pubkey == entry.payer_pubkey
        )
        if payer_open >= MAX_OPEN_PAYOUTS_PER_PAYER:
            return (False, "the payer already has too many open payout rules")
        return (True, "")

    def can_admit_execute(
        self, payout_id: bytes, sender_pubkey: Any, height: int, now: int,
        fee_limit: Optional[int] = None,
    ) -> Tuple[bool, str]:
        """True when a payout_execute may land (exists + live + unexpired).

        ``fee_limit`` is accepted for the admission call shape (mirroring
        standing) but not enforced: a payout rule has no per-execution
        fee cap, the fee is the standard transaction fee.
        """
        entry = self.open.get(payout_id)
        if entry is None:
            return (False, "unknown payout rule")
        if sender_pubkey != entry.payer_pubkey:
            return (False, "only the payer can execute its payout rule")
        if now < entry.start_at:
            return (False, "payout rule has not started yet")
        if now >= entry.expires_at:
            return (False, "payout rule has expired")
        return (True, "")

    def can_admit_remove(
        self, payout_id: bytes, sender_pubkey: Any, height: int, now: int
    ) -> Tuple[bool, str]:
        """True when a payout_remove may land.

        #33-aware: only the payer may remove, and a rule whose #33 lock
        (``locked_until``) is still in the future cannot be removed at
        all — the lock is the point where protected policy administration
        (#33) will attach, and removal already consults it.
        """
        entry = self.open.get(payout_id)
        if entry is None:
            return (False, "unknown payout rule")
        if sender_pubkey != entry.payer_pubkey:
            return (False, "only the payer can remove its payout rule")
        if entry.locked_until is not None and now < entry.locked_until:
            return (
                False,
                f"payout rule is locked until {entry.locked_until}",
            )
        return (True, "")

    # -- mutation --------------------------------------------------------
    def submit(self, entry: PayoutEntry) -> None:
        """Open a payout rule.

        A duplicate id is a programming error, not a replace: silently
        overwriting would drop the original rule's execution history.
        Admission and can_admit_create reject duplicates first, so this
        is the last line of defence.
        """
        if entry.payout_id in self.open:
            raise ValueError("a payout rule with this id already exists")
        self.open[entry.payout_id] = entry
        self._runtime[entry.payout_id] = _PayoutRuntime()

    def remove(self, payout_id: bytes) -> None:
        """Remove a payout rule, folding it into the resolved commitment."""
        entry = self.open.pop(payout_id, None)
        if entry is None:
            return
        self._runtime.pop(payout_id, None)
        self._resolved_count += 1
        h = blake3()
        h.update(encode_string(DOMAIN_PAYOUT_RESOLVED_V1))
        h.update(self._resolved_acc)
        h.update(entry.payout_id)
        self._resolved_acc = h.digest()

    def mark_executed(self, payout_id: bytes, period: int, total: int) -> None:
        """Record one execution's total against its period (cap tracking)."""
        rt = self._runtime.get(payout_id)
        if rt is None:
            return
        if rt.period_index != period:
            rt.period_index = period
            rt.paid_in_period = 0
        rt.paid_in_period += total
        rt.executions += 1

    def paid_in_period(self, payout_id: bytes, period: int) -> int:
        """Total paid in `period` (0 when the period is new)."""
        rt = self._runtime.get(payout_id)
        if rt is None or rt.period_index != period:
            return 0
        return rt.paid_in_period

    # -- persistence -----------------------------------------------------
    def snapshot_rows(self) -> List[Dict[str, Any]]:
        """Rows for the payouts table: one per open rule, plus its runtime."""
        rows: List[Dict[str, Any]] = []
        for payout_id in sorted(self.open):
            entry = self.open[payout_id]
            rt = self._runtime[payout_id]
            rows.append(
                {
                    "payout_id": payout_id.hex(),
                    "payer_pubkey": entry.payer_pubkey,
                    "recipients": list(entry.recipients),
                    "clause": entry.clause,
                    "max_per_execution": entry.max_per_execution,
                    "max_per_period": entry.max_per_period,
                    "period_kind": entry.period_kind,
                    "period_length": entry.period_length,
                    "period_anchor": entry.period_anchor,
                    "start_at": entry.start_at,
                    "expires_at": entry.expires_at,
                    "locked_until": entry.locked_until,
                    "sequence_number": entry.sequence_number,
                    "period_index": rt.period_index,
                    "paid_in_period": rt.paid_in_period,
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
    ) -> "PayoutBook":
        """Rebuild a book from stored rows.

        A row whose id does not recompute from its fields is refused: the
        stored state is corrupt, and loading it would fork the node.
        """
        book = cls()
        for row in rows:
            payout_id = bytes.fromhex(row["payout_id"])
            # Rows from the DB carry recipients as a JSON string (the
            # payouts_v1 column is TEXT); rows from snapshot_rows() carry
            # them as a list. Accept both, or a node restart / admission
            # rebuild from stored rows would read "[" as a pubkey.
            raw_recipients = row["recipients"]
            if isinstance(raw_recipients, str):
                recipients = tuple(json.loads(raw_recipients))
            else:
                recipients = tuple(raw_recipients)
            if payout_id != compute_payout_id(
                row["payer_pubkey"], recipients, int(row["sequence_number"])
            ):
                raise ValueError("stored payout id does not match its fields")
            entry = PayoutEntry(
                payout_id=payout_id,
                payer_pubkey=row["payer_pubkey"],
                recipients=recipients,
                clause=row["clause"],
                max_per_execution=int(row["max_per_execution"]),
                max_per_period=int(row["max_per_period"]),
                period_kind=int(row["period_kind"]),
                period_length=(
                    None if row["period_length"] is None
                    else int(row["period_length"])
                ),
                period_anchor=int(row["period_anchor"]),
                start_at=int(row["start_at"]),
                expires_at=int(row["expires_at"]),
                locked_until=(
                    None if row["locked_until"] is None
                    else int(row["locked_until"])
                ),
                sequence_number=int(row["sequence_number"]),
            )
            book.open[payout_id] = entry
            book._runtime[payout_id] = _PayoutRuntime(
                period_index=(
                    None if row["period_index"] is None
                    else int(row["period_index"])
                ),
                paid_in_period=int(row["paid_in_period"]),
                executions=int(row["executions"]),
            )
        book._resolved_count = int(resolved_count)
        book._resolved_acc = bytes(resolved_acc)
        return book


def apply_payout(
    book: PayoutBook,
    payout_id: bytes,
    ts: int,
    amounts: List[int],
    *,
    read,
    write,
    fee: int = 0,
    fee_beneficiary: str = "",
    credit_records=None,
) -> Tuple[str, Optional[int]]:
    """Pay one execution of a payout rule from its clause outputs.

    ``amounts[i]`` is the clause output ``o{i+1}`` for ``recipients[i]``
    (a missing or zero output pays nothing to that recipient). Returns
    ``(outcome, period)``. The caller advances the cap tracking
    (``book.mark_executed``) for the ``executed`` outcome only — a skipped
    execution pays nothing and must not consume the period cap.

    All legs are atomic or none: every check runs before any write is
    staged, so a rejected execution leaves every balance untouched.
    """
    entry = book.get(payout_id)
    if entry is None:
        return ("skipped_unknown", None)
    if len(amounts) != len(entry.recipients):
        return ("skipped_bad_outputs", None)
    try:
        current = current_period(entry, ts)
        first = first_period(entry)
    except PeriodError:
        return ("skipped_not_due", None)
    if current < first:
        return ("skipped_not_due", None)
    if ts < entry.start_at or ts >= entry.expires_at:
        return ("skipped_not_due", None)
    total = 0
    for amount in amounts:
        if not isinstance(amount, int) or isinstance(amount, bool):
            return ("skipped_bad_outputs", None)
        if amount < 0:
            return ("skipped_bad_outputs", None)
        total += amount
    if total <= 0:
        return ("skipped_zero", current)
    paid = book.paid_in_period(payout_id, current)
    if paid > 0 and paid >= entry.max_per_period:
        # The period is fully spent by an earlier execution: the rule has
        # already fired this period, so there is nothing left to pay. (A
        # period with headroom left reports skipped_period_cap instead.)
        return ("already_executed", current)
    if total > entry.max_per_execution:
        return ("skipped_exec_cap", current)
    if paid + total > entry.max_per_period:
        return ("skipped_period_cap", current)
    payer_bal = read(entry.payer_pubkey)
    if payer_bal < total + fee:
        return ("skipped_insufficient_funds", current)
    if fee > 0 and not fee_beneficiary:
        return ("skipped_no_beneficiary", None)
    # Every check passed: stage all legs, then record. The payer is
    # debited once for the total (plus fee); each recipient is credited
    # its leg. A leg of zero is skipped (a zero credit is not a record).
    write(entry.payer_pubkey, payer_bal - total - fee)
    for recipient, amount in zip(entry.recipients, amounts):
        if amount <= 0:
            continue
        write(recipient, read(recipient) + amount)
        if credit_records is not None:
            credit_records.record(
                recipient, amount, CREDIT_PAYOUT_LEG, payout_id.hex()
            )
    if fee > 0:
        write(fee_beneficiary, read(fee_beneficiary) + fee)
        if credit_records is not None:
            from consensus.credits import CREDIT_FEE_REWARD

            credit_records.record(
                fee_beneficiary, fee, CREDIT_FEE_REWARD, payout_id.hex()
            )
    return ("executed", current)


def clause_outputs_for(clause, *, payer_balance, ts, payer_pubkey, evaluator=None):
    """{output name: int} for a payout clause, evaluated in the payout pool.

    Inputs follow the transfer path: i1 = payer balance, i5 = block
    timestamp, i12 = payer pubkey (bv[384]). Returns None when the clause
    blocks or cannot be evaluated, so the execution fails closed (pays
    nothing). `evaluator` is injectable for tests; otherwise the
    payout-pool evaluator is used. Engine tests patch this function
    directly (the real worker is a subprocess the test harness cannot
    mock), so the payout execution path never depends on it succeeding.
    """
    from consensus.sender_policy import clause_inputs, evaluator as _pool_evaluator
    from tau_policy import PolicyBuildError, PolicyStepError

    if evaluator is None:
        evaluator = _pool_evaluator("payout")
    inputs = clause_inputs({
        1: str(payer_balance),
        5: str(ts),
        12: "{ #x" + str(payer_pubkey) + " }:bv[384]",
    })
    try:
        return evaluator.step_outputs(clause, inputs)
    except (PolicyBuildError, PolicyStepError):
        return None
