"""Credit classes for programmable payments (design sections 1.4 and 2.2).

Every credit the engine lands on an account carries a class. A receive route
(Stage 4) may split a credit only when its class is routable; everything else
passes through untouched. Classes are integers, like the other consensus
kinds in this package (``KIND_HEIGHT`` / ``KIND_TIME`` in
``consensus.retractable``, ``PERIOD_*`` in ``consensus.periods``).

Routable in v1 (exactly the design's list): ordinary ``transfer`` credits and
``standing_payment`` credits. Everything else is excluded: faucet grants,
genesis allocations, fee/reward credits, refunds, route outputs, grant draws
and refunds, payout legs, and retractable releases. A retractable release
lands through the sweep, not through an ordinary credit, so it is never
routed even though it pays the original recipient.

CONSENSUS-FROZEN SURFACE
------------------------
The class numbers below are part of the consensus vocabulary: a later stage
must not renumber them, and a new class is added only by extending this
module (never by reusing a number). ``is_routable_credit`` is total and
fail-closed: any class it does not recognise is not routable.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

CREDIT_TRANSFER = 0
CREDIT_STANDING_PAYMENT = 1
CREDIT_FAUCET = 2
CREDIT_GENESIS = 3
CREDIT_FEE_REWARD = 4
CREDIT_REFUND = 5
CREDIT_ROUTE_OUTPUT = 6
CREDIT_GRANT_DRAW = 7
CREDIT_GRANT_REFUND = 8
CREDIT_PAYOUT_LEG = 9
CREDIT_RETRACTABLE_RELEASE = 10

CREDIT_CLASS_NAMES: Dict[int, str] = {
    CREDIT_TRANSFER: "transfer",
    CREDIT_STANDING_PAYMENT: "standing_payment",
    CREDIT_FAUCET: "faucet",
    CREDIT_GENESIS: "genesis",
    CREDIT_FEE_REWARD: "fee_reward",
    CREDIT_REFUND: "refund",
    CREDIT_ROUTE_OUTPUT: "route_output",
    CREDIT_GRANT_DRAW: "grant_draw",
    CREDIT_GRANT_REFUND: "grant_refund",
    CREDIT_PAYOUT_LEG: "payout_leg",
    CREDIT_RETRACTABLE_RELEASE: "retractable_release",
}

# Design 1.4 / 2.2: only transfer and standing_payment credits are routable.
ROUTABLE_CREDIT_CLASSES = frozenset({CREDIT_TRANSFER, CREDIT_STANDING_PAYMENT})

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")


class CreditClassError(ValueError):
    """A credit record the node cannot classify or store."""


def is_routable_credit(credit_class: int) -> bool:
    """True only for the v1 routable classes; unknown classes are not routable."""
    return credit_class in ROUTABLE_CREDIT_CLASSES


def credit_class_name(credit_class: int) -> str:
    """Display name of a credit class; raises on an unknown class."""
    try:
        return CREDIT_CLASS_NAMES[credit_class]
    except KeyError:
        raise CreditClassError(f"unknown credit class: {credit_class!r}") from None


@dataclass(frozen=True)
class CreditRecord:
    """One credit landed on an account during a block, with its class.

    ``source`` names what produced the credit (a transaction id, or an object
    id for sweep-produced credits) and exists for debugging and receipts; it
    is not consensus state. Records are validated at construction so a bad
    class or a non-positive amount fails loudly instead of entering a block.
    """

    recipient_pubkey: str
    amount: int
    credit_class: int
    source: str

    def __post_init__(self) -> None:
        if not isinstance(self.recipient_pubkey, str) or not _PUBKEY_RE.match(
            self.recipient_pubkey
        ):
            raise CreditClassError("recipient_pubkey must be 96 lowercase hex characters")
        if not isinstance(self.amount, int) or isinstance(self.amount, bool) or self.amount <= 0:
            raise CreditClassError("credit amount must be a positive integer")
        if self.credit_class not in CREDIT_CLASS_NAMES:
            raise CreditClassError(f"unknown credit class: {self.credit_class!r}")
        if not isinstance(self.source, str) or not self.source:
            raise CreditClassError("credit source must be a non-empty string")

    @property
    def routable(self) -> bool:
        return is_routable_credit(self.credit_class)


class CreditLedger:
    """Append-only per-block record of the credits a block landed.

    The ledger is ephemeral: it is built while a block is applied, carried on
    the execution result so tests and later stages can observe it, and never
    persisted or folded into the state root (it is fully determined by the
    block's transactions plus the sweep, so any node recomputes it).
    Recording is fail-closed: a credit whose recipient is not a 96-hex
    pubkey is skipped instead of raising, so the ledger can never break
    block application.
    """

    def __init__(self) -> None:
        self._records: List[CreditRecord] = []

    def record(
        self, recipient_pubkey: str, amount: int, credit_class: int, source: str
    ) -> Optional[CreditRecord]:
        """Record a credit; skip it when the recipient is not a real pubkey.

        The ledger is an observation, never a gate on the apply path: a
        live transaction can hand it a beneficiary that is not a 96-hex
        pubkey (an empty or placeholder beneficiary, a mock in tests), and
        that must never break the block. Such a credit is simply not
        recorded. Returns the record, or ``None`` when skipped.
        """
        if not isinstance(recipient_pubkey, str) or not _PUBKEY_RE.match(
            recipient_pubkey
        ):
            return None
        entry = CreditRecord(
            recipient_pubkey=recipient_pubkey,
            amount=amount,
            credit_class=credit_class,
            source=source,
        )
        self._records.append(entry)
        return entry

    def all(self) -> Tuple[CreditRecord, ...]:
        return tuple(self._records)

    def routable_for(self, recipient_pubkey: str) -> Tuple[CreditRecord, ...]:
        return tuple(
            r
            for r in self._records
            if r.recipient_pubkey == recipient_pubkey and r.routable
        )

    def total_for(
        self, recipient_pubkey: str, credit_class: Optional[int] = None
    ) -> int:
        return sum(
            r.amount
            for r in self._records
            if r.recipient_pubkey == recipient_pubkey
            and (credit_class is None or r.credit_class == credit_class)
        )

    def __len__(self) -> int:
        return len(self._records)
