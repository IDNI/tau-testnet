"""Payout rules: rule-computed payouts under declared caps (#63).

An owner installs one payout rule: a declared recipient set, declared caps
(a maximum per execution and a maximum per period), and ONE of two forms
for computing the legs of an execution:

- the DECLARED PROGRAM form (the original): a stored leg program the node
  computes from the execution's submitted base amount;
- the TAU RULE form: the owner's own Tau clause, which the node steps
  through the real policy-evaluation path (sender_policy.clause_outputs)
  over a node-built input map — the form gmikeyg's payout shape asks for
  (the node runs the rule, the rule outputs recipients and amounts) and
  the form andrei-idni's acceptance criterion names: a new payout policy
  is a new CLAUSE, not a new execution path in the node.

Anyone may then submit an execution carrying the rule's inputs; the node —
never the submitter — computes the legs, checks them against the declared
set, both caps and the owner's balance, and settles every leg atomically
or none. Which form an entry is is a signed field, inside its rule id.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would
make two honest nodes disagree about admissibility, which forks.

- The leg program is data the owner signed, stored in the entry: each leg
  names a recipient from the declared set and computes its amount from the
  execution's submitted base amount — a FIXED declared amount, or a share
  of the base in basis points with floor rounding (the royalty shape: 500
  bps of a 101 base pays exactly 5). The submitter supplies only the base
  amount and the settlement id; it cannot steer recipients or amounts
  beyond what the signed program computes.
- The Tau form's clause is data the owner signed the same way: the clause
  text is stored in the entry and inside the rule id (its own hash
  domain), so a tampered clause is a different, unknown rule. At execution
  the node builds the clause's input map itself (payout_clause_inputs:
  base amount, owner balance, owner, executor, block timestamp, and the
  rule's per-period paid total at i26) — the submitter supplies only the
  base amount and the settlement id, exactly as in the declared form, and
  cannot write any stream of the map. The clause's outputs name the legs
  under the encoding pinned in payout_rule_capabilities() (o30 = leg
  count; per leg a recipient CANDIDATE INDEX into the declared set and an
  amount). The node then applies the SAME checks as the declared form —
  declared set, both caps, balance — so the clause decides and the node
  checks and applies; a clause that does not build, cannot be stepped, or
  writes a blocking o5 computes no legs and the execution settles
  nothing, deterministically on every node. The book itself never steps
  a clause: callers (engine at apply, admission at the tip) step it and
  hand the decoded legs in, which keeps this module Tau-free and its
  decision path reusable verbatim at both sites.
- Settlement is recorded in the book keyed by the execution's settlement
  id — that is what makes "pays 5, once" a consensus property, not a
  client property. A second execution carrying an already-settled
  settlement id (a replay of the same transaction, or a fresh transaction
  naming the same settlement) settles nothing. Settlements are rooted with
  the book and survive removal and replacement of the rule, so reinstalling
  the same rule can never reset one.
- Caps: a declared cap of 0 leaves that dimension uncapped. A cap that is
  declared binds exactly: an execution whose total exceeds the
  per-execution cap, or that would push the period's paid total past the
  per-period cap, settles nothing. The period is a fixed-length window
  from the rule's signed anchor (period_seconds), the standing book's
  fixed-schedule arithmetic; per-period paid totals are book state.
- An execution that cannot settle settles NOTHING: no leg moves, no
  settlement is recorded, no period total advances — the same discipline
  as a standing payment's insufficient-funds occurrence, so a retry with
  valid inputs is a well-defined, explicit operation.
- Legs settle with the payout-leg credit class (the design's credit-class
  table): a payout credit never triggers a receive route, another payout,
  or a standing payment.
- Removal follows the account's normal rules: an owner-signed removal
  transaction, screened by the book's can_remove at admission and apply
  verbatim. (A #33-style lock, if one is ever active on the account, binds
  through the same administration path as the other books; #33 is not on
  main at the base this book was built against.)
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.payment_calendar import SECONDS_PER_DAY
from consensus.serialization import (
    compute_payout_rule_book_root,
    compute_payout_rule_id,
    compute_payout_rule_tau_id,
)

TX_TYPE_INSTALL_PAYOUT_RULE = "install_payout_rule"
TX_TYPE_REMOVE_PAYOUT_RULE = "remove_payout_rule"
TX_TYPE_EXECUTE_PAYOUT_RULE = "execute_payout_rule"

PAYOUT_RULE_TX_TYPES = frozenset(
    {
        TX_TYPE_INSTALL_PAYOUT_RULE,
        TX_TYPE_REMOVE_PAYOUT_RULE,
        TX_TYPE_EXECUTE_PAYOUT_RULE,
    }
)

# Leg computation modes. A leg's amount is a pure function of the signed
# program and the execution's submitted base amount.
LEG_FIXED = 1
LEG_BPS_OF_BASE = 2
LEG_MODES = frozenset({LEG_FIXED, LEG_BPS_OF_BASE})
MAX_LEG_BPS = 10_000

# The two forms an entry can take. The form is a signed field of the rule:
# it is inside the install signature and the rule id, so the form an
# execution runs under is the form the owner signed.
FORM_DECLARED_PROGRAM = 1
FORM_TAU_RULE = 2
PAYOUT_FORMS = frozenset({FORM_DECLARED_PROGRAM, FORM_TAU_RULE})

# The Tau form's clause text bound, in UTF-8 bytes — the same bound the
# rule-offer path puts on rule text (consensus/rule_offers
# MAX_OFFER_RULE_BYTES), so a payout clause is no larger than a rule the
# node already carries.
MAX_PAYOUT_CLAUSE_BYTES = 8192

# The Tau form's output encoding: o30 carries the leg count, then each leg
# is a (recipient candidate index, amount) pair on consecutive streams.
PAYOUT_OUTPUT_COUNT_STREAM = 30
PAYOUT_OUTPUT_FIRST_STREAM = 31

# Bounded state: one rule per owner, and the rule itself is small.
MAX_RECIPIENTS = 32
MAX_LEGS = 32
MAX_PERIOD_SECONDS = 366 * SECONDS_PER_DAY

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class PayoutRuleShapeError(ValueError):
    """A payout-rule transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class PayoutLeg:
    """One leg of the signed program: who is paid, and how the amount computes."""

    recipient_pubkey: str
    mode: int
    value: int

    def amount_for(self, base_amount: int) -> int:
        if self.mode == LEG_FIXED:
            return self.value
        return (base_amount * self.value) // MAX_LEG_BPS


@dataclass(frozen=True)
class PayoutRuleEntry:
    """The signed terms of one payout rule version. Nothing here mutates.

    `form` and `clause_text` default to the declared-program form, so every
    entry constructed before the Tau form existed — and every declared-form
    entry constructed now — is byte-identical to what it was.
    """

    owner_pubkey: str
    recipients: Tuple[str, ...]
    legs: Tuple[PayoutLeg, ...]
    max_per_execution: int
    max_per_period: int
    period_seconds: int
    period_anchor_ts: int
    version: int
    form: int = FORM_DECLARED_PROGRAM
    clause_text: str = ""

    @property
    def rule_id(self) -> bytes:
        if self.form == FORM_TAU_RULE:
            return compute_payout_rule_tau_id(
                self.owner_pubkey,
                self.recipients,
                self.clause_text,
                self.max_per_execution,
                self.max_per_period,
                self.period_seconds,
                self.period_anchor_ts,
                self.version,
            )
        return compute_payout_rule_id(
            self.owner_pubkey,
            self.recipients,
            tuple(
                (leg.recipient_pubkey, leg.mode, leg.value) for leg in self.legs
            ),
            self.max_per_execution,
            self.max_per_period,
            self.period_seconds,
            self.period_anchor_ts,
            self.version,
        )


@dataclass(frozen=True)
class PayoutSettlement:
    """The record of one settled execution. History: never rewritten."""

    rule_id: bytes
    settlement_id: bytes
    base_amount: int
    total: int
    execution_ts: int


@dataclass(frozen=True)
class PayoutDecision:
    """The outcome of presenting one execution to the book.

    `executed` False means nothing moved: no leg settled, no settlement
    was recorded, no period total advanced. `reason` names why, for
    receipts and tests. On success `legs` is the computed (recipient,
    amount) list with zero legs dropped, `total` their sum, and
    `period_index` the period the execution landed in.
    """

    executed: bool
    reason: str
    legs: Tuple[Tuple[str, int], ...]
    total: int
    period_index: int
    period_total_after: int


def period_index_at(entry: PayoutRuleEntry, ts: int) -> int:
    """Which period contains `ts`; -1 before the anchor."""
    if ts < entry.period_anchor_ts:
        return -1
    return (ts - entry.period_anchor_ts) // entry.period_seconds


def compute_legs(
    entry: PayoutRuleEntry, base_amount: int
) -> Tuple[Tuple[str, int], ...]:
    """The legs the stored program computes for `base_amount`.

    Pure and deterministic: the same entry and the same inputs give the
    same legs on every node. Legs that compute to zero are dropped — a
    zero leg moves no value and must not pose as a payment.
    """
    out = []
    for leg in entry.legs:
        amount = leg.amount_for(base_amount)
        if amount > 0:
            out.append((leg.recipient_pubkey, amount))
    return tuple(out)


# --- The Tau form: input map and output decoding --------------------------------

_OUTPUT_VALUE_RE = re.compile(
    r"^\{?\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}?(?::bv\[\d+\])?$"
)


def _parse_output_value(value: Any) -> Optional[int]:
    """One clause output as an integer, or None when it is not one.

    The worker reports outputs as Tau value strings; this reads them with
    the same grammar tau_policy.parse_o5 reads o5 with (hex / binary /
    decimal, optional braces and :bv[N] annotation).
    """
    if value is None:
        return None
    match = _OUTPUT_VALUE_RE.match(str(value).strip())
    if not match:
        return None
    hex_digits, bin_digits, dec_digits = match.groups()
    if hex_digits is not None:
        return int(hex_digits, 16)
    if bin_digits is not None:
        return int(bin_digits, 2)
    return int(dec_digits)


def payout_clause_inputs(
    entry: PayoutRuleEntry,
    executor_pubkey: str,
    base_amount: int,
    ts: int,
    owner_balance: int,
    period_paid_total: int,
) -> Dict[int, Any]:
    """The input map a Tau-form execution steps the owner's clause over.

    ONE definition, called by the engine at apply and by admission at the
    tip with their own site values — the construction cannot drift between
    them. The value formats mirror the transfer input map
    (consensus/engine._transfer_input_map) exactly: amounts and the
    timestamp as decimal strings, accounts as `{ #x.. }:bv[384]` literals.

    - i1: the execution's submitted base amount
    - i2: the rule owner's balance
    - i3: the rule owner's pubkey
    - i4: the execution submitter's pubkey (anyone may execute)
    - i5: the block timestamp
    - i26 (tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX): what this rule has
      already paid in the period containing `ts`, from the book's recorded
      totals — the release-schedule input a grant or vesting clause
      computes its remaining allowance from

    Nothing in the map comes from the execution transaction beyond the
    base amount: the map is node-built, so no submitter can steer the
    clause by writing a stream.
    """
    return {
        1: str(int(base_amount)),
        2: str(int(owner_balance)),
        3: "{ #x" + str(entry.owner_pubkey) + " }:bv[384]",
        4: "{ #x" + str(executor_pubkey) + " }:bv[384]",
        5: str(int(ts)),
        tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX: str(int(period_paid_total)),
    }


def decode_clause_legs(
    entry: PayoutRuleEntry, outputs: Dict[str, Any]
) -> Tuple[Optional[Tuple[Tuple[str, int], ...]], str]:
    """The legs a stepped clause named, or (None, why not).

    The encoding (pinned in payout_rule_capabilities): o30 is the leg
    count; leg k reads its recipient candidate index — 0-based into the
    entry's canonical recipients tuple — from o(31+2k) and its amount from
    o(32+2k). Zero-amount legs are dropped, as compute_legs drops them. A
    count above MAX_LEGS, a missing or unreadable value, or an index
    outside the declared set means the clause named something the node
    cannot settle: no legs, and the execution settles nothing.
    """
    count = _parse_output_value(outputs.get(f"o{PAYOUT_OUTPUT_COUNT_STREAM}"))
    if count is None:
        return None, "the rule's clause did not report a leg count"
    if count < 0 or count > MAX_LEGS:
        return None, f"the rule's clause reported {count} legs"
    legs: List[Tuple[str, int]] = []
    for k in range(count):
        index = _parse_output_value(
            outputs.get(f"o{PAYOUT_OUTPUT_FIRST_STREAM + 2 * k}")
        )
        amount = _parse_output_value(
            outputs.get(f"o{PAYOUT_OUTPUT_FIRST_STREAM + 2 * k + 1}")
        )
        if index is None or amount is None:
            return None, "the rule's clause reported an unreadable leg"
        if not 0 <= index < len(entry.recipients):
            return None, (
                "the rule's clause named recipient candidate "
                f"{index}, outside the declared set"
            )
        if amount > 0:
            legs.append((entry.recipients[index], amount))
    return tuple(legs), ""


# --- Parsing -------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise PayoutRuleShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str, default: int = 0) -> int:
    value = tx.get(name, default)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise PayoutRuleShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _id_field(tx: Dict[str, Any], name: str) -> bytes:
    value = tx.get(name)
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise PayoutRuleShapeError(f"{name} must be 64 lowercase hex characters")
    return bytes.fromhex(value)


def _recipients_field(tx: Dict[str, Any]) -> Tuple[str, ...]:
    value = tx.get("payout_recipients")
    if not isinstance(value, list) or not value:
        raise PayoutRuleShapeError("payout_recipients must be a non-empty list")
    out = []
    for item in value:
        if not isinstance(item, str) or not _PUBKEY_RE.match(item):
            raise PayoutRuleShapeError(
                "payout_recipients entries must be 96 lowercase hex characters"
            )
        out.append(item)
    # The declared set is a set: canonical (sorted, unique) in the entry, so
    # two spellings of the same set are the same rule.
    return tuple(sorted(set(out)))


def _legs_field(tx: Dict[str, Any]) -> Tuple[PayoutLeg, ...]:
    value = tx.get("payout_legs")
    if not isinstance(value, list) or not value:
        raise PayoutRuleShapeError("payout_legs must be a non-empty list")
    out = []
    for item in value:
        if not isinstance(item, (list, tuple)) or len(item) != 3:
            raise PayoutRuleShapeError(
                "payout_legs entries must be [recipient, mode, value]"
            )
        recipient, mode, amount = item
        if not isinstance(recipient, str) or not _PUBKEY_RE.match(recipient):
            raise PayoutRuleShapeError(
                "payout_legs recipients must be 96 lowercase hex characters"
            )
        if not _is_int(mode) or not _is_int(amount):
            raise PayoutRuleShapeError("payout_legs mode and value must be integers")
        out.append(PayoutLeg(recipient, mode, amount))
    return tuple(out)


def _form_field(tx: Dict[str, Any]) -> int:
    value = tx.get("payout_form", FORM_DECLARED_PROGRAM)
    if not _is_int(value) or value not in PAYOUT_FORMS:
        raise PayoutRuleShapeError(
            "payout_form must be 1 (declared program) or 2 (Tau rule)"
        )
    return value


def _clause_field(tx: Dict[str, Any]) -> str:
    value = tx.get("payout_clause", "")
    if not isinstance(value, str):
        raise PayoutRuleShapeError("payout_clause must be a string")
    return value


def parse_install_payout_rule(tx: Dict[str, Any]) -> PayoutRuleEntry:
    """Read an installation from ROOT fields only; a nested `payload` is unsigned data.

    The form selects which leg source the root fields must carry: the
    declared form reads `payout_legs` and refuses a clause; the Tau form
    reads `payout_clause` and refuses a leg program. A transaction that
    carries both (or neither) does not have a shape the node can record.
    """
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    form = _form_field(tx)
    clause_text = _clause_field(tx)
    if form == FORM_TAU_RULE:
        if not clause_text:
            raise PayoutRuleShapeError(
                "a Tau-form payout rule must carry payout_clause"
            )
        raw_legs = tx.get("payout_legs")
        if raw_legs:
            raise PayoutRuleShapeError(
                "a Tau-form payout rule carries no payout_legs program"
            )
        legs: Tuple[PayoutLeg, ...] = ()
    else:
        if clause_text:
            raise PayoutRuleShapeError(
                "payout_clause is only for the Tau form (payout_form 2)"
            )
        legs = _legs_field(tx)
    return PayoutRuleEntry(
        owner_pubkey=_pubkey_field(tx, "sender_pubkey"),
        recipients=_recipients_field(tx),
        legs=legs,
        max_per_execution=_u64_field(tx, "payout_max_per_execution"),
        max_per_period=_u64_field(tx, "payout_max_per_period"),
        period_seconds=_u64_field(tx, "payout_period_seconds"),
        period_anchor_ts=_u64_field(tx, "payout_period_anchor_ts"),
        version=_u64_field(tx, "payout_version", default=1),
        form=form,
        clause_text=clause_text,
    )


def parse_remove_payout_rule(tx: Dict[str, Any]) -> str:
    """Read a removal's owner from ROOT fields only; returns the owner pubkey."""
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    return _pubkey_field(tx, "sender_pubkey")


def parse_execute_payout_rule(
    tx: Dict[str, Any],
) -> Tuple[bytes, bytes, int]:
    """Read an execution from ROOT fields: (rule id, settlement id, base amount)."""
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    return (
        _id_field(tx, "payout_rule_id"),
        _id_field(tx, "payout_settlement_id"),
        _u64_field(tx, "payout_base_amount"),
    )


def validate_payout_rule_shape(
    entry: PayoutRuleEntry, now_ts: int
) -> Optional[str]:
    """Stateless admissibility of a payout rule. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything needing the book lives in `can_install`.
    """
    if not 1 <= len(entry.recipients) <= MAX_RECIPIENTS:
        return f"a payout rule declares 1..{MAX_RECIPIENTS} recipients"
    if len(set(entry.recipients)) != len(entry.recipients):
        return "the declared recipient set names an account twice"
    if entry.owner_pubkey in entry.recipients:
        return "a payout rule cannot pay its own owner"
    if entry.form not in PAYOUT_FORMS:
        return "unknown payout form"
    if entry.form == FORM_TAU_RULE:
        if entry.legs:
            return "a Tau-form payout rule carries no leg program"
        if not entry.clause_text:
            return "a Tau-form payout rule must carry a clause"
        if len(entry.clause_text.encode("utf-8")) > MAX_PAYOUT_CLAUSE_BYTES:
            return (
                f"a payout clause is at most {MAX_PAYOUT_CLAUSE_BYTES} bytes"
            )
    else:
        if entry.clause_text:
            return "a declared-form payout rule carries no clause"
        if not 1 <= len(entry.legs) <= MAX_LEGS:
            return f"a payout rule's program has 1..{MAX_LEGS} legs"
        declared = set(entry.recipients)
        for leg in entry.legs:
            if leg.recipient_pubkey not in declared:
                return "a leg pays a recipient outside the declared set"
            if leg.mode not in LEG_MODES:
                return "unknown leg mode"
            if leg.mode == LEG_FIXED:
                if not 1 <= leg.value <= tau_defs.MAX_TRANSFER_VALUE:
                    return "a fixed leg must be in 1..MAX_TRANSFER_VALUE"
            elif not 1 <= leg.value <= MAX_LEG_BPS:
                return "a basis-point leg must be in 1..10000"
    if entry.max_per_execution > tau_defs.MAX_TRANSFER_VALUE:
        return "payout_max_per_execution exceeds the maximum transfer value"
    if entry.max_per_period > tau_defs.MAX_TRANSFER_VALUE:
        return "payout_max_per_period exceeds the maximum transfer value"
    if not 1 <= entry.period_seconds <= MAX_PERIOD_SECONDS:
        return f"payout_period_seconds must be in 1..{MAX_PERIOD_SECONDS}"
    if entry.version < 1:
        return "payout_version must start at 1"
    return None


# --- The book ------------------------------------------------------------------

_EntryRow = Tuple[
    bytes, str, Tuple[str, ...], Tuple[Tuple[str, int, int], ...],
    int, int, int, int, int, Tuple[Tuple[int, int], ...], int, str,
]
_SettlementRow = Tuple[bytes, bytes, int, int, int]


class PayoutRuleBook:
    """Payout rules, their per-period paid totals, and their settlements.

    Composed as a field of ConsensusLifecycleManager in the wiring slice, so
    the meta hash picks the book root up without a call site to forget (the
    RetractableBook pattern). Entries and settlements are frozen, so copies
    share them; only the period-total maps are duplicated.
    """

    def __init__(self) -> None:
        self._entries: Dict[str, PayoutRuleEntry] = {}
        self._by_id: Dict[bytes, str] = {}
        self._period_totals: Dict[bytes, Dict[int, int]] = {}
        self._settlements: Dict[Tuple[bytes, bytes], PayoutSettlement] = {}
        self._root: Optional[bytes] = None

    # -- copying / restoring ---------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PayoutRuleBook":
        clone = PayoutRuleBook.__new__(PayoutRuleBook)
        clone._entries = dict(self._entries)
        clone._by_id = dict(self._by_id)
        clone._period_totals = {
            k: dict(v) for k, v in self._period_totals.items()
        }
        clone._settlements = dict(self._settlements)
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls,
        rows: Iterable[_EntryRow],
        settlements: Iterable[_SettlementRow] = (),
    ) -> "PayoutRuleBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute."""
        book = cls()
        for row in rows:
            (rule_id, owner, recipients, legs, max_exec, max_period,
             period_seconds, anchor, version, period_totals,
             form, clause_text) = row
            entry = PayoutRuleEntry(
                owner,
                tuple(recipients),
                tuple(PayoutLeg(r, m, v) for r, m, v in legs),
                max_exec, max_period, period_seconds, anchor, version,
                form, clause_text,
            )
            if entry.rule_id != bytes(rule_id):
                raise ValueError(
                    f"stored payout rule id does not match its fields: {entry.rule_id.hex()}"
                )
            if owner in book._entries:
                raise ValueError(f"duplicate stored payout rule for owner: {owner}")
            totals: Dict[int, int] = {}
            for index, total in period_totals:
                if index in totals:
                    raise ValueError("duplicate stored period total")
                if total < 0:
                    raise ValueError("stored period total is negative")
                totals[int(index)] = int(total)
            book._entries[owner] = entry
            book._by_id[entry.rule_id] = owner
            book._period_totals[entry.rule_id] = totals
        for rule_id, settlement_id, base, total, exec_ts in settlements:
            record = PayoutSettlement(
                bytes(rule_id), bytes(settlement_id), base, total, exec_ts
            )
            key = (record.rule_id, record.settlement_id)
            if key in book._settlements:
                raise ValueError("duplicate stored payout settlement")
            book._settlements[key] = record
        return book

    def rows(self) -> List[_EntryRow]:
        out: List[_EntryRow] = []
        for entry in self._entries.values():
            totals = self._period_totals.get(entry.rule_id, {})
            out.append(
                (
                    entry.rule_id,
                    entry.owner_pubkey,
                    entry.recipients,
                    tuple(
                        (leg.recipient_pubkey, leg.mode, leg.value)
                        for leg in entry.legs
                    ),
                    entry.max_per_execution,
                    entry.max_per_period,
                    entry.period_seconds,
                    entry.period_anchor_ts,
                    entry.version,
                    tuple(sorted(totals.items())),
                    entry.form,
                    entry.clause_text,
                )
            )
        return out

    def settlement_rows(self) -> List[_SettlementRow]:
        return [
            (s.rule_id, s.settlement_id, s.base_amount, s.total, s.execution_ts)
            for s in self._settlements.values()
        ]

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_payout_rule_book_root(
                self.rows(), self.settlement_rows()
            )
        return self._root

    # -- queries -----------------------------------------------------------------

    def get(self, owner_pubkey: str) -> Optional[PayoutRuleEntry]:
        return self._entries.get(owner_pubkey)

    def get_by_id(self, rule_id: bytes) -> Optional[PayoutRuleEntry]:
        owner = self._by_id.get(bytes(rule_id))
        return self._entries.get(owner) if owner is not None else None

    def rule_count(self) -> int:
        return len(self._entries)

    def is_empty(self) -> bool:
        """True while no rule and no settlement exists.

        Settlements are rooted with the entries and outlive their rule
        versions, so a book that has ever settled is never empty again —
        that is what the meta-hash gate in governance keys off.
        """
        return not self._entries and not self._settlements

    def _entry(self, rule_id: bytes) -> PayoutRuleEntry:
        entry = self.get_by_id(rule_id)
        if entry is None:
            raise ValueError(f"no payout rule with id {bytes(rule_id).hex()}")
        return entry

    def is_settled(self, rule_id: bytes, settlement_id: bytes) -> bool:
        return (bytes(rule_id), bytes(settlement_id)) in self._settlements

    def settlement(
        self, rule_id: bytes, settlement_id: bytes
    ) -> Optional[PayoutSettlement]:
        return self._settlements.get((bytes(rule_id), bytes(settlement_id)))

    def settlements_for(self, rule_id: bytes) -> List[PayoutSettlement]:
        rule_id = bytes(rule_id)
        return sorted(
            (s for (rid, _), s in self._settlements.items() if rid == rule_id),
            key=lambda s: s.settlement_id,
        )

    def period_total(self, rule_id: bytes, period_index: int) -> int:
        return self._period_totals.get(bytes(rule_id), {}).get(period_index, 0)

    def period_paid_total(self, entry: PayoutRuleEntry, ts: int) -> int:
        """What `entry` has already paid in the period containing `ts`.

        The value payout_clause_inputs feeds at i26: the book's recorded
        total for that period, 0 before the first period. One definition
        for admission and apply, so the clause sees the same paid total
        at both sites (each site's own book state, as with the balance).
        """
        period = period_index_at(entry, ts)
        if period < 0:
            return 0
        return self.period_total(entry.rule_id, period)

    # -- installation / removal ----------------------------------------------------

    def can_install(
        self, entry: PayoutRuleEntry, now_ts: int
    ) -> Tuple[bool, str]:
        problem = validate_payout_rule_shape(entry, now_ts)
        if problem is not None:
            return False, problem
        if entry.rule_id in self._by_id:
            return False, "this payout rule already exists"
        existing = self._entries.get(entry.owner_pubkey)
        if existing is not None:
            if entry.version != existing.version + 1:
                return (
                    False,
                    "a replacement must be the next version "
                    f"({existing.version + 1}), got {entry.version}",
                )
        elif entry.version != 1:
            return False, "a first payout rule must be version 1"
        return True, ""

    def install(self, entry: PayoutRuleEntry, now_ts: int) -> bytes:
        """Install a rule; a new version supersedes the old one wholesale.

        The old version can no longer execute, but what it paid in its
        current period carries into the new version's first period
        (FIX 5C, cb8c42d parity): a replacement never gives a period its
        cap again, and neither does a chain of them through a lower cap.
        The carry is read on the old rule's clock at the replacing block
        and lands in the new rule's period containing that block (its
        first period when the anchor is the install time); when the
        anchors put the two periods apart — the old period already ended
        before the new rule's first period starts — nothing carries.
        Settlements stay recorded — history is not rewritten, and
        reinstalling the old version later cannot re-pay them.
        """
        ok, reason = self.can_install(entry, now_ts)
        if not ok:
            raise ValueError(reason)
        old = self._entries.get(entry.owner_pubkey)
        carried = 0
        if old is not None:
            old_period = period_index_at(old, now_ts)
            if old_period >= 0:
                carried = self.period_total(old.rule_id, old_period)
        if old is not None:
            del self._by_id[old.rule_id]
            self._period_totals.pop(old.rule_id, None)
        self._entries[entry.owner_pubkey] = entry
        self._by_id[entry.rule_id] = entry.owner_pubkey
        totals: Dict[int, int] = {}
        if carried:
            first = period_index_at(entry, now_ts)
            if first < 0:
                first = 0
            # The carry belongs to the new rule's first period only while
            # the two periods overlap in time: the old period's window
            # must reach the new period's window, else the old period
            # already ended before the new rule's first period starts.
            old_start = old.period_anchor_ts + old_period * old.period_seconds
            old_end = old_start + old.period_seconds
            new_start = entry.period_anchor_ts + first * entry.period_seconds
            new_end = new_start + entry.period_seconds
            if old_start < new_end and new_start < old_end:
                totals[first] = carried
        self._period_totals[entry.rule_id] = totals
        self._root = None
        return entry.rule_id

    def can_remove(self, owner_pubkey: str, now_ts: int) -> Tuple[bool, str]:
        if owner_pubkey not in self._entries:
            return False, "no payout rule installed for this account"
        return True, ""

    def remove(self, owner_pubkey: str, now_ts: int) -> PayoutRuleEntry:
        """Remove the owner's rule. Its settlements stay recorded."""
        ok, reason = self.can_remove(owner_pubkey, now_ts)
        if not ok:
            raise ValueError(reason)
        entry = self._entries.pop(owner_pubkey)
        del self._by_id[entry.rule_id]
        self._period_totals.pop(entry.rule_id, None)
        self._root = None
        return entry

    # -- execution -------------------------------------------------------------------

    def _evaluate(
        self,
        entry: PayoutRuleEntry,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
    ) -> PayoutDecision:
        """Pure evaluation: the decision an execution would produce.

        `clause_legs` is the Tau form's leg source: the legs the caller
        decoded from stepping the entry's clause (the book never steps a
        clause itself). A Tau-form entry evaluated without them refuses —
        there is no second way to compute its legs. A declared-form entry
        never consults the parameter; its legs come from compute_legs.
        Every check below the leg computation is shared by both forms.
        """

        def refuse(reason: str, period_index: int = -1) -> PayoutDecision:
            current = period_index_at(entry, ts) if period_index < 0 else period_index
            return PayoutDecision(
                False, reason, (), 0, max(current, 0),
                self.period_total(entry.rule_id, current) if current >= 0 else 0,
            )

        if not 1 <= base_amount <= tau_defs.MAX_TRANSFER_VALUE:
            return refuse("payout_base_amount must be in 1..MAX_TRANSFER_VALUE")
        if self.is_settled(entry.rule_id, settlement_id):
            return refuse(
                "this settlement is already recorded: the execution has paid, once"
            )
        period = period_index_at(entry, ts)
        if period < 0:
            return refuse("the execution precedes the rule's first period")
        if entry.form == FORM_TAU_RULE:
            if clause_legs is None:
                return refuse("the rule's clause was not evaluated", period)
            legs = tuple(clause_legs)
        else:
            legs = compute_legs(entry, base_amount)
        if not legs:
            return refuse("the rule computes no payment for these inputs", period)
        declared = set(entry.recipients)
        if any(recipient not in declared for recipient, _ in legs):
            return refuse("a computed leg pays an undeclared recipient", period)
        total = sum(amount for _, amount in legs)
        if entry.max_per_execution and total > entry.max_per_execution:
            return refuse(
                f"the computed total {total} exceeds the rule's declared "
                f"max per execution {entry.max_per_execution}",
                period,
            )
        paid_this_period = self.period_total(entry.rule_id, period)
        if entry.max_per_period and paid_this_period + total > entry.max_per_period:
            return refuse(
                f"the computed total {total} would push this period's paid "
                f"total past the rule's declared max per period "
                f"{entry.max_per_period}",
                period,
            )
        if total > owner_balance:
            return refuse(
                "insufficient funds: the execution settles nothing", period
            )
        return PayoutDecision(
            True, "executed", legs, total, period, paid_this_period + total
        )

    def evaluate_execution(
        self,
        rule_id: bytes,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
    ) -> PayoutDecision:
        """What an execution would do, without doing it."""
        entry = self._entry(rule_id)
        return self._evaluate(
            entry, bytes(settlement_id), base_amount, ts, owner_balance,
            clause_legs,
        )

    def execute(
        self,
        rule_id: bytes,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
    ) -> PayoutDecision:
        """Settle an execution, or settle nothing.

        On success the settlement is recorded under its settlement id and
        the period total advances by the computed total — the two writes
        that make a repeat execution of the same settlement a no-op. A
        refused execution changes no state.
        """
        entry = self._entry(rule_id)
        settlement_id = bytes(settlement_id)
        decision = self._evaluate(
            entry, settlement_id, base_amount, ts, owner_balance, clause_legs
        )
        if not decision.executed:
            return decision
        self._settlements[(entry.rule_id, settlement_id)] = PayoutSettlement(
            rule_id=entry.rule_id,
            settlement_id=settlement_id,
            base_amount=base_amount,
            total=decision.total,
            execution_ts=ts,
        )
        totals = self._period_totals.setdefault(entry.rule_id, {})
        totals[decision.period_index] = (
            totals.get(decision.period_index, 0) + decision.total
        )
        self._root = None
        return decision


# --- Capability reporting -------------------------------------------------------


def payout_rule_capabilities() -> Dict[str, Any]:
    """The payout-rule semantics a capability endpoint reports (#63).

    Built from the module's own values so the report can never drift from
    the code: if a bound changes, this record changes with it. (Support,
    leg modes, caps and settlement semantics, stated before send — the
    consensus-level record an endpoint serves, there being no
    capability-endpoint infrastructure in the codebase yet.)
    """
    return {
        "supported": True,
        "forms": {
            "declared_program": FORM_DECLARED_PROGRAM,
            "tau_rule": FORM_TAU_RULE,
        },
        "leg_modes": {"fixed": LEG_FIXED, "bps_of_base": LEG_BPS_OF_BASE},
        "rounding": "floor on basis-point legs",
        "tau_rule": {
            "inputs": {
                "i1": "the execution's base amount",
                "i2": "the rule owner's balance",
                "i3": "the rule owner's pubkey",
                "i4": "the execution submitter's pubkey",
                "i5": "the block timestamp",
                tau_defs.TAU_INPUT_STREAM_PAYOUT_PERIOD_PAID: (
                    "what this rule already paid in the current period"
                ),
            },
            "outputs": {
                f"o{PAYOUT_OUTPUT_COUNT_STREAM}": "the leg count",
                "pairs": (
                    f"from o{PAYOUT_OUTPUT_FIRST_STREAM}: per leg, a "
                    "recipient candidate index (0-based into the declared "
                    "recipient set) and an amount"
                ),
            },
            "max_clause_bytes": MAX_PAYOUT_CLAUSE_BYTES,
        },
        "caps": (
            "declared per execution and per period; 0 leaves that "
            "dimension uncapped"
        ),
        "settlement": (
            "recorded by settlement id; a settled execution never pays twice"
        ),
        "credit_class": "payout_leg",
        "fee": "the submitter pays the ordinary fee",
        "max_recipients": MAX_RECIPIENTS,
        "max_legs": MAX_LEGS,
    }
