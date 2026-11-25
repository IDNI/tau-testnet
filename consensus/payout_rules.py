"""Payout rules: rule-computed payouts under declared caps (#63).

An owner installs payout rules — up to MAX_RULES_PER_OWNER of them
(FIX 7, multi-rule), each addressed by its signed slot (`rule_index`,
0..7) and each fully independent: its own declared recipient set, declared
caps (a maximum per execution and a maximum per period), period anchor,
and ONE of two forms for computing the legs of an execution:

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
- Shared cap (FIX 8): a rule may additionally name a shared cap —
  `shared_cap_id` + `shared_cap_amount`, both signed fields inside the
  rule id. Every rule of the SAME owner naming the same id draws on one
  limit: the sum of what all of them have paid in their current periods
  (at the execution's timestamp, each on its own period clock) plus the
  execution's total may not exceed the shared amount the EXECUTING rule
  declares. The per-rule caps still bind first — the shared cap is a
  third ceiling, never a way around the other two, and it never crosses
  owners. Usage is counted from CURRENT book membership and CURRENT
  period totals only: a rule that leaves the book (removal, expiry of
  its period, supersession by a non-member) stops counting, and a
  superseding member inherits the slot's paid total through the FIX 5C
  carry, so replacement cannot launder usage out of the group either.
  An execution the shared cap refuses settles nothing, exactly like the
  other caps — no partial leg, no settlement, no debt.
- Period origin: by default the grid counts from the rule's recorded
  anchor — in practice the install moment, so "500 a week from
  1 December" counts its weeks from whenever the rule happened to be
  installed. An entry may instead carry a signed `periods_from` anchor
  (a fixed start date, e.g. 1 December): when it is set, EVERY period
  computation — the per-period cap totals and the i26 paid-total feed
  alike — counts from that date, and the install moment only decides
  from when the rule exists. The anchor is optional and additive: an
  entry without it is byte-identical to before (same rule id, same
  stored row, same book root), and an entry with it hashes the anchor
  into its rule id under its own domain, so the two spellings of the
  same terms are different rules with different period grids.
- An execution that cannot settle settles NOTHING: no leg moves, no
  settlement is recorded, no period total advances — the same discipline
  as a standing payment's insufficient-funds occurrence, so a retry with
  valid inputs is a well-defined, explicit operation.
- Legs settle with the payout-leg credit class (the design's credit-class
  table): a payout credit never triggers a receive route, another payout,
  or a standing payment.
- FIX 1-B (recorded-receipt base): a rule may declare its base source as
  the node's own record of an incoming transfer instead of the amount an
  execution submits. When an ordinary (or claimed-payment) credit lands
  on the account of an owner whose rule is receipt-based, the node
  records a receipt in this book — sender, recipient, gross amount,
  timestamp, under an id derived from the containing transaction — at
  the post-settlement site, so a fee-rejected transfer records nothing.
  An execution of a receipt-based rule names a receipt id; the node
  fills the base from the recorded amount and the submitted
  `payout_base_amount` is ignored entirely, so no executor can inflate
  the base a royalty computes over. A receipt funds exactly one
  execution: settling consumes it, and a second execution naming it
  settles nothing. Receipts are rooted with the book and survive rule
  removal and replacement, like settlements. The base resolution lives
  in this book's evaluation — the one point both leg forms draw from:
  the declared form's `compute_legs` here, and the Tau clause form's
  input map (its i1 is the base the engine hands this book) on the
  clause lineage, which must be fed the resolved base from here.
- The deciding-rule form (FIX 10, stage 2): a third form,
  FORM_TAU_DECIDING_RULE. A Tau-form clause computed the legs and the
  book decided whether they ran; a deciding rule is stepped over the
  stage-1 map PLUS the book's derived facts (payout_rule_inputs: its
  period, its signed caps, the shared cap's usage and room — headroom
  no stage-1 clause could see) and reports a VERDICT (o29: 1 executes,
  anything else declines) alongside its legs. The clause decides; the
  book enforces, through the same checks in the same order as every
  other form. No verdict, no payment. The form is inside its own id
  domain, so a stage-1 clause and a stage-2 deciding rule over one
  clause text are different rules.
- FIX 1-B (recorded-receipt base): a rule may declare its base source as
  the node's own record of an incoming transfer instead of the amount an
  execution submits. When an ordinary (or claimed-payment) credit lands
  on the account of an owner whose rule is receipt-based, the node
  records a receipt in this book — sender, recipient, gross amount,
  timestamp, under an id derived from the containing transaction — at
  the post-settlement site, so a fee-rejected transfer records nothing.
  An execution of a receipt-based rule names a receipt id; the node
  fills the base from the recorded amount and the submitted
  `payout_base_amount` is ignored entirely, so no executor can inflate
  the base a royalty computes over. A receipt funds exactly one
  execution: settling consumes it, and a second execution naming it
  settles nothing. Receipts are rooted with the book and survive rule
  removal and replacement, like settlements. The base resolution lives
  in this book's evaluation — the one point both leg forms draw from:
  the declared form's `compute_legs` here, and the Tau clause form's
  input map (its i1 is the base the engine hands this book) on the
  clause lineage, which must be fed the resolved base from here. A
  deciding-form rule (FIX 10) is clause-based too: its clause is
  stepped over the resolved base, and its verdict is read from o29
  alongside the legs.
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
    compute_payout_receipt_id,
    compute_payout_rule_book_root,
    compute_payout_rule_deciding_id,
    compute_payout_rule_id,
    compute_payout_rule_periods_from_id,
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
# FIX 10: the stage-2 deciding-rule form — the clause, stepped over the
# book's derived facts (its period, its caps' headroom, the shared
# cap's usage and room), reports the execute/decline verdict itself
# (o29); the book enforces the declared set, both caps, the shared cap
# and the balance, exactly as for the other forms.
FORM_TAU_DECIDING_RULE = 3
PAYOUT_FORMS = frozenset(
    {FORM_DECLARED_PROGRAM, FORM_TAU_RULE, FORM_TAU_DECIDING_RULE}
)

# The Tau form's clause text bound, in UTF-8 bytes — the same bound the
# rule-offer path puts on rule text (consensus/rule_offers
# MAX_OFFER_RULE_BYTES), so a payout clause is no larger than a rule the
# node already carries.
MAX_PAYOUT_CLAUSE_BYTES = 8192

# The Tau form's output encoding: o30 carries the leg count, then each leg
# is a (recipient candidate index, amount) pair on consecutive streams.
PAYOUT_OUTPUT_COUNT_STREAM = 30
PAYOUT_OUTPUT_FIRST_STREAM = 31

# Base sources (FIX 1-B). Where the base a rule's basis-point legs
# compute over comes from: the amount an execution submits (the legacy
# source), or the node's own recorded receipt of an incoming transfer
# (the execution names the receipt; the node fills the amount).
BASE_SUBMITTED = 0
BASE_RECORDED_RECEIPT = 1
BASE_SOURCES = frozenset({BASE_SUBMITTED, BASE_RECORDED_RECEIPT})

# FIX 10: the deciding form's verdict stream, below the shared leg
# encoding: o29 is 1 when the rule executes, and anything else — or an
# absent or unreadable value — when it declines.
PAYOUT_VERDICT_STREAM = 29

# Base sources (FIX 1-B). Where the base a rule's basis-point legs
# compute over comes from: the amount an execution submits (the legacy
# source), or the node's own recorded receipt of an incoming transfer
# (the execution names the receipt; the node fills the amount).
BASE_SUBMITTED = 0
BASE_RECORDED_RECEIPT = 1
BASE_SOURCES = frozenset({BASE_SUBMITTED, BASE_RECORDED_RECEIPT})

# Bounded state: at most MAX_RULES_PER_OWNER rules per owner (FIX 7), and
# each rule itself is small. The slot bound is what makes "a ninth rule"
# unaddressable: slots are 0..MAX_RULES_PER_OWNER-1, and a slot outside
# that range is a shape error everywhere (parse, book, payload).
MAX_RULES_PER_OWNER = 8
MAX_RECIPIENTS = 32
MAX_LEGS = 32
MAX_PERIOD_SECONDS = 366 * SECONDS_PER_DAY

# The shared cap's name (FIX 8): a short owner-chosen identifier. Rules of
# one owner that carry the same id share one period limit; the id is a
# signed field of each rule, so group membership is never something a
# proposer can rewrite. Bounded and charset-pinned so the canonical
# encodings (rule id, book record, payload body) stay unambiguous.
MAX_SHARED_CAP_ID_CHARS = 32
_SHARED_CAP_ID_RE = re.compile(r"^[0-9a-z_-]+$")

# A periods_from anchor further than this from the install moment, in
# either direction, is a mistake, not a schedule: the module's own
# longest period. A fixed start a year out (or a grid that began a year
# ago) is the extreme a considered choice ever needs.
MAX_PERIODS_FROM_SKEW_SECONDS = MAX_PERIOD_SECONDS

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
    entry constructed now — is byte-identical to what it was. `rule_index`
    (FIX 7) defaults to slot 0 the same way: every entry constructed before
    multi-rule is the owner's slot-0 rule, exactly what it was.
    `shared_cap_id` / `shared_cap_amount` (FIX 8) default to no shared cap
    the same way: an entry that names none behaves exactly as before.
    `periods_from_ts` follows the same discipline: 0 (the default) means
    the entry carries no periods_from anchor and is byte-identical to
    before the field existed — same rule id, same stored row; a nonzero
    value is the signed fixed start the period grid counts from, and it
    is inside the rule id under its own domain. `base_source` (FIX 1-B)
    follows it too: 0 (submitted, the default) means the execution's
    submitted base, exactly as before; 1 (recorded receipt) means the
    base is the node's own recorded receipt, and it is inside the rule
    id only when set.
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
    rule_index: int = 0
    shared_cap_id: str = ""
    shared_cap_amount: int = 0
    periods_from_ts: int = 0
    base_source: int = BASE_SUBMITTED

    @property
    def rule_id(self) -> bytes:
        if self.periods_from_ts:
            return compute_payout_rule_periods_from_id(
                self.owner_pubkey,
                self.recipients,
                tuple(
                    (leg.recipient_pubkey, leg.mode, leg.value)
                    for leg in self.legs
                ),
                self.clause_text,
                self.form,
                self.max_per_execution,
                self.max_per_period,
                self.period_seconds,
                self.period_anchor_ts,
                self.periods_from_ts,
                self.version,
                self.rule_index,
                self.shared_cap_id,
                self.shared_cap_amount,
                self.base_source,
            )
        if self.form == FORM_TAU_DECIDING_RULE:
            return compute_payout_rule_deciding_id(
                self.owner_pubkey,
                self.recipients,
                self.clause_text,
                self.max_per_execution,
                self.max_per_period,
                self.period_seconds,
                self.period_anchor_ts,
                self.version,
                self.rule_index,
                self.shared_cap_id,
                self.shared_cap_amount,
                self.base_source,
            )
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
                self.rule_index,
                self.shared_cap_id,
                self.shared_cap_amount,
                self.base_source,
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
            self.rule_index,
            self.shared_cap_id,
            self.shared_cap_amount,
            self.base_source,
        )


@dataclass(frozen=True)
class PayoutSettlement:
    """The record of one settled execution. History: never rewritten."""

    rule_id: bytes
    settlement_id: bytes
    base_amount: int
    total: int
    execution_ts: int
    receipt_id: bytes = b""


@dataclass(frozen=True)
class PayoutReceipt:
    """The node's record of one incoming transfer (FIX 1-B).

    Recorded when an ordinary or claimed-payment credit lands on the
    account of an owner whose payout rule is receipt-based: the gross
    amount that actually arrived, who sent it, and when. An execution
    names a receipt by id and the node — never the submitter — fills
    the execution's base from `amount`.
    """

    receipt_id: bytes
    recipient_pubkey: str
    sender_pubkey: str
    amount: int
    recorded_ts: int


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


def period_origin(entry: PayoutRuleEntry) -> int:
    """Where the entry's period grid starts counting from.

    The signed periods_from anchor when the entry carries one; otherwise
    the recorded anchor (in practice the install moment). ONE definition:
    the per-period cap totals, the i26 paid-total feed and every other
    period answer derive from period_index_at, so the two spellings of a
    rule can never disagree about which period a timestamp lands in.
    """
    return entry.periods_from_ts or entry.period_anchor_ts


def period_index_at(entry: PayoutRuleEntry, ts: int) -> int:
    """Which period contains `ts`; -1 before the period origin."""
    origin = period_origin(entry)
    if ts < origin:
        return -1
    return (ts - origin) // entry.period_seconds


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


def payout_rule_inputs(
    entry: PayoutRuleEntry,
    executor_pubkey: str,
    base_amount: int,
    ts: int,
    owner_balance: int,
    period_paid_total: int,
    shared_cap_usage: int,
) -> Dict[int, Any]:
    """The input map a deciding rule is stepped over (FIX 10).

    The Tau form's map (i1..i5, i26) verbatim, plus the book's derived
    facts on fresh streams — the headroom a stage-1 clause could not
    see at all:

    - i27: the period index containing `ts`, + 1 (0 before the first)
    - i28: the rule's signed max per period (0 = uncapped)
    - i29: the rule's signed shared cap amount (0 = no shared cap)
    - i30: what the shared-cap group has already paid this period,
      from the book's recorded totals (0 when there is no shared cap)
    - i31: the rule's signed max per execution (0 = uncapped)
    - i32: the shared cap's room left this period (0 when there is
      no shared cap)

    ONE definition, called by the engine at apply and by admission at
    the tip through the book (clause_inputs_for), so the construction
    cannot drift between them. Nothing in the map comes from the
    execution transaction beyond the base amount, exactly as in the
    Tau form.
    """
    inputs = payout_clause_inputs(
        entry, executor_pubkey, base_amount, ts, owner_balance,
        period_paid_total,
    )
    period = period_index_at(entry, ts)
    inputs[27] = str(int(period) + 1)
    inputs[28] = str(int(entry.max_per_period))
    inputs[29] = str(int(entry.shared_cap_amount))
    inputs[30] = str(int(shared_cap_usage))
    inputs[31] = str(int(entry.max_per_execution))
    inputs[32] = (
        str(max(0, int(entry.shared_cap_amount) - int(shared_cap_usage)))
        if entry.shared_cap_id
        else "0"
    )
    return inputs


def decode_rule_outputs(
    entry: PayoutRuleEntry, outputs: Dict[str, Any]
) -> Tuple[Optional[int], Optional[Tuple[Tuple[str, int], ...]], str]:
    """A deciding rule's step, decoded: (verdict, legs, why).

    The verdict (o29) is the clause's decision; the legs ride the
    shared encoding (o30/o31+), decoded by the same reader the Tau
    form uses. A missing or unreadable verdict reads as None — the
    book refuses an execution the rule never decided.
    """
    verdict = _parse_output_value(outputs.get(f"o{PAYOUT_VERDICT_STREAM}"))
    legs, why = decode_clause_legs(entry, outputs)
    return verdict, legs, why


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
            "payout_form must be 1 (declared program), 2 (Tau rule) "
            "or 3 (Tau deciding rule)"
        )
    return value


def _clause_field(tx: Dict[str, Any]) -> str:
    value = tx.get("payout_clause", "")
    if not isinstance(value, str):
        raise PayoutRuleShapeError("payout_clause must be a string")
    return value


def _shared_cap_id_field(tx: Dict[str, Any]) -> str:
    value = tx.get("payout_shared_cap_id", "")
    if not isinstance(value, str):
        raise PayoutRuleShapeError("payout_shared_cap_id must be a string")
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
    if form in (FORM_TAU_RULE, FORM_TAU_DECIDING_RULE):
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
                "payout_clause is only for the Tau forms (payout_form 2 or 3)"
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
        rule_index=_u64_field(tx, "payout_rule_index", default=0),
        shared_cap_id=_shared_cap_id_field(tx),
        shared_cap_amount=_u64_field(tx, "payout_shared_cap_amount", default=0),
        periods_from_ts=_u64_field(tx, "payout_periods_from_ts"),
        base_source=_u64_field(tx, "payout_base_source", default=0),
    )


def parse_remove_payout_rule(tx: Dict[str, Any]) -> Tuple[str, int]:
    """Read a removal from ROOT fields only: (owner pubkey, rule slot).

    The slot is a signed root field (FIX 7): a removal names exactly one
    of the owner's rules, and the signature covers the slot, so no
    proposer can redirect a removal to a different rule of the same
    owner. A removal without the field names slot 0 — the only rule a
    pre-multi-rule removal could have meant.
    """
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    return (
        _pubkey_field(tx, "sender_pubkey"),
        _u64_field(tx, "payout_rule_index", default=0),
    )


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


def parse_execute_payout_receipt_id(tx: Dict[str, Any]) -> Optional[bytes]:
    """The receipt an execution names (FIX 1-B), or None when it names none.

    A present-but-malformed field is a shape error, not an absence: an
    executor who names a receipt must name it exactly, or the execution
    is not the one they signed.
    """
    if not isinstance(tx, dict):
        raise PayoutRuleShapeError("transaction must be an object")
    if "payout_receipt_id" not in tx or tx.get("payout_receipt_id") is None:
        return None
    return _id_field(tx, "payout_receipt_id")


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
    if entry.form in (FORM_TAU_RULE, FORM_TAU_DECIDING_RULE):
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
    if entry.periods_from_ts:
        # A fixed start date is a considered choice near the install:
        # the official shape is days or weeks away (install in late
        # November, periods from 1 December; or a mid-period install
        # whose grid began earlier in the month). An anchor a full
        # longest-period away in either direction is a mistake.
        if not (
            now_ts - MAX_PERIODS_FROM_SKEW_SECONDS
            <= entry.periods_from_ts
            <= now_ts + MAX_PERIODS_FROM_SKEW_SECONDS
        ):
            return (
                "payout_periods_from_ts must lie within "
                f"{MAX_PERIODS_FROM_SKEW_SECONDS} seconds of the "
                "installation time"
            )
    if entry.version < 1:
        return "payout_version must start at 1"
    if not 0 <= entry.rule_index < MAX_RULES_PER_OWNER:
        return (
            f"payout_rule_index must be in 0..{MAX_RULES_PER_OWNER - 1}: "
            f"an account holds at most {MAX_RULES_PER_OWNER} payout rules"
        )
    if entry.shared_cap_id:
        if (
            len(entry.shared_cap_id) > MAX_SHARED_CAP_ID_CHARS
            or not _SHARED_CAP_ID_RE.match(entry.shared_cap_id)
        ):
            return (
                "payout_shared_cap_id must be 1.."
                f"{MAX_SHARED_CAP_ID_CHARS} characters of [0-9a-z_-]"
            )
        if not 1 <= entry.shared_cap_amount <= tau_defs.MAX_TRANSFER_VALUE:
            return (
                "payout_shared_cap_amount must be in "
                "1..MAX_TRANSFER_VALUE when a shared cap is named"
            )
    elif entry.shared_cap_amount:
        return (
            "payout_shared_cap_amount without a payout_shared_cap_id "
            "names no shared cap"
        )
    if entry.base_source not in BASE_SOURCES:
        return "payout_base_source must be 0 (submitted) or 1 (recorded receipt)"
    if entry.base_source == BASE_RECORDED_RECEIPT and not any(
        leg.mode == LEG_BPS_OF_BASE for leg in entry.legs
    ):
        return (
            "a receipt-based rule must declare a basis-point leg: the "
            "recorded receipt is the base those legs compute over"
        )
    return None


# --- The book ------------------------------------------------------------------

# A stored entry row. Rows written before periods_from existed carry the
# first twelve fields exactly; a row for an entry WITH a periods_from
# anchor appends it as a thirteenth. restore() accepts both shapes, and
# rows() emits the twelfth-field shape whenever the anchor is unset, so
# an existing book's stored rows never change under it.
_EntryRow = Tuple[
    bytes, str, Tuple[str, ...], Tuple[Tuple[str, int, int], ...],
    int, int, int, int, int, Tuple[Tuple[int, int], ...], int, str, int,
    str, int, int, int,
]
_SettlementRow = Tuple[bytes, bytes, int, int, int, bytes]
_ReceiptRow = Tuple[bytes, str, str, int, int]


class PayoutRuleBook:
    """Payout rules, their per-period paid totals, and their settlements.

    Composed as a field of ConsensusLifecycleManager in the wiring slice, so
    the meta hash picks the book root up without a call site to forget (the
    RetractableBook pattern). Entries and settlements are frozen, so copies
    share them; only the period-total maps are duplicated.

    FIX 7: entries are keyed by (owner, rule_index) — one owner holds up
    to MAX_RULES_PER_OWNER independent rules. Period totals and
    settlements stay keyed by rule_id, which already isolates every rule's
    accounting from every other's: no rule can borrow another's period
    allowance, and no replacement carries into a different slot.

    FIX 8: a rule may name a shared cap. The group is not stored anywhere:
    it is derived at evaluation time from the entries the book currently
    holds (same owner, same non-empty shared_cap_id) and their current
    period totals — so membership changes (install, replacement, removal)
    are reflected exactly, with no second ledger to drift.
    """

    def __init__(self) -> None:
        self._entries: Dict[Tuple[str, int], PayoutRuleEntry] = {}
        self._by_id: Dict[bytes, Tuple[str, int]] = {}
        self._period_totals: Dict[bytes, Dict[int, int]] = {}
        self._settlements: Dict[Tuple[bytes, bytes], PayoutSettlement] = {}
        self._receipts: Dict[bytes, PayoutReceipt] = {}
        self._consumed_receipts: set = set()
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
        clone._receipts = dict(self._receipts)
        clone._consumed_receipts = set(self._consumed_receipts)
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(
        cls,
        rows: Iterable[_EntryRow],
        settlements: Iterable = (),
        receipts: Iterable[_ReceiptRow] = (),
    ) -> "PayoutRuleBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute.

        Rows written before FIX 7 carry no slot term and restore as slot
        0; rows written after carry it as the thirteenth element. Rows
        written before FIX 8 carry no shared-cap terms and restore with
        no shared cap; rows written after carry them as the fourteenth
        and fifteenth elements. Rows written before periods_from carry
        no anchor and restore with none; rows written after carry it as
        the sixteenth element, only when set. Entry rows written before
        FIX 1-B carry no base source and settlement rows no receipt id;
        both restore with the legacy defaults, so an older stored book
        rebuilds identically.
        """
        book = cls()
        for row in rows:
            (rule_id, owner, recipients, legs, max_exec, max_period,
             period_seconds, anchor, version, period_totals,
             form, clause_text) = row[:12]
            rule_index = int(row[12]) if len(row) > 12 else 0
            shared_cap_id = str(row[13]) if len(row) > 13 else ""
            shared_cap_amount = int(row[14]) if len(row) > 14 else 0
            periods_from = int(row[15]) if len(row) > 15 else 0
            base_source = int(row[16]) if len(row) > 16 else BASE_SUBMITTED
            entry = PayoutRuleEntry(
                owner,
                tuple(recipients),
                tuple(PayoutLeg(r, m, v) for r, m, v in legs),
                max_exec, max_period, period_seconds, anchor, version,
                form, clause_text, rule_index,
                shared_cap_id, shared_cap_amount, periods_from,
                base_source,
            )
            if entry.rule_id != bytes(rule_id):
                raise ValueError(
                    f"stored payout rule id does not match its fields: {entry.rule_id.hex()}"
                )
            if not 0 <= rule_index < MAX_RULES_PER_OWNER:
                raise ValueError(
                    f"stored payout rule slot out of range: {rule_index}"
                )
            key = (owner, rule_index)
            if key in book._entries:
                raise ValueError(
                    f"duplicate stored payout rule for owner slot: {owner}#{rule_index}"
                )
            totals: Dict[int, int] = {}
            for index, total in period_totals:
                if index in totals:
                    raise ValueError("duplicate stored period total")
                if total < 0:
                    raise ValueError("stored period total is negative")
                totals[int(index)] = int(total)
            book._entries[key] = entry
            book._by_id[entry.rule_id] = key
            book._period_totals[entry.rule_id] = totals
        for row in settlements:
            rule_id, settlement_id, base, total, exec_ts = row[:5]
            receipt_id = bytes(row[5]) if len(row) > 5 else b""
            record = PayoutSettlement(
                bytes(rule_id), bytes(settlement_id), base, total, exec_ts,
                receipt_id,
            )
            key = (record.rule_id, record.settlement_id)
            if key in book._settlements:
                raise ValueError("duplicate stored payout settlement")
            book._settlements[key] = record
            if record.receipt_id:
                book._consumed_receipts.add(record.receipt_id)
        for row in receipts:
            receipt_id, recipient, sender, amount, recorded_ts = row[:5]
            receipt = PayoutReceipt(
                bytes(receipt_id), recipient, sender, int(amount),
                int(recorded_ts),
            )
            if receipt.receipt_id in book._receipts:
                raise ValueError("duplicate stored payout receipt")
            book._receipts[receipt.receipt_id] = receipt
            # A stored row may carry consumption as a sixth element:
            # admission's one-entry rebuild needs it, because the
            # settlement that consumed the receipt may belong to a rule
            # version the rebuilt book does not hold.
            if len(row) > 5 and row[5]:
                book._consumed_receipts.add(receipt.receipt_id)
        return book

    def rows(self) -> List[_EntryRow]:
        out: List[_EntryRow] = []
        for entry in self._entries.values():
            totals = self._period_totals.get(entry.rule_id, {})
            row = (
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
                entry.rule_index,
                entry.shared_cap_id,
                entry.shared_cap_amount,
            )
            if entry.periods_from_ts or entry.base_source:
                # Fixed positions: periods_from is field 16, base_source
                # field 17. A row carries periods_from whenever either is
                # set (0 when only the base source is), so restore() can
                # always read row[16] as the base source.
                row = row + (entry.periods_from_ts,)
                if entry.base_source:
                    row = row + (entry.base_source,)
            out.append(row)
        return out

    def settlement_rows(self) -> List[_SettlementRow]:
        return [
            (s.rule_id, s.settlement_id, s.base_amount, s.total, s.execution_ts,
             s.receipt_id)
            for s in self._settlements.values()
        ]

    def receipt_rows(self) -> List[_ReceiptRow]:
        return [
            (r.receipt_id, r.recipient_pubkey, r.sender_pubkey, r.amount,
             r.recorded_ts)
            for r in self._receipts.values()
        ]

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_payout_rule_book_root(
                self.rows(), self.settlement_rows(), self.receipt_rows()
            )
        return self._root

    # -- queries -----------------------------------------------------------------

    def get(
        self, owner_pubkey: str, rule_index: int = 0
    ) -> Optional[PayoutRuleEntry]:
        """One owner's rule at one slot (slot 0 by default)."""
        return self._entries.get((owner_pubkey, int(rule_index)))

    def get_all(self, owner_pubkey: str) -> List[PayoutRuleEntry]:
        """Every rule one owner holds, in slot order."""
        return [
            entry
            for (owner, _index), entry in sorted(
                self._entries.items(), key=lambda item: item[0][1]
            )
            if owner == owner_pubkey
        ]

    def get_by_id(self, rule_id: bytes) -> Optional[PayoutRuleEntry]:
        key = self._by_id.get(bytes(rule_id))
        return self._entries.get(key) if key is not None else None

    def rule_count(self) -> int:
        return len(self._entries)

    def rule_count_for_owner(self, owner_pubkey: str) -> int:
        return sum(1 for owner, _ in self._entries if owner == owner_pubkey)

    def is_empty(self) -> bool:
        """True while no rule, no settlement and no receipt exists.

        Settlements are rooted with the entries and outlive their rule
        versions, so a book that has ever settled is never empty again —
        that is what the meta-hash gate in governance keys off. Receipts
        (FIX 1-B) outlive their rule the same way, for the same reason:
        a recorded base must stay provable after the rule is gone.
        """
        return not self._entries and not self._settlements and not self._receipts

    # -- receipts (FIX 1-B) ------------------------------------------------------

    def get_receipt(self, receipt_id: bytes) -> Optional[PayoutReceipt]:
        return self._receipts.get(bytes(receipt_id))

    def receipt_consumed(self, receipt_id: bytes) -> bool:
        return bytes(receipt_id) in self._consumed_receipts

    def receipts_for(self, recipient_pubkey: str) -> List[PayoutReceipt]:
        return sorted(
            (r for r in self._receipts.values()
             if r.recipient_pubkey == recipient_pubkey),
            key=lambda r: r.receipt_id,
        )

    def record_receipt(self, receipt: PayoutReceipt) -> bool:
        """Record one incoming transfer. True when newly recorded.

        Called by the engine at the post-settlement site for a credit
        that actually landed. Recording the same receipt twice (the
        same transaction re-presented to the same state) is a no-op;
        a conflicting record under an existing id is a hard error —
        two different transfers must never share a name.
        """
        existing = self._receipts.get(receipt.receipt_id)
        if existing is not None:
            if existing == receipt:
                return False
            raise ValueError(
                f"payout receipt id {receipt.receipt_id.hex()} already "
                "records a different transfer"
            )
        self._receipts[receipt.receipt_id] = receipt
        self._root = None
        return True

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

    def shared_cap_usage(
        self, owner_pubkey: str, shared_cap_id: str, ts: int
    ) -> int:
        """What one shared-cap group has paid in its current periods (FIX 8).

        The sum, over every rule the book CURRENTLY holds for this owner
        naming this (non-empty) shared cap id, of that rule's paid total
        in the period containing `ts` on its own clock. Derived from live
        membership and live period totals — nothing is accumulated
        anywhere else, so a rule leaving the book stops counting at once
        and a replacement counts exactly what the book carried into it.
        """
        if not shared_cap_id:
            return 0
        total = 0
        for entry in self._entries.values():
            if entry.owner_pubkey != owner_pubkey:
                continue
            if entry.shared_cap_id != shared_cap_id:
                continue
            total += self.period_paid_total(entry, ts)
        return total

    def shared_cap_left(
        self, entry: PayoutRuleEntry, ts: int
    ) -> Optional[int]:
        """Room left under `entry`'s shared cap at `ts`; None when it names none.

        Never below 0: usage may stand over a lowered amount (a signed
        mid-period update), and the room is then simply gone — the
        left_this_period discipline of FIX 5C applied to the group.
        """
        if not entry.shared_cap_id:
            return None
        used = self.shared_cap_usage(
            entry.owner_pubkey, entry.shared_cap_id, ts
        )
        return max(0, entry.shared_cap_amount - used)

    # -- installation / removal ----------------------------------------------------

    def can_install(
        self, entry: PayoutRuleEntry, now_ts: int
    ) -> Tuple[bool, str]:
        problem = validate_payout_rule_shape(entry, now_ts)
        if problem is not None:
            return False, problem
        if entry.rule_id in self._by_id:
            return False, "this payout rule already exists"
        # The version chain runs PER SLOT (FIX 7): a rule's replacement is
        # the next version at the same slot, and a first rule at an empty
        # slot is version 1 whatever the owner's other slots hold. The
        # slot bound in the shape check is the per-account bound: with
        # slots 0..MAX_RULES_PER_OWNER-1 the only addresses a rule can
        # take, a ninth rule has no address and is refused there.
        existing = self._entries.get((entry.owner_pubkey, entry.rule_index))
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
        # The carry's source is the replaced rule AT THE SAME SLOT only
        # (FIX 7): what a rule paid in its current period carries into its
        # own replacement — never into a rule at another slot, whose
        # period accounting is its own.
        key = (entry.owner_pubkey, entry.rule_index)
        old = self._entries.get(key)
        carried = 0
        if old is not None:
            old_period = period_index_at(old, now_ts)
            if old_period >= 0:
                carried = self.period_total(old.rule_id, old_period)
        if old is not None:
            del self._by_id[old.rule_id]
            self._period_totals.pop(old.rule_id, None)
        self._entries[key] = entry
        self._by_id[entry.rule_id] = key
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

    def can_remove(
        self, owner_pubkey: str, now_ts: int, rule_index: int = 0
    ) -> Tuple[bool, str]:
        if not 0 <= rule_index < MAX_RULES_PER_OWNER:
            return False, (
                f"payout_rule_index must be in 0..{MAX_RULES_PER_OWNER - 1}"
            )
        if (owner_pubkey, int(rule_index)) not in self._entries:
            return False, "no payout rule installed for this account"
        return True, ""

    def remove(
        self, owner_pubkey: str, now_ts: int, rule_index: int = 0
    ) -> PayoutRuleEntry:
        """Remove the owner's rule at one slot. Its settlements stay recorded,
        and the owner's rules at every other slot are untouched."""
        ok, reason = self.can_remove(owner_pubkey, now_ts, rule_index)
        if not ok:
            raise ValueError(reason)
        entry = self._entries.pop((owner_pubkey, int(rule_index)))
        del self._by_id[entry.rule_id]
        self._period_totals.pop(entry.rule_id, None)
        self._root = None
        return entry

    # -- execution -------------------------------------------------------------------

    def clause_inputs_for(
        self,
        entry: PayoutRuleEntry,
        executor_pubkey: str,
        base_amount: int,
        ts: int,
        owner_balance: int,
    ) -> Dict[int, Any]:
        """The input map for this entry's form, built from this book.

        ONE construction for every caller (engine at apply, admission
        at the tip): the Tau form's map for the Tau form, the facts
        map for the deciding form (FIX 10) — the form selects the map,
        so no caller can step a deciding rule over stage-1 inputs and
        starve it of the headroom facts it decides on.
        """
        period_paid = self.period_paid_total(entry, ts)
        if entry.form == FORM_TAU_DECIDING_RULE:
            usage = (
                self.shared_cap_usage(
                    entry.owner_pubkey, entry.shared_cap_id, ts
                )
                if entry.shared_cap_id
                else 0
            )
            return payout_rule_inputs(
                entry, executor_pubkey, base_amount, ts, owner_balance,
                period_paid, usage,
            )
        return payout_clause_inputs(
            entry, executor_pubkey, base_amount, ts, owner_balance,
            period_paid,
        )

    def _evaluate(
        self,
        entry: PayoutRuleEntry,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
        receipt_id: Optional[bytes] = None,
        clause_verdict: Optional[int] = None,
    ) -> PayoutDecision:
        """Pure evaluation: the decision an execution would produce.

        `clause_legs` is the Tau form's leg source: the legs the caller
        decoded from stepping the entry's clause (the book never steps a
        clause itself). A Tau-form entry evaluated without them refuses —
        there is no second way to compute its legs. A declared-form entry
        never consults the parameter; its legs come from compute_legs.
        Every check below the leg computation is shared by both forms.

        `clause_verdict` is the deciding form's decision (FIX 10),
        decoded from the same step: the rule decides whether, over the
        book's facts; the checks below then enforce — they are the
        same checks, in the same order, as for every other form.
        """

        def refuse(reason: str, period_index: int = -1) -> PayoutDecision:
            current = period_index_at(entry, ts) if period_index < 0 else period_index
            return PayoutDecision(
                False, reason, (), 0, max(current, 0),
                self.period_total(entry.rule_id, current) if current >= 0 else 0,
            )

        # FIX 1-B: resolve the base before anything computes over it.
        # For a receipt-based rule the submitted base amount is ignored
        # entirely — the base is the recorded amount of the receipt the
        # execution names, filled in by the node — so no executor can
        # inflate the base a basis-point leg computes over.
        if entry.base_source == BASE_RECORDED_RECEIPT:
            if receipt_id is None:
                return refuse(
                    "this rule takes its base from a recorded receipt: "
                    "the execution must name payout_receipt_id"
                )
            receipt = self._receipts.get(bytes(receipt_id))
            if receipt is None:
                return refuse("no recorded receipt with the named id")
            if receipt.recipient_pubkey != entry.owner_pubkey:
                return refuse(
                    "the named receipt was not received by the rule's owner"
                )
            if bytes(receipt_id) in self._consumed_receipts:
                return refuse(
                    "this receipt has already funded an execution: "
                    "the royalty pays once"
                )
            base_amount = receipt.amount
        elif receipt_id is not None:
            return refuse(
                "this rule takes its base from the submitted amount: "
                "naming a receipt means nothing for it"
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
        if entry.form == FORM_TAU_DECIDING_RULE:
            if clause_verdict is None:
                return refuse("the rule's clause was not evaluated", period)
            if clause_verdict != 1:
                return refuse("the rule declined to execute", period)
            if clause_legs is None:
                return refuse("the rule's clause was not evaluated", period)
            legs = tuple(clause_legs)
        elif entry.form == FORM_TAU_RULE:
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
        if entry.shared_cap_id:
            # FIX 8: the shared cap is a third ceiling over the whole
            # group — the executing rule's own signed amount, charged
            # with everything the group has already paid this period
            # (this rule's own total included, via the group sum).
            group_paid = self.shared_cap_usage(
                entry.owner_pubkey, entry.shared_cap_id, ts
            )
            if group_paid + total > entry.shared_cap_amount:
                return refuse(
                    f"the computed total {total} would push the shared "
                    f"cap '{entry.shared_cap_id}' past its declared "
                    f"amount {entry.shared_cap_amount} "
                    f"(the group has paid {group_paid} this period)",
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
        receipt_id: Optional[bytes] = None,
        clause_verdict: Optional[int] = None,
    ) -> PayoutDecision:
        """What an execution would do, without doing it."""
        entry = self._entry(rule_id)
        return self._evaluate(
            entry, bytes(settlement_id), base_amount, ts, owner_balance,
            clause_legs, receipt_id, clause_verdict,
        )

    def execute(
        self,
        rule_id: bytes,
        settlement_id: bytes,
        base_amount: int,
        ts: int,
        owner_balance: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
        receipt_id: Optional[bytes] = None,
        clause_verdict: Optional[int] = None,
    ) -> PayoutDecision:
        """Settle an execution, or settle nothing.

        On success the settlement is recorded under its settlement id and
        the period total advances by the computed total — the two writes
        that make a repeat execution of the same settlement a no-op. A
        refused execution changes no state.

        For a receipt-based rule the settlement records the RESOLVED
        base (the receipt's recorded amount, never the submitted one)
        and the receipt it came from, and the receipt is consumed: a
        later execution naming it settles nothing.
        """
        entry = self._entry(rule_id)
        settlement_id = bytes(settlement_id)
        decision = self._evaluate(
            entry, settlement_id, base_amount, ts, owner_balance,
            clause_legs, receipt_id, clause_verdict,
        )
        if not decision.executed:
            return decision
        settled_receipt_id = b""
        settled_base = base_amount
        if entry.base_source == BASE_RECORDED_RECEIPT:
            receipt = self._receipts[bytes(receipt_id)]
            settled_receipt_id = receipt.receipt_id
            settled_base = receipt.amount
        self._settlements[(entry.rule_id, settlement_id)] = PayoutSettlement(
            rule_id=entry.rule_id,
            settlement_id=settlement_id,
            base_amount=settled_base,
            total=decision.total,
            execution_ts=ts,
            receipt_id=settled_receipt_id,
        )
        if settled_receipt_id:
            self._consumed_receipts.add(settled_receipt_id)
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
            "tau_deciding_rule": FORM_TAU_DECIDING_RULE,
        },
        "deciding_rule": {
            "decision": (
                "the clause decides whether an execution runs, over "
                "the book's derived facts; the book enforces the "
                "declared set, both caps, the shared cap and the "
                "balance, and settles nothing without a verdict"
            ),
            "fact_streams": {
                "i27": "the period index containing the timestamp, + 1 "
                       "(0 before the first period)",
                "i28": "the rule's signed max per period (0 = uncapped)",
                "i29": "the rule's signed shared cap amount (0 = no "
                       "shared cap)",
                "i30": "what the shared-cap group has already paid "
                       "this period",
                "i31": "the rule's signed max per execution "
                       "(0 = uncapped)",
                "i32": "the shared cap's room left this period "
                       "(0 when there is no shared cap)",
            },
            "verdict_stream": (
                f"o{PAYOUT_VERDICT_STREAM}: 1 executes; anything else, "
                "or an absent value, declines"
            ),
            "leg_encoding": "the shared o30/o31+ encoding of the Tau form",
        },
        "leg_modes": {"fixed": LEG_FIXED, "bps_of_base": LEG_BPS_OF_BASE},
        "base_sources": {
            "submitted": BASE_SUBMITTED,
            "recorded_receipt": BASE_RECORDED_RECEIPT,
        },
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
        "shared_cap": (
            "a rule may name a shared cap (payout_shared_cap_id + "
            "payout_shared_cap_amount, both signed and inside the rule "
            "id): all of one owner's rules naming the same id draw on "
            "that one amount per period, on top of their own caps; usage "
            "is counted from current book membership and current period "
            "totals, and never crosses owners"
        ),
        "periods_from": (
            "optional signed anchor (payout_periods_from_ts): when set, "
            "periods count from that fixed start instead of the install "
            "anchor; when unset, the grid counts from the recorded "
            "period anchor exactly as before"
        ),
        "settlement": (
            "recorded by settlement id; a settled execution never pays twice"
        ),
        "credit_class": "payout_leg",
        "fee": "the submitter pays the ordinary fee",
        "max_recipients": MAX_RECIPIENTS,
        "max_legs": MAX_LEGS,
        "max_rules_per_owner": MAX_RULES_PER_OWNER,
        "rule_addressing": (
            "each rule is addressed by its signed payout_rule_index slot "
            f"(0..{MAX_RULES_PER_OWNER - 1}); caps, period totals, "
            "settlements and the replacement carry are per rule"
        ),
    }
