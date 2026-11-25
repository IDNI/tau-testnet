"""Payout rules: rule-computed settlements under declared caps (#63).

An owner installs a payout rule: declared caps (maximum per
execution, maximum per period), a declared recipient set, and a
period kind. Anyone may then submit an execution carrying a
settlement id and rule inputs; the node steps the owner's rule (its
accepted clause on the payout stream) with those inputs, and the
rule's outputs name the legs -- a recipient chosen BY INDEX into the
declared set, and an amount. The node -- never the rule -- checks
every leg's recipient is declared, the total is within both caps and
the owner's balance, and applies all legs atomically or none.

Settlement ids make "pays 5, once" a consensus property: an
execution whose settlement id is already recorded settles nothing.
Per-period spend lives in this book, so the period cap binds across
executions and across executors, enforced by the settling node.

Removal follows the account's normal rules: an owner-signed remove
transaction, like a standing cancel. The rule's outputs are read
from the evaluation the same way the codebase reads policy outputs:
leg count on o20, then (amount, recipient index) pairs on
o21/o22 ... o35/o36 -- at most MAX_LEGS legs.

Triggers (Bounty 01 stage 1 in rules form, issues #34/#35): the
signed terms may additionally declare a trigger, so the SAME clause
form covers standing payments and receive routes without a new
execution path in the node.

- Clock (`due`): a standing payment. The terms carry the schedule
  (anchor + period kind, the arithmetic in consensus.periods) and
  exactly ONE end condition -- a final period index, a maximum
  number of firings, or a maximum total paid -- so no authorization
  is open-ended. At the block-end sweep the node steps a due rule's
  clause with a gross of 0 and the zero pubkey as executor (the node
  itself) and settles under the settlement id
  ``clock:<rule_id>:<period_index>``. A period with no block in it
  is skipped, never caught up.
- Arrival (`on_arrival`): a receive route. When an ordinary transfer
  credits the owner's account, the node steps the clause with the
  gross credit on i1 in the same apply and settles under the
  settlement id ``arrival:<crediting tx id>``. Legs paid by any
  payout settlement are payout-class: they never trigger a route,
  so a routed share can never cascade into another route.
  A route settles at most the gross credit -- across all of the
  owner's on-arrival rules, one credit's shares sum to at most the
  credit -- so the legs stay a division of what arrived and never
  a draw on the balance that was already there; a route whose legs
  exceed what is left of the credit settles nothing on it.

Both triggers settle through `check_execution`/`settle` exactly
like a submitted execution: same caps, same period accounting, same
settlement-id idempotency.

Stage 2 (the multi-rule book): the book is keyed by (owner,
rule_id), so one account runs up to MAX_RULES_PER_OWNER concurrent
rules -- a standing payment, a receive route and an escrow split
side by side, each with its own caps, period accounting and
settlement history. On top of the stage-1 book:

- `payout_rule_update` replaces a rule's terms in place. The new
  version keeps the rule's lineage (the superseded rule ids, in
  order) AND its accounting state -- settlement history, current
  period spend, clock totals and firing count, paid total, missed
  periods -- so an update can never resurrect a settled settlement
  id or reset a period cap. New terms are validated against the
  settled history (a period cap below what the current period has
  already spent is refused), and an update may not move the
  schedule (anchor or period kind): the calendar the history was
  recorded against is part of the rule's identity. Guarded accounts
  reach the same update through rule-change kind 6 (see
  consensus.approvals), never through a revoke-and-reinstall that
  would lose the history.
- A rule may be `sealed`: while sealed and unended it cannot be
  replaced, removed or updated, and the owner account's own
  transfers are refused -- the account is locked to the rule's own
  settlements until the rule's end condition ends it.
- A rule may declare `max_fee_per_execution`: a submitted
  execution whose transaction fee would exceed the cap is refused.
  Node-initiated settlements (clock, arrival) are fee-free by
  construction, so the cap binds exactly the executions that pay.
- Clock observability: the sweep settles at most
  MAX_CLOCK_SETTLEMENTS_PER_BLOCK due rules per block,
  earliest-due-first, and every period that closes without a clock
  settlement is counted on the rule as a missed period.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

import re

from consensus import periods
from consensus.serialization import canonical_json
from tau_manager import parse_tau_output as _parse_tau_output

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")


def _well_formed_pubkey(pk: str) -> bool:
    return bool(_PUBKEY_RE.match(pk or ""))


def canonical_json_bytes(data) -> bytes:
    return canonical_json(data)

TX_TYPE_PAYOUT_INSTALL = "payout_rule_install"
TX_TYPE_PAYOUT_EXECUTE = "payout_execute"
TX_TYPE_PAYOUT_REMOVE = "payout_rule_remove"
TX_TYPE_PAYOUT_UPDATE = "payout_rule_update"
PAYOUT_TX_TYPES = frozenset(
    {TX_TYPE_PAYOUT_INSTALL, TX_TYPE_PAYOUT_EXECUTE,
     TX_TYPE_PAYOUT_REMOVE, TX_TYPE_PAYOUT_UPDATE}
)

#: Stream the owner's payout clause is read on, and the leg outputs.
PAYOUT_STREAM_INDEX = 24
LEG_COUNT_STREAM = 20
LEG_STREAMS = (
    (21, 22), (23, 24), (25, 26), (27, 28),
    (29, 30), (31, 32), (33, 34), (35, 36),
)
MAX_LEGS = len(LEG_STREAMS)
MAX_RECIPIENTS = 8
MAX_SETTLEMENTS_KEPT = 512
MAX_PAYOUT_RULES = 4096
#: Stage 2: concurrent rules one account may hold in the book.
MAX_RULES_PER_OWNER = 8
#: Stage 2: due settlements the block-end sweep performs per block;
#: the rest stay due and are stepped by the next block.
MAX_CLOCK_SETTLEMENTS_PER_BLOCK = 16
#: Stage 2: a clock rule's period may not be shorter than this, so
#: due points of one rule are always spaced at least an hour apart
#: (every current period kind is a day or longer; the bound is the
#: validated floor, not a property of the kind list).
MIN_DUE_SPACING_SECONDS = 3600

#: Executor identity for node-initiated settlements (clock and
#: arrival triggers): the zero pubkey, i.e. the node itself.
ZERO_PUBKEY = "00" * 48

#: Clause templates, shipped as configuration examples. The amounts
#: and percentages are the owner's configuration -- edit the
#: constants, keep the shape. Leg streams are bv[24] as in the
#: landed royalty clause; the proportional form follows the repo's
#: own arithmetic probe (tests/test_o9_arithmetic_probe_native.py).
#: A standing payment pays a fixed leg each time its clock fires.
TEMPLATE_STANDING_PAYMENT_CLAUSE = (
    "always (o20[t]:bv[24] = { #x000001 }:bv[24]"
    " && o21[t]:bv[24] = { #x0001f4 }:bv[24]"
    " && o22[t]:bv[24] = { #x000000 }:bv[24])."
)
#: A receive route paying 20% of the gross credit (floor rounding,
#: Tau integer division) to declared recipient index 0; the rest
#: simply stays -- a route forwards only what its legs name.
TEMPLATE_PERCENTAGE_ROUTE_CLAUSE = (
    "always (o20[t]:bv[24] = { #x000001 }:bv[24]"
    " && o21[t]:bv[24] = ((i1[t]:bv[24] * { #x000014 }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o22[t]:bv[24] = { #x000000 }:bv[24])."
)
#: A 5% royalty on the gross input, floored the same way; the
#: settlement id makes it pay once per settlement.
TEMPLATE_ROYALTY_5PCT_CLAUSE = (
    "always (o20[t]:bv[24] = { #x000001 }:bv[24]"
    " && o21[t]:bv[24] = ((i1[t]:bv[24] * { #x000005 }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o22[t]:bv[24] = { #x000000 }:bv[24])."
)
#: The #63 work escrow, as one execution with six legs: of the
#: locked price on i1, the worker takes 50%, each of two reviewers
#: 10%, the defect bounty 10%, the poster takes back a 15%
#: remainder, and 5% is held back as the warranty holdback. Every
#: share is floored by Tau division; on a price divisible by 100
#: the six legs sum to the locked price exactly, and on any other
#: price the unallocated dust (under 6 units) simply stays with
#: the poster -- no leg is ever rounded up. Amounts are bv[24]:
#: keep the locked price under 2^24 / 50.
TEMPLATE_WORK_ESCROW_CLAUSE = (
    "always (o20[t]:bv[24] = { #x000006 }:bv[24]"
    " && o21[t]:bv[24] = ((i1[t]:bv[24] * { #x000032 }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o22[t]:bv[24] = { #x000000 }:bv[24]"
    " && o23[t]:bv[24] = ((i1[t]:bv[24] * { #x00000a }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o24[t]:bv[24] = { #x000001 }:bv[24]"
    " && o25[t]:bv[24] = ((i1[t]:bv[24] * { #x00000a }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o26[t]:bv[24] = { #x000002 }:bv[24]"
    " && o27[t]:bv[24] = ((i1[t]:bv[24] * { #x00000a }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o28[t]:bv[24] = { #x000003 }:bv[24]"
    " && o29[t]:bv[24] = ((i1[t]:bv[24] * { #x00000f }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o30[t]:bv[24] = { #x000004 }:bv[24]"
    " && o31[t]:bv[24] = ((i1[t]:bv[24] * { #x000005 }:bv[24])"
    " / { #x000064 }:bv[24])"
    " && o32[t]:bv[24] = { #x000005 }:bv[24])."
)


class PayoutShapeError(ValueError):
    """Raised when payout terms or an execution break the book's rules."""


@dataclass(frozen=True)
class PayoutTerms:
    owner: str
    max_per_execution: int
    max_per_period: int
    recipients: Tuple[str, ...]
    period_kind: int = periods.PERIOD_MONTH
    anchor_ts: int = 0
    sequence_number: int = 0
    # Triggers (stage 1 in rules form). Both default off; a rule
    # with no trigger is exactly the #63 rule that already shipped.
    due: bool = False
    on_arrival: bool = False
    # A clock rule's end condition: EXACTLY ONE of these is set.
    end_period_index: Optional[int] = None
    max_fires: Optional[int] = None
    max_total: Optional[int] = None
    # Stage 2 terms. Both default to the stage-1 behaviour; a rule
    # that sets neither keeps its pre-stage-2 rule id.
    sealed: bool = False
    max_fee_per_execution: Optional[int] = None

    @property
    def rule_id(self) -> str:
        return compute_rule_id(self)

    @property
    def has_trigger(self) -> bool:
        return bool(self.due or self.on_arrival)

    @property
    def has_stage2_terms(self) -> bool:
        return bool(self.sealed or self.max_fee_per_execution is not None)


def compute_rule_id(terms: PayoutTerms) -> str:
    payload = {
        "owner": terms.owner,
        "max_per_execution": terms.max_per_execution,
        "max_per_period": terms.max_per_period,
        "recipients": list(terms.recipients),
        "period_kind": terms.period_kind,
        "anchor_ts": terms.anchor_ts,
        "sequence_number": terms.sequence_number,
    }
    if terms.has_trigger:
        # Trigger terms hash differently from a plain #63 rule; a
        # rule WITHOUT a trigger keeps its pre-trigger rule id, so
        # rules installed before triggers existed recompute as-is.
        payload.update({
            "due": bool(terms.due),
            "on_arrival": bool(terms.on_arrival),
            "end_period_index": terms.end_period_index,
            "max_fires": terms.max_fires,
            "max_total": terms.max_total,
        })
    if terms.has_stage2_terms:
        # Stage-2 terms join the signed identity only when set, so
        # a rule that declares neither recomputes its earlier id.
        payload.update({
            "sealed": bool(terms.sealed),
            "max_fee_per_execution": terms.max_fee_per_execution,
        })
    return hashlib.sha256(canonical_json_bytes(payload)).hexdigest()


def validate_payout_shape(terms: PayoutTerms, *, now_ts: int) -> None:
    if not _well_formed_pubkey(terms.owner):
        raise PayoutShapeError("owner pubkey is not well-formed")
    if terms.max_per_execution <= 0:
        raise PayoutShapeError("max_per_execution must be positive")
    if terms.max_per_period < terms.max_per_execution:
        raise PayoutShapeError("max_per_period must cover one execution")
    if not (1 <= len(terms.recipients) <= MAX_RECIPIENTS):
        raise PayoutShapeError("declared recipient set must hold 1..8 entries")
    if len(set(terms.recipients)) != len(terms.recipients):
        raise PayoutShapeError("declared recipients must be distinct")
    for r in terms.recipients:
        if not _well_formed_pubkey(r):
            raise PayoutShapeError("a declared recipient pubkey is not well-formed")
    periods.validate_schedule(terms.anchor_ts, terms.period_kind)
    end_conditions = [
        terms.end_period_index is not None,
        terms.max_fires is not None,
        terms.max_total is not None,
    ]
    if any(end_conditions) and not (terms.due or terms.sealed):
        raise PayoutShapeError(
            "an end condition requires the clock trigger or a seal")
    if terms.due and sum(end_conditions) != 1:
        raise PayoutShapeError(
            "a clock rule must declare exactly one end condition")
    if terms.sealed and sum(end_conditions) != 1:
        raise PayoutShapeError(
            "a sealed rule must declare exactly one end condition")
    if terms.sealed and not terms.due \
            and terms.end_period_index is None:
        # The firing counters only move for clock settlements, so a
        # sealed rule without the clock trigger can only end on its
        # calendar: its end condition must be the final period.
        raise PayoutShapeError(
            "a sealed rule without the clock trigger ends on a final "
            "period index")
    if terms.end_period_index is not None and terms.end_period_index < 0:
        raise PayoutShapeError("end_period_index must be non-negative")
    if terms.max_fires is not None and terms.max_fires <= 0:
        raise PayoutShapeError("max_fires must be positive")
    if terms.max_total is not None and terms.max_total <= 0:
        raise PayoutShapeError("max_total must be positive")
    if terms.max_fee_per_execution is not None \
            and terms.max_fee_per_execution < 0:
        raise PayoutShapeError("max_fee_per_execution must be non-negative")
    if terms.due:
        period_seconds = periods.period_end(
            terms.anchor_ts, terms.period_kind, 0) - terms.anchor_ts
        if period_seconds < MIN_DUE_SPACING_SECONDS:
            raise PayoutShapeError(
                "a clock rule's period is shorter than the minimum "
                "due spacing")


@dataclass
class PayoutRuleState:
    terms: PayoutTerms
    period_index: int = -1
    spent_in_period: int = 0
    settlements: List[str] = field(default_factory=list)
    # Clock-trigger accounting, across all periods: how much the
    # clock has paid in total and how many times it has fired. The
    # rule's end conditions read these, never the period counters.
    total_spent: int = 0
    fires: int = 0
    # Stage-2 accounting, across ALL settlement kinds: the total
    # paid and the number of settlements, the update lineage (the
    # superseded rule ids, oldest first; `version` is 1 at install
    # and grows by one per update), and the clock observability
    # counters -- periods that closed without a clock settlement,
    # and the newest period the sweep has accounted for.
    paid_total: int = 0
    executions: int = 0
    version: int = 1
    lineage: List[str] = field(default_factory=list)
    missed_periods: int = 0
    last_clock_period: int = -1

    def roll_period(self, ts: int) -> None:
        idx = periods.period_index_at(
            self.terms.anchor_ts, self.terms.period_kind, ts)
        if idx != self.period_index:
            self.period_index = idx
            self.spent_in_period = 0

    def already_settled(self, settlement_id: str) -> bool:
        return settlement_id in self.settlements

    def record_settlement(self, settlement_id: str, total: int) -> None:
        self.settlements.append(settlement_id)
        if len(self.settlements) > MAX_SETTLEMENTS_KEPT:
            del self.settlements[: len(self.settlements) - MAX_SETTLEMENTS_KEPT]
        self.spent_in_period += total
        self.paid_total += total
        self.executions += 1


def clock_settlement_id(rule_id: str, period_index: int) -> str:
    """Settlement id of a clock firing: one per rule per period."""
    return f"clock:{rule_id}:{period_index}"


def arrival_settlement_id(tx_id: str) -> str:
    """Settlement id of an arrival settlement: one per crediting tx."""
    return f"arrival:{tx_id}"


def clock_due_period(state: PayoutRuleState, ts: int) -> Optional[int]:
    """The period a clock rule fires for at `ts`, or None.

    Only the CURRENT period can fire: a period that saw no block is
    skipped, never caught up. The end conditions are read here, so
    a rule past its final period / firing count / total is inert.
    Idempotency is the settlement id's: a period already settled
    does not fire again.
    """
    terms = state.terms
    if not terms.due:
        return None
    idx = periods.period_index_at(terms.anchor_ts, terms.period_kind, ts)
    if idx < 0:
        return None
    if terms.end_period_index is not None and idx > terms.end_period_index:
        return None
    if terms.max_fires is not None and state.fires >= terms.max_fires:
        return None
    if terms.max_total is not None and state.total_spent >= terms.max_total:
        return None
    if state.already_settled(clock_settlement_id(terms.rule_id, idx)):
        return None
    return idx


def rule_ended(state: PayoutRuleState, ts: int) -> bool:
    """Whether the rule's end condition has ended it at `ts`.

    A rule with no end condition never ends. The calendar end reads
    the period containing `ts`; the counter ends read the firing
    accounting. This is the seal's lift point and the update
    screen's notion of a finished rule.
    """
    terms = state.terms
    if terms.end_period_index is not None:
        idx = periods.period_index_at(
            terms.anchor_ts, terms.period_kind, ts)
        if idx > terms.end_period_index:
            return True
    if terms.max_fires is not None and state.fires >= terms.max_fires:
        return True
    if terms.max_total is not None and state.total_spent >= terms.max_total:
        return True
    return False


def observe_clock(state: PayoutRuleState, ts: int) -> int:
    """Account for clock periods that closed unsettled by `ts`.

    Called by the block-end sweep before it steps due rules. Every
    period older than the current one that the sweep had accounted
    for and that holds no clock settlement is a missed period: the
    rule was due, no block settled it (no block landed, or its legs
    could not be covered), and the no-catch-up rule moves on. The
    count is incremental -- each period is counted at most once,
    when it closes -- and periods past the rule's end condition are
    not missed, they are over. Returns the number newly counted.
    """
    terms = state.terms
    if not terms.due:
        return 0
    idx = periods.period_index_at(terms.anchor_ts, terms.period_kind, ts)
    if idx < 0:
        return 0
    if state.last_clock_period < 0:
        # First observation: accounting starts here; earlier
        # periods are history this build never watched.
        state.last_clock_period = idx
        return 0
    if terms.max_fires is not None and state.fires >= terms.max_fires:
        state.last_clock_period = idx
        return 0
    if terms.max_total is not None and state.total_spent >= terms.max_total:
        state.last_clock_period = idx
        return 0
    newly = 0
    for p in range(state.last_clock_period, idx):
        if terms.end_period_index is not None and p > terms.end_period_index:
            break
        if not state.already_settled(clock_settlement_id(terms.rule_id, p)):
            newly += 1
    state.missed_periods += newly
    state.last_clock_period = idx
    return newly


def fee_exceeds_cap(terms: PayoutTerms, fee: int) -> bool:
    """Whether an execution fee breaks the rule's declared cap."""
    return terms.max_fee_per_execution is not None \
        and fee > terms.max_fee_per_execution


def legs_from_outputs(outputs: Dict, terms: PayoutTerms) -> List[Tuple[str, int]]:
    """Read the rule's legs from an evaluation's outputs.

    Raises PayoutShapeError on any malformed or undeclared leg; the
    caller treats that as "the execution settles nothing".
    """
    raw_count = outputs.get(LEG_COUNT_STREAM)
    if raw_count is None:
        return []
    count = _parse_tau_output(raw_count)
    if count is None or not (0 <= count <= MAX_LEGS):
        raise PayoutShapeError("leg count output is malformed")
    legs: List[Tuple[str, int]] = []
    for k in range(count):
        amount_stream, index_stream = LEG_STREAMS[k]
        amount = _parse_tau_output(outputs.get(amount_stream))
        index = _parse_tau_output(outputs.get(index_stream))
        if amount is None or index is None:
            raise PayoutShapeError("a leg output is malformed")
        if amount <= 0:
            raise PayoutShapeError("a leg amount must be positive")
        if not (0 <= index < len(terms.recipients)):
            raise PayoutShapeError("a leg names an undeclared recipient")
        legs.append((terms.recipients[index], amount))
    return legs


class PayoutBook:
    """(owner, rule_id) -> PayoutRuleState, with a content root.

    Stage 1 keyed the book by owner alone: one rule per account.
    Stage 2 keys it by the pair, so an account holds up to
    MAX_RULES_PER_OWNER rules. The single-rule accessors keep their
    stage-1 meaning for an owner with exactly one rule -- `get`,
    `check_execution` and `settle` without a rule id resolve to
    that rule -- and refuse ambiguity rather than guess when the
    owner holds several: a caller settling money must name its
    rule.
    """

    def __init__(self) -> None:
        self._rules: Dict[str, Dict[str, PayoutRuleState]] = {}
        self._root_cache: Optional[str] = None

    def __len__(self) -> int:
        return sum(len(rules) for rules in self._rules.values())

    def is_empty(self) -> bool:
        return not self._rules

    def _resolve(self, owner: str,
                 rule_id: Optional[str]) -> Optional[PayoutRuleState]:
        rules = self._rules.get(owner)
        if not rules:
            return None
        if rule_id is not None:
            return rules.get(rule_id)
        if len(rules) == 1:
            return next(iter(rules.values()))
        return None

    def get(self, owner: str,
            rule_id: Optional[str] = None) -> Optional[PayoutRuleState]:
        """One rule state: the named rule, or the owner's only rule."""
        return self._resolve(owner, rule_id)

    def get_rule(self, owner: str, rule_id: str) -> Optional[PayoutRuleState]:
        rules = self._rules.get(owner)
        return rules.get(rule_id) if rules else None

    def rules_of(self, owner: str) -> List[PayoutRuleState]:
        """Every rule the owner holds, ordered by rule id."""
        rules = self._rules.get(owner)
        if not rules:
            return []
        return [rules[rid] for rid in sorted(rules)]

    def owner_rule_count(self, owner: str) -> int:
        return len(self._rules.get(owner, {}))

    def owners(self) -> List[str]:
        return sorted(self._rules)

    def all_states(self) -> List[PayoutRuleState]:
        """Every installed rule, ordered by (owner, rule id)."""
        out = []
        for owner in sorted(self._rules):
            out.extend(self.rules_of(owner))
        return out

    def install(self, terms: PayoutTerms) -> PayoutRuleState:
        rules = self._rules.setdefault(terms.owner, {})
        if terms.rule_id not in rules \
                and len(rules) >= MAX_RULES_PER_OWNER:
            raise PayoutShapeError(
                "the owner already holds the maximum number of rules")
        state = PayoutRuleState(terms=terms)
        rules[terms.rule_id] = state
        self._root_cache = None
        return state

    def remove(self, owner: str, rule_id: Optional[str] = None) -> bool:
        rules = self._rules.get(owner)
        if not rules:
            return False
        if rule_id is None:
            if len(rules) != 1:
                return False
            rule_id = next(iter(rules))
        if rule_id not in rules:
            return False
        del rules[rule_id]
        if not rules:
            del self._rules[owner]
        self._root_cache = None
        return True

    # --- updates ---------------------------------------------------

    def update_problem(self, owner: str, rule_id: str,
                       new_terms: PayoutTerms, *, ts: int) -> Optional[str]:
        """Why this update cannot be applied, or None when it can.

        Pure check, shared by the direct update transaction, the
        guarded rule-change path and admission: the terms must be
        shape-valid (checked by the caller through
        `validate_payout_shape`), addressed to the installed rule,
        and consistent with the settled history.
        """
        state = self.get_rule(owner, rule_id)
        if state is None:
            return "no payout rule with that id is installed for the owner"
        if new_terms.owner != owner:
            return "an update cannot change the rule's owner"
        if new_terms.anchor_ts != state.terms.anchor_ts \
                or new_terms.period_kind != state.terms.period_kind:
            return ("an update cannot move the schedule the settled "
                    "history was recorded against")
        if state.terms.sealed and not rule_ended(state, ts):
            return "a sealed rule cannot be updated before it ends"
        idx = periods.period_index_at(
            state.terms.anchor_ts, state.terms.period_kind, ts)
        spent_now = state.spent_in_period if idx == state.period_index else 0
        if new_terms.max_per_period < spent_now:
            return ("the new period cap is below what the current "
                    "period has already spent")
        if new_terms.max_total is not None \
                and state.total_spent >= new_terms.max_total:
            return ("the new total cap does not exceed what the rule "
                    "has already paid")
        if new_terms.rule_id != rule_id \
                and self.get_rule(owner, new_terms.rule_id) is not None:
            return "another rule of the owner already carries those terms"
        return None

    def update(self, owner: str, rule_id: str, new_terms: PayoutTerms,
               *, ts: int) -> PayoutRuleState:
        """Replace a rule's terms, preserving lineage and state.

        The superseded rule id joins the lineage; every accounting
        counter and the settlement history carry over, rolled into
        the current period under the (unchanged) schedule. Raises
        PayoutShapeError when `update_problem` refuses.
        """
        problem = self.update_problem(owner, rule_id, new_terms, ts=ts)
        if problem is not None:
            raise PayoutShapeError(problem)
        old = self.get_rule(owner, rule_id)
        old.roll_period(ts)
        state = PayoutRuleState(
            terms=new_terms,
            period_index=old.period_index,
            spent_in_period=old.spent_in_period,
            settlements=list(old.settlements),
            total_spent=old.total_spent,
            fires=old.fires,
            paid_total=old.paid_total,
            executions=old.executions,
            version=old.version + 1,
            lineage=list(old.lineage) + [rule_id],
            missed_periods=old.missed_periods,
            last_clock_period=old.last_clock_period,
        )
        rules = self._rules[owner]
        del rules[rule_id]
        rules[new_terms.rule_id] = state
        self._root_cache = None
        return state

    # --- executions --------------------------------------------------

    def check_execution(
        self, owner: str, settlement_id: str, legs: Sequence[Tuple[str, int]],
        *, ts: int, rule_id: Optional[str] = None,
    ) -> int:
        """Validate an execution against caps; returns the total.

        Pure check -- record via `settle` only when the legs apply.
        """
        state = self._resolve(owner, rule_id)
        if state is None:
            if rule_id is None and self.owner_rule_count(owner) > 1:
                raise PayoutShapeError(
                    "the owner holds several rules; the execution "
                    "must name its rule")
            raise PayoutShapeError("no payout rule installed for the owner")
        if not settlement_id:
            raise PayoutShapeError("a settlement id is required")
        if state.already_settled(settlement_id):
            raise PayoutShapeError("settlement id already settled")
        if not legs:
            raise PayoutShapeError("the rule produced no legs")
        total = sum(amount for _r, amount in legs)
        if total > state.terms.max_per_execution:
            raise PayoutShapeError("execution exceeds the per-execution cap")
        state.roll_period(ts)
        if state.spent_in_period + total > state.terms.max_per_period:
            raise PayoutShapeError("execution exceeds the period cap")
        return total

    def settle(self, owner: str, settlement_id: str, total: int, *, ts: int,
               rule_id: Optional[str] = None) -> None:
        state = self._resolve(owner, rule_id)
        if state is None:
            raise PayoutShapeError("no payout rule installed for the owner")
        state.roll_period(ts)
        state.record_settlement(settlement_id, total)
        self._root_cache = None

    def settle_clock(self, owner: str, settlement_id: str, total: int,
                     *, ts: int, rule_id: Optional[str] = None) -> None:
        """Settle a clock firing: `settle` plus the firing counters
        the end conditions read."""
        self.settle(owner, settlement_id, total, ts=ts, rule_id=rule_id)
        state = self._resolve(owner, rule_id)
        state.fires += 1
        state.total_spent += total
        self._root_cache = None

    def root(self) -> str:
        if self._root_cache is None:
            rows = []
            for state in self.all_states():
                rows.append({
                    "terms": _terms_payload(state.terms),
                    "period_index": state.period_index,
                    "spent_in_period": state.spent_in_period,
                    "settlements": list(state.settlements),
                    "total_spent": state.total_spent,
                    "fires": state.fires,
                    "paid_total": state.paid_total,
                    "executions": state.executions,
                    "version": state.version,
                    "lineage": list(state.lineage),
                    "missed_periods": state.missed_periods,
                    "last_clock_period": state.last_clock_period,
                })
            self._root_cache = hashlib.sha256(
                canonical_json_bytes(rows)).hexdigest()
        return self._root_cache

    def snapshot_rows(self) -> List[dict]:
        rows = []
        for state in self.all_states():
            row = _terms_payload(state.terms)
            row.update({
                "period_index": state.period_index,
                "spent_in_period": state.spent_in_period,
                "settlements": list(state.settlements),
                "total_spent": state.total_spent,
                "fires": state.fires,
                "paid_total": state.paid_total,
                "executions": state.executions,
                "version": state.version,
                "lineage": list(state.lineage),
                "missed_periods": state.missed_periods,
                "last_clock_period": state.last_clock_period,
            })
            rows.append(row)
        return rows

    @classmethod
    def restore(cls, rows: Sequence[dict]) -> "PayoutBook":
        book = cls()
        for row in rows:
            terms = PayoutTerms(
                owner=row["owner"],
                max_per_execution=int(row["max_per_execution"]),
                max_per_period=int(row["max_per_period"]),
                recipients=tuple(row["recipients"]),
                period_kind=int(row["period_kind"]),
                anchor_ts=int(row["anchor_ts"]),
                sequence_number=int(row["sequence_number"]),
                due=bool(row.get("due", False)),
                on_arrival=bool(row.get("on_arrival", False)),
                end_period_index=(
                    None if row.get("end_period_index") is None
                    else int(row["end_period_index"])),
                max_fires=(
                    None if row.get("max_fires") is None
                    else int(row["max_fires"])),
                max_total=(
                    None if row.get("max_total") is None
                    else int(row["max_total"])),
                sealed=bool(row.get("sealed", False)),
                max_fee_per_execution=(
                    None if row.get("max_fee_per_execution") is None
                    else int(row["max_fee_per_execution"])),
            )
            if terms.rule_id != row["rule_id"]:
                raise ValueError("payout row id does not recompute")
            state = book.install(terms)
            state.period_index = int(row["period_index"])
            state.spent_in_period = int(row["spent_in_period"])
            state.settlements = [str(s) for s in row["settlements"]]
            state.total_spent = int(row.get("total_spent", 0))
            state.fires = int(row.get("fires", 0))
            # Stage-2 counters: a row written before they existed
            # restores with the honest reconstruction -- one
            # execution per recorded settlement (the list is the
            # kept window, so this is a floor), an unknown paid
            # total of 0, version 1 with an empty lineage, and
            # clock accounting not yet observed.
            state.paid_total = int(row.get("paid_total", 0))
            state.executions = int(
                row.get("executions", len(state.settlements)))
            state.version = int(row.get("version", 1))
            state.lineage = [str(s) for s in row.get("lineage", [])]
            state.missed_periods = int(row.get("missed_periods", 0))
            state.last_clock_period = int(row.get("last_clock_period", -1))
        book._root_cache = None
        return book


def _terms_payload(terms: PayoutTerms) -> dict:
    return {
        "rule_id": terms.rule_id,
        "owner": terms.owner,
        "max_per_execution": terms.max_per_execution,
        "max_per_period": terms.max_per_period,
        "recipients": list(terms.recipients),
        "period_kind": terms.period_kind,
        "anchor_ts": terms.anchor_ts,
        "sequence_number": terms.sequence_number,
        "due": bool(terms.due),
        "on_arrival": bool(terms.on_arrival),
        "end_period_index": terms.end_period_index,
        "max_fires": terms.max_fires,
        "max_total": terms.max_total,
        "sealed": bool(terms.sealed),
        "max_fee_per_execution": terms.max_fee_per_execution,
    }


def _terms_from_payload(data: dict, *, owner: str) -> PayoutTerms:
    recipients = data.get("recipients")
    if not isinstance(recipients, list) or not all(
            isinstance(r, str) for r in recipients):
        raise PayoutShapeError("recipients must be a list of pubkeys")

    def _optional_int(name):
        value = data.get(name)
        return None if value is None else int(value)

    return PayoutTerms(
        owner=owner,
        max_per_execution=int(data.get("max_per_execution", 0)),
        max_per_period=int(data.get("max_per_period", 0)),
        recipients=tuple(recipients),
        period_kind=int(data.get("period_kind", periods.PERIOD_MONTH)),
        anchor_ts=int(data.get("anchor_ts", 0)),
        sequence_number=int(data.get("sequence_number", 0)),
        due=bool(data.get("due", False)),
        on_arrival=bool(data.get("on_arrival", False)),
        end_period_index=_optional_int("end_period_index"),
        max_fires=_optional_int("max_fires"),
        max_total=_optional_int("max_total"),
        sealed=bool(data.get("sealed", False)),
        max_fee_per_execution=_optional_int("max_fee_per_execution"),
    )


def parse_payout_install(data: dict) -> PayoutTerms:
    return _terms_from_payload(
        data, owner=str(data.get("sender_pubkey", "")))


def parse_payout_update(data: dict) -> Tuple[str, str, PayoutTerms]:
    """(owner, current rule_id, new terms) for an update.

    The payload is the install payload plus the `rule_id` of the
    version being superseded; the new terms hash to the new version's
    own id. The same shape is carried, as canonical JSON, in the
    body of a rule-change request of kind 6 (guarded accounts).
    """
    owner = str(data.get("sender_pubkey", ""))
    rule_id = str(data.get("rule_id", ""))
    if not _well_formed_pubkey(owner):
        raise PayoutShapeError("update owner pubkey is not well-formed")
    if not rule_id:
        raise PayoutShapeError("an update must name the rule it supersedes")
    if "terms_sequence_number" in data:
        # On the direct transaction the ``sequence_number`` field
        # is the sender's ACCOUNT sequence, which has nothing to
        # do with the rule's versioning; the terms carry their own
        # sequence under this name. (The rule-change request body
        # is a pure terms document and uses ``sequence_number``.)
        data = {**data, "sequence_number": data["terms_sequence_number"]}
    return owner, rule_id, _terms_from_payload(data, owner=owner)


def parse_payout_execute(data: dict) -> Tuple[str, str, int, Optional[str]]:
    """(owner, settlement_id, gross input, rule_id or None)."""
    owner = str(data.get("owner", ""))
    settlement_id = str(data.get("settlement_id", ""))
    gross = int(data.get("gross", 0))
    rule_id = data.get("rule_id")
    rule_id = str(rule_id) if rule_id else None
    if not _well_formed_pubkey(owner):
        raise PayoutShapeError("execution owner pubkey is not well-formed")
    return owner, settlement_id, gross, rule_id


def parse_payout_remove(data: dict) -> Tuple[str, str]:
    return str(data.get("sender_pubkey", "")), str(data.get("rule_id", ""))


def payout_values(base_values: Dict, terms: PayoutTerms, *,
                  executor: str, gross: int) -> Dict:
    """The evaluation input map for a payout execution.

    The owner's rule is stepped with the policy owner set to the
    owner (i12), the executor on i3, the gross on i1 -- the same
    discipline as the sender/recipient policy evaluations.
    """
    values = dict(base_values)
    values[1] = str(gross)
    values[3] = "{ #x" + str(executor) + " }:bv[384]"
    values[12] = "{ #x" + str(terms.owner) + " }:bv[384]"
    return values
