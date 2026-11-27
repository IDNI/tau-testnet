"""Payout rules: rule-computed settlements under declared caps (#63).

An owner installs ONE payout rule: declared caps (maximum per
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
o21/o22, o23/o24, o25/o26, o27/o28 -- at most MAX_LEGS legs.

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

Both triggers settle through `check_execution`/`settle` exactly
like a submitted execution: same caps, same period accounting, same
settlement-id idempotency.
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
PAYOUT_TX_TYPES = frozenset(
    {TX_TYPE_PAYOUT_INSTALL, TX_TYPE_PAYOUT_EXECUTE, TX_TYPE_PAYOUT_REMOVE}
)

#: Stream the owner's payout clause is read on, and the leg outputs.
PAYOUT_STREAM_INDEX = 24
LEG_COUNT_STREAM = 20
LEG_STREAMS = ((21, 22), (23, 24), (25, 26), (27, 28))
MAX_LEGS = len(LEG_STREAMS)
MAX_RECIPIENTS = 8
MAX_SETTLEMENTS_KEPT = 512
MAX_PAYOUT_RULES = 4096

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

    @property
    def rule_id(self) -> str:
        return compute_rule_id(self)

    @property
    def has_trigger(self) -> bool:
        return bool(self.due or self.on_arrival)


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
    if any(end_conditions) and not terms.due:
        raise PayoutShapeError("an end condition requires the clock trigger")
    if terms.due and sum(end_conditions) != 1:
        raise PayoutShapeError(
            "a clock rule must declare exactly one end condition")
    if terms.end_period_index is not None and terms.end_period_index < 0:
        raise PayoutShapeError("end_period_index must be non-negative")
    if terms.max_fires is not None and terms.max_fires <= 0:
        raise PayoutShapeError("max_fires must be positive")
    if terms.max_total is not None and terms.max_total <= 0:
        raise PayoutShapeError("max_total must be positive")


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
    """owner -> PayoutRuleState, with a content root over the terms."""

    def __init__(self) -> None:
        self._rules: Dict[str, PayoutRuleState] = {}
        self._root_cache: Optional[str] = None

    def __len__(self) -> int:
        return len(self._rules)

    def is_empty(self) -> bool:
        return not self._rules

    def get(self, owner: str) -> Optional[PayoutRuleState]:
        return self._rules.get(owner)

    def owners(self) -> List[str]:
        return sorted(self._rules)

    def install(self, terms: PayoutTerms) -> PayoutRuleState:
        state = PayoutRuleState(terms=terms)
        self._rules[terms.owner] = state
        self._root_cache = None
        return state

    def remove(self, owner: str) -> bool:
        if owner in self._rules:
            del self._rules[owner]
            self._root_cache = None
            return True
        return False

    def check_execution(
        self, owner: str, settlement_id: str, legs: Sequence[Tuple[str, int]],
        *, ts: int,
    ) -> int:
        """Validate an execution against caps; returns the total.

        Pure check -- record via `settle` only when the legs apply.
        """
        state = self._rules.get(owner)
        if state is None:
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

    def settle(self, owner: str, settlement_id: str, total: int, *, ts: int) -> None:
        state = self._rules[owner]
        state.roll_period(ts)
        state.record_settlement(settlement_id, total)
        self._root_cache = None

    def settle_clock(self, owner: str, settlement_id: str, total: int,
                     *, ts: int) -> None:
        """Settle a clock firing: `settle` plus the firing counters
        the end conditions read."""
        self.settle(owner, settlement_id, total, ts=ts)
        state = self._rules[owner]
        state.fires += 1
        state.total_spent += total
        self._root_cache = None

    def root(self) -> str:
        if self._root_cache is None:
            rows = []
            for owner in sorted(self._rules):
                st = self._rules[owner]
                rows.append({
                    "terms": _terms_payload(st.terms),
                    "period_index": st.period_index,
                    "spent_in_period": st.spent_in_period,
                    "settlements": list(st.settlements),
                    "total_spent": st.total_spent,
                    "fires": st.fires,
                })
            self._root_cache = hashlib.sha256(
                canonical_json_bytes(rows)).hexdigest()
        return self._root_cache

    def snapshot_rows(self) -> List[dict]:
        rows = []
        for owner in sorted(self._rules):
            st = self._rules[owner]
            row = _terms_payload(st.terms)
            row.update({
                "period_index": st.period_index,
                "spent_in_period": st.spent_in_period,
                "settlements": list(st.settlements),
                "total_spent": st.total_spent,
                "fires": st.fires,
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
            )
            if terms.rule_id != row["rule_id"]:
                raise ValueError("payout row id does not recompute")
            state = book.install(terms)
            state.period_index = int(row["period_index"])
            state.spent_in_period = int(row["spent_in_period"])
            state.settlements = [str(s) for s in row["settlements"]]
            state.total_spent = int(row.get("total_spent", 0))
            state.fires = int(row.get("fires", 0))
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
    }


def parse_payout_install(data: dict) -> PayoutTerms:
    recipients = data.get("recipients")
    if not isinstance(recipients, list) or not all(
            isinstance(r, str) for r in recipients):
        raise PayoutShapeError("recipients must be a list of pubkeys")
    def _optional_int(name):
        value = data.get(name)
        return None if value is None else int(value)

    return PayoutTerms(
        owner=str(data.get("sender_pubkey", "")),
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
    )


def parse_payout_execute(data: dict) -> Tuple[str, str, int]:
    """(owner, settlement_id, gross input) for an execution."""
    owner = str(data.get("owner", ""))
    settlement_id = str(data.get("settlement_id", ""))
    gross = int(data.get("gross", 0))
    if not _well_formed_pubkey(owner):
        raise PayoutShapeError("execution owner pubkey is not well-formed")
    return owner, settlement_id, gross


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
