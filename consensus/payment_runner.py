"""The Amendment 2 payment runner: ONE rule per account, three triggers.

This module implements the shape our second design amendment on issue #34
specifies (and withdraws the per-feature-books defense of the first
amendment's A3): an account carries at most ONE payment rule — a Tau
clause body plus a signed configuration — and the node steps that clause
on three occasions, feeds it facts, enforces coverage and the signed
bounds, and applies the legs the clause writes, atomically or not at all.
The node contributes no payment decision: standing payments, receive
routes, rule-computed payouts (#63) and conditional grants are the same
runner wearing different configurations, not four books.

The configuration is not a policy; it names only:

- **parties** — up to eight pubkeys, the payout design's signed candidate
  set generalized to every feature. The clause may write legs ONLY to
  parties, by index.
- **triggers** — which of execute / clock / arrival may ask the rule, and
  their terms (clock terms below).
- **bounds** — per-party caps (0 = uncapped), a per-run cap (0 = bounded
  only by the amount fed and coverage), an optional shared-cap id, and
  the signed `max_fee_per_execution` bound.

Facts are fed on the payout convention's input streams (Amendment 1's A1,
generalized from payouts to every trigger), extended by four streams:

    i1  = amount (execution input; the credited amount on arrival; the
          run's available source balance on clock)
    i3  = the rule owner's pubkey, as a bv[384] literal
    i5  = the block timestamp
    i12 = the executor's pubkey, as a bv[384] literal (on arrival, the
          sender; on clock, the owner)
    i13 = the run fingerprint (execute: the A1 settlement fingerprint,
          first 8 bytes of blake3(event_id); clock/arrival: derived from
          rule id + block height + trigger kind)
    i14 = trigger kind (1 execute, 2 clock, 3 arrival)
    i15 = missed periods awaiting settlement (clock only, else 0)
    i16 = the balance held for this rule (held-funded rules; the
          account's available balance otherwise)
    i17 = amount already settled under this rule in the current period

Legs are read from the A1 outputs unchanged: o30 = leg count, then
(party index, amount) pairs on o31..o46. The engine's evaluator adapter
(consensus/engine.py) owns the stepping and the strict decode; in this
layer the clause is an injected callable receiving the fact context, and
the BOOK enforces everything around its outputs — party set, per-party
caps, per-run cap, total vs the amount fed, coverage, shared cap,
atomicity, pays-once — through ONE plan per trigger that backs both the
`can_*` admission verdict and the applying mutation, so the two cannot
disagree.

Funding model: a rule is account-funded until it is funded. A
poster-signed funding transfer moves funds into the runner escrow
account (the grant book's escrow pattern: the escrow balance covers the
sum of held balances by construction) and marks the rule held-funded
permanently; its runs then draw on the held balance, which is what a
grant is in this shape. Account-funded runs debit the owner's account.
Arrival runs are funded by the credit itself: the legs come out of the
credited amount and the unwritten remainder stays with the account.

Clock bookkeeping: the clock terms' anchor and period kind define the
period grid (consensus/periods.py — calendar months clamp to the last
day of a shorter month, no drift). `clock_next` is the next period the
clock trigger has not resolved; a run at period p settles p plus at most
`max_catch_up` of the missed periods before it (the clause sees the full
missed count as i15 and writes legs for the whole run; older missed
periods are passed over). When the clock terms carry `until_ts` and the
configuration asks for a deadline run, one final clock run fires at the
deadline — the grant refund in this shape. Fees: the executor pays on
execute runs (the transaction is fee-bearing, as for payout execute);
clock and arrival runs are charged to the account against the signed
fee bound, and a clock run whose fee would exceed the bound does not
fire.

Exactly-once: every settled run is recorded under a run key (execute:
the event id; clock: the period, or the deadline; arrival: the credit's
own identity, supplied by the caller). An execute replay is refused as
already-settled, never re-run. A run that writes nothing settles
nothing: execute refuses it (the event stays open), a clock run leaves
its period open, an arrival run credits the full amount unsplit.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

from blake3 import blake3

from consensus.payments import (
    FEE_SINK_PUBKEY,
    MAX_CATCH_UP_LIMIT,
    MAX_PAYOUT_CANDIDATES,
    MAX_PAYOUT_CLAUSE_BYTES,
    DictLedger,
    FeeOracle,
    PaymentRefused,
    PaymentShapeError,
    _amount,
    _bool_field,
    _field,
    _id_field,
    _is_int,
    _pairs,
    _pubkey,
    _u64,
)
from consensus.periods import PERIOD_KINDS, period_index_at
from consensus.serialization import (
    canonical_json,
    compute_payment_entry_id,
    encode_pubkey48,
    encode_string,
    encode_uint64,
)

# --- Triggers ------------------------------------------------------------------

TRIGGER_EXECUTE = "execute"
TRIGGER_CLOCK = "clock"
TRIGGER_ARRIVAL = "arrival"
TRIGGER_NAMES = frozenset({TRIGGER_EXECUTE, TRIGGER_CLOCK, TRIGGER_ARRIVAL})

# The i14 fact values.
TRIGGER_KIND_EXECUTE = 1
TRIGGER_KIND_CLOCK = 2
TRIGGER_KIND_ARRIVAL = 3
_TRIGGER_KINDS = {
    TRIGGER_EXECUTE: TRIGGER_KIND_EXECUTE,
    TRIGGER_CLOCK: TRIGGER_KIND_CLOCK,
    TRIGGER_ARRIVAL: TRIGGER_KIND_ARRIVAL,
}

# Fact streams beyond the A1 layout (i1/i3/i5/i12/i13 and o30..o46 are the
# payout convention's constants, imported above and reused unchanged).
RUNNER_INPUT_TRIGGER_STREAM = 14
RUNNER_INPUT_MISSED_STREAM = 15
RUNNER_INPUT_HELD_STREAM = 16
RUNNER_INPUT_PERIOD_SETTLED_STREAM = 17

MAX_RUNNER_PARTIES = MAX_PAYOUT_CANDIDATES   # the signed candidate bound, generalized
MAX_RUNNER_CLAUSE_BYTES = MAX_PAYOUT_CLAUSE_BYTES

# Ledger sink account for held (grant) balances: credited somewhere real
# so value is conserved end to end, exactly like the grant book's escrow.
RUNNER_ESCROW_PUBKEY = "22" * 48

# The clause seam: the callable the engine's evaluator adapter hands the
# book. It receives the run's fact context (the book-level names of the
# streams above: amount, owner, ts, executor, fingerprint, trigger,
# missed, held, period_settled, parties) and returns (party_index,
# amount) legs, or raises PaymentRefused when the clause cannot be
# evaluated or its output is malformed.
RunnerClause = Callable[[Dict[str, Any]], List[Tuple[int, int]]]

ClauseFactory = Callable[["RuleTerms"], RunnerClause]


def settlement_fingerprint(event_id: str) -> int:
    """The A1 settlement fingerprint: first 8 bytes of blake3(event_id)."""
    return int.from_bytes(blake3(event_id.encode("utf-8")).digest()[:8], "big")


def runner_fingerprint(rule_id: bytes, height: int, trigger_kind: int) -> int:
    """The clock/arrival run fingerprint (i13): derived from the rule id,
    the block height and the trigger kind, as the amendment specifies."""
    out = bytearray(rule_id)
    out.extend(encode_uint64(height))
    out.extend(bytes([trigger_kind]))
    return int.from_bytes(blake3(bytes(out)).digest()[:8], "big")


# --- Signed configuration --------------------------------------------------------


@dataclass(frozen=True)
class ClockTerms:
    """The clock trigger's terms, and the rule's period grid.

    The anchor and period kind define the grid the i15/i17 facts and the
    catch-up bookkeeping run on, whether or not the clock trigger itself
    is enabled (a grant's draws are execute runs, but its draw schedule
    is a period policy the clause reads off this grid). `until_ts` ends
    the periodic runs; with `deadline_run` set, one final clock run
    fires AT `until_ts` — the grant deadline refund in this shape.
    """

    anchor_ts: int
    period_kind: str
    until_ts: Optional[int] = None
    max_fires: Optional[int] = None
    max_catch_up: int = 0        # signed permission; 0 = skip missed (default)
    deadline_run: bool = False

    def __post_init__(self) -> None:
        _u64(self.anchor_ts, "clock anchor_ts")
        if self.period_kind not in PERIOD_KINDS:
            raise PaymentShapeError(
                f"unknown period kind: {self.period_kind!r}")
        if self.until_ts is not None:
            _u64(self.until_ts, "clock until_ts")
            if self.until_ts <= self.anchor_ts:
                raise PaymentShapeError("clock until must be after the anchor")
        if self.max_fires is not None:
            _u64(self.max_fires, "clock max_fires")
            if self.max_fires < 1:
                raise PaymentShapeError("clock max_fires must be at least 1")
        if not _is_int(self.max_catch_up) or not (
            0 <= self.max_catch_up <= MAX_CATCH_UP_LIMIT
        ):
            raise PaymentShapeError(
                f"max_catch_up must be in 0..{MAX_CATCH_UP_LIMIT}")
        if not isinstance(self.deadline_run, bool):
            raise PaymentShapeError("clock deadline_run must be a boolean")
        if self.deadline_run and self.until_ts is None:
            raise PaymentShapeError("a deadline run requires an until_ts")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "anchor_ts": self.anchor_ts, "period_kind": self.period_kind,
            "until_ts": self.until_ts, "max_fires": self.max_fires,
            "max_catch_up": self.max_catch_up,
            "deadline_run": self.deadline_run,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ClockTerms":
        return cls(**{k: d[k] for k in (
            "anchor_ts", "period_kind", "until_ts", "max_fires",
            "max_catch_up", "deadline_run")})


@dataclass(frozen=True)
class RuleTerms:
    """One account's payment rule: the Tau clause body that decides, plus
    the signed configuration that bounds it. The rule id commits to both,
    following the payout terms' preimage pattern."""

    owner: str
    clause: str
    parties: Tuple[str, ...]
    party_caps: Tuple[int, ...]        # parallel to parties; 0 = uncapped
    triggers: Tuple[str, ...]          # sorted subset of TRIGGER_NAMES
    max_per_run: int                   # 0 = no cap beyond the amount fed
    max_fee_per_execution: int
    clock: Optional[ClockTerms] = None
    shared_cap_id: Optional[str] = None
    sequence_number: int = 0

    def __post_init__(self) -> None:
        _pubkey(self.owner, "owner")
        if not isinstance(self.clause, str):
            raise PaymentShapeError("rule clause must be text")
        if len(self.clause.encode("utf-8")) > MAX_RUNNER_CLAUSE_BYTES:
            raise PaymentShapeError(
                f"rule clause exceeds {MAX_RUNNER_CLAUSE_BYTES} bytes")
        if not (1 <= len(self.parties) <= MAX_RUNNER_PARTIES):
            raise PaymentShapeError(
                f"a payment rule has 1..{MAX_RUNNER_PARTIES} parties")
        if len(self.party_caps) != len(self.parties):
            raise PaymentShapeError("party_caps must parallel parties")
        seen = set()
        for party in self.parties:
            _pubkey(party, "rule party")
            if party in seen:
                raise PaymentShapeError("duplicate rule party")
            seen.add(party)
        for cap in self.party_caps:
            _u64(cap, "party cap")
        if not self.triggers or not set(self.triggers) <= TRIGGER_NAMES:
            raise PaymentShapeError(
                f"triggers must be a non-empty subset of {sorted(TRIGGER_NAMES)}")
        if tuple(sorted(set(self.triggers))) != tuple(self.triggers):
            raise PaymentShapeError("triggers must be sorted and unique")
        if TRIGGER_CLOCK in self.triggers and self.clock is None:
            raise PaymentShapeError(
                "the clock trigger requires clock terms")
        _u64(self.max_per_run, "max_per_run")
        _u64(self.max_fee_per_execution, "max_fee_per_execution")
        if self.shared_cap_id is not None and (
            not isinstance(self.shared_cap_id, str) or not self.shared_cap_id
        ):
            raise PaymentShapeError("shared_cap_id must be a non-empty string")
        _u64(self.sequence_number, "sequence_number")

    @property
    def rule_id(self) -> bytes:
        out = bytearray()
        out.extend(encode_pubkey48(self.owner))
        out.extend(encode_string(self.clause))
        out.extend(encode_uint64(len(self.parties)))
        for party, cap in zip(self.parties, self.party_caps):
            out.extend(encode_pubkey48(party))
            out.extend(encode_uint64(cap))
        bitmask = 0
        for name in self.triggers:
            bitmask |= 1 << (_TRIGGER_KINDS[name] - 1)
        out.extend(encode_uint64(bitmask))
        out.extend(encode_uint64(self.max_per_run))
        out.extend(encode_uint64(self.max_fee_per_execution))
        out.extend(encode_uint64(1 if self.clock is not None else 0))
        if self.clock is not None:
            clock = self.clock
            out.extend(encode_uint64(clock.anchor_ts))
            out.extend(encode_string(clock.period_kind))
            out.extend(encode_uint64(1 if clock.until_ts is not None else 0))
            out.extend(encode_uint64(clock.until_ts or 0))
            out.extend(encode_uint64(1 if clock.max_fires is not None else 0))
            out.extend(encode_uint64(clock.max_fires or 0))
            out.extend(encode_uint64(clock.max_catch_up))
            out.extend(encode_uint64(1 if clock.deadline_run else 0))
        out.extend(encode_string(self.shared_cap_id or ""))
        out.extend(encode_uint64(self.sequence_number))
        return compute_payment_entry_id("tau.payment.rule.v1", bytes(out))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner": self.owner, "clause": self.clause,
            "parties": list(self.parties),
            "party_caps": list(self.party_caps),
            "triggers": list(self.triggers),
            "max_per_run": self.max_per_run,
            "max_fee_per_execution": self.max_fee_per_execution,
            "clock": self.clock.to_dict() if self.clock is not None else None,
            "shared_cap_id": self.shared_cap_id,
            "sequence_number": self.sequence_number,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RuleTerms":
        return cls(
            owner=d["owner"], clause=d["clause"],
            parties=tuple(d["parties"]),
            party_caps=tuple(d["party_caps"]),
            triggers=tuple(d["triggers"]),
            max_per_run=d["max_per_run"],
            max_fee_per_execution=d["max_fee_per_execution"],
            clock=ClockTerms.from_dict(d["clock"])
            if d.get("clock") is not None else None,
            shared_cap_id=d.get("shared_cap_id"),
            sequence_number=d["sequence_number"],
        )


# --- Transaction parsing (root fields only) -------------------------------------


def parse_runner_terms(tx: Dict[str, Any]) -> RuleTerms:
    clock = None
    if tx.get("clock_anchor_ts") is not None:
        until = tx.get("clock_until_ts")
        max_fires = tx.get("clock_max_fires")
        clock = ClockTerms(
            anchor_ts=_field(tx, "clock_anchor_ts"),
            period_kind=_field(tx, "clock_period_kind"),
            until_ts=until if until is not None else None,
            max_fires=max_fires if max_fires is not None else None,
            max_catch_up=tx.get("max_catch_up", 0),
            deadline_run=_bool_field(tx, "clock_deadline_run", False),
        )
    triggers_raw = _field(tx, "triggers")
    if not isinstance(triggers_raw, (list, tuple)):
        raise PaymentShapeError("triggers must be a list of trigger names")
    parties = _pairs(tx, "parties")
    return RuleTerms(
        owner=_field(tx, "owner"),
        clause=_field(tx, "clause"),
        parties=tuple(p for p, _ in parties),
        party_caps=tuple(c for _, c in parties),
        triggers=tuple(sorted(set(triggers_raw))),
        max_per_run=tx.get("max_per_run", 0),
        max_fee_per_execution=_field(tx, "max_fee_per_execution"),
        clock=clock,
        shared_cap_id=tx.get("shared_cap_id"),
        sequence_number=tx.get("sequence_number", 0),
    )


def parse_runner_remove(tx: Dict[str, Any]) -> str:
    return _pubkey(_field(tx, "owner"), "owner")


def parse_runner_fund(tx: Dict[str, Any]) -> Tuple[bytes, int]:
    return _id_field(tx, "rule_id"), _amount(_field(tx, "amount"), "amount")


def parse_runner_execute(tx: Dict[str, Any]) -> Tuple[bytes, str, int]:
    rule_id = _id_field(tx, "rule_id")
    event_id = _field(tx, "event_id")
    if not isinstance(event_id, str) or not event_id:
        raise PaymentShapeError("event_id must be a non-empty string")
    return rule_id, event_id, _amount(_field(tx, "amount"), "amount")


# --- Run records and state --------------------------------------------------------


@dataclass(frozen=True)
class RunRecord:
    """One settled run. `key` is the exactly-once registry key."""

    key: str
    rule_id: bytes
    trigger: str                 # TRIGGER_* name
    executor: str
    legs: Tuple[Tuple[str, int], ...]   # resolved (pubkey, amount)
    total: int
    fee: int
    period_index: Optional[int]
    periods_covered: int
    ts: int
    height: int


@dataclass(frozen=True)
class ArrivalReceipt:
    owner: str
    gross: int
    net: int                     # what the owner keeps of the credit
    legs: Tuple[Tuple[str, int], ...]
    fee: int
    record: RunRecord


@dataclass
class RuleState:
    terms: RuleTerms
    held: int = 0
    held_funded: bool = False
    runs: Dict[str, RunRecord] = field(default_factory=dict)
    period_settled: Dict[int, int] = field(default_factory=dict)
    clock_next: int = 0          # next period the clock trigger has not resolved
    clock_fires: int = 0
    deadline_done: bool = False


@dataclass
class RunnerSharedCapState:
    """ONE counter per shared-cap id, across every rule that names it:
    a shared cap counted once per rule is not a shared cap."""

    limit: int
    spent: int = 0


@dataclass(frozen=True)
class _RunPlan:
    legs: Tuple[Tuple[str, int], ...]
    total: int
    period_index: Optional[int]
    context: Dict[str, Any]


class RunnerBook:
    """The Amendment 2 runner: at most one payment rule per account,
    stepped on execute / clock / arrival triggers."""

    def __init__(self) -> None:
        self.rules: Dict[bytes, RuleState] = {}
        self.by_owner: Dict[str, bytes] = {}
        self.shared_caps: Dict[str, RunnerSharedCapState] = {}

    def is_empty(self) -> bool:
        return not self.rules and not self.shared_caps

    def get(self, rule_id: bytes) -> Optional[RuleState]:
        return self.rules.get(rule_id)

    def get_by_owner(self, owner: str) -> Optional[RuleState]:
        rule_id = self.by_owner.get(owner)
        return self.rules.get(rule_id) if rule_id is not None else None

    # -- shared cap registration ---------------------------------------------------

    def can_set_shared_cap(self, cap_id: str, limit: int) -> Tuple[bool, str]:
        """The shared admission/apply check for registering a shared cap;
        `set_shared_cap` raises exactly these reasons."""
        if not isinstance(cap_id, str) or not cap_id:
            return False, "shared_cap_id must be a non-empty string"
        try:
            _amount(limit, "shared cap limit")
        except PaymentShapeError as exc:
            return False, str(exc)
        if cap_id in self.shared_caps:
            return False, "shared cap already registered under this id"
        return True, ""

    def set_shared_cap(self, cap_id: str, limit: int) -> None:
        ok, reason = self.can_set_shared_cap(cap_id, limit)
        if not ok:
            raise PaymentShapeError(reason)
        self.shared_caps[cap_id] = RunnerSharedCapState(limit=limit)

    def shared_cap_state(self, cap_id: str) -> Optional[RunnerSharedCapState]:
        return self.shared_caps.get(cap_id)

    # -- install / remove ------------------------------------------------------------

    def can_install(self, terms: RuleTerms) -> Tuple[bool, str]:
        """The shared admission/apply check for installing a rule;
        `install` raises exactly these reasons. Install REPLACES the
        account's current rule — one rule per account is the shape — but
        never strands held funds."""
        if not terms.clause.strip():
            return False, "payment rule carries no clause body"
        if terms.shared_cap_id is not None \
                and terms.shared_cap_id not in self.shared_caps:
            return False, "rule names a shared cap that is not registered"
        existing = self.get_by_owner(terms.owner)
        if existing is not None and existing.held > 0:
            return False, (
                "the account's current rule still holds funds; "
                "it cannot be replaced")
        return True, ""

    def install(self, terms: RuleTerms) -> bytes:
        ok, reason = self.can_install(terms)
        if not ok:
            raise PaymentShapeError(reason)
        existing = self.get_by_owner(terms.owner)
        if existing is not None:
            del self.rules[existing.terms.rule_id]
        state = RuleState(terms=terms)
        self.rules[terms.rule_id] = state
        self.by_owner[terms.owner] = terms.rule_id
        return terms.rule_id

    def can_remove(self, owner: str, signer: str) -> Tuple[bool, str]:
        """The shared admission/apply check for removing a rule;
        `remove` raises exactly these reasons."""
        state = self.get_by_owner(owner)
        if state is None:
            return False, "unknown payment rule"
        if signer != owner:
            return False, "only the owner may remove a payment rule"
        if state.held > 0:
            return False, (
                "the rule still holds funds; it cannot be removed")
        return True, ""

    def remove(self, owner: str, signer: str) -> None:
        """Owner-signed removal: the standing-payment cancellation of
        this shape. Once committed, no later clock run can fire and no
        later arrival run can split — admission and apply read the same
        state. Runs already settled are untouched."""
        ok, reason = self.can_remove(owner, signer)
        if not ok:
            raise PaymentRefused(reason)
        state = self.get_by_owner(owner)
        del self.rules[state.terms.rule_id]
        del self.by_owner[owner]

    # -- funding (held balances) ------------------------------------------------------

    def can_fund(
        self, rule_id: bytes, funder: str, amount: int, *, ledger: DictLedger,
    ) -> Tuple[bool, str]:
        """The shared admission/apply check for funding a rule's held
        balance; `fund` raises exactly these reasons."""
        state = self.rules.get(rule_id)
        if state is None:
            return False, "unknown payment rule"
        if funder != state.terms.owner:
            return False, "only the rule owner may fund a rule"
        try:
            _amount(amount, "amount")
        except PaymentShapeError as exc:
            return False, str(exc)
        if ledger.balance(funder) < amount:
            return False, "insufficient funds to fund the rule"
        return True, ""

    def fund(
        self, rule_id: bytes, funder: str, amount: int, *, ledger: DictLedger,
    ) -> None:
        """Move `amount` from the owner's account into the rule's held
        balance. The funds sit in the runner escrow account, so the
        supply accounting sees them exactly like grant escrow; the rule
        is held-funded from the first funding on, permanently."""
        ok, reason = self.can_fund(rule_id, funder, amount, ledger=ledger)
        if not ok:
            raise PaymentRefused(reason)
        state = self.rules[rule_id]
        ledger.debit(funder, amount)
        ledger.credit(RUNNER_ESCROW_PUBKEY, amount)
        state.held += amount
        state.held_funded = True

    # -- the shared run plan -----------------------------------------------------------

    def _period_index(self, state: RuleState, ts: int) -> Optional[int]:
        """The period containing `ts` on the rule's grid, or None when
        the rule carries no period grid (its i17 fact is then 0)."""
        clock = state.terms.clock
        if clock is None:
            return None
        index = period_index_at(clock.period_kind, clock.anchor_ts, ts)
        return index if index >= 0 else None

    def _source_balance(self, state: RuleState, ledger: DictLedger) -> int:
        if state.held_funded:
            return state.held
        return ledger.balance(state.terms.owner)

    def _plan_run(
        self, state: RuleState, trigger: str, clause: RunnerClause, *,
        amount: int, executor: str, fingerprint: int, missed: int,
        ts: int, ledger: DictLedger, source_balance: int,
    ) -> _RunPlan:
        """Every run check around the clause's outputs, in order.

        Steps the clause on the run's fact context and validates its
        legs: party set, per-party caps, per-run cap, total vs the
        amount fed, coverage, shared cap. Raises PaymentRefused with
        the receipt reason. This ONE plan backs both admission
        (`can_*`) and apply for every trigger, so the two cannot
        disagree. The clause is a pure evaluation by contract, so
        planning settles nothing and records nothing.

        `source_balance` is the coverage the legs draw on, named by the
        trigger: the held balance or the owner's account balance for
        execute/clock, the credit itself for arrival.
        """
        terms = state.terms
        period_index = self._period_index(state, ts)
        held_fact = state.held if state.held_funded \
            else ledger.balance(terms.owner)
        context: Dict[str, Any] = {
            "amount": amount,
            "owner": terms.owner,
            "ts": ts,
            "executor": executor,
            "fingerprint": fingerprint,
            "trigger": _TRIGGER_KINDS[trigger],
            "missed": missed,
            "held": held_fact,
            "period_settled": (
                state.period_settled.get(period_index, 0)
                if period_index is not None else 0
            ),
            "parties": terms.parties,
        }
        raw_legs = clause(context)
        if not isinstance(raw_legs, (list, tuple)):
            raise PaymentRefused("rule clause output is not a leg list")
        per_party: Dict[int, int] = {}
        for leg in raw_legs:
            if not isinstance(leg, (list, tuple)) or len(leg) != 2:
                raise PaymentRefused(
                    "rule clause leg is not an (index, amount) pair")
            index, leg_amount = leg
            if not _is_int(index) or not (0 <= index < len(terms.parties)):
                # The rule named an account outside the signed party
                # set. Nothing settles.
                raise PaymentRefused("rule leg names an undeclared party")
            if not _is_int(leg_amount) or leg_amount <= 0:
                raise PaymentRefused("rule leg amount must be positive")
            per_party[index] = per_party.get(index, 0) + leg_amount
        legs: List[Tuple[str, int]] = []
        total = 0
        for index in sorted(per_party):
            leg_total = per_party[index]
            cap = terms.party_caps[index]
            if cap and leg_total > cap:
                raise PaymentRefused("rule leg exceeds the party cap")
            legs.append((terms.parties[index], leg_total))
            total += leg_total
        if terms.max_per_run and total > terms.max_per_run:
            raise PaymentRefused("rule run exceeds the per-run cap")
        if total > amount:
            raise PaymentRefused("rule legs exceed the amount fed")
        if total > source_balance:
            raise PaymentRefused(
                "insufficient held balance" if state.held_funded
                else "insufficient funds")
        if total and terms.shared_cap_id is not None:
            cap_state = self.shared_caps.get(terms.shared_cap_id)
            if cap_state is None:
                raise PaymentRefused("rule's shared cap is not registered")
            if cap_state.spent + total > cap_state.limit:
                raise PaymentRefused("rule run exceeds the shared cap")
        return _RunPlan(
            legs=tuple(legs), total=total,
            period_index=period_index, context=context)

    def _settle_plan(
        self, state: RuleState, plan: _RunPlan, *, ledger: DictLedger,
    ) -> None:
        """Apply a planned run's movements from the rule's funding
        source and count it exactly once: period bucket and, when the
        rule names one, the shared-cap counter."""
        terms = state.terms
        if plan.total:
            if state.held_funded:
                state.held -= plan.total
                ledger.debit(RUNNER_ESCROW_PUBKEY, plan.total)
            else:
                ledger.debit(terms.owner, plan.total)
            for pubkey, leg_amount in plan.legs:
                ledger.credit(pubkey, leg_amount)
            if terms.shared_cap_id is not None:
                self.shared_caps[terms.shared_cap_id].spent += plan.total
            if plan.period_index is not None:
                state.period_settled[plan.period_index] = (
                    state.period_settled.get(plan.period_index, 0)
                    + plan.total)

    # -- execute trigger -----------------------------------------------------------------

    def _check_execute(
        self, state: RuleState, event_id: str,
    ) -> str:
        """The Tau-free execute conditions, shared by can_execute and
        execute; returns the run's registry key."""
        terms = state.terms
        if TRIGGER_EXECUTE not in terms.triggers:
            raise PaymentRefused("the rule does not enable the execute trigger")
        if not isinstance(event_id, str) or not event_id:
            raise PaymentShapeError("event_id must be a non-empty string")
        key = f"execute:{event_id}"
        if key in state.runs:
            raise PaymentRefused("event already settled")
        return key

    def can_execute(
        self, rule_id: bytes, event_id: str, amount: int,
        clause: RunnerClause, *, executor: str, ts: int, height: int,
        ledger: DictLedger,
    ) -> Tuple[bool, str]:
        """Admission-side verdict for one execute run."""
        state = self.rules.get(rule_id)
        if state is None:
            return False, "unknown payment rule"
        try:
            _amount(amount, "amount")
            key = self._check_execute(state, event_id)
            self._plan_run(
                state, TRIGGER_EXECUTE, clause, amount=amount,
                executor=executor,
                fingerprint=settlement_fingerprint(event_id),
                missed=0, ts=ts, ledger=ledger,
                source_balance=self._source_balance(state, ledger))
        except (PaymentRefused, PaymentShapeError) as exc:
            return False, str(exc)
        return True, ""

    def execute(
        self, rule_id: bytes, event_id: str, amount: int,
        clause: RunnerClause, *, executor: str, ts: int, height: int,
        ledger: DictLedger,
    ) -> RunRecord:
        """Run one execute trigger. Pays ONCE per event id: the event is
        recorded at settlement and a replay is refused as
        already-settled, never re-run. Open to any executor — the legs
        come from the rule's clause, never from the transaction — and
        the executor pays the network fee at the transaction layer, so
        the book charges none here. A run that writes nothing settles
        nothing and is refused, leaving the event open."""
        state = self.rules.get(rule_id)
        if state is None:
            raise PaymentRefused("unknown payment rule")
        _amount(amount, "amount")
        key = self._check_execute(state, event_id)
        plan = self._plan_run(
            state, TRIGGER_EXECUTE, clause, amount=amount,
            executor=executor,
            fingerprint=settlement_fingerprint(event_id),
            missed=0, ts=ts, ledger=ledger,
            source_balance=self._source_balance(state, ledger))
        if plan.total <= 0:
            raise PaymentRefused("rule settles nothing")
        self._settle_plan(state, plan, ledger=ledger)
        record = RunRecord(
            key=key, rule_id=rule_id, trigger=TRIGGER_EXECUTE,
            executor=executor, legs=plan.legs, total=plan.total, fee=0,
            period_index=plan.period_index, periods_covered=0,
            ts=ts, height=height)
        state.runs[key] = record
        return record

    # -- clock trigger ---------------------------------------------------------------------

    def _clock_position(
        self, state: RuleState, ts: int,
    ) -> Optional[Tuple[str, Optional[int], int]]:
        """What the clock trigger would do at `ts`:
        ("deadline", None, 0), ("period", current, missed), or None.

        Pure position arithmetic — no clause, no fee quote — so
        `has_due` and the plan share it."""
        terms = state.terms
        clock = terms.clock
        if clock is None or TRIGGER_CLOCK not in terms.triggers:
            return None
        if clock.until_ts is not None and ts >= clock.until_ts:
            if clock.deadline_run and not state.deadline_done:
                return ("deadline", None, 0)
            return None
        if clock.max_fires is not None \
                and state.clock_fires >= clock.max_fires:
            return None
        current = period_index_at(clock.period_kind, clock.anchor_ts, ts)
        if current < 0 or state.clock_next > current:
            return None
        return ("period", current, current - state.clock_next)

    def has_due(self, ts: int) -> bool:
        """Miner wake hint: True when a sweep at `ts` would find a clock
        run to attempt (an over-approximation is fine; the sweep
        decides)."""
        return any(
            self._clock_position(state, ts) is not None
            for state in self.rules.values()
        )

    def _plan_clock_run(
        self, state: RuleState, clause: RunnerClause, *,
        ts: int, height: int, ledger: DictLedger, fees: FeeOracle,
    ) -> Optional[Tuple[_RunPlan, str, Optional[int], int, int]]:
        """The clock plan: position, clause, fee bound. Returns
        (plan, kind, period, missed, fee), or None when no run is due
        or the quoted fee exceeds the signed bound — a run whose fee
        would exceed the bound does not fire, and nothing is recorded.
        Raises PaymentRefused when the clause refuses or its output
        fails validation."""
        position = self._clock_position(state, ts)
        if position is None:
            return None
        kind, current, missed = position
        terms = state.terms
        source = self._source_balance(state, ledger)
        plan = self._plan_run(
            state, TRIGGER_CLOCK, clause,
            amount=source,
            executor=terms.owner,
            fingerprint=runner_fingerprint(
                terms.rule_id, height, TRIGGER_KIND_CLOCK),
            missed=missed, ts=ts, ledger=ledger, source_balance=source)
        if plan.total <= 0:
            return (plan, kind, current, missed, 0)
        fee = fees.execution_fee(
            terms.owner, plan.legs[0][0] if plan.legs else terms.owner,
            plan.total)
        if fee < 0 or fee > terms.max_fee_per_execution:
            return None
        if ledger.balance(terms.owner) < fee:
            return None
        return (plan, kind, current, missed, fee)

    def can_clock_run(
        self, rule_id: bytes, clause: RunnerClause, *,
        ts: int, height: int, ledger: DictLedger, fees: FeeOracle,
    ) -> Tuple[bool, str]:
        """The can_* half of the clock trigger: the verdict the sweep's
        run_clock reaches, computed without settling anything."""
        state = self.rules.get(rule_id)
        if state is None:
            return False, "unknown payment rule"
        if self._clock_position(state, ts) is None:
            return False, "no clock run is due"
        try:
            planned = self._plan_clock_run(
                state, clause, ts=ts, height=height,
                ledger=ledger, fees=fees)
        except PaymentRefused as exc:
            return False, exc.reason
        if planned is None:
            return False, "execution fee exceeds the signed fee bound"
        if planned[0].total <= 0:
            return False, "rule settles nothing"
        return True, ""

    def run_clock(
        self, rule_id: bytes, clause: RunnerClause, *,
        ts: int, height: int, ledger: DictLedger, fees: FeeOracle,
    ) -> Optional[RunRecord]:
        """Fire one clock run for one rule. None when no run is due or
        the fee bound blocks firing. A run that writes nothing settles
        nothing: it is returned as an unsettled record and its period
        stays open. A settled period run resolves its period plus at
        most `max_catch_up` missed periods before it (the clause saw
        the full missed count as i15); a settled deadline run closes
        the clock for good."""
        state = self.rules.get(rule_id)
        if state is None:
            raise PaymentRefused("unknown payment rule")
        planned = self._plan_clock_run(
            state, clause, ts=ts, height=height,
            ledger=ledger, fees=fees)
        if planned is None:
            return None
        plan, kind, current, missed, fee = planned
        terms = state.terms
        if plan.total <= 0:
            return RunRecord(
                key="", rule_id=rule_id, trigger=TRIGGER_CLOCK,
                executor=terms.owner, legs=(), total=0, fee=0,
                period_index=current, periods_covered=0,
                ts=ts, height=height)
        self._settle_plan(state, plan, ledger=ledger)
        if fee:
            ledger.debit(terms.owner, fee)
            ledger.credit(FEE_SINK_PUBKEY, fee)
        if kind == "deadline":
            state.deadline_done = True
            key = "clock:deadline"
            periods_covered = 0
        else:
            settleable_missed = min(missed, terms.clock.max_catch_up)
            periods_covered = settleable_missed + 1
            state.clock_next = current + 1
            key = f"clock:{current}"
        state.clock_fires += 1
        record = RunRecord(
            key=key, rule_id=rule_id, trigger=TRIGGER_CLOCK,
            executor=terms.owner, legs=plan.legs, total=plan.total,
            fee=fee, period_index=current,
            periods_covered=periods_covered, ts=ts, height=height)
        state.runs[key] = record
        return record

    def sweep_clock(
        self, *, ts: int, height: int, ledger: DictLedger,
        fees: FeeOracle, clause_factory: ClauseFactory,
    ) -> List[RunRecord]:
        """Block-apply sweep: fire the due clock run of every rule, in
        rule-id order. A rule whose clause refuses (or whose fee bound
        blocks firing) settles nothing this block and is retried while
        its period is open — it never stops another rule's run."""
        out: List[RunRecord] = []
        for rule_id in sorted(self.rules):
            state = self.rules[rule_id]
            if self._clock_position(state, ts) is None:
                continue
            try:
                record = self.run_clock(
                    rule_id, clause_factory(state.terms),
                    ts=ts, height=height, ledger=ledger, fees=fees)
            except PaymentRefused:
                continue
            if record is not None and record.total > 0:
                out.append(record)
        return out

    # -- arrival trigger ---------------------------------------------------------------------

    def apply_arrival(
        self, owner: str, sender: str, amount: int, clause: RunnerClause,
        *, fee: int, ts: int, height: int, ledger: DictLedger,
        run_key: str,
    ) -> ArrivalReceipt:
        """Split one ordinary credit through the recipient's rule.

        The split is part of applying the credit: the sender signs only
        the gross; the clause's legs are FINAL credits, applied directly
        by this function and never re-run as arrivals (the runner
        invariant — a routed share can never trigger another route).
        The unwritten remainder stays with the account. Every check
        precedes every movement, so a refusing clause refuses the whole
        credit and nothing half-applies. `fee` is the run's fee, quoted
        by the caller (the engine charges the transfer's own step fee
        and passes 0, the one-fee-per-credit discipline of the route
        book); it is charged to the account against the signed bound.
        """
        state = self.get_by_owner(owner)
        if state is None:
            raise PaymentRefused("unknown payment rule")
        terms = state.terms
        if TRIGGER_ARRIVAL not in terms.triggers:
            raise PaymentRefused("the rule does not enable the arrival trigger")
        _amount(amount, "amount")
        if fee < 0:
            raise PaymentShapeError("fee must be non-negative")
        if fee > terms.max_fee_per_execution:
            raise PaymentRefused("arrival fee exceeds the signed fee bound")
        if ledger.balance(sender) < amount:
            raise PaymentRefused("insufficient funds")
        # Coverage for an arrival run is the credit itself: the legs
        # come out of the credited amount (checked as total <= amount
        # in the plan), never out of the owner's prior balance or the
        # rule's held balance — arrivals leave held funds untouched.
        plan = self._plan_run(
            state, TRIGGER_ARRIVAL, clause, amount=amount,
            executor=sender,
            fingerprint=runner_fingerprint(
                terms.rule_id, height, TRIGGER_KIND_ARRIVAL),
            missed=0, ts=ts, ledger=ledger, source_balance=amount)
        net = amount - plan.total
        if fee and ledger.balance(owner) + net < fee:
            raise PaymentRefused("insufficient funds for the arrival fee")
        ledger.debit(sender, amount)
        if plan.total:
            for pubkey, leg_amount in plan.legs:
                ledger.credit(pubkey, leg_amount)
            if terms.shared_cap_id is not None:
                self.shared_caps[terms.shared_cap_id].spent += plan.total
            if plan.period_index is not None:
                state.period_settled[plan.period_index] = (
                    state.period_settled.get(plan.period_index, 0)
                    + plan.total)
        ledger.credit(owner, net)
        if fee:
            ledger.debit(owner, fee)
            ledger.credit(FEE_SINK_PUBKEY, fee)
        record = RunRecord(
            key=f"arrival:{run_key}", rule_id=terms.rule_id,
            trigger=TRIGGER_ARRIVAL, executor=sender, legs=plan.legs,
            total=plan.total, fee=fee, period_index=plan.period_index,
            periods_covered=0, ts=ts, height=height)
        state.runs[record.key] = record
        return ArrivalReceipt(
            owner=owner, gross=amount, net=net, legs=plan.legs,
            fee=fee, record=record)

    # -- persistence / root ----------------------------------------------------

    def snapshot_rows(self) -> Dict[str, Any]:
        rules = []
        for rule_id in sorted(self.rules):
            s = self.rules[rule_id]
            rules.append({
                "terms": s.terms.to_dict(),
                "held": s.held,
                "held_funded": s.held_funded,
                "runs": {
                    key: {
                        "trigger": r.trigger, "executor": r.executor,
                        "legs": [[p, a] for p, a in r.legs],
                        "total": r.total, "fee": r.fee,
                        "period_index": r.period_index,
                        "periods_covered": r.periods_covered,
                        "ts": r.ts, "height": r.height,
                    }
                    for key, r in sorted(s.runs.items())
                },
                "period_settled": {
                    str(k): v for k, v in sorted(s.period_settled.items())
                },
                "clock_next": s.clock_next,
                "clock_fires": s.clock_fires,
                "deadline_done": s.deadline_done,
            })
        return {
            "rules": rules,
            "shared_caps": [
                {"cap_id": cap_id, "limit": c.limit, "spent": c.spent}
                for cap_id, c in sorted(self.shared_caps.items())
            ],
        }

    @classmethod
    def restore(cls, rows: Dict[str, Any]) -> "RunnerBook":
        book = cls()
        for row in rows.get("shared_caps", []):
            cap_id = row["cap_id"]
            if cap_id in book.shared_caps:
                raise ValueError("duplicate runner shared cap in snapshot rows")
            book.shared_caps[cap_id] = RunnerSharedCapState(
                limit=row["limit"], spent=row["spent"])
        for row in rows.get("rules", []):
            terms = RuleTerms.from_dict(row["terms"])
            if terms.rule_id in book.rules:
                raise ValueError("duplicate payment rule in snapshot rows")
            if terms.owner in book.by_owner:
                raise ValueError(
                    "two payment rules for one account in snapshot rows")
            state = RuleState(
                terms=terms, held=row["held"],
                held_funded=row["held_funded"],
                period_settled={
                    int(k): v for k, v in row["period_settled"].items()
                },
                clock_next=row["clock_next"],
                clock_fires=row["clock_fires"],
                deadline_done=row["deadline_done"],
            )
            for key, r in row["runs"].items():
                state.runs[key] = RunRecord(
                    key=key, rule_id=terms.rule_id, trigger=r["trigger"],
                    executor=r["executor"],
                    legs=tuple((p, a) for p, a in r["legs"]),
                    total=r["total"], fee=r["fee"],
                    period_index=r["period_index"],
                    periods_covered=r["periods_covered"],
                    ts=r["ts"], height=r["height"])
            book.rules[terms.rule_id] = state
            book.by_owner[terms.owner] = terms.rule_id
        return book

    def root_blobs(self) -> List[bytes]:
        rows = self.snapshot_rows()
        blobs = []
        for row in rows["rules"]:
            terms = RuleTerms.from_dict(row["terms"])
            blobs.append(terms.rule_id + canonical_json(row))
        for row in rows["shared_caps"]:
            blobs.append(compute_payment_entry_id(
                "tau.payment.runner_shared_cap.v1",
                encode_string(row["cap_id"])
                + encode_uint64(row["limit"])
                + encode_uint64(row["spent"]),
            ))
        return blobs
