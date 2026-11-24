"""Programmable payments: standing payments (#34), receive routing (#35),
rule-computed payouts (#63), conditional grants and shared caps (Bounty 01).

The design in one paragraph: every capability is a BOOK held in consensus
state (the `RetractableBook` pattern — a field of ConsensusLifecycleManager,
committed root, only-once settlement, no regenesis), enforced by the node,
never by wallet policy text. A signed authorization creates a standing
payment book entry with a REQUIRED end condition; execution is a sweep at
block apply that re-checks the payer's CURRENT policy before debiting. A
route is a recipient-installed book entry splitting a credit across up to 4
destinations validated at install time. A payout rule computes RECIPIENTS
inside a signed candidate set (<= 8, per-candidate caps) and settles
atomically or not at all. Grants escrow principal in the book; draws are
capped per period; unspent principal refunds at the deadline.

Two seams are deliberately injected, because they are the points where this
layer meets native Tau evaluation in the engine:

- `PolicyGate.allows_debit(payer, recipient, amount)`: the payer's current
  o5 policy re-check at execution time. The book calls it exactly once per
  settled occurrence; it never caches a policy verdict.
- The payout `clause` callable: the rule's own Tau clause -- signed as part
  of the rule's terms at install -- stepped in its isolated pool by the
  engine's payout evaluator, outputting (candidate_index, amount) legs
  under the output convention defined with the payout book below. The book
  receives only the callable, never the evaluation machinery.

Everything else — books, period math, caps, catch-up, cancel, routing
splits, escrow accounting, idempotency — is plain Python in this module.

Honesty bounds (stated in the design, enforced here): there are no #31
consensus spend totals on this HEAD, so spend accounting is BOOK-LOCAL (the
authorization's own cumulative counter, plus the payer-level shared-cap
counter) and this module claims nothing more. There is no #33 protected
policy on this HEAD, so no mechanism here depends on wallet policy being
non-removable; conditions live in these node-held books.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

import tau_defs
from consensus.periods import PERIOD_KINDS, period_bounds, period_index_at
from consensus.serialization import (
    canonical_json,
    compute_payment_entry_id,
    compute_payments_book_root,
    encode_hash32,
    encode_pubkey48,
    encode_string,
    encode_uint64,
)

# --- Bounds (consensus-frozen, like the retractable bounds) ------------------

MAX_CATCH_UP_LIMIT = 3            # signed catch-up bound (#34's carve-out)
MAX_ROUTE_DESTINATIONS = 4        # multi-destination routes in v1 (#35)
MAX_PAYOUT_CANDIDATES = 8         # signed candidate set bound (#63)
MAX_OPEN_AUTHORIZATIONS_PER_PAYER = 16
MAX_OPEN_GRANTS_PER_GRANTOR = 16
MAX_ROUTES_TOTAL = 4096
MAX_PAYOUT_RULES_PER_OWNER = 16

AUTH_ACTIVE = "active"
AUTH_CANCELLED = "cancelled"
AUTH_COMPLETED = "completed"

GRANT_ACTIVE = "active"
GRANT_CLOSED = "closed"

END_COUNT = "count"
END_DATE = "date"
END_TOTAL = "total"
END_KINDS = frozenset({END_COUNT, END_DATE, END_TOTAL})

CREDIT_CLASS_PLAIN_TRANSFER = "plain_transfer"
CREDIT_CLASS_CLAIMED_PAYMENT = "claimed_payment"
CREDIT_CLASS_STANDING_PAYMENT = "standing_payment"
CREDIT_CLASS_PAYOUT = "payout"
# v1 routable classes (design): plain transfers and claimed (released)
# payments. Standing-payment and payout credits are NOT routed in v1.
ROUTABLE_CREDIT_CLASSES = frozenset(
    {CREDIT_CLASS_PLAIN_TRANSFER, CREDIT_CLASS_CLAIMED_PAYMENT}
)

# Ledger sink accounts: fees and grant escrow are credited somewhere real so
# value is conserved end to end and tests can assert on it.
FEE_SINK_PUBKEY = "00" * 48
GRANT_ESCROW_PUBKEY = "11" * 48

# --- Transaction types (engine dispatch) --------------------------------------
#
# Every capability is reachable from a signed transaction of one of these
# types. Parsers below read ROOT fields only: only root fields are signed,
# so anything nested is unsigned data (the retractable convention).

TX_TYPE_STANDING_CREATE = "standing_authorization_create"
TX_TYPE_STANDING_CANCEL = "standing_authorization_cancel"
TX_TYPE_STANDING_EXECUTE = "standing_authorization_execute"
TX_TYPE_ROUTE_INSTALL = "payment_route_install"
TX_TYPE_ROUTE_UPDATE = "payment_route_update"
TX_TYPE_ROUTE_REMOVE = "payment_route_remove"
TX_TYPE_PAYOUT_INSTALL = "payout_rule_install"
TX_TYPE_PAYOUT_EXECUTE = "payout_rule_execute"
TX_TYPE_GRANT_CREATE = "payment_grant_create"
TX_TYPE_GRANT_DRAW = "payment_grant_draw"
TX_TYPE_GRANT_REFUND_CLAIM = "payment_grant_refund_claim"
TX_TYPE_SHARED_CAP_SET = "payment_shared_cap_set"

# The Amendment 2 runner types (consensus/payment_runner.py): ONE payment
# rule per account, stepped on three triggers. Install/remove/fund/execute
# are the only operations the runner adds; the books above keep their own
# types while both shapes coexist in this build.
TX_TYPE_RUNNER_INSTALL = "payment_rule_install"
TX_TYPE_RUNNER_REMOVE = "payment_rule_remove"
TX_TYPE_RUNNER_FUND = "payment_rule_fund"
TX_TYPE_RUNNER_EXECUTE = "payment_rule_execute"

PAYMENT_TX_TYPES = frozenset({
    TX_TYPE_STANDING_CREATE, TX_TYPE_STANDING_CANCEL, TX_TYPE_STANDING_EXECUTE,
    TX_TYPE_ROUTE_INSTALL, TX_TYPE_ROUTE_UPDATE, TX_TYPE_ROUTE_REMOVE,
    TX_TYPE_PAYOUT_INSTALL, TX_TYPE_PAYOUT_EXECUTE,
    TX_TYPE_GRANT_CREATE, TX_TYPE_GRANT_DRAW, TX_TYPE_GRANT_REFUND_CLAIM,
    TX_TYPE_SHARED_CAP_SET,
    TX_TYPE_RUNNER_INSTALL, TX_TYPE_RUNNER_REMOVE, TX_TYPE_RUNNER_FUND,
    TX_TYPE_RUNNER_EXECUTE,
})

# State-creating payment transactions pay the generic transaction fee (the
# engine's transfer-less fee-query step), like a retractable park or a rule
# offer: they are user-initiated and spam-sensitive. Payout EXECUTION pays
# it too: execution is open to any account and steps a Tau clause, so the
# executor -- the transaction's sender, never the rule owner -- pays the
# same fee-query step, which is also the spam price of an open trigger.
# The rest are exempt -- cancel/remove mirror retract (the creation
# already paid), and the standing execute / draw / refund-claim triggers
# move the payer's own money under fees the BOOK charges against signed
# bounds, so a second network fee would drift against those bounds.
PAYMENT_FEE_BEARING_TX_TYPES = frozenset({
    TX_TYPE_STANDING_CREATE, TX_TYPE_ROUTE_INSTALL, TX_TYPE_ROUTE_UPDATE,
    TX_TYPE_PAYOUT_INSTALL, TX_TYPE_PAYOUT_EXECUTE, TX_TYPE_GRANT_CREATE,
    TX_TYPE_SHARED_CAP_SET,
    # Runner: install and fund create state, execute is an open trigger
    # that steps a Tau clause (the executor pays, as for payout execute).
    # Remove is exempt, mirroring cancel/remove above.
    TX_TYPE_RUNNER_INSTALL, TX_TYPE_RUNNER_FUND, TX_TYPE_RUNNER_EXECUTE,
})

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class PaymentShapeError(ValueError):
    """Signed payment terms do not have a shape the node can record."""


class PaymentRefused(Exception):
    """An execution/draw/settlement was refused; `reason` is the receipt text."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


# --- Ledger and gates (the injected seams) -----------------------------------


class DictLedger:
    """Minimal balance ledger the books run against.

    The engine adapts its real account state to this interface; tests use
    this implementation directly. Debits never overdraw.
    """

    def __init__(self, balances: Optional[Dict[str, int]] = None) -> None:
        self.balances: Dict[str, int] = dict(balances or {})

    def balance(self, pubkey: str) -> int:
        return self.balances.get(pubkey, 0)

    def debit(self, pubkey: str, amount: int) -> None:
        if amount < 0:
            raise ValueError("debit amount must be non-negative")
        if self.balance(pubkey) < amount:
            raise PaymentRefused(f"insufficient funds for {pubkey[:12]}…")
        self.balances[pubkey] = self.balance(pubkey) - amount

    def credit(self, pubkey: str, amount: int) -> None:
        if amount < 0:
            raise ValueError("credit amount must be non-negative")
        self.balances[pubkey] = self.balance(pubkey) + amount

    def total(self) -> int:
        return sum(self.balances.values())


class PolicyGate:
    """The payer's CURRENT policy verdict for one debit (native seam).

    Production wiring evaluates the payer's current o5 policy; tests inject
    a scripted double. Implementations must be pure queries: the book calls
    this exactly once per execution attempt it settles or refuses on policy
    grounds, and the verdict is never stored.
    """

    def allows_debit(self, payer: str, recipient: str, amount: int) -> bool:
        raise NotImplementedError


class FeeOracle:
    """Quotes the network fee for one execution (native seam: o8/o9 streams).

    The quote is charged to the payer on top of the payment amount and is
    bounded by the signed `max_fee_per_execution` wherever one exists.
    """

    def execution_fee(self, payer: str, recipient: str, amount: int) -> int:
        raise NotImplementedError


# --- Shared validation helpers ------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise PaymentShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64(value: Any, name: str) -> int:
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise PaymentShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _amount(value: Any, name: str = "amount") -> int:
    value = _u64(value, name)
    if not (1 <= value <= tau_defs.MAX_TRANSFER_VALUE):
        raise PaymentShapeError(
            f"{name} must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
        )
    return value


# --- Transaction parsing (root fields only) ------------------------------------


def _field(tx: Dict[str, Any], name: str) -> Any:
    if not isinstance(tx, dict) or name not in tx:
        raise PaymentShapeError(f"missing field: {name}")
    return tx[name]


def _id_field(tx: Dict[str, Any], name: str) -> bytes:
    raw = _field(tx, name)
    if not isinstance(raw, str) or not _HASH_RE.match(raw):
        raise PaymentShapeError(f"{name} must be 64 lowercase hex characters")
    return bytes.fromhex(raw)


def _pairs(tx: Dict[str, Any], name: str) -> Tuple[Tuple[Any, Any], ...]:
    raw = _field(tx, name)
    if not isinstance(raw, (list, tuple)):
        raise PaymentShapeError(f"{name} must be a list of [account, value] pairs")
    out = []
    for item in raw:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            raise PaymentShapeError(f"{name} entries must be [account, value] pairs")
        out.append((item[0], item[1]))
    return tuple(out)


def _bool_field(tx: Dict[str, Any], name: str, default: bool = False) -> bool:
    raw = tx.get(name, default)
    if not isinstance(raw, bool):
        raise PaymentShapeError(f"{name} must be a boolean")
    return raw


def parse_standing_terms(tx: Dict[str, Any]) -> "StandingTerms":
    return StandingTerms(
        payer=_field(tx, "payer"),
        payee=_field(tx, "payee"),
        amount=_field(tx, "amount"),
        period_kind=_field(tx, "period_kind"),
        start_ts=_field(tx, "start_ts"),
        end_kind=_field(tx, "end_kind"),
        end_value=_field(tx, "end_value"),
        max_fee_per_execution=_field(tx, "max_fee_per_execution"),
        genesis_hash=_field(tx, "genesis_hash"),
        max_catch_up=tx.get("max_catch_up", 0),
        sequence_number=_field(tx, "sequence_number"),
    )


def parse_standing_cancel(tx: Dict[str, Any]) -> bytes:
    return _id_field(tx, "authorization_id")


def parse_standing_execute(tx: Dict[str, Any]) -> Tuple[bytes, int]:
    period_index = _field(tx, "period_index")
    if not _is_int(period_index) or period_index < 0:
        raise PaymentShapeError("period_index must be a non-negative integer")
    return _id_field(tx, "authorization_id"), period_index


def parse_route_terms(tx: Dict[str, Any]) -> "RouteTerms":
    return RouteTerms(
        owner=_field(tx, "owner"),
        destinations=_pairs(tx, "destinations"),
        locked=_bool_field(tx, "locked"),
        expires_ts=tx.get("expires_ts"),
        sequence_number=_field(tx, "sequence_number"),
    )


def parse_route_remove(tx: Dict[str, Any]) -> str:
    return _pubkey(_field(tx, "owner"), "owner")


def parse_payout_terms(tx: Dict[str, Any]) -> "PayoutTerms":
    return PayoutTerms(
        owner=_field(tx, "owner"),
        candidates=_pairs(tx, "candidates"),
        max_per_execution=_field(tx, "max_per_execution"),
        max_per_period=_field(tx, "max_per_period"),
        period_kind=tx.get("period_kind", "week"),
        anchor_ts=tx.get("anchor_ts", 0),
        sequence_number=_field(tx, "sequence_number"),
        clause=_field(tx, "clause"),
    )


def parse_payout_execute(tx: Dict[str, Any]) -> Tuple[bytes, str, int]:
    """(rule id, event id, gross) for one execution.

    The execute transaction carries NO legs and NO clause inputs: the legs
    are whatever the rule's clause outputs when the node steps it on this
    gross / event / executor context (the convention above PayoutTerms),
    and the book enforces everything around those outputs. Anyone may
    submit this transaction; the sender is the executor and pays the
    network fee (see PAYMENT_FEE_BEARING_TX_TYPES)."""
    event_id = _field(tx, "event_id")
    if not isinstance(event_id, str) or not event_id:
        raise PaymentShapeError("event_id must be a non-empty string")
    gross = _amount(_field(tx, "gross"), "gross")
    return _id_field(tx, "payout_rule_id"), event_id, gross


def parse_grant_terms(tx: Dict[str, Any]) -> "GrantTerms":
    return GrantTerms(
        grantor=_field(tx, "grantor"),
        grantee=_field(tx, "grantee"),
        principal=_field(tx, "principal"),
        period_cap=_field(tx, "period_cap"),
        period_kind=_field(tx, "period_kind"),
        start_ts=_field(tx, "start_ts"),
        expires_ts=_field(tx, "expires_ts"),
        max_fee_per_execution=_field(tx, "max_fee_per_execution"),
        per_payment_cap=tx.get("per_payment_cap"),
        shared_cap=_bool_field(tx, "shared_cap"),
        refund_to=tx.get("refund_to"),
        sequence_number=_field(tx, "sequence_number"),
    )


def parse_grant_draw(tx: Dict[str, Any]) -> Tuple[bytes, int]:
    amount = _field(tx, "amount")
    if not _is_int(amount):
        raise PaymentShapeError("amount must be an integer")
    return _id_field(tx, "grant_id"), amount


def parse_grant_refund_claim(tx: Dict[str, Any]) -> bytes:
    return _id_field(tx, "grant_id")


def parse_shared_cap_set(tx: Dict[str, Any]) -> Tuple[str, int]:
    return _field(tx, "payer"), _field(tx, "limit")


# --- Standing payments (#34) ---------------------------------------------------


@dataclass(frozen=True)
class StandingTerms:
    """The signed terms of one standing authorization. Immutable: an update
    is a new authorization, never an invisible mutation."""

    payer: str
    payee: str
    amount: int
    period_kind: str
    start_ts: int
    end_kind: str          # END_COUNT | END_DATE | END_TOTAL — REQUIRED
    end_value: int
    max_fee_per_execution: int
    genesis_hash: str      # network binding: cross-network reuse fails
    max_catch_up: int = 0  # signed permission; 0 = skip missed (the default)
    sequence_number: int = 0

    def __post_init__(self) -> None:
        _pubkey(self.payer, "payer")
        _pubkey(self.payee, "payee")
        _amount(self.amount)
        if self.period_kind not in PERIOD_KINDS:
            raise PaymentShapeError(f"unknown period kind: {self.period_kind!r}")
        _u64(self.start_ts, "start_ts")
        if self.end_kind not in END_KINDS:
            raise PaymentShapeError(
                "an authorization without an end condition is refused: "
                f"end_kind must be one of {sorted(END_KINDS)}"
            )
        _u64(self.end_value, "end_value")
        if self.end_kind in (END_COUNT, END_TOTAL) and self.end_value < 1:
            raise PaymentShapeError("end_value must be at least 1")
        if self.end_kind == END_DATE and self.end_value <= self.start_ts:
            raise PaymentShapeError("end date must be after the start")
        _u64(self.max_fee_per_execution, "max_fee_per_execution")
        if not isinstance(self.genesis_hash, str) or not _HASH_RE.match(self.genesis_hash):
            raise PaymentShapeError("genesis_hash must be 64 lowercase hex characters")
        if not _is_int(self.max_catch_up) or not (0 <= self.max_catch_up <= MAX_CATCH_UP_LIMIT):
            raise PaymentShapeError(
                f"max_catch_up must be in 0..{MAX_CATCH_UP_LIMIT}"
            )
        _u64(self.sequence_number, "sequence_number")

    @property
    def auth_id(self) -> bytes:
        out = bytearray()
        out.extend(encode_pubkey48(self.payer))
        out.extend(encode_pubkey48(self.payee))
        out.extend(encode_uint64(self.amount))
        out.extend(encode_string(self.period_kind))
        out.extend(encode_uint64(self.start_ts))
        out.extend(encode_string(self.end_kind))
        out.extend(encode_uint64(self.end_value))
        out.extend(encode_uint64(self.max_fee_per_execution))
        out.extend(encode_uint64(self.max_catch_up))
        out.extend(encode_hash32(self.genesis_hash))
        out.extend(encode_uint64(self.sequence_number))
        return compute_payment_entry_id("tau.payment.authorization.v1", bytes(out))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "payer": self.payer, "payee": self.payee, "amount": self.amount,
            "period_kind": self.period_kind, "start_ts": self.start_ts,
            "end_kind": self.end_kind, "end_value": self.end_value,
            "max_fee_per_execution": self.max_fee_per_execution,
            "genesis_hash": self.genesis_hash,
            "max_catch_up": self.max_catch_up,
            "sequence_number": self.sequence_number,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "StandingTerms":
        return cls(**{k: d[k] for k in (
            "payer", "payee", "amount", "period_kind", "start_ts", "end_kind",
            "end_value", "max_fee_per_execution", "genesis_hash",
            "max_catch_up", "sequence_number")})


@dataclass(frozen=True)
class Settlement:
    """One settled standing-payment occurrence."""

    auth_id: bytes
    period_index: int
    payer: str
    payee: str
    amount: int
    fee: int


@dataclass
class StandingState:
    terms: StandingTerms
    status: str = AUTH_ACTIVE
    settled: Dict[int, Settlement] = field(default_factory=dict)
    skipped: set = field(default_factory=set)
    cumulative_spent: int = 0   # book-local total (see module honesty note)

    @property
    def completed_count(self) -> int:
        return len(self.settled)


class StandingBook:
    """Standing authorizations for ONE network (genesis-bound)."""

    def __init__(self, network_id: str = "") -> None:
        self.network_id = network_id
        self.authorizations: Dict[bytes, StandingState] = {}

    # -- admission -----------------------------------------------------------

    def can_create(self, terms: StandingTerms) -> Tuple[bool, str]:
        if self.network_id and terms.genesis_hash != self.network_id:
            return False, "authorization is bound to a different network"
        if terms.auth_id in self.authorizations:
            return False, "authorization already exists"
        open_for_payer = sum(
            1 for s in self.authorizations.values()
            if s.terms.payer == terms.payer and s.status == AUTH_ACTIVE
        )
        if open_for_payer >= MAX_OPEN_AUTHORIZATIONS_PER_PAYER:
            return False, (
                f"payer already has {MAX_OPEN_AUTHORIZATIONS_PER_PAYER} "
                "active authorizations"
            )
        return True, ""

    def create(self, terms: StandingTerms) -> bytes:
        ok, reason = self.can_create(terms)
        if not ok:
            raise PaymentShapeError(reason)
        self.authorizations[terms.auth_id] = StandingState(terms=terms)
        return terms.auth_id

    # -- queries -------------------------------------------------------------

    def get(self, auth_id: bytes) -> Optional[StandingState]:
        return self.authorizations.get(auth_id)

    def is_empty(self) -> bool:
        return not self.authorizations

    def paid_fact(self, auth_id: bytes, period_index: int) -> Optional[Dict[str, Any]]:
        """The "paid for this period" fact other rules can read (#34)."""
        state = self.authorizations.get(auth_id)
        if state is None:
            return None
        s = state.settled.get(period_index)
        if s is None:
            return None
        return {"paid": True, "amount": s.amount, "fee": s.fee,
                "period_index": period_index}

    # -- cancel ----------------------------------------------------------------

    def can_cancel(self, auth_id: bytes, signer: str) -> Tuple[bool, str]:
        """The shared admission/apply check for a cancel. `cancel` raises
        exactly these reasons, so the two paths cannot disagree."""
        state = self.authorizations.get(auth_id)
        if state is None:
            return False, "unknown authorization"
        if signer != state.terms.payer:
            return False, "only the payer may cancel an authorization"
        if state.status != AUTH_ACTIVE:
            return False, f"authorization is {state.status}"
        return True, ""

    def cancel(self, auth_id: bytes, signer: str) -> None:
        """Cancellation is a transition on the book, not a wallet setting.

        Once committed, admission and the sweep read the same state, so no
        later occurrence — including a missed one eligible for the signed
        catch-up term — can settle after it. Occurrences already settled in
        earlier blocks are untouched. A cancel/execute race is resolved by
        canonical block order: whichever transition is applied first wins.
        """
        ok, reason = self.can_cancel(auth_id, signer)
        if not ok:
            raise PaymentRefused(reason)
        self.authorizations[auth_id].status = AUTH_CANCELLED

    def has_due(self, ts: int) -> bool:
        """Miner wake hint (the RetractableBook.has_due shape): True when a
        sweep at `ts` would find an unresolved period to settle or skip --
        an over-approximation is fine, the sweep itself decides."""
        for state in self.authorizations.values():
            if state.status != AUTH_ACTIVE:
                continue
            terms = state.terms
            current = period_index_at(terms.period_kind, terms.start_ts, ts)
            if current < 0:
                continue
            for p in range(current + 1):
                if p in state.settled or p in state.skipped:
                    continue
                if terms.end_kind == END_DATE and period_bounds(
                    terms.period_kind, terms.start_ts, p
                )[0] >= terms.end_value:
                    continue
                return True
        return False

    # -- execution -------------------------------------------------------------

    def _check_execution(
        self, state: StandingState, period_index: int, ts: int,
        network_id: str, ledger: DictLedger, gate: PolicyGate,
        fees: FeeOracle,
    ) -> int:
        """Every execution check, in the design's fixed order. Returns the
        quoted fee. Raises PaymentRefused with the receipt reason.

        This ONE function backs both admission (`can_execute`) and apply
        (`execute_period` / the sweep), so the two cannot disagree for the
        same authorization state and order (#34 case 8).
        """
        terms = state.terms
        if state.status != AUTH_ACTIVE:
            raise PaymentRefused(f"authorization is {state.status}")
        if network_id and terms.genesis_hash != network_id:
            raise PaymentRefused("execution is bound to a different network")
        if period_index in state.settled:
            raise PaymentRefused("period already settled")
        if period_index in state.skipped:
            raise PaymentRefused("period was skipped")
        p_start, _ = period_bounds(terms.period_kind, terms.start_ts, period_index)
        if terms.end_kind == END_COUNT and state.completed_count >= terms.end_value:
            raise PaymentRefused("occurrence limit reached")
        if terms.end_kind == END_TOTAL and state.cumulative_spent + terms.amount > terms.end_value:
            raise PaymentRefused("cumulative cap would be exceeded")
        if terms.end_kind == END_DATE and p_start >= terms.end_value:
            raise PaymentRefused("authorization end date reached")
        if not gate.allows_debit(terms.payer, terms.payee, terms.amount):
            raise PaymentRefused("payer's current policy refuses this debit")
        fee = fees.execution_fee(terms.payer, terms.payee, terms.amount)
        if fee < 0 or fee > terms.max_fee_per_execution:
            raise PaymentRefused("execution fee exceeds the signed fee bound")
        if ledger.balance(terms.payer) < terms.amount + fee:
            # No debt, no partial debit, and the period marker does NOT
            # advance: the occurrence stays open for a later attempt.
            raise PaymentRefused("insufficient funds")
        return fee

    def can_execute(
        self, auth_id: bytes, period_index: int, ts: int, network_id: str,
        ledger: DictLedger, gate: PolicyGate, fees: FeeOracle,
    ) -> Tuple[bool, str]:
        """Admission-side verdict for one execution, window included."""
        state = self.authorizations.get(auth_id)
        if state is None:
            return False, "unknown authorization"
        p_start, p_end = period_bounds(
            state.terms.period_kind, state.terms.start_ts, period_index)
        if not (p_start <= ts < p_end):
            return False, "outside the execution window for this period"
        try:
            self._check_execution(state, period_index, ts, network_id,
                                  ledger, gate, fees)
        except PaymentRefused as exc:
            return False, exc.reason
        return True, ""

    def _settle(
        self, state: StandingState, period_index: int, ts: int,
        network_id: str, ledger: DictLedger, gate: PolicyGate,
        fees: FeeOracle,
    ) -> Settlement:
        fee = self._check_execution(state, period_index, ts, network_id,
                                    ledger, gate, fees)
        terms = state.terms
        ledger.debit(terms.payer, terms.amount + fee)
        ledger.credit(terms.payee, terms.amount)
        if fee:
            ledger.credit(FEE_SINK_PUBKEY, fee)
        settlement = Settlement(
            auth_id=terms.auth_id, period_index=period_index,
            payer=terms.payer, payee=terms.payee,
            amount=terms.amount, fee=fee,
        )
        state.settled[period_index] = settlement
        state.cumulative_spent += terms.amount
        self._refresh_completion(state)
        return settlement

    def _refresh_completion(self, state: StandingState) -> None:
        terms = state.terms
        if state.status != AUTH_ACTIVE:
            return
        if terms.end_kind == END_COUNT and state.completed_count >= terms.end_value:
            state.status = AUTH_COMPLETED
        elif terms.end_kind == END_TOTAL and (
            state.cumulative_spent >= terms.end_value
            or state.cumulative_spent + terms.amount > terms.end_value
        ):
            state.status = AUTH_COMPLETED

    def execute_period(
        self, auth_id: bytes, period_index: int, *, ts: int, network_id: str,
        ledger: DictLedger, gate: PolicyGate, fees: FeeOracle,
        caller: Optional[str] = None,
    ) -> Settlement:
        """The anyone-can-trigger fallback for the same book transition.

        `caller` is deliberately unchecked against payer/payee: any party
        may trigger execution, and no caller can alter the signed terms —
        this function takes no terms, only the authorization id.
        """
        state = self.authorizations.get(auth_id)
        if state is None:
            raise PaymentRefused("unknown authorization")
        p_start, p_end = period_bounds(
            state.terms.period_kind, state.terms.start_ts, period_index)
        if not (p_start <= ts < p_end):
            raise PaymentRefused("outside the execution window for this period")
        return self._settle(state, period_index, ts, network_id,
                            ledger, gate, fees)

    def sweep(
        self, *, ts: int, network_id: str, ledger: DictLedger,
        gate: PolicyGate, fees: FeeOracle,
    ) -> List[Settlement]:
        """Block-apply sweep: settle every due occurrence, in book-id order.

        Missed periods are skipped by default. When the authorization signs
        `max_catch_up`, the sweep settles at most that many of the most
        recent missed occurrences in this block; older missed periods are
        marked skipped. Each settled occurrence is policy-checked,
        fee-bounded and counted exactly once. A failed occurrence (funds or
        current policy) does not advance its marker and stops this
        authorization for this block; it is retried while its window is open
        and becomes a missed period afterwards.
        """
        out: List[Settlement] = []
        for auth_id in sorted(self.authorizations):
            state = self.authorizations[auth_id]
            if state.status != AUTH_ACTIVE:
                continue
            terms = state.terms
            current = period_index_at(terms.period_kind, terms.start_ts, ts)
            if current < 0:
                continue
            unresolved = [
                p for p in range(current + 1)
                if p not in state.settled and p not in state.skipped
            ]
            missed = [p for p in unresolved if p < current]
            due_now = [p for p in unresolved if p == current]
            if terms.end_kind == END_DATE:
                missed = [p for p in missed
                          if period_bounds(terms.period_kind, terms.start_ts, p)[0]
                          < terms.end_value]
                due_now = [p for p in due_now
                           if period_bounds(terms.period_kind, terms.start_ts, p)[0]
                           < terms.end_value]
            # Decide skips first: only the most recent `max_catch_up` missed
            # periods are settleable; the rest are skipped for good.
            settleable = missed[-terms.max_catch_up:] if terms.max_catch_up else []
            for p in missed:
                if p not in settleable:
                    state.skipped.add(p)
            blocked = False
            for p in settleable + due_now:
                try:
                    out.append(self._settle(state, p, ts, network_id,
                                            ledger, gate, fees))
                except PaymentRefused:
                    blocked = True
                    break
            if blocked:
                continue
            if terms.end_kind == END_DATE:
                cur_start = period_bounds(
                    terms.period_kind, terms.start_ts, current)[0]
                remaining = [
                    p for p in range(current + 1)
                    if p not in state.settled and p not in state.skipped
                    and period_bounds(terms.period_kind, terms.start_ts, p)[0]
                    < terms.end_value
                ]
                if cur_start >= terms.end_value and not remaining:
                    state.status = AUTH_COMPLETED
        return out

    # -- persistence / root ----------------------------------------------------

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        rows = []
        for auth_id in sorted(self.authorizations):
            s = self.authorizations[auth_id]
            rows.append({
                "terms": s.terms.to_dict(),
                "status": s.status,
                "settled": {
                    str(p): {"amount": st.amount, "fee": st.fee}
                    for p, st in sorted(s.settled.items())
                },
                "skipped": sorted(s.skipped),
                "cumulative_spent": s.cumulative_spent,
            })
        return rows

    @classmethod
    def restore(cls, rows: List[Dict[str, Any]], network_id: str = "") -> "StandingBook":
        book = cls(network_id=network_id)
        for row in rows:
            terms = StandingTerms.from_dict(row["terms"])
            state = StandingState(terms=terms, status=row["status"])
            for p, st in row["settled"].items():
                idx = int(p)
                state.settled[idx] = Settlement(
                    auth_id=terms.auth_id, period_index=idx,
                    payer=terms.payer, payee=terms.payee,
                    amount=st["amount"], fee=st["fee"])
            state.skipped = set(row["skipped"])
            state.cumulative_spent = row["cumulative_spent"]
            if terms.auth_id in book.authorizations:
                raise ValueError("duplicate authorization in snapshot rows")
            book.authorizations[terms.auth_id] = state
        return book

    def root_blobs(self) -> List[bytes]:
        blobs = []
        for row in self.snapshot_rows():
            terms = StandingTerms.from_dict(row["terms"])
            blobs.append(terms.auth_id + canonical_json(row))
        return blobs


# --- Receive routing (#35) -----------------------------------------------------


@dataclass(frozen=True)
class RouteTerms:
    """A recipient-installed receive route: up to 4 destinations, each a
    basis-point share of every routable credit. The total is validated at
    INSTALL time (sum <= 10,000 bps), never left to apply-time luck."""

    owner: str
    destinations: Tuple[Tuple[str, int], ...]
    locked: bool = False
    expires_ts: Optional[int] = None
    sequence_number: int = 0

    def __post_init__(self) -> None:
        _pubkey(self.owner, "owner")
        if not (1 <= len(self.destinations) <= MAX_ROUTE_DESTINATIONS):
            raise PaymentShapeError(
                f"a route has 1..{MAX_ROUTE_DESTINATIONS} destinations"
            )
        seen = set()
        total = 0
        for dest, bps in self.destinations:
            _pubkey(dest, "route destination")
            if dest == self.owner:
                raise PaymentShapeError("a route destination must differ from the owner")
            if dest in seen:
                raise PaymentShapeError("duplicate route destination")
            seen.add(dest)
            if not _is_int(bps) or not (1 <= bps <= 10_000):
                raise PaymentShapeError("destination share must be in 1..10000 bps")
            total += bps
        if total > 10_000:
            raise PaymentShapeError(
                "route shares sum to more than 10000 bps (over-100% route set)"
            )
        if self.locked and self.expires_ts is None:
            raise PaymentShapeError("a locked route must carry an expiry")
        if self.expires_ts is not None:
            _u64(self.expires_ts, "expires_ts")
        _u64(self.sequence_number, "sequence_number")

    @property
    def route_id(self) -> bytes:
        out = bytearray()
        out.extend(encode_pubkey48(self.owner))
        for dest, bps in self.destinations:
            out.extend(encode_pubkey48(dest))
            out.extend(encode_uint64(bps))
        out.extend(encode_uint64(self.expires_ts or 0))
        out.extend(encode_uint64(1 if self.locked else 0))
        out.extend(encode_uint64(self.sequence_number))
        return compute_payment_entry_id("tau.payment.route.v1", bytes(out))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner": self.owner,
            "destinations": [[d, b] for d, b in self.destinations],
            "locked": self.locked, "expires_ts": self.expires_ts,
            "sequence_number": self.sequence_number,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "RouteTerms":
        return cls(
            owner=d["owner"],
            destinations=tuple((dest, bps) for dest, bps in d["destinations"]),
            locked=d["locked"], expires_ts=d["expires_ts"],
            sequence_number=d["sequence_number"],
        )


@dataclass(frozen=True)
class RouteReceipt:
    """The distinct routing receipt in history (#35 case 6): gross, net,
    routed legs and the single fee, all visible."""

    owner: str
    gross: int
    net: int
    legs: Tuple[Tuple[str, int], ...]
    fee: int
    routed: bool


class RouteBook:
    """One receive route per account, keyed by owner."""

    def __init__(self) -> None:
        self.routes: Dict[str, RouteTerms] = {}

    def is_empty(self) -> bool:
        return not self.routes

    def get(self, owner: str) -> Optional[RouteTerms]:
        return self.routes.get(owner)

    def _cycle_reason(self, terms: RouteTerms) -> Optional[str]:
        # Recursive routing is rejected at install: no destination of this
        # route may itself route back to this owner. (Apply-time chaining is
        # separately impossible — routed legs are final-class, see below.)
        for dest, _ in terms.destinations:
            dest_route = self.routes.get(dest)
            if dest_route is not None and any(
                d == terms.owner for d, _ in dest_route.destinations
            ):
                return "route would close a routing cycle"
        return None

    def can_install(self, terms: RouteTerms) -> Tuple[bool, str]:
        if terms.owner in self.routes:
            return False, "account already has a route; remove it first"
        if len(self.routes) >= MAX_ROUTES_TOTAL:
            return False, "route book is full"
        reason = self._cycle_reason(terms)
        if reason:
            return False, reason
        return True, ""

    def install(self, terms: RouteTerms) -> bytes:
        ok, reason = self.can_install(terms)
        if not ok:
            raise PaymentShapeError(reason)
        self.routes[terms.owner] = terms
        return terms.route_id

    def can_update(self, terms: RouteTerms, signer: str, ts: int) -> Tuple[bool, str]:
        """Replacing a route is removal + install as ONE transition: the old
        route's lock binds the update exactly as it binds a removal, and the
        new terms pass the install checks against the book with the owner's
        own route disregarded (it is the thing being replaced)."""
        if terms.owner not in self.routes:
            return False, "no route installed; install one first"
        ok, reason = self.can_remove(terms.owner, signer, ts)
        if not ok:
            return False, reason
        reason = self._cycle_reason(terms)
        if reason:
            return False, reason
        return True, ""

    def update(self, terms: RouteTerms, signer: str, ts: int) -> bytes:
        ok, reason = self.can_update(terms, signer, ts)
        if not ok:
            raise PaymentRefused(reason)
        self.routes[terms.owner] = terms
        return terms.route_id

    def can_remove(self, owner: str, signer: str, ts: int) -> Tuple[bool, str]:
        terms = self.routes.get(owner)
        if terms is None:
            return False, "no route installed"
        if signer != owner:
            return False, "only the owner may remove a route"
        if terms.locked and terms.expires_ts is not None and ts < terms.expires_ts:
            # Binding for its term (#35, scoped form of case 5): the
            # recipient alone cannot remove a locked route early. #33
            # protected policy-admin is not on this HEAD and is NOT claimed;
            # the lock lives in this book, not in wallet policy.
            return False, "route is locked until its expiry"
        return True, ""

    def remove(self, owner: str, signer: str, ts: int) -> None:
        ok, reason = self.can_remove(owner, signer, ts)
        if not ok:
            raise PaymentRefused(reason)
        del self.routes[owner]

    def split_for_credit(
        self, recipient: str, gross: int, credit_class: str, ts: int,
    ) -> Tuple[int, Tuple[Tuple[str, int], ...]]:
        """The (net, legs) split of one credit under the recipient's route.

        Pure arithmetic — no ledger movement, nothing raised. Splits are
        floor-rounded per leg and the recipient keeps the remainder, so
        net + sum(legs) == gross exactly. A class outside
        ROUTABLE_CREDIT_CLASSES, a missing route and an expired route all
        split to (gross, ()): the full credit lands on the recipient.

        `apply_credit` is the enforcement entry point for credits that
        still sit in the sender's balance. The engine's retractable-
        release path uses THIS split directly: a released payment's funds
        already left the sender at park time and sit in the retractable
        book's escrow, so there is nothing left to debit — but the split
        the recipient's route prescribes is the same one.
        """
        terms = self.routes.get(recipient)
        routable = (
            terms is not None
            and credit_class in ROUTABLE_CREDIT_CLASSES
            and (terms.expires_ts is None or ts < terms.expires_ts)
        )
        legs: Tuple[Tuple[str, int], ...] = ()
        if routable:
            legs = tuple(
                (dest, gross * bps // 10_000) for dest, bps in terms.destinations
            )
        return gross - sum(amount for _, amount in legs), legs

    def apply_credit(
        self, sender: str, recipient: str, gross: int, credit_class: str,
        *, fee: int, ledger: DictLedger, ts: int,
    ) -> RouteReceipt:
        """Move one credit from sender to recipient, splitting per the
        recipient's route when the class is routable.

        The sender signs/sends only the gross; the split is atomic (all
        legs or none — every check precedes every movement); exactly ONE
        fee is charged, to the sender, for the whole credit. Splits are
        floor-rounded per leg; the recipient keeps the remainder. A routed
        leg is final-class: it is credited directly and NEVER triggers the
        destination's own route (single hop, structurally — this function
        does not recurse). The recipient wallet need not be online: routing
        is a property of this book, not of any wallet process.
        """
        _amount(gross, "gross")
        if fee < 0:
            raise PaymentShapeError("fee must be non-negative")
        if ledger.balance(sender) < gross + fee:
            raise PaymentRefused("insufficient funds")
        net, legs = self.split_for_credit(recipient, gross, credit_class, ts)
        ledger.debit(sender, gross + fee)
        if fee:
            ledger.credit(FEE_SINK_PUBKEY, fee)
        ledger.credit(recipient, net)
        for dest, amount in legs:
            if amount:
                ledger.credit(dest, amount)
        return RouteReceipt(
            owner=recipient, gross=gross, net=net, legs=legs,
            fee=fee, routed=bool(legs),
        )

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        return [self.routes[owner].to_dict() for owner in sorted(self.routes)]

    @classmethod
    def restore(cls, rows: List[Dict[str, Any]]) -> "RouteBook":
        book = cls()
        for row in rows:
            terms = RouteTerms.from_dict(row)
            if terms.owner in book.routes:
                raise ValueError("duplicate route owner in snapshot rows")
            book.routes[terms.owner] = terms
        return book

    def root_blobs(self) -> List[bytes]:
        return [
            self.routes[owner].route_id + canonical_json(self.routes[owner].to_dict())
            for owner in sorted(self.routes)
        ]


# --- Rule-computed payouts (#63) -----------------------------------------------
#
# THE PAYOUT OUTPUT CONVENTION (this design's one new consensus surface,
# design question (a) -- the encoding chosen here, from this codebase's own
# stream idioms). The rule's clause is part of its signed terms. At
# execution the node steps that clause ONCE in its isolated evaluator pool
# (the same facility that steps o5 policy clauses), feeding one value per
# input stream and reading the legs from the step's output streams:
#
#   inputs   i1  = the execution's gross amount (the slot a transfer's
#                  amount rides, so a clause reads it the same way)
#            i3  = the rule owner's pubkey, as a bv[384] literal (the
#                  debited account, in the slot transfers use for the
#                  paying account)
#            i5  = the block timestamp (the consensus clock slot)
#            i12 = the executor's pubkey, as a bv[384] literal (the
#                  node-injected transaction-sender slot)
#            i13 = the settlement fingerprint: the first 8 bytes of
#                  blake3(event_id) as a decimal integer -- the first user
#                  custom stream, so a rule may vary its legs per
#                  settlement without the book interpreting event ids
#   outputs  o30 = the leg count N (0..MAX_PAYOUT_CANDIDATES)
#            o(31 + 2k) = leg k's candidate index, o(32 + 2k) = its
#                  amount, for k in 0..N-1 -- the leg streams o31..o46
#
# Streams 30..46 are unassigned in this codebase (the assigned outputs are
# the core/consensus/user streams o1..o9) and a payout clause is stepped in
# isolation, never merged into the accumulated spec, so the layout cannot
# collide with another rule's streams. Leg values are bv[64] quantities,
# decoded with the fee layer's strict Tau-int decode: an absent count, an
# absent pair member, an undecodable or negative value, or a count above
# the bound makes the clause output MALFORMED and refuses the whole
# execution -- the rule can settle nothing with a broken answer. The
# engine's evaluator adapter (consensus/engine.py) owns the stepping and
# the decode; in this layer the clause is an injected callable and the
# BOOK enforces everything around its outputs — candidate set,
# per-candidate caps, per-execution and per-period caps, owner balance,
# atomicity, pays-once.
PAYOUT_INPUT_GROSS_STREAM = 1
PAYOUT_INPUT_OWNER_STREAM = 3
PAYOUT_INPUT_TIMESTAMP_STREAM = 5
PAYOUT_INPUT_EXECUTOR_STREAM = 12
PAYOUT_INPUT_SETTLEMENT_STREAM = 13
PAYOUT_OUTPUT_COUNT_STREAM = 30
PAYOUT_OUTPUT_LEG_BASE_STREAM = 31
MAX_PAYOUT_LEGS = MAX_PAYOUT_CANDIDATES
MAX_PAYOUT_CLAUSE_BYTES = 8192   # the rule-offer bound, reused

# The payout clause seam: the callable the engine's evaluator adapter
# hands the book. It receives the execution context the book builds --
# {"gross": int, "event_id": str} -- and returns (candidate_index,
# amount) legs, or raises PaymentRefused when the clause cannot be
# evaluated or its output is malformed.
PayoutClause = Callable[[Dict[str, Any]], List[Tuple[int, int]]]


@dataclass(frozen=True)
class PayoutTerms:
    """An installed payout rule: the owner signs a bounded candidate list
    (<= 8 accounts, each with its own cap) AND the Tau clause body that
    computes the legs. The rule may pay ONLY listed candidates; the clause
    selects WHICH of them, and how much, per execution."""

    owner: str
    candidates: Tuple[Tuple[str, int], ...]   # (pubkey, per-candidate cap)
    max_per_execution: int
    max_per_period: int
    period_kind: str = "week"
    anchor_ts: int = 0
    sequence_number: int = 0
    # The clause BODY (the text inside `always ( ... ).`), in the same
    # form the clause registry stores for an o5 clause. It is part of the
    # signed terms: the rule_id commits to it, and execution steps exactly
    # this text. Empty until install screens it (see can_install).
    clause: str = ""

    def __post_init__(self) -> None:
        _pubkey(self.owner, "owner")
        if not (1 <= len(self.candidates) <= MAX_PAYOUT_CANDIDATES):
            raise PaymentShapeError(
                f"a payout rule has 1..{MAX_PAYOUT_CANDIDATES} candidates"
            )
        seen = set()
        for cand, cap in self.candidates:
            _pubkey(cand, "payout candidate")
            if cand in seen:
                raise PaymentShapeError("duplicate payout candidate")
            seen.add(cand)
            _amount(cap, "candidate cap")
        _amount(self.max_per_execution, "max_per_execution")
        _amount(self.max_per_period, "max_per_period")
        if self.period_kind not in PERIOD_KINDS:
            raise PaymentShapeError(f"unknown period kind: {self.period_kind!r}")
        _u64(self.anchor_ts, "anchor_ts")
        _u64(self.sequence_number, "sequence_number")
        if not isinstance(self.clause, str):
            raise PaymentShapeError("payout clause must be text")
        if len(self.clause.encode("utf-8")) > MAX_PAYOUT_CLAUSE_BYTES:
            raise PaymentShapeError(
                f"payout clause exceeds {MAX_PAYOUT_CLAUSE_BYTES} bytes"
            )

    @property
    def rule_id(self) -> bytes:
        out = bytearray()
        out.extend(encode_pubkey48(self.owner))
        for cand, cap in self.candidates:
            out.extend(encode_pubkey48(cand))
            out.extend(encode_uint64(cap))
        out.extend(encode_uint64(self.max_per_execution))
        out.extend(encode_uint64(self.max_per_period))
        out.extend(encode_string(self.period_kind))
        out.extend(encode_uint64(self.anchor_ts))
        out.extend(encode_uint64(self.sequence_number))
        out.extend(encode_string(self.clause))
        return compute_payment_entry_id("tau.payment.payout_rule.v1", bytes(out))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "owner": self.owner,
            "candidates": [[c, cap] for c, cap in self.candidates],
            "max_per_execution": self.max_per_execution,
            "max_per_period": self.max_per_period,
            "period_kind": self.period_kind, "anchor_ts": self.anchor_ts,
            "sequence_number": self.sequence_number,
            "clause": self.clause,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "PayoutTerms":
        return cls(
            owner=d["owner"],
            candidates=tuple((c, cap) for c, cap in d["candidates"]),
            max_per_execution=d["max_per_execution"],
            max_per_period=d["max_per_period"],
            period_kind=d["period_kind"], anchor_ts=d["anchor_ts"],
            sequence_number=d["sequence_number"],
            clause=d.get("clause", ""),
        )


@dataclass(frozen=True)
class PayoutReceipt:
    rule_id: bytes
    event_id: str
    legs: Tuple[Tuple[str, int], ...]   # resolved (pubkey, amount)
    total: int


@dataclass
class PayoutState:
    terms: PayoutTerms
    settled_events: Dict[str, PayoutReceipt] = field(default_factory=dict)
    period_spent: Dict[int, int] = field(default_factory=dict)


class PayoutBook:
    def __init__(self) -> None:
        self.rules: Dict[bytes, PayoutState] = {}

    def is_empty(self) -> bool:
        return not self.rules

    def get(self, rule_id: bytes) -> Optional[PayoutState]:
        return self.rules.get(rule_id)

    def can_install(self, terms: PayoutTerms) -> Tuple[bool, str]:
        """The shared admission/apply check for installing a rule;
        `install` raises exactly these reasons."""
        if not terms.clause.strip():
            return False, "payout rule carries no clause body"
        if terms.rule_id in self.rules:
            return False, "payout rule already exists"
        owned = sum(1 for s in self.rules.values() if s.terms.owner == terms.owner)
        if owned >= MAX_PAYOUT_RULES_PER_OWNER:
            return False, (
                f"owner already has {MAX_PAYOUT_RULES_PER_OWNER} payout rules"
            )
        return True, ""

    def install(self, terms: PayoutTerms) -> bytes:
        ok, reason = self.can_install(terms)
        if not ok:
            raise PaymentShapeError(reason)
        self.rules[terms.rule_id] = PayoutState(terms=terms)
        return terms.rule_id

    def _plan_execution(
        self, state: PayoutState, event_id: str, gross: int,
        clause: PayoutClause, *, ts: int, ledger: DictLedger,
    ) -> Tuple[List[Tuple[str, int]], int, int]:
        """Every execution check, in order; returns (legs, total, period).

        This ONE plan backs both admission (`can_execute`) and apply
        (`execute`), so the two cannot disagree. It runs the clause on the
        execution context ({"gross", "event_id"}): the clause is a pure
        evaluation by contract, so planning an execution settles nothing
        and records nothing.
        """
        terms = state.terms
        if not isinstance(event_id, str) or not event_id:
            raise PaymentShapeError("event_id must be a non-empty string")
        _amount(gross, "gross")
        if event_id in state.settled_events:
            raise PaymentRefused("event already settled")
        raw_legs = clause({"gross": gross, "event_id": event_id})
        if not isinstance(raw_legs, (list, tuple)):
            raise PaymentRefused("payout clause output is not a leg list")
        per_candidate: Dict[int, int] = {}
        for leg in raw_legs:
            if not isinstance(leg, (list, tuple)) or len(leg) != 2:
                raise PaymentRefused("payout clause leg is not an (index, amount) pair")
            index, amount = leg
            if not _is_int(index) or not (0 <= index < len(terms.candidates)):
                # The rule named an account outside the signed candidate
                # set. Nothing settles.
                raise PaymentRefused("payout leg names an undeclared candidate")
            if not _is_int(amount) or amount <= 0:
                raise PaymentRefused("payout leg amount must be positive")
            per_candidate[index] = per_candidate.get(index, 0) + amount
        legs: List[Tuple[str, int]] = []
        total = 0
        for index in sorted(per_candidate):
            pubkey, cap = terms.candidates[index]
            amount = per_candidate[index]
            if amount > cap:
                raise PaymentRefused("payout leg exceeds the candidate cap")
            legs.append((pubkey, amount))
            total += amount
        if total <= 0:
            raise PaymentRefused("payout settles nothing")
        if total > terms.max_per_execution:
            raise PaymentRefused("payout exceeds the per-execution cap")
        period = period_index_at(terms.period_kind, terms.anchor_ts, ts)
        if period < 0:
            raise PaymentRefused("payout before the rule's anchor")
        if state.period_spent.get(period, 0) + total > terms.max_per_period:
            raise PaymentRefused("payout exceeds the per-period cap")
        if ledger.balance(terms.owner) < total:
            raise PaymentRefused("insufficient funds")
        return legs, total, period

    def can_execute(
        self, rule_id: bytes, event_id: str, gross: int,
        clause: PayoutClause, *, ts: int, ledger: DictLedger,
    ) -> Tuple[bool, str]:
        """Admission-side verdict for one payout execution."""
        state = self.rules.get(rule_id)
        if state is None:
            return False, "unknown payout rule"
        try:
            self._plan_execution(state, event_id, gross, clause,
                                 ts=ts, ledger=ledger)
        except (PaymentRefused, PaymentShapeError) as exc:
            return False, str(exc)
        return True, ""

    def execute(
        self, rule_id: bytes, event_id: str, gross: int,
        clause: PayoutClause, *, ts: int, ledger: DictLedger,
    ) -> PayoutReceipt:
        """Run one payout execution. Pays ONCE per event: the event
        identifier is recorded in the book at settlement, and a replayed
        execution submission is refused as already-settled, never re-run.

        Atomic-or-none: every leg is validated (candidate set, per-candidate
        caps, per-execution cap, per-period cap, owner balance) BEFORE any
        balance moves, so a failing leg settles nothing.
        """
        state = self.rules.get(rule_id)
        if state is None:
            raise PaymentRefused("unknown payout rule")
        legs, total, period = self._plan_execution(
            state, event_id, gross, clause, ts=ts, ledger=ledger)
        terms = state.terms
        ledger.debit(terms.owner, total)
        for pubkey, amount in legs:
            ledger.credit(pubkey, amount)
        receipt = PayoutReceipt(
            rule_id=rule_id, event_id=event_id,
            legs=tuple(legs), total=total,
        )
        state.settled_events[event_id] = receipt
        state.period_spent[period] = state.period_spent.get(period, 0) + total
        return receipt

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        rows = []
        for rule_id in sorted(self.rules):
            s = self.rules[rule_id]
            rows.append({
                "terms": s.terms.to_dict(),
                "settled_events": {
                    eid: {"legs": [[p, a] for p, a in r.legs], "total": r.total}
                    for eid, r in sorted(s.settled_events.items())
                },
                "period_spent": {str(k): v for k, v in sorted(s.period_spent.items())},
            })
        return rows

    @classmethod
    def restore(cls, rows: List[Dict[str, Any]]) -> "PayoutBook":
        book = cls()
        for row in rows:
            terms = PayoutTerms.from_dict(row["terms"])
            state = PayoutState(terms=terms)
            for eid, r in row["settled_events"].items():
                state.settled_events[eid] = PayoutReceipt(
                    rule_id=terms.rule_id, event_id=eid,
                    legs=tuple((p, a) for p, a in r["legs"]), total=r["total"])
            state.period_spent = {int(k): v for k, v in row["period_spent"].items()}
            if terms.rule_id in book.rules:
                raise ValueError("duplicate payout rule in snapshot rows")
            book.rules[terms.rule_id] = state
        return book

    def root_blobs(self) -> List[bytes]:
        blobs = []
        for row in self.snapshot_rows():
            terms = PayoutTerms.from_dict(row["terms"])
            blobs.append(terms.rule_id + canonical_json(row))
        return blobs


# --- Conditional grants and shared caps (stages 2, 4, 5) -----------------------


@dataclass(frozen=True)
class GrantTerms:
    """A conditional grant: the grantor escrows principal into the book;
    the grantee may draw against it under per-period caps from `start_ts`;
    whatever is unspent at `expires_ts` refunds to `refund_to` (default the
    grantor). The conditions live in this book — not in the grantee's wallet
    policy — so no key the conditions restrict can remove them."""

    grantor: str
    grantee: str
    principal: int
    period_cap: int
    period_kind: str
    start_ts: int
    expires_ts: int                       # required: a grant has a deadline
    max_fee_per_execution: int
    per_payment_cap: Optional[int] = None
    shared_cap: bool = False              # draw against the payer-level cap
    refund_to: Optional[str] = None       # default: the grantor
    sequence_number: int = 0

    def __post_init__(self) -> None:
        _pubkey(self.grantor, "grantor")
        _pubkey(self.grantee, "grantee")
        _amount(self.principal, "principal")
        _amount(self.period_cap, "period_cap")
        if self.period_kind not in PERIOD_KINDS:
            raise PaymentShapeError(f"unknown period kind: {self.period_kind!r}")
        _u64(self.start_ts, "start_ts")
        _u64(self.expires_ts, "expires_ts")
        if self.expires_ts <= self.start_ts:
            raise PaymentShapeError("a grant's deadline must be after its start")
        _u64(self.max_fee_per_execution, "max_fee_per_execution")
        if self.per_payment_cap is not None:
            _amount(self.per_payment_cap, "per_payment_cap")
        if self.refund_to is not None:
            _pubkey(self.refund_to, "refund_to")
        _u64(self.sequence_number, "sequence_number")

    @property
    def refund_recipient(self) -> str:
        return self.refund_to or self.grantor

    @property
    def grant_id(self) -> bytes:
        out = bytearray()
        out.extend(encode_pubkey48(self.grantor))
        out.extend(encode_pubkey48(self.grantee))
        out.extend(encode_uint64(self.principal))
        out.extend(encode_uint64(self.period_cap))
        out.extend(encode_string(self.period_kind))
        out.extend(encode_uint64(self.start_ts))
        out.extend(encode_uint64(self.expires_ts))
        out.extend(encode_uint64(self.sequence_number))
        return compute_payment_entry_id("tau.payment.grant.v1", bytes(out))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "grantor": self.grantor, "grantee": self.grantee,
            "principal": self.principal, "period_cap": self.period_cap,
            "period_kind": self.period_kind, "start_ts": self.start_ts,
            "expires_ts": self.expires_ts,
            "max_fee_per_execution": self.max_fee_per_execution,
            "per_payment_cap": self.per_payment_cap,
            "shared_cap": self.shared_cap, "refund_to": self.refund_to,
            "sequence_number": self.sequence_number,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "GrantTerms":
        return cls(**{k: d[k] for k in (
            "grantor", "grantee", "principal", "period_cap", "period_kind",
            "start_ts", "expires_ts", "max_fee_per_execution",
            "per_payment_cap", "shared_cap", "refund_to", "sequence_number")})


@dataclass
class GrantState:
    terms: GrantTerms
    status: str = GRANT_ACTIVE
    held: int = 0
    drawn_total: int = 0
    refunded: int = 0
    refund_fee_paid: int = 0
    period_drawn: Dict[int, int] = field(default_factory=dict)


@dataclass(frozen=True)
class RefundRecord:
    grant_id: bytes
    to: str
    amount: int
    fee: int


@dataclass
class SharedCapState:
    """ONE book-level counter per payer for the shared cumulative cap. The
    counter is deliberately not per-authorization and not per-grant: a
    shared cap counted once per grant is not a shared cap (the 108-history
    check exists to prove exactly that)."""

    limit: int
    spent: int = 0


class GrantBook:
    def __init__(self) -> None:
        self.grants: Dict[bytes, GrantState] = {}
        self.shared_caps: Dict[str, SharedCapState] = {}

    def is_empty(self) -> bool:
        return not self.grants and not self.shared_caps

    def get(self, grant_id: bytes) -> Optional[GrantState]:
        return self.grants.get(grant_id)

    # -- shared cap ------------------------------------------------------------

    def can_set_shared_cap(self, payer: str, limit: int) -> Tuple[bool, str]:
        """The shared admission/apply check for registering a shared cap;
        `set_shared_cap` raises exactly these reasons."""
        try:
            _pubkey(payer, "payer")
            _amount(limit, "shared cap limit")
        except PaymentShapeError as exc:
            return False, str(exc)
        if payer in self.shared_caps:
            return False, "shared cap already registered for this payer"
        return True, ""

    def set_shared_cap(self, payer: str, limit: int) -> None:
        """The payer signs ONE shared cumulative cap across their grants
        (and authorizations) that opt into it."""
        ok, reason = self.can_set_shared_cap(payer, limit)
        if not ok:
            raise PaymentShapeError(reason)
        self.shared_caps[payer] = SharedCapState(limit=limit)

    def shared_cap_state(self, payer: str) -> Optional[SharedCapState]:
        return self.shared_caps.get(payer)

    # -- grant lifecycle ---------------------------------------------------------

    def _check_create(self, terms: GrantTerms, *, ledger: DictLedger) -> None:
        """Every create check, raising the refusal/shape error itself.

        This ONE check backs both admission (`can_create`) and apply
        (`create`), so the two cannot disagree.
        """
        if terms.grant_id in self.grants:
            raise PaymentShapeError("grant already exists")
        open_for = sum(
            1 for s in self.grants.values()
            if s.terms.grantor == terms.grantor and s.status == GRANT_ACTIVE
        )
        if open_for >= MAX_OPEN_GRANTS_PER_GRANTOR:
            raise PaymentShapeError(
                f"grantor already has {MAX_OPEN_GRANTS_PER_GRANTOR} active grants"
            )
        if terms.shared_cap and terms.grantor not in self.shared_caps:
            raise PaymentShapeError(
                "grant opts into a shared cap the payer has not registered"
            )
        if ledger.balance(terms.grantor) < terms.principal:
            raise PaymentRefused("insufficient funds to escrow the grant")

    def can_create(
        self, terms: GrantTerms, *, ledger: DictLedger
    ) -> Tuple[bool, str]:
        """Admission-side verdict for creating a grant."""
        try:
            self._check_create(terms, ledger=ledger)
        except (PaymentRefused, PaymentShapeError) as exc:
            return False, str(exc)
        return True, ""

    def create(self, terms: GrantTerms, *, ledger: DictLedger) -> bytes:
        self._check_create(terms, ledger=ledger)
        ledger.debit(terms.grantor, terms.principal)
        ledger.credit(GRANT_ESCROW_PUBKEY, terms.principal)
        self.grants[terms.grant_id] = GrantState(terms=terms, held=terms.principal)
        return terms.grant_id

    def _check_draw(
        self, state: GrantState, amount: int, *, ts: int, ledger: DictLedger,
    ) -> Tuple[int, Optional[SharedCapState]]:
        """Every draw check, in order; returns (period, shared cap state).

        This ONE check backs both admission (`can_draw`) and apply (`draw`),
        so the two cannot disagree. The escrow-balance check is the book's
        own: the escrow account is credited only by `create`, so its balance
        covers the held principal by construction.
        """
        terms = state.terms
        if state.status != GRANT_ACTIVE:
            raise PaymentRefused(f"grant is {state.status}")
        if not _is_int(amount) or amount <= 0:
            raise PaymentRefused("draw amount must be positive")
        if ts < terms.start_ts:
            raise PaymentRefused("grant has not started")
        if ts >= terms.expires_ts:
            raise PaymentRefused("grant deadline has passed; draws are closed")
        if terms.per_payment_cap is not None and amount > terms.per_payment_cap:
            raise PaymentRefused("draw exceeds the per-payment cap")
        period = period_index_at(terms.period_kind, terms.start_ts, ts)
        if state.period_drawn.get(period, 0) + amount > terms.period_cap:
            raise PaymentRefused("draw exceeds the per-period cap")
        if amount > state.held:
            raise PaymentRefused("draw exceeds the remaining principal")
        shared = None
        if terms.shared_cap:
            shared = self.shared_caps[terms.grantor]
            if shared.spent + amount > shared.limit:
                raise PaymentRefused("draw exceeds the payer's shared cap")
        if ledger.balance(GRANT_ESCROW_PUBKEY) < amount:
            raise PaymentRefused("insufficient escrowed funds")
        return period, shared

    def can_draw(
        self, grant_id: bytes, amount: int, *, ts: int, ledger: DictLedger,
    ) -> Tuple[bool, str]:
        """Admission-side verdict for one draw."""
        state = self.grants.get(grant_id)
        if state is None:
            return False, "unknown grant"
        try:
            self._check_draw(state, amount, ts=ts, ledger=ledger)
        except PaymentRefused as exc:
            return False, exc.reason
        return True, ""

    def draw(
        self, grant_id: bytes, amount: int, *, ts: int, ledger: DictLedger,
    ) -> int:
        """Draw against a grant. Every applicable cap must have headroom:
        per-payment cap, per-period cap, remaining principal, and — when the
        grant opts in — the payer's ONE shared counter, incremented exactly
        once per successful draw."""
        state = self.grants.get(grant_id)
        if state is None:
            raise PaymentRefused("unknown grant")
        terms = state.terms
        period, shared = self._check_draw(state, amount, ts=ts, ledger=ledger)
        ledger.debit(GRANT_ESCROW_PUBKEY, amount)
        ledger.credit(terms.grantee, amount)
        state.held -= amount
        state.drawn_total += amount
        state.period_drawn[period] = state.period_drawn.get(period, 0) + amount
        if shared is not None:
            shared.spent += amount
        return amount

    def _refund_one(
        self, state: GrantState, *, ts: int, ledger: DictLedger,
        fees: FeeOracle,
    ) -> Optional[RefundRecord]:
        """Refund one grant whose deadline has passed; None when not due.

        The single refund transition: the block sweep and an explicit
        refund claim both run exactly this, so they cannot disagree.
        """
        if state.status != GRANT_ACTIVE or ts < state.terms.expires_ts:
            return None
        terms = state.terms
        amount = state.held
        fee_paid = 0
        if amount:
            ledger.debit(GRANT_ESCROW_PUBKEY, amount)
            ledger.credit(terms.refund_recipient, amount)
            quoted = fees.execution_fee(
                terms.grantor, terms.refund_recipient, amount)
            fee_due = max(0, min(quoted, terms.max_fee_per_execution))
            if fee_due and ledger.balance(terms.grantor) >= fee_due:
                ledger.debit(terms.grantor, fee_due)
                ledger.credit(FEE_SINK_PUBKEY, fee_due)
                fee_paid = fee_due
        state.held = 0
        state.refunded = amount
        state.refund_fee_paid = fee_paid
        state.status = GRANT_CLOSED
        return RefundRecord(
            grant_id=terms.grant_id, to=terms.refund_recipient,
            amount=amount, fee=fee_paid)

    def sweep_refunds(
        self, *, ts: int, ledger: DictLedger, fees: FeeOracle,
    ) -> List[RefundRecord]:
        """At the deadline, unspent principal returns to the refund
        recipient, exactly once, in the same block-apply sweep as standing
        executions. The refund amount is NOT netted: the refund's fee is
        charged to the grantor separately, bounded by the grant's signed
        `max_fee_per_execution` (addendum correction on case 5). A refund is
        never blocked by the fee: if the grantor cannot cover it, the
        refund proceeds and the fee is recorded as unpaid (0)."""
        out: List[RefundRecord] = []
        for grant_id in sorted(self.grants):
            record = self._refund_one(
                self.grants[grant_id], ts=ts, ledger=ledger, fees=fees)
            if record is not None:
                out.append(record)
        return out

    def can_claim_refund(self, grant_id: bytes, ts: int) -> Tuple[bool, str]:
        """The shared admission/apply check for a refund claim;
        `claim_refund` raises exactly these reasons."""
        state = self.grants.get(grant_id)
        if state is None:
            return False, "unknown grant"
        if state.status != GRANT_ACTIVE:
            return False, f"grant is {state.status}"
        if ts < state.terms.expires_ts:
            return False, "grant deadline has not passed; the refund is not due"
        return True, ""

    def claim_refund(
        self, grant_id: bytes, *, ts: int, ledger: DictLedger,
        fees: FeeOracle,
    ) -> RefundRecord:
        """The anyone-can-trigger fallback for the sweep's refund: the same
        transition `_refund_one` runs in the sweep, claimed explicitly.
        Whoever triggers it cannot alter the amount, the recipient or the
        fee bound — all three come from the signed terms."""
        ok, reason = self.can_claim_refund(grant_id, ts)
        if not ok:
            raise PaymentRefused(reason)
        record = self._refund_one(
            self.grants[grant_id], ts=ts, ledger=ledger, fees=fees)
        if record is None:  # can_claim_refund just established due-ness
            raise PaymentRefused("grant deadline has not passed; the refund is not due")
        return record

    def has_due(self, ts: int) -> bool:
        """Miner wake hint: True when a sweep at `ts` would refund a grant."""
        return any(
            state.status == GRANT_ACTIVE and ts >= state.terms.expires_ts
            for state in self.grants.values()
        )

    def accounting(self, grant_id: bytes) -> Dict[str, int]:
        """principal == drawn + held + refunded, at all times."""
        state = self.grants.get(grant_id)
        if state is None:
            raise PaymentRefused("unknown grant")
        return {
            "principal": state.terms.principal,
            "drawn": state.drawn_total,
            "held": state.held,
            "refunded": state.refunded,
        }

    def snapshot_rows(self) -> Dict[str, Any]:
        return {
            "grants": [
                {
                    "terms": self.grants[gid].terms.to_dict(),
                    "status": self.grants[gid].status,
                    "held": self.grants[gid].held,
                    "drawn_total": self.grants[gid].drawn_total,
                    "refunded": self.grants[gid].refunded,
                    "refund_fee_paid": self.grants[gid].refund_fee_paid,
                    "period_drawn": {
                        str(k): v
                        for k, v in sorted(self.grants[gid].period_drawn.items())
                    },
                }
                for gid in sorted(self.grants)
            ],
            "shared_caps": [
                {"payer": p, "limit": c.limit, "spent": c.spent}
                for p, c in sorted(self.shared_caps.items())
            ],
        }

    @classmethod
    def restore(cls, rows: Dict[str, Any]) -> "GrantBook":
        book = cls()
        for row in rows["grants"]:
            terms = GrantTerms.from_dict(row["terms"])
            state = GrantState(
                terms=terms, status=row["status"], held=row["held"],
                drawn_total=row["drawn_total"], refunded=row["refunded"],
                refund_fee_paid=row["refund_fee_paid"],
                period_drawn={int(k): v for k, v in row["period_drawn"].items()},
            )
            if terms.grant_id in book.grants:
                raise ValueError("duplicate grant in snapshot rows")
            book.grants[terms.grant_id] = state
        for row in rows["shared_caps"]:
            book.shared_caps[row["payer"]] = SharedCapState(
                limit=row["limit"], spent=row["spent"])
        return book

    def root_blobs(self) -> List[bytes]:
        rows = self.snapshot_rows()
        blobs = [
            GrantTerms.from_dict(r["terms"]).grant_id + canonical_json(r)
            for r in rows["grants"]
        ]
        blobs += [
            compute_payment_entry_id(
                "tau.payment.shared_cap.v1",
                encode_pubkey48(r["payer"]) + encode_uint64(r["limit"])
                + encode_uint64(r["spent"]),
            )
            for r in rows["shared_caps"]
        ]
        return blobs


# --- How conditions combine (stage 5) ------------------------------------------


def check_payment_envelope(
    *,
    policy_allows: bool,
    route: Optional[RouteTerms],
    payout_terms: Optional[PayoutTerms],
    recipient: str,
    requires_direct_credit: bool = False,
) -> Optional[str]:
    """The AND-ed condition envelope, evaluated in ONE fixed order — sender
    policy, recipient route/lock, payout caps. Returns None when the
    payment is admissible, or the refusal text NAMING the conflicting pair.
    A conflict is refused at admission, never silently spendable and never
    silently void."""
    if not policy_allows:
        return "sender policy refuses the payment"
    if requires_direct_credit and route is not None and route.locked:
        return (
            "conflict between sender policy and recipient route: the "
            "payment requires direct credit but the recipient's route is "
            "locked for its term"
        )
    if payout_terms is not None and recipient not in {
        cand for cand, _ in payout_terms.candidates
    }:
        return (
            "conflict between recipient and payout caps: the recipient is "
            "not in the payout rule's signed candidate set"
        )
    return None


# --- Capability reporting (#34 case 9, #35 case 8) -------------------------------


def capability_report() -> Dict[str, Any]:
    """What the capability/check surface reports BEFORE a wallet offers
    either feature. Every value is read from the constants and semantics
    this module actually enforces, so the report cannot drift from
    admission/apply behaviour."""
    return {
        "standing_payments": {
            "supported": True,
            "schedule_semantics": {
                "periods": ["week", "month"],
                "time_source": "block_timestamp",
                "month_end_rule": "last_day_of_shorter_month",
                "anchor_drift_after_short_month": False,
                "missed_period_default": "skip",
                "catch_up": "signed_opt_in",
                "max_catch_up_bound": MAX_CATCH_UP_LIMIT,
                "end_condition": "required",
            },
            "spend_accounting": "book_local_per_authorization",
        },
        "receive_routing": {
            "supported": True,
            "max_destinations": MAX_ROUTE_DESTINATIONS,
            "install_time_validation": "sum_of_bps_at_most_10000",
            "rounding": "floor_per_leg_remainder_to_recipient",
            "fee_semantics": "one_fee_per_credit_charged_to_sender",
            "routable_credit_classes": sorted(ROUTABLE_CREDIT_CLASSES),
            "single_hop": True,
        },
        "rule_payouts": {
            "supported": True,
            "recipient_selection": "rule_selects_within_signed_candidate_set",
            "max_candidates": MAX_PAYOUT_CANDIDATES,
            "settlement": "atomic_or_none",
            "idempotency": "pays_once_per_event_id",
            "execution": "open_to_any_executor",
            "executor_pays": "network_fee_query_step",
            "owner_charged_for_execution": False,
            "leg_source": "payout_clause_outputs_at_execution",
            "output_convention": {
                "input_streams": {
                    "gross": PAYOUT_INPUT_GROSS_STREAM,
                    "owner": PAYOUT_INPUT_OWNER_STREAM,
                    "block_timestamp": PAYOUT_INPUT_TIMESTAMP_STREAM,
                    "executor": PAYOUT_INPUT_EXECUTOR_STREAM,
                    "settlement_fingerprint": PAYOUT_INPUT_SETTLEMENT_STREAM,
                },
                "leg_count_stream": PAYOUT_OUTPUT_COUNT_STREAM,
                "leg_stream_base": PAYOUT_OUTPUT_LEG_BASE_STREAM,
                "leg_layout": "(candidate_index, amount) pairs",
                "max_legs": MAX_PAYOUT_LEGS,
            },
        },
    }


# --- The composed books ----------------------------------------------------------


def _runner_book_cls():
    """The Amendment 2 runner book class, imported lazily: payment_runner
    imports THIS module for the shared ledger/validation vocabulary, so a
    top-level import here would cycle. By the time any ProgrammablePayments
    instance is built, both modules are fully loaded."""
    from consensus.payment_runner import RunnerBook
    return RunnerBook


class ProgrammablePayments:
    """All Bounty 01 books, composed as ONE field of
    ConsensusLifecycleManager (the RetractableBook composition pattern), so
    the consensus meta hash picks the root up without a call site to
    forget. The root enters the meta hash only once a book is used, so a
    chain that never touches programmable payments hashes byte-identically
    to before (no regenesis)."""

    def __init__(self, network_id: str = "") -> None:
        self.standing = StandingBook(network_id=network_id)
        self.routes = RouteBook()
        self.payouts = PayoutBook()
        self.grants = GrantBook()
        # The Amendment 2 runner (consensus/payment_runner.py), composed
        # alongside the books while both shapes coexist in this build.
        self.runner = _runner_book_cls()()

    def is_empty(self) -> bool:
        return (
            self.standing.is_empty() and self.routes.is_empty()
            and self.payouts.is_empty() and self.grants.is_empty()
            and self.runner.is_empty()
        )

    def has_due(self, height: int, ts: int) -> bool:
        """Miner wake hint, the RetractableBook.has_due shape: True when the
        next block's payment sweep would settle or refund something.
        (Height is accepted for shape parity; payment periods run on the
        block timestamp, so only `ts` decides.)"""
        return (
            self.standing.has_due(ts) or self.grants.has_due(ts)
            or self.runner.has_due(ts)
        )

    def root(self) -> bytes:
        sections = [
            self.standing.root_blobs(),
            self.routes.root_blobs(),
            self.payouts.root_blobs(),
            self.grants.root_blobs(),
        ]
        # The runner section joins the root ONLY once a rule exists, so a
        # books-only state's root stays byte-identical to the books-only
        # build (the section count is part of the root preimage).
        if not self.runner.is_empty():
            sections.append(self.runner.root_blobs())
        return compute_payments_book_root(sections)

    def snapshot_rows(self) -> Dict[str, Any]:
        return {
            "standing": self.standing.snapshot_rows(),
            "routes": self.routes.snapshot_rows(),
            "payouts": self.payouts.snapshot_rows(),
            "grants": self.grants.snapshot_rows(),
            "runner": self.runner.snapshot_rows(),
        }

    @classmethod
    def restore(cls, rows: Dict[str, Any], network_id: str = "") -> "ProgrammablePayments":
        books = cls(network_id=network_id)
        books.standing = StandingBook.restore(rows["standing"], network_id=network_id)
        books.routes = RouteBook.restore(rows["routes"])
        books.payouts = PayoutBook.restore(rows["payouts"])
        books.grants = GrantBook.restore(rows["grants"])
        # Tolerant: rows written before the runner existed carry no
        # "runner" section and restore as an empty runner book.
        runner_rows = rows.get("runner")
        if runner_rows is not None:
            books.runner = _runner_book_cls().restore(runner_rows)
        return books
