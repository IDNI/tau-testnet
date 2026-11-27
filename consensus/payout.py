"""Payout rules: an account's money paid out by a rule it installed (#63).

An account installs ONE payout rule with `payout_rule_set`: a Tau clause, up to
eight recipient slots, a cap per execution, a cap per period and an end. From
then on anyone may send `payout_execute` naming the account, the rule's id and
the inputs the rule reads. The node steps the clause once in an isolated policy
worker, reads one amount per slot, and pays all of them or none:

    total = sum of the slot amounts
    1 <= total <= cap_per_execution
    paid in this period + total <= cap_per_period
    total <= the account's balance

A slot is fixed (a recipient written into the rule) or open (the executor names
the recipient, and the rule sees it as an input and decides what it may get).

The rule is a second, separate authorization for the account's money, chosen
by the account: the o5 clause governs transfers the account signs, the payout
rule governs executions. Installing, replacing and revoking a payout rule are
rule changes, so an account's rule-change guard judges them (kinds 6 and 7) and
a guarded account installs one through a rule-change request. An escrow account
therefore locks its money to its payout rule with three things: a payout rule,
an o5 clause that blocks signed transfers, and a guard that needs co-signers
for any rule change.

PAYOUT ABI v1 (CONSENSUS-FROZEN)
--------------------------------
A payout rule is evaluated in its own policy pool, never beside o5 clauses, and
every stream it mentions must carry exactly the width below. Stream typing is
process-global and sticky in an interpreter process, so fixed widths are what
let any number of payout rules share one worker.

    i2   bv[24]   the account's balance at the parent block (capped at bv[24])
    i5   bv[64]   block timestamp
    i6   bv[64]   block height
    i13  bv[384]  the executor's public key
    i26  bv[24]   paid out of this account by the rule in the current period
    i30+k bv[384] recipient of slot k (0 for an open slot nobody named)
    i40+k bv[24]  executor data k, k in 0..7 (0 when not given)
    o30+k bv[24]  amount for slot k (0 when the rule does not write it)

  only in a rule installed with `per_sale` (see PER SALE below):
    i27  bv[24]   the amount of the sale the execution names
    i28  bv[384]  who paid it

A rule reads [t] only, reads at least one input and writes at least one slot
amount, and mentions no slot it does not have.

  two clocks the node keeps for a rule that reads them, on the rule's own clock
  (heights with `period_blocks`, unix seconds with `period_seconds`):
    i48  bv[64]   the clock at which the rule was installed
    i49  bv[64]   the clock of its last paid execution (the install clock
                  until one has paid)

OPTIONAL TERMS
--------------
Two signed terms a rule may carry. A rule without them, and that reads neither
i48 nor i49, has the id, the book entry and the stored row it always had.

`periods_from`: the clock value the periods count from, in place of the install
clock. "500 a week from 1 December" then counts its weeks from 1 December,
whenever the rule was installed. Everything before that point belongs to the
first period.

`due_at`: a point on the rule's clock at which the node runs the rule itself,
once, with no executor and no named recipient: in the first block whose clock
reaches it, after the block's transactions and the runs on arrival, at
most MAX_PAYOUT_DUE_RUNS_PER_BLOCK rules a block (the rest wait for the next
blocks, earliest due point first). The run is an execution like any other (the
rule is stepped once, all slots are paid or none, both caps and the balance
hold) with three differences: i13 is 0, only fixed slots can be paid, and i2 is
the balance the block has reached, not the parent block's, so a rule that pays
"everything that is left" pays exactly what is there. It costs nothing beyond
the fee of the transaction that installed the rule. A rule whose due point has
not run yet is kept past its end until it has.

PER SALE
--------
A royalty is owed once per sale, and the sale's amount must not be the
claimant's word. A rule installed with `per_sale: true` therefore pays only
against sales the chain recorded itself: every signed transfer into the account
while the rule is installed is recorded as an open sale, its id the transfer's
transaction hash, its amount what that transaction paid the account (capped at
bv[24]). An execution must name one open sale; the rule reads the sale's amount
and payer (i27, i28), and a paid execution closes the sale, so a second
execution naming it is refused. A refused execution leaves it open. At most
MAX_OPEN_SALES are open at once.
When that many are open, a larger sale takes the place of the smallest open one
and the smaller is counted as missed; a sale no larger than every open one is
not recorded and is counted as missed. So sales too small to pay anything (a 5%
royalty pays nothing on 19 or less) cannot hold every place and keep later
sales out. Replacing, revoking or expiring the rule drops its open sales.

With `on_arrival: true` the node runs the rule inside the payment itself (see
consensus/engine.py, _run_arrivals_of_payment), so its sale is closed in the
same transaction. An account holds at most one such rule.
"""
from __future__ import annotations

import bisect
import hashlib
import json
import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.serialization import (
    compute_payout_body_hash,
    compute_payout_book_root,
    compute_payout_resolved_acc,
    compute_payout_rule_id,
    payout_options_present,
)

TX_TYPE_PAYOUT_RULE_SET = "payout_rule_set"
TX_TYPE_PAYOUT_RULE_REVOKE = "payout_rule_revoke"
TX_TYPE_PAYOUT_EXECUTE = "payout_execute"

PAYOUT_TX_TYPES = frozenset(
    {TX_TYPE_PAYOUT_RULE_SET, TX_TYPE_PAYOUT_RULE_REVOKE, TX_TYPE_PAYOUT_EXECUTE}
)

# The pools payout rules are stepped in: never the o5 pools.
POOL_APPLY = "payout_apply"
POOL_ADMISSION = "payout_admission"

# Period clocks.
KIND_BLOCKS = 0
KIND_SECONDS = 1
KIND_NAMES = {KIND_BLOCKS: "blocks", KIND_SECONDS: "seconds"}
PERIOD_FIELDS = (("period_blocks", KIND_BLOCKS), ("period_seconds", KIND_SECONDS))

# Folded into the removal commitment, one byte each.
OUTCOME_REVOKED = 1
OUTCOME_EXPIRED = 2
OUTCOME_REPLACED = 3
OUTCOME_NAMES = {OUTCOME_REVOKED: "revoked", OUTCOME_EXPIRED: "expired",
                 OUTCOME_REPLACED: "replaced"}

MAX_SLOTS = 8
MAX_DATA = 8
STREAM_BALANCE = 2
STREAM_TIME = 5
STREAM_HEIGHT = 6
STREAM_EXECUTOR = 13
STREAM_SPENT = 26
SLOT_BASE = 30
DATA_BASE = 40
STREAM_INSTALLED = 48
STREAM_LAST_PAID = 49
STREAM_SALE_AMOUNT = 27
STREAM_SALE_PAYER = 28
MAX_OPEN_SALES = 64

AMOUNT_WIDTH = tau_defs.TRANSFER_VALUE_BV_WIDTH
KEY_WIDTH = 384
CLOCK_WIDTH = 64

MAX_RULE_BYTES = 4096
MAX_PAYOUT_RULES_TOTAL = 4096
MAX_PAYOUT_EXECUTIONS_PER_BLOCK = 16
MAX_PAYOUT_DUE_RUNS_PER_BLOCK = 16
# A sale recorded by an apply that writes transfers at once (one without a
# proposer) waits for a run after the block's transactions; an apply that stages
# them runs it inside the payment.
MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK = 16
# Runs the node makes again for due points that found the account short, after
# the due points of the block and on their own budget, so a retry never delays
# another rule's due point.
MAX_PAYOUT_RETRY_RUNS_PER_BLOCK = 4
# Rules one account may hold at once: the first place, and places 1..7 named by
# `rule_index`.
MAX_RULES_PER_ACCOUNT = 8
# A rule that repeats is run at most this often. The floor on the block clock
# is what lets a full book be served: every due point gets its run before the
# rule's next one comes.
MIN_DUE_EVERY_BLOCKS = 256
MIN_DUE_EVERY_SECONDS = 3_600
MAX_DUE_MONTHS = 12
MAX_PERIOD_BLOCKS = 1_000_000
MAX_PERIOD_SECONDS = 31_622_400            # 366 days
MAX_LIFETIME_BLOCKS = 10_000_000
MAX_LIFETIME_SECONDS = 4 * 31_622_400      # four years of 366 days

assert MIN_DUE_EVERY_BLOCKS >= -(-MAX_PAYOUT_RULES_TOTAL // MAX_PAYOUT_DUE_RUNS_PER_BLOCK)

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_MENTION_RE = re.compile(r"\b([io])(\d+)\b")
_CLOCKS_RE = re.compile(r"\bi(?:%d|%d)\b" % (STREAM_INSTALLED, STREAM_LAST_PAID))
_TYPED_RE = re.compile(r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*(\d+)\s*\]")


class PayoutShapeError(ValueError):
    """A payout transaction does not have a shape the node can record."""


def payout_key(account: str, rule_index: int = 0) -> str:
    """The book key of an account's rule in place `rule_index`."""
    return account if not rule_index else f"{account}/{int(rule_index)}"


class PayoutRefused(ValueError):
    """An execution the rule, its caps or the balance do not allow. Nothing moves."""


class PayoutShort(PayoutRefused):
    """The rule pays more than the account holds. Nothing moves; a due point
    whose rule carries `due_retry` is run again later."""


class PayoutPolicyBlocked(PayoutRefused):
    """The account's current o5 clause blocks a payment of the run. Nothing
    moves, and nothing is owed for it later."""


def abi_width(name: str, slot_count: int = MAX_SLOTS, per_sale: bool = False) -> Optional[int]:
    """The width stream `name` must carry in a payout rule, or None if it may not
    be mentioned at all."""
    io, index = name[0], int(name[1:])
    if io == "o":
        return AMOUNT_WIDTH if SLOT_BASE <= index < SLOT_BASE + slot_count else None
    if index in (STREAM_BALANCE, STREAM_SPENT):
        return AMOUNT_WIDTH
    if per_sale and index == STREAM_SALE_AMOUNT:
        return AMOUNT_WIDTH
    if per_sale and index == STREAM_SALE_PAYER:
        return KEY_WIDTH
    if index in (STREAM_TIME, STREAM_HEIGHT, STREAM_INSTALLED, STREAM_LAST_PAID):
        return CLOCK_WIDTH
    if index == STREAM_EXECUTOR:
        return KEY_WIDTH
    if SLOT_BASE <= index < SLOT_BASE + slot_count:
        return KEY_WIDTH
    if DATA_BASE <= index < DATA_BASE + MAX_DATA:
        return AMOUNT_WIDTH
    return None


# --- Calendar (integer arithmetic, proleptic Gregorian, UTC) -------------------


def _days_from_civil(year: int, month: int, day: int) -> int:
    """Days since 1970-01-01 for a valid date (H. Hinnant's algorithm)."""
    year -= month <= 2
    era = year // 400
    yoe = year - era * 400
    doy = (153 * (month + (-3 if month > 2 else 9)) + 2) // 5 + day - 1
    doe = yoe * 365 + yoe // 4 - yoe // 100 + doy
    return era * 146097 + doe - 719468


def _civil_from_days(days: int) -> Tuple[int, int, int]:
    """(year, month, day) of a day count since 1970-01-01."""
    days += 719468
    era = days // 146097
    doe = days - era * 146097
    yoe = (doe - doe // 1460 + doe // 36524 - doe // 146096) // 365
    doy = doe - (365 * yoe + yoe // 4 - yoe // 100)
    mp = (5 * doy + 2) // 153
    day = doy - (153 * mp + 2) // 5 + 1
    month = mp + 3 if mp < 10 else mp - 9
    return yoe + era * 400 + (month <= 2), month, day


def _month_length(year: int, month: int) -> int:
    if month == 2:
        leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
        return 29 if leap else 28
    return 30 if month in (4, 6, 9, 11) else 31


def add_months(anchor: int, months: int) -> int:
    """`anchor` moved by whole calendar months, keeping day and time of day.

    A day the target month does not have becomes its last day: a schedule
    anchored on the 31st pays on 30 April and on 28 or 29 February. Each due
    point is derived from the anchor, never from the previous due point, so the
    31st comes back in May (no drift).
    """
    days, seconds = divmod(int(anchor), 86400)
    year, month, day = _civil_from_days(days)
    total = (month - 1) + int(months)
    year, month = year + total // 12, total % 12 + 1
    day = min(day, _month_length(year, month))
    return _days_from_civil(year, month, day) * 86400 + seconds


# --- Terms and state -------------------------------------------------------------


def due_point_of(due_at: int, due_every: Optional[int], due_months: Optional[int],
                 index: int) -> int:
    """Due point number `index` of a rule; number 0 is `due_at`. Each one is
    derived from `due_at`, never from the one before, so a monthly rule signed
    for the 31st runs on the last day of a shorter month and comes back to the
    31st."""
    if due_months is not None:
        return add_months(int(due_at), int(index) * int(due_months))
    if due_every is not None:
        return int(due_at) + int(index) * int(due_every)
    return int(due_at)


@dataclass(frozen=True)
class PayoutTerms:
    """What the account signed. Immutable."""

    account_pubkey: str
    sequence_number: int
    body: str
    slots: Tuple[str, ...]          # a recipient pubkey, or "" for an open slot
    cap_per_execution: int
    cap_per_period: int
    kind: int
    period: int
    expires_at: int
    per_sale: bool = False          # pays only against sales the chain recorded
    periods_from: Optional[int] = None   # the periods count from here, not the install
    due_at: Optional[int] = None         # the node runs the rule itself at this point
    due_every: Optional[int] = None      # ... and again every so much on the rule's clock
    due_months: Optional[int] = None     # ... or every so many calendar months (UTC)
    on_arrival: bool = False             # per sale: the node pays each sale as it arrives
    sealed: bool = False                 # the account signs nothing until the rule ends
    rule_index: Optional[int] = None     # the rule's place on the account, 1..7; left out = 0
    due_retry: Optional[int] = None      # a due point that found the account short is run
                                         # again until this much later on the rule's clock
    policy_exempt: bool = False          # the account's o5 clause is not asked for its runs

    @property
    def options(self) -> Tuple:
        return (self.periods_from, self.due_at, self.due_every, self.due_months,
                self.on_arrival, self.sealed, self.rule_index, self.due_retry,
                self.policy_exempt)

    @property
    def key(self) -> str:
        """Where the rule sits in the book: the account for the first place,
        `account/k` for place k."""
        return payout_key(self.account_pubkey, self.rule_index or 0)

    @property
    def later_terms(self) -> bool:
        """Carries a term from after the first two optional ones: its entry then
        holds the longer `more` (see serialization.encode_payout_entry)."""
        return (self.repeats or self.on_arrival or self.sealed or self.newest_terms)

    @property
    def newest_terms(self) -> bool:
        return (self.rule_index is not None or self.due_retry is not None
                or self.policy_exempt)

    @property
    def repeats(self) -> bool:
        return self.due_every is not None or self.due_months is not None

    def due_point(self, index: int) -> int:
        """The rule's due point number `index`; number 0 is `due_at`."""
        return due_point_of(self.due_at, self.due_every, self.due_months, index)

    def due_index_after(self, index: int, clock: int) -> int:
        """The next due point after number `index` that the clock has not
        reached. One the clock has passed is not caught up."""
        k = int(index) + 1
        if self.due_every is not None and clock >= self.due_at:
            k = max(k, (int(clock) - self.due_at) // self.due_every + 1)
        while self.due_point(k) <= clock and self.due_point(k) < self.expires_at:
            k += 1
        return k

    @property
    def body_hash(self) -> bytes:
        return compute_payout_body_hash(self.body)

    @property
    def rule_id(self) -> bytes:
        return compute_payout_rule_id(
            self.account_pubkey, self.sequence_number, self.body_hash, self.slots,
            self.cap_per_execution, self.cap_per_period, self.kind, self.period,
            self.expires_at, self.per_sale, *self.options,
        )

    @property
    def reads_clocks(self) -> bool:
        """The rule reads i48 or i49, so the node keeps its last paid clock."""
        from consensus.rule_offers import strip_clause_comments

        return _CLOCKS_RE.search(strip_clause_comments(self.body)) is not None

    @property
    def extended(self) -> bool:
        """Carries an optional term or reads the kept clocks: its entry and its
        stored row hold `more` (see serialization.encode_payout_entry)."""
        return payout_options_present(self.options) or self.reads_clocks

    def clock(self, height: int, ts: int) -> int:
        return height if self.kind == KIND_BLOCKS else ts


@dataclass(frozen=True)
class PayoutState:
    """Where an installed rule stands. Replaced, never mutated."""

    anchor: int                  # the clock when the rule was installed
    period_index: int = 0        # the period `spent_in_period` belongs to
    spent_in_period: int = 0
    executions: int = 0
    paid_total: int = 0
    last_height: int = 0         # height of the last execution, 0 = never
    # per-sale rules only: (sale_id, payer, amount, height) in arrival order
    open_sales: Tuple[Tuple[bytes, str, int, int], ...] = ()
    sales_missed: int = 0
    # kept only for a rule that is `extended`:
    last_clock: int = 0          # the rule's clock at its last paid execution, 0 = never
    due_done: bool = False       # the node owes the rule no further due point
    due_index: int = 0           # a rule that repeats: the number of its next due point
    # kept only for a rule with due_retry: the node runs an unpaid due point
    # again from retry_at on, while the rule's clock is before retry_until;
    # both 0 while it owes no retry
    retry_at: int = 0
    retry_until: int = 0

    def sale(self, sale_id: bytes) -> Optional[Tuple[bytes, str, int, int]]:
        for entry in self.open_sales:
            if entry[0] == sale_id:
                return entry
        return None

    def period_at(self, terms: PayoutTerms, clock: int) -> int:
        base = self.anchor if terms.periods_from is None else terms.periods_from
        return max(0, int(clock) - base) // terms.period

    def next_due(self, terms: PayoutTerms) -> Optional[int]:
        """The due point the node still owes the rule, or None."""
        if terms.due_at is None or self.due_done:
            return None
        return terms.due_point(self.due_index)

    def due_pending(self, terms: PayoutTerms) -> bool:
        return terms.due_at is not None and not self.due_done

    def more(self, terms: PayoutTerms) -> Optional[Tuple]:
        """(periods_from, due_at, last_clock, due_done) for an extended rule,
        followed by (due_every, due_months, on_arrival, sealed, due_index) when
        the rule carries one of those, followed by (rule_index, due_retry,
        retry_at, retry_until) when it carries one of the last two, and (True,)
        when it is signed with policy_exempt."""
        if not terms.extended:
            return None
        head = (terms.periods_from, terms.due_at, self.last_clock, self.due_done)
        if not terms.later_terms:
            return head
        head += (terms.due_every, terms.due_months, terms.on_arrival,
                 terms.sealed, self.due_index)
        if not terms.newest_terms:
            return head
        head += (terms.rule_index, terms.due_retry, self.retry_at, self.retry_until)
        return head + (True,) if terms.policy_exempt else head

    def spent_at(self, terms: PayoutTerms, clock: int) -> int:
        return self.spent_in_period if self.period_index == self.period_at(terms, clock) else 0


@dataclass(frozen=True)
class PayoutExecution:
    executor_pubkey: str                      # "" for a run by the node at a due point
    account_pubkey: str
    rule_id: bytes
    recipients: Tuple[Tuple[int, str], ...]   # (slot, pubkey) for open slots, sorted
    data: Tuple[Tuple[int, int], ...]         # (k, value) for i40+k, sorted
    sale_id: Optional[bytes] = None           # the recorded sale it pays (per-sale rules)


# --- Parsing ---------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise PayoutShapeError(f"{what} must be 96 lowercase hex characters")
    return value


def _u64(fields: Dict[str, Any], name: str) -> int:
    value = fields.get(name)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise PayoutShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def payout_rule_body(rule_text: Any) -> str:
    """The body of a single `always ( ... ).` unit, by the o5 clause's own rules."""
    from consensus.rule_offers import RuleOfferShapeError, clause_body_v1

    if not isinstance(rule_text, str) or not rule_text.strip():
        raise PayoutShapeError("rule_text must be a non-empty string")
    if len(rule_text.encode("utf-8", "surrogatepass")) > MAX_RULE_BYTES:
        raise PayoutShapeError(f"rule_text exceeds {MAX_RULE_BYTES} bytes")
    try:
        return clause_body_v1(rule_text)
    except RuleOfferShapeError as exc:
        raise PayoutShapeError(f"rule_text is not a single clause: {exc}") from exc


def _terms_from_fields(fields: Dict[str, Any], account: str, sequence: int) -> PayoutTerms:
    body = payout_rule_body(fields.get("rule_text"))
    slots = fields.get("slots")
    if not isinstance(slots, list) or not 1 <= len(slots) <= MAX_SLOTS:
        raise PayoutShapeError(f"slots must be a list of 1..{MAX_SLOTS} entries")
    parsed: List[str] = []
    for k, slot in enumerate(slots):
        if slot == "":
            parsed.append("")
        else:
            parsed.append(_pubkey(slot, f"slots[{k}]"))
    present = [(n, kind) for n, kind in PERIOD_FIELDS if fields.get(n) is not None]
    if len(present) != 1:
        raise PayoutShapeError("exactly one of period_blocks and period_seconds is required")
    name, kind = present[0]
    per_sale = fields.get("per_sale")
    if per_sale is not None and per_sale is not True:
        # one spelling per meaning: leave the field out for a rule that does not
        # pay per sale, so equal terms always sign and hash the same
        raise PayoutShapeError("per_sale must be true or left out")
    # Optional terms: a number, or left out. `null` is refused so equal terms
    # always sign and hash the same.
    optional: Dict[str, Any] = {}
    for field in ("periods_from", "due_at", "due_every", "due_months", "rule_index",
                  "due_retry"):
        if field in fields:
            optional[field] = _u64(fields, field)
    if "rule_index" in optional:
        _check_rule_index(optional["rule_index"])
    for field in ("on_arrival", "sealed", "policy_exempt"):
        if field in fields:
            if fields[field] is not True:
                raise PayoutShapeError(f"{field} must be true or left out")
            optional[field] = True
    return PayoutTerms(
        account_pubkey=account,
        sequence_number=sequence,
        body=body,
        slots=tuple(parsed),
        cap_per_execution=_u64(fields, "cap_per_execution"),
        cap_per_period=_u64(fields, "cap_per_period"),
        kind=kind,
        period=_u64(fields, name),
        expires_at=_u64(fields, "expires_at"),
        per_sale=per_sale is True,
        **optional,
    )


SPEC_FIELDS = ("rule_text", "slots", "cap_per_execution", "cap_per_period",
               "period_blocks", "period_seconds", "expires_at", "per_sale",
               "periods_from", "due_at", "due_every", "due_months", "on_arrival",
               "sealed", "rule_index", "due_retry", "policy_exempt")


def parse_payout_rule_set(tx: Dict[str, Any]) -> PayoutTerms:
    """Read a payout rule from ROOT fields only; a nested `payload` is unsigned."""
    if not isinstance(tx, dict):
        raise PayoutShapeError("transaction must be an object")
    account = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    sequence = _u64(tx, "sequence_number")
    return _terms_from_fields(tx, account, sequence)


def payout_spec_text(fields: Dict[str, Any], sequence_number: Optional[int] = None) -> str:
    """CONSENSUS-FROZEN. The canonical text of a payout rule's terms: sorted keys,
    no spaces. A rule-change request (kind 6) carries it as `rule_text` without
    a sequence number; the request's stored body adds the request's own
    sequence number, which then enters the installed rule's id."""
    spec = {k: fields[k] for k in SPEC_FIELDS if fields.get(k) is not None}
    if sequence_number is not None:
        spec["sequence_number"] = int(sequence_number)
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_payout_spec(text: Any, account: str,
                      sequence_number: Optional[int] = None) -> PayoutTerms:
    """Terms from canonical spec text. Refuses any text that is not exactly its
    own canonical form, so one set of terms has one body hash and one request
    id. The sequence number comes from the text (a stored body) or from the
    caller (a request as sent), never from both."""
    if not isinstance(text, str):
        raise PayoutShapeError("payout spec must be a string")
    try:
        fields = json.loads(text)
    except ValueError as exc:
        raise PayoutShapeError(f"payout spec is not JSON: {exc}") from exc
    if not isinstance(fields, dict) or set(fields) - set(SPEC_FIELDS) - {"sequence_number"}:
        raise PayoutShapeError(f"payout spec may carry only {', '.join(SPEC_FIELDS)}")
    stored = fields.get("sequence_number")
    if (stored is None) == (sequence_number is None):
        raise PayoutShapeError("payout spec needs exactly one sequence number")
    if payout_spec_text(fields, stored) != text:
        raise PayoutShapeError("payout spec is not in canonical form")
    sequence = stored if stored is not None else sequence_number
    if not _is_int(sequence) or not 0 <= sequence <= _U64_MAX:
        raise PayoutShapeError("sequence_number must be an unsigned 64-bit integer")
    return _terms_from_fields(fields, account, sequence)


def _check_rule_index(value: Any) -> int:
    """A rule's place named in a transaction: 1..7. The first place is named
    by leaving the field out, so one place has one spelling."""
    if not _is_int(value) or not 1 <= value < MAX_RULES_PER_ACCOUNT:
        raise PayoutShapeError(
            f"rule_index must be 1..{MAX_RULES_PER_ACCOUNT - 1}, or left out for the first rule")
    return int(value)


def parse_payout_rule_revoke(tx: Dict[str, Any]) -> str:
    return parse_payout_rule_revoke_place(tx)[0]


def parse_payout_rule_revoke_place(tx: Dict[str, Any]) -> Tuple[str, int]:
    """(account, place) of a revoke; the place is 0 when `rule_index` is left out."""
    if not isinstance(tx, dict):
        raise PayoutShapeError("transaction must be an object")
    account = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    if "rule_index" not in tx:
        return account, 0
    return account, _check_rule_index(tx.get("rule_index"))


def payout_revoke_place(text: Any) -> int:
    """The place a revoke request (kind 7) names in its rule_text: "" is the
    first rule, "1".."7" the rule in that place."""
    if text in ("", None):
        return 0
    if not isinstance(text, str) or not text.isdigit() or str(int(text)) != text:
        raise PayoutShapeError(
            f"a payout revoke request carries no rule_text, or the place 1.."
            f"{MAX_RULES_PER_ACCOUNT - 1} as a number")
    return _check_rule_index(int(text))


def parse_payout_execute(tx: Dict[str, Any]) -> PayoutExecution:
    if not isinstance(tx, dict):
        raise PayoutShapeError("transaction must be an object")
    executor = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    account = _pubkey(tx.get("account_pubkey"), "account_pubkey")
    raw_id = tx.get("rule_id")
    if not isinstance(raw_id, str) or not _ID_RE.match(raw_id):
        raise PayoutShapeError("rule_id must be 64 lowercase hex characters")
    recipients = tx.get("recipients")
    if recipients is None:
        recipients = {}
    if not isinstance(recipients, dict) or len(recipients) > MAX_SLOTS:
        raise PayoutShapeError(f"recipients must map at most {MAX_SLOTS} slots to keys")
    named: List[Tuple[int, str]] = []
    for key, value in recipients.items():
        if not isinstance(key, str) or not key.isdigit() or int(key) >= MAX_SLOTS \
                or str(int(key)) != key:
            raise PayoutShapeError(f"recipients keys must be slot numbers 0..{MAX_SLOTS - 1}")
        named.append((int(key), _pubkey(value, f"recipients[{key}]")))
    data = tx.get("data")
    if data is None:
        data = {}
    if not isinstance(data, dict) or len(data) > MAX_DATA:
        raise PayoutShapeError(f"data must map at most {MAX_DATA} inputs to values")
    values: List[Tuple[int, int]] = []
    for key, value in data.items():
        if not isinstance(key, str) or not key.isdigit() or int(key) >= MAX_DATA \
                or str(int(key)) != key:
            raise PayoutShapeError(f"data keys must be 0..{MAX_DATA - 1} (input i{DATA_BASE}+k)")
        if not _is_int(value) or not 0 <= value <= tau_defs.MAX_TRANSFER_VALUE:
            raise PayoutShapeError(f"data values must be integers 0..{tau_defs.MAX_TRANSFER_VALUE}")
        values.append((int(key), value))
    sale = tx.get("sale_id")
    if sale is not None and (not isinstance(sale, str) or not _ID_RE.match(sale)):
        raise PayoutShapeError("sale_id must be 64 lowercase hex characters (a transaction hash)")
    return PayoutExecution(executor, account, bytes.fromhex(raw_id),
                           tuple(sorted(named)), tuple(sorted(values)),
                           bytes.fromhex(sale) if sale is not None else None)


# --- Screens ---------------------------------------------------------------------


def screen_payout_body(body: str, slot_count: int, per_sale: bool = False) -> Optional[str]:
    """None when the body fits the payout ABI, else why not. Shared by admission,
    apply and the rule-change release."""
    from consensus.admission import screen_rule_fragment
    from consensus.rule_fragment import clause_unit
    from consensus.rule_offers import screen_clause_structure, strip_clause_comments

    fragment = screen_rule_fragment(clause_unit(body))
    if fragment:
        return fragment
    scrubbed = strip_clause_comments(body)
    seen: Dict[str, int] = {}
    for match in _MENTION_RE.finditer(scrubbed):
        name = f"{match.group(1)}{match.group(2)}"
        typed = _TYPED_RE.match(scrubbed, match.end())
        if typed is None:
            return f"every mention of {name} must be written {name}[t]:bv[<width>]"
        want = abi_width(name, slot_count, per_sale)
        if want is None:
            if name in (f"i{STREAM_SALE_AMOUNT}", f"i{STREAM_SALE_PAYER}"):
                return f"{name} is read only by a rule installed with per_sale"
            return f"{name} is not part of the payout ABI for {slot_count} slot(s)"
        width = int(typed.group(1))
        if width != want:
            return f"{name} must be bv[{want}] in a payout rule, not bv[{width}]"
        seen[name] = width
    if not any(n.startswith("o") for n in seen):
        return "a payout rule must write at least one slot amount (o30..)"
    if not any(n.startswith("i") for n in seen):
        return "a payout rule must read at least one input"
    shape = screen_payout_shape(scrubbed)
    if shape:
        return shape
    return screen_clause_structure(body)


# --- The shape of a payout rule (CONSENSUS-FROZEN with ABI v1) ---------------------
#
# Every node must pay the same amounts, whatever that node evaluated before, and
# the amounts must be the rule's decision, not the engine's. Two things would
# break that, so the screen refuses them:
#
# 1. An amount the rule does not fix. `o30 <= i40` has many answers; an engine
#    picks one of them, and which one is its own choice (it may differ between
#    engine versions). An equation fixes an unknown only in its definitional form
#    (one solution exactly when f(0) and f(1) are complements; Rudeanu, Boolean
#    Functions and Equations, Thm 6.6), so every amount is written as
#    `oN = <expression over inputs>`. Definitions are joined with `&&`, or chosen
#    by `(condition) ? (...) : (...)` whose condition reads inputs only; both
#    branches fix the same amounts. Anything else that mentions an amount (`<=`,
#    `||`, `!`, `!=`, an amount on the right side) is refused. So is a bare
#    condition over inputs beside a definition (`(i40 > 0) && o30 = i40`): where
#    it does not hold the clause has no answer, and the engine does not build a
#    clause that cannot answer every input (measured in test_payout_native.py).
#    A rule that pays nothing for some inputs writes zero there, on the other
#    side of a choice; an execution that pays nothing is refused.
# 2. Anything whose answer depends on earlier steps. Policy interpreters are kept
#    and stepped again, so a temporal operator (always/G/[], sometimes/F/<>,
#    until/U, release/R, weak_until/W, since/S, trigger/T, A, E), a step
#    constraint such as `[t > 3]`, a quantifier, a variable, a named constant or a
#    function would make an amount depend on what that node stepped before.
#    Only the tokens below are accepted: everything else is refused by name.

_SHAPE_TOKENS = re.compile(
    r"\s*(?:"
    r"(?P<io>([io])(\d+)\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*\d+\s*\])"
    r"|(?P<const>\{\s*(?:#x[0-9a-fA-F]+|#b[01]+|\d+)\s*\}\s*:\s*bv\s*\[\s*\d+\s*\])"
    r"|(?P<fn>\b(?:min|max)\b)"
    r"|(?P<never><>)"
    r"|(?P<op><->|!<=|!>=|->|<-|&&|\|\||\^\^|!=|<=|>=|!<|!>|<<|>>|!\||!\^|!&"
    r"|[=<>!?:()+\-*/%|^&',])"
    r")")
_BOOL_OPS = frozenset({"<->", "->", "<-", "&&", "||", "^^", "!", "?", ":"})
_COMPARE_OPS = frozenset({"=", "!=", "<", "<=", ">", ">=", "!<", "!<=", "!>", "!>="})
_TERM_OPS = frozenset({"(", ")", "+", "-", "*", "/", "%", "<<", ">>", "|", "^", "&",
                       "!|", "!^", "!&", "'", ","})


class _Open(ValueError):
    """The rule leaves an amount open (or names one where it cannot fix it)."""


def _shape_tokens(text: str):
    """[(kind, text, name)] with kind io_in | io_out | const | fn | op, or the
    first piece of text a payout rule may not use."""
    out, i, end = [], 0, len(text.rstrip())
    while i < end:
        m = _SHAPE_TOKENS.match(text, i)
        if m is None or m.end() == i:
            piece = text[i:].strip().split()[0] if text[i:].strip() else text[i:]
            return None, piece[:24]
        if m.group("never"):
            return None, m.group("never")
        i = m.end()
        if m.group("io"):
            kind = "io_out" if m.group(2) == "o" else "io_in"
            out.append((kind, m.group("io"), f"{m.group(2)}{m.group(3)}"))
        elif m.group("const"):
            out.append(("const", m.group("const"), ""))
        elif m.group("fn"):
            out.append(("fn", m.group("fn"), ""))
        else:
            op = m.group("op")
            if op == "-" and not (out and (out[-1][0] in ("io_in", "io_out", "const")
                                          or out[-1][1] in (")", "'"))):
                return None, "-"
            out.append(("op", op, ""))
    return out, None


def _match_paren(tok, i: int) -> int:
    depth = 0
    for j in range(i, len(tok)):
        if tok[j][1] == "(":
            depth += 1
        elif tok[j][1] == ")":
            depth -= 1
            if depth == 0:
                return j
    raise _Open("unbalanced parentheses")


def _amounts(tok, lo: int, hi: int) -> set:
    return {t[2] for t in tok[lo:hi] if t[0] == "io_out"}


_JOINS = frozenset({"||", "^^", "->", "<-", "<->", "?", ":", "!"})


def _fixed(tok, lo: int, hi: int) -> set:
    """The amounts tok[lo:hi] fixes; raises _Open where it leaves one open."""
    parts, joins, depth, start = [], set(), 0, lo
    for j in range(lo, hi + 1):
        kind, t = (tok[j][0], tok[j][1]) if j < hi else ("op", "&&")
        if t == "(":
            depth += 1
        elif t == ")":
            depth -= 1
        elif depth == 0 and kind == "op" and t in _JOINS:
            joins.add(t)
        elif t == "&&" and depth == 0:
            if start == j:
                raise _Open("empty part around &&")
            parts.append((start, j))
            start = j + 1
    if len(parts) > 1 and joins:
        # How && groups against ||, ->, ?: ... is the parser's choice; a rule
        # must not depend on it, so mixed joins need their own parentheses.
        raise _Open(f"put parentheses around the part with {sorted(joins)[0]!r} before joining it with &&")
    fixed = set()
    for a, b in parts:
        if len(parts) > 1 and not _amounts(tok, a, b):
            # A condition on inputs beside a definition. Where it does not hold
            # the clause has no answer at all, and the engine builds only
            # clauses that answer every input.
            raise _Open("a bare condition on inputs leaves no answer where it does not hold; "
                        "choose with (c) ? (...) : (...) and write zero where nothing is paid")
        fixed |= _fixed_part(tok, a, b)
    return fixed


def _fixed_part(tok, lo: int, hi: int) -> set:
    if not _amounts(tok, lo, hi):
        return set()  # a condition on inputs only: it fixes nothing
    if tok[lo][1] == "(":
        close = _match_paren(tok, lo)
        if close == hi - 1:
            return _fixed(tok, lo + 1, close)
        if close + 1 < hi and tok[close + 1][1] == "?":
            if _amounts(tok, lo, close + 1):
                raise _Open("a condition may read inputs only, not an amount")
            a = close + 2
            if a >= hi or tok[a][1] != "(":
                raise _Open("write both sides of a condition in parentheses: (c) ? (...) : (...)")
            a_end = _match_paren(tok, a)
            b = a_end + 2
            if a_end + 1 >= hi or tok[a_end + 1][1] != ":" or b >= hi or tok[b][1] != "(":
                raise _Open("write both sides of a condition in parentheses: (c) ? (...) : (...)")
            b_end = _match_paren(tok, b)
            if b_end != hi - 1:
                raise _Open("put a condition (c) ? (...) : (...) in parentheses before joining it with more")
            yes, no = _fixed(tok, a + 1, a_end), _fixed(tok, b + 1, b_end)
            if yes != no:
                name = sorted(yes ^ no)[0]
                raise _Open(f"{name} is fixed on one side of a condition only")
            return yes
    first = tok[lo]
    if first[0] == "io_out" and hi - lo >= 3 and tok[lo + 1][1] == "=":
        expr = tok[lo + 2:hi]
        if any(t[0] == "io_out" for t in expr):
            raise _Open(f"{first[2]} must be fixed by inputs, not by another amount")
        bad = [t[1] for t in expr if t[0] == "op" and t[1] not in _TERM_OPS]
        if bad:
            raise _Open(f"{first[2]} = ... may hold an expression only, not {bad[0]!r}")
        return {first[2]}
    name = sorted(_amounts(tok, lo, hi))[0]
    raise _Open(f"{name} is not fixed: write it as {name}[t]:bv[24] = <expression of inputs>")


def screen_payout_shape(scrubbed_body: str) -> Optional[str]:
    """None when every amount is fixed by the inputs and nothing reads earlier
    steps, else why not. `scrubbed_body` is the comment-stripped clause body."""
    tok, bad = _shape_tokens(scrubbed_body)
    if tok is None:
        return (f"a payout rule may not use {bad!r}: only typed streams at [t], typed "
                f"constants, min/max, and comparison, Boolean and bit-vector operators")
    try:
        _fixed(tok, 0, len(tok))
    except _Open as e:
        return f"a payout rule must fix every amount: {e}"
    return None


def validate_terms_shape(terms: PayoutTerms, height: int, ts: int) -> Optional[str]:
    """Stateless admissibility of terms against the block that installs them."""
    screened = screen_payout_body(terms.body, len(terms.slots), terms.per_sale)
    if screened:
        return screened
    fixed = [s for s in terms.slots if s]
    if terms.account_pubkey in fixed:
        return "a slot may not pay the account itself"
    if len(set(fixed)) != len(fixed):
        return "a fixed recipient may appear in one slot only"
    if not 1 <= terms.cap_per_execution <= tau_defs.MAX_TRANSFER_VALUE:
        return f"cap_per_execution must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if not terms.cap_per_execution <= terms.cap_per_period <= tau_defs.MAX_TRANSFER_VALUE:
        return f"cap_per_period must be in cap_per_execution..{tau_defs.MAX_TRANSFER_VALUE}"
    if terms.kind == KIND_BLOCKS:
        hi, now, life = MAX_PERIOD_BLOCKS, height, MAX_LIFETIME_BLOCKS
    else:
        hi, now, life = MAX_PERIOD_SECONDS, ts, MAX_LIFETIME_SECONDS
    if not 1 <= terms.period <= hi:
        return f"the period must be in 1..{hi} {KIND_NAMES[terms.kind]}"
    if terms.expires_at <= now:
        return "expires_at must be in the future"
    if terms.expires_at > now + life:
        return f"expires_at is more than {life} {KIND_NAMES[terms.kind]} ahead"
    if terms.periods_from is not None and terms.periods_from >= terms.expires_at:
        return "periods_from must be before expires_at"
    if terms.due_at is not None:
        if terms.per_sale:
            return "a rule that pays per sale has no due point"
        if not fixed:
            return "a due point needs a fixed slot: the node names no recipient"
        if not now < terms.due_at < terms.expires_at:
            return "due_at must be in the future and before expires_at"
    if terms.repeats:
        if terms.due_at is None:
            return "a rule that repeats needs its first due point (due_at)"
        if terms.due_every is not None and terms.due_months is not None:
            return "due_every and due_months exclude each other"
        if terms.due_every is not None:
            lo = MIN_DUE_EVERY_BLOCKS if terms.kind == KIND_BLOCKS else MIN_DUE_EVERY_SECONDS
            if not lo <= terms.due_every <= hi:
                return f"due_every must be in {lo}..{hi} {KIND_NAMES[terms.kind]}"
        else:
            if terms.kind != KIND_SECONDS:
                return "due_months needs the time clock (period_seconds)"
            if not 1 <= terms.due_months <= MAX_DUE_MONTHS:
                return f"due_months must be in 1..{MAX_DUE_MONTHS}"
    if terms.on_arrival:
        if not terms.per_sale:
            return "on_arrival needs a rule that pays per sale"
        if not fixed:
            return "on_arrival needs a fixed slot: the node names no recipient"
    if terms.due_retry is not None:
        if terms.due_at is None:
            return "due_retry needs a due point (due_at)"
        if not 1 <= terms.due_retry <= hi:
            return f"due_retry must be in 1..{hi} {KIND_NAMES[terms.kind]}"
    if terms.rule_index is not None and not 1 <= terms.rule_index < MAX_RULES_PER_ACCOUNT:
        return f"rule_index must be 1..{MAX_RULES_PER_ACCOUNT - 1}"
    return None


# --- Evaluation ------------------------------------------------------------------


def _key_literal(pubkey: str) -> str:
    return "{ #x" + pubkey + " }:bv[%d]" % KEY_WIDTH


def execution_inputs(terms: PayoutTerms, state: PayoutState, exe: PayoutExecution, *,
                     parent_balance: int, height: int, ts: int) -> Dict[int, str]:
    """The payout ABI input map for one execution (stream index -> value)."""
    named = dict(exe.recipients)
    data = dict(exe.data)
    values: Dict[int, str] = {
        STREAM_BALANCE: str(max(0, min(int(parent_balance), tau_defs.MAX_TRANSFER_VALUE))),
        STREAM_TIME: str(int(ts)),
        STREAM_HEIGHT: str(int(height)),
        STREAM_EXECUTOR: _key_literal(exe.executor_pubkey) if exe.executor_pubkey else "0",
        STREAM_SPENT: str(state.spent_at(terms, terms.clock(height, ts))),
    }
    if terms.reads_clocks:
        values[STREAM_INSTALLED] = str(state.anchor)
        values[STREAM_LAST_PAID] = str(state.last_clock or state.anchor)
    for k, slot in enumerate(terms.slots):
        who = slot or named.get(k, "")
        values[SLOT_BASE + k] = _key_literal(who) if who else "0"
    for k in range(MAX_DATA):
        values[DATA_BASE + k] = str(data.get(k, 0))
    if terms.per_sale:
        sale = state.sale(exe.sale_id) if exe.sale_id is not None else None
        if sale is None:
            raise PayoutRefused("the sale named is not an open sale of this rule")
        values[STREAM_SALE_AMOUNT] = str(sale[2])
        values[STREAM_SALE_PAYER] = _key_literal(sale[1])
    return values


def parse_amount(value: Any) -> int:
    """An output value as an integer; absent is 0."""
    from tau_policy import parse_o5

    if value is None:
        return 0
    parsed = parse_o5(str(value))
    return 0 if parsed is None else int(parsed)


# The refusal of a run whose rule pays nothing. A run on arrival that pays
# nothing leaves the payment whole; every other refusal refuses the payment.
PAYS_NOTHING = "the rule pays nothing for these inputs"


def settle(terms: PayoutTerms, state: PayoutState, exe: PayoutExecution,
           outputs: Dict[str, Any], *, height: int, ts: int,
           balance: int) -> List[Tuple[int, str, int]]:
    """The legs (slot, recipient, amount) of one execution, or PayoutRefused.

    All or none: every check runs before anything moves.
    """
    named = dict(exe.recipients)
    legs: List[Tuple[int, str, int]] = []
    for k, slot in enumerate(terms.slots):
        amount = parse_amount(outputs.get(f"o{SLOT_BASE + k}"))
        if amount <= 0:
            continue
        who = slot or named.get(k)
        if not who:
            raise PayoutRefused(f"the rule pays open slot {k}, but no recipient was named")
        legs.append((k, who, amount))
    total = sum(a for _, _, a in legs)
    if total <= 0:
        raise PayoutRefused(PAYS_NOTHING)
    if total > terms.cap_per_execution:
        raise PayoutRefused(
            f"the rule pays {total}, over the cap per execution {terms.cap_per_execution}")
    spent = state.spent_at(terms, terms.clock(height, ts))
    if spent + total > terms.cap_per_period:
        raise PayoutRefused(
            f"the rule pays {total}; with {spent} paid this period that is over "
            f"the cap per period {terms.cap_per_period}")
    if total > balance:
        raise PayoutShort(f"the rule pays {total}, the account holds {balance}")
    return legs


def policy_inputs(account: str, recipient: str, amount: int, *, parent_balance: Any,
                  since_last: Optional[Any], slots_active: bool, timestamp: int) -> Dict[int, str]:
    """The o5 inputs of one payment of a run: those of a plain transfer of `amount`
    from the account to `recipient`, same keys, values and order, with no custom
    input and every approval slot empty (nobody co-signs a run). `since_last` is
    None while the cooldown stream is off."""
    values: Dict[int, str] = {1: str(amount), 2: str(parent_balance)}
    if since_last is not None:
        values[16] = str(since_last)
    values[3] = "{ #x" + str(account) + " }:bv[384]"
    values[4] = "{ #x" + str(recipient) + " }:bv[384]"
    values[12] = "{ #x" + str(account) + " }:bv[384]"
    if slots_active:
        for idx in tau_defs.approval_slot_indices():
            values[idx] = "0"
    values[5] = str(timestamp)
    return values


def check_policy(terms: PayoutTerms, legs: List[Tuple[int, str, int]], clause: Optional[str], *,
                 pool: str, timeout: Any, replay_mode: bool = False, **feed: Any) -> None:
    """PayoutPolicyBlocked when the account's current o5 clause blocks a payment.

    Every payment of a run is asked like a transfer from the account. Not asked
    without a clause, nor for a rule signed with `policy_exempt`. A replay
    without an evaluator moves nothing, as for the rule itself.
    """
    if terms.policy_exempt or not clause:
        return
    from consensus import sender_policy

    for k, who, amount in legs:
        values = policy_inputs(terms.account_pubkey, who, amount, **feed)
        try:
            blocked, _ = sender_policy.clause_blocks(clause, values, pool=pool, timeout=timeout)
        except Exception:
            if not replay_mode:
                raise
            raise PayoutRefused("no evaluator during replay") from None
        if blocked:
            raise PayoutPolicyBlocked(f"the account's o5 clause blocks the payment of slot {k}")


# --- The book --------------------------------------------------------------------

# The 16 fields of encode_payout_entry; then `sales` for a per-sale rule; then
# `more` for an extended rule (with `sales` None before it when it is not per-sale).
_Row = Tuple


def _with_extras(row: Tuple, terms: "PayoutTerms", state: "PayoutState") -> Tuple:
    sales = (state.sales_missed, state.open_sales) if terms.per_sale else None
    more = state.more(terms)
    if more is not None:
        return row + (sales, more)
    return row + (sales,) if sales is not None else row


def _restore_more(more: Any, rid: bytes) -> Dict[str, Any]:
    """A stored `more`, checked: the optional terms and the progress they keep.
    Everything is absent for a rule without it."""
    out: Dict[str, Any] = {"periods_from": None, "due_at": None, "due_every": None,
                           "due_months": None, "on_arrival": False, "sealed": False,
                           "last_clock": 0, "due_done": False, "due_index": 0,
                           "rule_index": None, "due_retry": None, "retry_at": 0,
                           "retry_until": 0, "policy_exempt": False}
    if more is None:
        return out
    try:
        more = tuple(more)
        if len(more) not in (4, 9, 13, 14):
            raise ValueError
        out["periods_from"], out["due_at"], out["last_clock"], out["due_done"] = more[:4]
        if len(more) >= 9:
            (out["due_every"], out["due_months"], out["on_arrival"], out["sealed"],
             out["due_index"]) = more[4:9]
        if len(more) >= 13:
            out["rule_index"], out["due_retry"], out["retry_at"], out["retry_until"] = more[9:13]
        if len(more) == 14:
            if more[13] is not True and more[13] != 1:
                raise ValueError
            out["policy_exempt"] = True
    except (TypeError, ValueError):
        raise ValueError(f"stored payout rule has malformed optional terms: {rid.hex()}") from None
    for name in ("periods_from", "due_at", "due_every", "due_months", "rule_index",
                 "due_retry"):
        value = out[name]
        if value is not None and not (_is_int(value) and 0 <= value <= _U64_MAX):
            raise ValueError(f"stored payout rule has a bad optional term: {rid.hex()}")
    for name in ("on_arrival", "sealed", "due_done"):
        if out[name] not in (0, 1, False, True):
            raise ValueError(f"stored payout rule has a bad switch: {rid.hex()}")
        out[name] = bool(out[name])
    for name in ("last_clock", "due_index", "retry_at", "retry_until"):
        if not (_is_int(out[name]) and out[name] >= 0):
            raise ValueError(f"stored payout rule has bad clocks: {rid.hex()}")
        out[name] = int(out[name])
    if out["due_done"] and out["due_at"] is None:
        raise ValueError(f"stored payout rule ran a due point it does not have: {rid.hex()}")
    if out["rule_index"] is not None and not 1 <= out["rule_index"] < MAX_RULES_PER_ACCOUNT:
        raise ValueError(f"stored payout rule has a bad place: {rid.hex()}")
    if (out["retry_at"] == 0) != (out["retry_until"] == 0) or (
            out["retry_at"] and (out["due_retry"] is None
                                 or out["retry_at"] >= out["retry_until"])):
        raise ValueError(f"stored payout rule has an impossible retry: {rid.hex()}")
    return out


def _with_sale(open_sales: Tuple[Tuple[bytes, str, int, int], ...],
               entry: Tuple[bytes, str, int, int]):
    """`open_sales` with `entry` recorded, and the sale left out (None if none).

    Below MAX_OPEN_SALES the sale is added. At the bound it takes the place of
    the smallest open sale if it is larger (of equally small ones, the one
    recorded last gives way), else it is the one left out."""
    if len(open_sales) < MAX_OPEN_SALES:
        return open_sales + (entry,), None
    low = min(range(len(open_sales)), key=lambda i: (open_sales[i][2], -i))
    if entry[2] <= open_sales[low][2]:
        return open_sales, entry
    return open_sales[:low] + open_sales[low + 1:] + (entry,), open_sales[low]


def _restore_sales(sales: Any, rid: bytes) -> Tuple[Tuple[Tuple[bytes, str, int, int], ...], int]:
    """A stored (missed, open sales) pair, checked; ((), 0) for a rule without it."""
    if sales is None:
        return (), 0
    try:
        missed, entries = sales
        out = []
        for sale_id, payer, amount, height in entries:
            sale_id = bytes.fromhex(sale_id) if isinstance(sale_id, str) else bytes(sale_id)
            if len(sale_id) != 32 or not _PUBKEY_RE.match(str(payer)):
                raise ValueError
            if not (_is_int(amount) and 1 <= amount <= tau_defs.MAX_TRANSFER_VALUE
                    and _is_int(height) and height >= 0):
                raise ValueError
            out.append((sale_id, str(payer), int(amount), int(height)))
    except (TypeError, ValueError):
        raise ValueError(f"stored payout rule has malformed sales: {rid.hex()}") from None
    if not _is_int(missed) or missed < 0 or len(out) > MAX_OPEN_SALES \
            or len({e[0] for e in out}) != len(out):
        raise ValueError(f"stored payout rule has impossible sales: {rid.hex()}")
    return tuple(out), int(missed)


class PayoutBook:
    """The installed rules, at most MAX_RULES_PER_ACCOUNT per account. A rule
    sits under its key: the account for the first place, `account/k` for place
    k. Copies share the frozen terms and states."""

    def __init__(self) -> None:
        self.terms: Dict[str, PayoutTerms] = {}
        self.state: Dict[str, PayoutState] = {}
        # (expires_at, key), sorted, per clock.
        self._expiry: Dict[int, List[Tuple[int, str]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        # (due_at, key) of the rules whose due point has not run, sorted, per clock.
        self._due: Dict[int, List[Tuple[int, str]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        # (retry_at, key) of the rules that owe an unpaid due point a retry, per clock.
        self._retry: Dict[int, List[Tuple[int, str]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        # keys of the rules the node runs on arrival that hold an open sale
        self._arrivals: set = set()
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PayoutBook":
        clone = PayoutBook.__new__(PayoutBook)
        clone.terms = dict(self.terms)
        clone.state = dict(self.state)
        clone._expiry = {k: list(rows) for k, rows in self._expiry.items()}
        clone._due = {k: list(rows) for k, rows in self._due.items()}
        clone._retry = {k: list(rows) for k, rows in self._retry.items()}
        clone._arrivals = set(self._arrivals)
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[Tuple], resolved_count: int,
                resolved_acc: bytes) -> "PayoutBook":
        """Rebuild from stored rows (key, sequence, body, slots, caps, kind,
        period, expires_at, rule_id, anchor, state...); refuses a row whose id
        does not recompute or whose state is impossible."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for row in rows:
            row = tuple(row)
            sales = row[16] if len(row) > 16 else None
            more = row[17] if len(row) > 17 else None
            (stored_id, key, sequence, body, slots, cap_exec, cap_period, kind,
             period, expires_at, anchor, period_index, spent, executions, paid_total,
             last_height) = row[:16]
            if kind not in KIND_NAMES:
                raise ValueError("stored payout rule has an unknown period clock")
            if not (_is_int(period) and period >= 1):
                raise ValueError("stored payout rule has a bad period")
            kept = _restore_more(more, bytes(stored_id))
            account = str(key).split("/", 1)[0]
            terms = PayoutTerms(account, sequence, body, tuple(slots), cap_exec,
                                cap_period, kind, period, expires_at, sales is not None,
                                kept["periods_from"], kept["due_at"], kept["due_every"],
                                kept["due_months"], kept["on_arrival"], kept["sealed"],
                                kept["rule_index"], kept["due_retry"],
                                kept["policy_exempt"])
            rid = terms.rule_id
            if rid != bytes(stored_id):
                raise ValueError(f"stored payout rule id does not match its terms: {rid.hex()}")
            if terms.key != key:
                raise ValueError(f"stored payout rule sits in the wrong place: {rid.hex()}")
            if key in book.terms:
                raise ValueError(f"two stored payout rules for one place: {str(key)[:18]}")
            if (more is not None) != terms.extended:
                raise ValueError(f"stored payout rule and its optional terms disagree: {rid.hex()}")
            open_sales, missed = _restore_sales(sales, rid)
            state = PayoutState(anchor, period_index, spent, executions, paid_total,
                                last_height, open_sales, missed, kept["last_clock"],
                                kept["due_done"], kept["due_index"], kept["retry_at"],
                                kept["retry_until"])
            if more is not None and len(tuple(more)) != len(state.more(terms) or ()):
                raise ValueError(f"stored payout rule and its optional terms disagree: {rid.hex()}")
            if state.due_index and not terms.repeats:
                raise ValueError(f"stored payout rule counts due points it does not have: {rid.hex()}")
            if not all(_is_int(v) and v >= 0 for v in (anchor, period_index, spent,
                                                        executions, paid_total, last_height)):
                raise ValueError(f"stored payout rule has bad progress: {rid.hex()}")
            # Only a spend carried from a replaced rule can stand over the cap,
            # and then the rule has paid nothing yet (an execution needs room).
            if spent > tau_defs.MAX_TRANSFER_VALUE or (spent > cap_period and executions) \
                    or (executions == 0) != (paid_total == 0):
                raise ValueError(f"stored payout rule has inconsistent progress: {rid.hex()}")
            book._insert(terms, state)
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals ---------------------------------------------------------------

    def _insert(self, terms: PayoutTerms, state: PayoutState) -> None:
        key = terms.key
        self.terms[key] = terms
        self.state[key] = state
        bisect.insort(self._expiry[terms.kind], (terms.expires_at, key))
        due = state.next_due(terms)
        if due is not None:
            bisect.insort(self._due[terms.kind], (due, key))
        if state.retry_at:
            bisect.insort(self._retry[terms.kind], (state.retry_at, key))
        if terms.on_arrival and state.open_sales:
            self._arrivals.add(key)
        self._root = None

    def _remove(self, key: str, outcome: int) -> PayoutTerms:
        terms = self.terms.pop(key)
        state = self.state.pop(key)
        rows = self._expiry[terms.kind]
        del rows[bisect.bisect_left(rows, (terms.expires_at, key))]
        due = state.next_due(terms)
        if due is not None:
            rows = self._due[terms.kind]
            del rows[bisect.bisect_left(rows, (due, key))]
        if state.retry_at:
            rows = self._retry[terms.kind]
            del rows[bisect.bisect_left(rows, (state.retry_at, key))]
        self._arrivals.discard(key)
        self.resolved_acc = compute_payout_resolved_acc(self.resolved_acc, terms.rule_id, outcome)
        self.resolved_count += 1
        self._root = None
        return terms

    def _set_retry(self, key: str, retry_at: int, retry_until: int) -> None:
        terms, state = self.terms[key], self.state[key]
        rows = self._retry[terms.kind]
        if state.retry_at:
            del rows[bisect.bisect_left(rows, (state.retry_at, key))]
        if retry_at:
            bisect.insort(rows, (retry_at, key))
        self.state[key] = replace(state, retry_at=retry_at, retry_until=retry_until)
        self._root = None

    # -- queries -----------------------------------------------------------------

    def _row(self, key: str) -> _Row:
        t, s = self.terms[key], self.state[key]
        row = (t.rule_id, t.account_pubkey, t.sequence_number, t.body_hash, t.slots,
               t.cap_per_execution, t.cap_per_period, t.kind, t.period, t.expires_at,
               s.anchor, s.period_index, s.spent_in_period, s.executions,
               s.paid_total, s.last_height)
        return _with_extras(row, t, s)

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_payout_book_root(
                [self._row(k) for k in self.terms], self.resolved_count, self.resolved_acc)
        return self._root

    def is_empty(self) -> bool:
        """True while the book has never held a rule (it then stays out of the hash)."""
        return not self.terms and self.resolved_count == 0

    def get(self, key: str) -> Optional[PayoutTerms]:
        """The rule under `key`: an account names its first rule."""
        return self.terms.get(key)

    def state_of(self, key: str) -> Optional[PayoutState]:
        return self.state.get(key)

    def keys_of(self, account: Any) -> List[str]:
        """The keys of the account's rules, first place first."""
        if not isinstance(account, str):
            return []
        return [k for k in (payout_key(account, i) for i in range(MAX_RULES_PER_ACCOUNT))
                if k in self.terms]

    def count(self) -> int:
        return len(self.terms)

    def has_expiring(self, height: int, ts: int) -> bool:
        h, t = self._expiry[KIND_BLOCKS], self._expiry[KIND_SECONDS]
        return bool((h and h[0][0] <= height) or (t and t[0][0] <= ts))

    def has_due(self, height: int, ts: int) -> bool:
        h, t = self._due[KIND_BLOCKS], self._due[KIND_SECONDS]
        return bool((h and h[0][0] <= height) or (t and t[0][0] <= ts))

    def due(self, height: int, ts: int,
            cap: int = MAX_PAYOUT_DUE_RUNS_PER_BLOCK) -> List[str]:
        """The keys of the rules the node runs in this block: every due point
        this block's clock reached and that has not run, earliest first (rules
        on the block clock before rules on the time clock), at most `cap`."""
        out: List[str] = []
        for kind, clock in ((KIND_BLOCKS, height), (KIND_SECONDS, ts)):
            for due_at, key in self._due[kind]:
                if due_at > clock or len(out) >= cap:
                    break
                out.append(key)
        return out

    def due_execution(self, key: str) -> Tuple[PayoutTerms, PayoutState, PayoutExecution]:
        """The run the node makes at a rule's due point: no executor, no named
        recipient, no data."""
        terms, state = self.terms[key], self.state[key]
        if not state.due_pending(terms):
            raise KeyError(key)
        return terms, state, PayoutExecution("", terms.account_pubkey, terms.rule_id, (), ())

    def due_ran(self, key: str, clock: Optional[int] = None,
                short: bool = False) -> Optional[int]:
        """The due point of the rule under `key` has run, paid or not: each one
        runs once. A rule that repeats is queued for its next due point after
        `clock`, the block's value on the rule's clock, if that lies before the
        rule's end. A retry the rule still owed for an earlier due point ends
        here. When the run found the account `short` and the rule carries
        `due_retry`, the node owes this due point a retry: from the next value
        of the clock on, while the clock is before the due point plus
        `due_retry`, the rule's next due point and its end, whichever comes
        first. Returns where the retry starts, else None."""
        terms, state = self.terms[key], self.state[key]
        due = state.next_due(terms)
        if due is None:
            raise KeyError(key)
        rows = self._due[terms.kind]
        del rows[bisect.bisect_left(rows, (due, key))]
        now = due if clock is None else int(clock)
        index, done = state.due_index, True
        if terms.repeats:
            index = terms.due_index_after(state.due_index, now)
            done = terms.due_point(index) >= terms.expires_at
        self.state[key] = replace(state, due_done=done, due_index=index)
        if not done:
            bisect.insort(rows, (terms.due_point(index), key))
        self._root = None
        retry_at, retry_until = 0, 0
        if short and terms.due_retry is not None:
            retry_until = min(due + terms.due_retry, terms.expires_at)
            if not done:
                retry_until = min(retry_until, terms.due_point(index))
            retry_at = now + 1
            if retry_at >= retry_until:
                retry_at, retry_until = 0, 0
        if retry_at or self.state[key].retry_at:
            self._set_retry(key, retry_at, retry_until)
        return retry_at or None

    # -- retries of a due point that found the account short ---------------------------

    def has_retry(self, height: int, ts: int) -> bool:
        h, t = self._retry[KIND_BLOCKS], self._retry[KIND_SECONDS]
        return bool((h and h[0][0] <= height) or (t and t[0][0] <= ts))

    def retries(self, height: int, ts: int,
                cap: int = MAX_PAYOUT_RETRY_RUNS_PER_BLOCK) -> Tuple[List[str], List[str]]:
        """(keys the node retries in this block, at most `cap`, longest waiting
        first; keys whose retry ended unpaid). A retry ends when the rule's
        clock reaches its `retry_until`."""
        run: List[str] = []
        ended: List[str] = []
        for kind, clock in ((KIND_BLOCKS, height), (KIND_SECONDS, ts)):
            for retry_at, key in self._retry[kind]:
                if retry_at > clock:
                    break
                if clock >= self.state[key].retry_until:
                    ended.append(key)
                elif len(run) < cap:
                    run.append(key)
        return run, ended

    def retry_execution(self, key: str) -> Tuple[PayoutTerms, PayoutState, PayoutExecution]:
        """The run the node makes again for an unpaid due point: as at the due point."""
        terms, state = self.terms[key], self.state[key]
        if not state.retry_at:
            raise KeyError(key)
        return terms, state, PayoutExecution("", terms.account_pubkey, terms.rule_id, (), ())

    def retry_ran(self, key: str, clock: int, short: bool = False) -> Optional[int]:
        """A retry ran. Found the account short again, it is owed once more
        from the next value of the clock on, inside the same window; paid or
        refused for any other reason, it is done. Returns where the next retry
        starts, else None."""
        state = self.state[key]
        if not state.retry_at:
            raise KeyError(key)
        retry_at, retry_until = 0, 0
        if short and int(clock) + 1 < state.retry_until:
            retry_at, retry_until = int(clock) + 1, state.retry_until
        self._set_retry(key, retry_at, retry_until)
        return retry_at or None

    def retry_ended(self, key: str) -> None:
        """The retry's window closed before the account could pay."""
        if not self.state[key].retry_at:
            raise KeyError(key)
        self._set_retry(key, 0, 0)

    # -- runs on arrival, and the seal ----------------------------------------------

    def sealed(self, account: Any) -> bool:
        """One of the account's rules is sealed: until it ends, the node takes
        no transaction the account signs."""
        return any(self.terms[k].sealed for k in self.keys_of(account))

    def has_arrivals(self) -> bool:
        return bool(self._arrivals)

    def arrivals(self, cap: int = MAX_PAYOUT_ARRIVAL_RUNS_PER_BLOCK) -> List[Tuple[str, bytes]]:
        """The open sales the node runs in this block, (key, sale_id), at most
        `cap`: every rule's longest-waiting sale first, then every rule's
        second, and so on; within one such round the sale of the earlier block
        first, then by key. So a rule with many sales waiting does not hold up
        the single sale of another."""
        rows = []
        for key in self._arrivals:
            for position, (sale_id, _payer, _amount, height) in enumerate(
                    self.state[key].open_sales[:cap]):
                rows.append((position, height, key, sale_id))
        rows.sort()
        return [(key, sale_id) for _, _, key, sale_id in rows[:cap]]

    def arrival_execution(self, key: str,
                          sale_id: bytes) -> Tuple[PayoutTerms, PayoutState, PayoutExecution]:
        """The run the node makes for one sale: no executor, no named recipient,
        no data."""
        terms, state = self.terms[key], self.state[key]
        if not terms.on_arrival or state.sale(sale_id) is None:
            raise KeyError(key)
        return terms, state, PayoutExecution("", terms.account_pubkey, terms.rule_id,
                                             (), (), bytes(sale_id))

    def arrival_key(self, account: Any, sale_id: bytes) -> Optional[str]:
        """The key of the account's rule the node runs on arrival when it holds
        this sale open, else None. An account has at most one such rule."""
        for key in self.keys_of(account):
            if self.terms[key].on_arrival and self.state[key].sale(bytes(sale_id)) is not None:
                return key
        return None

    def drop_sale(self, key: str, sale_id: bytes) -> None:
        """The node ran the rule for this sale and the rule paid nothing: the
        sale is closed, a run on arrival happens once."""
        terms, state = self.terms[key], self.state[key]
        left = tuple(e for e in state.open_sales if e[0] != bytes(sale_id))
        if len(left) != len(state.open_sales) - 1:
            raise KeyError("not an open sale of this rule")
        self.state[key] = replace(state, open_sales=left)
        if not left:
            self._arrivals.discard(key)
        self._root = None

    def store_rows(self) -> List[Tuple]:
        """Rows for persistence: the key instead of the account, the body text
        instead of its hash. A first-place rule's key is its account."""
        out = []
        for key in sorted(self.terms):
            t, s = self.terms[key], self.state[key]
            row = (t.rule_id, key, t.sequence_number, t.body, t.slots,
                   t.cap_per_execution, t.cap_per_period, t.kind, t.period,
                   t.expires_at, s.anchor, s.period_index, s.spent_in_period,
                   s.executions, s.paid_total, s.last_height)
            out.append(_with_extras(row, t, s))
        return out

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    # -- admission ---------------------------------------------------------------

    def can_admit_set(self, terms: PayoutTerms, height: int, ts: int) -> Tuple[bool, str]:
        reason = validate_terms_shape(terms, height, ts)
        if reason:
            return False, reason
        current = self.terms.get(terms.key)
        if current is not None and current.rule_id == terms.rule_id:
            return False, "this payout rule is already installed"
        if self.sealed(terms.account_pubkey):
            return False, "the account's payout rule is sealed until it ends"
        if terms.on_arrival and any(self.terms[k].on_arrival
                                    for k in self.keys_of(terms.account_pubkey)
                                    if k != terms.key):
            return False, ("the account already has a rule the node runs on arrival; "
                           "it may have one")
        if current is None and len(self.terms) >= MAX_PAYOUT_RULES_TOTAL:
            return False, "the payout rule book is full"
        return True, ""

    def can_admit_revoke(self, account: str, rule_index: int = 0) -> Tuple[bool, str]:
        if payout_key(account, rule_index) not in self.terms:
            if rule_index:
                return False, f"the account has no payout rule in place {int(rule_index)}"
            return False, "the account has no payout rule"
        if self.sealed(account):
            return False, "the account's payout rule is sealed until it ends"
        return True, ""

    def find(self, account: str, rule_id: bytes) -> Optional[str]:
        """The key of the account's rule with this id, else None."""
        for key in self.keys_of(account):
            if self.terms[key].rule_id == rule_id:
                return key
        return None

    def check_execution(self, exe: PayoutExecution, height: int,
                        ts: int) -> Tuple[PayoutTerms, PayoutState]:
        """The installed rule and its state for this execution, or PayoutRefused."""
        keys = self.keys_of(exe.account_pubkey)
        if not keys:
            raise PayoutRefused("the account has no payout rule")
        key = self.find(exe.account_pubkey, exe.rule_id)
        if key is None:
            if len(keys) == 1:
                raise PayoutRefused("the account's payout rule is not the one named")
            raise PayoutRefused("none of the account's payout rules is the one named")
        terms = self.terms[key]
        if terms.clock(height, ts) >= terms.expires_at:
            raise PayoutRefused("the payout rule has expired")
        for k, who in exe.recipients:
            if k >= len(terms.slots):
                raise PayoutRefused(f"slot {k} does not exist")
            if terms.slots[k]:
                raise PayoutRefused(f"slot {k} has a fixed recipient")
            if who == terms.account_pubkey:
                raise PayoutRefused("a slot may not pay the account itself")
        state = self.state[key]
        if terms.per_sale:
            if exe.sale_id is None:
                raise PayoutRefused("this payout rule pays per sale: name an open sale (sale_id)")
            if state.sale(exe.sale_id) is None:
                raise PayoutRefused("the sale named is not an open sale of this rule "
                                    "(never recorded, or already paid)")
        elif exe.sale_id is not None:
            raise PayoutRefused("this payout rule does not pay per sale")
        return terms, state

    # -- mutation ----------------------------------------------------------------

    def install(self, terms: PayoutTerms, anchor: int, height: Optional[int] = None,
                ts: Optional[int] = None) -> Optional[bytes]:
        """Install `terms` in its place; the id of a rule it replaced there, else None.

        A rule that replaces another in its place starts its first period with
        what that rule paid in its own current period (read on its own clock at
        this block) already spent, all of it, even above the new cap. So no
        replacement, and no chain of them through a lower cap, gives a period
        its cap again. A rule that has reached its end carries nothing. The
        block apply passes the block's `height` and `ts`; without them nothing
        is carried.
        """
        replaced, carried = None, 0
        if terms.key in self.terms:
            if height is not None:
                old, was = self.terms[terms.key], self.state[terms.key]
                now = old.clock(int(height), int(ts or 0))
                if now < old.expires_at:
                    carried = was.spent_at(old, now)
            replaced = self._remove(terms.key, OUTCOME_REPLACED).rule_id
        state = PayoutState(anchor=int(anchor))
        if carried:
            state = replace(state, period_index=state.period_at(terms, int(anchor)),
                            spent_in_period=carried)
        self._insert(terms, state)
        return replaced

    def revoke(self, key: str) -> PayoutTerms:
        if key not in self.terms:
            raise KeyError(key)
        return self._remove(key, OUTCOME_REVOKED)

    def record(self, key: str, total: int, height: int, ts: int,
               sale_id: Optional[bytes] = None) -> PayoutState:
        """A paid execution; for a per-sale rule it closes the sale it paid."""
        terms, state = self.terms[key], self.state[key]
        clock = terms.clock(height, ts)
        index = state.period_at(terms, clock)
        spent = state.spent_at(terms, clock)
        open_sales = state.open_sales
        if terms.per_sale:
            open_sales = tuple(e for e in open_sales if e[0] != sale_id)
            if len(open_sales) != len(state.open_sales) - 1:
                raise KeyError("the sale paid is not an open sale of this rule")
        state = replace(state, period_index=index, spent_in_period=spent + total,
                        executions=state.executions + 1,
                        paid_total=state.paid_total + total, last_height=int(height),
                        open_sales=open_sales,
                        last_clock=int(clock) if terms.extended else 0)
        self.state[key] = state
        if terms.on_arrival and not open_sales:
            self._arrivals.discard(key)
        self._root = None
        return state

    def pays_per_sale(self, account: str) -> bool:
        return any(self.terms[k].per_sale for k in self.keys_of(account))

    def note_sale(self, account: str, sale_id: bytes, payer: str, amount: int,
                  height: int, ts: Optional[int] = None) -> Optional[str]:
        """A signed transaction paid `account` `amount` in total: record it as an
        open sale of each per-sale rule the account holds, its id the
        transaction hash; each rule pays its own share of it under its own caps.
        Returns "recorded" (by at least one rule), "missed" (MAX_OPEN_SALES
        already open, none of them smaller), or None when the account has no
        per-sale rule that takes it, the payer is the account itself, or the
        sale is already recorded. A recorded sale may have taken the place of a
        smaller open one, which is then counted as missed."""
        noted = [self._note_sale_on(k, sale_id, payer, amount, height, ts)
                 for k in self.keys_of(account)]
        if "recorded" in noted:
            return "recorded"
        return "missed" if "missed" in noted else None

    def _note_sale_on(self, key: str, sale_id: bytes, payer: str, amount: int,
                      height: int, ts: Optional[int]) -> Optional[str]:
        """One rule's part of note_sale. A rule the node runs on arrival takes
        no sale once its end is reached: the node would owe a run the rule no
        longer promises."""
        terms = self.terms[key]
        if not terms.per_sale or payer == terms.account_pubkey or amount <= 0:
            return None
        if terms.on_arrival and ts is not None and terms.clock(height, ts) >= terms.expires_at:
            return None
        state = self.state[key]
        sale_id = bytes(sale_id)
        if state.sale(sale_id) is not None:
            return None
        # At most MAX_OPEN_SALES wait, also for a rule the node runs on arrival,
        # and a larger sale takes the place of the smallest: sales that pay
        # nothing cannot hold every place, and what waits for a run stays small.
        entry = (sale_id, payer, min(int(amount), tau_defs.MAX_TRANSFER_VALUE), int(height))
        open_sales, left_out = _with_sale(state.open_sales, entry)
        self.state[key] = replace(state, open_sales=open_sales,
                                  sales_missed=state.sales_missed + (0 if left_out is None else 1))
        self._root = None
        if left_out is entry:
            return "missed"
        if terms.on_arrival:
            self._arrivals.add(key)
        return "recorded"

    def expire(self, height: int, ts: int) -> List[PayoutTerms]:
        """Remove every rule whose end this block reached, earliest first. A rule
        whose due point has not run yet stays until it has, and so does a rule
        with a sale still waiting for its run on arrival: the node owes them. A
        retry never outlives the rule: its window closes at the rule's end."""
        gone: List[PayoutTerms] = []
        for kind, clock in ((KIND_BLOCKS, height), (KIND_SECONDS, ts)):
            rows = self._expiry[kind]
            # keys are lowercase hex, maybe "/" and a digit: "g" sorts after
            # every key at `clock`
            ended = [key for _, key in rows[:bisect.bisect_right(rows, (clock, "g"))]]
            for key in ended:
                if (not self.state[key].due_pending(self.terms[key])
                        and key not in self._arrivals):
                    gone.append(self._remove(key, OUTCOME_EXPIRED))
        return gone


def describe(terms: PayoutTerms, state: PayoutState, *, height: int = 0,
             ts: int = 0) -> Dict[str, Any]:
    """One installed rule as a wallet reads it."""
    clock = terms.clock(height, ts) if (height or ts) else None
    spent = state.spent_at(terms, clock) if clock is not None else state.spent_in_period
    return {
        "rule_id": terms.rule_id.hex(),
        "account_pubkey": terms.account_pubkey,
        "sequence_number": terms.sequence_number,
        "rule_text": f"always ( {terms.body} ).",
        "rule_sha256": hashlib.sha256(terms.body.encode("utf-8")).hexdigest(),
        "slots": [{"slot": k, "recipient_pubkey": s or None, "open": not s}
                  for k, s in enumerate(terms.slots)],
        "cap_per_execution": terms.cap_per_execution,
        "cap_per_period": terms.cap_per_period,
        "period_clock": KIND_NAMES[terms.kind],
        "period": terms.period,
        "anchor": state.anchor,
        **({"periods_from": terms.periods_from} if terms.periods_from is not None else {}),
        **({"due_at": terms.due_at, "due_done": state.due_done}
           if terms.due_at is not None else {}),
        **({"due_every": terms.due_every} if terms.due_every is not None else {}),
        **({"due_months": terms.due_months} if terms.due_months is not None else {}),
        **({"next_due": state.next_due(terms)} if terms.repeats else {}),
        **({"on_arrival": True} if terms.on_arrival else {}),
        **({"sealed": True} if terms.sealed else {}),
        **({"policy_exempt": True} if terms.policy_exempt else {}),
        **({"rule_index": terms.rule_index} if terms.rule_index is not None else {}),
        **({"due_retry": terms.due_retry} if terms.due_retry is not None else {}),
        **({"retry_at": state.retry_at, "retry_until": state.retry_until}
           if state.retry_at else {}),
        **({"last_paid_clock": state.last_clock or None} if terms.extended else {}),
        "expires_at": terms.expires_at,
        "spent_this_period": spent,
        "left_this_period": max(0, terms.cap_per_period - spent),
        "executions": state.executions,
        "paid_total": state.paid_total,
        "last_height": state.last_height or None,
        **({"per_sale": True,
            "open_sales": [{"sale_id": sid.hex(), "payer_pubkey": payer, "amount": amount,
                            "height": h} for sid, payer, amount, h in state.open_sales],
            "sales_missed": state.sales_missed} if terms.per_sale else {}),
    }
