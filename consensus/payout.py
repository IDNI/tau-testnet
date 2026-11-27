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
reaches it, after the block's transactions, at most
MAX_PAYOUT_DUE_RUNS_PER_BLOCK rules a block (the rest wait for the next
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
MAX_OPEN_SALES are open at once. When that many are open, a larger sale takes
the place of the smallest open one and the smaller is counted as missed; a sale
no larger than every open one is not recorded and is counted as missed. So
sales too small to pay anything (a 5% royalty pays nothing on 19 or less)
cannot hold every place and keep later sales out. Replacing, revoking or
expiring the rule
drops its open sales.
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
MAX_PERIOD_BLOCKS = 1_000_000
MAX_PERIOD_SECONDS = 31_622_400            # 366 days
MAX_LIFETIME_BLOCKS = 10_000_000
MAX_LIFETIME_SECONDS = 4 * 31_622_400      # four years of 366 days

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_MENTION_RE = re.compile(r"\b([io])(\d+)\b")
_CLOCKS_RE = re.compile(r"\bi(?:%d|%d)\b" % (STREAM_INSTALLED, STREAM_LAST_PAID))
_TYPED_RE = re.compile(r"\s*\[\s*t\s*\]\s*:\s*bv\s*\[\s*(\d+)\s*\]")


class PayoutShapeError(ValueError):
    """A payout transaction does not have a shape the node can record."""


class PayoutRefused(ValueError):
    """An execution the rule, its caps or the balance do not allow. Nothing moves."""


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


# --- Terms and state -------------------------------------------------------------


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

    @property
    def body_hash(self) -> bytes:
        return compute_payout_body_hash(self.body)

    @property
    def rule_id(self) -> bytes:
        return compute_payout_rule_id(
            self.account_pubkey, self.sequence_number, self.body_hash, self.slots,
            self.cap_per_execution, self.cap_per_period, self.kind, self.period,
            self.expires_at, self.per_sale, self.periods_from, self.due_at,
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
        return self.periods_from is not None or self.due_at is not None or self.reads_clocks

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
    due_done: bool = False       # the node has run the rule at its due point

    def sale(self, sale_id: bytes) -> Optional[Tuple[bytes, str, int, int]]:
        for entry in self.open_sales:
            if entry[0] == sale_id:
                return entry
        return None

    def period_at(self, terms: PayoutTerms, clock: int) -> int:
        base = self.anchor if terms.periods_from is None else terms.periods_from
        return max(0, int(clock) - base) // terms.period

    def due_pending(self, terms: PayoutTerms) -> bool:
        return terms.due_at is not None and not self.due_done

    def more(self, terms: PayoutTerms) -> Optional[Tuple]:
        """(periods_from, due_at, last_clock, due_done) for an extended rule."""
        if not terms.extended:
            return None
        return (terms.periods_from, terms.due_at, self.last_clock, self.due_done)

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
    optional = {}
    for field in ("periods_from", "due_at"):
        if field in fields:
            optional[field] = _u64(fields, field)
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
               "periods_from", "due_at")


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


def parse_payout_rule_revoke(tx: Dict[str, Any]) -> str:
    if not isinstance(tx, dict):
        raise PayoutShapeError("transaction must be an object")
    return _pubkey(tx.get("sender_pubkey"), "sender_pubkey")


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
        raise PayoutRefused("the rule pays nothing for these inputs")
    if total > terms.cap_per_execution:
        raise PayoutRefused(
            f"the rule pays {total}, over the cap per execution {terms.cap_per_execution}")
    spent = state.spent_at(terms, terms.clock(height, ts))
    if spent + total > terms.cap_per_period:
        raise PayoutRefused(
            f"the rule pays {total}; with {spent} paid this period that is over "
            f"the cap per period {terms.cap_per_period}")
    if total > balance:
        raise PayoutRefused(f"the rule pays {total}, the account holds {balance}")
    return legs


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


def _restore_more(more: Any, rid: bytes) -> Tuple[Optional[int], Optional[int], int, bool]:
    """A stored `more`, checked; (None, None, 0, False) for a rule without it."""
    if more is None:
        return None, None, 0, False
    try:
        periods_from, due_at, last_clock, due_done = more
    except (TypeError, ValueError):
        raise ValueError(f"stored payout rule has malformed optional terms: {rid.hex()}") from None
    for value in (periods_from, due_at):
        if value is not None and not (_is_int(value) and 0 <= value <= _U64_MAX):
            raise ValueError(f"stored payout rule has a bad optional term: {rid.hex()}")
    if not (_is_int(last_clock) and last_clock >= 0) or due_done not in (0, 1, False, True):
        raise ValueError(f"stored payout rule has bad clocks: {rid.hex()}")
    if due_done and due_at is None:
        raise ValueError(f"stored payout rule ran a due point it does not have: {rid.hex()}")
    return periods_from, due_at, int(last_clock), bool(due_done)


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
    """One installed rule per account. Copies share the frozen terms and states."""

    def __init__(self) -> None:
        self.terms: Dict[str, PayoutTerms] = {}
        self.state: Dict[str, PayoutState] = {}
        # (expires_at, account), sorted, per clock.
        self._expiry: Dict[int, List[Tuple[int, str]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        # (due_at, account) of the rules whose due point has not run, sorted, per clock.
        self._due: Dict[int, List[Tuple[int, str]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PayoutBook":
        clone = PayoutBook.__new__(PayoutBook)
        clone.terms = dict(self.terms)
        clone.state = dict(self.state)
        clone._expiry = {k: list(rows) for k, rows in self._expiry.items()}
        clone._due = {k: list(rows) for k, rows in self._due.items()}
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[Tuple], resolved_count: int,
                resolved_acc: bytes) -> "PayoutBook":
        """Rebuild from stored rows (account, sequence, body, slots, caps, kind,
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
            (stored_id, account, sequence, body, slots, cap_exec, cap_period, kind,
             period, expires_at, anchor, period_index, spent, executions, paid_total,
             last_height) = row[:16]
            if kind not in KIND_NAMES:
                raise ValueError("stored payout rule has an unknown period clock")
            if not (_is_int(period) and period >= 1):
                raise ValueError("stored payout rule has a bad period")
            periods_from, due_at, last_clock, due_done = _restore_more(more, bytes(stored_id))
            terms = PayoutTerms(account, sequence, body, tuple(slots), cap_exec,
                                cap_period, kind, period, expires_at, sales is not None,
                                periods_from, due_at)
            rid = terms.rule_id
            if rid != bytes(stored_id):
                raise ValueError(f"stored payout rule id does not match its terms: {rid.hex()}")
            if account in book.terms:
                raise ValueError(f"two stored payout rules for one account: {account[:16]}")
            if (more is not None) != terms.extended:
                raise ValueError(f"stored payout rule and its optional terms disagree: {rid.hex()}")
            open_sales, missed = _restore_sales(sales, rid)
            state = PayoutState(anchor, period_index, spent, executions, paid_total,
                                last_height, open_sales, missed, last_clock, due_done)
            if not all(_is_int(v) and v >= 0 for v in (anchor, period_index, spent,
                                                        executions, paid_total, last_height)):
                raise ValueError(f"stored payout rule has bad progress: {rid.hex()}")
            if spent > cap_period or (executions == 0) != (paid_total == 0):
                raise ValueError(f"stored payout rule has inconsistent progress: {rid.hex()}")
            book._insert(terms, state)
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals ---------------------------------------------------------------

    def _insert(self, terms: PayoutTerms, state: PayoutState) -> None:
        self.terms[terms.account_pubkey] = terms
        self.state[terms.account_pubkey] = state
        bisect.insort(self._expiry[terms.kind], (terms.expires_at, terms.account_pubkey))
        if state.due_pending(terms):
            bisect.insort(self._due[terms.kind], (terms.due_at, terms.account_pubkey))
        self._root = None

    def _remove(self, account: str, outcome: int) -> PayoutTerms:
        terms = self.terms.pop(account)
        state = self.state.pop(account)
        rows = self._expiry[terms.kind]
        del rows[bisect.bisect_left(rows, (terms.expires_at, account))]
        if state.due_pending(terms):
            due = self._due[terms.kind]
            del due[bisect.bisect_left(due, (terms.due_at, account))]
        self.resolved_acc = compute_payout_resolved_acc(self.resolved_acc, terms.rule_id, outcome)
        self.resolved_count += 1
        self._root = None
        return terms

    # -- queries -----------------------------------------------------------------

    def _row(self, account: str) -> _Row:
        t, s = self.terms[account], self.state[account]
        row = (t.rule_id, t.account_pubkey, t.sequence_number, t.body_hash, t.slots,
               t.cap_per_execution, t.cap_per_period, t.kind, t.period, t.expires_at,
               s.anchor, s.period_index, s.spent_in_period, s.executions,
               s.paid_total, s.last_height)
        return _with_extras(row, t, s)

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_payout_book_root(
                [self._row(a) for a in self.terms], self.resolved_count, self.resolved_acc)
        return self._root

    def is_empty(self) -> bool:
        """True while the book has never held a rule (it then stays out of the hash)."""
        return not self.terms and self.resolved_count == 0

    def get(self, account: str) -> Optional[PayoutTerms]:
        return self.terms.get(account)

    def state_of(self, account: str) -> Optional[PayoutState]:
        return self.state.get(account)

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
        """The accounts whose rule the node runs in this block: every due point
        this block's clock reached and that has not run, earliest first (rules
        on the block clock before rules on the time clock), at most `cap`."""
        out: List[str] = []
        for kind, clock in ((KIND_BLOCKS, height), (KIND_SECONDS, ts)):
            for due_at, account in self._due[kind]:
                if due_at > clock or len(out) >= cap:
                    break
                out.append(account)
        return out

    def due_execution(self, account: str) -> Tuple[PayoutTerms, PayoutState, PayoutExecution]:
        """The run the node makes at a rule's due point: no executor, no named
        recipient, no data."""
        terms, state = self.terms[account], self.state[account]
        if not state.due_pending(terms):
            raise KeyError(account)
        return terms, state, PayoutExecution("", account, terms.rule_id, (), ())

    def due_ran(self, account: str) -> None:
        """The due point of `account`'s rule has run, paid or not: it runs once."""
        terms, state = self.terms[account], self.state[account]
        if not state.due_pending(terms):
            raise KeyError(account)
        rows = self._due[terms.kind]
        del rows[bisect.bisect_left(rows, (terms.due_at, account))]
        self.state[account] = replace(state, due_done=True)
        self._root = None

    def store_rows(self) -> List[Tuple]:
        """Rows for persistence: the body text instead of its hash."""
        out = []
        for account in sorted(self.terms):
            t, s = self.terms[account], self.state[account]
            row = (t.rule_id, account, t.sequence_number, t.body, t.slots,
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
        current = self.terms.get(terms.account_pubkey)
        if current is not None and current.rule_id == terms.rule_id:
            return False, "this payout rule is already installed"
        if current is None and len(self.terms) >= MAX_PAYOUT_RULES_TOTAL:
            return False, "the payout rule book is full"
        return True, ""

    def can_admit_revoke(self, account: str) -> Tuple[bool, str]:
        if account not in self.terms:
            return False, "the account has no payout rule"
        return True, ""

    def check_execution(self, exe: PayoutExecution, height: int,
                        ts: int) -> Tuple[PayoutTerms, PayoutState]:
        """The installed rule and its state for this execution, or PayoutRefused."""
        terms = self.terms.get(exe.account_pubkey)
        if terms is None:
            raise PayoutRefused("the account has no payout rule")
        if terms.rule_id != exe.rule_id:
            raise PayoutRefused("the account's payout rule is not the one named")
        if terms.clock(height, ts) >= terms.expires_at:
            raise PayoutRefused("the payout rule has expired")
        for k, who in exe.recipients:
            if k >= len(terms.slots):
                raise PayoutRefused(f"slot {k} does not exist")
            if terms.slots[k]:
                raise PayoutRefused(f"slot {k} has a fixed recipient")
            if who == terms.account_pubkey:
                raise PayoutRefused("a slot may not pay the account itself")
        state = self.state[exe.account_pubkey]
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

    def install(self, terms: PayoutTerms, anchor: int) -> Optional[bytes]:
        """Install `terms`; the id of a rule it replaced, else None."""
        replaced = None
        if terms.account_pubkey in self.terms:
            replaced = self._remove(terms.account_pubkey, OUTCOME_REPLACED).rule_id
        self._insert(terms, PayoutState(anchor=int(anchor)))
        return replaced

    def revoke(self, account: str) -> PayoutTerms:
        if account not in self.terms:
            raise KeyError(account)
        return self._remove(account, OUTCOME_REVOKED)

    def record(self, account: str, total: int, height: int, ts: int,
               sale_id: Optional[bytes] = None) -> PayoutState:
        """A paid execution; for a per-sale rule it closes the sale it paid."""
        terms, state = self.terms[account], self.state[account]
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
        self.state[account] = state
        self._root = None
        return state

    def pays_per_sale(self, account: str) -> bool:
        terms = self.terms.get(account)
        return terms is not None and terms.per_sale

    def note_sale(self, account: str, sale_id: bytes, payer: str, amount: int,
                  height: int) -> Optional[str]:
        """A signed transaction paid `account` `amount` in total: record it as an
        open sale of the account's per-sale rule, its id the transaction hash.
        Returns "recorded", "missed" (MAX_OPEN_SALES already open, none of them
        smaller), or None when the account has no per-sale rule, the payer is the
        account itself, or the sale is already recorded. A recorded sale may have
        taken the place of a smaller open one, which is then counted as missed."""
        terms = self.terms.get(account)
        if terms is None or not terms.per_sale or payer == account or amount <= 0:
            return None
        state = self.state[account]
        sale_id = bytes(sale_id)
        if state.sale(sale_id) is not None:
            return None
        # At most MAX_OPEN_SALES are open, and a larger sale takes the place of
        # the smallest: sales that pay nothing cannot hold every place.
        entry = (sale_id, payer, min(int(amount), tau_defs.MAX_TRANSFER_VALUE), int(height))
        open_sales, left_out = _with_sale(state.open_sales, entry)
        missed = state.sales_missed + (0 if left_out is None else 1)
        self.state[account] = replace(state, open_sales=open_sales, sales_missed=missed)
        self._root = None
        return "missed" if left_out is entry else "recorded"

    def expire(self, height: int, ts: int) -> List[PayoutTerms]:
        """Remove every rule whose end this block reached, earliest first. A rule
        whose due point has not run yet stays until it has: the node owes it."""
        gone: List[PayoutTerms] = []
        for kind, clock in ((KIND_BLOCKS, height), (KIND_SECONDS, ts)):
            rows = self._expiry[kind]
            # keys are lowercase hex, so "g" sorts after every account at `clock`
            ended = [account for _, account in rows[:bisect.bisect_right(rows, (clock, "g"))]]
            for account in ended:
                if not self.state[account].due_pending(self.terms[account]):
                    gone.append(self._remove(account, OUTCOME_EXPIRED))
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
        **({"last_paid_clock": state.last_clock or None} if terms.extended else {}),
        "expires_at": terms.expires_at,
        "spent_this_period": spent,
        "left_this_period": terms.cap_per_period - spent,
        "executions": state.executions,
        "paid_total": state.paid_total,
        "last_height": state.last_height or None,
        **({"per_sale": True,
            "open_sales": [{"sale_id": sid.hex(), "payer_pubkey": payer, "amount": amount,
                            "height": h} for sid, payer, amount, h in state.open_sales],
            "sales_missed": state.sales_missed} if terms.per_sale else {}),
    }
