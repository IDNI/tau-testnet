"""Rule-computed payouts (#63): a Tau rule decides who is paid how much.

An account owner installs a payout rule with ``payout_rule_install``:

- ``rule_text``: one Tau clause body (evaluated as ``always ( body ).`` in an
  isolated policy worker of its own pool, so its stream typing cannot clash
  with the chain's interpreter or with o5 policy clauses);
- ``recipients``: up to ``MAX_PAYOUT_LEGS`` declared recipient keys. Recipient
  slot k (1-based) is paid what the rule writes on output stream ``o<k>``,
  typed ``bv[24]``; a slot the rule leaves unwritten is paid 0;
- declared caps: ``max_per_execution`` and ``max_per_period`` over a period
  (``consensus.periods``), plus an optional active window.

Anyone may submit ``payout_execute`` with the rule's inputs. The node runs the
rule, reads the amounts, checks the total against the caps, then executes every
leg through the OWNER's ordinary transfer gates (current o5 policy, fee step,
balance). All legs apply atomically or none do. The executor pays the fee for
the execute transaction.

Rule inputs
-----------
- ``i1``  = the owner's spendable balance before the execution (bv[24]);
- ``i2``  = executions so far in the current period (bv[24]);
- ``i3``  = the period index (bv[64]);
- ``i13`` .. ``i20`` = values supplied by the executor in ``inputs``
  ({"13": "..."}), each a decimal or a Tau literal, bv[24] by convention.

The rule cannot name a recipient the owner did not declare: recipients are
bound at install time, and the rule only chooses amounts.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Dict, List, Optional, Tuple

import tau_defs
from consensus import periods
from consensus.serialization import compute_payout_book_root, compute_payout_rule_id

TX_TYPE_PAYOUT_INSTALL = "payout_rule_install"
TX_TYPE_PAYOUT_EXECUTE = "payout_execute"
TX_TYPE_PAYOUT_REMOVE = "payout_rule_remove"
PAYOUT_TX_TYPES = frozenset({TX_TYPE_PAYOUT_INSTALL, TX_TYPE_PAYOUT_EXECUTE, TX_TYPE_PAYOUT_REMOVE})

PAYOUT_POLICY_POOL = "payout"
MAX_PAYOUT_LEGS = 8
MAX_RULES_PER_OWNER = 4
MAX_RULES_TOTAL = 4096
MAX_RULE_TEXT_BYTES = 8192
EXECUTOR_INPUT_MIN = 13
EXECUTOR_INPUT_MAX = 20
MAX_INPUT_TEXT = 128

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_INPUT_VALUE_RE = re.compile(r"^(\d{1,20}|\{ ?#[xb][0-9a-fA-F]+ ?\}(:bv\[\d{1,3}\])?)$")


class PayoutShapeError(ValueError):
    """A payout transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class PayoutTerms:
    owner_pubkey: str
    rule_text: str
    recipients: Tuple[str, ...]
    max_per_execution: int
    max_per_period: int
    period_kind: int
    period_seconds: int
    start_at: int
    expires_at: int  # 0 = none
    sequence_number: int

    def as_tuple(self) -> tuple:
        return (self.owner_pubkey, self.rule_text, self.recipients, self.max_per_execution,
                self.max_per_period, self.period_kind, self.period_seconds, self.start_at,
                self.expires_at, self.sequence_number)

    @property
    def rule_id(self) -> bytes:
        return compute_payout_rule_id(*self.as_tuple())

    def period_of(self, ts: int) -> int:
        return periods.period_index(self.period_kind, ts, anchor=self.start_at,
                                    length=self.period_seconds)

    def active_at(self, ts: int) -> bool:
        return ts >= self.start_at and (not self.expires_at or ts < self.expires_at)


@dataclass(frozen=True)
class PayoutState:
    terms: PayoutTerms
    period_index: int
    paid_in_period: int
    executions_in_period: int
    executions: int
    total_paid: int

    def paid_this_period(self, ts: int) -> Tuple[int, int]:
        """(paid, executions) in the period containing ts."""
        if self.terms.period_of(ts) == self.period_index:
            return self.paid_in_period, self.executions_in_period
        return 0, 0


@dataclass(frozen=True)
class PayoutExecute:
    executor_pubkey: str
    rule_id: bytes
    inputs: Tuple[Tuple[int, str], ...]


@dataclass(frozen=True)
class PayoutRemove:
    owner_pubkey: str
    rule_id: bytes


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _pubkey(value: Any, name: str) -> str:
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise PayoutShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64(tx: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    v = tx.get(name, default)
    if not _is_int(v) or v < 0 or v > _U64_MAX:
        raise PayoutShapeError(f"{name} must be an unsigned 64-bit integer")
    return v


def _rid(tx: Dict[str, Any]) -> bytes:
    raw = tx.get("rule_id")
    if not isinstance(raw, str) or not _ID_RE.match(raw):
        raise PayoutShapeError("rule_id must be 64 lowercase hex characters")
    return bytes.fromhex(raw)


def parse_payout_install(tx: Dict[str, Any]) -> PayoutTerms:
    if not isinstance(tx, dict):
        raise PayoutShapeError("transaction must be an object")
    text = tx.get("rule_text")
    if not isinstance(text, str) or not text.strip():
        raise PayoutShapeError("rule_text must be a non-empty string")
    recipients = tx.get("recipients")
    if not isinstance(recipients, list):
        raise PayoutShapeError("recipients must be a list of public keys")
    return PayoutTerms(
        owner_pubkey=_pubkey(tx.get("sender_pubkey"), "sender_pubkey"),
        rule_text=text.strip(),
        recipients=tuple(_pubkey(r, "recipient") for r in recipients),
        max_per_execution=_u64(tx, "max_per_execution"),
        max_per_period=_u64(tx, "max_per_period"),
        period_kind=_u64(tx, "period_kind", periods.PERIOD_MONTH),
        period_seconds=_u64(tx, "period_seconds", 0),
        start_at=_u64(tx, "start_at", 0),
        expires_at=_u64(tx, "expires_at", 0),
        sequence_number=_u64(tx, "sequence_number"),
    )


def parse_payout_execute(tx: Dict[str, Any]) -> PayoutExecute:
    if not isinstance(tx, dict):
        raise PayoutShapeError("transaction must be an object")
    raw = tx.get("inputs", {})
    if not isinstance(raw, dict):
        raise PayoutShapeError("inputs must be an object of stream -> value")
    items = []
    for key, value in raw.items():
        if not (isinstance(key, str) and key.isdigit()
                and EXECUTOR_INPUT_MIN <= int(key) <= EXECUTOR_INPUT_MAX):
            raise PayoutShapeError(
                f"inputs keys must be stream numbers {EXECUTOR_INPUT_MIN}..{EXECUTOR_INPUT_MAX}"
            )
        if not isinstance(value, str) or len(value) > MAX_INPUT_TEXT \
                or not _INPUT_VALUE_RE.match(value.strip()):
            raise PayoutShapeError(f"input {key} must be a decimal or a Tau bitvector literal")
        items.append((int(key), value.strip()))
    return PayoutExecute(_pubkey(tx.get("sender_pubkey"), "sender_pubkey"), _rid(tx),
                         tuple(sorted(items)))


def parse_payout_remove(tx: Dict[str, Any]) -> PayoutRemove:
    if not isinstance(tx, dict):
        raise PayoutShapeError("transaction must be an object")
    return PayoutRemove(_pubkey(tx.get("sender_pubkey"), "sender_pubkey"), _rid(tx))


def validate_payout_terms(t: PayoutTerms, ts: int) -> Optional[str]:
    if not 1 <= len(t.recipients) <= MAX_PAYOUT_LEGS:
        return f"recipients must list 1..{MAX_PAYOUT_LEGS} keys"
    if len(set(t.recipients)) != len(t.recipients):
        return "recipients must be distinct"
    if t.owner_pubkey in t.recipients:
        return "the owner cannot be a recipient"
    if len(t.rule_text.encode("utf-8")) > MAX_RULE_TEXT_BYTES:
        return f"rule_text is longer than {MAX_RULE_TEXT_BYTES} bytes"
    if not 1 <= t.max_per_execution <= tau_defs.MAX_TRANSFER_VALUE:
        return f"max_per_execution must be in 1..{tau_defs.MAX_TRANSFER_VALUE}"
    if not t.max_per_execution <= t.max_per_period:
        return "max_per_period must be at least max_per_execution"
    try:
        periods.validate_period(t.period_kind, t.period_seconds)
    except periods.PeriodError as exc:
        return f"invalid period ({exc})"
    if t.expires_at and t.expires_at <= max(ts, t.start_at):
        return "expires_at must be in the future and after start_at"
    return None


def tau_amount(value: Optional[str]) -> int:
    """Parse one output value (decimal, #x.., #b.., optionally braced/typed) -> int."""
    if value is None:
        return 0
    text = str(value).strip()
    text = re.sub(r":bv\[\d+\]$", "", text).strip()
    text = text.strip("{} ")
    if text.startswith("#x"):
        return int(text[2:], 16)
    if text.startswith("#b"):
        return int(text[2:], 2)
    return int(text)


def rule_inputs(owner_balance: int, executions_in_period: int, period: int,
                executor_inputs: Tuple[Tuple[int, str], ...]) -> Dict[str, str]:
    """The input map the rule is stepped with (see the module docstring)."""
    values = {"i1": str(int(owner_balance)), "i2": str(int(executions_in_period)),
              "i3": str(int(period))}
    for idx, value in executor_inputs:
        values[f"i{idx}"] = value
    return values


def legs_from_outputs(terms: PayoutTerms, outputs: Dict[str, str]) -> List[Tuple[str, int]]:
    """[(recipient, amount)] for every slot with a positive amount, in slot order."""
    legs = []
    for slot, recipient in enumerate(terms.recipients, start=1):
        amount = tau_amount(outputs.get(f"o{slot}"))
        if amount:
            legs.append((recipient, amount))
    return legs


class PayoutBook:
    def __init__(self) -> None:
        self.rules: Dict[bytes, PayoutState] = {}
        self.changes = 0
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PayoutBook":
        clone = PayoutBook.__new__(PayoutBook)
        clone.rules = dict(self.rules)
        clone.changes = self.changes
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    def is_empty(self) -> bool:
        return not self.rules and not self.changes

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_payout_book_root(
                [(rid, s.terms.as_tuple(), s.period_index, s.paid_in_period,
                  s.executions, s.total_paid) for rid, s in self.rules.items()],
                self.changes,
            )
        return self._root

    def get(self, rid: bytes) -> Optional[PayoutState]:
        return self.rules.get(rid)

    def count_for(self, owner: str) -> int:
        return sum(1 for s in self.rules.values() if s.terms.owner_pubkey == owner)

    def can_admit_install(self, terms: PayoutTerms, ts: int) -> Tuple[bool, str]:
        reason = validate_payout_terms(terms, ts)
        if reason:
            return False, reason
        if terms.rule_id in self.rules:
            return False, "payout rule already installed"
        if self.count_for(terms.owner_pubkey) >= MAX_RULES_PER_OWNER:
            return False, f"owner already has {MAX_RULES_PER_OWNER} payout rules"
        if len(self.rules) >= MAX_RULES_TOTAL:
            return False, "payout rule book is full"
        return True, ""

    def can_admit_execute(self, req: PayoutExecute, ts: int) -> Tuple[bool, str]:
        state = self.rules.get(req.rule_id)
        if state is None:
            return False, "unknown payout rule"
        if not state.terms.active_at(ts):
            return False, "payout rule is not active now"
        return True, ""

    def check_legs(self, rid: bytes, legs: List[Tuple[str, int]], ts: int) -> Tuple[bool, str]:
        state = self.rules[rid]
        total = sum(a for _, a in legs)
        if total <= 0:
            return False, "the rule computed no payout"
        if total > state.terms.max_per_execution:
            return False, f"computed total {total} exceeds max_per_execution"
        paid, _ = state.paid_this_period(ts)
        if paid + total > state.terms.max_per_period:
            return False, f"computed total {total} exceeds what is left of max_per_period"
        return True, ""

    def can_admit_remove(self, req: PayoutRemove, ts: int) -> Tuple[bool, str]:
        state = self.rules.get(req.rule_id)
        if state is None:
            return False, "unknown payout rule"
        if state.terms.owner_pubkey != req.owner_pubkey:
            return False, "only the owner may remove a payout rule"
        return True, ""

    def install(self, terms: PayoutTerms) -> bytes:
        rid = terms.rule_id
        self.rules[rid] = PayoutState(terms, 0, 0, 0, 0, 0)
        self.changes += 1
        self._root = None
        return rid

    def record(self, rid: bytes, total: int, ts: int) -> PayoutState:
        state = self.rules[rid]
        paid, count = state.paid_this_period(ts)
        after = replace(state, period_index=state.terms.period_of(ts),
                        paid_in_period=paid + total, executions_in_period=count + 1,
                        executions=state.executions + 1, total_paid=state.total_paid + total)
        self.rules[rid] = after
        self._root = None
        return after

    def remove(self, rid: bytes) -> PayoutState:
        state = self.rules.pop(rid)
        self.changes += 1
        self._root = None
        return state

    def expire_due(self, ts: int) -> List[bytes]:
        gone = sorted(r for r, s in self.rules.items() if s.terms.expires_at and s.terms.expires_at <= ts)
        for r in gone:
            self.remove(r)
        return gone

    def snapshot(self) -> Dict[str, Any]:
        out = []
        for rid, s in sorted(self.rules.items()):
            t = s.terms
            out.append({
                "rule_id": rid.hex(), "owner_pubkey": t.owner_pubkey, "rule_text": t.rule_text,
                "recipients": list(t.recipients), "max_per_execution": t.max_per_execution,
                "max_per_period": t.max_per_period, "period_kind": t.period_kind,
                "period_seconds": t.period_seconds, "start_at": t.start_at,
                "expires_at": t.expires_at, "sequence_number": t.sequence_number,
                "period_index": s.period_index, "paid_in_period": s.paid_in_period,
                "executions_in_period": s.executions_in_period, "executions": s.executions,
                "total_paid": s.total_paid,
            })
        return {"changes": self.changes, "rules": out}


def load_payout_book(state: Dict[str, Any]) -> PayoutBook:
    book = PayoutBook()
    for r in state.get("rules", []):
        terms = parse_payout_install({
            "sender_pubkey": r["owner_pubkey"], "rule_text": r["rule_text"],
            "recipients": r["recipients"], "max_per_execution": r["max_per_execution"],
            "max_per_period": r["max_per_period"], "period_kind": r["period_kind"],
            "period_seconds": r["period_seconds"], "start_at": r["start_at"],
            "expires_at": r["expires_at"], "sequence_number": r["sequence_number"],
        })
        if terms.rule_id.hex() != r["rule_id"]:
            raise ValueError(f"stored payout rule id does not match its terms: {r['rule_id']}")
        if r["paid_in_period"] > terms.max_per_period:
            raise ValueError("stored payout rule exceeds its period cap")
        book.rules[terms.rule_id] = PayoutState(
            terms, int(r["period_index"]), int(r["paid_in_period"]),
            int(r["executions_in_period"]), int(r["executions"]), int(r["total_paid"]))
    changes = state.get("changes", 0)
    if not _is_int(changes) or changes < len(book.rules):
        raise ValueError("stored payout change count is impossible")
    book.changes = changes
    return book
