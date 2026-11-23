"""Receive routing rules: an account's money split on arrival (#35).

An account installs ONE receive route with `route_set`: a Tau clause, one
fixed destination, a minimum incoming amount, an activation time and an end.
From then on, when an ordinary credit lands on the account, the node steps
the clause once in an isolated policy worker, reads the routed amount, and
splits the gross credit atomically: net to the account, routed to the
destination.

    routed = the rule's o30 for this arrival (0 when the rule does not write it)
    net    = gross - routed
    0 <= routed <= gross (a rule that routes more is refused for this credit:
    the gross lands whole, and the refusal is logged -- a broken route must
    never burn value, and must not let a recipient grief senders by failing
    their transfers)

A route is a second, separate authorization for the account's incoming
money, chosen by the account: the o5 clause governs transfers the account
signs, the route governs credits the account receives. Installing, replacing
and revoking a route are rule changes, so an account's rule-change guard
judges them (kinds 8 and 9) and a guarded account installs one through a
rule-change request.

ROUTE ABI v1 (CONSENSUS-FROZEN)
--------------------------------
A route rule is evaluated in its own policy pool, never beside o5 clauses,
and every stream it mentions must carry exactly the width below. Stream
typing is process-global and sticky in an interpreter process, so fixed
widths are what let any number of route rules share one worker.

    i2   bv[24]   the account's balance at the parent block (capped at bv[24])
    i5   bv[64]   block timestamp
    i6   bv[64]   block height
    i27  bv[24]   the gross amount of the credit arriving now
    i28  bv[384]  who paid it
    o30  bv[24]   the routed amount (0 when the rule does not write it)

A rule reads [t] only, reads at least one input and writes o30, and mentions
no other stream. The shape is the payout rule's definitional shape (see
consensus/payout.py): every amount a definition, a condition chooses between
definitions, no temporal operator, no step constraint, no quantifier.

ON ARRIVAL
----------
A route is owed on every eligible credit, and the amount it is computed from
must not be the word of whoever claims it. The node therefore steps the
route itself, at the moment the credit is applied, with the gross amount the
transfer carries:

- **Eligible credits.** Ordinary signed transfers (`user_tx`) into the
  account while the route is installed. A transfer from the account itself
  is not a routed credit. Refunds, faucet/genesis funding, consensus
  fees/rewards and route outputs themselves are not routed credits.
- **Single hop.** A routed credit does not trigger the destination's route
  in the same originating transaction: the routed leg is written straight
  to the destination, never re-entered. Loops such as A routes to B and B
  routes to A therefore cannot recurse.
- **Minimum and window.** A credit below `min_amount`, or outside
  [`active_from`, `expires_at`), lands whole: the route does not apply.
- **Atomic.** Gross, net and routed commit together or not at all: the
  split is staged with the transfer's own writes, so a refused transfer
  moves nothing.
- **One fee.** The sender pays the transfer's fee as evaluated; the split
  itself costs no extra fee.
"""
from __future__ import annotations

import bisect
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.payout import (
    KIND_BLOCKS,
    KIND_NAMES,
    KIND_SECONDS,
    MAX_RULE_BYTES,
    _key_literal,
    parse_amount,
    payout_rule_body,
    PayoutShapeError,
    screen_payout_body,
)
from consensus.serialization import (
    compute_route_book_root,
    compute_route_resolved_acc,
    compute_route_rule_id,
)

TX_TYPE_ROUTE_SET = "route_set"
TX_TYPE_ROUTE_REVOKE = "route_revoke"

ROUTE_TX_TYPES = frozenset({TX_TYPE_ROUTE_SET, TX_TYPE_ROUTE_REVOKE})

# The pools route rules are stepped in: never the o5 pools, never the payout pools.
POOL_APPLY = "route_apply"
POOL_ADMISSION = "route_admission"

# Expiry clocks (shared with payout rules).
EXPIRY_FIELDS = (("expiry_blocks", KIND_BLOCKS), ("expiry_seconds", KIND_SECONDS))

# Folded into the removal commitment, one byte each.
OUTCOME_REVOKED = 1
OUTCOME_EXPIRED = 2
OUTCOME_REPLACED = 3
OUTCOME_NAMES = {OUTCOME_REVOKED: "revoked", OUTCOME_EXPIRED: "expired",
                 OUTCOME_REPLACED: "replaced"}

STREAM_BALANCE = 2
STREAM_TIME = 5
STREAM_HEIGHT = 6
STREAM_GROSS = 27
STREAM_PAYER = 28
SLOT_ROUTED = 30

AMOUNT_WIDTH = tau_defs.TRANSFER_VALUE_BV_WIDTH
KEY_WIDTH = 384
CLOCK_WIDTH = 64

MAX_ROUTES_TOTAL = 4096
MAX_LIFETIME_BLOCKS = 10_000_000
MAX_LIFETIME_SECONDS = 4 * 31_622_400      # four years of 366 days

ZERO_ACC = bytes(32)

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF
_MENTION_RE = re.compile(r"\b([io])(\d+)\b")

# Streams a route rule may mention: reads i2/i5/i6/i27/i28, writes o30 only.
_ROUTE_READS = {(1, 2), (1, 5), (1, 6), (1, 27), (1, 28)}
_ROUTE_WRITES = {(0, 30)}


class RouteShapeError(ValueError):
    """A receive route transaction does not have a shape the node can record."""


class RouteRefused(ValueError):
    """A route does not apply to this credit, or its rule refuses it."""


@dataclass(frozen=True)
class RouteTerms:
    """What the account signed. Immutable."""

    account_pubkey: str
    sequence_number: int
    body: str
    destination: str               # the fixed recipient of the routed share
    min_amount: int = 0            # credits below this land whole
    active_from: int = 0           # the route applies from this clock value
    expires_at: int = 0            # the route ends at this clock value
    kind: int = KIND_BLOCKS        # the clock active_from/expires_at use

    @property
    def body_hash(self) -> bytes:
        from consensus.serialization import compute_route_body_hash

        return compute_route_body_hash(self.body)

    @property
    def rule_id(self) -> bytes:
        return compute_route_rule_id(
            self.account_pubkey, self.sequence_number, self.body_hash,
            self.destination, self.min_amount, self.active_from,
            self.expires_at, self.kind,
        )

    def clock(self, height: int, ts: int) -> int:
        return height if self.kind == KIND_BLOCKS else ts


@dataclass(frozen=True)
class RouteState:
    """Where an installed route stands. Replaced, never mutated."""

    anchor: int = 0                # the clock when the route was installed


# --- Parsing ---------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey(value: Any, what: str) -> str:
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise RouteShapeError(f"{what} must be a 96-hex-char public key")
    return value


def _u64(fields: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    value = fields.get(name, default)
    if value is None:
        if default is not None:
            return default
        raise RouteShapeError(f"{name} is required")
    if not _is_int(value) or not 0 <= value <= _U64_MAX:
        raise RouteShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _check_route_streams(body: str) -> Optional[str]:
    """Only i2/i5/i6/i27/i28 may be read, only o30 may be written."""
    for direction, num in _MENTION_RE.findall(body):
        is_input = direction == "i"
        if is_input and (1, int(num)) not in _ROUTE_READS:
            return f"a route rule may not read i{num}"
        if not is_input and (0, int(num)) not in _ROUTE_WRITES:
            return f"a route rule may only write o30, not o{num}"
    return None


def _terms_from_fields(fields: Dict[str, Any], account: str, sequence: int) -> RouteTerms:
    try:
        body = payout_rule_body(fields.get("rule_text"))
    except PayoutShapeError as exc:
        raise RouteShapeError(str(exc)) from exc
    shape = screen_payout_body(body, slot_count=1, per_sale=True)
    if shape is not None:
        raise RouteShapeError(f"route rule shape refused: {shape}")
    streams = _check_route_streams(body)
    if streams is not None:
        raise RouteShapeError(streams)
    destination = _pubkey(fields.get("destination"), "destination")
    if destination == account:
        raise RouteShapeError("the route destination may not be the account itself")
    present = [(n, kind) for n, kind in EXPIRY_FIELDS if fields.get(n) is not None]
    if len(present) != 1:
        raise RouteShapeError("exactly one of expiry_blocks and expiry_seconds is required")
    name, kind = present[0]
    return RouteTerms(
        account_pubkey=account,
        sequence_number=sequence,
        body=body,
        destination=destination,
        min_amount=_u64(fields, "min_amount", 0),
        active_from=_u64(fields, "active_from", 0),
        expires_at=_u64(fields, name),
        kind=kind,
    )


SPEC_FIELDS = ("rule_text", "destination", "min_amount", "active_from",
               "expiry_blocks", "expiry_seconds")


def parse_route_set(tx: Dict[str, Any]) -> RouteTerms:
    """Read a receive route from ROOT fields only; a nested `payload` is unsigned."""
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    account = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    sequence = _u64(tx, "sequence_number")
    return _terms_from_fields(tx, account, sequence)


def route_spec_text(fields: Dict[str, Any], sequence_number: Optional[int] = None) -> str:
    """CONSENSUS-FROZEN. The canonical text of a route's terms: sorted keys,
    no spaces. A rule-change request (kind 8) carries it as `rule_text` without
    a sequence number; the request's stored body adds the request's own
    sequence number, which then enters the installed route's id."""
    spec = {k: fields[k] for k in SPEC_FIELDS if fields.get(k) is not None}
    if sequence_number is not None:
        spec["sequence_number"] = int(sequence_number)
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_route_spec(text: Any, account: str,
                     sequence_number: Optional[int] = None) -> RouteTerms:
    """Terms from canonical spec text. Refuses any text that is not exactly its
    own canonical form, so one set of terms has one body hash and one request
    id. The sequence number comes from the text (a stored body) or from the
    caller (a request as sent), never from both."""
    if not isinstance(text, str):
        raise RouteShapeError("route spec must be a string")
    try:
        fields = json.loads(text)
    except ValueError as exc:
        raise RouteShapeError(f"route spec is not JSON: {exc}") from exc
    if not isinstance(fields, dict) or set(fields) - set(SPEC_FIELDS) - {"sequence_number"}:
        raise RouteShapeError(f"route spec may carry only {', '.join(SPEC_FIELDS)}")
    stored = fields.get("sequence_number")
    if (stored is None) == (sequence_number is None):
        raise RouteShapeError("route spec needs exactly one sequence number")
    if route_spec_text(fields, stored) != text:
        raise RouteShapeError("route spec is not in canonical form")
    sequence = stored if stored is not None else sequence_number
    if not _is_int(sequence) or not 0 <= sequence <= _U64_MAX:
        raise RouteShapeError("sequence_number must be an unsigned 64-bit integer")
    return _terms_from_fields(fields, account, sequence)


def parse_route_revoke(tx: Dict[str, Any]) -> str:
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    return _pubkey(tx.get("sender_pubkey"), "sender_pubkey")


def validate_terms_shape(terms: RouteTerms, height: int, ts: int) -> Optional[str]:
    """Why these terms may not be installed now, or None."""
    clock = terms.clock(height, ts)
    if terms.expires_at <= clock:
        return "the route has already ended"
    lifetime = terms.expires_at - clock
    limit = MAX_LIFETIME_BLOCKS if terms.kind == KIND_BLOCKS else MAX_LIFETIME_SECONDS
    if lifetime > limit:
        return "the route lives longer than the lifetime limit"
    if terms.active_from >= terms.expires_at:
        return "active_from must be before expires_at"
    if terms.min_amount > tau_defs.MAX_TRANSFER_VALUE:
        return "min_amount is over the largest transfer"
    return None


def route_inputs(terms: RouteTerms, *, gross: int, payer: str,
                 parent_balance: int, height: int, ts: int) -> Dict[int, str]:
    """The route ABI input map for one arrival (stream index -> value)."""
    return {
        STREAM_BALANCE: str(max(0, min(int(parent_balance), tau_defs.MAX_TRANSFER_VALUE))),
        STREAM_TIME: str(int(ts)),
        STREAM_HEIGHT: str(int(height)),
        STREAM_GROSS: str(int(gross)),
        STREAM_PAYER: _key_literal(payer),
    }


def settle_route(terms: RouteTerms, outputs: Dict[str, Any], *, gross: int) -> int:
    """The routed amount for this arrival, or RouteRefused.

    A rule that routes more than the gross is refused for this credit: the
    gross lands whole. A rule that routes nothing routes nothing.
    """
    routed = parse_amount(outputs.get(f"o{SLOT_ROUTED}"))
    if routed < 0:
        raise RouteRefused("the route rule routes a negative amount")
    if routed > gross:
        raise RouteRefused(
            f"the route rule routes {routed}, over the gross credit {gross}")
    return routed


# --- The book --------------------------------------------------------------------


_Row = Tuple  # the 11 fields of encode_route_entry


class RouteBook:
    """One installed route per account. Copies share the frozen terms."""

    def __init__(self) -> None:
        self.terms: Dict[str, RouteTerms] = {}
        self.state: Dict[str, RouteState] = {}
        # (expires_at, account), sorted, per clock.
        self._expiry: Dict[int, List[Tuple[int, str]]] = {KIND_BLOCKS: [], KIND_SECONDS: []}
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "RouteBook":
        clone = RouteBook.__new__(RouteBook)
        clone.terms = dict(self.terms)
        clone.state = dict(self.state)
        clone._expiry = {k: list(rows) for k, rows in self._expiry.items()}
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[Tuple], resolved_count: int,
                resolved_acc: bytes) -> "RouteBook":
        """Rebuild from stored rows (account, sequence, body, destination,
        min_amount, active_from, expires_at, kind, anchor, rule_id); refuses a
        row whose id does not recompute."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for row in rows:
            row = tuple(row)
            (stored_id, account, sequence, body, destination, min_amount,
             active_from, expires_at, kind, anchor) = row[:10]
            if kind not in KIND_NAMES:
                raise ValueError("stored route has an unknown expiry clock")
            terms = RouteTerms(account, sequence, body, destination, min_amount,
                               active_from, expires_at, kind)
            rid = terms.rule_id
            if rid != bytes(stored_id):
                raise ValueError(f"stored route id does not match its terms: {rid.hex()}")
            if account in book.terms:
                raise ValueError(f"two stored routes for one account: {account[:16]}")
            book._insert(terms, RouteState(anchor))
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals ---------------------------------------------------------------

    def _insert(self, terms: RouteTerms, state: RouteState) -> None:
        self.terms[terms.account_pubkey] = terms
        self.state[terms.account_pubkey] = state
        bisect.insort(self._expiry[terms.kind], (terms.expires_at, terms.account_pubkey))
        self._root = None

    def _remove(self, account: str, outcome: int) -> RouteTerms:
        terms = self.terms.pop(account)
        del self.state[account]
        rows = self._expiry[terms.kind]
        del rows[bisect.bisect_left(rows, (terms.expires_at, account))]
        self.resolved_acc = compute_route_resolved_acc(self.resolved_acc, terms.rule_id, outcome)
        self.resolved_count += 1
        self._root = None
        return terms

    # -- queries -----------------------------------------------------------------

    def _row(self, account: str) -> _Row:
        t, s = self.terms[account], self.state[account]
        return (t.rule_id, t.account_pubkey, t.sequence_number, t.body_hash,
                t.destination, t.min_amount, t.active_from, t.expires_at,
                t.kind, s.anchor)

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_route_book_root(
                [self._row(a) for a in self.terms], self.resolved_count, self.resolved_acc)
        return self._root

    def is_empty(self) -> bool:
        """True while the book has never held a route (it then stays out of the hash)."""
        return not self.terms and self.resolved_count == 0

    def get(self, account: str) -> Optional[RouteTerms]:
        return self.terms.get(account)

    def state_of(self, account: str) -> Optional[RouteState]:
        return self.state.get(account)

    def count(self) -> int:
        return len(self.terms)

    def has_expiring(self, height: int, ts: int) -> bool:
        h, t = self._expiry[KIND_BLOCKS], self._expiry[KIND_SECONDS]
        return bool((h and h[0][0] <= height) or (t and t[0][0] <= ts))

    def store_rows(self) -> List[Tuple]:
        """Rows for persistence: the body text instead of its hash."""
        out = []
        for account in sorted(self.terms):
            t, s = self.terms[account], self.state[account]
            out.append((t.rule_id, account, t.sequence_number, t.body,
                        t.destination, t.min_amount, t.active_from, t.expires_at,
                        t.kind, s.anchor))
        return out

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    # -- admission ---------------------------------------------------------------

    def can_admit_set(self, terms: RouteTerms, height: int, ts: int) -> Tuple[bool, str]:
        reason = validate_terms_shape(terms, height, ts)
        if reason:
            return False, reason
        current = self.terms.get(terms.account_pubkey)
        if current is not None and current.rule_id == terms.rule_id:
            return False, "this receive route is already installed"
        if current is None and len(self.terms) >= MAX_ROUTES_TOTAL:
            return False, "the receive route book is full"
        return True, ""

    def can_admit_revoke(self, account: str) -> Tuple[bool, str]:
        if account not in self.terms:
            return False, "the account has no receive route"
        return True, ""

    # -- mutation ----------------------------------------------------------------

    def install(self, terms: RouteTerms, anchor: int) -> Optional[bytes]:
        """Install `terms`; the id of a route it replaced, else None."""
        replaced = None
        if terms.account_pubkey in self.terms:
            replaced = self._remove(terms.account_pubkey, OUTCOME_REPLACED).rule_id
        self._insert(terms, RouteState(anchor=int(anchor)))
        return replaced

    def revoke(self, account: str) -> RouteTerms:
        if account not in self.terms:
            raise KeyError(account)
        return self._remove(account, OUTCOME_REVOKED)

    def expire(self, height: int, ts: int) -> List[RouteTerms]:
        """Remove every route whose end this block reached, earliest first."""
        gone: List[RouteTerms] = []
        for kind, clock in ((KIND_BLOCKS, height), (KIND_SECONDS, ts)):
            rows = self._expiry[kind]
            while rows and rows[0][0] <= clock:
                gone.append(self._remove(rows[0][1], OUTCOME_EXPIRED))
        return gone


def describe(terms: RouteTerms, state: RouteState, *, height: int = 0,
             ts: int = 0) -> Dict[str, Any]:
    """One installed route as a wallet reads it."""
    clock = terms.clock(height, ts)
    return {
        "account_pubkey": terms.account_pubkey,
        "rule_id": terms.rule_id.hex(),
        "rule_text": terms.body,
        "destination": terms.destination,
        "min_amount": terms.min_amount,
        "active_from": terms.active_from,
        "expires_at": terms.expires_at,
        "clock": KIND_NAMES[terms.kind],
        "active": terms.active_from <= clock < terms.expires_at,
        "installed_at": state.anchor,
    }
