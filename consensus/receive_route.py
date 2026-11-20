"""Receive routes: a share of every payment to an account, sent on as it lands (#35).

An account installs ONE receive route with `receive_route_set`: a destination
account, a share in basis points, and optionally a minimum credit, a start, an
end and a lock. From then on every payment credited to the account is split in
the same state transition that credits it:

    routed = floor(gross * share_bps / 10000)    (0 when gross < min_amount)
    net    = gross - routed

`net` lands on the account and `routed` on the destination. The payer signed
"gross to the account" and is charged exactly what it would be charged without
the route: routing has no fee of its own and changes no fee. The routed part
never touches the account's balance, so it is not a send of the account: no o5
clause of the account judges it, no cooldown clock is stamped, and nothing the
account's rules count as spent grows.

CREDIT CLASSES (CONSENSUS-FROZEN)
---------------------------------
Routed, because each is a payment someone made to the account:

    transfer             a transfer inside a user_tx
    approved_transfer    a parked transfer released by its co-signatures
    retractable_release  a retractable transfer reaching its release point
    standing_payment     a standing payment the end-of-block sweep makes
    payout               a leg of a payout rule's execution
    envelope_spend       a spend from an envelope, to its payee
    envelope_release     what an envelope holds when it is released or ends

Not routed, because none is a payment to the account:

    retract_refund       a retracted transfer's money returning to its sender
    faucet_grant         the grant of a new account
    fee                  a fee credited to the proposer or fee beneficiary
    routed_share         money that arrives through another account's route

The last line is what makes routing single-hop: a routed share is never routed
again, so A -> B -> A cannot loop and a chain of routes moves money one step.

A route is the account's own rule about money it receives, so setting,
replacing and removing it are rule changes: an account with a rule-change
guard (kinds 8 and 9) changes its route only through a rule-change request,
and one stolen key cannot silently redirect future receipts.

A LOCKED route protects the destination instead: until it ends, the owner can
neither remove nor weaken it (a replacement must keep the destination and give
it at least as much for at least as long). Only the destination can let go of
it early, with `receive_route_release`. A locked route must have an end.
"""
from __future__ import annotations

import bisect
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.serialization import (
    compute_receive_route_book_root,
    compute_receive_route_id,
    compute_receive_route_resolved_acc,
)

TX_TYPE_RECEIVE_ROUTE_SET = "receive_route_set"
TX_TYPE_RECEIVE_ROUTE_REMOVE = "receive_route_remove"
TX_TYPE_RECEIVE_ROUTE_RELEASE = "receive_route_release"

ROUTE_TX_TYPES = frozenset(
    {TX_TYPE_RECEIVE_ROUTE_SET, TX_TYPE_RECEIVE_ROUTE_REMOVE, TX_TYPE_RECEIVE_ROUTE_RELEASE}
)

# The credit classes, by the names receipts and history carry.
CREDIT_TRANSFER = "transfer"
CREDIT_APPROVED_TRANSFER = "approved_transfer"
CREDIT_RETRACTABLE_RELEASE = "retractable_release"
CREDIT_STANDING_PAYMENT = "standing_payment"
CREDIT_PAYOUT = "payout"
CREDIT_ENVELOPE_SPEND = "envelope_spend"
CREDIT_ENVELOPE_RELEASE = "envelope_release"
ROUTED_CLASSES = (CREDIT_TRANSFER, CREDIT_APPROVED_TRANSFER, CREDIT_RETRACTABLE_RELEASE,
                  CREDIT_STANDING_PAYMENT, CREDIT_PAYOUT, CREDIT_ENVELOPE_SPEND,
                  CREDIT_ENVELOPE_RELEASE)
UNROUTED_CLASSES = ("retract_refund", "faucet_grant", "fee", "routed_share")

# Removals folded into the book's commitment.
OUTCOME_REMOVED = 1
OUTCOME_RELEASED = 2
OUTCOME_EXPIRED = 3
OUTCOME_REPLACED = 4
OUTCOME_NAMES = {OUTCOME_REMOVED: "removed", OUTCOME_RELEASED: "released",
                 OUTCOME_EXPIRED: "expired", OUTCOME_REPLACED: "replaced"}

BPS_DENOMINATOR = 10_000
# The wire field takes 0..10000; the network installs at most 90%: an account
# always keeps at least a tenth of what it is paid, so a route can never leave
# it with nothing.
MAX_SHARE_BPS = 9_000
MAX_RECEIVE_ROUTES_TOTAL = 4096
MAX_START_DELAY_SECONDS = 31_622_400            # a start at most 366 days ahead
MAX_LIFETIME_SECONDS = 4 * 31_622_400           # an end at most four years ahead
MAX_LOCK_SECONDS = 31_622_400                   # a locked route ends within 366 days

ZERO_ACC = bytes(32)
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class RouteShapeError(ValueError):
    """A route transaction or spec that is malformed in itself."""


# --- Terms -----------------------------------------------------------------------


@dataclass(frozen=True)
class RouteTerms:
    """What the owner signed. Immutable."""

    owner_pubkey: str
    sequence_number: int
    destination_pubkey: str
    share_bps: int
    min_amount: int = 0
    active_from: int = 0        # unix seconds; 0 = from the block that installs it
    expires_at: int = 0         # unix seconds; 0 = no end
    locked: bool = False

    @property
    def route_id(self) -> bytes:
        return compute_receive_route_id(
            self.owner_pubkey, self.sequence_number, self.destination_pubkey,
            self.share_bps, self.min_amount, self.active_from, self.expires_at,
            self.locked,
        )

    def ended(self, ts: int) -> bool:
        return bool(self.expires_at) and int(ts) >= self.expires_at

    def is_active(self, ts: int) -> bool:
        return int(ts) >= self.active_from and not self.ended(ts)

    def binding(self, ts: int) -> bool:
        """True while the lock holds the owner to this route."""
        return self.locked and not self.ended(ts)

    def share_of(self, gross: int) -> int:
        """The routed part of a credit of `gross`, by the one rounding rule."""
        gross = int(gross)
        if gross <= 0 or gross < self.min_amount:
            return 0
        return gross * self.share_bps // BPS_DENOMINATOR

    def status(self, ts: int) -> str:
        if self.ended(ts):
            return "ended"
        return "active" if self.is_active(ts) else "scheduled"


# --- Parsing ---------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey(value: Any, what: str) -> str:
    if not isinstance(value, str) or len(value) != 96 or any(
            c not in "0123456789abcdef" for c in value):
        raise RouteShapeError(f"{what} must be 96 lowercase hex characters")
    return value


def _u64(fields: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    value = fields.get(name)
    if value is None and default is not None:
        return default
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise RouteShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


SPEC_FIELDS = ("destination_pubkey", "share_bps", "min_amount", "active_from",
               "expires_at", "locked")


def _terms_from_fields(fields: Dict[str, Any], owner: str, sequence: int) -> RouteTerms:
    destination = _pubkey(fields.get("destination_pubkey"), "destination_pubkey")
    share = fields.get("share_bps")
    if not _is_int(share) or not 0 <= share <= BPS_DENOMINATOR:
        raise RouteShapeError(f"share_bps must be an integer in 0..{BPS_DENOMINATOR}")
    locked = fields.get("locked", False)
    if locked is None:
        locked = False
    if not isinstance(locked, bool):
        raise RouteShapeError("locked must be true or false")
    return RouteTerms(
        owner_pubkey=owner,
        sequence_number=sequence,
        destination_pubkey=destination,
        share_bps=share,
        min_amount=_u64(fields, "min_amount", 0),
        active_from=_u64(fields, "active_from", 0),
        expires_at=_u64(fields, "expires_at", 0),
        locked=locked,
    )


def parse_receive_route_set(tx: Dict[str, Any]) -> RouteTerms:
    """Read a route from ROOT fields only; a nested `payload` is unsigned."""
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    owner = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    return _terms_from_fields(tx, owner, _u64(tx, "sequence_number"))


def parse_receive_route_remove(tx: Dict[str, Any]) -> str:
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    return _pubkey(tx.get("sender_pubkey"), "sender_pubkey")


def parse_receive_route_release(tx: Dict[str, Any]) -> Tuple[str, str, bytes]:
    """(destination signer, owner, route id) of a release."""
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    signer = _pubkey(tx.get("sender_pubkey"), "sender_pubkey")
    owner = _pubkey(tx.get("owner_pubkey"), "owner_pubkey")
    raw = tx.get("route_id")
    if not isinstance(raw, str) or len(raw) != 64 or any(
            c not in "0123456789abcdef" for c in raw):
        raise RouteShapeError("route_id must be 64 lowercase hex characters")
    return signer, owner, bytes.fromhex(raw)


def route_spec_text(fields: Dict[str, Any], sequence_number: Optional[int] = None) -> str:
    """CONSENSUS-FROZEN. The canonical text of a route's terms: sorted keys, no
    spaces, defaults left out (min_amount, active_from and expires_at 0, locked
    false). A rule-change request (kind 8) carries it as `rule_text` without a
    sequence number; the request's stored body adds the request's own, which
    then enters the installed route's id."""
    spec: Dict[str, Any] = {}
    for key in SPEC_FIELDS:
        value = fields.get(key)
        if value is None:
            continue
        if key in ("min_amount", "active_from", "expires_at") and value == 0 \
                and _is_int(value):
            continue
        if key == "locked" and value is False:
            continue
        spec[key] = value
    if sequence_number is not None:
        spec["sequence_number"] = int(sequence_number)
    return json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def parse_route_spec(text: Any, owner: str,
                     sequence_number: Optional[int] = None) -> RouteTerms:
    """Terms from canonical spec text; any other spelling of the same terms is
    refused, so one set of terms has one request id. The sequence number comes
    from the text (a stored body) or from the caller (a request as sent)."""
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
    return _terms_from_fields(fields, owner, sequence)


def validate_route_shape(terms: RouteTerms, ts: int) -> Optional[str]:
    """Stateless admissibility of terms against the block that installs them."""
    ts = int(ts)
    if terms.destination_pubkey == terms.owner_pubkey:
        return "a route may not point at its own account"
    if not 1 <= terms.share_bps <= MAX_SHARE_BPS:
        return (f"share_bps must be in 1..{MAX_SHARE_BPS} "
                f"(the account keeps at least {100 - MAX_SHARE_BPS // 100}%)")
    if terms.min_amount > tau_defs.MAX_TRANSFER_VALUE:
        return f"min_amount must be at most {tau_defs.MAX_TRANSFER_VALUE}"
    if terms.active_from > ts + MAX_START_DELAY_SECONDS:
        return f"active_from is more than {MAX_START_DELAY_SECONDS} seconds ahead"
    if terms.expires_at:
        if terms.expires_at <= ts:
            return "expires_at must be in the future"
        if terms.expires_at > ts + MAX_LIFETIME_SECONDS:
            return f"expires_at is more than {MAX_LIFETIME_SECONDS} seconds ahead"
        if terms.active_from >= terms.expires_at:
            return "the route would end before it starts"
    if terms.locked:
        if not terms.expires_at:
            return "a locked route needs an end (expires_at)"
        if terms.expires_at > ts + MAX_LOCK_SECONDS:
            return f"a locked route must end within {MAX_LOCK_SECONDS} seconds"
    return None


def strengthens(old: RouteTerms, new: RouteTerms, ts: int) -> bool:
    """True when `new` gives the destination of a locked `old` at least what
    `old` promised: same destination, still locked, no smaller share, no higher
    minimum, no later start, no earlier end."""
    return (new.destination_pubkey == old.destination_pubkey
            and new.locked
            and new.share_bps >= old.share_bps
            and new.min_amount <= old.min_amount
            and new.active_from <= max(old.active_from, int(ts))
            and new.expires_at >= old.expires_at)


# --- The book --------------------------------------------------------------------

_Row = Tuple[bytes, str, int, str, int, int, int, int, bool]


class ReceiveRouteBook:
    """One route per account. Copies share the frozen terms."""

    def __init__(self) -> None:
        self.terms: Dict[str, RouteTerms] = {}
        self._expiry: List[Tuple[int, str]] = []    # (expires_at, owner), ends only
        self.resolved_count = 0
        self.resolved_acc = ZERO_ACC
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "ReceiveRouteBook":
        clone = ReceiveRouteBook.__new__(ReceiveRouteBook)
        clone.terms = dict(self.terms)
        clone._expiry = list(self._expiry)
        clone.resolved_count = self.resolved_count
        clone.resolved_acc = self.resolved_acc
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[Tuple], resolved_count: int,
                resolved_acc: bytes) -> "ReceiveRouteBook":
        """Rebuild from stored rows (route_id, owner, sequence, destination,
        share_bps, min_amount, active_from, expires_at, locked); refuses a row
        whose id does not recompute or whose terms no block could install."""
        if not isinstance(resolved_acc, (bytes, bytearray)) or len(resolved_acc) != 32:
            raise ValueError("resolved_acc must be 32 bytes")
        if not _is_int(resolved_count) or resolved_count < 0:
            raise ValueError("resolved_count must be a non-negative integer")
        book = cls()
        for row in rows:
            (stored_id, owner, sequence, destination, share, min_amount, active_from,
             expires_at, locked) = row
            terms = RouteTerms(owner, sequence, destination, share, min_amount,
                               active_from, expires_at, bool(locked))
            rid = terms.route_id
            if rid != bytes(stored_id):
                raise ValueError(f"stored receive route id does not match its terms: {rid.hex()}")
            if owner in book.terms:
                raise ValueError(f"two stored receive routes for one account: {owner[:16]}")
            if owner == destination or not 1 <= share <= MAX_SHARE_BPS \
                    or (locked and not expires_at):
                raise ValueError(f"stored receive route has impossible terms: {rid.hex()}")
            book._insert(terms)
        book.resolved_count = resolved_count
        book.resolved_acc = bytes(resolved_acc)
        return book

    # -- internals ---------------------------------------------------------------

    def _insert(self, terms: RouteTerms) -> None:
        self.terms[terms.owner_pubkey] = terms
        if terms.expires_at:
            bisect.insort(self._expiry, (terms.expires_at, terms.owner_pubkey))
        self._root = None

    def _remove(self, owner: str, outcome: int) -> RouteTerms:
        terms = self.terms.pop(owner)
        if terms.expires_at:
            del self._expiry[bisect.bisect_left(self._expiry, (terms.expires_at, owner))]
        self.resolved_acc = compute_receive_route_resolved_acc(
            self.resolved_acc, terms.route_id, outcome)
        self.resolved_count += 1
        self._root = None
        return terms

    # -- queries -----------------------------------------------------------------

    def _row(self, owner: str) -> _Row:
        t = self.terms[owner]
        return (t.route_id, t.owner_pubkey, t.sequence_number, t.destination_pubkey,
                t.share_bps, t.min_amount, t.active_from, t.expires_at, t.locked)

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_receive_route_book_root(
                [self._row(o) for o in self.terms], self.resolved_count, self.resolved_acc)
        return self._root

    def is_empty(self) -> bool:
        """True while the book has never held a route (it then stays out of the hash)."""
        return not self.terms and self.resolved_count == 0

    def get(self, owner: str) -> Optional[RouteTerms]:
        return self.terms.get(owner)

    def count(self) -> int:
        return len(self.terms)

    def routes_to(self, destination: str) -> List[RouteTerms]:
        """Every route paying into `destination`, by owner."""
        return [self.terms[o] for o in sorted(self.terms)
                if self.terms[o].destination_pubkey == destination]

    def has_expiring(self, ts: int) -> bool:
        return bool(self._expiry and self._expiry[0][0] <= int(ts))

    def store_rows(self) -> List[_Row]:
        return [self._row(o) for o in sorted(self.terms)]

    def resolved_state(self) -> Tuple[int, bytes]:
        return self.resolved_count, self.resolved_acc

    def split(self, recipient: str, gross: int, ts: int) -> Tuple[Optional[RouteTerms], int]:
        """(route, routed part) for a credit of `gross` to `recipient` at `ts`;
        (None, 0) when nothing is routed."""
        terms = self.terms.get(recipient)
        if terms is None or not terms.is_active(ts):
            return None, 0
        routed = terms.share_of(gross)
        return (terms, routed) if routed else (None, 0)

    # -- admission ---------------------------------------------------------------

    def can_admit_set(self, terms: RouteTerms, ts: int) -> Tuple[bool, str]:
        reason = validate_route_shape(terms, ts)
        if reason:
            return False, reason
        back = self.terms.get(terms.destination_pubkey)
        if back is not None and back.destination_pubkey == terms.owner_pubkey:
            return False, "the destination routes back to this account (A -> B -> A)"
        current = self.terms.get(terms.owner_pubkey)
        if current is not None:
            if current.route_id == terms.route_id:
                return False, "this route is already installed"
            if current.binding(ts) and not strengthens(current, terms, ts):
                return False, (
                    f"the current route is locked until {current.expires_at}; a "
                    "replacement must keep its destination and give it at least as "
                    "much for at least as long, or the destination releases it")
        elif len(self.terms) >= MAX_RECEIVE_ROUTES_TOTAL:
            return False, "the receive route book is full"
        return True, ""

    def can_admit_remove(self, owner: str, ts: int) -> Tuple[bool, str]:
        current = self.terms.get(owner)
        if current is None:
            return False, "the account has no receive route"
        if current.binding(ts):
            return False, (f"the route is locked until {current.expires_at}; "
                           "only its destination can release it earlier")
        return True, ""

    def can_admit_release(self, owner: str, route_id: bytes, signer: str) -> Tuple[bool, str]:
        current = self.terms.get(owner)
        if current is None:
            return False, "the account has no receive route"
        if current.route_id != bytes(route_id):
            return False, "the account's route is not the one named"
        if signer != current.destination_pubkey:
            return False, "only the route's destination may release it"
        return True, ""

    # -- mutation ----------------------------------------------------------------

    def install(self, terms: RouteTerms) -> Optional[bytes]:
        """Install `terms`; the id of a route it replaced, else None."""
        replaced = None
        if terms.owner_pubkey in self.terms:
            replaced = self._remove(terms.owner_pubkey, OUTCOME_REPLACED).route_id
        self._insert(terms)
        return replaced

    def remove(self, owner: str) -> RouteTerms:
        if owner not in self.terms:
            raise KeyError(owner)
        return self._remove(owner, OUTCOME_REMOVED)

    def release(self, owner: str) -> RouteTerms:
        if owner not in self.terms:
            raise KeyError(owner)
        return self._remove(owner, OUTCOME_RELEASED)

    def expire(self, ts: int) -> List[RouteTerms]:
        """Remove every route whose end this block reached, earliest first."""
        gone: List[RouteTerms] = []
        while self._expiry and self._expiry[0][0] <= int(ts):
            gone.append(self._remove(self._expiry[0][1], OUTCOME_EXPIRED))
        return gone


# --- What wallets and history read ------------------------------------------------


def credit_event(terms: RouteTerms, gross: int, routed: int, credit_class: str,
                 **source: Any) -> Dict[str, Any]:
    """One routed credit as receipts and history carry it."""
    return {
        "outcome": "routed",
        "owner_pubkey": terms.owner_pubkey,
        "destination_pubkey": terms.destination_pubkey,
        "route_id": terms.route_id.hex(),
        "credit_class": credit_class,
        "gross": int(gross),
        "routed": int(routed),
        "net": int(gross) - int(routed),
        **{k: v for k, v in source.items() if v is not None},
    }


def lifecycle_event(terms: RouteTerms, outcome: str, **extra: Any) -> Dict[str, Any]:
    return {
        "outcome": outcome,
        "owner_pubkey": terms.owner_pubkey,
        "destination_pubkey": terms.destination_pubkey,
        "route_id": terms.route_id.hex(),
        **{k: v for k, v in extra.items() if v is not None},
    }


def describe(terms: RouteTerms, ts: int = 0) -> Dict[str, Any]:
    """One route as a wallet reads it."""
    return {
        "route_id": terms.route_id.hex(),
        "owner_pubkey": terms.owner_pubkey,
        "sequence_number": terms.sequence_number,
        "destination_pubkey": terms.destination_pubkey,
        "share_bps": terms.share_bps,
        "share_percent": terms.share_bps / 100,
        "min_amount": terms.min_amount,
        "active_from": terms.active_from or None,
        "expires_at": terms.expires_at or None,
        "locked": terms.locked,
        "status": terms.status(ts) if ts else None,
        "removable_by_owner": not terms.binding(ts) if ts else not terms.locked,
        "example": {"gross": 101, "routed": terms.share_of(101),
                    "net": 101 - terms.share_of(101)},
    }


SEMANTICS: Dict[str, Any] = {
    "supported": True,
    "version": 1,
    "routes_per_account": 1,
    "destinations_per_route": 1,
    "share_bps_max": MAX_SHARE_BPS,
    "rounding": "routed = floor(gross * share_bps / 10000); net = gross - routed; "
                "computed per credit from its gross amount",
    "min_amount": "a credit smaller than min_amount is not routed",
    "routed_credit_classes": list(ROUTED_CLASSES),
    "unrouted_credit_classes": list(UNROUTED_CLASSES),
    "hops": "single: a routed share is never routed again",
    "fees": "routing has no fee of its own: the payer pays the fee of its own "
            "transaction, unchanged, and neither the account nor the destination "
            "pays anything for the split",
    "spending": "the routed part never reaches the account's balance, so it is not "
                "a send of the account: no o5 clause, cooldown or spend count sees it",
    "admin": "set and remove are rule changes (guard kinds 8 and 9); a locked route "
             "binds the owner until it ends and only its destination can release it",
    "timing": "active from active_from (block timestamp) until expires_at; a credit "
              "that lands later (retractable release, standing payment) uses the "
              "route in force in the block where it lands",
}


def _amount(value: Any) -> Optional[int]:
    try:
        amount = int(value)
    except (TypeError, ValueError):
        return None
    return amount if amount > 0 else None


def preview_credits(tx: Dict[str, Any], book: "ReceiveRouteBook",
                    ts: int) -> List[Dict[str, Any]]:
    """How the routes in force now would split the credits a transaction makes.

    Advisory, like every admission answer: the block it lands in decides. Credits
    that land later say so, because the route in force then decides them.
    """
    from consensus.approvals import TX_TYPE_APPROVAL_REQUEST
    from consensus.envelope import TX_TYPE_ENVELOPE_SPEND
    from consensus.retractable import TX_TYPE_RETRACTABLE_TRANSFER
    from consensus.standing import TX_TYPE_STANDING_PAYMENT_CREATE

    if not isinstance(tx, dict) or book is None or not book.terms:
        return []
    tx_type = tx.get("tx_type", "user_tx")
    credits: List[Tuple[str, Any, str, bool]] = []
    if tx_type == "user_tx":
        ops = tx.get("operations")
        transfers = ops.get("1") if isinstance(ops, dict) else None
        for item in transfers if isinstance(transfers, list) else []:
            if isinstance(item, (list, tuple)) and len(item) == 3:
                credits.append((item[1], item[2], CREDIT_TRANSFER, False))
    elif tx_type == TX_TYPE_APPROVAL_REQUEST:
        credits.append((tx.get("recipient_pubkey"), tx.get("amount"),
                        CREDIT_APPROVED_TRANSFER, True))
    elif tx_type == TX_TYPE_RETRACTABLE_TRANSFER:
        credits.append((tx.get("recipient_pubkey"), tx.get("amount"),
                        CREDIT_RETRACTABLE_RELEASE, True))
    elif tx_type == TX_TYPE_STANDING_PAYMENT_CREATE:
        credits.append((tx.get("recipient_pubkey"), tx.get("amount"),
                        CREDIT_STANDING_PAYMENT, True))
    elif tx_type == TX_TYPE_ENVELOPE_SPEND:
        credits.append((tx.get("to_pubkey"), tx.get("amount"), CREDIT_ENVELOPE_SPEND, False))
    out: List[Dict[str, Any]] = []
    for recipient, raw, credit_class, later in credits:
        amount = _amount(raw)
        if not isinstance(recipient, str) or amount is None:
            continue
        terms, routed = book.split(recipient, amount, ts)
        if terms is None and book.get(recipient) is None:
            continue
        current = book.get(recipient)
        item = {
            "recipient_pubkey": recipient,
            "credit_class": credit_class,
            "gross": amount,
            "routed": routed,
            "net": amount - routed,
            "destination_pubkey": current.destination_pubkey,
            "route_id": current.route_id.hex(),
            "route_status": current.status(ts),
        }
        if later:
            item["lands_later"] = True
        out.append(item)
    return out
