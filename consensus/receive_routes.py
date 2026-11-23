"""Receive routes: a recipient-side atomic split of an ordinary credit (#35).

An opted-in account installs one route: a fixed share (basis points) of every
ordinary credit it receives is routed to one destination, atomically with the
credit itself — no wallet needs to be online at receipt time. This module is
the book: the pure consensus state, its validation, and the split arithmetic.
The engine hook that stages the split inside `_execute_fee_era_transfer`
consults `apply_route` and nothing else, so admission and apply can never
disagree about a route.

CONSENSUS-FROZEN SURFACE
------------------------
The bounds below are module constants, not config: a per-node value would
make two honest nodes disagree about admissibility, which forks.

- Rounding is floor on the routed share of the gross credit, computed once
  from the gross: 101 at 2000 bps routes 20 and nets 81.
- Only two credit classes trigger a route: ordinary user transfers and
  claimed payments (#36). Every other credit — above all a credit produced
  BY a route — is a different class and never triggers one. The loop stopper
  is this class check, not a depth counter, so a routed share can never
  trigger another route even across accounts (A routes to B, B routes to A).
- A route is one ledger split of the original transfer: one fee, charged
  exactly as the unrouted transfer would be. The split itself creates no
  second fee event (asserted by the named case-1 test at this level; the
  engine seam asserts it again where fees settle).
- TWO FORMS (FIX 2, the stage-1 clause form): a route is either the
  DECLARED form above — a fixed share in basis points — or the TAU
  CLAUSE form: the owner's own Tau clause, stepped by the node through
  the existing policy-evaluation path (sender_policy.clause_outputs)
  over a node-built input map (route_clause_inputs), names the routed
  legs under the stage's shared output encoding (o30 leg count, o31..
  candidate/amount pairs). The clause decides the share; the book
  re-checks every leg against the candidate set (the signed
  destination) and the product cap, and the class check above stays
  the book's and stays FIRST: a route output never triggers a route
  in either form, because the clause is only ever stepped for a
  triggering class. A clause that cannot be stepped, or names legs
  the book refuses, routes nothing — the credit lands whole, so a
  broken route clause can never block someone else's transfer. The
  form is a signed field, inside the route id (a domain-separated id
  for the clause form), so the form a credit runs under is the form
  the owner signed.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.serialization import (
    compute_receive_route_book_root,
    compute_receive_route_id,
    compute_receive_route_tau_id,
)

TX_TYPE_INSTALL_RECEIVE_ROUTE = "install_receive_route"
TX_TYPE_REMOVE_RECEIVE_ROUTE = "remove_receive_route"

RECEIVE_ROUTE_TX_TYPES = frozenset(
    {TX_TYPE_INSTALL_RECEIVE_ROUTE, TX_TYPE_REMOVE_RECEIVE_ROUTE}
)

# Credit classes. Only ROUTE_TRIGGER_CREDIT_CLASSES trigger a route.
CREDIT_ORDINARY_TRANSFER = "ordinary_transfer"
CREDIT_CLAIMED_PAYMENT = "claimed_payment"
CREDIT_ROUTE_OUTPUT = "route_output"
CREDIT_STANDING_EXECUTION = "standing_execution"
CREDIT_PAYOUT_LEG = "payout_leg"
CREDIT_GRANT_DRAW = "grant_draw"
CREDIT_REFUND = "refund"
CREDIT_SWEEP_RELEASE = "sweep_release"
CREDIT_FAUCET_OR_GENESIS = "faucet_or_genesis"
CREDIT_FEE_OR_REWARD = "fee_or_reward"

ROUTE_TRIGGER_CREDIT_CLASSES = frozenset(
    {CREDIT_ORDINARY_TRANSFER, CREDIT_CLAIMED_PAYMENT}
)

# The issue's range is 0..10000 bps with "a conservative product limit below
# 100%". The product cap for v1 is 9000 bps (90%): a route can never take a
# whole credit, and the receiving account always keeps a share.
MAX_ROUTE_BPS = 10_000
PRODUCT_CAP_BPS = 9_000

# The two forms a route can take. The form is a signed field of the
# route: it is inside the install signature and the route id, so the
# form a credit runs under is the form the owner signed.
FORM_DECLARED = 1
FORM_TAU_CLAUSE = 2
ROUTE_FORMS = frozenset({FORM_DECLARED, FORM_TAU_CLAUSE})

# The Tau form's clause text bound, in UTF-8 bytes — the stage's shared
# bound (consensus/payout_rules MAX_PAYOUT_CLAUSE_BYTES).
MAX_ROUTE_CLAUSE_BYTES = 8192

# The Tau form's output encoding — the stage's shared encoding, the
# same one the payout-rule form pins: o30 carries the leg count, then
# each leg is a (destination candidate index, amount) pair on
# consecutive streams.
ROUTE_OUTPUT_COUNT_STREAM = 30
ROUTE_OUTPUT_FIRST_STREAM = 31

# A clause names at most this many legs for one credit (the stage's
# shared MAX_LEGS bound).
MAX_CLAUSE_LEGS = 32

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class ReceiveRouteShapeError(ValueError):
    """A receive-route transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class ReceiveRouteEntry:
    """The signed terms of one route version. Nothing here mutates.

    `form` and `clause_text` default to the declared form, so every
    entry constructed before the Tau form existed — and every
    declared-form entry constructed now — is byte-identical to what
    it was. A Tau-form route carries no share: its shape requires
    bps 0, and its clause names the routed amount per credit.
    """

    owner_pubkey: str
    destination_pubkey: str
    bps: int
    min_amount: int
    activation_ts: int
    expiry_ts: int
    locked_until_ts: int
    version: int
    form: int = FORM_DECLARED
    clause_text: str = ""

    @property
    def route_id(self) -> bytes:
        if self.form == FORM_TAU_CLAUSE:
            return compute_receive_route_tau_id(
                self.owner_pubkey,
                self.destination_pubkey,
                self.clause_text,
                self.min_amount,
                self.activation_ts,
                self.expiry_ts,
                self.locked_until_ts,
                self.version,
            )
        return compute_receive_route_id(
            self.owner_pubkey,
            self.destination_pubkey,
            self.bps,
            self.min_amount,
            self.activation_ts,
            self.expiry_ts,
            self.locked_until_ts,
            self.version,
        )

    @property
    def candidates(self) -> Tuple[str, ...]:
        """The destination candidate set a clause's legs index into.

        A route has exactly one signed destination, so the set has one
        member: candidate 0 is the destination, and any other index
        names something the owner never signed.
        """
        return (self.destination_pubkey,)


@dataclass(frozen=True)
class RouteApplication:
    """The outcome of presenting one credit to the book.

    `applied` False means the credit lands whole: `routed` is 0 and `net` is
    the gross. `reason` names why, for receipts and tests. When applied,
    `destination_pubkey` and `route_id` identify the route that split the
    credit, so the engine can stage the routed share and write the routing
    receipt without a second lookup.
    """

    applied: bool
    routed: int
    net: int
    reason: str
    destination_pubkey: str = ""
    route_id: bytes = b""


def split_credit(gross: int, bps: int) -> Tuple[int, int]:
    """(routed, net) for a gross credit at `bps`, floor on the routed share.

    Computed once from the gross; routed + net == gross always, so a split
    can neither burn nor duplicate value.
    """
    if gross < 0:
        raise ValueError("gross must be non-negative")
    if not 0 <= bps <= MAX_ROUTE_BPS:
        raise ValueError("bps must be in 0..10000")
    routed = (gross * bps) // MAX_ROUTE_BPS
    return routed, gross - routed


# --- The Tau form: input map and output decoding ------------------------------

_OUTPUT_VALUE_RE = re.compile(
    r"^\{?\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}?(?::bv\[\d+\])?$"
)


def _parse_output_value(value: Any) -> Optional[int]:
    """One clause output as an integer, or None when it is not one.

    The worker reports outputs as Tau value strings; this reads them
    with the same grammar tau_policy.parse_o5 reads o5 with (hex /
    binary / decimal, optional braces and :bv[N] annotation) — the
    payout form's identical reader, kept per book as this codebase
    keeps its small helpers.
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


def route_clause_inputs(
    entry: ReceiveRouteEntry,
    sender_pubkey: str,
    gross: int,
    ts: int,
    owner_balance: int,
) -> Dict[int, Any]:
    """The input map a Tau-form split steps the owner's clause over.

    ONE definition, called by the engine at the transfer seam with its
    site values (routes have no execution transaction of their own, so
    there is no second site to drift from). The value formats mirror
    the transfer input map (consensus/engine._transfer_input_map)
    exactly: amounts and the timestamp as decimal strings, accounts as
    `{ #x.. }:bv[384]` literals. The map is the payout form's map
    (i1..i5/i26) with the route meanings:

    - i1: the gross credit amount being split
    - i2: the receiving owner's balance before this credit
    - i3: the receiving owner's pubkey
    - i4: the credit sender's pubkey
    - i5: the block timestamp
    - i26 (tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX): the route book
      keeps no per-period paid total, so the stream is fed 0 — a
      defined value a clause written against the shared map can read,
      never an absent stream

    Nothing in the map comes from the credit beyond its own amount and
    sender: the map is node-built, so no sender can steer the clause
    by writing a stream.
    """
    return {
        1: str(int(gross)),
        2: str(int(owner_balance)),
        3: "{ #x" + str(entry.owner_pubkey) + " }:bv[384]",
        4: "{ #x" + str(sender_pubkey) + " }:bv[384]",
        5: str(int(ts)),
        tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX: "0",
    }


def decode_clause_legs(
    entry: ReceiveRouteEntry, outputs: Dict[str, Any]
) -> Tuple[Optional[Tuple[Tuple[str, int], ...]], str]:
    """The legs a stepped clause named, or (None, why not).

    The encoding (pinned in route_capabilities): o30 is the leg count;
    leg k reads its destination candidate index — 0-based into the
    entry's candidate set — from o(31+2k) and its amount from
    o(32+2k). Zero-amount legs are dropped, as the payout form drops
    them. A count above the bound, a missing or unreadable value, or
    an index outside the candidate set means the clause named
    something the node cannot settle: no legs, and the credit lands
    whole.
    """
    count = _parse_output_value(outputs.get(f"o{ROUTE_OUTPUT_COUNT_STREAM}"))
    if count is None:
        return None, "the route's clause did not report a leg count"
    if count < 0 or count > MAX_CLAUSE_LEGS:
        return None, f"the route's clause reported {count} legs"
    legs: List[Tuple[str, int]] = []
    for k in range(count):
        index = _parse_output_value(
            outputs.get(f"o{ROUTE_OUTPUT_FIRST_STREAM + 2 * k}")
        )
        amount = _parse_output_value(
            outputs.get(f"o{ROUTE_OUTPUT_FIRST_STREAM + 2 * k + 1}")
        )
        if index is None or amount is None:
            return None, "the route's clause reported an unreadable leg"
        if not 0 <= index < len(entry.candidates):
            return None, (
                "the route's clause named destination candidate "
                f"{index}, outside the declared set"
            )
        if amount > 0:
            legs.append((entry.candidates[index], amount))
    return tuple(legs), ""


# --- Parsing ------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise ReceiveRouteShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64_field(tx: Dict[str, Any], name: str, default: int = 0) -> int:
    value = tx.get(name, default)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise ReceiveRouteShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def _form_field(tx: Dict[str, Any]) -> int:
    value = tx.get("route_form", FORM_DECLARED)
    if not _is_int(value) or value not in ROUTE_FORMS:
        raise ReceiveRouteShapeError(
            "route_form must be 1 (declared) or 2 (Tau clause)"
        )
    return int(value)


def _clause_field(tx: Dict[str, Any]) -> str:
    value = tx.get("route_clause", "")
    if not isinstance(value, str):
        raise ReceiveRouteShapeError("route_clause must be a string")
    return value


def parse_install_receive_route(tx: Dict[str, Any]) -> ReceiveRouteEntry:
    """Read an installation from ROOT fields only; a nested `payload` is unsigned data.

    The form selects which fields carry the share decision, and the
    two forms' fields are mutually exclusive (the payout form's parse
    discipline): the Tau form reads `route_clause` and refuses a bps;
    the declared form reads `route_bps` and refuses a clause.
    """
    if not isinstance(tx, dict):
        raise ReceiveRouteShapeError("transaction must be an object")
    form = _form_field(tx)
    clause_text = _clause_field(tx)
    if form == FORM_TAU_CLAUSE:
        if not clause_text:
            raise ReceiveRouteShapeError(
                "a Tau-form receive route must carry route_clause"
            )
    elif clause_text:
        raise ReceiveRouteShapeError(
            "route_clause is only for the Tau form (route_form 2)"
        )
    return ReceiveRouteEntry(
        owner_pubkey=_pubkey_field(tx, "sender_pubkey"),
        destination_pubkey=_pubkey_field(tx, "route_destination_pubkey"),
        bps=_u64_field(tx, "route_bps"),
        min_amount=_u64_field(tx, "route_min_amount"),
        activation_ts=_u64_field(tx, "route_activation_ts"),
        expiry_ts=_u64_field(tx, "route_expiry_ts"),
        locked_until_ts=_u64_field(tx, "route_locked_until_ts"),
        version=_u64_field(tx, "route_version", default=1),
        form=form,
        clause_text=clause_text,
    )


def validate_route_shape(route: ReceiveRouteEntry, now_ts: int) -> Optional[str]:
    """Stateless admissibility of a route. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything needing the book lives in `can_install`.
    """
    if route.destination_pubkey == route.owner_pubkey:
        return "route destination must differ from the receiving account"
    if not 0 <= route.bps <= MAX_ROUTE_BPS:
        return "route_bps must be in 0..10000"
    if route.bps > PRODUCT_CAP_BPS:
        return f"route_bps exceeds the v1 product cap of {PRODUCT_CAP_BPS}"
    if route.min_amount > tau_defs.MAX_TRANSFER_VALUE:
        return "route_min_amount exceeds the maximum transfer value"
    if route.version < 1:
        return "route_version must start at 1"
    if route.expiry_ts and route.expiry_ts <= route.activation_ts:
        return "route_expiry_ts must be after route_activation_ts"
    if route.expiry_ts and route.expiry_ts <= now_ts:
        return "route is already expired"
    if route.locked_until_ts:
        # gmikeyg on #35: expiry is mandatory for locked routes, so no route
        # is permanent (or permanently locked) by accident.
        if not route.expiry_ts:
            return "a locked route must carry an expiry"
        if route.locked_until_ts > route.expiry_ts:
            return "route_locked_until_ts must not exceed route_expiry_ts"
    if route.form not in ROUTE_FORMS:
        return "unknown receive route form"
    if route.form == FORM_TAU_CLAUSE:
        if route.bps != 0:
            return "a Tau-form route carries no bps; its clause names the share"
        if not route.clause_text:
            return "a Tau-form receive route must carry a clause"
        if len(route.clause_text.encode("utf-8")) > MAX_ROUTE_CLAUSE_BYTES:
            return f"a route clause is at most {MAX_ROUTE_CLAUSE_BYTES} bytes"
    elif route.clause_text:
        return "a declared-form receive route carries no clause"
    return None


# --- The book -----------------------------------------------------------------

_Row = Tuple[bytes, str, str, int, int, int, int, int, int, int, str]


class ReceiveRouteBook:
    """One active route per owner; replacement is a new signed version.

    Composed as a field of ConsensusLifecycleManager in the wiring slice, so
    the meta hash picks the book root up without a call site to forget (the
    RetractableBook pattern). Entries are frozen, so copies share them and
    only the container is duplicated.
    """

    def __init__(self) -> None:
        self._routes: Dict[str, ReceiveRouteEntry] = {}
        self._root: Optional[bytes] = None

    # -- copying / restoring -------------------------------------------------

    def __deepcopy__(self, memo: Dict[int, Any]) -> "ReceiveRouteBook":
        clone = ReceiveRouteBook.__new__(ReceiveRouteBook)
        clone._routes = dict(self._routes)
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[_Row]) -> "ReceiveRouteBook":
        """Rebuild from stored rows; refuses any row whose id does not recompute."""
        book = cls()
        for stored_id, owner, dest, bps, min_amt, act, exp, lock, ver, form, clause_text in rows:
            entry = ReceiveRouteEntry(
                owner, dest, bps, min_amt, act, exp, lock, ver, form, clause_text
            )
            if entry.route_id != bytes(stored_id):
                raise ValueError(
                    f"stored route id does not match its fields: {entry.route_id.hex()}"
                )
            if owner in book._routes:
                raise ValueError(f"duplicate stored route for owner: {owner}")
            book._routes[owner] = entry
        return book

    def rows(self) -> List[_Row]:
        return [
            (
                e.route_id,
                e.owner_pubkey,
                e.destination_pubkey,
                e.bps,
                e.min_amount,
                e.activation_ts,
                e.expiry_ts,
                e.locked_until_ts,
                e.version,
                e.form,
                e.clause_text,
            )
            for e in self._routes.values()
        ]

    # -- queries ---------------------------------------------------------------

    def get(self, owner_pubkey: str) -> Optional[ReceiveRouteEntry]:
        return self._routes.get(owner_pubkey)

    def route_count(self) -> int:
        return len(self._routes)

    def is_empty(self) -> bool:
        return not self._routes

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_receive_route_book_root(self.rows())
        return self._root

    def active_route(self, owner_pubkey: str, ts: int) -> Optional[ReceiveRouteEntry]:
        """The route in force for a credit landing at `ts`, or None."""
        entry = self._routes.get(owner_pubkey)
        if entry is None:
            return None
        if ts < entry.activation_ts:
            return None
        if entry.expiry_ts and ts >= entry.expiry_ts:
            return None
        return entry

    # -- mutation ----------------------------------------------------------------

    def can_install(
        self, route: ReceiveRouteEntry, now_ts: int
    ) -> Tuple[bool, str]:
        problem = validate_route_shape(route, now_ts)
        if problem is not None:
            return False, problem
        existing = self._routes.get(route.owner_pubkey)
        if existing is not None:
            if route.version != existing.version + 1:
                return (
                    False,
                    "replacement must be the next version "
                    f"({existing.version + 1}), got {route.version}",
                )
            locked = self._lock_blocks(existing, now_ts, destination_authorized=False)
            if locked is not None:
                return False, locked
        elif route.version != 1:
            return False, "a first route must be version 1"
        return True, ""

    def install(self, route: ReceiveRouteEntry, now_ts: int) -> bytes:
        ok, reason = self.can_install(route, now_ts)
        if not ok:
            raise ValueError(reason)
        self._routes[route.owner_pubkey] = route
        self._root = None
        return route.route_id

    @staticmethod
    def _lock_blocks(
        entry: ReceiveRouteEntry, now_ts: int, destination_authorized: bool
    ) -> Optional[str]:
        """Why the lock on `entry` blocks a change/removal now, or None.

        gmikeyg on #35: while locked, the recipient alone cannot change or
        remove the route — removal needs the destination's authorization, or
        the lock runs out (locked_until_ts passes; expiry bounds it always).
        """
        if entry.locked_until_ts and now_ts < entry.locked_until_ts:
            if not destination_authorized:
                return "route is locked; change requires the destination's authorization"
        return None

    def can_remove(
        self, owner_pubkey: str, now_ts: int, destination_authorized: bool = False
    ) -> Tuple[bool, str]:
        entry = self._routes.get(owner_pubkey)
        if entry is None:
            return False, "no route installed for this account"
        locked = self._lock_blocks(entry, now_ts, destination_authorized)
        if locked is not None:
            return False, locked
        return True, ""

    def remove(
        self, owner_pubkey: str, now_ts: int, destination_authorized: bool = False
    ) -> ReceiveRouteEntry:
        ok, reason = self.can_remove(owner_pubkey, now_ts, destination_authorized)
        if not ok:
            raise ValueError(reason)
        entry = self._routes.pop(owner_pubkey)
        self._root = None
        return entry

    # -- the split ----------------------------------------------------------------

    def apply_route(
        self,
        owner_pubkey: str,
        gross: int,
        credit_class: str,
        ts: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]] = None,
    ) -> RouteApplication:
        """Present one credit to the book and learn its split.

        The class check comes first and is absolute: a credit that is not an
        ordinary transfer or a claimed payment never splits, whatever route
        the account holds — that is what makes routing single-hop.

        `clause_legs` is the Tau form's leg source: the legs the caller
        (the engine at the transfer seam) decoded from stepping the
        owner's clause. Declared entries never consult it; Tau entries
        REQUIRE it — None routes nothing, because stepping is the
        caller's job, exactly as in the payout and standing books.
        """
        if gross < 0:
            raise ValueError("gross must be non-negative")
        if credit_class not in ROUTE_TRIGGER_CREDIT_CLASSES:
            return RouteApplication(False, 0, gross, f"credit class {credit_class} never routes")
        entry = self.active_route(owner_pubkey, ts)
        if entry is None:
            return RouteApplication(False, 0, gross, "no active route")
        if gross < entry.min_amount:
            return RouteApplication(False, 0, gross, "below the route minimum")
        if entry.form == FORM_TAU_CLAUSE:
            return self._apply_clause_route(entry, gross, clause_legs)
        routed, net = split_credit(gross, entry.bps)
        if routed == 0:
            return RouteApplication(False, 0, gross, "share rounds to zero")
        return RouteApplication(
            True, routed, net, "routed",
            destination_pubkey=entry.destination_pubkey,
            route_id=entry.route_id,
        )

    def _apply_clause_route(
        self,
        entry: ReceiveRouteEntry,
        gross: int,
        clause_legs: Optional[Tuple[Tuple[str, int], ...]],
    ) -> RouteApplication:
        """The Tau form's split of one credit.

        What the clause named is re-checked here against everything
        the owner signed: every leg must name the declared destination
        (the candidate set), and the routed total may not exceed the
        product cap's share of the gross — the same ceiling the
        declared form's bps is held to, so a clause route can never
        take a whole credit either. Any refusal routes nothing: the
        credit lands whole.
        """
        if clause_legs is None:
            return RouteApplication(
                False, 0, gross, "the route's clause was not evaluated")
        for recipient, leg_amount in clause_legs:
            if recipient not in entry.candidates:
                return RouteApplication(
                    False, 0, gross,
                    "the clause named a leg outside the declared set")
            if leg_amount <= 0:
                return RouteApplication(
                    False, 0, gross, "the clause named a non-positive leg")
        routed = sum(leg_amount for _, leg_amount in clause_legs)
        if routed == 0:
            return RouteApplication(
                False, 0, gross, "the route's clause named no routed share")
        cap = (gross * PRODUCT_CAP_BPS) // MAX_ROUTE_BPS
        if routed > cap:
            return RouteApplication(
                False, 0, gross,
                "the clause's routed share exceeds the product cap")
        return RouteApplication(
            True, routed, gross - routed, "routed",
            destination_pubkey=entry.destination_pubkey,
            route_id=entry.route_id,
        )


# --- Removal authorization ----------------------------------------------------
#
# A locked route binds the recipient for its term (gmikeyg on #35): the owner
# alone cannot remove or replace it early. The early-release path is the
# destination's BLS signature over a domain-separated message naming the
# owner and the exact route id, so an authorization lifted from one route
# releases no other. Verified the same way transaction signatures are
# (consensus.bls.verify over the sha256 digest), and shared by admission and
# apply so the two can never disagree about whether a removal is authorized.

REMOVE_AUTHORIZATION_DOMAIN = b"tau.receive_route.remove_authorization.v1"


def parse_remove_receive_route(tx: Dict[str, Any]) -> str:
    """Read a removal's owner from ROOT fields only; returns the owner pubkey."""
    if not isinstance(tx, dict):
        raise ReceiveRouteShapeError("transaction must be an object")
    return _pubkey_field(tx, "sender_pubkey")


def remove_authorization_message(owner_pubkey: str, route_id: bytes) -> bytes:
    return (
        REMOVE_AUTHORIZATION_DOMAIN
        + bytes.fromhex(owner_pubkey)
        + bytes(route_id)
    )


def destination_authorized(tx: Dict[str, Any], entry: Optional[ReceiveRouteEntry]) -> bool:
    """True when `tx` carries the destination's signature releasing `entry`.

    Never raises: a malformed or absent signature is simply not an
    authorization, because this runs inside block apply.
    """
    if entry is None:
        return False
    signature = tx.get("route_destination_signature") if isinstance(tx, dict) else None
    if not isinstance(signature, str):
        return False
    try:
        import hashlib

        from consensus import bls

        digest = hashlib.sha256(
            remove_authorization_message(entry.owner_pubkey, entry.route_id)
        ).digest()
        return bool(
            bls.verify(
                bytes.fromhex(entry.destination_pubkey),
                digest,
                bytes.fromhex(signature),
            )
        )
    except Exception:
        return False


# --- Capability reporting -------------------------------------------------------


def route_capabilities() -> Dict[str, Any]:
    """The route semantics a capability endpoint reports, from the constants.

    Built from the module's own values so the report can never drift from
    the code: if a bound changes, this record changes with it. (#35 case 8:
    support, credit classes, rounding and fee semantics, stated before send.)
    """
    return {
        "supported": True,
        "trigger_credit_classes": sorted(ROUTE_TRIGGER_CREDIT_CLASSES),
        "rounding": "floor",
        "fee": "one original transfer fee; the split adds no fee event",
        "max_bps": MAX_ROUTE_BPS,
        "product_cap_bps": PRODUCT_CAP_BPS,
        "locked_route_expiry": "mandatory",
        "single_hop": "route outputs never trigger a route",
        "forms": {
            "declared": FORM_DECLARED,
            "tau_clause": FORM_TAU_CLAUSE,
        },
        "clause_form": {
            "input_streams": {
                "i1": "the gross credit amount",
                "i2": "the receiving owner's balance before the credit",
                "i3": "the receiving owner's pubkey",
                "i4": "the credit sender's pubkey",
                "i5": "the block timestamp",
                "i26": "0 (the route book keeps no per-period paid total)",
            },
            "output_encoding": (
                f"o{ROUTE_OUTPUT_COUNT_STREAM} leg count; leg k reads "
                f"o{ROUTE_OUTPUT_FIRST_STREAM}+2k (candidate index) and "
                f"o{ROUTE_OUTPUT_FIRST_STREAM + 1}+2k (amount)"
            ),
            "candidate_set": "the signed destination (candidate 0)",
            "cap": "the routed total never exceeds the product cap's "
                   "share of the gross",
            "max_clause_bytes": MAX_ROUTE_CLAUSE_BYTES,
            "max_legs": MAX_CLAUSE_LEGS,
        },
    }
