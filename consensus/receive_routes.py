"""Recipient-controlled receive routing (issue #35).

An account installs ONE route: a share of every eligible credit it receives is
split off, in the same atomic write as the credit, to a fixed destination. The
recipient does not need to be online and a sender cannot bypass it: the split is
part of how the node applies the credit, not a transaction the recipient sends.

    gross  = the amount the sender signed
    routed = floor(gross * bps / 10_000)
    net    = gross - routed

CONSENSUS-FROZEN SURFACE
------------------------
Everything below that decides a balance (the rounding rule, the credit classes,
the caps, when a route is active) is a module constant, not config: a per-node
value would give two honest nodes different balances for the same block.

The book holds installed routes only. Its root joins the consensus meta hash
only once a route exists, so a chain that never installs one keeps its genesis
hash and needs no regenesis.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Dict, Iterable, List, Optional, Tuple

import tau_defs
from consensus.serialization import compute_receive_route_book_root

TX_TYPE_RECEIVE_ROUTE_SET = "receive_route_set"
TX_TYPE_RECEIVE_ROUTE_CLEAR = "receive_route_clear"

RECEIVE_ROUTE_TX_TYPES = frozenset(
    {TX_TYPE_RECEIVE_ROUTE_SET, TX_TYPE_RECEIVE_ROUTE_CLEAR}
)

BPS_DENOMINATOR = 10_000
# Conservative cap below 100%: a route can never take a whole credit, so an
# account with a route still receives something from every credit it routes.
MAX_ROUTE_BPS = 9_000
# No book-wide cap: the book holds at most one route per account, so it is
# already bounded by the account set, and a fixed cap is a squatting target (on
# a faucet network fresh keys pay the install fee from their grant, and a full
# book would refuse every later install until a coordinated upgrade).

# A locked route must end: it cannot be held for longer than this from install.
MAX_LOCK_SECONDS = 94_608_000  # 3 * 365 days
# A locked route neither routes nor binds until this long after it is installed.
# Until then its owner can still clear or replace it, so a stolen key alone
# cannot capture years of future receipts with one transaction: the owner has
# this window to see the route (getaccountstate, getreceiveroute) and remove it.
# The chain cannot tell the owner from a thief holding the owner's key, so every
# locked route waits, and the window is a chain rule rather than a route field
# (whoever writes the route would pick the shortest). Seven days matches the
# longer cancellation windows wallets and rollups give for changes that are
# hard to undo, and covers an owner who checks the account once a week: the
# testnet has no push alerts, only what the wallet shows when it is opened.
LOCK_NOTICE_SECONDS = 604_800  # 7 days
# How far ahead a route may be scheduled to start.
MAX_SCHEDULE_SECONDS = 31_536_000  # 365 days

ROUNDING = "floor"

# Credit classes. Only the first two trigger a route.
CREDIT_CLASS_TRANSFER = "transfer"
CREDIT_CLASS_CLAIMED_PAYMENT = "claimed_payment"
ROUTED_CREDIT_CLASSES = (CREDIT_CLASS_TRANSFER, CREDIT_CLASS_CLAIMED_PAYMENT)
EXCLUDED_CREDIT_CLASSES = (
    "retract_refund",
    "faucet_grant",
    "genesis_allocation",
    "fee_or_reward",
    "route_output",
)

STATUS_ACTIVE = "active"
STATUS_SCHEDULED = "scheduled"
STATUS_EXPIRED = "expired"

# Who cleared a route, for receipts.
CLEARED_BY_OWNER = "owner"
CLEARED_BY_DESTINATION = "destination"
CLEARED_BY_EXPIRY = "expiry"

# Stable refusal codes, carried by RouteCheck so admission never has to read
# them back out of the human-readable reason.
CODE_INVALID = "INVALID_RECEIVE_ROUTE"
CODE_LOCKED = "RECEIVE_ROUTE_LOCKED"
CODE_UNKNOWN = "UNKNOWN_RECEIVE_ROUTE"
CODE_NOT_OWNER = "NOT_ROUTE_OWNER"

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_DECIMAL_RE = re.compile(r"^(0|[1-9][0-9]*)$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class ReceiveRouteShapeError(ValueError):
    """A receive-route transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class ReceiveRoute:
    owner_pubkey: str
    destination_pubkey: str
    bps: int
    min_amount: int = 0
    active_from: int = 0   # 0: active from install
    expires_at: int = 0    # 0: no expiry
    locked: bool = False
    version: int = 0       # sequence number of the installing transaction
    # Timestamp of the block that installed it. Set by the node at install,
    # never by the signer; it starts a locked route's notice period.
    installed_at: int = 0

    def starts_at(self) -> int:
        """When the route begins to route (0: from install). A locked route
        starts no earlier than the end of its notice period."""
        start = self.active_from
        if self.locked:
            start = max(start, self.installed_at + LOCK_NOTICE_SECONDS)
        return start

    def is_active(self, ts: int) -> bool:
        start = self.starts_at()
        if start and ts < start:
            return False
        if self.expires_at and ts >= self.expires_at:
            return False
        return True

    def status(self, ts: int) -> str:
        if self.expires_at and ts >= self.expires_at:
            return STATUS_EXPIRED
        start = self.starts_at()
        if start and ts < start:
            return STATUS_SCHEDULED
        return STATUS_ACTIVE

    def lock_holds(self, ts: int) -> bool:
        """The owner cannot replace or clear it: locked, started, not expired.

        During a locked route's notice period the lock does not hold yet, so the
        owner can still take it back."""
        return bool(self.locked) and self.starts_at() <= ts < self.expires_at

    def as_row(self) -> Tuple[str, str, int, int, int, int, bool, int, int]:
        return (
            self.owner_pubkey, self.destination_pubkey, self.bps, self.min_amount,
            self.active_from, self.expires_at, bool(self.locked), self.version,
            self.installed_at,
        )

    def to_dict(self, ts: Optional[int] = None) -> Dict[str, Any]:
        out = {
            "owner_pubkey": self.owner_pubkey,
            "destination_pubkey": self.destination_pubkey,
            "bps": self.bps,
            "min_amount": self.min_amount,
            "active_from_time": self.active_from or None,
            "expires_at_time": self.expires_at or None,
            "locked": bool(self.locked),
            "version": self.version,
            "installed_at_time": self.installed_at or None,
        }
        if self.locked:
            # When the notice period ends and the lock starts to bind.
            out["binds_from_time"] = self.starts_at()
        if ts is not None:
            out["status"] = self.status(ts)
        return out


@dataclass(frozen=True)
class RouteClear:
    signer_pubkey: str
    owner_pubkey: str


@dataclass(frozen=True)
class RouteCheck:
    """Verdict of `can_install` / `can_clear`.

    `code` is a stable error code (empty when ok); `cleared_by` is set only for
    an allowed clear.
    """

    ok: bool
    reason: str = ""
    code: str = ""
    cleared_by: str = ""


@dataclass(frozen=True)
class RouteSplit:
    """One routed credit. `gross == net + routed` always."""

    owner_pubkey: str
    destination_pubkey: str
    gross: int
    net: int
    routed: int
    bps: int
    version: int
    credit_class: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "recipient_pubkey": self.owner_pubkey,
            "destination_pubkey": self.destination_pubkey,
            "gross": self.gross,
            "net": self.net,
            "routed": self.routed,
            "bps": self.bps,
            "route_version": self.version,
            "credit_class": self.credit_class,
        }


# --- Parsing ------------------------------------------------------------------


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise ReceiveRouteShapeError(f"{name} must be 96 lowercase hex characters")
    return value


def _u64(tx: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    value = tx.get(name)
    if value is None and default is not None:
        return default
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise ReceiveRouteShapeError(f"{name} must be an unsigned 64-bit integer")
    return value


def parse_route_set(tx: Dict[str, Any]) -> ReceiveRoute:
    """Read a route install from ROOT fields only; nothing nested is signed."""
    if not isinstance(tx, dict):
        raise ReceiveRouteShapeError("transaction must be an object")
    owner = _pubkey(tx, "sender_pubkey")
    destination = _pubkey(tx, "destination_pubkey")
    locked = tx.get("locked")
    if locked is None:
        # An absent `locked` and an explicit null sign identically (the signing
        # dict carries the value or null), so they must parse identically too.
        locked = False
    if not isinstance(locked, bool):
        raise ReceiveRouteShapeError("locked must be a boolean")
    return ReceiveRoute(
        owner_pubkey=owner,
        destination_pubkey=destination,
        bps=_u64(tx, "route_bps"),
        min_amount=_u64(tx, "min_amount", 0),
        active_from=_u64(tx, "active_from_time", 0),
        expires_at=_u64(tx, "expires_at_time", 0),
        locked=locked,
        version=_u64(tx, "sequence_number"),
    )


def parse_route_clear(tx: Dict[str, Any]) -> RouteClear:
    if not isinstance(tx, dict):
        raise ReceiveRouteShapeError("transaction must be an object")
    return RouteClear(_pubkey(tx, "sender_pubkey"), _pubkey(tx, "route_owner_pubkey"))


def validate_route_shape(route: ReceiveRoute, ts: int) -> Optional[str]:
    """Stateless admissibility of an install at block time `ts`. None when fine.

    Shared by admission and apply: they must reject the same inputs or the
    chain splits. Anything that needs the book lives in `can_install`.
    """
    if route.destination_pubkey == route.owner_pubkey:
        return "destination must not be the receiving account"
    if not (1 <= route.bps <= MAX_ROUTE_BPS):
        return f"route_bps must be in 1..{MAX_ROUTE_BPS}"
    if route.min_amount > tau_defs.MAX_TRANSFER_VALUE:
        return f"min_amount must be at most {tau_defs.MAX_TRANSFER_VALUE}"
    if route.active_from and route.active_from > ts + MAX_SCHEDULE_SECONDS:
        return f"active_from_time is more than {MAX_SCHEDULE_SECONDS} seconds ahead"
    if route.expires_at:
        if route.expires_at <= ts:
            return "expires_at_time must be in the future"
        if route.active_from and route.expires_at <= route.active_from:
            return "expires_at_time must be after active_from_time"
    if route.locked:
        if not route.expires_at:
            return "a locked route needs expires_at_time"
        if route.expires_at <= ts + LOCK_NOTICE_SECONDS:
            return (
                "a locked route must expire more than "
                f"{LOCK_NOTICE_SECONDS} seconds after install (its notice period)"
            )
        if route.expires_at > ts + MAX_LOCK_SECONDS:
            return f"a locked route may last at most {MAX_LOCK_SECONDS} seconds"
    return None


def compute_split(route: ReceiveRoute, gross: int, credit_class: str) -> Optional[RouteSplit]:
    """The split of one credit under `route`, or None when nothing is routed.

    Pure arithmetic on the gross credit: no fee is taken out of it, and the
    two parts always sum back to it.
    """
    if credit_class not in ROUTED_CREDIT_CLASSES:
        return None
    if gross <= 0 or gross < route.min_amount:
        return None
    routed = (gross * route.bps) // BPS_DENOMINATOR
    if routed <= 0:
        return None
    return RouteSplit(
        owner_pubkey=route.owner_pubkey,
        destination_pubkey=route.destination_pubkey,
        gross=gross,
        net=gross - routed,
        routed=routed,
        bps=route.bps,
        version=route.version,
        credit_class=credit_class,
    )


# --- Guard-blocked changes (rule_change_request kinds 6 and 7) ------------------
#
# When the owner's rule-change guard blocks a direct receive_route_set or an
# owner's receive_route_clear, the owner parks the same change as a
# rule_change_request: kind 6 with a route spec as its `rule_text`, kind 7 with
# no text. Approvals or the time escape release it like any other kind.
#
# The request's BODY -- bound into its id and the approval state root -- is the
# canonical spec plus the request's sequence number, which becomes the route's
# version. The release therefore needs nothing the stored entry does not hash.

ROUTE_SPEC_TAG = "receive_route_v1"
_SPEC_FIELDS = frozenset({
    "destination", "bps", "min_amount", "active_from_time", "expires_at_time",
    "locked", "version",
})


def stamped(route: ReceiveRoute, ts: int) -> ReceiveRoute:
    """`route` as installed by a block with timestamp `ts`."""
    return replace(route, installed_at=int(ts))


def route_spec_text(
    destination_pubkey: str,
    bps: int,
    *,
    min_amount: int = 0,
    active_from_time: int = 0,
    expires_at_time: int = 0,
    locked: bool = False,
) -> str:
    """The `rule_text` of a kind-6 request. It carries no version: the
    request's sequence number supplies it."""
    return (
        f"{ROUTE_SPEC_TAG} destination={destination_pubkey} bps={int(bps)} "
        f"min_amount={int(min_amount)} active_from_time={int(active_from_time)} "
        f"expires_at_time={int(expires_at_time)} locked={1 if locked else 0}"
    )


def route_spec_body(route: ReceiveRoute) -> str:
    """Canonical body of a parked install: every field, in a fixed order."""
    return route_spec_text(
        route.destination_pubkey, route.bps,
        min_amount=route.min_amount, active_from_time=route.active_from,
        expires_at_time=route.expires_at, locked=route.locked,
    ) + f" version={route.version}"


def _spec_fields(text: Any) -> Dict[str, str]:
    if not isinstance(text, str):
        raise ReceiveRouteShapeError("a route spec must be a string")
    tokens = text.split()
    if not tokens or tokens[0] != ROUTE_SPEC_TAG:
        raise ReceiveRouteShapeError(f"a route spec starts with {ROUTE_SPEC_TAG}")
    fields: Dict[str, str] = {}
    for token in tokens[1:]:
        key, sep, value = token.partition("=")
        if not sep or key not in _SPEC_FIELDS:
            raise ReceiveRouteShapeError(f"unknown route spec field {token!r}")
        if key in fields:
            raise ReceiveRouteShapeError(f"route spec field {key} is given twice")
        fields[key] = value
    return fields


def _spec_u64(fields: Dict[str, str], key: str, default: Optional[int] = None) -> int:
    raw = fields.get(key)
    if raw is None:
        if default is None:
            raise ReceiveRouteShapeError(f"a route spec needs {key}")
        return default
    # Canonical decimal only, so one route has one spelling.
    if not _DECIMAL_RE.match(raw) or int(raw) > _U64_MAX:
        raise ReceiveRouteShapeError(f"{key} must be an unsigned 64-bit decimal")
    return int(raw)


def parse_route_spec(
    text: Any, owner_pubkey: str, *, version: Optional[int] = None
) -> ReceiveRoute:
    """The route a spec describes, owned by `owner_pubkey`.

    Pass `version` (the request's sequence number) when reading a request's
    `rule_text`, which must not carry one; leave it None when reading a stored
    body, which must. Shape only: `can_install` judges the route at release.
    """
    fields = _spec_fields(text)
    if version is None:
        version = _spec_u64(fields, "version")
    elif "version" in fields:
        raise ReceiveRouteShapeError(
            "version is the request's sequence number; leave it out of rule_text"
        )
    destination = fields.get("destination")
    if destination is None or not _PUBKEY_RE.match(destination):
        raise ReceiveRouteShapeError("destination must be 96 lowercase hex characters")
    locked = fields.get("locked", "0")
    if locked not in ("0", "1"):
        raise ReceiveRouteShapeError("locked must be 0 or 1")
    return ReceiveRoute(
        owner_pubkey=owner_pubkey,
        destination_pubkey=destination,
        bps=_spec_u64(fields, "bps"),
        min_amount=_spec_u64(fields, "min_amount", 0),
        active_from=_spec_u64(fields, "active_from_time", 0),
        expires_at=_spec_u64(fields, "expires_at_time", 0),
        locked=locked == "1",
        version=int(version),
    )


def route_spec_destination(text: Any) -> Optional[str]:
    """The destination a spec names, or None when it does not get that far
    (the request's own shape check reports why)."""
    try:
        return _spec_fields(text).get("destination")
    except ReceiveRouteShapeError:
        return None


def capability() -> Dict[str, Any]:
    """What this node does with receive routes. Served by RPC, never hashed."""
    return {
        "supported": True,
        "version": 1,
        "tx_types": sorted(RECEIVE_ROUTE_TX_TYPES),
        "routes_per_account": 1,
        "destinations_per_route": 1,
        "bps_denominator": BPS_DENOMINATOR,
        "max_bps": MAX_ROUTE_BPS,
        "rounding": ROUNDING,
        "rounding_rule": "routed = floor(gross * bps / 10000); net = gross - routed",
        "credit_classes_routed": list(ROUTED_CREDIT_CLASSES),
        "credit_classes_excluded": list(EXCLUDED_CREDIT_CLASSES),
        "hops": 1,
        "fee_model": (
            "single ledger-level split: the sender pays the one ordinary fee of "
            "the transaction that carries the credit; routing adds no fee and "
            "takes nothing from gross, net or routed"
        ),
        "routing_fee": 0,
        "admin_fee": "receive_route_set and receive_route_clear pay the ordinary transaction fee",
        "counts_toward_recipient_spend": False,
        "guard_kinds": {
            "set": tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE,
            "clear": tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE,
        },
        # A change the owner's guard blocks is parked as a rule_change_request
        # of the same kind and released by approvals or the time escape.
        "guarded_change": {
            "tx_type": "rule_change_request",
            "set_rule_text": (
                f"{ROUTE_SPEC_TAG} destination=<hex> bps=<n> [min_amount=<n>] "
                "[active_from_time=<unix>] [expires_at_time=<unix>] [locked=0|1]"
            ),
            "clear_rule_text": "",
        },
        "max_lock_seconds": MAX_LOCK_SECONDS,
        "lock_notice_seconds": LOCK_NOTICE_SECONDS,
        "max_schedule_seconds": MAX_SCHEDULE_SECONDS,
    }


# --- The book -----------------------------------------------------------------

_Row = Tuple[str, str, int, int, int, int, bool, int, int]


class ReceiveRouteBook:
    """owner -> route. Routes are frozen, so copies share them."""

    def __init__(self) -> None:
        self.routes: Dict[str, ReceiveRoute] = {}
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "ReceiveRouteBook":
        clone = ReceiveRouteBook.__new__(ReceiveRouteBook)
        clone.routes = dict(self.routes)
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    @classmethod
    def restore(cls, rows: Iterable[_Row]) -> "ReceiveRouteBook":
        """Rebuild from stored rows; refuses a row that is not a route the
        node could have installed (unknown shape, duplicate owner)."""
        book = cls()
        for (owner, destination, bps, min_amount, active_from, expires_at, locked, version,
             installed_at) in rows:
            for key in (owner, destination):
                if not isinstance(key, str) or not _PUBKEY_RE.match(key):
                    raise ValueError("stored receive route has a malformed key")
            # Every number is hashed as a u64 (bps as a u32): a value outside
            # that range would fail later, inside the meta-hash computation.
            for value in (bps, min_amount, active_from, expires_at, version, installed_at):
                if not _is_int(value) or not 0 <= value <= _U64_MAX:
                    raise ValueError(f"stored receive route has a bad number: {owner[:16]}")
            if not isinstance(locked, bool):
                raise ValueError(f"stored receive route has a bad lock flag: {owner[:16]}")
            if owner == destination:
                raise ValueError(f"stored receive route routes to itself: {owner[:16]}")
            if not (1 <= int(bps) <= MAX_ROUTE_BPS):
                raise ValueError(f"stored receive route has bps out of range: {owner[:16]}")
            if locked and not expires_at:
                raise ValueError(f"stored locked receive route has no expiry: {owner[:16]}")
            if owner in book.routes:
                raise ValueError(f"duplicate stored receive route: {owner[:16]}")
            book.routes[owner] = ReceiveRoute(
                owner, destination, int(bps), int(min_amount), int(active_from),
                int(expires_at), bool(locked), int(version), int(installed_at),
            )
        return book

    # -- queries -------------------------------------------------------------

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_receive_route_book_root(
                [r.as_row() for r in self.routes.values()]
            )
        return self._root

    def is_empty(self) -> bool:
        return not self.routes

    def get(self, owner: str) -> Optional[ReceiveRoute]:
        return self.routes.get(owner)

    def __len__(self) -> int:
        return len(self.routes)

    def split(self, recipient: str, gross: int, ts: int,
              credit_class: str) -> Optional[RouteSplit]:
        """The split of a credit to `recipient` at block time `ts`, or None."""
        route = self.routes.get(recipient)
        if route is None or not route.is_active(ts):
            return None
        return compute_split(route, int(gross), credit_class)

    def snapshot_rows(self) -> List[Dict[str, Any]]:
        return [
            {
                "owner_pubkey": r.owner_pubkey,
                "destination_pubkey": r.destination_pubkey,
                "bps": r.bps,
                "min_amount": r.min_amount,
                "active_from": r.active_from,
                "expires_at": r.expires_at,
                "locked": bool(r.locked),
                "version": r.version,
                "installed_at": r.installed_at,
            }
            for _, r in sorted(self.routes.items())
        ]

    # -- admission (shared with apply) ---------------------------------------

    def can_install(self, route: ReceiveRoute, ts: int) -> RouteCheck:
        reason = validate_route_shape(route, ts)
        if reason:
            return RouteCheck(False, reason, CODE_INVALID)
        current = self.routes.get(route.owner_pubkey)
        if current is not None and current.lock_holds(ts):
            return RouteCheck(
                False, f"the current route is locked until {current.expires_at}", CODE_LOCKED
            )
        return RouteCheck(True)

    def can_clear(self, request: RouteClear, ts: int) -> RouteCheck:
        """The owner may clear an unlocked route; the destination may always
        release one, since that only gives up its share."""
        current = self.routes.get(request.owner_pubkey)
        if current is None:
            return RouteCheck(
                False, "no receive route is installed for this account", CODE_UNKNOWN
            )
        if request.signer_pubkey == current.destination_pubkey:
            return RouteCheck(True, cleared_by=CLEARED_BY_DESTINATION)
        if request.signer_pubkey != request.owner_pubkey:
            return RouteCheck(
                False, "only the owner or the route's destination may clear it", CODE_NOT_OWNER
            )
        if current.lock_holds(ts):
            return RouteCheck(
                False, f"the route is locked until {current.expires_at}", CODE_LOCKED
            )
        return RouteCheck(True, cleared_by=CLEARED_BY_OWNER)

    # -- mutation ------------------------------------------------------------

    def install(self, route: ReceiveRoute) -> Optional[ReceiveRoute]:
        """Install or replace; returns the route it replaced. Callers stamp
        `installed_at` with the block timestamp first (see `stamped`)."""
        previous = self.routes.get(route.owner_pubkey)
        self.routes[route.owner_pubkey] = route
        self._root = None
        return previous

    def clear(self, owner: str) -> ReceiveRoute:
        route = self.routes.pop(owner)
        self._root = None
        return route

    def expire(self, ts: int) -> List[ReceiveRoute]:
        """Drop every route whose expiry has passed, in owner order."""
        gone = sorted(
            owner for owner, r in self.routes.items() if r.expires_at and ts >= r.expires_at
        )
        if not gone:
            return []
        self._root = None
        return [self.routes.pop(owner) for owner in gone]
