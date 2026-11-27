"""Receive routes (#35): recipient-controlled atomic split of incoming credits.

An account owner installs a route with ``receive_route_set``: a destination and
a share in basis points. From then on, when an ordinary credit reaches the
account, the node divides the GROSS credit in the same atomic write:

    routed = floor(gross * bps / 10000)      -> destination
    net    = gross - routed                  -> the owner

No wallet needs to be online, and a sender cannot bypass the route: the sender
signs "send gross to recipient" as always, and the recipient's public on-chain
route decides how the account accepts it.

Credit classes routed (v1): ordinary transfers (user_tx), executed co-signature
requests, standing-payment executions and grant draws -- every credit made by
the per-transaction transfer step. NOT routed: faucet/genesis funding, fees,
retractable releases, grant refunds and cancellations, and route outputs
themselves. Routing is single-hop: a routed credit never triggers the
destination's own route, so A->B->A loops cannot exist.

A route may be LOCKED until ``locked_until`` (a binding revenue-share): until
then the owner can neither replace nor remove it, and an expiry is mandatory.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from consensus.serialization import compute_route_book_root

TX_TYPE_ROUTE_SET = "receive_route_set"
TX_TYPE_ROUTE_REMOVE = "receive_route_remove"
ROUTE_TX_TYPES = frozenset({TX_TYPE_ROUTE_SET, TX_TYPE_ROUTE_REMOVE})

BPS_DENOMINATOR = 10_000
MAX_ROUTE_BPS = 9_000  # product limit below 100%
MAX_ROUTES_TOTAL = 65_536
MAX_ROUTE_HORIZON_SECONDS = 5 * 31_536_000

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF


class RouteShapeError(ValueError):
    """A route transaction does not have a shape the node can record."""


@dataclass(frozen=True)
class ReceiveRoute:
    owner_pubkey: str
    destination_pubkey: str
    bps: int
    min_incoming: int
    activate_at: int
    expires_at: int  # 0 = none (not allowed when locked)
    locked_until: int  # 0 = not locked
    version: int  # the owner's sequence number at installation

    def as_tuple(self) -> tuple:
        return (self.owner_pubkey, self.destination_pubkey, self.bps, self.min_incoming,
                self.activate_at, self.expires_at, self.locked_until, self.version)

    def active_at(self, ts: int) -> bool:
        return ts >= self.activate_at and (not self.expires_at or ts < self.expires_at)

    def locked_at(self, ts: int) -> bool:
        return bool(self.locked_until) and ts < self.locked_until

    def split(self, gross: int) -> Tuple[int, int]:
        """(net, routed) for a gross credit. Floor rounding; net + routed == gross."""
        if gross < self.min_incoming:
            return gross, 0
        routed = gross * self.bps // BPS_DENOMINATOR
        return gross - routed, routed


@dataclass(frozen=True)
class RouteRemove:
    owner_pubkey: str


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _pubkey(tx: Dict[str, Any], name: str) -> str:
    v = tx.get(name)
    if not isinstance(v, str) or not _PUBKEY_RE.match(v):
        raise RouteShapeError(f"{name} must be 96 lowercase hex characters")
    return v


def _u64(tx: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    v = tx.get(name, default)
    if not _is_int(v) or v < 0 or v > _U64_MAX:
        raise RouteShapeError(f"{name} must be an unsigned 64-bit integer")
    return v


def parse_route_set(tx: Dict[str, Any]) -> ReceiveRoute:
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    return ReceiveRoute(
        owner_pubkey=_pubkey(tx, "sender_pubkey"),
        destination_pubkey=_pubkey(tx, "destination_pubkey"),
        bps=_u64(tx, "bps"),
        min_incoming=_u64(tx, "min_incoming", 0),
        activate_at=_u64(tx, "activate_at", 0),
        expires_at=_u64(tx, "expires_at", 0),
        locked_until=_u64(tx, "locked_until", 0),
        version=_u64(tx, "sequence_number"),
    )


def parse_route_remove(tx: Dict[str, Any]) -> RouteRemove:
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    return RouteRemove(_pubkey(tx, "sender_pubkey"))


def validate_route(r: ReceiveRoute, ts: int) -> Optional[str]:
    """Stateless admissibility of a route at block time ``ts``. None when fine."""
    if r.destination_pubkey == r.owner_pubkey:
        return "destination must differ from the owner (no self-route)"
    if not 1 <= r.bps <= MAX_ROUTE_BPS:
        return f"bps must be in 1..{MAX_ROUTE_BPS}"
    if r.expires_at and r.expires_at <= max(ts, r.activate_at):
        return "expires_at must be in the future and after activate_at"
    if r.expires_at and r.expires_at > ts + MAX_ROUTE_HORIZON_SECONDS:
        return f"expires_at is more than {MAX_ROUTE_HORIZON_SECONDS} seconds ahead"
    if r.activate_at > ts + MAX_ROUTE_HORIZON_SECONDS:
        return "activate_at is too far ahead"
    if r.locked_until:
        if not r.expires_at:
            return "a locked route needs an expiry"
        if r.locked_until > r.expires_at:
            return "locked_until cannot be after expires_at"
        if r.locked_until <= ts:
            return "locked_until must be in the future"
    return None


class RouteBook:
    """At most one route per account. ``changes`` counts installs and removals."""

    def __init__(self) -> None:
        self.routes: Dict[str, ReceiveRoute] = {}
        self.changes = 0
        self._root: Optional[bytes] = None

    def __deepcopy__(self, memo: Dict[int, Any]) -> "RouteBook":
        clone = RouteBook.__new__(RouteBook)
        clone.routes = dict(self.routes)
        clone.changes = self.changes
        clone._root = self._root
        memo[id(self)] = clone
        return clone

    def is_empty(self) -> bool:
        return not self.routes and not self.changes

    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_route_book_root(
                [r.as_tuple() for r in self.routes.values()], self.changes
            )
        return self._root

    def get(self, owner: str) -> Optional[ReceiveRoute]:
        return self.routes.get(owner)

    def active_route(self, owner: str, ts: int) -> Optional[ReceiveRoute]:
        r = self.routes.get(owner)
        return r if r is not None and r.active_at(ts) else None

    def has_due(self, ts: int) -> bool:
        return any(r.expires_at and r.expires_at <= ts for r in self.routes.values())

    def can_admit_set(self, route: ReceiveRoute, ts: int) -> Tuple[bool, str]:
        reason = validate_route(route, ts)
        if reason:
            return False, reason
        current = self.routes.get(route.owner_pubkey)
        if current is not None and current.locked_at(ts):
            return False, "the current route is locked until locked_until"
        if current is None and len(self.routes) >= MAX_ROUTES_TOTAL:
            return False, "route book is full"
        return True, ""

    def can_admit_remove(self, req: RouteRemove, ts: int) -> Tuple[bool, str]:
        current = self.routes.get(req.owner_pubkey)
        if current is None:
            return False, "no receive route installed"
        if current.locked_at(ts):
            return False, "the route is locked until locked_until"
        return True, ""

    def install(self, route: ReceiveRoute) -> None:
        self.routes[route.owner_pubkey] = route
        self.changes += 1
        self._root = None

    def remove(self, owner: str) -> ReceiveRoute:
        route = self.routes.pop(owner)
        self.changes += 1
        self._root = None
        return route

    def expire_due(self, ts: int) -> List[ReceiveRoute]:
        """Drop routes whose expiry has passed (book hygiene; they route nothing)."""
        gone = sorted(o for o, r in self.routes.items() if r.expires_at and r.expires_at <= ts)
        return [self.remove(o) for o in gone]

    def snapshot(self) -> Dict[str, Any]:
        return {
            "changes": self.changes,
            "routes": [
                {"owner_pubkey": r.owner_pubkey, "destination_pubkey": r.destination_pubkey,
                 "bps": r.bps, "min_incoming": r.min_incoming, "activate_at": r.activate_at,
                 "expires_at": r.expires_at, "locked_until": r.locked_until,
                 "version": r.version}
                for _, r in sorted(self.routes.items())
            ],
        }


def load_route_book(state: Dict[str, Any]) -> RouteBook:
    book = RouteBook()
    for r in state.get("routes", []):
        route = parse_route_set({
            "sender_pubkey": r["owner_pubkey"], "destination_pubkey": r["destination_pubkey"],
            "bps": r["bps"], "min_incoming": r["min_incoming"], "activate_at": r["activate_at"],
            "expires_at": r["expires_at"], "locked_until": r["locked_until"],
            "sequence_number": r["version"],
        })
        if not 1 <= route.bps <= MAX_ROUTE_BPS or route.owner_pubkey == route.destination_pubkey:
            raise ValueError(f"stored route is invalid: {route.owner_pubkey[:16]}")
        if route.owner_pubkey in book.routes:
            raise ValueError("duplicate stored route")
        book.routes[route.owner_pubkey] = route
    changes = state.get("changes", 0)
    if not _is_int(changes) or changes < len(book.routes):
        raise ValueError("stored route change count is impossible")
    book.changes = changes
    return book
