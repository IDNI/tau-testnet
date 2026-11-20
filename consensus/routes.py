"""Receive routes (Bounty 01, issue #35).

An account installs at most one route: a fixed share (basis points) of
every ordinary incoming transfer is diverted, atomically with the
credit, to one destination. The split is computed from the gross credit
by the node inside the transfer-execution seam, so a normal transfer
cannot bypass it and the fee is charged once, on the whole transfer,
exactly as the unrouted transfer would be charged.

The book in this module is the state machine for those installations.
It follows the RetractableBook / StandingBook pattern: entries are a
field of the consensus lifecycle manager, identity is a pure hash of
the signed terms, and the root binds exactly the routes installed now
(a route book is configuration, not a settlement ledger -- there is no
resolved accumulator, because a removal is an administrative act the
owner signs, not a settlement other rules must be able to audit).

Design rules that are consensus-visible and therefore live here:

- One destination per owner; the destination can never be the owner
  (a self-route is rejected at installation, not merely inert).
- The share is 1..9999 basis points: a product cap below 100%, so a
  route can never divert an entire credit and leave the recipient a
  zero it never agreed to (the issue rejects ">100% sets"; 100% is the
  same failure with a different label).
- A locked route is binding (the maintainer's #35 requirement): while
  the lock runs, removal or replacement needs the destination's
  signature over the unlock message, and a locked route must carry an
  expiry -- after the expiry the owner acts alone again. An expired
  route is inert whether or not it has been removed.
- Routing is a credit class of its own: the diverted share is credited
  by the seam itself and never re-enters the seam as an ordinary
  transfer, so a routed share can never trigger another route. That is
  a class rule, not a depth counter.

Balance, fee and policy (o5) checks live in the engine; this book only
decides *what is installed, whether it is active, and what the split
of a given gross amount is*.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from consensus import bls
from consensus.serialization import compute_route_book_root, compute_route_id

TX_TYPE_ROUTE_INSTALL = "receive_route_install"
TX_TYPE_ROUTE_REMOVE = "receive_route_remove"

ROUTE_TX_TYPES = frozenset({TX_TYPE_ROUTE_INSTALL, TX_TYPE_ROUTE_REMOVE})

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")
_ID_RE = re.compile(r"^[0-9a-f]{64}$")
_U64_MAX = 0xFFFFFFFFFFFFFFFF

MAX_ROUTES_TOTAL = 4096
MAX_BPS = 9999  # product cap: strictly below 100%

UNLOCK_DOMAIN = "tau.route.unlock.v1"


class RouteShapeError(ValueError):
    """A receive-route transaction does not have a recordable shape."""


@dataclass(frozen=True)
class RouteTerms:
    """The signed terms of one installed route. Never mutated.

    Pubkeys are the canonical 96-char lowercase hex strings the
    transaction layer carries (the RetractableEntry convention).
    ``activation_ts`` / ``expiry_ts`` are block-timestamp seconds;
    0 means "no bound" on that side. ``locked`` marks a binding route.
    """

    owner: str
    destination: str
    bps: int
    min_incoming: int = 0
    activation_ts: int = 0
    expiry_ts: int = 0
    locked: bool = False
    sequence_number: int = 0

    @property
    def route_id(self) -> bytes:
        return compute_route_id(
            self.owner,
            self.destination,
            self.bps,
            self.min_incoming,
            self.activation_ts,
            self.expiry_ts,
            1 if self.locked else 0,
            self.sequence_number,
        )

    def is_active(self, ts: int) -> bool:
        if self.activation_ts and ts < self.activation_ts:
            return False
        if self.expiry_ts and ts >= self.expiry_ts:
            return False
        return True

    def split(self, amount: int) -> int:
        """The diverted share of a gross credit of ``amount``.

        Floor rounding on the gross (101 at 20% routes 20, never 21).
        Below the route's minimum incoming amount, or when the floor
        share would be zero, nothing is diverted.
        """
        if amount < max(self.min_incoming, 1):
            return 0
        return amount * self.bps // 10_000

    def removal_locked(self, ts: int) -> bool:
        """True while removing/replacing this route needs the
        destination's signature: the route is locked and its expiry
        (mandatory for locked routes) has not yet passed."""
        return bool(self.locked and self.expiry_ts and ts < self.expiry_ts)


def unlock_message_bytes(route: RouteTerms) -> bytes:
    """The canonical bytes the destination signs to release a lock."""
    msg = {
        "domain": UNLOCK_DOMAIN,
        "route_id": route.route_id.hex(),
        "owner": route.owner,
        "destination": route.destination,
    }
    return json.dumps(msg, sort_keys=True, separators=(",", ":")).encode()


def verify_route_unlock(route: RouteTerms, signature_hex: Any) -> bool:
    """Verify the destination's BLS signature over the unlock message.

    Never raises: a malformed signature is a failed unlock, not an
    exception, because this runs inside block apply.
    """
    if not isinstance(signature_hex, str):
        return False
    try:
        sig_bytes = bytes.fromhex(signature_hex)
        pubkey_bytes = bytes.fromhex(route.destination)
        msg_hash = hashlib.sha256(unlock_message_bytes(route)).digest()
        return bool(bls.verify(pubkey_bytes, msg_hash, sig_bytes))
    except Exception:
        return False


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _pubkey_field(tx: Dict[str, Any], name: str) -> str:
    value = tx.get(name)
    if not isinstance(value, str) or not _PUBKEY_RE.match(value):
        raise RouteShapeError(f"{name} must be a 96-char lowercase hex pubkey")
    return value


def _u64_field(tx: Dict[str, Any], name: str, default: Optional[int] = None) -> int:
    value = tx.get(name, default)
    if not _is_int(value) or value < 0 or value > _U64_MAX:
        raise RouteShapeError(f"{name} must be an unsigned 64-bit integer")
    return int(value)


def parse_route_install(tx: Dict[str, Any]) -> RouteTerms:
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    locked_raw = tx.get("locked", False)
    if not isinstance(locked_raw, bool):
        raise RouteShapeError("locked must be a boolean")
    return RouteTerms(
        owner=_pubkey_field(tx, "sender_pubkey"),
        destination=_pubkey_field(tx, "destination_pubkey"),
        bps=_u64_field(tx, "bps"),
        min_incoming=_u64_field(tx, "min_incoming", 0),
        activation_ts=_u64_field(tx, "activation_timestamp", 0),
        expiry_ts=_u64_field(tx, "expiry_timestamp", 0),
        locked=locked_raw,
        sequence_number=_u64_field(tx, "sequence_number"),
    )


@dataclass(frozen=True)
class RouteRemoval:
    owner: str
    route_id: bytes
    destination_signature: Optional[str] = None


def parse_route_remove(tx: Dict[str, Any]) -> RouteRemoval:
    if not isinstance(tx, dict):
        raise RouteShapeError("transaction must be an object")
    owner = _pubkey_field(tx, "sender_pubkey")
    raw_id = tx.get("route_id")
    if not isinstance(raw_id, str) or not _ID_RE.match(raw_id):
        raise RouteShapeError("route_id must be a 64-char lowercase hex id")
    sig = tx.get("destination_signature")
    if sig is not None and not isinstance(sig, str):
        raise RouteShapeError("destination_signature must be a hex string")
    return RouteRemoval(
        owner=owner, route_id=bytes.fromhex(raw_id), destination_signature=sig
    )


def validate_route_shape(terms: RouteTerms, ts: int) -> Optional[str]:
    """Stateless admissibility of an install against the target block.

    Shared by admission and apply: they must reject the same inputs or
    the chain splits. Anything needing the book (the lock on the route
    being replaced) lives in the engine's checks against the book.
    Returns None when fine.
    """
    if terms.destination == terms.owner:
        return "a route's destination cannot be its owner (self-route)"
    if not 1 <= terms.bps <= MAX_BPS:
        return "bps must be in 1..9999 (a route diverts strictly less than the whole credit)"
    if terms.activation_ts and terms.expiry_ts and terms.expiry_ts <= terms.activation_ts:
        return "expiry_timestamp must be after activation_timestamp"
    if terms.locked and not terms.expiry_ts:
        return "a locked route must carry an expiry_timestamp (binding routes expire)"
    if terms.expiry_ts and terms.expiry_ts <= ts:
        return "expiry_timestamp is not in the future"
    return None


class RouteBook:
    """The installed routes, keyed by owner (at most one per owner)."""

    def __init__(self) -> None:
        self._routes: Dict[str, RouteTerms] = {}
        self._root: Optional[bytes] = None

    # -- queries ---------------------------------------------------------
    def get(self, owner: str) -> Optional[RouteTerms]:
        return self._routes.get(owner)

    def active_route(self, owner: str, ts: int) -> Optional[RouteTerms]:
        route = self._routes.get(owner)
        if route is None or not route.is_active(ts):
            return None
        return route

    def count(self) -> int:
        return len(self._routes)

    def is_empty(self) -> bool:
        return not self._routes

    # -- mutation --------------------------------------------------------
    def install(self, terms: RouteTerms) -> None:
        self._routes[terms.owner] = terms
        self._root = None

    def remove(self, owner: str) -> Optional[RouteTerms]:
        removed = self._routes.pop(owner, None)
        if removed is not None:
            self._root = None
        return removed

    # -- commitment ------------------------------------------------------
    def root(self) -> bytes:
        if self._root is None:
            self._root = compute_route_book_root(
                (
                    route.route_id,
                    route.owner,
                    route.destination,
                    route.bps,
                    route.min_incoming,
                    route.activation_ts,
                    route.expiry_ts,
                    1 if route.locked else 0,
                    route.sequence_number,
                )
                for route in self._routes.values()
            )
        return self._root

    # -- persistence -----------------------------------------------------
    def snapshot_rows(self) -> List[Dict[str, Any]]:
        return [
            {
                "owner_pubkey": route.owner,
                "destination_pubkey": route.destination,
                "bps": route.bps,
                "min_incoming": route.min_incoming,
                "activation_timestamp": route.activation_ts,
                "expiry_timestamp": route.expiry_ts,
                "locked": 1 if route.locked else 0,
                "sequence_number": route.sequence_number,
                "route_id": route.route_id.hex(),
            }
            for route in sorted(self._routes.values(), key=lambda r: r.owner)
        ]

    @classmethod
    def restore(cls, rows: List[Dict[str, Any]]) -> "RouteBook":
        book = cls()
        for row in rows:
            terms = RouteTerms(
                owner=row["owner_pubkey"],
                destination=row["destination_pubkey"],
                bps=int(row["bps"]),
                min_incoming=int(row.get("min_incoming", 0)),
                activation_ts=int(row.get("activation_timestamp", 0)),
                expiry_ts=int(row.get("expiry_timestamp", 0)),
                locked=bool(row.get("locked", 0)),
                sequence_number=int(row.get("sequence_number", 0)),
            )
            claimed = row.get("route_id")
            if claimed is not None and bytes.fromhex(claimed) != terms.route_id:
                raise ValueError(
                    "stored route row does not recompute to its route_id; "
                    "refusing to restore a book the rows do not describe"
                )
            if terms.owner in book._routes:
                raise ValueError("duplicate route row for one owner")
            book._routes[terms.owner] = terms
        return book
