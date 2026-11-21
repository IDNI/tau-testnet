"""Receive routes (Bounty 01, Stage 4).

One route per account: when a routable credit lands on the account, a
portion of it is forwarded to a destination. The split is::

    routed = floor(gross * bps / 10000)
    net    = gross - routed

with ``bps`` in 1..9000, so the recipient always keeps at least 10%.

Only two credit classes are routable (design 1.4 / 2.2, see
``consensus/credits.py``): ordinary ``transfer`` credits and
``standing_payment`` credits. Everything else passes through untouched:
faucet grants, genesis allocations, fee/reward credits, refunds, route
outputs, grant draws and refunds, payout legs, and retractable releases.
The routed portion is recorded as ``CREDIT_ROUTE_OUTPUT``, which is itself
NOT routable — so the split is a single hop by construction, even when the
destination has its own route.

The receipt is atomic: the recipient's balance grows by ``net`` and the
destination's by ``routed`` in the same staged-write step, and both are
recorded with the same transaction id, so the pair (net, routed) sums to
the gross and either both land or neither does (staged writes commit only
for an accepted transaction).

A route is active only inside ``[activate_at, expires_at)`` and only for
incoming amounts at or above ``min_incoming``. ``locked_until`` is an
optional binding lock: while it is in the future the route cannot be
changed or removed, so the owner can commit to a split for a fixed window.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple

from blake3 import blake3

from consensus.credits import CREDIT_ROUTE_OUTPUT, is_routable_credit
from consensus.serialization import (
    encode_hash32,
    encode_pubkey48,
    encode_string,
    encode_uint32,
    encode_uint64,
)

TX_TYPE_ROUTE_SET = "route_set"
TX_TYPE_ROUTE_REMOVE = "route_remove"
ROUTE_TX_TYPES = frozenset({TX_TYPE_ROUTE_SET, TX_TYPE_ROUTE_REMOVE})
# route_set changes consensus state, so it pays; route_remove is
# fee-exempt, like a retract or a standing/grant cancel.
ROUTE_FEE_BEARING_TX_TYPES = frozenset({TX_TYPE_ROUTE_SET})

DOMAIN_ROUTE_BOOK_V1 = "tau.route.book.v1"
DOMAIN_ROUTE_RESOLVED_V1 = "tau.route.resolved.v1"

MIN_BPS = 1
MAX_BPS = 9000
MAX_ROUTES_TOTAL = 4096

_PUBKEY_RE = re.compile(r"^[0-9a-f]{96}$")


class RouteShapeError(ValueError):
    """A route transaction whose shape the node cannot accept."""


def _is_pubkey(value: Any) -> bool:
    return isinstance(value, str) and bool(_PUBKEY_RE.match(value))


def _u64_field(tx: Dict, name: str) -> int:
    value = tx.get(name)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RouteShapeError(f"{name} must be a non-negative integer")
    if value > 2**64 - 1:
        raise RouteShapeError(f"{name} exceeds uint64")
    return value


def _opt_u64_field(tx: Dict, name: str) -> Optional[int]:
    value = tx.get(name)
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RouteShapeError(f"{name} must be a non-negative integer or null")
    if value > 2**64 - 1:
        raise RouteShapeError(f"{name} exceeds uint64")
    return value


@dataclass(frozen=True)
class RouteEntry:
    """The immutable terms of one account's receive route.

    One route per account, keyed by the account pubkey. ``bps`` is the
    routed share in basis points (1..9000). ``min_incoming`` is the
    smallest gross the route applies to (0 = any amount). The route is
    active in ``[activate_at, expires_at)``. ``locked_until`` is None for
    an unlocked route; while it is in the future the route cannot be
    changed or removed.
    """

    account_pubkey: str
    destination_pubkey: str
    bps: int
    min_incoming: int
    activate_at: int
    expires_at: int
    locked_until: Optional[int]
    sequence_number: int

    @property
    def route_id(self) -> bytes:
        """Stable id: the account plus the sequence that created the route."""
        h = blake3()
        h.update(encode_string("tau.route.v1"))
        h.update(encode_pubkey48(self.account_pubkey))
        h.update(encode_uint64(self.sequence_number))
        return h.digest()


def parse_route_set(tx: Dict) -> RouteEntry:
    """Structural parse of a route_set transaction (no state checks)."""
    sender = tx.get("sender_pubkey")
    if not _is_pubkey(sender):
        raise RouteShapeError("sender_pubkey must be a 96-hex pubkey")
    destination = tx.get("destination_pubkey")
    if not _is_pubkey(destination):
        raise RouteShapeError("destination_pubkey must be a 96-hex pubkey")
    return RouteEntry(
        account_pubkey=sender,
        destination_pubkey=destination,
        bps=_u64_field(tx, "bps"),
        min_incoming=_u64_field(tx, "min_incoming"),
        activate_at=_u64_field(tx, "activate_at"),
        expires_at=_u64_field(tx, "expires_at"),
        locked_until=_opt_u64_field(tx, "locked_until"),
        sequence_number=_u64_field(tx, "sequence_number"),
    )


@dataclass(frozen=True)
class RouteRemoveRequest:
    account_pubkey: str


def parse_route_remove(tx: Dict) -> RouteRemoveRequest:
    """Structural parse of a route_remove transaction (no state checks)."""
    sender = tx.get("sender_pubkey")
    if not _is_pubkey(sender):
        raise RouteShapeError("sender_pubkey must be a 96-hex pubkey")
    return RouteRemoveRequest(account_pubkey=sender)


def validate_route_shape(
    entry: RouteEntry, height: int, now: int
) -> Optional[str]:
    """Semantic shape checks for a route. None when the shape is valid."""
    if not _is_pubkey(entry.account_pubkey):
        return "account_pubkey must be a 96-hex pubkey"
    if not _is_pubkey(entry.destination_pubkey):
        return "destination_pubkey must be a 96-hex pubkey"
    if entry.destination_pubkey == entry.account_pubkey:
        return "a route cannot point at its own account"
    if not MIN_BPS <= entry.bps <= MAX_BPS:
        return f"bps must be in {MIN_BPS}..{MAX_BPS}"
    if entry.min_incoming < 0:
        return "min_incoming must be non-negative"
    if entry.activate_at >= entry.expires_at:
        return "activate_at must be before expires_at"
    if entry.locked_until is not None:
        if entry.locked_until <= now:
            return "locked_until must be in the future"
        if entry.locked_until > entry.expires_at:
            return "locked_until must not exceed expires_at"
    return None


class RouteBook:
    """One receive route per account.

    The book is the consensus state for routes: it is deep-copied per
    candidate block (like the other programmable-payments books), bound
    into the consensus meta hash through ``root()``, and persisted by
    ``chain_state``/``db``. A removed route folds into the resolved
    commitment, so a restart cannot resurrect it.
    """

    def __init__(self) -> None:
        self.routes: Dict[str, RouteEntry] = {}
        self._resolved_count: int = 0
        self._resolved_acc: bytes = bytes(32)

    # -- queries ---------------------------------------------------------
    def get(self, account_pubkey: str) -> Optional[RouteEntry]:
        return self.routes.get(account_pubkey)

    def is_empty(self) -> bool:
        return not self.routes

    def open_count(self) -> int:
        return len(self.routes)

    def resolved_state(self) -> Tuple[int, bytes]:
        return (self._resolved_count, self._resolved_acc)

    def root(self) -> bytes:
        """Deterministic commitment over the open routes + resolved."""
        h = blake3()
        h.update(encode_string(DOMAIN_ROUTE_BOOK_V1))
        for account in sorted(self.routes):
            entry = self.routes[account]
            h.update(encode_pubkey48(entry.account_pubkey))
            h.update(encode_pubkey48(entry.destination_pubkey))
            h.update(encode_uint64(entry.bps))
            h.update(encode_uint64(entry.min_incoming))
            h.update(encode_uint64(entry.activate_at))
            h.update(encode_uint64(entry.expires_at))
            h.update(encode_uint64(entry.locked_until or 0))
            h.update(encode_uint64(entry.sequence_number))
        h.update(encode_uint64(self._resolved_count))
        h.update(self._resolved_acc)
        return h.digest()

    # -- admission -------------------------------------------------------
    def can_admit_set(
        self, entry: RouteEntry, height: int, now: int
    ) -> Tuple[bool, str]:
        """True when a route_set may land (shape + lock + book cap)."""
        shape_error = validate_route_shape(entry, height, now)
        if shape_error is not None:
            return (False, shape_error)
        current = self.routes.get(entry.account_pubkey)
        if current is not None and current.locked_until is not None:
            if now < current.locked_until:
                return (
                    False,
                    f"route is locked until {current.locked_until}",
                )
        if current is None and len(self.routes) >= MAX_ROUTES_TOTAL:
            return (False, "the route book is full")
        return (True, "")

    def can_admit_remove(
        self, account_pubkey: str, sender_pubkey: Any, height: int, now: int
    ) -> Tuple[bool, str]:
        """True when a route_remove may land (owner + exists + unlocked)."""
        current = self.routes.get(account_pubkey)
        if current is None:
            return (False, "unknown route")
        if sender_pubkey != account_pubkey:
            return (False, "only the account owner can remove its route")
        if current.locked_until is not None and now < current.locked_until:
            return (
                False,
                f"route is locked until {current.locked_until}",
            )
        return (True, "")

    # -- mutation --------------------------------------------------------
    def submit(self, entry: RouteEntry) -> None:
        """Set (or replace) the account's route. One route per account."""
        self.routes[entry.account_pubkey] = entry

    def remove(self, account_pubkey: str) -> None:
        """Remove the account's route, folding it into the resolved commitment."""
        entry = self.routes.pop(account_pubkey, None)
        if entry is None:
            return
        self._resolved_count += 1
        h = blake3()
        h.update(encode_string(DOMAIN_ROUTE_RESOLVED_V1))
        h.update(self._resolved_acc)
        h.update(entry.route_id)
        self._resolved_acc = h.digest()

    # -- the split -------------------------------------------------------
    def apply_route(
        self, account_pubkey: str, amount: int, credit_class: int, ts: int
    ) -> Optional[Tuple[int, int, str]]:
        """Split an incoming credit for ``account_pubkey``.

        Returns ``(net, routed, destination)`` when the route applies, else
        None. The credit class must be routable, the route must be active
        at ``ts``, the gross must reach ``min_incoming``, and the routed
        share must be positive (a dust gross under a small bps splits
        nothing). The routed share is ``floor(gross * bps / 10000)``.
        """
        if not is_routable_credit(credit_class):
            return None
        entry = self.routes.get(account_pubkey)
        if entry is None:
            return None
        if ts < entry.activate_at or ts >= entry.expires_at:
            return None
        if amount < entry.min_incoming:
            return None
        routed = (amount * entry.bps) // 10000
        if routed <= 0:
            return None
        net = amount - routed
        if net <= 0:
            return None
        return (net, routed, entry.destination_pubkey)

    # -- persistence -----------------------------------------------------
    def snapshot_rows(self) -> List[Dict[str, Any]]:
        """Rows for the routes table: one per open route."""
        rows: List[Dict[str, Any]] = []
        for account in sorted(self.routes):
            entry = self.routes[account]
            rows.append(
                {
                    "account_pubkey": entry.account_pubkey,
                    "destination_pubkey": entry.destination_pubkey,
                    "bps": entry.bps,
                    "min_incoming": entry.min_incoming,
                    "activate_at": entry.activate_at,
                    "expires_at": entry.expires_at,
                    "locked_until": entry.locked_until,
                    "sequence_number": entry.sequence_number,
                }
            )
        return rows

    @classmethod
    def restore(
        cls,
        rows: Iterable[Dict[str, Any]],
        resolved_count: int,
        resolved_acc: bytes,
    ) -> "RouteBook":
        """Rebuild a book from stored rows.

        A row whose fields do not parse is refused: the stored state is
        corrupt, and loading it would fork the node.
        """
        book = cls()
        for row in rows:
            entry = RouteEntry(
                account_pubkey=row["account_pubkey"],
                destination_pubkey=row["destination_pubkey"],
                bps=int(row["bps"]),
                min_incoming=int(row["min_incoming"]),
                activate_at=int(row["activate_at"]),
                expires_at=int(row["expires_at"]),
                locked_until=(
                    None
                    if row["locked_until"] is None
                    else int(row["locked_until"])
                ),
                sequence_number=int(row["sequence_number"]),
            )
            # A stored route passed admission once. Restore re-checks only
            # the time-independent shape (pubkeys, bps range, the window);
            # the locked_until future check is time-dependent and is not
            # re-applied to stored state.
            if not _is_pubkey(entry.account_pubkey):
                raise ValueError("stored route has a bad account pubkey")
            if not _is_pubkey(entry.destination_pubkey):
                raise ValueError("stored route has a bad destination pubkey")
            if entry.destination_pubkey == entry.account_pubkey:
                raise ValueError("stored route points at its own account")
            if not MIN_BPS <= entry.bps <= MAX_BPS:
                raise ValueError("stored route has bps out of range")
            if entry.activate_at >= entry.expires_at:
                raise ValueError("stored route has an empty window")
            book.routes[entry.account_pubkey] = entry
        book._resolved_count = int(resolved_count)
        book._resolved_acc = bytes(resolved_acc)
        return book
