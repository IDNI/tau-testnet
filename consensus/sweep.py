"""Post-transaction sweep framework for programmable payments.

The design (Bounty 01, sections 1.3 and 3) names exactly three triggers for
programmed money movement: time (this sweep), an ordinary credit (receive
routes, Stage 4), and an explicit execution transaction. This module is the
time trigger: after the transaction loop of a block, each registered book
reports what is due, the framework orders the work deterministically, runs it
up to a per-block cap, and carries the overflow to the next block by leaving
it due in its book.

CONSENSUS-FROZEN SURFACE
------------------------
``MAX_SWEEP_ACTIONS_PER_BLOCK`` is a module constant, not config: a per-node
value would make two honest nodes disagree about how much sweep work a block
does, which forks. Ordering is total and deterministic: ``(due_ts,
object_id)`` — a node that runs the same books at the same height and
timestamp executes the same items in the same order.

How a later stage plugs in
--------------------------
A book module registers one handler per object kind::

    from consensus import sweep

    sweep.register_handler("grant", _grant_sweep_handler)

A handler is any object with ``collect_due(lm, height, ts)`` returning the
due items (each a :class:`SweepDue` with the timestamp it fell due and the
object id) and ``execute(item, ctx)`` performing one item and returning an
outcome name (``"executed"``, ``"skipped"``, ...). The framework never lets
one item fail the block: an exception is recorded on that item and the sweep
goes on. A handler that mutates balances must conserve supply exactly like
the retractable release does (see ``_release_due_retractables``).

Stage 1 registers no handlers: the engine hook
(:func:`run_programmable_sweep`) is a no-op until Stage 2. That is
deliberate — the framework, its ordering, its cap and its failure isolation
are tested here, before any book depends on them.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Protocol, Tuple

# Design section 3: consensus-frozen, like MAX_OPEN_* in the book modules.
MAX_SWEEP_ACTIONS_PER_BLOCK = 256


@dataclass(frozen=True)
class SweepDue:
    """One item a book reports as due at a block's height/timestamp.

    ``due_ts`` is the block-header timestamp at which the item fell due (for
    height-triggered items, the timestamp of the block that reached the
    height); ``object_id`` is the object's consensus id, which breaks ties
    deterministically. ``kind`` names the owning book (``"grant"``,
    ``"standing"``, ...).
    """

    due_ts: int
    object_id: bytes
    kind: str

    def __post_init__(self) -> None:
        if not isinstance(self.due_ts, int) or isinstance(self.due_ts, bool) or self.due_ts < 0:
            raise ValueError("due_ts must be a non-negative integer")
        if not isinstance(self.object_id, (bytes, bytearray)) or not self.object_id:
            raise ValueError("object_id must be non-empty bytes")
        if not isinstance(self.kind, str) or not self.kind:
            raise ValueError("kind must be a non-empty string")


@dataclass
class SweepContext:
    """What a handler needs to execute one due item.

    ``balances`` / ``sequences`` are the block's mutable overlays (the same
    maps ``_release_due_retractables`` writes into); ``lm`` is the block's
    lifecycle manager; ``height`` / ``timestamp`` are the block header's.
    ``faucet_grant`` is the network's faucet grant for reading balances with
    no overlay record; ``credit_records`` is the block's credit ledger, when
    the caller wants sweep-produced credits recorded.
    """

    lm: Any
    balances: Dict[str, int]
    sequences: Dict[str, int]
    height: int
    timestamp: int
    # The faucet grant of the network (0 when there is none): handlers use
    # it to read a balance the overlay has no record for, the same way the
    # retractable release does.
    faucet_grant: int = 0
    # The block's credit ledger, when the caller wants sweep-produced
    # credits recorded (the engine passes its ledger); None records nothing.
    credit_records: Optional[Any] = None
    # The block's resolved fee beneficiary (governance beneficiary or
    # proposer), for handlers that charge a fee (standing payments). Empty
    # when the engine did not resolve one; a handler that needs it and
    # finds it empty must leave the item due, never burn the fee.
    fee_beneficiary: str = ""
    # Optional fee measurer for handlers that charge a fee: called as
    # measure_fee(payer_pubkey, payee_pubkey, amount, timestamp) -> int.
    # None means the fee model is inactive and the fee is 0.
    measure_fee: Optional[Any] = None
    # Optional route splitter for handlers that land a routable credit:
    # called as route_split(recipient, amount, credit_class, timestamp)
    # -> (net, routed, destination) or None. None means no route applies.
    route_split: Optional[Any] = None


class SweepHandler(Protocol):
    """A book's sweep interface: report what is due, then execute one item."""

    def collect_due(self, lm: Any, height: int, ts: int) -> Iterable[SweepDue]:
        ...

    def execute(self, item: SweepDue, ctx: SweepContext) -> str:
        ...


@dataclass
class SweepReport:
    """Outcome of one sweep run, in execution order.

    ``deferred`` holds due items the cap left unrun: they stay due in their
    books and the next block collects them again, so overflow carries
    forward in deterministic order without any framework state.
    """

    executed: List[Tuple[SweepDue, str]] = field(default_factory=list)
    failed: List[Tuple[SweepDue, str]] = field(default_factory=list)
    deferred: List[SweepDue] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        return {
            "executed": [
                {"object_id": item.object_id.hex(), "kind": item.kind, "outcome": outcome}
                for item, outcome in self.executed
            ],
            "failed": [
                {"object_id": item.object_id.hex(), "kind": item.kind, "reason": reason}
                for item, reason in self.failed
            ],
            "deferred": [item.object_id.hex() for item in self.deferred],
        }


class SweepRegistry:
    """The set of books whose due items one sweep run executes."""

    def __init__(self) -> None:
        self._handlers: Dict[str, SweepHandler] = {}

    def register(self, kind: str, handler: SweepHandler) -> None:
        if not isinstance(kind, str) or not kind:
            raise ValueError("kind must be a non-empty string")
        if kind in self._handlers:
            raise ValueError(f"sweep handler already registered for kind {kind!r}")
        self._handlers[kind] = handler

    def kinds(self) -> Tuple[str, ...]:
        return tuple(sorted(self._handlers))

    def run(self, ctx: SweepContext, cap: int = MAX_SWEEP_ACTIONS_PER_BLOCK) -> SweepReport:
        """Collect, order and execute due items up to ``cap``.

        Collection is per handler; the merged list is sorted by
        ``(due_ts, object_id)`` so every node runs the same items in the same
        order. An item that raises is recorded as failed and the sweep goes
        on; a failure is never a block failure.
        """
        if not isinstance(cap, int) or isinstance(cap, bool) or cap < 0:
            raise ValueError("cap must be a non-negative integer")
        due: List[SweepDue] = []
        for handler in self._handlers.values():
            due.extend(handler.collect_due(ctx.lm, ctx.height, ctx.timestamp))
        due.sort(key=lambda item: (item.due_ts, item.object_id))
        report = SweepReport()
        for item in due[:cap]:
            handler = self._handlers.get(item.kind)
            if handler is None:
                report.failed.append((item, f"no sweep handler for kind {item.kind!r}"))
                continue
            try:
                report.executed.append((item, handler.execute(item, ctx)))
            except Exception as exc:  # noqa: BLE001 - one item never fails the block
                report.failed.append((item, f"{type(exc).__name__}: {exc}"))
        report.deferred.extend(due[cap:])
        return report


# The registry the engine uses. Book modules register into it at import time;
# Stage 1 registers nothing, so the engine hook below is a no-op for now.
DEFAULT_SWEEP_REGISTRY = SweepRegistry()


def register_handler(kind: str, handler: SweepHandler) -> None:
    """Register a book's sweep handler in the default registry."""
    DEFAULT_SWEEP_REGISTRY.register(kind, handler)


def run_programmable_sweep(
    lm: Any,
    balances: Dict[str, int],
    sequences: Dict[str, int],
    height: int,
    timestamp: int,
    *,
    registry: Optional[SweepRegistry] = None,
    cap: int = MAX_SWEEP_ACTIONS_PER_BLOCK,
    faucet_grant: int = 0,
    credit_records: Optional[Any] = None,
    fee_beneficiary: str = "",
    measure_fee: Optional[Any] = None,
    route_split: Optional[Any] = None,
) -> SweepReport:
    """Engine hook: run the post-transaction programmable sweep for a block.

    Called from ``_apply_block`` right after the retractable release, at the
    same position the design gives the sweep (after the transaction loop,
    before the supply-conservation check). With no registered handlers this
    returns an empty report and touches nothing.
    """
    ctx = SweepContext(
        lm=lm,
        balances=balances,
        sequences=sequences,
        height=int(height),
        timestamp=int(timestamp),
        faucet_grant=faucet_grant,
        credit_records=credit_records,
        fee_beneficiary=fee_beneficiary,
        measure_fee=measure_fee,
        route_split=route_split,
    )
    return (registry or DEFAULT_SWEEP_REGISTRY).run(ctx, cap=cap)
