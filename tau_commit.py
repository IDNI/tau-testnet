"""The commit owner (M4/C4): one place that decides a block is durable.

The distinction this exists to make: an UNCOMMITTED proposal and a COMMITTED block
whose evaluator is not available are different situations. Discarding the first is
correct; reporting the second as rejected or abandoned is a lie that lets a caller
retry a transition that already happened.

    PREPARING -> PREPARED -> DURABLY_COMMITTED -> ACTIVE
                                   \\-> COMMITTED_BUT_UNAVAILABLE

    before DURABLY_COMMITTED:  discard the proposal and its private state
    after  DURABLY_COMMITTED:  recover from the committed state; never "rejected"

Canonical state and the allocation delta go down together: they live in one
SQLite file behind one connection, so a single transaction is available and is
what this uses. "Readiness" is published only after the evaluator is actually
serving the committed state.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

import tau_allocator

logger = logging.getLogger(__name__)

PREPARING = "PREPARING"
PREPARED = "PREPARED"
DURABLY_COMMITTED = "DURABLY_COMMITTED"
ACTIVE = "ACTIVE"
COMMITTED_BUT_UNAVAILABLE = "COMMITTED_BUT_UNAVAILABLE"
ABANDONED = "ABANDONED"

_TERMINAL = (ACTIVE, COMMITTED_BUT_UNAVAILABLE, ABANDONED)


class CommitStateError(RuntimeError):
    """An illegal transition -- most importantly, trying to abandon or retry a
    block that is already durable."""


class StaleProposal(RuntimeError):
    """The parent or the mapping epoch moved. Operational: retry against the new
    tip. NOT a verdict about any transaction in the proposal."""


@dataclass
class BlockProposal:
    """Block-local working state. Nothing here is visible to anyone else."""

    parent: str
    canonical: dict = field(default_factory=dict)
    allocator: "tau_allocator.Allocator | None" = None
    accepted: list = field(default_factory=list)
    receipts: dict = field(default_factory=dict)

    def accept(self, tx_id: str, delta: dict, receipt=None) -> None:
        self.canonical.update(delta)
        self.accepted.append(tx_id)
        if receipt is not None:
            self.receipts[tx_id] = receipt


class BlockCommitCoordinator:
    """Owns block-local state, the authoritative evaluator, and commit ordering."""

    def __init__(self, store, *, evaluator=None, commit_id=None):
        self._store = store
        self._evaluator = evaluator
        self.state = PREPARING
        self.commit_id = commit_id
        self.proposal: BlockProposal | None = None
        self._replacement = None
        self._result = None

    # --- proposal -------------------------------------------------------------

    def open(self, parent: str, allocator=None) -> BlockProposal:
        if self.state != PREPARING:
            raise CommitStateError(f"cannot open a proposal in {self.state}")
        self.proposal = BlockProposal(parent=parent, allocator=allocator)
        return self.proposal

    def prepare(self) -> None:
        """Validate the parent and epoch, and build the replacement evaluator
        BEFORE anything is durable, so a reconstruction failure surfaces while the
        proposal can still be discarded."""
        if self.state != PREPARING or self.proposal is None:
            raise CommitStateError(f"cannot prepare in {self.state}")
        self._check_not_stale()
        if self._evaluator is not None:
            self._replacement = self._evaluator.prepare_replacement(
                self.proposal.canonical
            )
        self.state = PREPARED

    def _check_not_stale(self) -> None:
        tip = self._store.current_tip()
        if tip != self.proposal.parent:
            raise StaleProposal(
                f"parent moved: proposal built on {self.proposal.parent!r}, tip is {tip!r}"
            )
        if self.proposal.allocator is not None:
            epoch, _ = self._store.snapshot_mapping()
            if epoch != self.proposal.allocator.epoch:
                raise StaleProposal(
                    f"mapping epoch moved {self.proposal.allocator.epoch} -> {epoch}"
                )

    def abandon(self, reason: str = "") -> None:
        """Discard an UNCOMMITTED proposal, including transactions that individually
        succeeded. Refused once the block is durable -- that is the whole point of
        the state machine."""
        if self.state in (DURABLY_COMMITTED, ACTIVE, COMMITTED_BUT_UNAVAILABLE):
            raise CommitStateError(
                f"cannot abandon a block that is already {self.state}"
            )
        if self.proposal is not None and self.proposal.allocator is not None:
            self.proposal.allocator._discarded = True
        self.proposal = None
        self._replacement = None
        self.state = ABANDONED
        logger.info("block proposal abandoned: %s", reason or "no reason given")

    # --- commit ---------------------------------------------------------------

    def commit(self, tip: str) -> dict:
        """Persist, then activate, then publish readiness.

        Returns the commit result. Once this returns DURABLY_COMMITTED or later,
        the block HAPPENED, whatever the evaluator does next.
        """
        if self.state in _TERMINAL and self._result is not None:
            # A retried request for a transition that already completed must be a
            # no-op, not a second application of fees or lifecycle changes.
            logger.info("commit %s already completed; returning the first result",
                        self.commit_id)
            return self._result
        if self.state != PREPARED or self.proposal is None:
            raise CommitStateError(f"cannot commit in {self.state}")

        self._check_not_stale()
        delta = (self.proposal.allocator.delta()
                 if self.proposal.allocator is not None else {})

        try:
            self._store.commit_block(
                tip=tip,
                parent=self.proposal.parent,
                canonical=dict(self.proposal.canonical),
                allocation_delta=delta,
                expected_epoch=(self.proposal.allocator.epoch
                                if self.proposal.allocator is not None else None),
            )
        except tau_allocator.AllocatorConflict as exc:
            raise StaleProposal(str(exc)) from exc

        # Past this line the block exists. Nothing below may report it as rejected.
        self.state = DURABLY_COMMITTED
        self._result = {"state": DURABLY_COMMITTED, "tip": tip,
                        "accepted": list(self.proposal.accepted),
                        "allocation_delta": delta}

        try:
            if self._evaluator is not None:
                self._evaluator.activate(self._replacement)
            self.state = ACTIVE
            self._result["state"] = ACTIVE
        except Exception as exc:
            self.state = COMMITTED_BUT_UNAVAILABLE
            self._result["state"] = COMMITTED_BUT_UNAVAILABLE
            self._result["unavailable_reason"] = repr(exc)
            logger.error(
                "block %s is durably committed but its evaluator is unavailable: %s",
                tip, exc,
            )
        return self._result

    # --- readiness ------------------------------------------------------------

    @property
    def ready(self) -> bool:
        """Readiness is about SERVING, not about having committed."""
        return self.state == ACTIVE

    @property
    def committed(self) -> bool:
        return self.state in (DURABLY_COMMITTED, ACTIVE, COMMITTED_BUT_UNAVAILABLE)

    def recover(self) -> dict:
        """Reconstruct the evaluator from the COMMITTED state -- never from
        whichever worker happened to finish last."""
        if not self.committed:
            raise CommitStateError(f"nothing to recover from in {self.state}")
        canonical = self._store.committed_canonical()
        replacement = self._evaluator.prepare_replacement(canonical)
        self._evaluator.activate(replacement)
        self.state = ACTIVE
        if self._result is not None:
            self._result["state"] = ACTIVE
            self._result.pop("unavailable_reason", None)
        return {"state": ACTIVE, "recovered_from": "committed canonical state"}
