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

import hashlib
import json
import logging
from dataclasses import dataclass, field
from types import MappingProxyType

import tau_allocator
import tau_journal

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


class PreparedCommitMismatch(RuntimeError):
    """A prepared commit does not describe the thing it is being committed for.

    Fail closed and loudly: the whole value of freezing the artifact is that the
    bytes committed are the bytes some specific worker evaluated, and a mismatch
    means that correspondence has already been broken.
    """


def block_execution_id(*, parent, height, timestamp, proposer, transactions,
                       consensus_context=None) -> str:
    """Identify an EXACT block execution, not merely its parent.

    A prepared commit is only valid for the execution it came from. Keying it on
    the parent alone lets a mined block be rebuilt -- different timestamp, a
    transaction dropped, a different proposer after a role change -- and still
    accept an artifact computed for the previous shape. Every field the evaluator
    could have seen goes into the digest.
    """
    payload = {
        "parent": parent,
        "height": height,
        "timestamp": timestamp,
        "proposer": proposer,
        "transactions": [
            (tx.get("tx_id") or tx.get("tx_hash") or "", tx.get("tx_type") or "user_tx")
            for tx in (transactions or [])
        ],
        "consensus": consensus_context or "",
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


def _allocator_digest(base_digest, delta) -> str:
    """A deterministic name for "this mapping, plus exactly these bindings"."""
    blob = json.dumps({"base": base_digest, "delta": sorted(dict(delta).items())},
                      sort_keys=True, default=str)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class PreparedBlockCommit:
    """Everything the commit consumes, frozen at one instant.

    The failure this shape prevents is subtle and would be very hard to see
    afterwards: validate the proposal worker, then derive the allocator or
    journal delta AGAIN during commitment, and commit something other than what
    that worker evaluated. Deriving twice from a live object is the bug; so the
    artifact is built once, is immutable, and the coordinator consumes exactly
    it.

    `worker` is the one field that is not data. It is the identity of the
    evaluator that produced all of the above, and promotion transfers ownership
    of that exact object rather than replaying to build an equivalent one.
    """

    parent_tip_id: str | None
    execution_id: str
    next_snapshot: object

    journal_base_head: str | None
    journal_delta: tuple = ()
    journal_final_head: str | None = None

    allocator_base_digest: str | None = None
    allocator_delta: tuple = ()
    allocator_final_digest: str | None = None

    representation_plan_id: str | None = None

    worker: object = None
    worker_session_revision: int | None = None
    proposal_time_point: int | None = None
    proposal_spec_revision: int | None = None

    canonical: MappingProxyType = field(default_factory=lambda: MappingProxyType({}))
    lifecycle: object = None
    native_build_id: str | None = None

    # --- construction ---------------------------------------------------------

    @classmethod
    def freeze(cls, proposal, *, execution_id, next_snapshot, parent_tip_id=None,
               journal_base_head=None, store=None):
        """Take ONE reading of the proposal and never take another.

        Refuses a proposal that is not in a committable condition rather than
        freezing an artifact whose worker does not correspond to it.
        """
        import db as _db
        import tau_reconstruction

        store = store or _db
        if getattr(proposal, "poisoned", None):
            raise PreparedCommitMismatch(
                f"the proposal is poisoned: {proposal.poisoned}"
            )
        if getattr(proposal, "dirty", False):
            raise PreparedCommitMismatch(
                "the proposal owes a reconstruction: a rejected transaction "
                "stepped the evaluator and the worker no longer corresponds to "
                "the accepted journal"
            )
        session = proposal.session
        if session is None:
            raise PreparedCommitMismatch("the proposal has no evaluator")

        entries = tuple(proposal.journal.entries())
        delta = dict(proposal.allocator.delta())
        base_digest = getattr(proposal.allocator, "epoch", None)
        state = _worker_state(session)

        return cls(
            parent_tip_id=parent_tip_id,
            execution_id=execution_id,
            next_snapshot=next_snapshot,
            journal_base_head=journal_base_head,
            journal_delta=entries,
            journal_final_head=entries[-1].link if entries else journal_base_head,
            allocator_base_digest=base_digest,
            allocator_delta=tuple(sorted(delta.items())),
            allocator_final_digest=_allocator_digest(base_digest, delta),
            representation_plan_id=(proposal.plan.plan_id
                                    if proposal.plan is not None else None),
            worker=session,
            worker_session_revision=state.get("session_revision"),
            proposal_time_point=state.get("time_point"),
            proposal_spec_revision=state.get("spec_revision"),
            canonical=MappingProxyType(dict(proposal.state)),
            lifecycle=proposal.lifecycle,
            native_build_id=tau_reconstruction.native_build_id(),
        )

    # --- the pre-commit gate --------------------------------------------------

    def verify(self, *, proposal=None, execution_id=None, store=None) -> None:
        """Check every anchor together, immediately before the irreversible step.

        Deliberately one method rather than checks scattered through `commit`:
        the anchors are only meaningful as a set, and a partial check is how a
        proposal that agrees about its parent and disagrees about its mapping
        gets published.
        """
        import db as _db

        store = store or _db
        problems = []

        if execution_id is not None and execution_id != self.execution_id:
            problems.append(
                f"prepared for execution {self.execution_id}, asked to commit "
                f"{execution_id}"
            )

        tip = _current_tip(store)
        if self.parent_tip_id is not None and tip is not None and tip != self.parent_tip_id:
            problems.append(f"committed tip moved: {self.parent_tip_id} -> {tip}")

        epoch = store.shrink_mapping_epoch()
        if self.allocator_base_digest is not None and epoch != self.allocator_base_digest:
            problems.append(
                f"allocator base moved: {self.allocator_base_digest} -> {epoch}"
            )

        if proposal is not None:
            if getattr(proposal, "poisoned", None):
                problems.append(f"the proposal is poisoned: {proposal.poisoned}")
            if getattr(proposal, "dirty", False):
                problems.append("the proposal owes a reconstruction")
            if proposal.session is not self.worker:
                problems.append(
                    "the proposal's evaluator is not the one this commit was "
                    "prepared from"
                )
            live_entries = proposal.journal.entries()
            live_head = live_entries[-1].link if live_entries else self.journal_base_head
            if live_head != self.journal_final_head:
                problems.append(
                    f"journal head moved since freezing: {self.journal_final_head} "
                    f"-> {live_head}"
                )
            live_delta = tuple(sorted(dict(proposal.allocator.delta()).items()))
            if live_delta != self.allocator_delta:
                problems.append("the allocator delta moved since freezing")
            plan_id = proposal.plan.plan_id if proposal.plan is not None else None
            if plan_id != self.representation_plan_id:
                problems.append(
                    f"representation plan moved: {self.representation_plan_id} "
                    f"-> {plan_id}"
                )

        if self.worker is not None:
            state = _worker_state(self.worker)
            for name, mine in (("spec_revision", self.proposal_spec_revision),
                               ("time_point", self.proposal_time_point)):
                theirs = state.get(name)
                if mine is not None and theirs is not None and mine != theirs:
                    problems.append(
                        f"the worker advanced since freezing: {name} {mine} -> {theirs}"
                    )

        # The journal's own structure, not just its head: a swapped or altered
        # entry that happens to end at the same link would otherwise pass.
        try:
            tau_journal.verify_entries(self.journal_delta)
        except Exception as exc:
            problems.append(f"journal chain: {exc}")

        if problems:
            raise PreparedCommitMismatch("; ".join(problems))

    # --- reading --------------------------------------------------------------

    @property
    def allocation(self) -> dict:
        return dict(self.allocator_delta)

    def summary(self) -> dict:
        return {
            "execution_id": self.execution_id,
            "parent": self.parent_tip_id,
            "journal": f"{self.journal_base_head} -> {self.journal_final_head}",
            "journal_entries": len(self.journal_delta),
            "allocator": f"{self.allocator_base_digest} -> {self.allocator_final_digest}",
            "allocation_delta": len(self.allocator_delta),
            "plan": self.representation_plan_id,
            "spec_revision": self.proposal_spec_revision,
            "time_point": self.proposal_time_point,
        }


def _worker_state(session) -> dict:
    """The evaluator's own counters, or an empty reading if it cannot answer.

    Empty rather than raising: a worker that has died is a real condition the
    gate should report as a mismatch, not an exception from a helper.
    """
    spec = getattr(session, "_spec", None)
    if spec is None or not hasattr(spec, "state"):
        return {}
    try:
        state = dict(spec.state() or {})
    except Exception:
        return {}
    if "session_revision" not in state:
        state["session_revision"] = getattr(spec, "state_revision", None)
    return state


def _current_tip(store):
    for name in ("current_tip", "get_canonical_head_hash"):
        fn = getattr(store, name, None)
        if fn is None:
            continue
        try:
            return fn()
        except Exception:
            return None
    return None


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
