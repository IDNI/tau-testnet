"""One proposal, one ownership boundary.

Everything a candidate block does lives here until the block commits: the
evaluator, the journal branch, the allocation overlay and the canonical deltas.
Rejection is disposal and replay, never attempted rollback -- the engine commits a
stream's width on the first accepted revision and offers no way back.

The unit is the BRANCH, not the individual record. A transaction's journal child,
allocator child and state delta merge together or not at all: merging one and
failing on another leaves the proposal internally inconsistent even though
nothing reached canonical state, and an inconsistent proposal is exactly the
thing nobody can reason about afterwards.

Two facts drive the reconstruction rule:

* `spec_revision` unchanged does NOT mean the evaluator is unchanged. An accepted
  no-op advances execution, and so does an ordinary input step. So the question
  is not "did the spec change" but "did this rejected transaction cause any
  authoritative-semantic step at all".
* There is no in-process undo. If it did, the evaluator is rebuilt from the
  ACCEPTED proposal journal, which by construction never contained the rejected
  transaction.
"""
from __future__ import annotations

import contextlib
import copy
import logging

import tau_journal
import tau_reconstruction

logger = logging.getLogger(__name__)

MAX_REPRESENTATION_RETRIES = 3


@contextlib.contextmanager
def boundary(proposal=None, *, label="proposal"):
    """The ONE deliberate terminal catch for an isolation breach.

    `GlobalStateLeak` is a BaseException so that no broad `except Exception`
    inside transaction logic can absorb it and report a valid transaction as
    invalid. That property must stop at the boundary that owns the proposal:
    left unbounded it behaves like KeyboardInterrupt, unwinding the node over a
    node-local integration failure.

    So every owner of a proposal wraps its execution in this, and the leak
    becomes a typed operational error -- after the caller's own cleanup has run,
    since a `finally` inside the wrapped block completes before the exception
    reaches here.
    """
    import tau_guard
    from errors import ProposalIsolationFailure

    try:
        yield
    except tau_guard.GlobalStateLeak as leak:
        if proposal is not None and not getattr(proposal, "poisoned", None):
            proposal.poison(f"isolation breach: {leak}")
        logger.error("%s: isolation breach, abandoning the proposal: %s", label, leak)
        raise ProposalIsolationFailure(str(leak)) from None


class ProposalPoisoned(RuntimeError):
    """The proposal's own bookkeeping became inconsistent.

    Operational and terminal for this proposal: discard it and rebuild from the
    committed anchor. Never a verdict about a transaction.
    """


class TxBranch:
    """A transaction's private deltas, committed together or discarded whole."""

    def __init__(self, proposal: "ProposalContext", tx_id: str):
        self.proposal = proposal
        self.tx_id = tx_id
        self.journal = proposal.journal.child(tx_id)
        self.allocation = proposal.allocator.child(tx_id)
        # The branch points the session at its own children, and points it back on
        # resolve. Leaving that to the caller means the session keeps writing into
        # a child that was merged or discarded -- a discarded allocator refuses,
        # which surfaces as a confusing intern failure somewhere unrelated.
        self._bind()
        self.state_delta: dict = {}
        self._lifecycle = None
        self._lifecycle_parent = None
        self.resolved = False
        self.accepted = False

    # --- lifecycle ------------------------------------------------------------

    @property
    def lifecycle(self):
        """This transaction's private lifecycle state, cloned on first use.

        Replacement, not undo. The registered-clause registry, the approval book
        and the offer book are mutated in place by the paths that own them --
        `resolve_all_for_sender` marks requests failed, `accepted_clauses[key]`
        is overwritten -- and there is no inverse for any of it that survives
        contact with the next change. So the transaction gets its own copy and
        the proposal keeps the parent until the transaction is accepted.

        Cloned lazily because most transactions never touch lifecycle state and
        a deepcopy per transfer would be paid for nothing.
        """
        if self._lifecycle is None:
            # The parent is captured HERE, by identity. Adoption later checks
            # that the proposal still holds this exact object: a clone taken
            # from one lifecycle and adopted into another would write a history
            # that never happened, and a type check cannot see that.
            self._lifecycle_parent = self.proposal.lifecycle
            self._lifecycle = copy.deepcopy(self._lifecycle_parent)
        return self._lifecycle

    @property
    def touched_lifecycle(self) -> bool:
        return self._lifecycle is not None

    def _adopt_lifecycle(self) -> None:
        """Make the child's state the proposal's, in one rebind.

        The contents are replaced wholesale; object IDENTITY is preserved on
        purpose. The block builder holds this same manager and hashes it after
        apply returns, so handing the proposal a different object would leave the
        caller hashing the parent -- accepted lifecycle changes silently missing
        from the consensus state hash.
        """
        child = self._lifecycle
        if child is None:
            return
        parent = self.proposal.lifecycle
        if parent is None:
            self.proposal.lifecycle = child
            return
        if parent is not self._lifecycle_parent:
            raise ProposalPoisoned(
                f"{self.tx_id}: the proposal's lifecycle was replaced while this "
                "transaction held a clone of the previous one"
            )
        try:
            parent.__dict__ = dict(child.__dict__)
        except (AttributeError, TypeError):
            # __slots__ or a type that refuses the rebind. Identity is worth
            # keeping but not at the price of a half-adopted object.
            self.proposal.lifecycle = child

    def _bind(self) -> None:
        session = getattr(self.proposal, "session", None)
        if session is not None:
            session.allocation = self.allocation
            session.journal = self.journal

    def _unbind(self) -> None:
        session = getattr(self.proposal, "session", None)
        if session is not None:
            session.allocation = self.proposal.allocator
            session.journal = self.proposal.journal

    # --- evaluator effects ----------------------------------------------------

    @property
    def touched_evaluator(self) -> bool:
        """Whether this branch caused ANY authoritative-semantic step.

        Not `spec_revision`: an accepted no-op leaves it unchanged and still
        advances execution, and so does an ordinary input step.
        """
        return len(self.journal) > 0

    # --- resolution -----------------------------------------------------------

    def accept(self) -> None:
        if self.resolved:
            raise ProposalPoisoned(f"transaction {self.tx_id} was already resolved")
        # Validate BOTH children before mutating either: a half-applied merge
        # leaves the proposal describing a history that never happened.
        for child, parent in ((self.journal, self.proposal.journal),
                              (self.allocation, self.proposal.allocator)):
            if getattr(child, "_parent", None) is not parent:
                raise ProposalPoisoned(f"{self.tx_id}: child belongs to another parent")
            if getattr(child, "_discarded", False):
                raise ProposalPoisoned(f"{self.tx_id}: child was already discarded")
        try:
            self.proposal.journal.merge(self.journal)
            self.proposal.allocator.merge(self.allocation)
        except Exception as exc:
            self.proposal.poison(f"{self.tx_id}: partial merge ({exc})")
            raise
        self.proposal.state.update(self.state_delta)
        self._adopt_lifecycle()
        self.resolved = True
        self.accepted = True
        self._unbind()

    def reject(self, reason: str = "") -> None:
        if self.resolved:
            raise ProposalPoisoned(f"transaction {self.tx_id} was already resolved")
        self.proposal.journal.discard(self.journal)
        self.proposal.allocator.discard(self.allocation)
        self.state_delta.clear()
        # Dropped, never unwound: the parent was never mutated.
        self._lifecycle = None
        self._lifecycle_parent = None
        self.resolved = True
        self.accepted = False
        self._unbind()
        if self.touched_evaluator:
            # It ran. There is no undo, so the evaluator no longer corresponds to
            # the accepted history and has to be rebuilt from it.
            self.proposal.mark_dirty(f"{self.tx_id} rejected after stepping the evaluator")
        logger.info("proposal %s: rejected %s (%s)", self.proposal.label,
                    self.tx_id, reason or "no reason given")

    # --- context manager ------------------------------------------------------

    def __enter__(self) -> "TxBranch":
        return self

    def __exit__(self, exc_type, exc, tb):
        if not self.resolved:
            # An exception mid-transaction is a rejection: nothing half-applied.
            self.reject(f"unresolved ({exc_type.__name__})" if exc_type else "unresolved")
        return False


class ProposalContext:
    """The owner of everything a candidate block touches before it commits."""

    def __init__(self, *, session, journal, allocator, plan, descriptor=None,
                 rebuild=None, lifecycle=None, label="proposal"):
        self.session = session
        self.journal = journal
        self.allocator = allocator
        self.plan = plan
        self.descriptor = descriptor
        self.label = label
        self.state: dict = {}
        # Point the session at THIS proposal's journal and allocation overlay.
        # Without it a session created by `begin_proposal` keeps the private
        # journal that call gave it, and anything recorded outside a transaction
        # branch -- block-level governance activation, most importantly -- lands
        # in a journal nobody reads. A reconstruction from `self.journal` would
        # then come back missing the activated consensus rule.
        self._bind_session()
        # The proposal's lifecycle manager: clause registry, approval book, offer
        # book, governance queues. Owned like every other proposal state -- a
        # transaction mutates a clone and the proposal adopts it on acceptance.
        self.lifecycle = lifecycle
        self._rebuild = rebuild
        self._dirty = False
        self._poisoned = None
        self._retries = 0

    def _bind_session(self) -> None:
        if self.session is None:
            return
        if hasattr(self.session, "journal"):
            self.session.journal = self.journal
        if hasattr(self.session, "allocation"):
            self.session.allocation = self.allocator

    # --- health ---------------------------------------------------------------

    @property
    def dirty(self) -> bool:
        return self._dirty

    @property
    def poisoned(self):
        return self._poisoned

    def poison(self, reason: str) -> None:
        self._poisoned = reason
        logger.error("proposal %s poisoned: %s", self.label, reason)

    def mark_dirty(self, reason: str) -> None:
        self._dirty = True
        logger.info("proposal %s needs reconstruction: %s", self.label, reason)

    def _check_usable(self) -> None:
        if self._poisoned:
            raise ProposalPoisoned(self._poisoned)

    # --- transactions ---------------------------------------------------------

    def transaction(self, tx_id: str) -> TxBranch:
        self._check_usable()
        if self._dirty:
            self.reconstruct()
        return TxBranch(self, tx_id)

    # --- reconstruction -------------------------------------------------------

    def reconstruct(self) -> None:
        """Rebuild the evaluator from the ACCEPTED proposal journal.

        By construction that journal never contained a rejected transaction, so
        there is nothing to filter out -- which is the whole reason the branch is
        the unit rather than the record.
        """
        self._check_usable()
        if self._rebuild is None:
            raise ProposalPoisoned("no reconstruction available for this proposal")
        try:
            old = self.session
            self.session = self._rebuild(self.journal, self.plan)
            if old is not None and old is not self.session:
                try:
                    old.dispose()
                except Exception:
                    pass
        except tau_reconstruction.ReconstructionMismatch:
            # The anchors disagree. That is not a transaction verdict and not a
            # thing to continue past.
            self.poison("reconstruction mismatch")
            raise
        except Exception as exc:
            self.poison(f"reconstruction failed: {exc}")
            raise
        # The replacement session is a different object, so it needs the same
        # binding the original got. Missing it is silent: everything works until
        # the NEXT reconstruction, which replays a journal with a hole in it.
        self._bind_session()
        self._dirty = False

    def replan(self, required_plain) -> None:
        """Extend the representation and rebuild, keeping the accepted prefix.

        A rule discovered DURING apply -- a regenerated composite, an accepted
        offer, an activated governance revision -- can need a representation the
        current worker cannot express. That is not a transaction rejection: the
        accepted journal and allocation plan are retained, the plan is widened,
        and the accepted prefix is replayed.
        """
        self._check_usable()
        self._retries += 1
        if self._retries > MAX_REPRESENTATION_RETRIES:
            raise ProposalPoisoned(
                f"representation still conflicting after {self._retries} attempts"
            )
        before = self.plan.plan_id
        self.plan = tau_reconstruction.RepresentationPlan(
            width=self.plan.width,
            interned=frozenset(self.plan.interned) - frozenset(required_plain),
            plain=frozenset(self.plan.plain) | frozenset(required_plain),
        )
        if self.plan.plan_id == before:
            raise ProposalPoisoned("representation retry made no progress")
        self.mark_dirty("representation plan widened")
        self.reconstruct()

    # --- outcome --------------------------------------------------------------

    def summary(self) -> dict:
        entries = self.journal.entries()
        return {
            "label": self.label,
            "journal_entries": len(entries),
            "journal_head": entries[-1].link if entries else None,
            "allocation_delta": dict(self.allocator.delta()),
            "state": dict(self.state),
            "plan_id": self.plan.plan_id if self.plan else None,
            "dirty": self._dirty,
            "poisoned": self._poisoned,
        }

    def dispose(self) -> None:
        if self.session is not None:
            try:
                self.session.dispose()
            except Exception:
                pass
            self.session = None
