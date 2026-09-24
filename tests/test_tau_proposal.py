"""The transaction branch is the unit: all three deltas, or none.

Merging a journal child and then failing on the allocator child leaves the
proposal describing a history that never happened -- nothing has reached
canonical state, and the proposal is still unusable.
"""
import pytest

import tau_allocator as alloc
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr


class _FakeSession:
    def __init__(self, name="w0"):
        self.name = name
        self.disposed = False

    def dispose(self):
        self.disposed = True


class _FakeStore:
    def __init__(self):
        self.committed = {}
        self.epoch = "0:empty"

    def snapshot_mapping(self):
        return self.epoch, dict(self.committed)


def _context(rebuild=None):
    snapshot = alloc.MappingSnapshot(epoch="e0", committed={})
    plan = tr.RepresentationPlan(width=8, interned=frozenset({12}), plain=frozenset())
    return tp.ProposalContext(
        session=_FakeSession(),
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=8, label="proposal"),
        plan=plan,
        rebuild=rebuild,
    )


# --- atomicity ----------------------------------------------------------------

def test_an_accepted_branch_merges_all_three_deltas():
    ctx = _context()
    with ctx.transaction("A") as tx:
        tx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="A")
        tx.allocation.id_for("bv384:alice")
        tx.state_delta["balance:alice"] = 10
        tx.accept()
    assert len(ctx.journal) == 1
    assert ctx.allocator.delta() == {"bv384:alice": 1}
    assert ctx.state == {"balance:alice": 10}


def test_a_rejected_branch_merges_none_of_them():
    ctx = _context(rebuild=lambda j, p: _FakeSession("rebuilt"))
    with ctx.transaction("B") as tx:
        tx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="B")
        tx.allocation.id_for("bv384:bob")
        tx.state_delta["balance:bob"] = 99
        tx.reject("fee")
    assert len(ctx.journal) == 0
    assert ctx.allocator.delta() == {}
    assert ctx.state == {}


def test_an_unresolved_branch_is_rejected_on_exit():
    """An exception mid-transaction must not leave half of it applied."""
    ctx = _context(rebuild=lambda j, p: _FakeSession())
    with pytest.raises(RuntimeError):
        with ctx.transaction("C") as tx:
            tx.journal.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "5"})
            raise RuntimeError("boom")
    assert len(ctx.journal) == 0
    assert ctx.allocator.delta() == {}


def test_a_partial_merge_poisons_the_proposal():
    """Nothing reached canonical state, but the proposal now describes a history
    that never happened, so it must not be reasoned about further."""
    ctx = _context()
    tx = ctx.transaction("A")
    tx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="A")
    tx.allocation.id_for("bv384:alice")

    def explode(_child):
        raise RuntimeError("allocator merge failed")

    ctx.allocator.merge = explode
    with pytest.raises(RuntimeError):
        tx.accept()
    assert ctx.poisoned
    with pytest.raises(tp.ProposalPoisoned):
        ctx.transaction("B")


def test_a_branch_cannot_be_resolved_twice():
    ctx = _context()
    tx = ctx.transaction("A")
    tx.accept()
    with pytest.raises(tp.ProposalPoisoned):
        tx.accept()
    with pytest.raises(tp.ProposalPoisoned):
        tx.reject()


# --- reconstruction on a dirty rejection --------------------------------------

def test_rejecting_after_any_step_marks_the_proposal_dirty():
    """`spec_revision` unchanged does not mean the evaluator is unchanged: an
    accepted no-op advances execution, and so does an ordinary input step."""
    ctx = _context(rebuild=lambda j, p: _FakeSession("rebuilt"))
    with ctx.transaction("B") as tx:
        tx.journal.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "5"})
        tx.reject("fee")
    assert ctx.dirty


def test_rejecting_without_touching_the_evaluator_needs_no_rebuild():
    ctx = _context(rebuild=lambda j, p: _FakeSession("rebuilt"))
    with ctx.transaction("B") as tx:
        tx.reject("bad signature")           # rejected before any Tau work
    assert not ctx.dirty


def test_the_next_transaction_reconstructs_from_the_accepted_journal():
    rebuilt_from = {}

    def rebuild(journal, plan):
        rebuilt_from["entries"] = [e.rule_text for e in journal.entries()]
        return _FakeSession("rebuilt")

    ctx = _context(rebuild=rebuild)
    with ctx.transaction("A") as tx:
        tx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="A")
        tx.accept()
    with ctx.transaction("B") as tx:
        tx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="B")
        tx.reject("fee")
    old = ctx.session
    ctx.transaction("C")
    assert rebuilt_from["entries"] == ["A"], "B must not be in the rebuild source"
    assert not ctx.dirty
    assert old.disposed, "the contaminated worker was not disposed"


def test_a_reconstruction_mismatch_poisons_rather_than_continues():
    """The anchors disagree. That is not a transaction verdict, and not something
    to continue past."""
    def rebuild(journal, plan):
        raise tr.ReconstructionMismatch("journal references an unknown value")

    ctx = _context(rebuild=rebuild)
    with ctx.transaction("B") as tx:
        tx.journal.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "5"})
        tx.reject("fee")
    with pytest.raises(tr.ReconstructionMismatch):
        ctx.transaction("C")
    assert ctx.poisoned


# --- representation conflict discovered during apply --------------------------

def test_a_representation_conflict_replans_rather_than_rejecting():
    """A rule discovered DURING apply -- a regenerated composite, an accepted
    offer, an activated revision -- can need a representation the current worker
    cannot express. That is not a transaction rejection."""
    rebuilds = []
    ctx = _context(rebuild=lambda j, p: rebuilds.append(p) or _FakeSession())
    with ctx.transaction("A") as tx:
        tx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="A")
        tx.accept()
    before = ctx.plan.plan_id
    ctx.replan({12})
    assert ctx.plan.plan_id != before
    assert 12 in ctx.plan.plain and 12 not in ctx.plan.interned
    assert rebuilds, "the worker was not rebuilt under the new plan"
    assert len(ctx.journal) == 1, "the accepted prefix was retained"


def test_replanning_is_bounded_and_must_make_progress():
    ctx = _context(rebuild=lambda j, p: _FakeSession())
    ctx.replan({12})
    with pytest.raises(tp.ProposalPoisoned):
        ctx.replan({12})          # same plan again: no progress


def test_replanning_gives_up_rather_than_looping():
    ctx = _context(rebuild=lambda j, p: _FakeSession())
    with pytest.raises(tp.ProposalPoisoned):
        for stream in (12, 3, 4, 18, 19):
            ctx.replan({stream})
