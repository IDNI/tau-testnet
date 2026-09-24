"""The frozen commit artifact and the gate in front of the irreversible step.

The failure this shape exists to prevent is hard to see afterwards: validate the
proposal worker, then derive the allocator or journal delta AGAIN during
commitment, and commit something other than what that worker evaluated. Deriving
twice from a live object IS the bug, so the artifact is taken once and the
coordinator consumes exactly it.
"""
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import tau_allocator as alloc
import tau_commit as tc
import tau_journal as tj
import tau_reconstruction as tr


class _Spec:
    def __init__(self, spec_revision=2, time_point=7, state_revision=3):
        self._state = {"spec_revision": spec_revision, "time_point": time_point}
        self.state_revision = state_revision

    def state(self):
        return dict(self._state)

    def advance(self):
        self._state["spec_revision"] += 1


def _proposal(temp_database, *, entries=2, allocate=("k1", "k2")):
    import tau_proposal as tp

    plan = tr.plan_representation(candidate_rules=[])
    snapshot = alloc.DbMappingSnapshot()
    session = SimpleNamespace(_spec=_Spec(), journal=None, allocation=None,
                              dispose=lambda: None)
    ctx = tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan,
    )
    for i in range(entries):
        ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE,
                           rule_text=f"always ( o5[t]:bv[24] = {{ #x00000{i} }}:bv[24] ).")
    for key in allocate:
        ctx.allocator.id_for(key)
    ctx.state["application_rules"] = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
    return ctx


def _freeze(ctx, **kw):
    kw.setdefault("execution_id", "exec-1")
    kw.setdefault("next_snapshot", object())
    return tc.PreparedBlockCommit.freeze(ctx, **kw)


# --- the execution identity ---------------------------------------------------

def _exec(**kw):
    base = dict(parent="p0", height=5, timestamp=1700000000, proposer="d4" * 48,
                transactions=[{"tx_id": "A"}, {"tx_id": "B"}])
    base.update(kw)
    return tc.block_execution_id(**base)


def test_the_execution_id_covers_every_evaluator_relevant_field():
    """Keying on the parent alone lets a mined block be rebuilt -- different
    timestamp, a transaction dropped, a different proposer -- and still accept an
    artifact computed for the previous shape."""
    base = _exec()
    assert _exec() == base, "the digest is not deterministic"
    assert _exec(height=6) != base
    assert _exec(timestamp=1700000001) != base
    assert _exec(proposer="ee" * 48) != base
    assert _exec(parent="p1") != base
    assert _exec(transactions=[{"tx_id": "A"}]) != base, "a dropped transaction"
    assert _exec(transactions=[{"tx_id": "B"}, {"tx_id": "A"}]) != base, "reordered"
    assert _exec(consensus_context="v2") != base


# --- freezing -----------------------------------------------------------------

def test_freezing_takes_one_reading(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)

    assert len(frozen.journal_delta) == 2
    assert frozen.journal_final_head == ctx.journal.entries()[-1].link
    assert dict(frozen.allocator_delta) == dict(ctx.allocator.delta())
    assert frozen.proposal_spec_revision == 2
    assert frozen.proposal_time_point == 7
    assert frozen.worker is ctx.session
    assert frozen.representation_plan_id == ctx.plan.plan_id


def test_the_artifact_does_not_track_the_proposal(temp_database):
    """The whole point. A live object consulted twice can answer differently the
    second time, and the second answer is the one that gets committed."""
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    before_journal = len(frozen.journal_delta)
    before_alloc = dict(frozen.allocator_delta)

    ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="later")
    ctx.allocator.id_for("k-later")
    ctx.state["application_rules"] = "something else"

    assert len(frozen.journal_delta) == before_journal
    assert dict(frozen.allocator_delta) == before_alloc
    assert frozen.canonical["application_rules"] != "something else"
    with pytest.raises(TypeError):
        frozen.canonical["application_rules"] = "x"


def test_a_dirty_proposal_cannot_be_frozen(temp_database):
    ctx = _proposal(temp_database)
    ctx.mark_dirty("a rejection stepped the evaluator")
    with pytest.raises(tc.PreparedCommitMismatch, match="reconstruction"):
        _freeze(ctx)


def test_a_poisoned_proposal_cannot_be_frozen(temp_database):
    ctx = _proposal(temp_database)
    ctx.poison("isolation breach")
    with pytest.raises(tc.PreparedCommitMismatch, match="poisoned"):
        _freeze(ctx)


# --- the gate -----------------------------------------------------------------

def test_a_clean_artifact_passes_the_gate(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    frozen.verify(proposal=ctx, execution_id="exec-1")


def test_the_gate_refuses_a_different_execution(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    with pytest.raises(tc.PreparedCommitMismatch, match="execution"):
        frozen.verify(proposal=ctx, execution_id="exec-2")


def test_the_gate_refuses_a_moved_journal_head(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="later")
    with pytest.raises(tc.PreparedCommitMismatch, match="journal head moved"):
        frozen.verify(proposal=ctx)


def test_the_gate_refuses_a_moved_allocator_delta(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    ctx.allocator.id_for("k-later")
    with pytest.raises(tc.PreparedCommitMismatch, match="allocator delta moved"):
        frozen.verify(proposal=ctx)


def test_the_gate_refuses_a_moved_allocator_base(temp_database):
    """An externally advanced mapping epoch makes the attempt stale."""
    import db

    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    db.publish_shrink_ids({"someone-else": 900}, db.shrink_mapping_epoch())
    with pytest.raises(tc.PreparedCommitMismatch, match="allocator base moved"):
        frozen.verify(proposal=ctx)


def test_the_gate_refuses_a_worker_that_advanced(temp_database):
    """The artifact names the state the worker was in. If it has moved on, what
    was validated is not what would be promoted."""
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    ctx.session._spec.advance()
    with pytest.raises(tc.PreparedCommitMismatch, match="worker advanced"):
        frozen.verify(proposal=ctx)


def test_the_gate_refuses_a_substituted_worker(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    ctx.session = SimpleNamespace(_spec=_Spec(), journal=None, allocation=None)
    with pytest.raises(tc.PreparedCommitMismatch, match="not the one this commit"):
        frozen.verify(proposal=ctx)


def test_the_gate_refuses_a_proposal_gone_dirty(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    ctx.mark_dirty("late rejection")
    with pytest.raises(tc.PreparedCommitMismatch, match="reconstruction"):
        frozen.verify(proposal=ctx)


def test_the_gate_refuses_a_tampered_journal(temp_database):
    """Head equality is not enough: a swapped or altered entry that happens to
    end at the same link would otherwise pass."""
    from dataclasses import replace

    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    entries = list(frozen.journal_delta)
    entries[0] = replace(entries[0], rule_text="a different rule")
    tampered = replace(frozen, journal_delta=tuple(entries))
    with pytest.raises(tc.PreparedCommitMismatch, match="journal chain"):
        tampered.verify()


def test_the_gate_refuses_a_moved_tip(temp_database):
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx, parent_tip_id="tip-A")
    store = MagicMock()
    store.current_tip.return_value = "tip-B"
    store.shrink_mapping_epoch.return_value = frozen.allocator_base_digest
    with pytest.raises(tc.PreparedCommitMismatch, match="tip moved"):
        frozen.verify(store=store)


def test_the_gate_reports_every_problem_at_once(temp_database):
    """The anchors are only meaningful as a set. Reporting the first one and
    stopping is how a proposal that agrees about its parent and disagrees about
    its mapping gets investigated one round-trip at a time."""
    ctx = _proposal(temp_database)
    frozen = _freeze(ctx)
    ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="later")
    ctx.allocator.id_for("k-later")
    ctx.session._spec.advance()
    with pytest.raises(tc.PreparedCommitMismatch) as excinfo:
        frozen.verify(proposal=ctx, execution_id="other")
    message = str(excinfo.value)
    for expected in ("execution", "journal head moved", "allocator delta moved",
                     "worker advanced"):
        assert expected in message, f"{expected!r} missing from {message!r}"
