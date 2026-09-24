"""M4/C4: the durable commit point, and what failure means on each side of it.

The distinction under test: an uncommitted proposal may be discarded whole; a
committed block whose evaluator is unavailable must NEVER be reported as rejected
or abandoned, and a retry of that transition must not apply anything twice.
"""
import pytest

import tau_allocator as alloc
import tau_commit


class FakeStore:
    def __init__(self, tip="parent0"):
        self.tip = tip
        self.committed = {}
        self.mapping = {}
        self.epoch = 0
        self.commits = []
        self.fail_persist = False
        self.fail_allocation = False

    # allocator surface
    def snapshot_mapping(self):
        return self.epoch, dict(self.mapping)

    def publish_mapping(self, delta, expected_epoch):
        self.mapping.update(delta)
        self.epoch += 1

    # coordinator surface
    def current_tip(self):
        return self.tip

    def committed_canonical(self):
        return dict(self.committed)

    def commit_block(self, *, tip, parent, canonical, allocation_delta, expected_epoch):
        if self.fail_persist:
            raise RuntimeError("disk on fire")
        if self.fail_allocation:
            raise alloc.AllocatorConflict("id already taken")
        # ONE transaction: canonical state, allocation delta, committed tip
        self.committed.update(canonical)
        self.mapping.update(allocation_delta)
        self.epoch += 1
        self.tip = tip
        self.commits.append({"tip": tip, "canonical": dict(canonical),
                             "delta": dict(allocation_delta)})


class FakeEvaluator:
    def __init__(self):
        self.active = None
        self.prepared = []
        self.fail_prepare = False
        self.fail_activate = False

    def prepare_replacement(self, canonical):
        if self.fail_prepare:
            raise RuntimeError("reconstruction failed")
        self.prepared.append(dict(canonical))
        return {"canonical": dict(canonical)}

    def activate(self, replacement):
        if self.fail_activate:
            raise RuntimeError("activation failed")
        self.active = replacement


def _coord(store=None, evaluator=None):
    store = store or FakeStore()
    ev = evaluator if evaluator is not None else FakeEvaluator()
    c = tau_commit.BlockCommitCoordinator(store, evaluator=ev, commit_id="c1")
    return c, store, ev


def _proposal(c, store, *, with_alloc=True):
    allocator = None
    if with_alloc:
        allocator = alloc.Allocator(alloc.MappingSnapshot.capture(store), width=16, label="block")
    p = c.open(store.current_tip(), allocator=allocator)
    return p


# --- happy path ---------------------------------------------------------------

def test_commit_persists_then_activates_then_is_ready():
    c, store, ev = _coord()
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "always ( o5[t]:bv[24] = { #x1 }:bv[24] )."})
    p.allocator.child("tx1").id_for("bv384:alice")
    c.prepare()
    assert ev.prepared, "the replacement is built BEFORE anything is durable"
    assert not c.ready
    result = c.commit("block1")
    assert result["state"] == tau_commit.ACTIVE
    assert c.ready and c.committed
    assert store.commits[0]["tip"] == "block1"


def test_canonical_state_and_allocation_go_down_together():
    c, store, _ = _coord()
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    child = p.allocator.child("tx1")
    child.id_for("bv384:alice")
    p.allocator.merge(child)
    c.prepare()
    c.commit("block1")
    assert len(store.commits) == 1
    assert store.commits[0]["canonical"] == {"rules": "R"}
    assert store.commits[0]["delta"] == {"bv384:alice": 1}


# --- before the commit point --------------------------------------------------

def test_an_uncommitted_proposal_can_be_abandoned_whole():
    """Including transactions that individually succeeded."""
    c, store, _ = _coord()
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    c.prepare()
    c.abandon("mining lost the race")
    assert c.state == tau_commit.ABANDONED
    assert store.committed == {} and store.commits == []


def test_a_reconstruction_failure_surfaces_before_anything_is_durable():
    ev = FakeEvaluator()
    ev.fail_prepare = True
    c, store, _ = _coord(evaluator=ev)
    _proposal(c, store)
    with pytest.raises(RuntimeError):
        c.prepare()
    assert store.commits == []
    c.abandon("reconstruction failed")


def test_persistence_failure_leaves_nothing_committed():
    c, store, _ = _coord()
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    c.prepare()
    store.fail_persist = True
    with pytest.raises(RuntimeError):
        c.commit("block1")
    assert not c.committed
    assert store.committed == {}


def test_allocation_publication_failure_is_stale_not_invalid():
    c, store, _ = _coord()
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    c.prepare()
    store.fail_allocation = True
    with pytest.raises(tau_commit.StaleProposal):
        c.commit("block1")
    assert not c.committed


def test_a_moved_parent_makes_the_proposal_stale():
    c, store, _ = _coord()
    _proposal(c, store)
    c.prepare()
    store.tip = "someone_else_won"
    with pytest.raises(tau_commit.StaleProposal):
        c.commit("block1")


# --- after the commit point ---------------------------------------------------

def test_activation_failure_after_durable_commit_is_not_a_rejection():
    ev = FakeEvaluator()
    c, store, _ = _coord(evaluator=ev)
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    c.prepare()
    ev.fail_activate = True
    result = c.commit("block1")
    assert result["state"] == tau_commit.COMMITTED_BUT_UNAVAILABLE
    assert c.committed and not c.ready          # committed, but not serving
    assert store.commits, "the block really happened"
    assert "unavailable_reason" in result


def test_a_committed_block_cannot_be_abandoned():
    c, store, _ = _coord()
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    c.prepare()
    c.commit("block1")
    with pytest.raises(tau_commit.CommitStateError):
        c.abandon("changed my mind")


def test_recovery_reconstructs_from_the_committed_state():
    ev = FakeEvaluator()
    c, store, _ = _coord(evaluator=ev)
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    c.prepare()
    ev.fail_activate = True
    c.commit("block1")
    assert c.state == tau_commit.COMMITTED_BUT_UNAVAILABLE
    ev.fail_activate = False
    out = c.recover()
    assert out["state"] == tau_commit.ACTIVE
    assert c.ready
    assert ev.prepared[-1] == {"rules": "R"}    # from committed state, not a cache


def test_retrying_a_completed_commit_applies_nothing_twice():
    c, store, _ = _coord()
    p = _proposal(c, store)
    p.accept("tx1", {"rules": "R"})
    child = p.allocator.child("tx1")
    child.id_for("bv384:alice")
    p.allocator.merge(child)
    c.prepare()
    first = c.commit("block1")
    again = c.commit("block1")
    assert again == first
    assert len(store.commits) == 1, "a retried transition must not commit twice"


def test_readiness_is_about_serving_not_about_having_committed():
    ev = FakeEvaluator()
    c, store, _ = _coord(evaluator=ev)
    _proposal(c, store)
    c.prepare()
    ev.fail_activate = True
    c.commit("block1")
    assert c.committed is True
    assert c.ready is False


def test_the_execution_id_binds_transaction_content():
    """Persisted block transactions carry no `tx_id`; identifying them by it gave
    every transaction the same identity, so two different blocks in the same
    second on the same parent shared one execution id."""
    base = dict(parent="p", height=1, timestamp=10, proposer="x",
                consensus_context="c")
    one = {"tx_type": "user_tx", "sender_pubkey": "a", "operations": {"1": []}}
    other = {"tx_type": "user_tx", "sender_pubkey": "b", "operations": {"1": []}}
    a = tau_commit.block_execution_id(transactions=[one], **base)
    assert a != tau_commit.block_execution_id(transactions=[other], **base)
    # the synthetic label createblock adds to its execution copies is not
    # part of what was executed
    assert a == tau_commit.block_execution_id(transactions=[{**one, "tx_id": "label"}], **base)
