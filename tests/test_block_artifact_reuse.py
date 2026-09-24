"""A locally built block is not evaluated twice.

The miner evaluated the block; ingestion used to evaluate it again against the
same parent with the same transactions. The artifact the miner leaves behind is
claimed by ingestion instead -- once, for exactly the block it describes.

A miss is always a valid answer: the block is evaluated as before. That is what
keeps this from being able to change an outcome, only the work done to reach it.
"""
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import block as block_mod
import chain_state
import db
import tau_allocator as alloc
import tau_commit as tc
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from consensus.state import TauStateSnapshot, compute_consensus_state_hash


class _Spec:
    def __init__(self):
        self._state = {"spec_revision": 1, "time_point": 4, "session_healthy": True}

    def state(self):
        return dict(self._state)


class _Session:
    def __init__(self):
        self._spec = _Spec()
        self.journal = None
        self.allocation = None
        self.disposed = False

    def dispose(self):
        self.disposed = True


@pytest.fixture(autouse=True)
def _clean_registry():
    tc.registry().discard()
    yield
    tc.registry().discard()


@pytest.fixture(autouse=True)
def _accept_headers():
    """These tests are about which evaluation ingestion uses, not about PoA."""
    from consensus.engine import TauConsensusEngine

    with patch.object(TauConsensusEngine, "verify_block_header",
                      lambda *a, **k: True):
        yield


def _next_snapshot():
    """What applying an empty block to the current state produces."""
    from chain_state import compute_accounts_hash

    app_rules = (chain_state._application_rules_state or "").encode("utf-8")
    cons_rules = (chain_state._consensus_rules_state or "").encode("utf-8")
    acc_hash = compute_accounts_hash(chain_state._balances,
                                     chain_state._sequence_numbers)
    meta_hash = chain_state._lifecycle_manager.consensus_meta_hash()
    return TauStateSnapshot(
        state_hash=compute_consensus_state_hash(cons_rules, app_rules, acc_hash,
                                                meta_hash),
        tau_bytes=app_rules,
        metadata={
            "balances": dict(chain_state._balances),
            "sequence_numbers": dict(chain_state._sequence_numbers),
            "last_transfer_ts": dict(chain_state._last_transfer_ts),
            "lifecycle_manager": chain_state._lifecycle_manager,
            "consensus_rules_state": chain_state._consensus_rules_state,
            "active_consensus_id": chain_state._active_consensus_id,
        },
    )


def _block(snapshot, transactions=()):
    head = db.get_canonical_head() or {}
    header = head.get("header") or {}
    blk = block_mod.Block.create(
        block_number=int(header.get("block_number", -1)) + 1,
        previous_hash=head.get("block_hash") or "0" * 64,
        transactions=list(transactions),
        proposer_pubkey="d4" * 48,
        timestamp=int(time.time()),
        state_hash=snapshot.state_hash,
    )
    return blk


def _artifact(blk, snapshot, *, session=None):
    plan = tr.plan_representation(candidate_rules=[])
    mapping = alloc.DbMappingSnapshot()
    ctx = tp.ProposalContext(
        session=session or _Session(),
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(mapping, width=plan.width, label="proposal"),
        plan=plan,
    )
    execution_id = tc.block_execution_id(
        parent=blk.header.previous_hash, height=blk.header.block_number,
        timestamp=blk.header.timestamp, proposer=blk.header.proposer_pubkey,
        transactions=blk.transactions,
        # The same context ingestion derives: the active view's consensus rules
        # come from the parent snapshot's consensus_rules_state.
        consensus_context=chain_state._consensus_rules_state or "",
    )
    prepared = tc.PreparedBlockCommit.freeze(
        ctx, execution_id=execution_id, next_snapshot=snapshot,
        parent_tip_id=blk.header.previous_hash,
    )
    return execution_id, prepared, ctx, ctx.session


def _refuse_apply():
    """apply_block must not be reached. Raising is louder than counting."""
    from consensus.engine import TauConsensusEngine

    def _boom(*a, **k):
        raise AssertionError("the block was evaluated a second time")

    return patch.object(TauConsensusEngine, "apply_block", _boom)


def test_a_matching_artifact_replaces_the_second_evaluation(node_state):
    snapshot = _next_snapshot()
    blk = _block(snapshot)
    execution_id, prepared, ctx, worker = _artifact(blk, snapshot)
    tc.registry().offer(execution_id, prepared, ctx)

    with _refuse_apply():
        assert chain_state.process_new_block(blk) is True

    assert db.get_canonical_head()["block_hash"] == blk.block_hash
    assert worker.disposed, "the reused proposal's worker was leaked"
    assert tc.registry().pending is None, "the artifact was not consumed"


def test_the_artifact_is_consumed_exactly_once(node_state):
    snapshot = _next_snapshot()
    blk = _block(snapshot)
    execution_id, prepared, ctx, worker = _artifact(blk, snapshot)
    tc.registry().offer(execution_id, prepared, ctx)

    assert tc.registry().claim(execution_id) is not None
    assert tc.registry().claim(execution_id) is None, \
        "an artifact was usable twice"


def test_an_artifact_for_another_block_is_ignored(node_state):
    """The block was rebuilt -- a different timestamp here. Ingestion must
    evaluate it rather than commit a state computed for something else."""
    snapshot = _next_snapshot()
    mined = _block(snapshot)
    execution_id, prepared, ctx, worker = _artifact(mined, snapshot)
    tc.registry().offer(execution_id, prepared, ctx)

    rebuilt = _block(snapshot)
    rebuilt.header.timestamp = mined.header.timestamp + 1
    rebuilt.block_hash = block_mod.sha256_hex(rebuilt.header.canonical_bytes())

    calls = []
    from consensus.engine import TauConsensusEngine
    real = TauConsensusEngine.apply_block

    def _record(self, *a, **k):
        calls.append(True)
        return real(self, *a, **k)

    with patch.object(TauConsensusEngine, "apply_block", _record):
        chain_state.process_new_block(rebuilt)

    assert calls, "a stale artifact was used for a block it does not describe"
    assert tc.registry().pending == execution_id, \
        "the wrong block consumed the artifact"


def test_a_stale_artifact_falls_back_instead_of_failing(node_state):
    """The safe direction has to stay cheap to take: a proposal that moved on
    since freezing must not make the block unprocessable."""
    snapshot = _next_snapshot()
    blk = _block(snapshot)
    execution_id, prepared, ctx, worker = _artifact(blk, snapshot)
    # Something advanced the proposal after the artifact was taken.
    ctx.journal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="later")
    tc.registry().offer(execution_id, prepared, ctx)

    calls = []
    from consensus.engine import TauConsensusEngine
    real = TauConsensusEngine.apply_block

    def _record(self, *a, **k):
        calls.append(True)
        return real(self, *a, **k)

    with patch.object(TauConsensusEngine, "apply_block", _record):
        assert chain_state.process_new_block(blk) is True

    assert calls, "the stale artifact was used"
    assert worker.disposed, "the rejected proposal's worker was leaked"


def test_an_unclaimed_artifact_is_disposed_by_the_next_offer(node_state):
    """A block abandoned somewhere that did not say so would otherwise leave a
    worker process alive for the life of the node."""
    snapshot = _next_snapshot()
    blk = _block(snapshot)
    first_id, first, first_ctx, first_worker = _artifact(blk, snapshot)
    tc.registry().offer(first_id, first, first_ctx)

    second_id, second, second_ctx, second_worker = _artifact(blk, snapshot, session=_Session())
    tc.registry().offer(second_id + "-other", second, second_ctx)

    assert first_worker.disposed, "the abandoned proposal's worker leaked"
    assert not second_worker.disposed
