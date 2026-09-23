"""The block-level activation against a REAL proposal evaluator.

What a scripted session cannot answer: whether the activated revision reaches
the journal the proposal will be reconstructed from. A session created by
`begin_proposal` starts with a journal of its own, and anything recorded outside
a transaction branch goes there -- so an activation could run correctly, change
the evaluator correctly, and still be missing from the record that defines the
evaluator's state.
"""
import os

import pytest
from unittest.mock import MagicMock, patch

import tau_allocator as alloc
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
import tau_session as ts
from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate
from consensus.state import TauStateSnapshot


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(),
                                reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROPOSER = "d4" * 48
HEIGHT = 20
ACTIVATION_RULE = "always ( o9[t]:bv[16] = { #x0005 }:bv[16] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _update():
    return ConsensusRuleUpdate(rule_revisions=[ACTIVATION_RULE],
                               activate_at_height=HEIGHT,
                               proposer_pubkey=PROPOSER)


def _proposal():
    plan = tr.plan_representation(candidate_rules=[ACTIVATION_RULE])
    snapshot = alloc.DbMappingSnapshot()

    def respawn(current_plan):
        session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env(),
                                         plan=current_plan)
        session.begin_proposal(alloc.Allocator(snapshot, width=current_plan.width))
        return session

    def rebuild(proposal_journal, current_plan):
        # the node's own replay, which understands RESET
        return ts.replay_entries(None, proposal_journal.entries(),
                                 respawn=lambda: respawn(current_plan))

    return tp.ProposalContext(
        session=respawn(plan),
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan, rebuild=rebuild, respawn=respawn,
    )


def _run():
    proposal = _proposal()
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    update = _update()
    lm = ConsensusLifecycleManager(active_validators=[PROPOSER])
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates = [(update.activate_at_height, update.update_id)]
    parent = TauStateSnapshot(
        state_hash="0" * 64, tau_bytes=b"",
        metadata={"balances": {PROPOSER: 1000}, "sequence_numbers": {},
                  "last_transfer_ts": {}, "lifecycle_manager": lm,
                  "active_consensus_id": ""},
    )
    block = Block.create(block_number=HEIGHT, previous_hash="0" * 64,
                         transactions=[], proposer_pubkey=PROPOSER,
                         timestamp=1700000000)
    view = ActiveConsensusView(target_height=HEIGHT, consensus_rules="",
                               active_validators=[bytes.fromhex(PROPOSER)])
    with patch("tau_manager.communicate_with_tau") as live:
        result = engine.apply_block(view, block, parent,
                                    session=proposal.session, proposal=proposal)
    return proposal, result, live, update


def test_the_activation_lands_in_the_proposal_journal(temp_database):
    proposal, result, live, update = _run()
    try:
        revisions = [e.rule_text for e in proposal.journal.entries()
                     if e.kind == tj.REVISION]
        assert ACTIVATION_RULE in revisions, (
            "the activation is missing from the journal the proposal would be "
            f"reconstructed from: {revisions}"
        )
        entry = next(e for e in proposal.journal.entries()
                     if e.rule_text == ACTIVATION_RULE)
        assert entry.accumulate is False, (
            "an activation revision must not be recorded as part of the "
            "application-rules accumulation"
        )
        proposal.journal.verify_chain()
        assert live.call_count == 0, (
            "governance activation stepped the node's own interpreter"
        )
    finally:
        proposal.dispose()


def test_a_reconstruction_reproduces_the_activation(temp_database):
    """The point of journalling it: rebuild from the journal and the activated
    consensus rule is still in force."""
    proposal, result, live, update = _run()
    try:
        before = proposal.session._spec.state()["spec_revision"]
        assert before > 0, "the activation did not revise the evaluator at all"

        proposal.mark_dirty("test")
        proposal.reconstruct()
        after = proposal.session._spec.state()["spec_revision"]
        assert after == before, (
            f"the rebuilt evaluator is at revision {after}, the original at "
            f"{before}: the activation did not survive reconstruction"
        )
    finally:
        proposal.dispose()
