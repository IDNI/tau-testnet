"""Governance activation is block-level, and in proposal mode it is the
proposal's.

The height transition runs once, after the transaction loop, and belongs to the
block rather than to whichever transaction happened to run last -- so it gets no
transaction child. What it must not do is route its activated revisions through
`tau_manager`: that installs a consensus rule in the NODE's interpreter for a
block that may still be abandoned, and there is no in-process way to take it
back afterwards.
"""
from unittest.mock import MagicMock, patch

import pytest

import tau_allocator as alloc
import tau_guard
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate
from consensus.state import TauStateSnapshot

PROPOSER = "d4" * 48
HEIGHT = 20
ACTIVATION_RULE = "always ( o9[t]:bv[16] = { #x0005 }:bv[16] )."


class _Session:
    """Records what the proposal evaluator was asked to do."""

    is_speculative = True

    def __init__(self, rule_accepted=True):
        self.rule_accepted = rule_accepted
        self.rules_seen = []
        self.allocation = None
        self.journal = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        self.rules_seen.append((rule_text, accumulate))
        return "ok" if self.rule_accepted else "error"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        return {} if multi else ""

    def last_receipt(self):
        return {"accepted": self.rule_accepted,
                "outcome": "ACCEPTED_CHANGED" if self.rule_accepted else "REJECTED_RULE"}

    def dispose(self):
        pass


def _update():
    return ConsensusRuleUpdate(rule_revisions=[ACTIVATION_RULE],
                               activate_at_height=HEIGHT,
                               proposer_pubkey=PROPOSER)


def _lifecycle_with_scheduled_update(update):
    lm = ConsensusLifecycleManager(active_validators=[PROPOSER])
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates = [(update.activate_at_height, update.update_id)]
    return lm


def _parent_snapshot(lm):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always ( o0[t]=1 ).",
        metadata={
            "balances": {PROPOSER: 1000},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "active_consensus_id": "",
        },
    )


def _block():
    return Block.create(
        block_number=HEIGHT, previous_hash="0" * 64, transactions=[],
        proposer_pubkey=PROPOSER, timestamp=1700000000,
    )


def _proposal(session):
    plan = tr.plan_representation(candidate_rules=[ACTIVATION_RULE])
    snapshot = alloc.DbMappingSnapshot()
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan,
    )


def _run(*, rule_accepted=True):
    session = _Session(rule_accepted=rule_accepted)
    proposal = _proposal(session)
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    update = _update()
    lm = _lifecycle_with_scheduled_update(update)
    view = ActiveConsensusView(target_height=HEIGHT, consensus_rules="",
                               active_validators=[bytes.fromhex(PROPOSER)])
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau") as live:
        ready.is_set.return_value = True
        result = engine.apply_block(
            view, _block(), _parent_snapshot(lm),
            session=session, proposal=proposal,
        )
    return proposal, session, result, live, update


def test_an_activation_revision_runs_on_the_proposal_evaluator(temp_database):
    proposal, session, result, live, update = _run()

    assert (ACTIVATION_RULE, False) in session.rules_seen, (
        "the activated revision did not reach the proposal's evaluator: "
        f"{session.rules_seen}"
    )
    assert live.call_count == 0, (
        "governance activation stepped the node's own interpreter for a block "
        "that has not committed"
    )


def test_the_activation_is_fed_without_accumulating(temp_database):
    """An activation revision changes the evaluator but is NOT part of the
    application-rules accumulation -- consensus provenance is carried by the
    deterministic tag written into the snapshot instead. Feeding it through the
    rules handler would persist a partially-stripped intermediate.

    Whether it reaches the proposal JOURNAL is asserted against a real session
    in tests/test_apply_block_governance_native.py; a scripted session recording
    its own calls would only be testing the script.
    """
    proposal, session, result, live, update = _run()
    assert (ACTIVATION_RULE, False) in session.rules_seen


def test_a_refused_activation_fails_the_block(temp_database):
    """Deterministic invalid activation keeps the existing block-failure
    semantics -- it is not silently skipped, and not a transaction verdict."""
    from consensus.fees import FeeRuleError

    with pytest.raises(FeeRuleError):
        _run(rule_accepted=False)


def test_the_lifecycle_the_block_hashes_is_the_proposal_s(temp_database):
    """apply_block deep-copies the parent lifecycle and hands it to the
    proposal. If the two drifted apart, the state hash would be computed from
    an object the transactions never mutated."""
    proposal, session, result, live, update = _run()

    assert proposal.lifecycle is not None
    assert update.update_id in proposal.lifecycle.archival_updates, (
        "the activation did not land on the lifecycle the proposal owns"
    )
    assert proposal.lifecycle.scheduled_updates == []
