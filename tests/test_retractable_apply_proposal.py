"""Retractable transfers in proposal mode.

A proposal evaluates a candidate block against a clone of the parent: a park or
retract mutates the transaction's own lifecycle clone, the sweep mutates the
block's lifecycle, and nothing may reach the parent until the block commits.
Driven with a scripted evaluator; what is under test is ownership of state.
"""
import copy
from unittest.mock import MagicMock, patch

import pytest

import config
import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.retractable import KIND_HEIGHT, RetractableEntry
from consensus.state import TauStateSnapshot
from test_retractable_apply import (
    ALICE, BOB, CAROL, HEIGHT, PROPOSER, TS, park_tx, retract_tx, rid_of,
)

RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
DUE = RetractableEntry(ALICE, BOB, 300, 0, KIND_HEIGHT, HEIGHT)
LATER = RetractableEntry(ALICE, CAROL, 200, 1, KIND_HEIGHT, HEIGHT + 50)


@pytest.fixture(autouse=True)
def _no_faucet(monkeypatch):
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False)


class _Session:
    is_speculative = True

    def __init__(self, fee="0"):
        self.fee = fee
        self.allocation = None
        self.journal = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        return "ok"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        outputs = {
            tau_defs.USER_POLICY_STREAM_INDEX: "1",
            tau_defs.CONSENSUS_FEE_STREAM_INDEX: self.fee,
        }
        return outputs if multi else ""

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        pass


def _parent_lifecycle():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.activate_approval_slots()
    lm.retractable_transfers.submit(DUE)
    lm.retractable_transfers.submit(LATER)
    return lm


def _balances():
    # Alice's 500 in escrow is already out of her balance.
    return {ALICE: 10_000 - 500, BOB: 0, CAROL: 0, PROPOSER: 0}


def _parent(lm):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always ( o0[t]=1 ).",
        metadata={
            "balances": _balances(),
            "sequence_numbers": {ALICE: 2},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "",
            "active_consensus_id": "",
        },
    )


def _proposal(session):
    plan = tr.plan_representation(candidate_rules=[RULE])
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(
            alloc.DbMappingSnapshot(), width=plan.width, label="proposal"
        ),
        plan=plan,
    )


def _view():
    return ActiveConsensusView(
        target_height=HEIGHT, consensus_rules="",
        active_validators=[bytes.fromhex(ALICE)],
    )


def _block(txs):
    return Block.create(
        block_number=HEIGHT, previous_hash="0" * 64, transactions=txs,
        proposer_pubkey=PROPOSER, timestamp=TS,
    )


def _engine():
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    return engine


def _run_proposal(txs, lm, *, fee="0"):
    session = _Session(fee=fee)
    proposal = _proposal(session)
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = _engine().apply_block(
            _view(), _block(txs), _parent(lm), session=session, proposal=proposal,
        )
    return proposal, result


def _run_plain(txs, lm, *, fee="0"):
    def multi(**kwargs):
        return {tau_defs.USER_POLICY_STREAM_INDEX: "1",
                tau_defs.CONSENSUS_FEE_STREAM_INDEX: fee}

    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", return_value="T"), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=multi), \
         patch("chain_state.get_application_rules_state", return_value=""):
        ready.is_set.return_value = True
        return TauConsensusEngine().apply_block(_view(), _block(txs), _parent(lm))


def _fingerprint(snapshot):
    meta = snapshot.metadata
    lm = meta["lifecycle_manager"]
    book = lm.retractable_transfers
    return copy.deepcopy((
        meta["balances"], meta["sequence_numbers"], meta["last_transfer_ts"],
        book.snapshot_rows(), book.resolved_state(), book.root(),
        book.escrow_total(), lm.consensus_meta_hash(),
    ))


def test_a_rejected_park_leaves_no_trace(temp_database):
    lm = _parent_lifecycle()
    tx = park_tx(amount=100, seq=2, at_height=HEIGHT + 5, fee_limit="10")
    proposal, result = _run_proposal([tx], lm, fee="500")

    assert result.invalid_tx_ids == [tx["tx_id"]]
    book = proposal.lifecycle.retractable_transfers
    assert rid_of(tx) not in {k.hex() for k in book.open}
    meta = result.next_snapshot.metadata
    assert meta["balances"][ALICE] == 10_000 - 500
    assert meta["sequence_numbers"][ALICE] == 2
    assert meta["last_transfer_ts"] == {}
    assert meta["balances"][PROPOSER] == 0


def test_an_accepted_park_lands_on_the_proposal_lifecycle(temp_database):
    lm = _parent_lifecycle()
    tx = park_tx(amount=100, seq=2, at_height=HEIGHT + 5)
    proposal, result = _run_proposal([tx], lm, fee="3")

    assert result.accepted_tx_ids == [tx["tx_id"]]
    assert bytes.fromhex(rid_of(tx)) in proposal.lifecycle.retractable_transfers.open
    meta = result.next_snapshot.metadata
    assert meta["balances"][ALICE] == 10_000 - 500 - 100 - 3
    assert meta["balances"][PROPOSER] == 3
    assert meta["last_transfer_ts"][ALICE] == TS


def test_the_proposal_lifecycle_is_the_swept_manager(temp_database):
    lm = _parent_lifecycle()
    proposal, result = _run_proposal([], lm)

    swept = result.next_snapshot.metadata["lifecycle_manager"]
    assert proposal.lifecycle is swept
    assert DUE.retractable_id not in swept.retractable_transfers.open
    assert swept.retractable_transfers.resolved_count == 1
    assert result.next_snapshot.metadata["balances"][BOB] == 300
    assert result.governance_changes["released_retractables"] == [
        DUE.retractable_id.hex()
    ]


def test_the_parent_is_untouched_by_candidate_evaluation(temp_database):
    lm = _parent_lifecycle()
    parent = _parent(lm)
    before = _fingerprint(parent)

    park = park_tx(amount=100, seq=2, at_height=HEIGHT + 5)
    retract = retract_tx(LATER.retractable_id.hex(), seq=3)
    session = _Session(fee="3")
    proposal = _proposal(session)
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = _engine().apply_block(
            _view(), _block([park, retract]), parent, session=session, proposal=proposal,
        )

    assert set(result.accepted_tx_ids) == {park["tx_id"], retract["tx_id"]}
    assert _fingerprint(parent) == before
    assert proposal.lifecycle is not lm


def test_proposal_and_plain_apply_reach_the_same_state_hash(temp_database):
    def txs():
        return [
            park_tx(amount=100, seq=2, at_height=HEIGHT + 5),
            retract_tx(LATER.retractable_id.hex(), seq=3),
        ]

    block_txs = txs()
    _, proposed = _run_proposal(block_txs, _parent_lifecycle(), fee="3")
    plain = _run_plain(block_txs, _parent_lifecycle(), fee="3")

    assert proposed.accepted_tx_ids == plain.accepted_tx_ids
    assert proposed.next_snapshot.state_hash == plain.next_snapshot.state_hash
    assert proposed.next_snapshot.metadata["balances"] == plain.next_snapshot.metadata["balances"]
    assert (
        proposed.next_snapshot.metadata["lifecycle_manager"].retractable_transfers.root()
        == plain.next_snapshot.metadata["lifecycle_manager"].retractable_transfers.root()
    )
