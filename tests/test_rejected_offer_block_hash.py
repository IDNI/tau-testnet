"""A rule offer that fails fee settlement leaves no trace in the block state.

The miner applies the block with the offer, drops the rejected offer from the
block, and ingestion applies the block again without it. Both applications must
give the same state hash, or the node refuses its own block on every attempt.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
TS = 1700000000
FAR_FUTURE = 9999999999
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
_TX_SEQ = itertools.count()

SK_ALICE = 11111
ALICE = G2Basic.SkToPk(SK_ALICE).hex()
BOB = G2Basic.SkToPk(44444).hex()
PROPOSER = "d4" * 48


class _FlatFeeSession:
    """Deterministic evaluator that charges a flat consensus fee on o9."""

    is_speculative = True

    def __init__(self, fee):
        self.fee = fee
        self.allocation = None
        self.journal = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        return "ok"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        outputs = {tau_defs.CONSENSUS_FEE_STREAM_INDEX: str(self.fee)}
        if multi:
            return outputs
        return "" if target is None else outputs.get(target, "")

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        pass


def _offer_tx(fee_limit):
    tx = {
        "tx_id": f"rule_offer-{next(_TX_SEQ)}",
        "tx_type": "rule_offer",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": EXPIRE,
        "fee_limit": fee_limit,
        "recipient_pubkey": BOB,
        "rule_text": OFFER_RULE,
    }
    tx["signature"] = G2Basic.Sign(
        SK_ALICE, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _proposal(session):
    plan = tr.plan_representation(candidate_rules=[OFFER_RULE])
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan, lifecycle=None,
    )


def _apply_block(txs, mode):
    lifecycle = ConsensusLifecycleManager(active_validators=[ALICE])
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"rules",
        metadata={
            "balances": {ALICE: 100_000, BOB: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lifecycle,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(ALICE)],
        mechanism_specific_metadata={"poa": True},
    )
    block = Block.create(
        block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=PROPOSER, timestamp=TS,
    )
    session = _FlatFeeSession(fee=10)
    proposal = _proposal(session) if mode == "proposal" else None
    with patch("tau_manager.tau_ready") as ready, \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch("chain_state.save_application_rules_state"):
        ready.is_set.return_value = True
        return TauConsensusEngine().apply_block(
            view, block, parent, session=session, proposal=proposal,
        )


@pytest.mark.parametrize("mode", ["proposal", "direct"])
def test_an_offer_rejected_at_fee_settlement_hashes_like_an_empty_block(
        temp_database, mode):
    tx = _offer_tx(fee_limit="0")
    mined = _apply_block([tx], mode)
    reapplied = _apply_block([], mode)

    assert mined.invalid_tx_ids == [tx["tx_id"]]
    logs = [o.receipt_logs for o in mined.outcomes if o.tx_id == tx["tx_id"]][0]
    assert "Fee 10 exceeds fee_limit 0" in logs, logs
    assert mined.next_snapshot.state_hash == reapplied.next_snapshot.state_hash, logs
    assert mined.next_snapshot.metadata["lifecycle_manager"].rule_offers.offered == {}


@pytest.mark.parametrize("mode", ["proposal", "direct"])
def test_an_offer_that_pays_its_fee_is_recorded(temp_database, mode):
    tx = _offer_tx(fee_limit="1000")
    mined = _apply_block([tx], mode)
    empty = _apply_block([], mode)

    assert mined.invalid_tx_ids == []
    assert mined.next_snapshot.state_hash != empty.next_snapshot.state_hash


@pytest.mark.parametrize("mode", ["proposal", "direct"])
def test_an_accepted_offer_stays_in_the_block_lifecycle(temp_database, mode):
    tx = _offer_tx(fee_limit="1000")
    mined = _apply_block([tx], mode)

    offers = mined.next_snapshot.metadata["lifecycle_manager"].rule_offers
    assert mined.invalid_tx_ids == []
    assert len(offers.offered) == 1
    assert list(offers.offer_payloads.values()) == [OFFER_RULE]
