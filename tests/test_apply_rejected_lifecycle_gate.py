"""A transaction the envelope checks already rejected must not touch lifecycle state.

Expiry and a wrong sequence number hard-reject a transaction before type
dispatch. The lifecycle branches used to run anyway: they record governance
updates and votes, offers, accepts, approval requests and transfer votes on a
manager that, outside proposal mode, is never rolled back per transaction.
Proposal mode discards the branch clone, and an approval request has a
hand-written un-park, so those two already came out clean. Everything else
kept the mutation.

The scripted session stands in for Tau. What is under test is that a dead
transaction never reaches the evaluator and never changes the hashed
lifecycle, balances, nonces or transfer history.
"""
import hashlib
import itertools
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest
from py_ecc.bls import G2Basic

import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from block import Block
from consensus.approvals import ApprovalRequest
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate
from consensus.rule_offers import RuleOffer
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
TS = 1700000000
FAR_FUTURE = 9999999999
_TX_SEQ = itertools.count()

GOV_RULE = "always ( o6[t]:bv[16] = { 0 }:bv[16] )."
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_AUTH, AUTH = _key(22222)
SK_BOB, BOB = _key(44444)
PROPOSER = "d4" * 48

KINDS = [
    "transfer_vote",
    "approval_request",
    "rule_offer",
    "rule_offer_accept",
    "consensus_rule_update",
    "consensus_rule_vote",
]
CAUSES = ["sequence", "expire_at_height", "expiration_time"]
MODES = ["proposal", "direct"]


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


class _CountingSession:
    """Deterministic evaluator. `allows` omits o5, which the apply path treats
    as permit; otherwise o5 blocks, so an approval request is parked rather
    than waved through.
    """

    is_speculative = True

    def __init__(self, *, allows=False, fee="0"):
        self.allows = allows
        self.fee = fee
        self.rules_seen = []
        self.evaluations = []
        self.allocation = None
        self.journal = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        self.rules_seen.append(rule_text)
        return "ok"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        self.evaluations.append(source)
        outputs = {tau_defs.CONSENSUS_FEE_STREAM_INDEX: self.fee}
        if not self.allows:
            outputs[tau_defs.USER_POLICY_STREAM_INDEX] = str(
                tau_defs.USER_POLICY_BLOCK_VALUE
            )
        if multi:
            return outputs
        return "" if target is None else outputs.get(target, "")

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        pass


def _lifecycle():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.approval_slots_active = True
    return lm


def _proposal(lifecycle, session):
    plan = tr.plan_representation(candidate_rules=[OFFER_RULE])
    snapshot = alloc.DbMappingSnapshot()
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(snapshot, width=plan.width, label="proposal"),
        plan=plan, lifecycle=lifecycle,
    )


def _request():
    return ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=5000,
        sequence_number=0, expire_at_height=EXPIRE,
        approvers={18: AUTH}, custom_inputs={},
    )


def _offer():
    return RuleOffer(
        offerer_pubkey=ALICE, recipient_pubkey=BOB,
        rule_text=OFFER_RULE, expire_at_height=EXPIRE,
    )


def _update():
    return ConsensusRuleUpdate(
        rule_revisions=[GOV_RULE],
        activate_at_height=100,
        proposer_pubkey=ALICE,
    )


def _envelope(sender, tx_type, **fields):
    tx = {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": 0,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": EXPIRE,
        "fee_limit": "10000",
    }
    tx.update(fields)
    return tx


def _reject(tx, cause):
    if cause == "sequence":
        tx["sequence_number"] = 99
    elif cause == "expire_at_height":
        tx["expire_at_height"] = HEIGHT
    elif cause == "expiration_time":
        tx["expiration_time"] = TS - 1
    else:
        raise AssertionError(cause)
    return tx


def _prepared(kind, cause):
    """Lifecycle seeded so the transaction WOULD mutate it, then rejected."""
    lifecycle = _lifecycle()
    if kind == "transfer_vote":
        request = _request()
        assert lifecycle.approval_requests.submit_request(request)
        tx = _envelope(
            AUTH, "transfer_vote",
            request_id=request.request_id_hex, approve=True, reason="",
        )
        sk = SK_AUTH
        allows = True
    elif kind == "approval_request":
        request = _request()
        tx = _envelope(
            ALICE, "approval_request",
            recipient_pubkey=request.recipient_pubkey,
            amount=request.amount,
            approvers={str(k): v for k, v in request.approvers.items()},
            custom_inputs={},
        )
        sk = SK_ALICE
        allows = False
    elif kind == "rule_offer":
        offer = _offer()
        tx = _envelope(
            ALICE, "rule_offer",
            recipient_pubkey=offer.recipient_pubkey,
            rule_text=offer.rule_text,
        )
        sk = SK_ALICE
        allows = False
    elif kind == "rule_offer_accept":
        offer = _offer()
        assert lifecycle.rule_offers.submit_offer(offer)
        tx = _envelope(
            BOB, "rule_offer_accept",
            offer_id=offer.offer_id_hex, rule_text=offer.rule_text,
        )
        sk = SK_BOB
        allows = False
    elif kind == "consensus_rule_update":
        update = _update()
        tx = _envelope(
            ALICE, "consensus_rule_update",
            rule_revisions=list(update.rule_revisions),
            activate_at_height=update.activate_at_height,
        )
        sk = SK_ALICE
        allows = False
    elif kind == "consensus_rule_vote":
        update = _update()
        assert lifecycle.submit_update(update)
        tx = _envelope(
            ALICE, "consensus_rule_vote",
            update_id=update.update_id_hex, approve=True,
        )
        sk = SK_ALICE
        allows = False
    else:
        raise AssertionError(kind)
    return lifecycle, _CountingSession(allows=allows), _sign(_reject(tx, cause), sk)


def _apply(tx, lifecycle, session, mode):
    balances = {ALICE: 100_000, BOB: 100_000, AUTH: 100_000}
    sequences = {}
    transfer_ts = {}
    before = (
        lifecycle.consensus_meta_hash(),
        dict(balances),
        dict(sequences),
        dict(transfer_ts),
    )
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    proposal = _proposal(lifecycle, session) if mode == "proposal" else None
    patches = [patch("tau_manager.tau_ready")]
    if mode == "direct":
        patches.append(patch(
            "chain_state.get_application_rules_state", return_value="",
        ))
        patches.append(patch("chain_state.save_application_rules_state"))
    with ExitStack() as stack:
        ready = stack.enter_context(patches[0])
        for item in patches[1:]:
            stack.enter_context(item)
        ready.is_set.return_value = True
        result = engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [tx], TS,
            target_balances=balances,
            target_sequences=sequences,
            target_last_transfer_ts=transfer_ts,
            target_lifecycle=lifecycle,
            proposer_pubkey=PROPOSER,
            block_height=HEIGHT,
            proposal=proposal,
            session=session,
        )
    return result, before, balances, sequences, transfer_ts


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cause", CAUSES)
@pytest.mark.parametrize("kind", KINDS)
def test_a_pre_rejected_lifecycle_tx_does_not_mutate(temp_database, kind, cause, mode):
    lifecycle, session, tx = _prepared(kind, cause)
    result, before, balances, sequences, transfer_ts = _apply(
        tx, lifecycle, session, mode,
    )
    meta_before, bal_before, seq_before, lts_before = before
    logs = result.receipts[tx["tx_id"]]["logs"]
    assert tx in result.rejected_transactions, logs
    assert lifecycle.consensus_meta_hash() == meta_before, logs
    assert balances == bal_before, balances
    assert sequences == seq_before, sequences
    assert transfer_ts == lts_before, transfer_ts
    assert session.evaluations == [], session.evaluations
    assert session.rules_seen == [], session.rules_seen
    assert any("already rejected" in line for line in logs), logs


def _apply_block(txs, lifecycle, session):
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"rules",
        metadata={
            "balances": {ALICE: 100_000, BOB: 0, AUTH: 0},
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
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block = Block.create(
        block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=PROPOSER, timestamp=TS,
    )
    engine = TauConsensusEngine()
    with patch("tau_manager.tau_ready") as ready, \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch("chain_state.save_application_rules_state"):
        ready.is_set.return_value = True
        return engine.apply_block(view, block, parent, session=session)


def test_a_direct_block_with_a_rejected_releasing_vote_hashes_like_an_empty_one(
        temp_database):
    """Honest-proposer wedge: sim applies a vote the block then drops.

    The vote is already dead (stale sequence) but would release the parked
    transfer. Direct apply must leave the same state hash as the empty block,
    or the sim hash and the re-apply hash disagree and the block is refused.
    """
    lifecycle = _lifecycle()
    request = _request()
    assert lifecycle.approval_requests.submit_request(request)
    session = _CountingSession(allows=True)
    tx = _sign(_reject(_envelope(
        AUTH, "transfer_vote",
        request_id=request.request_id_hex, approve=True, reason="",
    ), "sequence"), SK_AUTH)

    empty = _apply_block([], lifecycle, session)
    voted = _apply_block([tx], lifecycle, _CountingSession(allows=True))

    assert voted.invalid_tx_ids == [tx["tx_id"]]
    assert empty.invalid_tx_ids == []
    assert voted.next_snapshot.state_hash == empty.next_snapshot.state_hash
