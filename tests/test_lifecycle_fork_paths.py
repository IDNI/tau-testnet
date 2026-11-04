"""Each transaction forks the lifecycle, on the proposal path and the direct path.

A rejected transaction drops its fork. The block without that transaction must
then give the same state hash, or the node refuses its own block. The two apply
paths must also give the same state hash for the same block.
"""
import hashlib
import itertools
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

import config
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
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
GOV_RULE = "always ( o6[t]:bv[16] = { 0 }:bv[16] )."
MODES = ["proposal", "direct"]
_TX_SEQ = itertools.count()


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_AUTH, AUTH = _key(22222)
SK_BOB, BOB = _key(44444)
PROPOSER = "d4" * 48


@pytest.fixture(autouse=True)
def _no_faucet(monkeypatch):
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False)


class _Session:
    """Deterministic evaluator: a flat fee on o9, an optional o5 block."""

    is_speculative = True

    def __init__(self, *, fee="500", block_o5=False, rule_accepted=True):
        self.fee = fee
        self.block_o5 = block_o5
        self.rule_accepted = rule_accepted
        self.rules_seen = []
        self.allocation = None
        self.journal = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        self.rules_seen.append(rule_text)
        return "ok" if self.rule_accepted else "error: REJECTED_RULE"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        outputs = {tau_defs.CONSENSUS_FEE_STREAM_INDEX: self.fee}
        if self.block_o5:
            outputs[tau_defs.USER_POLICY_STREAM_INDEX] = str(
                tau_defs.USER_POLICY_BLOCK_VALUE
            )
        if multi:
            return outputs
        return "" if target is None else outputs.get(target, "")

    def last_receipt(self):
        if self.rule_accepted:
            return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}
        return {"accepted": False, "outcome": "REJECTED_RULE"}

    def dispose(self):
        pass


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _envelope(sender, tx_type, *, seq=0, fee_limit="100", **fields):
    tx = {
        "tx_id": f"{tx_type}-{next(_TX_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": EXPIRE,
        "fee_limit": fee_limit,
    }
    tx.update(fields)
    return tx


def _offer(expire=EXPIRE):
    return RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=BOB,
                     rule_text=OFFER_RULE, expire_at_height=expire)


def _offer_tx(offer, fee_limit="100"):
    return _sign(_envelope(
        ALICE, "rule_offer", fee_limit=fee_limit,
        expire_at_height=offer.expire_at_height,
        recipient_pubkey=offer.recipient_pubkey, rule_text=offer.rule_text,
    ), SK_ALICE)


def _decision_tx(offer, accept, fee_limit="100", seq=0):
    fields = {"offer_id": offer.offer_id_hex}
    if accept:
        fields["rule_text"] = offer.rule_text
    return _sign(_envelope(
        BOB, "rule_offer_accept" if accept else "rule_offer_reject",
        seq=seq, fee_limit=fee_limit, **fields,
    ), SK_BOB)


def _request():
    return ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=5000,
        sequence_number=0, expire_at_height=EXPIRE,
        approvers={18: AUTH}, custom_inputs={},
    )


def _request_tx(request, fee_limit="100"):
    return _sign(_envelope(
        ALICE, "approval_request", fee_limit=fee_limit,
        recipient_pubkey=request.recipient_pubkey, amount=request.amount,
        approvers={str(k): v for k, v in request.approvers.items()},
        custom_inputs={},
    ), SK_ALICE)


def _park_tx(fee_limit="100", seq=0):
    return _sign(_envelope(
        ALICE, "retractable_transfer", seq=seq, fee_limit=fee_limit,
        recipient_pubkey=BOB, amount=100, release_at_height=HEIGHT + 10,
    ), SK_ALICE)


def _update_tx(signer_sk=SK_ALICE):
    return _sign(_envelope(
        ALICE, "consensus_rule_update", fee_limit="0",
        rule_revisions=[GOV_RULE], activate_at_height=100,
    ), signer_sk)


def _update():
    return ConsensusRuleUpdate(
        rule_revisions=[GOV_RULE], activate_at_height=100, proposer_pubkey=ALICE,
    )


def _proposal(session):
    plan = tr.plan_representation(candidate_rules=[OFFER_RULE])
    return tp.ProposalContext(
        session=session,
        journal=tj.Journal(authoritative=False),
        allocator=alloc.Allocator(alloc.DbMappingSnapshot(), width=plan.width,
                                  label="proposal"),
        plan=plan, lifecycle=None,
    )


def _apply_block(txs, mode, *, seed=None, **session_args):
    lifecycle = ConsensusLifecycleManager(active_validators=[ALICE])
    lifecycle.approval_slots_active = True
    if seed is not None:
        seed(lifecycle)
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"rules",
        metadata={
            "balances": {ALICE: 100_000, BOB: 100_000, AUTH: 0},
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
    session = _Session(**session_args)
    proposal = _proposal(session) if mode == "proposal" else None
    with patch("tau_manager.tau_ready") as ready, \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch("chain_state.save_application_rules_state"):
        ready.is_set.return_value = True
        return TauConsensusEngine().apply_block(
            view, block, parent, session=session, proposal=proposal,
        )


def _logs(result, tx):
    return [o.receipt_logs for o in result.outcomes if o.tx_id == tx["tx_id"]][0]


def _lifecycle_of(result):
    return result.next_snapshot.metadata["lifecycle_manager"]


def _assert_no_trace(mined, empty, tx):
    logs = _logs(mined, tx)
    assert mined.invalid_tx_ids == [tx["tx_id"]], logs
    assert mined.next_snapshot.state_hash == empty.next_snapshot.state_hash, logs
    assert (_lifecycle_of(mined).consensus_meta_hash()
            == _lifecycle_of(empty).consensus_meta_hash()), logs


# --- a rejected transaction leaves no lifecycle write ------------------------

@pytest.mark.parametrize("mode", MODES)
def test_a_rejected_approval_request_leaves_no_lifecycle_write(temp_database, mode):
    """The fee rejects the request after it is parked. The un-park is disabled,
    so only the fork keeps the request out of the block lifecycle."""
    request = _request()
    tx = _request_tx(request)
    with patch("consensus.approvals.ApprovalRequestLifecycleManager.withdraw_request",
               return_value=False) as no_undo:
        mined = _apply_block([tx], mode, block_o5=True)
    empty = _apply_block([], mode, block_o5=True)

    assert no_undo.called, _logs(mined, tx)
    _assert_no_trace(mined, empty, tx)
    assert request.request_id not in _lifecycle_of(mined).approval_requests.open_requests


@pytest.mark.parametrize("mode", MODES)
def test_a_rejected_retractable_park_leaves_no_lifecycle_write(temp_database, mode):
    tx = _park_tx()
    mined = _apply_block([tx], mode)
    empty = _apply_block([], mode)

    assert "Fee 500 exceeds fee_limit 100" in _logs(mined, tx)
    _assert_no_trace(mined, empty, tx)
    assert _lifecycle_of(mined).retractable_transfers.open == {}


@pytest.mark.parametrize("mode", MODES)
def test_a_rejected_governance_update_leaves_no_lifecycle_write(temp_database, mode):
    tx = _update_tx(signer_sk=SK_BOB)
    mined = _apply_block([tx], mode)
    empty = _apply_block([], mode)

    _assert_no_trace(mined, empty, tx)
    assert _lifecycle_of(mined).pending_updates == set()


@pytest.mark.parametrize("mode", MODES)
def test_an_accepted_governance_update_is_recorded(temp_database, mode):
    tx = _update_tx()
    mined = _apply_block([tx], mode)
    empty = _apply_block([], mode)

    assert mined.invalid_tx_ids == [], _logs(mined, tx)
    assert _update().update_id in _lifecycle_of(mined).pending_updates
    assert mined.next_snapshot.state_hash != empty.next_snapshot.state_hash


@pytest.mark.parametrize("mode", MODES)
@pytest.mark.parametrize("cause", ["fee", "composite"])
def test_a_rejected_offer_accept_leaves_no_lifecycle_write(temp_database, mode, cause):
    """The accept resolves the offer and registers the clause before the
    composite runs and before the fee settles."""
    offer = _offer()
    seed = lambda lm: lm.rule_offers.submit_offer(offer)  # noqa: E731
    if cause == "fee":
        session_args = {"fee": "500"}
    else:
        session_args = {"fee": "0", "rule_accepted": False}
    tx = _decision_tx(offer, accept=True)
    mined = _apply_block([tx], mode, seed=seed, **session_args)
    empty = _apply_block([], mode, seed=seed, **session_args)

    _assert_no_trace(mined, empty, tx)
    offers = _lifecycle_of(mined).rule_offers
    assert offer.offer_id in offers.offered
    assert offers.accepted_clauses == {}


@pytest.mark.parametrize("mode", MODES)
def test_a_rejected_offer_reject_leaves_no_lifecycle_write(temp_database, mode):
    """The reject resolves the offer before the fee settles."""
    offer = _offer()
    seed = lambda lm: lm.rule_offers.submit_offer(offer)  # noqa: E731
    tx = _decision_tx(offer, accept=False)
    mined = _apply_block([tx], mode, seed=seed)
    empty = _apply_block([], mode, seed=seed)

    assert "Fee 500 exceeds fee_limit 100" in _logs(mined, tx)
    _assert_no_trace(mined, empty, tx)
    offers = _lifecycle_of(mined).rule_offers
    assert offer.offer_id in offers.offered
    assert offer.offer_id not in offers.resolved


@pytest.mark.parametrize("mode", MODES)
def test_an_accepted_offer_reject_resolves_the_offer(temp_database, mode):
    offer = _offer()
    seed = lambda lm: lm.rule_offers.submit_offer(offer)  # noqa: E731
    tx = _decision_tx(offer, accept=False, fee_limit="10000")
    mined = _apply_block([tx], mode, seed=seed)

    assert mined.invalid_tx_ids == [], _logs(mined, tx)
    offers = _lifecycle_of(mined).rule_offers
    assert offer.offer_id not in offers.offered
    assert offer.offer_id in offers.resolved


# --- a rejected and an accepted transaction from one sender -------------------

@pytest.mark.parametrize("mode", MODES)
def test_a_rejected_then_accepted_tx_from_one_sender(temp_database, mode):
    """The rejected offer takes no sequence number, so the next one reuses 0."""
    dropped, kept = _offer(), _offer(expire=EXPIRE + 1)
    rejected_tx = _offer_tx(dropped, fee_limit="100")
    accepted_tx = _offer_tx(kept, fee_limit="10000")
    mined = _apply_block([rejected_tx, accepted_tx], mode)
    alone = _apply_block([accepted_tx], mode)

    assert mined.invalid_tx_ids == [rejected_tx["tx_id"]]
    assert alone.invalid_tx_ids == []
    assert mined.next_snapshot.state_hash == alone.next_snapshot.state_hash
    assert set(_lifecycle_of(mined).rule_offers.offered) == {kept.offer_id}
    assert mined.next_snapshot.metadata["sequence_numbers"] == {ALICE: 1}


# --- the two apply paths agree ------------------------------------------------

def _offer_block():
    offer = _offer()
    return [
        _offer_tx(offer, fee_limit="100"),
        _offer_tx(_offer(expire=EXPIRE + 1), fee_limit="10000"),
    ], {}


def _decision_block():
    first, second = _offer(), _offer(expire=EXPIRE + 1)

    def seed(lm):
        lm.rule_offers.submit_offer(first)
        lm.rule_offers.submit_offer(second)

    return [
        _decision_tx(first, accept=False, fee_limit="10000"),
        _decision_tx(second, accept=True, fee_limit="100", seq=1),
    ], {"seed": seed}


def _park_block():
    return [_park_tx(fee_limit="100"), _park_tx(fee_limit="10000")], {}


def _governance_block():
    return [_update_tx(signer_sk=SK_BOB), _update_tx()], {}


def _approval_block():
    return [_request_tx(_request(), fee_limit="10000")], {"block_o5": True}


BLOCKS = {
    "offers": _offer_block,
    "decisions": _decision_block,
    "parks": _park_block,
    "governance": _governance_block,
    "approval": _approval_block,
}


@pytest.mark.parametrize("name", sorted(BLOCKS))
def test_both_apply_paths_give_the_same_state_hash(temp_database, name):
    txs, args = BLOCKS[name]()
    by_proposal = _apply_block(txs, "proposal", **args)
    direct = _apply_block(txs, "direct", **args)
    empty = _apply_block([], "direct", **args)

    assert by_proposal.invalid_tx_ids == direct.invalid_tx_ids
    assert len(direct.invalid_tx_ids) < len(txs), direct.outcomes
    assert direct.next_snapshot.state_hash != empty.next_snapshot.state_hash
    assert by_proposal.next_snapshot.state_hash == direct.next_snapshot.state_hash
