"""Families 4 and 5: the approval book and the offer book are branched too.

Both paths record something in the lifecycle manager and can then lose the
transaction at fee settlement. They differ in how visible that was:

* The approval request already had a hand-written compensation -- a
  `withdraw_request` un-park after settlement. These tests DISABLE it, so what
  they measure is the branch rather than the compensation.
* The rule offer had no compensation at all. A submitted offer whose fee is
  never paid stayed in consensus state, having paid nothing. That one fails
  outright without the branch.

Driven with a scripted session rather than the real engine: what is under test
is ownership of lifecycle state, and a native interpreter would only add ways
for the test to be flaky about something it is not asserting.
"""
import hashlib
import itertools

import pytest
from py_ecc.bls import G2Basic
from unittest.mock import MagicMock, patch

import tau_allocator as alloc
import tau_defs
import tau_journal as tj
import tau_proposal as tp
import tau_reconstruction as tr
from consensus.approvals import ApprovalRequest
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import RuleOffer
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
_TX_SEQ = itertools.count()


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_AUTH, AUTH = _key(22222)
SK_BOB, BOB = _key(44444)
PROPOSER = "d4" * 48
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


# --- the scripted evaluator ---------------------------------------------------

class _Session:
    """Answers the apply path deterministically.

    `o5` BLOCKS, so an approval request is genuinely gated and gets parked
    rather than waved through; `o9` prices it above the transaction's fee_limit,
    which is what rejects the transaction AFTER the lifecycle mutation.
    """

    is_speculative = True

    def __init__(self, fee="500", rule_accepted=True):
        self.fee = fee
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
        outputs = {
            tau_defs.USER_POLICY_STREAM_INDEX: str(tau_defs.USER_POLICY_BLOCK_VALUE),
            tau_defs.CONSENSUS_FEE_STREAM_INDEX: self.fee,
        }
        if multi:
            return outputs
        return "" if target is None else outputs.get(target, "")

    def last_receipt(self):
        if self.rule_accepted:
            return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}
        return {"accepted": False, "outcome": "REJECTED_RULE"}

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


def _run(txs, lifecycle, *, fee="500", rule_accepted=True):
    session = _Session(fee=fee, rule_accepted=rule_accepted)
    proposal = _proposal(lifecycle, session)
    engine = TauConsensusEngine(state_store=MagicMock())
    with patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            txs, 1700000000,
            target_balances={ALICE: 100000, BOB: 100000},
            target_sequences={},
            target_lifecycle=lifecycle,
            proposer_pubkey=PROPOSER,
            block_height=HEIGHT,
            proposal=proposal,
            session=session,
        )
    return proposal, result, session


# --- family 4: approval request -----------------------------------------------

def _request(amount=5000):
    return ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=amount,
        sequence_number=0, expire_at_height=EXPIRE,
        approvers={18: AUTH}, custom_inputs={},
    )


def _request_tx(request, fee_limit="100"):
    tx = {
        "tx_id": f"req-{next(_TX_SEQ)}",
        "tx_type": "approval_request",
        "sender_pubkey": request.sender_pubkey,
        "sequence_number": request.sequence_number,
        "expiration_time": 9999999999,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": request.recipient_pubkey,
        "amount": request.amount,
        "expire_at_height": request.expire_at_height,
        "approvers": {str(k): v for k, v in request.approvers.items()},
        "custom_inputs": {},
    }
    return _sign(tx, SK_ALICE)


def test_a_parked_request_does_not_survive_its_fee_rejection(temp_database):
    """The fee (500) exceeds the transaction's limit (100), so the request is
    parked and then the transaction is rejected."""
    lifecycle = _lifecycle()
    request = _request()
    proposal, result, session = _run([_request_tx(request)], lifecycle)

    assert result.rejected_transactions, "the transaction was supposed to be rejected"
    assert request.request_id not in lifecycle.approval_requests.open_requests, \
        "a rejected transaction left its approval request parked in consensus state"


def test_the_branch_not_the_compensation_is_what_un_parks_it(temp_database):
    """Disable the hand-written un-park and the request must STILL not survive.

    Otherwise this family's safety rests on somebody having remembered to write
    an inverse mutation for one particular path, which is the arrangement the
    whole refactor exists to replace.
    """
    lifecycle = _lifecycle()
    request = _request()
    with patch("consensus.approvals.ApprovalRequestLifecycleManager.withdraw_request",
               return_value=False) as no_undo:
        proposal, result, session = _run([_request_tx(request)], lifecycle)

    assert result.rejected_transactions
    assert no_undo.called, "the compensation was not exercised, so it proves nothing"
    assert request.request_id not in lifecycle.approval_requests.open_requests, \
        "without the compensation the parked request survived its rejection"


def test_an_affordable_request_still_parks(temp_database):
    """Guard the guard: ownership must not stop an accepted request landing."""
    lifecycle = _lifecycle()
    request = _request()
    proposal, result, session = _run([_request_tx(request, fee_limit="10000")], lifecycle)

    assert result.accepted_transactions, f"expected acceptance: {result.receipts}"
    assert request.request_id in lifecycle.approval_requests.open_requests, \
        "an accepted request was not parked"


# --- family 5: rule offer -----------------------------------------------------

def _offer():
    return RuleOffer(offerer_pubkey=ALICE, recipient_pubkey=BOB,
                     rule_text=OFFER_RULE, expire_at_height=EXPIRE)


def _offer_tx(offer, fee_limit="100"):
    return {
        "tx_id": f"offer-{next(_TX_SEQ)}",
        "tx_type": "rule_offer",
        "sender_pubkey": offer.offerer_pubkey,
        "sequence_number": 0,
        "recipient_pubkey": offer.recipient_pubkey,
        "rule_text": offer.rule_text,
        "expire_at_height": offer.expire_at_height,
        "fee_limit": str(fee_limit),
    }


def test_a_submitted_offer_does_not_survive_its_fee_rejection(temp_database):
    """No compensation ever existed for this one.

    A rule offer is fee-bearing, so the transaction that submits it can be
    rejected at settlement -- and the offer stayed in the book anyway, recorded
    in consensus state having paid nothing for the privilege.
    """
    lifecycle = _lifecycle()
    offer = _offer()
    proposal, result, session = _run([_offer_tx(offer)], lifecycle)

    assert result.rejected_transactions, "the transaction was supposed to be rejected"
    assert offer.offer_id not in lifecycle.rule_offers.offered, \
        "a rejected transaction left its rule offer in the book"
    assert offer.offer_id not in lifecycle.rule_offers.resolved


def test_an_affordable_offer_still_lands(temp_database):
    lifecycle = _lifecycle()
    offer = _offer()
    proposal, result, session = _run([_offer_tx(offer, fee_limit="10000")], lifecycle)

    assert result.accepted_transactions, f"expected acceptance: {result.receipts}"
    assert offer.offer_id in lifecycle.rule_offers.offered, \
        "an accepted offer was not recorded"


def _accept_tx(offer, fee_limit="10000"):
    return {
        "tx_id": f"accept-{next(_TX_SEQ)}",
        "tx_type": "rule_offer_accept",
        "sender_pubkey": offer.recipient_pubkey,
        "sequence_number": 0,
        "offer_id": offer.offer_id_hex,
        "rule_text": offer.rule_text,
        "fee_limit": str(fee_limit),
    }


def test_a_rejected_composite_leaves_the_offer_book_untouched(temp_database):
    """`submit_decision` runs BEFORE the composite is evaluated.

    So an accept whose composite the engine refuses has already resolved the
    offer and registered the acceptor's clause by the time the transaction
    hard-rejects. Ownership is the only thing that takes that back -- the
    decision was recorded on a clone.
    """
    lifecycle = _lifecycle()
    offer = _offer()
    # Park the offer with an affordable transaction first.
    _run([_offer_tx(offer, fee_limit="10000")], lifecycle)
    assert offer.offer_id in lifecycle.rule_offers.offered

    proposal, result, session = _run(
        [_accept_tx(offer)], lifecycle, rule_accepted=False,
    )

    assert result.rejected_transactions, "a refused composite must hard-reject"
    assert session.rules_seen, "the composite was never evaluated, so this proves nothing"
    assert offer.offer_id in lifecycle.rule_offers.offered, \
        "a rejected acceptance resolved the offer anyway"
    assert offer.offer_id not in lifecycle.rule_offers.resolved
    assert lifecycle.rule_offers.accepted_clauses == {}, \
        "a rejected acceptance registered the acceptor's clause"


def test_an_accepted_offer_still_registers_its_clause(temp_database):
    lifecycle = _lifecycle()
    offer = _offer()
    _run([_offer_tx(offer, fee_limit="10000")], lifecycle)

    proposal, result, session = _run([_accept_tx(offer)], lifecycle)

    assert result.accepted_transactions, f"expected acceptance: {result.receipts}"
    assert offer.offer_id in lifecycle.rule_offers.resolved
    assert (BOB.lower(), tau_defs.USER_POLICY_STREAM_INDEX) \
        in lifecycle.rule_offers.accepted_clauses, \
        "an accepted offer did not register the acceptor's clause"
