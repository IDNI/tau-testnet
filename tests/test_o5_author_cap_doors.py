"""Both doors into the o5 clause registry honor the same author cap.

Self-service (an op-"0" rule routed into the registry) and offer-accept feed ONE
derived composite. Once approval slots are active, `MAX_TIER_AUTHORS` bounds the
registry at admission and at apply regardless of which door a clause came in by.
Before activation only the consensus-frozen `MAX_ACCEPTORS_PER_STREAM` applies,
and the golden hashes below pin that replay.
"""
import hashlib

import pytest
from unittest.mock import MagicMock, patch
from py_ecc.bls import G2Basic

from block import Block
from consensus.admission import (
    TipAdmissionView,
    validate_mempool_admission,
    validate_o5_clause_routing,
)
from consensus.approvals import MAX_TIER_AUTHORS
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import (
    MAX_ACCEPTORS_PER_STREAM,
    STATUS_ACCEPTED,
    STATUS_OFFERED,
    STATUS_REJECTED,
    RuleOffer,
    RuleOfferDecision,
    RuleOfferLifecycleManager,
    clause_author_cap,
    clause_body_v1,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
O5 = 5


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(77777)
SK_MALLORY, MALLORY = _key(66666)    # offerer and block proposer

ALLOW_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
BLOCK_BODY = clause_body_v1(BLOCK_RULE)


def _sign(tx, sk):
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def _base(tx_id, tx_type, sender, seq):
    return {
        "tx_id": tx_id,
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
    }


def offer_tx(tx_id, offer, *, seq, sk=SK_MALLORY):
    tx = _base(tx_id, "rule_offer", offer.offerer_pubkey, seq)
    tx.update(recipient_pubkey=offer.recipient_pubkey, rule_text=offer.rule_text,
              expire_at_height=offer.expire_at_height)
    return _sign(tx, sk)


def accept_tx(tx_id, offer, *, sender, seq, sk):
    tx = _base(tx_id, "rule_offer_accept", sender, seq)
    tx.update(offer_id=offer.offer_id_hex, rule_text=offer.rule_text)
    return _sign(tx, sk)


def rule_tx(tx_id, rule, *, sender, seq, sk):
    tx = _base(tx_id, "user_tx", sender, seq)
    tx["operations"] = {"0": rule}
    return _sign(tx, sk)


def _offer(recipient, text=ALLOW_RULE):
    return RuleOffer(offerer_pubkey=MALLORY, recipient_pubkey=recipient,
                     rule_text=text, expire_at_height=EXPIRE)


def _apply(txs, lm, *, replay_mode=False):
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: 100000, BOB: 100000, CAROL: 100000, MALLORY: 100000},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(MALLORY)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block = Block.create(block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
                         proposer_pubkey=MALLORY, timestamp=1234567890)

    fed = []

    def _single(**kw):
        text = str(kw.get("rule_text") or "")
        if "always" in text:
            fed.append(text)
        return "T"

    def _multi(**kw):
        return {8: "0", 9: "0"}

    with patch("tau_manager.communicate_with_tau", side_effect=_single), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = TauConsensusEngine().apply_block(
            view, block, parent, replay_mode=replay_mode)
    return result, result.next_snapshot.metadata["lifecycle_manager"], fed


def _logs(result, tx_id=None):
    return " | ".join(
        str(line) for o in result.outcomes if tx_id is None or o.tx_id == tx_id
        for line in o.receipt_logs)


def _lm(*, active=True, authors=()):
    lm = ConsensusLifecycleManager(active_validators=[MALLORY])
    if active:
        lm.activate_approval_slots()
    for who in authors:
        lm.rule_offers.accepted_clauses[(who, O5)] = BLOCK_BODY
    return lm


def _others(n):
    return [("%02x" % (i + 1)) * 48 for i in range(n)]


def _pending(lm, *recipients, text=BLOCK_RULE):
    offers = [_offer(who, text) for who in recipients]
    for offer in offers:
        lm.rule_offers.submit_offer(offer)
    return offers


def _registry(post):
    return post.rule_offers.clauses_for_stream(O5)


# --- golden replay pins ------------------------------------------------------

THREE_ACCEPTORS = (
    (ALICE, SK_ALICE, "alice"), (BOB, SK_BOB, "bob"), (CAROL, SK_CAROL, "carol"),
)


def _accepts_block(acceptors):
    offers = [_offer(who) for who, _, _ in acceptors]
    txs = [offer_tx("offer-%s" % name, offer, seq=i)
           for i, (offer, (_, _, name)) in enumerate(zip(offers, acceptors))]
    txs += [accept_tx("accept-%s" % name, offer, sender=who, seq=0, sk=sk)
            for offer, (who, sk, name) in zip(offers, acceptors)]
    return txs


PRE_ACTIVATION_THREE_ACCEPTS_HASH = "a35cd7390ddbc34864a1a72a0238b99ee3546405c9ee8835084c2070b74bc6a5"
ACTIVATED_WITHIN_CAP_HASH = "aad2264f90e6db370e9ffdb9e96db87be9633ac4c3d6889f538068a507ad8f55"


def test_pre_activation_block_registers_three_new_acceptors():
    for replay_mode in (False, True):
        result, post, _ = _apply(_accepts_block(THREE_ACCEPTORS),
                                 _lm(active=False), replay_mode=replay_mode)
        assert len(_registry(post)) == 3
        assert result.invalid_tx_ids == []
        assert result.skipped_tx_ids == []
        assert result.next_snapshot.state_hash == PRE_ACTIVATION_THREE_ACCEPTS_HASH


def test_activated_block_within_the_cap_registers_both_acceptors():
    for replay_mode in (False, True):
        result, post, _ = _apply(_accepts_block(THREE_ACCEPTORS[:MAX_TIER_AUTHORS]),
                                 _lm(), replay_mode=replay_mode)
        assert sorted(_registry(post)) == sorted([ALICE, BOB])
        assert result.invalid_tx_ids == []
        assert result.skipped_tx_ids == []
        assert result.next_snapshot.state_hash == ACTIVATED_WITHIN_CAP_HASH


# --- the shared predicate ----------------------------------------------------

@pytest.mark.parametrize("active, stream, expected", [
    (True, O5, MAX_TIER_AUTHORS),
    (False, O5, MAX_ACCEPTORS_PER_STREAM),
    (True, 6, MAX_ACCEPTORS_PER_STREAM),
    (False, 6, MAX_ACCEPTORS_PER_STREAM),
])
def test_clause_author_cap(active, stream, expected):
    assert clause_author_cap(stream, active) == expected


# --- submit_decision ---------------------------------------------------------

def _decision(mgr, acceptor):
    offer = _offer(acceptor, BLOCK_RULE)
    mgr.submit_offer(offer)
    decision = RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=acceptor,
                                 accept=True, rule_text=offer.rule_text)
    return offer, decision


def _full_manager():
    return RuleOfferLifecycleManager(accepted_clauses={
        (who, O5): BLOCK_BODY for who in _others(MAX_TIER_AUTHORS)})


def test_submit_decision_at_the_tier_cap_is_a_soft_no_op_once_active():
    mgr = _full_manager()
    offer, decision = _decision(mgr, ALICE)
    assert mgr.submit_decision(decision, approval_slots_active=True) is None
    assert (ALICE, O5) not in mgr.accepted_clauses
    assert offer.offer_id in mgr.resolved and offer.offer_id not in mgr.offered
    assert mgr.terminal_status[offer.offer_id] == STATUS_REJECTED


@pytest.mark.parametrize("kwargs", [{}, {"approval_slots_active": False}])
def test_submit_decision_ignores_the_tier_cap_before_activation(kwargs):
    mgr = _full_manager()
    offer, decision = _decision(mgr, ALICE)
    assert mgr.submit_decision(decision, **kwargs) == O5
    assert mgr.accepted_clauses[(ALICE, O5)] == BLOCK_BODY
    assert mgr.terminal_status[offer.offer_id] == STATUS_ACCEPTED


def test_submit_decision_replacement_is_never_capped():
    mgr = RuleOfferLifecycleManager(accepted_clauses={
        (who, O5): "(o5[t]:bv[24] = { #x000001 }:bv[24])"
        for who in [ALICE, *_others(MAX_TIER_AUTHORS - 1)]})
    _, decision = _decision(mgr, ALICE)
    assert mgr.submit_decision(decision, approval_slots_active=True) == O5
    assert mgr.accepted_clauses[(ALICE, O5)] == BLOCK_BODY


def test_submit_decision_below_the_tier_cap_registers_once_active():
    mgr = RuleOfferLifecycleManager(accepted_clauses={
        (who, O5): BLOCK_BODY for who in _others(MAX_TIER_AUTHORS - 1)})
    _, decision = _decision(mgr, ALICE)
    assert mgr.submit_decision(decision, approval_slots_active=True) == O5
    assert (ALICE, O5) in mgr.accepted_clauses


# --- admission: one registry, both doors -------------------------------------

A = "aa" * 48          # offerer
B = "bb" * 48          # recipient / acceptor
NEXT_HEIGHT = 50


@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {A}
    view.next_block_height = NEXT_HEIGHT
    view.eligibility_mode = ""
    view.approval_slots_active = True
    view.get_offer_lifecycle_state.return_value = None
    view.get_offer.return_value = None
    view.pending_offers_for_recipient.return_value = 0
    view.pending_offers_for_offerer.return_value = 0
    _registry_of(view, {})
    return view


def _registry_of(view, clauses):
    clauses = dict(clauses)
    view.clauses_for_stream.side_effect = lambda s: dict(clauses) if s == O5 else {}
    view.clause_author_count.side_effect = lambda s: len(clauses) if s == O5 else 0
    view.clause_for.side_effect = lambda who, s: clauses.get(who) if s == O5 else None


def _full(n, *, also=()):
    return {who: BLOCK_BODY for who in [*_others(n - len(also)), *also]}


def _offer_to(recipient):
    return {
        "tx_type": "rule_offer",
        "sender_pubkey": A,
        "recipient_pubkey": recipient,
        "rule_text": BLOCK_RULE,
        "expire_at_height": EXPIRE,
    }


def _accept_from(view, acceptor):
    offer = RuleOffer(offerer_pubkey=A, recipient_pubkey=acceptor,
                      rule_text=BLOCK_RULE, expire_at_height=EXPIRE)
    view.get_offer.return_value = {
        "offer_id": offer.offer_id_hex,
        "offerer_pubkey": A,
        "recipient_pubkey": acceptor,
        "rule_text": BLOCK_RULE,
        "expire_at_height": EXPIRE,
        "status": STATUS_OFFERED,
    }
    return {
        "tx_type": "rule_offer_accept",
        "expire_at_height": 5000,
        "sender_pubkey": acceptor,
        "offer_id": offer.offer_id_hex,
        "rule_text": BLOCK_RULE,
    }


def _declare_from(sender, rule=BLOCK_RULE):
    return {"tx_type": "user_tx", "sender_pubkey": sender, "operations": {"0": rule}}


def _self_service(view, sender):
    tx = _declare_from(sender)
    return validate_o5_clause_routing(tx, view, BLOCK_RULE)


@pytest.mark.parametrize("held", [MAX_TIER_AUTHORS, MAX_TIER_AUTHORS + 3])
def test_accept_by_a_new_acceptor_is_refused_at_the_tier_cap(tip_view, held):
    _registry_of(tip_view, _full(held))
    res = validate_mempool_admission(_accept_from(tip_view, B), tip_view)
    assert not res.is_valid
    assert res.code == "CLAUSE_REGISTRY_FULL"


def test_accept_replacing_an_own_clause_is_valid_at_the_tier_cap(tip_view):
    _registry_of(tip_view, _full(MAX_TIER_AUTHORS, also=(B,)))
    res = validate_mempool_admission(_accept_from(tip_view, B), tip_view)
    assert res.is_valid, res.error
    assert B in res.data["composite_rule"]


def test_offer_to_a_non_author_is_refused_at_the_tier_cap(tip_view):
    _registry_of(tip_view, _full(MAX_TIER_AUTHORS))
    res = validate_mempool_admission(_offer_to(B), tip_view)
    assert not res.is_valid
    assert res.code == "CLAUSE_REGISTRY_FULL"


def test_offer_to_an_existing_author_is_valid_at_the_tier_cap(tip_view):
    _registry_of(tip_view, _full(MAX_TIER_AUTHORS, also=(B,)))
    res = validate_mempool_admission(_offer_to(B), tip_view)
    assert res.is_valid, res.error


def test_both_doors_refuse_with_the_same_message(tip_view):
    _registry_of(tip_view, _full(MAX_TIER_AUTHORS))
    declared = _self_service(tip_view, B)
    accepted = validate_mempool_admission(_accept_from(tip_view, B), tip_view)
    offered = validate_mempool_admission(_offer_to(B), tip_view)
    assert declared.code == accepted.code == offered.code == "CLAUSE_REGISTRY_FULL"
    assert declared.error == accepted.error == offered.error


@pytest.mark.parametrize("held", [MAX_TIER_AUTHORS, MAX_TIER_AUTHORS + 1])
def test_pre_activation_the_tier_cap_does_not_bind_either_offer_step(tip_view, held):
    tip_view.approval_slots_active = False
    _registry_of(tip_view, _full(held))
    assert validate_mempool_admission(_offer_to(B), tip_view).is_valid
    res = validate_mempool_admission(_accept_from(tip_view, B), tip_view)
    assert res.is_valid, res.error


def test_pre_activation_the_frozen_cap_keeps_its_own_message(tip_view):
    tip_view.approval_slots_active = False
    _registry_of(tip_view, _full(MAX_ACCEPTORS_PER_STREAM))
    res = validate_mempool_admission(_accept_from(tip_view, B), tip_view)
    assert not res.is_valid
    assert res.code != "CLAUSE_REGISTRY_FULL"
    assert f"maximum {MAX_ACCEPTORS_PER_STREAM} accepted clauses" in res.error


# --- apply: the offer door ---------------------------------------------------

def test_accept_by_a_new_acceptor_at_the_cap_is_a_soft_no_op():
    lm = _lm(authors=_others(MAX_TIER_AUTHORS))
    (offer,) = _pending(lm, ALICE)
    tx = accept_tx("accept", offer, sender=ALICE, seq=0, sk=SK_ALICE)
    result, post, fed = _apply([tx], lm)

    assert (ALICE, O5) not in post.rule_offers.accepted_clauses
    assert len(_registry(post)) == MAX_TIER_AUTHORS
    assert offer.offer_id in post.rule_offers.resolved
    assert offer.offer_id not in post.rule_offers.offered
    assert post.rule_offers.terminal_status[offer.offer_id] == STATUS_REJECTED
    assert fed == []
    assert result.invalid_tx_ids == []
    assert "accept" in result.accepted_tx_ids + result.skipped_tx_ids
    assert "clause registry full" in _logs(result, "accept")


def test_accept_replacing_an_own_clause_at_the_cap_registers_and_feeds_a_composite():
    lm = _lm(authors=[ALICE, *_others(MAX_TIER_AUTHORS - 1)])
    (offer,) = _pending(lm, ALICE, text=ALLOW_RULE)
    tx = accept_tx("accept", offer, sender=ALICE, seq=0, sk=SK_ALICE)
    result, post, fed = _apply([tx], lm)

    assert post.rule_offers.clause_for(ALICE, O5) == clause_body_v1(ALLOW_RULE)
    assert len(_registry(post)) == MAX_TIER_AUTHORS
    assert len(fed) == 1 and ALICE in fed[0]
    assert result.invalid_tx_ids == []
    assert "composite applied" in _logs(result, "accept")


def test_pre_activation_a_new_acceptor_ignores_the_tier_cap():
    lm = _lm(active=False, authors=_others(MAX_TIER_AUTHORS))
    (offer,) = _pending(lm, ALICE)
    tx = accept_tx("accept", offer, sender=ALICE, seq=0, sk=SK_ALICE)
    result, post, fed = _apply([tx], lm)

    assert post.rule_offers.clause_for(ALICE, O5) == BLOCK_BODY
    assert len(_registry(post)) == MAX_TIER_AUTHORS + 1
    assert len(fed) == 1 and ALICE in fed[0]
    assert "composite applied" in _logs(result, "accept")


@pytest.mark.parametrize("order", [(ALICE, BOB), (BOB, ALICE)],
                         ids=["alice-first", "bob-first"])
def test_in_one_block_the_first_new_acceptor_takes_the_last_slot(order):
    keys = {ALICE: SK_ALICE, BOB: SK_BOB}
    lm = _lm(authors=_others(MAX_TIER_AUTHORS - 1))
    offers = dict(zip(order, _pending(lm, *order)))
    txs = [accept_tx("accept-%d" % i, offers[who], sender=who, seq=0, sk=keys[who])
           for i, who in enumerate(order)]
    result, post, fed = _apply(txs, lm)

    first, second = order
    assert sorted(_registry(post)) == sorted([*_others(MAX_TIER_AUTHORS - 1), first])
    assert post.rule_offers.terminal_status[offers[first].offer_id] == STATUS_ACCEPTED
    assert post.rule_offers.terminal_status[offers[second].offer_id] == STATUS_REJECTED
    assert len(fed) == 1 and first in fed[0] and second not in fed[0]
    assert result.invalid_tx_ids == []
    assert "clause registry full" in _logs(result, "accept-1")


# --- apply and admission: the two doors share the registry -------------------

def test_a_registry_filled_by_offers_refuses_a_self_service_declare(tip_view):
    _, filled, _ = _apply(_accepts_block(THREE_ACCEPTORS[:MAX_TIER_AUTHORS]), _lm())
    assert len(_registry(filled)) == MAX_TIER_AUTHORS

    declare = rule_tx("declare", BLOCK_RULE, sender=CAROL, seq=0, sk=SK_CAROL)
    result, post, _ = _apply([declare], filled)
    assert result.invalid_tx_ids == ["declare"]
    assert (CAROL, O5) not in post.rule_offers.accepted_clauses
    assert "registry full" in _logs(result, "declare")

    _registry_of(tip_view, _registry(filled))
    refusal = _self_service(tip_view, CAROL)
    assert refusal.code == "CLAUSE_REGISTRY_FULL"


def test_a_registry_filled_by_self_service_refuses_an_offer_accept(tip_view):
    declares = [
        rule_tx("declare-alice", BLOCK_RULE, sender=ALICE, seq=0, sk=SK_ALICE),
        rule_tx("declare-bob", BLOCK_RULE, sender=BOB, seq=0, sk=SK_BOB),
    ]
    result, filled, _ = _apply(declares, _lm())
    assert result.invalid_tx_ids == []
    assert len(_registry(filled)) == MAX_TIER_AUTHORS

    (offer,) = _pending(filled, CAROL)
    accept = accept_tx("accept", offer, sender=CAROL, seq=0, sk=SK_CAROL)
    result, post, fed = _apply([accept], filled)
    assert (CAROL, O5) not in post.rule_offers.accepted_clauses
    assert fed == []
    assert "clause registry full" in _logs(result, "accept")

    _registry_of(tip_view, _registry(filled))
    refusal = validate_mempool_admission(_accept_from(tip_view, CAROL), tip_view)
    assert refusal.code == "CLAUSE_REGISTRY_FULL"
