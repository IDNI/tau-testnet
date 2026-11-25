"""The rule-change guard at both policy-change doors (the op-0 o5 rule and the
offer accept), at admission and at block apply."""
import pytest

import tau_defs
from consensus import sender_policy
from consensus.admission import validate_mempool_admission
from consensus.approvals import STATUS_OPEN, ApprovalRequest
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import STATUS_OFFERED

import test_clause_domain_apply_screen as h
from test_clause_domain_apply_screen import (  # noqa: F401  (fixture)
    ALICE, MALLORY, tip_view,
)

GUARD_KEY = (ALICE, tau_defs.RULE_CHANGE_GUARD_INDEX)
GUARD = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
SET_TEXT = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
REVOKE_TEXT = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
EXISTING = "(o5[t]:bv[24] = { #x000000 }:bv[24])"

NEEDS_APPROVAL = "rule_change_needs_approval"
DOORS = ["set", "revoke", "accept"]
KIND = {"set": "1", "revoke": "2", "accept": "3"}

MODES = {
    "none": lambda inputs: "1",
    "all": lambda inputs: "0",
    "kind2": lambda inputs: "0" if inputs.get("i1") == "2" else "1",
}


def _blocks(mode, door):
    return MODES[mode]({"i1": KIND[door]}) == "0"


@pytest.fixture(autouse=True)
def evaluators():
    evs = {}
    for pool in ("apply", "admission"):
        evs[pool] = MockPolicyEvaluator(pool=pool)
        sender_policy.set_evaluator(pool, evs[pool])
    yield evs
    for pool in evs:
        sender_policy.set_evaluator(pool, None)


def _install(evs, mode):
    for ev in evs.values():
        ev.set_verdict(GUARD, MODES[mode])


def _lm(door, guard=True, request=False):
    lm = h._lifecycle(slots=True, open_offer=SET_TEXT if door == "accept" else None)
    if door == "revoke":
        lm.rule_offers.accepted_clauses[(ALICE, 5)] = EXISTING
    if guard:
        lm.rule_offers.accepted_clauses[GUARD_KEY] = GUARD
    if request:
        req = ApprovalRequest(
            sender_pubkey=ALICE, recipient_pubkey=MALLORY, amount=5,
            sequence_number=0, expire_at_height=500,
            approvers={18: MALLORY}, custom_inputs={},
        )
        lm.approval_requests.submit_request(req)
        return lm, req
    return lm


def _apply_door(door, lm):
    if door == "set":
        return ("rule", *h._apply(h._rule_tx(SET_TEXT), lm))
    if door == "revoke":
        return ("rule", *h._apply(h._rule_tx(REVOKE_TEXT), lm))
    return ("accept", *h._apply(h._accept_tx(SET_TEXT), lm))


def _admit_door(door, tip_view, guard=True):
    tip_view.clause_for.side_effect = (
        lambda who, idx: GUARD if guard and idx == tau_defs.RULE_CHANGE_GUARD_INDEX
        else None
    )
    tip_view.next_block_timestamp = 1234567890
    if door == "set":
        return validate_mempool_admission(h._user_tx(SET_TEXT), tip_view)
    if door == "revoke":
        return validate_mempool_admission(h._user_tx(REVOKE_TEXT), tip_view)
    return h._admit("accept", SET_TEXT, tip_view)


def _landed(door, post):
    if door == "set":
        return post.rule_offers.clause_for(ALICE, 5) is not None
    if door == "revoke":
        return post.rule_offers.clause_for(ALICE, 5) is None
    return post.rule_offers.clause_for(ALICE, 5) is not None


@pytest.mark.parametrize("door", DOORS)
def test_without_a_guard_nothing_changes(evaluators, tip_view, door):
    admitted = _admit_door(door, tip_view, guard=False)
    tx_id, result, post, _ = _apply_door(door, _lm(door, guard=False))
    assert admitted.is_valid
    assert tx_id in result.accepted_tx_ids
    assert _landed(door, post)
    assert not evaluators["apply"].verdict_calls
    assert not evaluators["admission"].verdict_calls


@pytest.mark.parametrize("mode", list(MODES))
@pytest.mark.parametrize("door", DOORS)
def test_admission_and_apply_agree_on_the_guard_verdict(evaluators, tip_view, door, mode):
    _install(evaluators, mode)
    admitted = _admit_door(door, tip_view)
    tx_id, result, post, _ = _apply_door(door, _lm(door))

    blocked = _blocks(mode, door)
    assert admitted.is_valid is (not blocked)
    assert (tx_id in result.invalid_tx_ids) is blocked
    assert _landed(door, post) is (not blocked)
    if blocked:
        assert admitted.code == "RULE_CHANGE_NEEDS_APPROVAL"
        assert h._outcome(result, tx_id).reason == NEEDS_APPROVAL
        assert result.accepted_tx_ids == []


@pytest.mark.parametrize("door", DOORS)
def test_the_guard_is_fed_the_kind_the_timestamp_and_empty_slots(evaluators, tip_view, door):
    _install(evaluators, "none")
    _admit_door(door, tip_view)
    _apply_door(door, _lm(door))
    for pool in ("admission", "apply"):
        body, inputs = evaluators[pool].verdict_calls[0]
        assert body == GUARD
        assert inputs == sender_policy.change_inputs(int(KIND[door]), 1234567890)


@pytest.mark.parametrize("door", ["set", "revoke"])
def test_a_blocked_rule_change_leaves_open_requests_alone(evaluators, door):
    _install(evaluators, "all")
    lm, req = _lm(door, request=True)
    before = lm.rule_offers.clause_for(ALICE, 5)
    _, result, post, _ = _apply_door(door, lm)
    assert post.rule_offers.clause_for(ALICE, 5) == before
    assert post.approval_requests.get_request(req.request_id) is not None
    assert post.approval_requests.terminal_status[req.request_id] == STATUS_OPEN


def test_a_blocked_accept_keeps_the_offer_open_and_acceptable(evaluators):
    _install(evaluators, "all")
    lm, req = _lm("accept", request=True)
    offer_id = h._offer(SET_TEXT).offer_id
    _, result, post, _ = _apply_door("accept", lm)

    assert post.rule_offers.clause_for(ALICE, 5) is None
    assert post.rule_offers.get_offer(offer_id) is not None
    assert offer_id in post.rule_offers.offered
    assert offer_id not in post.rule_offers.resolved
    assert post.rule_offers.terminal_status[offer_id] == STATUS_OFFERED
    assert post.approval_requests.get_request(req.request_id) is not None

    post.rule_offers.accepted_clauses.pop(GUARD_KEY)
    tx_id, result, later, _ = _apply_door("accept", post)
    assert result.accepted_tx_ids == [tx_id]
    assert later.rule_offers.clause_for(ALICE, 5) is not None


def test_rejecting_an_offer_never_consults_the_guard(evaluators, tip_view):
    _install(evaluators, "all")
    tip_view.clause_for.side_effect = lambda who, idx: GUARD
    tip_view.next_block_timestamp = 1234567890
    tip_view.get_offer.return_value = h._open_offer_row(SET_TEXT)
    payload = {"tx_type": "rule_offer_reject", "expire_at_height": 5000,
               "sender_pubkey": ALICE, "offer_id": h._offer(SET_TEXT).offer_id_hex}
    assert validate_mempool_admission(payload, tip_view).is_valid

    lm = _lm("accept")
    tx = h._base("reject", "rule_offer_reject", ALICE, 0)
    tx.update(offer_id=h._offer(SET_TEXT).offer_id_hex)
    result, post, _ = h._apply(h.sign_tx(tx, h.SK_ALICE), lm)
    assert result.accepted_tx_ids == ["reject"]
    assert post.rule_offers.get_offer(h._offer(SET_TEXT).offer_id) is None
    assert not evaluators["apply"].verdict_calls
    assert not evaluators["admission"].verdict_calls


@pytest.mark.parametrize("door", DOORS)
def test_a_guard_that_does_not_build_blocks(evaluators, tip_view, door):
    for ev in evaluators.values():
        ev.fail_build(GUARD)
    admitted = _admit_door(door, tip_view)
    tx_id, result, post, _ = _apply_door(door, _lm(door))
    assert not admitted.is_valid
    assert admitted.code == "RULE_CHANGE_NEEDS_APPROVAL"
    assert tx_id in result.invalid_tx_ids
    assert h._outcome(result, tx_id).reason == NEEDS_APPROVAL
    assert not _landed(door, post)


def test_the_timestamp_input_is_derived_from_its_stream_name():
    from consensus.admission import GUARD_READABLE_INPUTS
    assert int(tau_defs.TAU_INPUT_STREAM_TIMESTAMP[1:]) in GUARD_READABLE_INPUTS


# --- the payout doors (stage 2) ------------------------------------------------
# Installing, removing or updating a payout rule decides whose hands
# a registered clause's legs land in, so all three travel the guard
# like the doors above. The update's kind is the request kind (6):
# the direct transaction and the guarded request path judge the
# change by the same number.

from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_tx  # noqa: E402
from consensus.payouts import PayoutTerms  # noqa: E402

BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)

PAYOUT_DOORS = ["install", "remove", "update"]
PAYOUT_KIND = {"install": "7", "remove": "8", "update": "6"}
PAYOUT_ANCHOR = 1234560000
PAYOUT_TS = 1234567890

PAYOUT_MODES = {
    "none": lambda inputs: "1",
    "all": lambda inputs: "0",
    "kind6": lambda inputs: "0" if inputs.get("i1") == "6" else "1",
    "kind7": lambda inputs: "0" if inputs.get("i1") == "7" else "1",
    "kind8": lambda inputs: "0" if inputs.get("i1") == "8" else "1",
}


def _payout_blocks(mode, door):
    return PAYOUT_MODES[mode]({"i1": PAYOUT_KIND[door]}) == "0"


def _install_payout_mode(evs, mode):
    for ev in evs.values():
        ev.set_verdict(GUARD, PAYOUT_MODES[mode])


def _payout_terms(recipients=(CAROL,)):
    return PayoutTerms(
        owner=ALICE, max_per_execution=1000, max_per_period=1500,
        recipients=recipients, period_kind=1, anchor_ts=PAYOUT_ANCHOR,
        sequence_number=0,
    )


def _payout_row():
    terms = _payout_terms()
    return {
        "rule_id": terms.rule_id, "owner": ALICE,
        "anchor_ts": PAYOUT_ANCHOR, "period_kind": 1,
        "spent_in_period": 0, "period_index": 0, "total_spent": 0,
        "sealed": False, "version": 1,
    }


def _payout_install_payload(recipients=(MALLORY,)):
    return {
        "tx_type": "payout_rule_install", "expire_at_height": 5000,
        "sender_pubkey": ALICE, "max_per_execution": 1000,
        "max_per_period": 1500, "recipients": list(recipients),
        "period_kind": 1, "anchor_ts": PAYOUT_ANCHOR, "sequence_number": 0,
    }


def _payout_update_fields(recipients=(MALLORY,)):
    return {
        "rule_id": _payout_terms().rule_id,
        "max_per_execution": 1000, "max_per_period": 1500,
        "recipients": list(recipients), "period_kind": 1,
        "anchor_ts": PAYOUT_ANCHOR, "terms_sequence_number": 2,
    }


def _payout_install_tx(recipients=(MALLORY,)):
    tx = h._base("payout-install", "payout_rule_install", ALICE, 0)
    tx.update(
        max_per_execution=1000, max_per_period=1500,
        recipients=list(recipients), period_kind=1,
        anchor_ts=PAYOUT_ANCHOR, sequence_number=0,
    )
    return sign_tx(tx, SK_ALICE)


def _payout_remove_tx():
    tx = h._base("payout-remove", "payout_rule_remove", ALICE, 0)
    tx.update(rule_id=_payout_terms().rule_id)
    return sign_tx(tx, SK_ALICE)


def _payout_update_tx(recipients=(MALLORY,)):
    tx = h._base("payout-update", "payout_rule_update", ALICE, 0)
    tx.update(_payout_update_fields(recipients))
    return sign_tx(tx, SK_ALICE)


def _lm_payout(door, guard=True):
    lm = h._lifecycle(slots=True)
    if door in ("remove", "update"):
        lm.payout_rules.install(_payout_terms())
    if guard:
        lm.rule_offers.accepted_clauses[GUARD_KEY] = GUARD
    return lm


def _apply_payout_door(door, lm):
    if door == "install":
        return ("payout-install", *h._apply(_payout_install_tx(), lm))
    if door == "remove":
        return ("payout-remove", *h._apply(_payout_remove_tx(), lm))
    return ("payout-update", *h._apply(_payout_update_tx(), lm))


def _admit_payout_door(door, tip_view, guard=True):
    tip_view.clause_for.side_effect = (
        lambda who, idx: GUARD if guard and idx == tau_defs.RULE_CHANGE_GUARD_INDEX
        else None
    )
    tip_view.next_block_timestamp = PAYOUT_TS
    if door == "install":
        tip_view.get_payout_rule.return_value = None
        tip_view.payout_rule_count.return_value = 0
        return validate_mempool_admission(_payout_install_payload(), tip_view)
    tip_view.get_payout_rule.return_value = _payout_row()
    if door == "remove":
        payload = {
            "tx_type": "payout_rule_remove", "expire_at_height": 5000,
            "sender_pubkey": ALICE, "rule_id": _payout_terms().rule_id,
        }
        return validate_mempool_admission(payload, tip_view)
    payload = {
        "tx_type": "payout_rule_update", "expire_at_height": 5000,
        "sender_pubkey": ALICE, **_payout_update_fields(),
    }
    return validate_mempool_admission(payload, tip_view)


def _payout_landed(door, post):
    state = post.payout_rules.get(ALICE)
    if door == "install":
        return state is not None
    if door == "remove":
        return state is None
    return state is not None and state.terms.recipients == (MALLORY,)


@pytest.mark.parametrize("door", PAYOUT_DOORS)
def test_payout_doors_without_a_guard_nothing_changes(evaluators, tip_view, door):
    admitted = _admit_payout_door(door, tip_view, guard=False)
    tx_id, result, post, _ = _apply_payout_door(door, _lm_payout(door, guard=False))
    assert admitted.is_valid
    assert tx_id in result.accepted_tx_ids
    assert _payout_landed(door, post)
    assert not evaluators["apply"].verdict_calls
    assert not evaluators["admission"].verdict_calls


@pytest.mark.parametrize("mode", list(PAYOUT_MODES))
@pytest.mark.parametrize("door", PAYOUT_DOORS)
def test_payout_doors_admission_and_apply_agree(evaluators, tip_view, door, mode):
    _install_payout_mode(evaluators, mode)
    admitted = _admit_payout_door(door, tip_view)
    tx_id, result, post, _ = _apply_payout_door(door, _lm_payout(door))

    blocked = _payout_blocks(mode, door)
    assert admitted.is_valid is (not blocked)
    assert (tx_id in result.invalid_tx_ids) is blocked
    assert _payout_landed(door, post) is (not blocked)
    if blocked:
        assert admitted.code == "RULE_CHANGE_NEEDS_APPROVAL"
        assert h._outcome(result, tx_id).reason == NEEDS_APPROVAL
        assert result.accepted_tx_ids == []


@pytest.mark.parametrize("door", PAYOUT_DOORS)
def test_payout_doors_guard_is_fed_the_kind_and_timestamp(evaluators, tip_view, door):
    _install_payout_mode(evaluators, "none")
    _admit_payout_door(door, tip_view)
    _apply_payout_door(door, _lm_payout(door))
    for pool in ("admission", "apply"):
        body, inputs = evaluators[pool].verdict_calls[0]
        assert body == GUARD
        assert inputs == sender_policy.change_inputs(
            int(PAYOUT_KIND[door]), PAYOUT_TS)


def test_a_blocked_payout_install_leaves_the_installed_rule_alone(evaluators):
    _install_payout_mode(evaluators, "all")
    lm = h._lifecycle(slots=True)
    lm.payout_rules.install(_payout_terms(recipients=(BOB,)))
    lm.rule_offers.accepted_clauses[GUARD_KEY] = GUARD
    tx_id, result, post, _ = (
        "payout-install", *h._apply(_payout_install_tx(recipients=(MALLORY,)), lm))
    assert tx_id in result.invalid_tx_ids
    assert h._outcome(result, tx_id).reason == NEEDS_APPROVAL
    assert post.payout_rules.owner_rule_count(ALICE) == 1
    assert post.payout_rules.get(ALICE).terms.recipients == (BOB,)


def test_errnex_shape_blocked_install_and_update_cannot_divert_a_route(evaluators):
    """errnex's #128 shape, adapted: BOB's route clause already pays
    90% to recipient index 0 and his guard blocks every rule change.
    Both remaining doors to the payee -- a fresh install naming
    MALLORY and a direct update rewriting the rule's recipients --
    must be refused, so a 1,000 credit still lands 900 on CAROL."""
    import test_payout_triggers as t
    from test_payout_stage2_apply import update_tx as stage2_update_tx

    evaluators["apply"].set_verdict(GUARD, PAYOUT_MODES["all"])
    ch = t.Chain({t.ALICE: 10_000, t.BOB: 0, t.CAROL: 0, t.MALLORY: 0,
                  t.PROPOSER: 0})
    terms = ch.install_rule(t.BOB, t.SK_BOB, height=20, recipients=[t.CAROL],
                            extra={"on_arrival": True})
    ch.lm.rule_offers.accepted_clauses[
        (t.BOB, tau_defs.RULE_CHANGE_GUARD_INDEX)] = GUARD

    attack_install = t.install_tx(owner=t.BOB, sk=t.SK_BOB, seq=1,
                                  recipients=[t.MALLORY],
                                  extra={"on_arrival": True})
    ch.block([attack_install], height=21, ts=t.NOW)
    assert not ch.accepted(attack_install)
    assert ch.receipt(attack_install)["reason"] == NEEDS_APPROVAL

    attack_update = stage2_update_tx(
        {"max_per_execution": 1000, "max_per_period": 1500,
         "recipients": [t.MALLORY], "period_kind": 2, "anchor_ts": t.JAN1},
        terms.rule_id, owner=t.BOB, sk=t.SK_BOB, seq=1)
    ch.block([attack_update], height=22, ts=t.NOW)
    assert not ch.accepted(attack_update)
    assert ch.receipt(attack_update)["reason"] == NEEDS_APPROVAL
    assert ch.book.get_rule(t.BOB, terms.rule_id).terms.recipients == (t.CAROL,)
    assert any(body == GUARD for body, _ in evaluators["apply"].verdict_calls)

    ch.legs_fn = t._pct(90)
    pay = t.transfer_tx(t.BOB, 1000, t.SK_ALICE, sender=t.ALICE, seq=0)
    ch.block([pay], height=23, ts=t.NOW)
    assert ch.accepted(pay)
    assert ch.bal[t.MALLORY] == 0
    assert ch.bal[t.CAROL] == 900
    assert ch.bal[t.BOB] == 100
