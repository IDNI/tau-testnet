"""The sender's own o5 clause as a second block condition: the helper, and the
apply, admission and approval-preview sites that go through it (mock mode)."""
import json
import os
import shutil
import tempfile
import time
from contextlib import ExitStack
from unittest.mock import patch

import pytest

import chain_state
import config
import db
import tau_admission
import tau_defs
import tau_policy
from bls_keys import SK_ALICE, pubkey_hex, sign_payload
from commands import getapprovalpreview, sendtx
from consensus import sender_policy
from consensus.policy_mock import MockPolicyEvaluator
from tau_speculation import SpeculationError, WorkerLost, WorkerTimeout

import test_approval_apply as ap
import test_approval_rpc as rpc

POOLS = ("apply", "admission")
CLAUSE = "(i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)


class _Exploding:
    def verdict(self, *a, **k):
        raise AssertionError("the evaluator must not be consulted")


def _blocking(body=CLAUSE, o5="0", pool="apply"):
    ev = MockPolicyEvaluator(pool=pool)
    ev.set_verdict(body, o5)
    return ev


# --- clause_inputs ----------------------------------------------------------

def test_inputs_become_bare_values_keyed_by_stream_name():
    out = sender_policy.clause_inputs({
        1: "2000",
        3: "{ #xabcd }:bv[384]",
        "i4": "{ #x12ef }:bv[384]",
        13: ["5"],
        5: 1700000000,
    })
    assert out == {"i1": "2000", "i3": "#xabcd", "i4": "#x12ef", "i13": "5",
                   "i5": "1700000000"}


def test_a_list_takes_its_first_present_item_and_an_empty_one_is_empty():
    assert sender_policy.clause_inputs({13: [None, "7", "8"], 14: []}) == {
        "i13": "7", "i14": ""}


def test_no_inputs_is_an_empty_map():
    assert sender_policy.clause_inputs({}) == {}
    assert sender_policy.clause_inputs(None) == {}


# --- clause_blocks ----------------------------------------------------------

@pytest.mark.parametrize("body", [None, ""])
def test_no_body_does_not_touch_an_evaluator(body):
    sender_policy.set_evaluator("apply", _Exploding())
    assert sender_policy.clause_blocks(body, {1: "5"}, pool="apply") == (False, "")


def test_a_blocking_verdict_is_reported_with_its_o5_value():
    ev = _blocking()
    sender_policy.set_evaluator("apply", ev)
    blocked, detail = sender_policy.clause_blocks(CLAUSE, {1: "5"}, pool="apply")
    assert blocked is True and detail == "0"
    assert ev.verdict_calls == [(CLAUSE, {"i1": "5"})]


def test_an_allowing_verdict_passes():
    ev = _blocking(o5="1")
    sender_policy.set_evaluator("apply", ev)
    assert sender_policy.clause_blocks(CLAUSE, {1: "5"}, pool="apply") == (False, "1")


def test_an_absent_o5_allows():
    sender_policy.set_evaluator("apply", MockPolicyEvaluator())
    blocked, _ = sender_policy.clause_blocks(CLAUSE, {1: "5"}, pool="apply")
    assert blocked is False


def test_a_clause_that_does_not_build_blocks():
    ev = MockPolicyEvaluator()
    ev.fail_build(CLAUSE, "no good")
    sender_policy.set_evaluator("apply", ev)
    blocked, detail = sender_policy.clause_blocks(CLAUSE, {}, pool="apply")
    assert blocked is True and "no good" in detail


def test_a_clause_the_engine_refuses_to_step_blocks():
    ev = MockPolicyEvaluator()
    ev.fail_step(CLAUSE, "engine says no")
    sender_policy.set_evaluator("apply", ev)
    blocked, detail = sender_policy.clause_blocks(CLAUSE, {}, pool="apply")
    assert blocked is True and detail == tau_policy.PolicyStepError.MESSAGE


@pytest.mark.parametrize("exc", [WorkerLost("gone"), WorkerTimeout("slow")])
def test_loss_of_the_evaluator_propagates(exc):
    class _Lost:
        def verdict(self, *a, **k):
            raise exc

    sender_policy.set_evaluator("apply", _Lost())
    with pytest.raises(type(exc)):
        sender_policy.clause_blocks(CLAUSE, {}, pool="apply")


def test_other_speculation_errors_propagate():
    class _Broken:
        def verdict(self, *a, **k):
            raise SpeculationError("protocol")

    sender_policy.set_evaluator("apply", _Broken())
    with pytest.raises(SpeculationError):
        sender_policy.clause_blocks(CLAUSE, {}, pool="apply")


def test_the_timeout_reaches_the_evaluator():
    seen = {}

    class _Spy:
        def verdict(self, body, inputs, *, timeout):
            seen["timeout"] = timeout
            return tau_policy.PolicyVerdict(blocked=False, o5="1", built=True)

    sender_policy.set_evaluator("apply", _Spy())
    sender_policy.clause_blocks(CLAUSE, {}, pool="apply", timeout=3.5)
    assert seen["timeout"] == 3.5


# --- evaluator() ------------------------------------------------------------

@pytest.mark.parametrize("pool", POOLS)
def test_force_test_gives_a_process_wide_mock_per_pool(pool):
    with patch("tau_manager.is_force_test_enabled", return_value=True):
        first = sender_policy.evaluator(pool)
        assert isinstance(first, MockPolicyEvaluator)
        assert sender_policy.evaluator(pool) is first
        assert first.verdict("x", {}).blocked is False


def test_without_force_test_the_real_pool_is_used():
    sentinel = object()
    with patch("tau_manager.is_force_test_enabled", return_value=False), \
            patch("tau_policy.get_policy_evaluator", return_value=sentinel) as get:
        assert sender_policy.evaluator("admission") is sentinel
    get.assert_called_once_with("admission")


def test_an_override_wins_and_none_restores_the_default():
    mine = MockPolicyEvaluator()
    with patch("tau_manager.is_force_test_enabled", return_value=True):
        default = sender_policy.evaluator("apply")
        sender_policy.set_evaluator("apply", mine)
        assert sender_policy.evaluator("apply") is mine
        assert sender_policy.evaluator("admission") is not mine
        sender_policy.set_evaluator("apply", None)
        assert sender_policy.evaluator("apply") is default


# --- apply ------------------------------------------------------------------

def _transfer_tx(amount, seq=0):
    return ap._sign({
        "tx_id": f"tr-{next(ap._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": ap.ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[ap.ALICE, ap.BOB, str(amount)]]},
    }, ap.SK_ALICE)


def _registered(body=CLAUSE):
    lm = ap._lm()
    if body:
        lm.rule_offers.accepted_clauses[(ap.ALICE, 5)] = body
    return lm


def _reason(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.reason


def test_apply_rejects_a_transfer_the_senders_clause_blocks():
    ev = _blocking()
    sender_policy.set_evaluator("apply", ev)
    tx = _transfer_tx(500)
    result, _lm, calls = ap._apply([tx], lm=_registered())
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == "user_policy_block"
    assert ap._balances(result)[ap.ALICE] == 100000
    assert "sender's own policy clause" in ap._logs(result)
    assert ev.verdict_calls, "the clause must be consulted"


def test_apply_rejects_a_transfer_whose_clause_the_engine_refuses_to_step():
    ev = MockPolicyEvaluator()
    ev.fail_step(CLAUSE, "engine says no")
    sender_policy.set_evaluator("apply", ev)
    tx = _transfer_tx(500)
    result, _lm, _calls = ap._apply([tx], lm=_registered())
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == "user_policy_block"


def test_apply_lets_a_transfer_through_when_the_clause_allows():
    ev = _blocking(o5="1")
    sender_policy.set_evaluator("apply", ev)
    tx = _transfer_tx(500)
    result, _lm, _calls = ap._apply([tx], lm=_registered())
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ap._balances(result)[ap.BOB] == 500


def test_the_evaluator_gets_the_values_the_main_step_got():
    ev = _blocking(o5="1")
    sender_policy.set_evaluator("apply", ev)
    _result, _lm, calls = ap._apply([_transfer_tx(500)], lm=_registered())
    main_values = [c["input_stream_values"] for c in calls
                   if str(c["input_stream_values"].get(1)) == "500"][-1]
    body, inputs = ev.verdict_calls[-1]
    assert body == CLAUSE
    assert inputs == sender_policy.clause_inputs(main_values)
    assert inputs["i12"] == "#x" + ap.ALICE


def test_a_sender_without_a_clause_never_reaches_the_evaluator():
    sender_policy.set_evaluator("apply", _Exploding())
    tx = _transfer_tx(500)
    result, _lm, _calls = ap._apply([tx], lm=_registered(None))
    assert tx["tx_id"] in result.accepted_tx_ids


def test_a_clause_registered_earlier_in_the_block_judges_the_next_transfer():
    ev = _blocking(body=ap.TIER_CLAUSE_BODY)
    sender_policy.set_evaluator("apply", ev)
    rule = ap.rule_tx(ap.UNGUARDED_RULE, seq=0)
    tx = _transfer_tx(500, seq=1)
    result, _lm, _calls = ap._apply([rule, tx])
    assert rule["tx_id"] in result.accepted_tx_ids
    assert tx["tx_id"] in result.invalid_tx_ids
    assert ev.verdict_calls[-1][0] == ap.TIER_CLAUSE_BODY


def test_a_clause_revoked_earlier_in_the_block_no_longer_judges():
    sender_policy.set_evaluator("apply", _Exploding())
    revoke = ap.rule_tx(ap.NEUTRAL_RULE, seq=0)
    tx = _transfer_tx(500, seq=1)
    result, _lm, _calls = ap._apply([revoke, tx], lm=_registered(ap.TIER_CLAUSE_BODY))
    assert tx["tx_id"] in result.accepted_tx_ids


def test_a_clause_that_does_not_build_blocks_at_apply():
    ev = MockPolicyEvaluator()
    ev.fail_build(CLAUSE)
    sender_policy.set_evaluator("apply", ev)
    tx = _transfer_tx(500)
    result, _lm, _calls = ap._apply([tx], lm=_registered())
    assert tx["tx_id"] in result.invalid_tx_ids


def test_a_lost_evaluator_is_not_a_verdict_at_apply():
    class _Lost:
        def verdict(self, *a, **k):
            raise WorkerLost("gone")

    sender_policy.set_evaluator("apply", _Lost())
    with pytest.raises(WorkerLost):
        ap._apply([_transfer_tx(500)], lm=_registered())


def test_a_parked_request_is_gated_by_the_senders_clause():
    """The fake main policy allows 500; only the clause makes it gated, so the
    request parks instead of being refused as ungated."""
    ev = _blocking()
    sender_policy.set_evaluator("apply", ev)
    req = ap._request(amount=500)
    result, lm, _calls = ap._apply([ap.request_tx(req)], lm=_registered())
    assert lm.approval_requests.get_request(req.request_id) is not None
    assert "Approval request parked" in ap._logs(result)
    body, inputs = ev.verdict_calls[-1]
    assert inputs["i1"] == "500" and inputs["i12"] == "#x" + ap.ALICE


def test_a_parked_request_without_a_clause_is_still_refused_as_ungated():
    sender_policy.set_evaluator("apply", _Exploding())
    req = ap._request(amount=500)
    result, lm, _calls = ap._apply([ap.request_tx(req)], lm=_registered(None))
    assert lm.approval_requests.get_request(req.request_id) is None
    assert "allows this transfer with no votes" in ap._logs(result)


# --- admission --------------------------------------------------------------

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = "ab" * 48
ADMISSION_CLAUSE_VIEW = "consensus.facade.TipAdmissionView.clause_for"


@pytest.fixture
def admission(temp_database):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state.load_genesis("data/genesis.json")
    db.clear_mempool()
    chain_state._balances[SENDER] = 100000
    with ExitStack() as stack:
        for target, kwargs in (
            ("commands.sendtx._validate_bls12_381_pubkey", {"return_value": (True, None)}),
            ("tau_manager.is_force_test_enabled", {"return_value": False}),
            ("tau_manager.communicate_with_tau_multi", {"return_value": {1: "1", 5: "1"}}),
        ):
            stack.enter_context(patch(target, **kwargs))
        ready = stack.enter_context(patch("tau_manager.tau_ready"))
        ready.is_set.return_value = True
        yield


def _queue():
    tx = {
        "sender_pubkey": SENDER,
        "sequence_number": chain_state.get_sequence_number(SENDER),
        "expiration_time": int(time.time()) + 1000,
        "expire_at_height": 5000,
        "operations": {"1": [[SENDER, RECIPIENT, "1"]]},
        "fee_limit": "1000",
    }
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, SK_ALICE)))


def test_admission_rejects_a_transfer_the_senders_clause_blocks(admission):
    ev = _blocking(pool="admission")
    sender_policy.set_evaluator("admission", ev)
    with patch(ADMISSION_CLAUSE_VIEW, return_value=CLAUSE):
        res = _queue()
    assert res["ok"] is False and res["code"] == "TX_REJECTED"
    assert "sender's own policy clause" in res["message"] and "#1" in res["message"]
    body, inputs = ev.verdict_calls[-1]
    assert body == CLAUSE and inputs["i1"] == "1" and inputs["i12"] == "#x" + SENDER


def test_admission_rejects_a_transfer_whose_clause_the_engine_refuses_to_step(admission):
    ev = MockPolicyEvaluator(pool="admission")
    ev.fail_step(CLAUSE, "engine says no")
    sender_policy.set_evaluator("admission", ev)
    with patch(ADMISSION_CLAUSE_VIEW, return_value=CLAUSE):
        res = _queue()
    assert res["ok"] is False and res["code"] == "TX_REJECTED"
    assert tau_policy.PolicyStepError.MESSAGE in res["message"]
    assert db.get_mempool_txs() == []


def test_admission_accepts_when_the_clause_allows(admission):
    sender_policy.set_evaluator("admission", _blocking(o5="1", pool="admission"))
    with patch(ADMISSION_CLAUSE_VIEW, return_value=CLAUSE):
        assert _queue()["ok"] is True


def test_admission_without_a_clause_never_reaches_the_evaluator(admission):
    sender_policy.set_evaluator("admission", _Exploding())
    with patch(ADMISSION_CLAUSE_VIEW, return_value=None):
        assert _queue()["ok"] is True


@pytest.mark.parametrize("exc, code", [
    (WorkerLost("gone"), "ADMISSION_UNAVAILABLE"),
    (WorkerTimeout("slow"), "ADMISSION_TIMEOUT"),
    (SpeculationError("protocol"), "ADMISSION_UNAVAILABLE"),
])
def test_an_evaluator_failure_is_operational_not_a_rejection(admission, exc, code):
    class _Failing:
        def verdict(self, *a, **k):
            raise exc

    sender_policy.set_evaluator("admission", _Failing())
    with patch(ADMISSION_CLAUSE_VIEW, return_value=CLAUSE):
        res = _queue()
    assert res["ok"] is False and res["code"] == code
    assert db.get_mempool_txs() == []


def test_admission_passes_its_budget_as_the_deadline(admission):
    seen = {}

    class _Spy:
        def verdict(self, body, inputs, *, timeout):
            seen["timeout"] = timeout
            return tau_policy.PolicyVerdict(blocked=False, o5="1", built=True)

    sender_policy.set_evaluator("admission", _Spy())
    with patch(ADMISSION_CLAUSE_VIEW, return_value=CLAUSE):
        assert _queue()["ok"] is True
    assert seen["timeout"] == tau_admission.default_budget()


# --- approval preview -------------------------------------------------------

def _preview(draft, clause, *, evaluator, context=None):
    sender_policy.set_evaluator("admission", evaluator)
    with patch(ADMISSION_CLAUSE_VIEW, return_value=clause):
        if context is None:
            with patch("tau_manager.communicate_with_tau_multi",
                       side_effect=rpc._fake_policy), \
                    patch("tau_manager.tau_ready") as ready:
                ready.is_set.return_value = True
                return getapprovalpreview.execute("getapprovalpreview " + draft, None)
        resp, _ctx = rpc._preview_under_authority(draft, context=context)
        return resp


def _enable(temp_database):
    rpc._activate()
    rpc._persist()


def test_the_preview_in_process_takes_the_clause_verdict_into_account(temp_database):
    _enable(temp_database)
    # The fake main policy allows 500; only the clause blocks it.
    ev = _blocking(pool="admission")
    data = rpc._data(_preview(rpc._draft(500, {18: rpc.AUTH}), CLAUSE, evaluator=ev))
    assert data["satisfiable"] is False and data["required_slots"] is None
    assert ev.verdict_calls and ev.verdict_calls[0][1]["i1"] == "500"


def test_the_preview_in_process_without_a_clause_is_unchanged(temp_database):
    _enable(temp_database)
    data = rpc._data(_preview(rpc._draft(500, {18: rpc.AUTH}), None, evaluator=_Exploding()))
    assert data["needs_no_approval"] is True


def test_the_preview_under_authority_takes_the_clause_verdict_into_account(temp_database):
    _enable(temp_database)
    ev = _blocking(pool="admission")
    data = rpc._data(_preview(rpc._draft(500, {18: rpc.AUTH}), CLAUSE, evaluator=ev,
                              context=rpc._FakeContext()))
    assert data["satisfiable"] is False and data["required_slots"] is None


def test_the_clause_can_be_satisfied_by_a_slot_in_the_preview(temp_database):
    _enable(temp_database)
    ev = MockPolicyEvaluator(pool="admission")
    ev.set_verdict(CLAUSE, lambda inputs: "1" if rpc.AUTH in inputs.get("i18", "") else "0")
    data = rpc._data(_preview(rpc._draft(500, {18: rpc.AUTH, 19: rpc.SCAN}), CLAUSE,
                              evaluator=ev))
    assert data["required_slots"] == [18]


@pytest.mark.parametrize("exc", [WorkerLost("gone"), WorkerTimeout("slow")])
def test_a_lost_evaluator_is_no_answer_on_the_context_path(temp_database, exc):
    _enable(temp_database)

    class _Lost:
        def verdict(self, *a, **k):
            raise exc

    data = rpc._data(_preview(rpc._draft(500, {18: rpc.AUTH}), CLAUSE, evaluator=_Lost(),
                              context=rpc._FakeContext()))
    assert data["available"] is False and "reason" in data


def test_a_lost_evaluator_is_a_tau_error_in_process(temp_database):
    _enable(temp_database)

    class _Lost:
        def verdict(self, *a, **k):
            raise WorkerLost("gone")

    resp = _preview(rpc._draft(500, {18: rpc.AUTH}), CLAUSE, evaluator=_Lost())
    assert rpc._err(resp)["code"] == "TAU_ERROR"
