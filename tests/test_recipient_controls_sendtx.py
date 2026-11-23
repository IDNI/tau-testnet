"""queue_transaction with the recipient gate switched on.

The apply tests call the helper. These execute the sendtx lines: the hold
measured on the admission clock, the error envelope, and the fee step, which
must not see i17. Clause verdicts are the in-process mock.
"""
import json
import time
from unittest.mock import PropertyMock, patch

import pytest

import chain_state
import db
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from consensus import sender_policy
from consensus.facade import TipAdmissionView
from consensus.policy_mock import MockPolicyEvaluator
from consensus.recipient_policy import HEIGHT_CODE_BASE, MAX_HOLD, POLICY_BLOCK

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
OTHER = pubkey_hex(SK_CAROL)
NEXT_HEIGHT = 50
TIP_TS = 1_700_000_000
FAR = 9_999_999_999
HOLD = "i17[t]:bv[64]"
CAP_0 = "(i17[t]:bv[64] > {1}:bv[64])"
CAP_600 = "(i17[t]:bv[64] > {601}:bv[64])"
OUTBOUND = "o5[t]:bv[24] = {0}:bv[24]"


@pytest.fixture(autouse=True)
def _mock_evaluator():
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)
    yield
    sender_policy.set_evaluator("apply", None)
    sender_policy.set_evaluator("admission", None)


@pytest.fixture
def node(temp_database, monkeypatch):
    """A real database, real signatures, and a scriptable fee step."""
    from commands import sendtx

    script = {"calls": []}

    def multi(**kwargs):
        script["calls"].append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        return {1: str(vals.get(1, "0")), 5: "1", 8: "0", 9: "0"}

    patches = [
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau", return_value="x1001"),
        patch("tau_manager.communicate_with_tau_multi", side_effect=multi),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
    ]
    mocks = [p.start() for p in patches]
    mocks[0].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    opened = int(time.time())
    height = patch.object(
        TipAdmissionView, "next_block_height",
        new_callable=PropertyMock, return_value=NEXT_HEIGHT,
    )
    ts = patch.object(
        TipAdmissionView, "tip_timestamp",
        new_callable=PropertyMock, return_value=TIP_TS,
    )
    next_ts = patch.object(
        TipAdmissionView, "next_block_timestamp",
        new_callable=PropertyMock, return_value=opened,
    )
    height.start()
    ts.start()
    clock = next_ts.start()
    yield sendtx, script, clock, opened
    for started in reversed(patches + [height, ts, next_ts]):
        started.stop()


def _arm(active):
    chain_state._lifecycle_manager.recipient_controls_active = active


def _register(pubkey, body):
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO rule_clauses_v1 "
            "(acceptor_pubkey, target_stream, clause_body) VALUES (?, ?, ?)",
            (pubkey.lower(), tau_defs.USER_POLICY_STREAM_INDEX, body),
        )


def _install(body, decide):
    mock = MockPolicyEvaluator()
    mock.set_verdict(body, decide)
    sender_policy.set_evaluator("admission", mock)
    return mock


def _over(limit):
    def decide(inputs):
        return 0 if int(inputs["i17"]) > limit else 1
    return decide


def _pay(to=RECIPIENT, amount="40", **over):
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "sequence_number": 1,
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "100",
        "operations": {"1": [[SENDER, to, amount]]},
    }
    tx.update(over)
    return sign_payload(tx, SK_ALICE)


def _park(**over):
    tx = {
        "tx_type": "retractable_transfer",
        "sender_pubkey": SENDER,
        "sequence_number": 1,
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "100",
        "recipient_pubkey": RECIPIENT,
        "amount": 100,
        "release_at_height": NEXT_HEIGHT + 30,
    }
    tx.update(over)
    if "release_at_time" in tx:
        tx.pop("release_at_height", None)
    return sign_payload(tx, SK_ALICE)


def _time_park(clock, seconds, **over):
    """A time park whose deadline is still in the future and before release."""
    release = int(clock) + int(seconds)
    expiration = release - 1
    if expiration <= int(time.time()):
        raise RuntimeError("the release window is already in the past")
    return _park(release_at_time=release, expiration_time=expiration, **over)


def _queue(sendtx, payload):
    return sendtx.queue_transaction(json.dumps(payload), propagate=False)


def _mempool():
    with db._db_lock:
        return [row[0] for row in db._db_conn.execute("SELECT tx_hash FROM mempool")]


def _fee_inputs(script):
    assert script["calls"], "the fee step did not run"
    return [call["input_stream_values"] for call in script["calls"]]


def _no_hold_on_fee_step(script):
    for inputs in _fee_inputs(script):
        assert 17 not in inputs
        assert "17" not in inputs


def test_a_queued_payment_ignores_a_hold_clause_while_the_flag_is_off(node):
    sendtx, script, _clock, _opened = node
    _arm(False)
    _register(RECIPIENT, HOLD)
    mock = _install(HOLD, _over(1))
    result = _queue(sendtx, _pay())
    assert result["ok"], result
    assert mock.verdict_calls == []
    assert _mempool() == [result["tx_hash"]]
    _no_hold_on_fee_step(script)


def test_a_queued_payment_the_recipient_blocks_names_no_maximum(node):
    sendtx, script, _clock, _opened = node
    _arm(True)
    _register(RECIPIENT, HOLD)

    def decide(inputs):
        if int(inputs["i17"]) == 0:
            return 1
        return 0

    mock = _install(HOLD, decide)
    result = _queue(sendtx, _pay())
    assert result["ok"] is False
    assert result["code"] == POLICY_BLOCK
    assert result["message"] == "rejected by recipient policy (o5)"
    assert result["details"] == {"transfer_index": 1}
    assert mock.verdict_calls[0][1]["i17"] == "1"
    assert mock.verdict_calls[0][1]["i3"] == "#x" + SENDER
    assert mock.verdict_calls[0][1]["i4"] == "#x" + RECIPIENT
    assert _mempool() == []
    _no_hold_on_fee_step(script)


def test_a_plain_payment_under_a_zero_cap_is_queued_and_a_park_is_not(node):
    sendtx, script, _clock, opened = node
    _arm(True)
    _register(RECIPIENT, CAP_0)
    _install(CAP_0, _over(1))
    admitted = _queue(sendtx, _pay())
    assert admitted["ok"], admitted
    assert _mempool() == [admitted["tx_hash"]]
    _no_hold_on_fee_step(script)

    parked = _queue(sendtx, _time_park(opened, 60, sequence_number=2))
    assert parked["ok"] is False
    assert parked["code"] == MAX_HOLD
    assert parked["details"]["transfer_index"] == 1
    assert parked["details"]["max_hold_seconds"] == 0
    assert "straight away" in parked["message"]
    assert _mempool() == [admitted["tx_hash"]]


def test_a_queued_park_past_the_seconds_cap_names_that_cap(node):
    sendtx, script, _clock, opened = node
    _arm(True)
    _register(RECIPIENT, CAP_600)
    mock = _install(CAP_600, _over(601))
    result = _queue(sendtx, _time_park(opened, 3600))
    assert result["ok"] is False
    assert result["code"] == MAX_HOLD
    assert result["details"] == {"transfer_index": 1, "max_hold_seconds": 600}
    assert result["message"] == (
        "Recipient accepts payments held for up to 600 seconds (max_hold_seconds=600)."
    )
    assert mock.verdict_calls[0][1]["i17"] == "3601"
    assert _mempool() == []
    _no_hold_on_fee_step(script)


def test_a_queued_height_park_past_a_seconds_cap_names_zero_blocks(node):
    sendtx, script, _clock, _opened = node
    _arm(True)
    _register(RECIPIENT, CAP_600)
    mock = _install(CAP_600, _over(601))
    result = _queue(sendtx, _park())
    assert result["ok"] is False
    assert result["code"] == MAX_HOLD
    assert result["details"] == {
        "transfer_index": 1,
        "max_hold_blocks": 0,
        "max_hold_seconds": 600,
    }
    assert "600 seconds" in result["message"]
    assert "straight away" not in result["message"]
    assert mock.verdict_calls[0][1]["i17"] == str(HEIGHT_CODE_BASE + 30)
    assert _mempool() == []
    _no_hold_on_fee_step(script)


def test_a_queued_park_inside_the_cap_is_admitted(node):
    sendtx, script, _clock, opened = node
    _arm(True)
    _register(RECIPIENT, CAP_600)
    mock = _install(CAP_600, _over(601))
    result = _queue(sendtx, _time_park(opened, 600))
    assert result["ok"], result
    assert [call[1]["i17"] for call in mock.verdict_calls] == ["601"]
    assert _mempool() == [result["tx_hash"]]
    _no_hold_on_fee_step(script)


def test_the_admission_clock_is_the_next_block_timestamp(node):
    sendtx, script, clock, opened = node
    _arm(True)
    _register(RECIPIENT, CAP_600)
    _install(CAP_600, _over(601))
    release = opened + 700
    payload = _park(release_at_time=release, expiration_time=release - 1)
    refused = _queue(sendtx, payload)
    assert refused["code"] == MAX_HOLD
    assert refused["details"]["max_hold_seconds"] == 600

    clock.return_value = opened + 100
    admitted = _queue(sendtx, payload)
    assert admitted["ok"], admitted
    assert script["calls"][-1]["input_stream_values"][5] == str(opened + 100)
    assert _mempool() == [admitted["tx_hash"]]
    for inputs in _fee_inputs(script):
        assert 17 not in inputs


def test_an_outbound_clause_is_not_consulted_on_an_incoming_payment(node):
    sendtx, script, _clock, _opened = node
    _arm(True)
    _register(RECIPIENT, OUTBOUND)

    seen = []

    def decide(inputs):
        seen.append(inputs)
        return 0

    _install(OUTBOUND, decide)
    result = _queue(sendtx, _pay())
    assert result["ok"], result
    assert seen == []
    assert _mempool() == [result["tx_hash"]]
    _no_hold_on_fee_step(script)


def test_one_refused_leg_queues_the_whole_batch_as_nothing(node):
    sendtx, script, _clock, _opened = node
    _arm(True)
    _register(RECIPIENT, HOLD)

    def decide(inputs):
        if int(inputs["i17"]) == 0:
            return 1
        return 0

    _install(HOLD, decide)
    tx = _pay()
    tx["operations"] = {"1": [[SENDER, OTHER, "10"], [SENDER, RECIPIENT, "10"]]}
    refused = _queue(sendtx, sign_payload(tx, SK_ALICE))
    assert refused["ok"] is False
    assert refused["code"] == POLICY_BLOCK
    assert refused["details"] == {"transfer_index": 2}
    assert refused["message"] == "rejected by recipient policy (o5)"
    assert len(script["calls"]) == 2
    assert _mempool() == []
    _no_hold_on_fee_step(script)
