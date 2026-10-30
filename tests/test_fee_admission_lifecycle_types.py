"""Admission prices every fee-bearing type the way block apply charges it.

A rule offer, a rule accept, a rule reject and an approval request carry no
transfer leg. Apply still charges them a fee, so admission must estimate that
fee and refuse a fee_limit below it.
"""
import json
from unittest.mock import PropertyMock, patch

import pytest

import chain_state
import config
import db
from consensus.admission import TipAdmissionView
from consensus.rule_offers import RuleOffer

SENDER = "a" * 96
RECIPIENT = "c" * 96
APPROVER = "e" * 96
NEXT_HEIGHT = 50
TIP_TS = 1_700_000_000
FAR = 9_999_999_999
BASE_FEE = 10
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


@pytest.fixture
def node(temp_database, monkeypatch):
    """A real database, a mocked signature check, and a Tau with a flat fee."""
    from commands import sendtx

    script = {"calls": []}

    def multi(**kwargs):
        script["calls"].append(kwargs)
        # o5 blocks, so a parked approval request is what the sender's policy asks for.
        return {5: "0", 9: str(BASE_FEE)}

    patches = [
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau", return_value="x1001"),
        patch("tau_manager.communicate_with_tau_multi", side_effect=multi),
        patch("commands.sendtx.G2Basic"),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch("commands.sendtx._validate_bls12_381_pubkey", return_value=(True, None)),
        patch("tau_native.compile_revisions_isolated_subprocess", return_value=None),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
        patch.object(TipAdmissionView, "next_block_height",
                     new_callable=PropertyMock, return_value=NEXT_HEIGHT),
        patch.object(TipAdmissionView, "tip_timestamp",
                     new_callable=PropertyMock, return_value=TIP_TS),
        patch.object(TipAdmissionView, "approval_slots_active",
                     new_callable=PropertyMock, return_value=True),
    ]
    mocks = [p.start() for p in patches]
    mocks[0].is_set.return_value = True
    mocks[3].Verify.return_value = True
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False)
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    monkeypatch.setitem(chain_state._balances, RECIPIENT, 1_000_000)
    yield sendtx, script
    for p in reversed(patches):
        p.stop()


def _envelope(tx_type, sender, fee_limit, **fields):
    tx = {
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": 1,
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 100,
        "fee_limit": fee_limit,
        "signature": "00" * 48,
    }
    tx.update(fields)
    return tx


def _offer():
    return RuleOffer(
        offerer_pubkey=SENDER, recipient_pubkey=RECIPIENT,
        rule_text=OFFER_RULE, expire_at_height=NEXT_HEIGHT + 100,
    )


def _offer_row():
    offer = _offer()
    return {
        "offer_id": offer.offer_id_hex,
        "offerer_pubkey": SENDER,
        "recipient_pubkey": RECIPIENT,
        "rule_text": OFFER_RULE,
        "expire_at_height": offer.expire_at_height,
        "status": "offered",
    }


def _payload(kind, fee_limit):
    offer = _offer()
    if kind == "rule_offer":
        return _envelope(kind, SENDER, fee_limit, recipient_pubkey=RECIPIENT,
                         rule_text=OFFER_RULE)
    if kind == "rule_offer_accept":
        return _envelope(kind, RECIPIENT, fee_limit, offer_id=offer.offer_id_hex,
                         rule_text=OFFER_RULE)
    if kind == "rule_offer_reject":
        return _envelope(kind, RECIPIENT, fee_limit, offer_id=offer.offer_id_hex)
    if kind == "approval_request":
        return _envelope(kind, SENDER, fee_limit, recipient_pubkey=RECIPIENT,
                         amount=500, approvers={"18": APPROVER}, custom_inputs={})
    raise AssertionError(kind)


def _queue(sendtx, payload):
    with patch.object(TipAdmissionView, "get_offer", return_value=_offer_row()):
        return sendtx.queue_transaction(json.dumps(payload), propagate=False)


def _mempool_fees():
    with db._db_lock:
        return [tuple(r) for r in db._db_conn.execute(
            "SELECT estimated_fee, fee_limit FROM mempool")]


KINDS = ["rule_offer", "rule_offer_accept", "rule_offer_reject", "approval_request"]


@pytest.mark.parametrize("kind", KINDS)
def test_a_fee_limit_below_the_fee_is_refused(node, kind):
    sendtx, _ = node
    result = _queue(sendtx, _payload(kind, "0"))
    assert result["ok"] is False, result
    assert result["code"] == "FEE_LIMIT_TOO_LOW", result
    assert _mempool_fees() == []


@pytest.mark.parametrize("kind", KINDS)
def test_a_fee_limit_above_the_fee_is_queued_with_its_estimate(node, kind):
    sendtx, _ = node
    result = _queue(sendtx, _payload(kind, "1000"))
    assert result["ok"], result
    assert _mempool_fees() == [(BASE_FEE, 1000)]


def test_an_approval_request_is_priced_on_its_parked_transfer(node):
    sendtx, script = node
    assert _queue(sendtx, _payload("approval_request", "1000"))["ok"]
    assert len(script["calls"]) == 1
    inputs = script["calls"][0]["input_stream_values"]
    assert inputs[1] == "500"
    assert SENDER in inputs[3] and RECIPIENT in inputs[4]
    assert inputs[18] == "0"
    assert list(inputs)[-1] == 5
