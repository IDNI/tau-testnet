"""Admission and sendtx refuse BLS public keys that py_ecc KeyValidate refuses."""
from __future__ import annotations

import json

import pytest
from unittest.mock import MagicMock

from commands import sendtx
from consensus.admission import (
    TipAdmissionView,
    validate_approval_request_payload,
    validate_mempool_admission,
    validate_retractable_transfer_payload,
    validate_rule_offer_payload,
    validate_user_tx_reserved_domains,
)
from consensus.approvals import ApprovalRequest
from consensus.tx_checks import validate_bls_pubkey
from py_ecc.bls import G2Basic
from py_ecc.bls.point_compression import decompress_G1
from bls_keys import INVALID_PUBKEYS, OFF_CURVE_PUBKEY, pubkey_hex

REAL = pubkey_hex(0x7EA1)
SENDER = pubkey_hex(0x5E1D)
OFFERER = pubkey_hex(0x0FF1)
RECIPIENT = pubkey_hex(0x2EC1)
OTHER = pubkey_hex(0x07E2)
AUTH = pubkey_hex(0xA07)
SCAN = pubkey_hex(0x5CA)
PARTNER = pubkey_hex(0xBA7)
PARK_SENDER = pubkey_hex(0x9A5E)
PARK_RECIPIENT = pubkey_hex(0x9A2E)

BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
NEXT_HEIGHT = 50
EXPIRE = 500


def test_off_curve_pubkey_fails_decompression():
    compressed = int.from_bytes(bytes.fromhex(OFF_CURVE_PUBKEY), "big")
    with pytest.raises(ValueError, match="not on G1"):
        decompress_G1(compressed)


@pytest.mark.parametrize("label,key_hex", INVALID_PUBKEYS)
def test_validate_bls_pubkey_rejects_bad_keys(label, key_hex):
    assert validate_bls_pubkey(key_hex, "test key")


def test_validate_bls_pubkey_accepts_real_key():
    assert validate_bls_pubkey(REAL, "test key") is None


# Block apply runs this check, so every node must reach the py_ecc verdict.
@pytest.mark.parametrize("key_hex", [k for _, k in INVALID_PUBKEYS] + [REAL, SENDER, OFFERER])
def test_validate_bls_pubkey_matches_py_ecc_key_validate(key_hex):
    expected = G2Basic.KeyValidate(bytes.fromhex(key_hex))
    assert (validate_bls_pubkey(key_hex, "test key") is None) == expected


def _user_tx_transfer(to_key: str, *, from_key: str | None = None):
    sender = from_key or SENDER
    return {
        "operations": {
            "1": [[sender, to_key, "1"]],
        },
    }


def _user_tx_tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.eligibility_mode = ""
    view.approval_slots_active = False
    return view


@pytest.mark.parametrize("label,key_hex", INVALID_PUBKEYS)
def test_user_tx_admission_rejects_bad_transfer_to(label, key_hex):
    res = validate_user_tx_reserved_domains(
        _user_tx_transfer(key_hex), _user_tx_tip_view())
    assert res.is_valid is False
    assert res.code == "TX_INVALID"


@pytest.mark.parametrize("label,key_hex", INVALID_PUBKEYS)
def test_user_tx_admission_rejects_bad_transfer_from(label, key_hex):
    res = validate_user_tx_reserved_domains(
        _user_tx_transfer(REAL, from_key=key_hex), _user_tx_tip_view())
    assert res.is_valid is False
    assert res.code == "TX_INVALID"


def test_user_tx_admission_accepts_real_from_and_to():
    res = validate_user_tx_reserved_domains(
        _user_tx_transfer(REAL), _user_tx_tip_view())
    assert res.is_valid is True, res.error


def test_sendtx_bls_unavailable_with_valid_sender_shape(monkeypatch):
    tx_json = json.dumps({
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "sequence_number": 0,
        "expiration_time": 9_999_999_999,
        "expire_at_height": EXPIRE,
        "operations": {"1": [[SENDER, REAL, "1"]]},
        "fee_limit": "0",
        "signature": "00" * 96,
    })
    monkeypatch.setattr(sendtx, "_PY_ECC_AVAILABLE", False)
    monkeypatch.setattr(sendtx, "_PY_ECC_BLS", None)
    result = sendtx.queue_transaction(tx_json)
    assert result["ok"] is False
    assert result["code"] == "BLS_UNAVAILABLE"


def test_sendtx_malformed_sender_tx_invalid_without_py_ecc(monkeypatch):
    monkeypatch.setattr(sendtx, "_PY_ECC_AVAILABLE", False)
    monkeypatch.setattr(sendtx, "_PY_ECC_BLS", None)
    result = sendtx.queue_transaction(json.dumps({
        "tx_type": "user_tx",
        "sender_pubkey": "not-a-key",
        "sequence_number": 0,
        "expiration_time": 9_999_999_999,
        "expire_at_height": EXPIRE,
        "operations": {"1": [[SENDER, REAL, "1"]]},
        "fee_limit": "0",
        "signature": "00" * 96,
    }))
    assert result["ok"] is False
    assert result["code"] == "TX_INVALID"


def _rule_offer_tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.get_offer_lifecycle_state.return_value = None
    view.pending_offers_for_recipient.return_value = 0
    view.pending_offers_for_offerer.return_value = 0
    view.clauses_for_stream.return_value = {}
    view.clause_for.return_value = None
    return view


@pytest.mark.parametrize("label,key_hex", INVALID_PUBKEYS)
def test_rule_offer_admission_rejects_bad_recipient(label, key_hex):
    tx = {
        "tx_type": "rule_offer",
        "sender_pubkey": OFFERER,
        "recipient_pubkey": key_hex,
        "rule_text": BLOCK_RULE,
        "expire_at_height": EXPIRE,
    }
    res = validate_rule_offer_payload(tx, _rule_offer_tip_view())
    assert res.is_valid is False
    assert res.error


def test_rule_offer_admission_accepts_real_recipient():
    tx = {
        "tx_type": "rule_offer",
        "sender_pubkey": OFFERER,
        "recipient_pubkey": RECIPIENT,
        "rule_text": BLOCK_RULE,
        "expire_at_height": EXPIRE,
    }
    res = validate_rule_offer_payload(tx, _rule_offer_tip_view())
    assert res.is_valid is True, res.error


def _approval_tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.approval_slots_active = True
    view.get_approval_request.return_value = None
    view.open_requests_for_sender.return_value = 0
    view.open_requests_for_approver.return_value = 0
    return view


def _approval_request_tx(**over):
    req = ApprovalRequest(
        sender_pubkey=SENDER,
        recipient_pubkey=RECIPIENT,
        amount=200000,
        sequence_number=1,
        expire_at_height=EXPIRE,
        approvers={18: AUTH, 19: SCAN, 20: PARTNER},
        custom_inputs={},
    )
    tx = {
        "tx_type": "approval_request",
        "sender_pubkey": req.sender_pubkey,
        "sequence_number": req.sequence_number,
        "recipient_pubkey": req.recipient_pubkey,
        "amount": req.amount,
        "expire_at_height": req.expire_at_height,
        "approvers": {str(k): v for k, v in req.approvers.items()},
        "custom_inputs": {},
    }
    tx.update(over)
    return tx


@pytest.mark.parametrize("label,key_hex", INVALID_PUBKEYS)
def test_approval_admission_rejects_bad_recipient(label, key_hex):
    res = validate_approval_request_payload(
        _approval_request_tx(recipient_pubkey=key_hex), _approval_tip_view())
    assert res.is_valid is False
    assert "approval_request rejected" in (res.error or "")


@pytest.mark.parametrize("label,key_hex", INVALID_PUBKEYS)
def test_approval_admission_rejects_bad_approver(label, key_hex):
    res = validate_approval_request_payload(
        _approval_request_tx(approvers={"18": key_hex}), _approval_tip_view())
    assert res.is_valid is False
    assert "approval_request rejected" in (res.error or "")


def test_approval_admission_accepts_real_keys():
    res = validate_approval_request_payload(_approval_request_tx(), _approval_tip_view())
    assert res.is_valid is True, res.error


def _retractable_tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = 1_700_000_000
    view.get_retractable.return_value = None
    view.open_retractable_count_for_sender.return_value = 0
    view.open_retractable_count.return_value = 0
    return view


def _retractable_tx(**over):
    tx = {
        "tx_type": "retractable_transfer",
        "sender_pubkey": PARK_SENDER,
        "sequence_number": 1,
        "expiration_time": 9_999_999_999,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "10",
        "recipient_pubkey": PARK_RECIPIENT,
        "amount": 100,
        "release_at_height": NEXT_HEIGHT + 30,
    }
    tx.update(over)
    return tx


@pytest.mark.parametrize("label,key_hex", INVALID_PUBKEYS)
def test_retractable_admission_rejects_bad_recipient(label, key_hex):
    res = validate_retractable_transfer_payload(
        _retractable_tx(recipient_pubkey=key_hex), _retractable_tip_view())
    assert res.is_valid is False
    assert "retractable_transfer rejected" in (res.error or "")


def test_retractable_admission_accepts_real_recipient():
    res = validate_retractable_transfer_payload(_retractable_tx(), _retractable_tip_view())
    assert res.is_valid is True, res.error


def test_mempool_rule_offer_with_real_recipient():
    tx = {
        "tx_type": "rule_offer",
        "sender_pubkey": OFFERER,
        "recipient_pubkey": RECIPIENT,
        "rule_text": BLOCK_RULE,
        "expire_at_height": EXPIRE,
    }
    view = _rule_offer_tip_view()
    view.active_validators = {OFFERER}
    view.eligibility_mode = ""
    res = validate_mempool_admission(tx, view, compile_rules=False)
    assert res.is_valid is True, res.error
