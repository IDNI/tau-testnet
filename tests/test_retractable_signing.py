import hashlib
import json

import pytest
from py_ecc.bls import G2Basic

from consensus.retractable import (
    TX_TYPE_RETRACT_TRANSFER,
    TX_TYPE_RETRACTABLE_TRANSFER,
    RetractableShapeError,
    parse_retract_transfer,
    parse_retractable_transfer,
)
from consensus.tx_signing import signing_message_bytes, verify_tx_signature

SK = 4242
SENDER = G2Basic.SkToPk(SK).hex()
RECIPIENT = "b" * 96
RID = "cd" * 32


def _sign(tx: dict) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(SK, digest).hex()
    return tx


def _envelope(tx_type):
    return {
        "sender_pubkey": SENDER,
        "sequence_number": 3,
        "expiration_time": 1_700_000_000,
        "expire_at_height": 77,
        "fee_limit": "5",
        "tx_type": tx_type,
    }


def _park(**over):
    tx = {**_envelope(TX_TYPE_RETRACTABLE_TRANSFER), "recipient_pubkey": RECIPIENT,
          "amount": 100, "release_at_height": 90, "release_at_time": None}
    tx.update(over)
    return _sign(tx)


def _retract(**over):
    tx = {**_envelope(TX_TYPE_RETRACT_TRANSFER), "retractable_id": RID}
    tx.update(over)
    return _sign(tx)


def test_valid_signatures_verify():
    assert verify_tx_signature(_park()) == (True, "")
    assert verify_tx_signature(_retract()) == (True, "")


@pytest.mark.parametrize("field,value", [
    ("sender_pubkey", "d" * 96),
    ("sequence_number", 4),
    ("expiration_time", 1_700_000_001),
    ("expire_at_height", 78),
    ("fee_limit", "6"),
    ("recipient_pubkey", "c" * 96),
    ("amount", 101),
    ("release_at_height", 91),
    ("release_at_time", 5000),
])
def test_park_tampering_breaks_signature(field, value):
    tx = _park()
    tx[field] = value
    assert verify_tx_signature(tx)[0] is False


def test_park_time_kind_signed():
    tx = _park(release_at_height=None, release_at_time=5000)
    assert verify_tx_signature(tx)[0]
    tx["release_at_time"] = 5001
    assert not verify_tx_signature(tx)[0]
    tx["release_at_time"] = None
    tx["release_at_height"] = 90
    assert not verify_tx_signature(tx)[0]


@pytest.mark.parametrize("field,value", [
    ("retractable_id", "ce" * 32),
    ("sequence_number", 4),
    ("fee_limit", "1"),
    ("expire_at_height", 1),
])
def test_retract_tampering_breaks_signature(field, value):
    tx = _retract()
    tx[field] = value
    assert verify_tx_signature(tx)[0] is False


def test_injected_payload_and_operations_are_ignored_by_parsers():
    park = _park()
    park["payload"] = {"recipient_pubkey": "c" * 96, "amount": 1, "release_at_height": 1}
    park["operations"] = {"1": [["x", "y", "9"]]}
    entry = parse_retractable_transfer(park)
    assert entry.recipient_pubkey == RECIPIENT and entry.amount == 100
    assert entry.release_at == 90

    retract = _retract()
    retract["payload"] = {"retractable_id": "ee" * 32}
    assert parse_retract_transfer(retract).retractable_id == bytes.fromhex(RID)

    nested_only = {**_envelope(TX_TYPE_RETRACTABLE_TRANSFER),
                   "payload": {"recipient_pubkey": RECIPIENT, "amount": 5,
                               "release_at_height": 9}}
    with pytest.raises(RetractableShapeError):
        parse_retractable_transfer(nested_only)


@pytest.mark.parametrize("over", [
    {"amount": True}, {"amount": "5"}, {"amount": 5.0}, {"amount": -1},
    {"recipient_pubkey": "B" * 96}, {"recipient_pubkey": "b" * 95},
    {"sender_pubkey": "A" * 96},
    {"release_at_height": 9, "release_at_time": 9},
    {"release_at_height": None, "release_at_time": None},
    {"release_at_height": True},
    {"sequence_number": True},
])
def test_park_parser_is_strict(over):
    tx = {**_envelope(TX_TYPE_RETRACTABLE_TRANSFER), "recipient_pubkey": RECIPIENT,
          "amount": 100, "release_at_height": 90}
    tx.update(over)
    with pytest.raises(RetractableShapeError):
        parse_retractable_transfer(tx)


@pytest.mark.parametrize("rid", ["AB" * 32, "ab" * 31, 5, None])
def test_retract_parser_is_strict(rid):
    with pytest.raises(RetractableShapeError):
        parse_retract_transfer({"sender_pubkey": SENDER, "retractable_id": rid})


def test_park_parser_kinds():
    entry = parse_retractable_transfer(
        {**_envelope(TX_TYPE_RETRACTABLE_TRANSFER), "recipient_pubkey": RECIPIENT,
         "amount": 1, "release_at_time": 5000})
    assert (entry.kind, entry.release_at) == (1, 5000)


GOLDEN = {
    "user_tx": "a8636c7eab26370764ff33142da2896bdbd86cd28d44c85255a6fa52894bb50a",
    "approval_request": "39c45a28f9c1b0dd93e160696beeb85dc3e013fac015c1e093939d317e3a450a",
    "transfer_vote": "b32d7141ec9f38b9d91eb656e8d849bc3d47d881c5ea1cd64f04c839606379ff",
    "rule_offer": "e1217e06d802a228b4c914791d972ddde67f6fd55c29132f83b282c11a860a9d",
}


def test_existing_types_preimages_unchanged():
    a, b = "a" * 96, "b" * 96
    base = {"sender_pubkey": a, "sequence_number": 3, "expiration_time": 1_700_000_000,
            "fee_limit": "5", "expire_at_height": 77}
    extras = {
        "user_tx": {"operations": {"1": [[a, b, "5"]]}},
        "approval_request": {"recipient_pubkey": b, "amount": 9,
                             "approvers": {"18": b}, "custom_inputs": {}},
        "transfer_vote": {"request_id": "ab" * 32, "approve": True, "reason": "ok"},
        "rule_offer": {"recipient_pubkey": b, "rule_text": "x"},
    }
    for tx_type, extra in extras.items():
        got = hashlib.sha256(signing_message_bytes({**base, "tx_type": tx_type, **extra})).hexdigest()
        assert got == GOLDEN[tx_type], tx_type


def test_new_preimage_fields():
    park = json.loads(signing_message_bytes(_park()))
    assert {"recipient_pubkey", "amount", "release_at_height", "release_at_time"} <= set(park)
    assert park["release_at_time"] is None
    assert "payload" not in park and "operations" not in park
    retract = json.loads(signing_message_bytes(_retract()))
    assert retract["retractable_id"] == RID
