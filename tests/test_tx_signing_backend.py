"""The arkworks verifier must return exactly py_ecc G2Basic.Verify's verdict.

A divergence is a consensus split: two nodes would disagree on whether a
transaction in a block is validly signed.
"""
import json
import random
from pathlib import Path
from unittest.mock import patch

import pytest

from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_payload
from consensus import tx_signing
from consensus.tx_signing import _bls_verify, verify_tx_signature

VECTORS_PATH = Path(__file__).parent / "fixtures" / "bls_g2basic_vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text())["vectors"]
LIVE_SAMPLE = 10

IDENTITY_PK = "c0" + "00" * 47
IDENTITY_SIG = "c0" + "00" * 95


def _vector_inputs(v):
    return bytes.fromhex(v["pk"]), bytes.fromhex(v["msg"]), bytes.fromhex(v["sig"])


def _tx(sk=SK_ALICE, **over):
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": pubkey_hex(sk),
        "sequence_number": 7,
        "expiration_time": 1_700_000_000,
        "expire_at_height": 90,
        "fee_limit": "10",
        "operations": {"1": [["a" * 96, "b" * 96, "5"]]},
    }
    tx.update(over)
    return sign_payload(tx, sk)


def test_vector_file_covers_both_verdicts_and_the_edge_groups():
    assert len(VECTORS) >= 500
    assert {v["expected"] for v in VECTORS} == {True, False}
    labels = {v["label"].split(":")[0] for v in VECTORS}
    assert {"valid", "identity_pk_valid_sig", "nonsubgroup", "noncanon", "flags", "len", "mutant"} <= labels


def test_every_vector_gets_the_oracle_verdict():
    wrong = [
        (i, v["label"], v["expected"])
        for i, v in enumerate(VECTORS)
        if _bls_verify(*_vector_inputs(v)) is not v["expected"]
    ]
    assert wrong == []


def test_a_live_sample_still_matches_py_ecc():
    # Re-derive the oracle verdict so the recorded fixture cannot drift from py_ecc.
    from py_ecc.bls import G2Basic

    rng = random.Random(20261103)
    accepted = [i for i, v in enumerate(VECTORS) if v["expected"]]
    rejected = [i for i, v in enumerate(VECTORS) if not v["expected"]]
    picks = rng.sample(accepted, LIVE_SAMPLE // 2) + rng.sample(rejected, LIVE_SAMPLE - LIVE_SAMPLE // 2)
    for i in picks:
        v = VECTORS[i]
        pk, msg, sig = _vector_inputs(v)
        oracle = bool(G2Basic.Verify(pk, msg, sig))
        assert oracle is v["expected"], (i, v["label"])
        assert _bls_verify(pk, msg, sig) is oracle, (i, v["label"])


@pytest.mark.parametrize(
    "pk,msg,sig",
    [
        (bytearray(48), b"m", bytes(96)),
        (memoryview(bytes(48)), b"m", bytes(96)),
        (bytes(48).hex(), b"m", bytes(96)),
        (None, b"m", bytes(96)),
        (bytes(48), "m", bytes(96)),
        (bytes(48), None, bytes(96)),
        (bytes(48), b"m", bytearray(96)),
        (bytes(48), b"m", 5),
    ],
)
def test_non_bytes_inputs_are_rejected_without_raising(pk, msg, sig):
    assert _bls_verify(pk, msg, sig) is False


def test_a_signed_transaction_verifies():
    assert verify_tx_signature(_tx()) == (True, "")


@pytest.mark.parametrize(
    "field,value",
    [
        ("sequence_number", 8),
        ("expiration_time", 1_700_000_001),
        ("expire_at_height", 91),
        ("fee_limit", "11"),
        ("operations", {"1": [["a" * 96, "b" * 96, "6"]]}),
    ],
)
def test_a_tampered_signed_field_fails(field, value):
    tx = _tx()
    tx[field] = value
    assert verify_tx_signature(tx) == (False, "signature does not verify against sender_pubkey")


def test_another_keys_signature_fails():
    tx = _tx(SK_BOB)
    tx["sender_pubkey"] = pubkey_hex(SK_ALICE)
    assert verify_tx_signature(tx) == (False, "signature does not verify against sender_pubkey")


def test_the_identity_pubkey_with_the_identity_signature_fails():
    tx = _tx()
    tx["sender_pubkey"] = IDENTITY_PK
    tx["signature"] = IDENTITY_SIG
    assert verify_tx_signature(tx) == (False, "signature does not verify against sender_pubkey")


@pytest.mark.parametrize("field", ["signature", "sender_pubkey"])
def test_malformed_hex_fails(field):
    tx = _tx()
    tx[field] = "zz" * 40
    assert verify_tx_signature(tx) == (False, "signature or sender_pubkey is not valid hex")


def test_a_missing_signature_fails():
    tx = _tx()
    del tx["signature"]
    assert verify_tx_signature(tx) == (False, "missing sender_pubkey or signature")


def test_a_non_string_signature_fails():
    tx = _tx()
    tx["signature"] = 12345
    assert verify_tx_signature(tx) == (False, "missing sender_pubkey or signature")


def test_a_payload_missing_a_signed_field_is_unsignable():
    tx = _tx()
    del tx["fee_limit"]
    ok, reason = verify_tx_signature(tx)
    assert ok is False and reason.startswith("unsignable payload")


def test_the_verdict_comes_from_bls_verify():
    tx = _tx()
    tx["signature"] = "00" * 96
    with patch.object(tx_signing, "_bls_verify", return_value=True) as forced:
        assert verify_tx_signature(tx) == (True, "")
    assert forced.call_count == 1
