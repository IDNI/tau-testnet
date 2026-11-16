"""Public-key validation must return exactly py_ecc KeyValidate's verdict.

A divergence is a split in what admission accepts, and a way for a key that
cannot sign to receive funds.
"""
import json
import random
from pathlib import Path

import pytest

from bls_keys import SK_ALICE, pubkey_hex
from consensus import bls
from consensus.tx_checks import validate_bls_pubkey

FIXTURES = Path(__file__).parent / "fixtures"
KEY_VECTORS = json.loads((FIXTURES / "bls_keyvalidate_vectors.json").read_text())["vectors"]
LIVE_KEY_SAMPLE = 30

IDENTITY_PK = "c0" + "00" * 47


def test_key_vectors_cover_both_verdicts_and_the_edge_groups():
    assert len(KEY_VECTORS) >= 300
    assert len({v["pk"] for v in KEY_VECTORS}) == len(KEY_VECTORS)
    assert all(len(bytes.fromhex(v["pk"])) == 48 for v in KEY_VECTORS)
    verdicts = [v["expected"] for v in KEY_VECTORS]
    assert verdicts.count(True) >= 60 and verdicts.count(False) >= 150
    labels = {v["label"].split(":")[0] for v in KEY_VECTORS}
    assert {
        "valid",
        "identity_variant",
        "flags",
        "noncanon",
        "nonsubgroup",
        "offcurve",
        "sweep",
        "random_bytes",
    } <= labels


def test_every_key_vector_gets_the_oracle_verdict():
    wrong = [
        (i, v["label"], v["expected"])
        for i, v in enumerate(KEY_VECTORS)
        if bls.pubkey_valid(bytes.fromhex(v["pk"])) is not v["expected"]
    ]
    assert wrong == []


def test_a_live_key_sample_still_matches_py_ecc():
    from py_ecc.bls import G2Basic

    rng = random.Random(20261105)
    accepted = [i for i, v in enumerate(KEY_VECTORS) if v["expected"]]
    rejected = [i for i, v in enumerate(KEY_VECTORS) if not v["expected"]]
    half = LIVE_KEY_SAMPLE // 2
    for i in rng.sample(accepted, half) + rng.sample(rejected, LIVE_KEY_SAMPLE - half):
        v = KEY_VECTORS[i]
        pk = bytes.fromhex(v["pk"])
        oracle = bool(G2Basic.KeyValidate(pk))
        assert oracle is v["expected"], (i, v["label"])
        assert bls.pubkey_valid(pk) is oracle, (i, v["label"])


@pytest.mark.parametrize(
    "pk", [b"", bytes(47), bytes(49), bytearray(48), bytes(48).hex(), None, 5]
)
def test_pubkey_valid_rejects_non_48_byte_input_without_raising(pk):
    assert bls.pubkey_valid(pk) is False


def test_the_validator_accepts_a_real_key():
    assert validate_bls_pubkey(pubkey_hex(SK_ALICE), "k") is None


@pytest.mark.parametrize("key", [IDENTITY_PK, "00" * 48, "a" * 96])
def test_the_validator_rejects_bytes_that_are_not_a_key(key):
    assert validate_bls_pubkey(key, "sender_pubkey") == (
        "Invalid sender_pubkey: not a valid BLS12-381 public key."
    )


@pytest.mark.parametrize("key", ["ab" * 10, "zz" * 48, None, 5])
def test_the_validator_rejects_malformed_text_before_decoding(key):
    assert validate_bls_pubkey(key, "k") == (
        "Invalid k: must be a 96-character hex BLS12-381 public key."
    )


@pytest.mark.parametrize("v", KEY_VECTORS, ids=lambda v: v["label"])
def test_the_validator_agrees_with_every_key_vector(v):
    assert (validate_bls_pubkey(v["pk"], "k") is None) is v["expected"]
