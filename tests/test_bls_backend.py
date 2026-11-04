"""Header proofs must get exactly py_ecc's verdict.

A divergence is a consensus split: two nodes would disagree on whether a block
header is validly signed.
"""
import hashlib
import json
import random
from pathlib import Path
from unittest.mock import patch

from block import Block, BlockHeader, sha256_hex
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_header, sign_payload
from consensus import bls
from consensus.tx_signing import verify_tx_signature

FIXTURES = Path(__file__).parent / "fixtures"
HEADER_VECTORS = json.loads((FIXTURES / "bls_header_vectors.json").read_text())["vectors"]
LIVE_HEADER_SAMPLE = 6


def _header(fields, proposer):
    return BlockHeader(proposer_pubkey=proposer, **fields)


def _block(header, proof):
    return Block(
        header=header,
        transactions=[],
        block_hash=sha256_hex(header.canonical_bytes()),
        consensus_proof=proof,
        tx_ids=[],
    )


def _vector_block(v):
    return _block(_header(v["header"], v["proposer"]), v["proof"])


def _signed_block(sk=SK_ALICE, number=5):
    header = BlockHeader(
        block_number=number,
        previous_hash="11" * 32,
        timestamp=1_700_000_000,
        merkle_root="22" * 32,
        proposer_pubkey=pubkey_hex(sk),
        state_hash="33" * 32,
    )
    return _block(header, sign_header(header, sk))


def test_header_vectors_cover_both_verdicts_and_the_edge_groups():
    assert len(HEADER_VECTORS) >= 200
    verdicts = [v["expected"] for v in HEADER_VECTORS]
    assert verdicts.count(True) >= 30 and verdicts.count(False) >= 100
    labels = {v["label"].split(":")[0] for v in HEADER_VECTORS}
    assert {
        "valid",
        "tampered",
        "swapped_proposer",
        "sig_by_other_key",
        "sig_over_other_header",
        "edge_pubkey",
        "edge_proof",
    } <= labels
    assert all(v["header"]["block_number"] >= 1 for v in HEADER_VECTORS)


def test_every_header_vector_gets_the_oracle_verdict():
    wrong = [
        (i, v["label"], v["expected"])
        for i, v in enumerate(HEADER_VECTORS)
        if _vector_block(v).verify_consensus_proof() is not v["expected"]
    ]
    assert wrong == []


def test_a_live_header_sample_still_matches_py_ecc():
    from py_ecc.bls import G2Basic

    rng = random.Random(20261104)
    accepted = [i for i, v in enumerate(HEADER_VECTORS) if v["expected"]]
    # Tampered headers reach the pairing, so they cost a full verify.
    rejected = [i for i, v in enumerate(HEADER_VECTORS) if v["label"].startswith("tampered:")]
    half = LIVE_HEADER_SAMPLE // 2
    for i in rng.sample(accepted, half) + rng.sample(rejected, LIVE_HEADER_SAMPLE - half):
        v = HEADER_VECTORS[i]
        block = _vector_block(v)
        digest = hashlib.sha256(block.header.canonical_bytes()).digest()
        oracle = bool(
            G2Basic.Verify(bytes.fromhex(v["proposer"]), digest, bytes.fromhex(v["proof"]))
        )
        assert oracle is v["expected"], (i, v["label"])
        assert block.verify_consensus_proof() is oracle, (i, v["label"])


def test_block_zero_is_valid_without_a_proof():
    header = BlockHeader(
        block_number=0,
        previous_hash="00" * 32,
        timestamp=0,
        merkle_root="00" * 32,
        proposer_pubkey="",
    )
    assert _block(header, None).verify_consensus_proof() is True


def test_a_dict_proof_uses_its_signature_field():
    block = _signed_block()
    block.consensus_proof = {"signature": block.consensus_proof}
    assert block.verify_consensus_proof() is True
    block.consensus_proof = {"signature": "00" * 96}
    assert block.verify_consensus_proof() is False


def test_a_missing_proof_or_proposer_or_bad_hex_is_false():
    block = _signed_block()
    good = block.consensus_proof
    for proof in (None, "", {}, {"signature": None}, "zz" * 96, "abc"):
        block.consensus_proof = proof
        assert block.verify_consensus_proof() is False, proof
    block.consensus_proof = good
    block.header.proposer_pubkey = ""
    assert block.verify_consensus_proof() is False
    block.header.proposer_pubkey = "zz" * 48
    assert block.verify_consensus_proof() is False


def test_an_uppercase_hex_proof_gets_the_same_verdict():
    block = _signed_block()
    block.consensus_proof = block.consensus_proof.upper()
    assert block.verify_consensus_proof() is True
    block.consensus_proof = ("00" * 96).upper()
    assert block.verify_consensus_proof() is False


def test_the_genuine_header_proof_verifies_and_a_swapped_key_does_not():
    block = _signed_block(SK_ALICE)
    assert block.verify_consensus_proof() is True
    block.header.proposer_pubkey = pubkey_hex(SK_BOB)
    assert block.verify_consensus_proof() is False


def test_patching_bls_verify_forces_the_header_and_the_tx_verdict():
    block = _signed_block()
    block.consensus_proof = "00" * 96
    tx = sign_payload(
        {
            "tx_type": "user_tx",
            "sender_pubkey": pubkey_hex(SK_ALICE),
            "sequence_number": 1,
            "expiration_time": 1_700_000_000,
            "fee_limit": "0",
            "operations": {},
        },
        SK_ALICE,
    )
    tx["signature"] = "00" * 96
    assert block.verify_consensus_proof() is False
    assert verify_tx_signature(tx)[0] is False
    with patch.object(bls, "verify", return_value=True) as forced:
        assert block.verify_consensus_proof() is True
        assert verify_tx_signature(tx) == (True, "")
    assert forced.call_count == 2

