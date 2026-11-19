"""Cross-network replay protection for programmable payments (#34: "Replays and
cross-network reuse fail").

Every programmable-payment transaction signs ``chain_id`` (the genesis hash).
A transaction signed for another network is refused at admission and at block
apply, and tampering with the field breaks the signature.
"""
import hashlib
import itertools

import pytest
from py_ecc.bls import G2Basic

from chain_ids import OTHER_CHAIN_ID, TEST_CHAIN_ID
from consensus import chain_binding
from consensus.admission import validate_route_payload
from consensus.facade import TipAdmissionView
from consensus.tx_signing import signing_message_bytes, verify_tx_signature
from tau_testnet_cli import tx as tx_mod
from tests.test_retractable_apply import ALICE, BOB, CAROL, FAR, SK_ALICE, SK_BOB, Chain, _sign

_SEQ = itertools.count()
T0 = 1_795_000_000


def _route(chain_id, seq=0):
    tx = {"tx_id": f"route-{next(_SEQ)}", "tx_type": "receive_route_set",
          "sender_pubkey": BOB, "sequence_number": seq, "expiration_time": FAR,
          "expire_at_height": 1000, "fee_limit": "100", "chain_id": chain_id,
          "destination_pubkey": CAROL, "bps": 2000, "min_incoming": 0,
          "activate_at": 0, "expires_at": 0, "locked_until": 0}
    return _sign(tx, SK_BOB)


def test_chain_id_is_signed():
    tx = _route(TEST_CHAIN_ID)
    assert verify_tx_signature(tx)[0]
    tampered = dict(tx, chain_id=OTHER_CHAIN_ID)
    assert signing_message_bytes(tampered) != signing_message_bytes(tx)
    assert not verify_tx_signature(tampered)[0]


def test_older_transaction_types_sign_exactly_as_before():
    plain = {"tx_type": "user_tx", "sender_pubkey": ALICE, "sequence_number": 0,
             "expiration_time": 1, "fee_limit": "0", "operations": {}}
    assert b"chain_id" not in signing_message_bytes(dict(plain, chain_id=TEST_CHAIN_ID))


def test_block_apply_refuses_another_networks_transaction():
    ch = Chain({BOB: 100})
    ch.block([_route(OTHER_CHAIN_ID)], ts=T0)
    assert ch.last.invalid_tx_ids and ch.lm.receive_routes.get(BOB) is None
    ch.block([_route(TEST_CHAIN_ID)], ts=T0 + 1)
    assert ch.lm.receive_routes.get(BOB) is not None


@pytest.mark.parametrize("value", [None, "", "zz" * 32, TEST_CHAIN_ID[:-2]])
def test_missing_or_malformed_chain_id_is_refused(value):
    tx = {"tx_type": "grant_cancel", "chain_id": value}
    assert "chain_id" in (chain_binding.check_chain_id(tx) or "")


def test_admission_refuses_another_network(temp_database):
    tx = _route(OTHER_CHAIN_ID)
    res = validate_route_payload(tx, TipAdmissionView())
    assert not res.is_valid and res.code == "WRONG_CHAIN_ID"
    assert validate_route_payload(_route(TEST_CHAIN_ID), TipAdmissionView()).is_valid


def test_unknown_chain_fails_closed(monkeypatch):
    monkeypatch.setattr(chain_binding, "current_chain_id", lambda: "")
    assert "does not know" in chain_binding.check_chain_id(
        {"tx_type": "grant_cancel", "chain_id": TEST_CHAIN_ID})


def test_builders_require_a_chain_id():
    with pytest.raises(ValueError):
        tx_mod.build_route_remove_tx(sender_pubkey=BOB, sequence_number=0,
                                     expiration_time=1, expire_at_height=1)
