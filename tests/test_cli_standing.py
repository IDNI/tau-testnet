"""Tests for `tau-testnet standing ...`, on the canned-response harness."""
from __future__ import annotations

import pytest

from consensus.standing import (
    parse_standing_payment_create,
    parse_standing_payment_execute,
    parse_standing_payment_update,
)
from consensus.network_binding import FIELD, chain_genesis_hash
from consensus.tx_signing import verify_tx_signature

from tests.test_cli_retractable import ESTIMATED_FEE, TIP, _ok, _run_cli, _sent_payload, alice  # noqa: F401

SID = "ab" * 32
BOB = "bb" * 48
TERMS = ["--to", BOB, "--amount", "250", "--periods", "6", "--every-blocks", "128",
         "--first-due-in", "20"]


def _send(argv, tip=TIP, seq=3):
    """Like the retractable harness, with a node that reports its network."""
    recorded = []
    sequence = {"sequence_number": seq, "tip_height": tip, "genesis_hash": chain_genesis_hash()}
    rc, out, err = _run_cli(argv, send_responses=[_ok(sequence), _ok({"tx_hash": "de"})],
                            recorded=recorded)
    return rc, out, err, recorded


def test_create_signs_the_terms_and_prints_the_id(alice):
    rc, out, _err, recorded = _send(["standing", "create", "--key", "alice", *TERMS])
    assert rc == 0, out
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "standing_payment_create"
    assert payload[FIELD] == chain_genesis_hash()
    assert verify_tx_signature(payload)[0]
    terms = parse_standing_payment_create(payload)
    assert (terms.amount, terms.interval, terms.periods) == (250, 128, 6)
    assert terms.first_due == TIP + 1 + 20
    assert terms.standing_id.hex() in out


def test_update_signs_the_replaced_id_and_the_new_terms(alice):
    rc, out, _err, recorded = _send(["standing", "update", SID, "--key", "alice", *TERMS])
    assert rc == 0, out
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "standing_payment_update"
    assert payload["fee_limit"] == ESTIMATED_FEE
    assert payload[FIELD] == chain_genesis_hash()
    assert verify_tx_signature(payload)[0]
    old, terms = parse_standing_payment_update(payload)
    assert old.hex() == SID and terms.payer_pubkey == alice
    assert f"new version of {SID}: {terms.standing_id.hex()}" in out


def test_execute_names_only_the_authorization(alice):
    rc, out, _err, recorded = _send(["standing", "execute", SID, "--key", "alice"])
    assert rc == 0, out
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "standing_payment_execute"
    assert payload[FIELD] == chain_genesis_hash()
    assert verify_tx_signature(payload)[0]
    assert parse_standing_payment_execute(payload) == (alice, bytes.fromhex(SID))
    assert not {"amount", "recipient_pubkey"} & set(payload)


@pytest.mark.parametrize("argv", [
    ["standing", "execute", "xyz", "--key", "alice"],
    ["standing", "update", "xyz", "--key", "alice", *TERMS],
])
def test_a_bad_id_is_refused_before_anything_is_sent(alice, argv):
    rc, _out, _err, recorded = _send(argv)
    assert rc != 0
    assert not any(c.startswith("sendtx ") for c in recorded)
