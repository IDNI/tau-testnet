"""A transaction signed for one network is refused on every other one.

The types in `BOUND_TX_TYPES` sign `genesis_hash`, the hash of block 0 of the
network they are for. These tests hold the three places that enforce it to the
same answer: the signed bytes, mempool admission and block apply (through the
real `apply_block`, against the full-state oracle of the standing payment
tests). Every other type must keep the bytes it signed before.
"""
import hashlib
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import MagicMock, patch

import pytest
from py_ecc.bls import G2Basic

import db
from commands import getsequence
from consensus import network_binding
from consensus.admission import TipAdmissionView, validate_mempool_admission
from consensus.network_binding import BOUND_TX_TYPES, FIELD, chain_genesis_hash, problem
from consensus.standing import StandingBook
from consensus.tx_checks import apply_tx_error
from consensus.tx_signing import signing_message_bytes, verify_tx_signature
from tau_testnet_cli import cli, keys as keys_mod, tx as tx_mod

from tests.test_standing_apply import (
    ALICE, BOB, HEIGHT, SK_ALICE, Chain, Oracle, _balances, _logs,
    cancel_tx, create_tx, sid_of, spend_tx,
)

HERE = chain_genesis_hash()
ELSEWHERE = "c3" * 32


def on_network(tx: dict, genesis_hash, sk=SK_ALICE) -> dict:
    """`tx` as its sender would have signed it for another network, or (None)
    without naming one. Signed here, because the shared `_sign` fills the field in."""
    if genesis_hash is None:
        tx.pop(FIELD, None)
    else:
        tx[FIELD] = genesis_hash
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


# --- the rule itself --------------------------------------------------------------

def test_the_test_network_is_the_one_the_node_reports():
    assert HERE == chain_genesis_hash() and len(HERE) == 64 and HERE != ELSEWHERE


def test_a_transaction_for_this_network_passes():
    assert problem(create_tx()) is None
    assert problem(cancel_tx("ab" * 32)) is None


@pytest.mark.parametrize("value,why", [
    (ELSEWHERE, "another network"),
    (None, "must be the hash of block 0"),
    ("", "must be the hash of block 0"),
    (HERE.upper(), "must be the hash of block 0"),
    (HERE[:-2], "must be the hash of block 0"),
    (HERE + "00", "must be the hash of block 0"),
    (int(HERE, 16), "must be the hash of block 0"),
    ([HERE], "must be the hash of block 0"),
])
def test_any_other_value_is_refused_with_its_reason(value, why):
    for tx in (create_tx(), cancel_tx("ab" * 32)):
        tx[FIELD] = value
        if value is None:
            del tx[FIELD]
        assert why in problem(tx)


def test_the_refusal_names_both_networks():
    reason = problem(on_network(create_tx(), ELSEWHERE))
    assert ELSEWHERE[:16] in reason and HERE[:16] in reason


def test_types_outside_the_list_are_never_asked():
    plain = spend_tx(ALICE, BOB, 5, 0)
    assert problem(plain) is None
    assert problem({**plain, FIELD: ELSEWHERE}) is None
    assert problem({"tx_type": "retractable_transfer", FIELD: ELSEWHERE}) is None
    assert problem({}) is None and problem(None) is None


def test_a_node_without_a_genesis_block_refuses(monkeypatch):
    tx = create_tx()
    monkeypatch.setattr(network_binding, "_known", None)
    monkeypatch.setattr(db, "get_genesis_hash", lambda: "")
    assert chain_genesis_hash() == ""
    assert "no genesis block yet" in problem(tx)
    assert apply_tx_error(tx)[0] == "wrong_network"


# --- where the node learns its own network ---------------------------------------

def test_the_node_reads_block_0_once_and_keeps_it(monkeypatch):
    calls = []
    monkeypatch.setattr(network_binding, "_known", None)
    monkeypatch.setattr(db, "get_genesis_hash", lambda: calls.append(1) or ELSEWHERE)
    assert chain_genesis_hash() == ELSEWHERE and chain_genesis_hash() == ELSEWHERE
    assert len(calls) == 1
    network_binding.forget()
    assert chain_genesis_hash() == ELSEWHERE and len(calls) == 2


@pytest.mark.parametrize("stored", ["", "GENESIS", None, "zz" * 32, ELSEWHERE.upper()])
def test_a_placeholder_is_never_taken_for_a_network(monkeypatch, stored):
    monkeypatch.setattr(network_binding, "_known", None)
    monkeypatch.setattr(db, "get_genesis_hash", lambda: stored)
    assert chain_genesis_hash() == ""
    # ... and it is not kept: the real hash is read once it is there.
    monkeypatch.setattr(db, "get_genesis_hash", lambda: ELSEWHERE)
    assert chain_genesis_hash() == ELSEWHERE


def test_a_database_error_reads_as_no_network(monkeypatch):
    def boom():
        raise RuntimeError("database is closed")

    monkeypatch.setattr(network_binding, "_known", None)
    monkeypatch.setattr(db, "get_genesis_hash", boom)
    assert chain_genesis_hash() == ""


def test_getsequence_reports_the_network():
    container = MagicMock()
    container.chain_state.get_sequence_number.return_value = 4
    with patch.object(db, "get_pending_sequence", return_value=None), \
         patch.object(db, "get_canonical_head_block", return_value=None):
        data = json.loads(getsequence.execute(f"getsequence {ALICE}", container))["data"]
    assert data == {"address": ALICE, "sequence_number": 4, "tip_height": 0,
                    "genesis_hash": HERE}


# --- the signed bytes -------------------------------------------------------------

@pytest.mark.parametrize("make", [create_tx, lambda: cancel_tx("ab" * 32)])
def test_the_network_is_in_the_signed_bytes(make):
    tx = make()
    here = signing_message_bytes(tx)
    assert json.loads(here)[FIELD] == HERE
    assert signing_message_bytes({**tx, FIELD: ELSEWHERE}) != here


@pytest.mark.parametrize("make", [create_tx, lambda: cancel_tx("ab" * 32)])
def test_the_network_cannot_be_rewritten_after_signing(make):
    signed_elsewhere = on_network(make(), ELSEWHERE)
    assert verify_tx_signature(signed_elsewhere)[0]
    moved = {**signed_elsewhere, FIELD: HERE}
    assert problem(moved) is None                 # it now claims this network ...
    assert not verify_tx_signature(moved)[0]      # ... which its sender never signed


def test_older_types_sign_exactly_what_they_signed_before():
    plain = spend_tx(ALICE, BOB, 5, 0)
    before = signing_message_bytes(plain)
    assert FIELD not in json.loads(before)
    assert signing_message_bytes({**plain, FIELD: ELSEWHERE}) == before
    assert verify_tx_signature({**plain, FIELD: ELSEWHERE})[0]


# --- mempool admission ------------------------------------------------------------

@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = HEIGHT
    view.tip_timestamp = 1_767_225_600
    view.next_block_timestamp = 1_767_225_600
    view.standing_book.return_value = StandingBook()
    return view


def _admit(tx, tip_view):
    return validate_mempool_admission({**tx, "expire_at_height": HEIGHT + 3}, tip_view)


def test_admission_takes_a_create_for_this_network(tip_view):
    result = _admit(create_tx(), tip_view)
    assert result.is_valid, result.error


@pytest.mark.parametrize("value", [ELSEWHERE, None, HERE.upper()])
def test_admission_refuses_another_network_with_a_code(tip_view, value):
    for tx in (create_tx(), cancel_tx("ab" * 32)):
        result = _admit(on_network(tx, value), tip_view)
        assert not result.is_valid and result.code == "WRONG_NETWORK", result.error
        assert result.details == {"genesis_hash": HERE}
        assert tx["tx_type"] in result.error


@pytest.mark.parametrize("value", [HERE, ELSEWHERE, None, "", HERE.upper(), HERE[:-2], 7])
def test_admission_and_apply_agree_on_every_value(tip_view, value):
    tx = on_network(create_tx(), value) if isinstance(value, (str, type(None))) \
        else {**create_tx(), FIELD: value}
    refused_at_admission = _admit(tx, tip_view).code == "WRONG_NETWORK"
    at_apply = apply_tx_error(tx)
    assert refused_at_admission == (at_apply is not None)
    assert refused_at_admission == (value != HERE)
    if at_apply is not None:
        assert at_apply[0] == "wrong_network"


# --- block apply ------------------------------------------------------------------

def test_a_create_signed_for_another_network_stays_out_and_pays_nothing():
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    result = ch.block([on_network(create_tx(), ELSEWHERE)])
    oracle.check(ch)                      # no fee, no sequence number used
    assert ch.book.is_empty() and not ch.book.terms
    assert "another network" in _logs(result)
    assert [(o.status, o.reason) for o in result.outcomes] == [("invalid", "wrong_network")]
    assert result.accepted_tx_ids == []


def test_the_same_create_for_this_network_is_applied():
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    tx = create_tx()
    ch.block([tx])
    oracle.create(tx, fee=7)
    oracle.check(ch)
    assert ch.book.knows(bytes.fromhex(sid_of(tx)))


@pytest.mark.parametrize("value", [None, HERE.upper(), HERE[:-2]])
def test_a_create_without_a_proper_network_stays_out(value):
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    result = ch.block([on_network(create_tx(), value)])
    oracle.check(ch)
    assert ch.book.is_empty()
    assert "must be the hash of block 0" in _logs(result)


def test_a_create_moved_to_this_network_after_signing_stays_out():
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    moved = {**on_network(create_tx(), ELSEWHERE), FIELD: HERE}
    result = ch.block([moved])
    oracle.check(ch)
    assert ch.book.is_empty()
    assert "signature" in _logs(result).lower()


def test_a_cancel_signed_for_another_network_ends_nothing():
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    tx = create_tx()
    ch.block([tx])
    oracle.create(tx, fee=7)
    sid = sid_of(tx)

    result = ch.block([on_network(cancel_tx(sid), ELSEWHERE)], height=HEIGHT + 1)
    oracle.check(ch)                      # the cancel used no sequence number
    assert ch.book.knows(bytes.fromhex(sid)) and ch.book.get(bytes.fromhex(sid)) is not None
    assert "another network" in _logs(result)

    ch.block([cancel_tx(sid)], height=HEIGHT + 2)
    oracle.cancel(ALICE)
    oracle.check(ch)
    assert ch.book.get(bytes.fromhex(sid)) is None


def test_a_refused_transaction_does_not_hold_up_the_next_one_in_the_block():
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    good = create_tx()
    ch.block([on_network(create_tx(), ELSEWHERE), good])
    oracle.create(good, fee=7)
    oracle.check(ch)
    assert ch.book.knows(bytes.fromhex(sid_of(good)))


def test_replay_gives_the_same_state_with_a_refused_transaction_in_the_block():
    txs = [on_network(create_tx(), ELSEWHERE), create_tx()]
    fresh, again = Chain(_balances(), fee=7), Chain(_balances(), fee=7)
    fresh.block([dict(t) for t in txs])
    again.block([dict(t) for t in txs], replay=True)
    assert fresh.hashes == again.hashes and fresh.bal == again.bal


# --- the CLI ----------------------------------------------------------------------

def test_the_cli_names_the_network_only_where_it_is_signed():
    bound = tx_mod.bind_to_network({"tx_type": "standing_payment_create"}, HERE)
    assert bound[FIELD] == HERE
    plain = tx_mod.bind_to_network({"tx_type": "user_tx"}, HERE)
    assert FIELD not in plain
    assert FIELD not in tx_mod.bind_to_network({"tx_type": "user_tx"}, "")
    with pytest.raises(ValueError, match="did not report its genesis hash"):
        tx_mod.bind_to_network({"tx_type": "standing_payment_cancel"}, "")


def _run_cli(argv, sequence_answer):
    recorded = []

    def fake_send(command, host, port, *, timeout=10.0, max_bytes=None):
        recorded.append(command)
        if command.startswith("getsequence "):
            return json.dumps({"status": "ok", "command": "getsequence",
                               "data": sequence_answer})
        if command.startswith("checktx estimate "):
            return json.dumps({"status": "ok", "command": "checktx",
                               "data": {"estimated_fee": "13"}})
        return json.dumps({"status": "ok", "command": "sendtx", "data": {"tx_hash": "aa"}})

    out, err = io.StringIO(), io.StringIO()
    with patch("tau_testnet_cli.rpc.send_command", side_effect=fake_send), \
         redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    sent = [json.loads(c[len("sendtx "):].strip().strip("'"))
            for c in recorded if c.startswith("sendtx ")]
    return rc, sent, recorded, err.getvalue()


@pytest.fixture
def alice_key(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    return json.loads((tmp_path / "alice.json").read_text())["public_key_hex"]


STANDING_CREATE = ["standing", "create", "--key", "alice", "--to", BOB, "--amount", "25",
                   "--every-blocks", "200", "--periods", "3", "--first-due-in", "20"]


def test_cli_signs_a_standing_payment_for_the_network_the_node_reports(alice_key):
    rc, sent, recorded, err = _run_cli(
        STANDING_CREATE,
        {"address": alice_key, "sequence_number": 2, "tip_height": 40, "genesis_hash": HERE},
    )
    assert rc == 0, err
    assert [c.split()[0] for c in recorded] == ["getsequence", "checktx", "sendtx"]
    (payload,) = sent
    assert payload["tx_type"] == "standing_payment_create" and payload[FIELD] == HERE
    assert verify_tx_signature(payload)[0] and problem(payload) is None

    rc, sent, _, err = _run_cli(
        ["standing", "cancel", "--key", "alice", "ab" * 32],
        {"address": alice_key, "sequence_number": 3, "tip_height": 40, "genesis_hash": HERE},
    )
    assert rc == 0, err
    assert sent[0][FIELD] == HERE and verify_tx_signature(sent[0])[0]


def test_cli_sends_nothing_when_the_node_names_no_network(alice_key):
    rc, sent, recorded, err = _run_cli(
        STANDING_CREATE,
        {"address": alice_key, "sequence_number": 2, "tip_height": 40},   # an older node
    )
    assert rc != 0 and sent == []
    assert [c.split()[0] for c in recorded] == ["getsequence"]
    assert "did not report its genesis hash" in err


def test_cli_leaves_a_plain_transfer_as_it_was(alice_key):
    rc, sent, _, err = _run_cli(
        ["tx", "send", "--key", "alice", "--transfer", f"{BOB}:5", "--fee", "0"],
        {"address": alice_key, "sequence_number": 0, "tip_height": 40, "genesis_hash": HERE},
    )
    assert rc == 0, err
    assert FIELD not in sent[0]


def test_every_bound_type_is_a_type_the_node_knows():
    from commands.sendtx import _get_signing_message_bytes  # noqa: F401  (import check)
    from consensus.payout import PAYOUT_TX_TYPES
    from consensus.standing import STANDING_TX_TYPES

    assert set(STANDING_TX_TYPES) | set(PAYOUT_TX_TYPES) <= BOUND_TX_TYPES
