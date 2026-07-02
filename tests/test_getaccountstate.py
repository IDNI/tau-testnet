"""Issue #11: pending-aware account state (getaccountstate)."""
import json
import types

import pytest

import chain_state
import db
from commands import getaccountstate, getbalance

SENDER = "a" * 96
RECIP = "b" * 96
OTHER = "c" * 96


@pytest.fixture()
def container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def _add_tx(tx_hash, sender, transfers, *, seq=0, expiration=9999999999,
            fee_limit=0, estimated_fee=0, tx_type="user_tx"):
    payload = {
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": expiration,
        "operations": {"1": transfers} if transfers is not None else {},
        "fee_limit": str(fee_limit),
        "signature": "00" * 48,
    }
    db.add_mempool_tx(json.dumps(payload), tx_hash, 1_700_000_000_000,
                      fee_limit=fee_limit, estimated_fee=estimated_fee)


def _state(container, address):
    resp = json.loads(getaccountstate.execute(f"getaccountstate {address}", container))
    assert resp["status"] == "ok", resp
    return resp["data"]


def test_no_pending_matches_getbalance(temp_database, container):
    chain_state._balances[SENDER] = 1000
    data = _state(container, SENDER)
    assert data["chain_balance"] == "1000"
    assert data["available_balance"] == "1000"
    assert data["pending_outgoing"] == "0"
    assert data["pending_txs"] == []
    # getbalance response is unchanged (regression).
    bal = json.loads(getbalance.execute(f"getbalance {SENDER}", container))
    assert bal["data"] == {"address": SENDER, "balance": "1000"}


def test_outgoing_with_fee(temp_database, container):
    chain_state._balances[SENDER] = 1000
    _add_tx("aa" * 32, SENDER, [[SENDER, RECIP, "101"]], estimated_fee=2)
    data = _state(container, SENDER)
    assert data["pending_outgoing"] == "101"
    assert data["pending_fees"] == "2"
    # available = 1000 - (101 + 2)
    assert data["available_balance"] == "897"
    assert len(data["pending_txs"]) == 1
    tx = data["pending_txs"][0]
    assert tx["direction"] == "outgoing"
    assert tx["amount"] == "101"
    assert tx["fee"] == "2"
    assert tx["status"] == "queued"


def test_incoming_not_spendable(temp_database, container):
    chain_state._balances[RECIP] = 500
    _add_tx("bb" * 32, SENDER, [[SENDER, RECIP, "50"]], estimated_fee=1)
    data = _state(container, RECIP)
    assert data["pending_incoming"] == "50"
    assert data["pending_outgoing"] == "0"
    assert data["pending_fees"] == "0"  # recipient does not pay the sender's fee
    # incoming is reported but not added to available.
    assert data["available_balance"] == "500"
    assert data["pending_txs"][0]["direction"] == "incoming"


def test_self_transfer_nets_out(temp_database, container):
    chain_state._balances[SENDER] = 1000
    _add_tx("cc" * 32, SENDER, [[SENDER, SENDER, "10"]], estimated_fee=3)
    data = _state(container, SENDER)
    assert data["pending_outgoing"] == "10"
    assert data["pending_incoming"] == "10"
    assert data["pending_fees"] == "3"
    # available = 1000 - 10 - 3 (the fee still applies)
    assert data["available_balance"] == "987"
    assert data["pending_txs"][0]["direction"] == "self"


def test_multi_transfer_sums(temp_database, container):
    chain_state._balances[SENDER] = 1000
    _add_tx("dd" * 32, SENDER, [[SENDER, RECIP, "10"], [SENDER, OTHER, "5"]],
            estimated_fee=4)
    data = _state(container, SENDER)
    assert data["pending_outgoing"] == "15"
    assert data["pending_fees"] == "4"
    assert data["available_balance"] == "981"


def test_reserved_status_renders_queued(temp_database, container):
    chain_state._balances[SENDER] = 1000
    _add_tx("ee" * 32, SENDER, [[SENDER, RECIP, "10"]])
    with db._db_lock:
        db._db_conn.execute("UPDATE mempool SET status='reserved' WHERE tx_hash=?", ("ee" * 32,))
        db._db_conn.commit()
    data = _state(container, SENDER)
    assert data["pending_txs"][0]["status"] == "queued"
    assert data["pending_outgoing"] == "10"


def test_expired_excluded_from_state(temp_database, container):
    chain_state._balances[SENDER] = 1000
    _add_tx("ff" * 32, SENDER, [[SENDER, RECIP, "10"]], expiration=1)  # long past
    data = _state(container, SENDER)
    assert data["pending_outgoing"] == "0"
    assert data["pending_txs"] == []


def test_amounts_are_strings(temp_database, container):
    chain_state._balances[SENDER] = 1000
    _add_tx("ab" * 32, SENDER, [[SENDER, RECIP, "7"]])
    data = _state(container, SENDER)
    for key in ("chain_balance", "pending_outgoing", "pending_incoming",
                "pending_fees", "available_balance"):
        assert isinstance(data[key], str)


def test_usage_error(temp_database, container):
    resp = json.loads(getaccountstate.execute("getaccountstate", container))
    assert resp["status"] == "error"
    assert resp["error"]["code"] == "INVALID_PARAMS"
