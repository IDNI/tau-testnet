"""Issue #11: gettxstatus resolution (queued/expired/confirmed/dropped/unknown)."""
import json
import time
import types

import pytest

import db
import block as block_module
from commands import gettxstatus


@pytest.fixture()
def container():
    return types.SimpleNamespace(db=db)


def _status(container, tx_hash):
    resp = json.loads(gettxstatus.execute(f"gettxstatus {tx_hash}", container))
    assert resp["status"] == "ok", resp
    return resp["data"]


def _add_mempool(tx_hash, expiration):
    payload = {
        "tx_type": "user_tx", "sender_pubkey": "a" * 96, "sequence_number": 0,
        "expiration_time": expiration, "operations": {"1": []}, "signature": "00" * 48,
    }
    db.add_mempool_tx(json.dumps(payload), tx_hash, int(time.time() * 1000))


def _set_canonical_head(block_hash, number):
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_hash', ?)",
            (block_hash,),
        )
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_number', ?)",
            (str(number),),
        )
        db._db_conn.commit()


def test_queued(temp_database, container):
    _add_mempool("aa" * 32, 9999999999)
    data = _status(container, "aa" * 32)
    assert data["status"] == "queued"


def test_reserved_is_queued(temp_database, container):
    _add_mempool("bb" * 32, 9999999999)
    with db._db_lock:
        db._db_conn.execute("UPDATE mempool SET status='reserved' WHERE tx_hash=?", ("bb" * 32,))
        db._db_conn.commit()
    assert _status(container, "bb" * 32)["status"] == "queued"


def test_expired_in_mempool(temp_database, container):
    _add_mempool("cc" * 32, int(time.time()) - 100)
    assert _status(container, "cc" * 32)["status"] == "expired"


def test_confirmed(temp_database, container):
    tx = {"tx_id": "t", "operations": {"1": [["a" * 96, "b" * 96, "1"]]}}
    genesis = block_module.Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey="a" * 96, timestamp=1_700_000_000)
    blk = block_module.Block.create(
        block_number=1, previous_hash=genesis.block_hash, transactions=[tx],
        proposer_pubkey="a" * 96, timestamp=1_700_000_001)
    db.add_block(genesis)
    db.add_block(blk)
    _set_canonical_head(blk.block_hash, 1)
    data = _status(container, blk.tx_ids[0])
    assert data["status"] == "confirmed"
    assert data["block_number"] == 1
    assert data["confirmations"] == 1


def test_fork_only_block_is_unknown(temp_database, container):
    # A tx that lives only in a non-canonical fork block resolves to unknown
    # (it is not in the mempool, not dropped, and not on the canonical chain).
    genesis = block_module.Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey="a" * 96, timestamp=1_700_000_000)
    canonical = block_module.Block.create(
        block_number=1, previous_hash=genesis.block_hash, transactions=[],
        proposer_pubkey="a" * 96, timestamp=1_700_000_001)
    fork_tx = {"tx_id": "f", "operations": {"1": [["a" * 96, "c" * 96, "9"]]}}
    fork = block_module.Block.create(
        block_number=1, previous_hash=genesis.block_hash, transactions=[fork_tx],
        proposer_pubkey="a" * 96, timestamp=1_700_000_999)
    db.add_block(genesis)
    db.add_block(canonical)
    db.add_block(fork)
    _set_canonical_head(canonical.block_hash, 1)
    assert _status(container, fork.tx_ids[0])["status"] == "unknown"


def test_dropped_reasons(temp_database, container):
    db.record_dropped_txs(["dd" * 32], "rejected")
    db.record_dropped_txs(["ee" * 32], "evicted")
    assert _status(container, "dd" * 32)["status"] == "rejected"
    assert _status(container, "ee" * 32)["status"] == "evicted"


def test_unknown(temp_database, container):
    assert _status(container, "ab" * 32)["status"] == "unknown"


def test_malformed_hash(temp_database, container):
    resp = json.loads(gettxstatus.execute("gettxstatus not_a_hash", container))
    assert resp["status"] == "error"
    assert resp["error"]["code"] == "INVALID_PARAMS"


def test_usage(temp_database, container):
    resp = json.loads(gettxstatus.execute("gettxstatus", container))
    assert resp["status"] == "error"
