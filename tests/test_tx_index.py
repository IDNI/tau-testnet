"""Issue #11: tx_index population/backfill, canonical resolution, drop recording."""
import json
import time

import pytest

import config
import db
import block as block_module


def _mk_block(number, prev_hash, txs, proposer="a" * 96, ts=1_700_000_000):
    return block_module.Block.create(
        block_number=number,
        previous_hash=prev_hash,
        transactions=txs,
        proposer_pubkey=proposer,
        timestamp=ts,
    )


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


def test_add_block_populates_tx_index(temp_database):
    tx = {"tx_id": "x", "operations": {"1": [["a" * 96, "b" * 96, "5"]]}}
    blk = _mk_block(1, "00" * 32, [tx])
    db.add_block(blk)
    locs = db.get_tx_block_locations(blk.tx_ids[0])
    assert len(locs) == 1
    assert locs[0]["block_hash"] == blk.block_hash
    assert locs[0]["block_number"] == 1


def test_add_block_index_idempotent(temp_database):
    tx = {"tx_id": "x", "operations": {"1": [["a" * 96, "b" * 96, "5"]]}}
    blk = _mk_block(1, "00" * 32, [tx])
    db.add_block(blk)
    # Inserting the same tx_index rows again must not raise or duplicate.
    with db._db_lock:
        for th in blk.tx_ids:
            db._db_conn.execute(
                "INSERT OR IGNORE INTO tx_index (tx_hash, block_hash, block_number) VALUES (?,?,?)",
                (th, blk.block_hash, 1),
            )
        db._db_conn.commit()
    assert len(db.get_tx_block_locations(blk.tx_ids[0])) == 1


def test_tx_index_backfill_on_reinit(temp_database):
    tx = {"tx_id": "x", "operations": {"1": [["a" * 96, "b" * 96, "5"]]}}
    blk = _mk_block(1, "00" * 32, [tx])
    db.add_block(blk)
    tx_hash = blk.tx_ids[0]
    # Simulate a pre-upgrade DB: wipe the index but keep the block.
    with db._db_lock:
        db._db_conn.execute("DELETE FROM tx_index")
        db._db_conn.commit()
    assert db.get_tx_block_locations(tx_hash) == []
    # Re-init (as on process restart) triggers the one-time backfill.
    db._db_conn.close()
    db._db_conn = None
    db.init_db()
    locs = db.get_tx_block_locations(tx_hash)
    assert len(locs) == 1
    assert locs[0]["block_hash"] == blk.block_hash


def test_canonical_confirmation_across_fork(temp_database):
    # Genesis -> A (canonical) and Genesis -> B (fork) at height 1.
    genesis = _mk_block(0, "00" * 32, [])
    db.add_block(genesis)
    tx_a = {"tx_id": "a", "operations": {"1": [["a" * 96, "b" * 96, "1"]]}}
    tx_b = {"tx_id": "b", "operations": {"1": [["a" * 96, "c" * 96, "2"]]}}
    blk_a = _mk_block(1, genesis.block_hash, [tx_a])
    blk_b = _mk_block(1, genesis.block_hash, [tx_b], ts=1_700_000_999)
    db.add_block(blk_a)
    db.add_block(blk_b)
    _set_canonical_head(blk_a.block_hash, 1)

    ok_a, head_a = db.get_canonical_confirmation(blk_a.block_hash, 1)
    ok_b, _ = db.get_canonical_confirmation(blk_b.block_hash, 1)
    assert ok_a is True and head_a == 1
    assert ok_b is False


def test_add_mempool_expiry_records_dropped(temp_database):
    now_s = int(time.time())
    expired = {
        "tx_type": "user_tx", "sender_pubkey": "a" * 96, "sequence_number": 0,
        "expiration_time": now_s - 10, "operations": {"1": []}, "signature": "00" * 48,
    }
    fresh = dict(expired)
    fresh["expiration_time"] = now_s + 10_000
    fresh["sequence_number"] = 1
    db.add_mempool_tx(json.dumps(expired), "11" * 32, now_s * 1000)
    # A second insert triggers the expiry prune of the first.
    db.add_mempool_tx(json.dumps(fresh), "22" * 32, now_s * 1000)
    dropped = db.get_dropped_tx("11" * 32)
    assert dropped is not None
    assert dropped["reason"] == "expired"


def test_record_dropped_txs_public(temp_database):
    db.record_dropped_txs(["33" * 32], "rejected")
    d = db.get_dropped_tx("33" * 32)
    assert d["reason"] == "rejected"
    assert db.get_dropped_tx("44" * 32) is None
