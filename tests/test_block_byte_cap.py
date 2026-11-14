"""Consensus block byte cap (18 MiB stored JSON)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import block as block_mod
import chain_state
import config
import db
from block import (
    Block,
    MAX_BLOCK_BYTES,
    transaction_json_bytes_in_block,
    block_storage_json_bytes,
    block_byte_cap_reason,
)
from errors import BlockByteCapExceeded
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "block_byte_size_vectors.json")
SYNC_BLOCKS_REPLY_CAP = 20971520
PROPOSER = "a" * 96
PREV = "b" * 64
BASE_TS = 1_700_000_000
PROOF = "c" * 192

ESCAPE_SUBSTRINGS = {
    "escapes": ("\\n", "\\t", "\\r"),
    "escape_b": ("\\b",),
    "escape_f": ("\\f",),
    "escape_u0001": ("\\u0001",),
    "escape_u007f": ("\\u007f",),
}

ESCAPE_FORBIDDEN = {
    "escapes": ("\\u000a", "\\u0009", "\\u000d"),
    "escape_b": ("\\u0008",),
    "escape_f": ("\\u000c",),
}


def _parent_snapshot() -> TauStateSnapshot:
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"",
        metadata={
            "balances": {},
            "sequence_numbers": {},
            "lifecycle_manager": MagicMock(),
        },
    )


def _block_with_padding(pad_len: int, *, number: int = 1, previous_hash: str = PREV) -> Block:
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": PROPOSER,
        "sequence_number": 0,
        "padding": "x" * pad_len,
    }
    return Block.create(
        number,
        previous_hash,
        [tx],
        PROPOSER,
        timestamp=BASE_TS,
        consensus_proof=PROOF,
    )


def _find_padding_for_target(target: int) -> int:
    lo, hi = 0, MAX_BLOCK_BYTES
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        n = block_storage_json_bytes(_block_with_padding(mid))
        if n <= target:
            best = mid
            lo = mid + 1
        else:
            hi = mid - 1
    return best


class TestBlockByteSizeSpec(unittest.TestCase):
    def test_fixture_vectors_match_python(self):
        with open(FIXTURES, encoding="utf-8") as f:
            doc = json.load(f)
        self.assertEqual(doc["max_block_bytes"], MAX_BLOCK_BYTES)
        for row in doc["vectors"]:
            payload = json.loads(row["block_json"])
            self.assertEqual(
                block_storage_json_bytes(Block.from_dict(payload)),
                row["byte_count"],
                msg=row["id"],
            )
            received = len(row["block_json"].encode("utf-8"))
            self.assertEqual(received, row.get("received_byte_count", row["byte_count"]), msg=row["id"])
            vid = row["id"]
            if vid in ESCAPE_SUBSTRINGS:
                for frag in ESCAPE_SUBSTRINGS[vid]:
                    self.assertIn(frag, row["block_json"], msg=vid)
            if vid in ESCAPE_FORBIDDEN:
                for frag in ESCAPE_FORBIDDEN[vid]:
                    self.assertNotIn(frag, row["block_json"], msg=vid)

    def test_dropped_keys_do_not_count(self):
        with open(FIXTURES, encoding="utf-8") as f:
            rows = [r for r in json.load(f)["vectors"] if "received_byte_count" in r]
        self.assertTrue(rows)
        for row in rows:
            payload = json.loads(row["block_json"])
            self.assertTrue(set(payload) - set(Block.from_dict(payload).to_dict()), msg=row["id"])
            self.assertGreater(row["received_byte_count"], row["byte_count"], msg=row["id"])
            self.assertEqual(block_storage_json_bytes(payload), row["received_byte_count"], msg=row["id"])

    def test_hex_whitespace_counts_and_keeps_the_hash(self):
        with open(FIXTURES, encoding="utf-8") as f:
            rows = [r for r in json.load(f)["vectors"] if "same_hash_as_previous_hash" in r]
        self.assertTrue(rows)
        for row in rows:
            payload = json.loads(row["block_json"])
            plain = json.loads(row["block_json"])
            plain["header"]["previous_hash"] = row["same_hash_as_previous_hash"]
            blk = Block.from_dict(payload)
            self.assertNotEqual(blk.header.previous_hash, row["same_hash_as_previous_hash"])
            self.assertEqual(blk.block_hash, Block.from_dict(plain).block_hash, msg=row["id"])
            self.assertEqual(block_storage_json_bytes(blk), row["byte_count"], msg=row["id"])
            self.assertGreater(row["byte_count"], block_storage_json_bytes(Block.from_dict(plain)))

    def test_int_header_strings(self):
        with open(FIXTURES, encoding="utf-8") as f:
            cases = json.load(f)["int_header_strings"]
        base = Block.create(3, PREV, [], PROPOSER, timestamp=BASE_TS, consensus_proof=PROOF).to_dict()
        self.assertTrue(any(v is None for _, v in cases) and any(v is not None for _, v in cases))
        for text, value in cases:
            payload = json.loads(json.dumps(base))
            payload["header"]["block_number"] = text
            if value is None:
                with self.assertRaises(ValueError, msg=repr(text)):
                    Block.from_dict(payload)
            else:
                blk = Block.from_dict(payload)
                self.assertEqual(blk.header.block_number, value, msg=repr(text))
                self.assertEqual(blk.to_dict()["header"]["block_number"], value)

    def test_peer_and_db_paths_preserve_byte_count(self):
        blk = Block.create(1, PREV, [], PROPOSER, timestamp=BASE_TS, consensus_proof=PROOF)
        raw = json.dumps(blk.to_dict())
        n0 = len(raw.encode())
        wire = json.loads(raw)
        again = Block.from_dict(wire)
        n1 = block_storage_json_bytes(again)
        self.assertEqual(n0, n1)
        stored = json.dumps(blk.to_dict())
        loaded = json.loads(stored)
        n2 = block_storage_json_bytes(loaded)
        self.assertEqual(n0, n2)

    def test_incremental_size_matches_block_storage_bytes(self):
        txs = [
            {"tx_type": "user_tx", "sequence_number": i, "sender_pubkey": PROPOSER, "memo": "\u00e9\n"}
            for i in range(5)
        ]
        make = lambda body: Block.create(1, PREV, body, PROPOSER, timestamp=BASE_TS, consensus_proof=PROOF)
        total = block_storage_json_bytes(make([]))
        for n, tx in enumerate(txs):
            total += transaction_json_bytes_in_block(tx, first=n == 0)
            self.assertEqual(total, block_storage_json_bytes(make(txs[: n + 1])))


class TestBlockByteCapApply(unittest.TestCase):
    def test_block_at_cap_has_no_cap_reason(self):
        pad = _find_padding_for_target(MAX_BLOCK_BYTES)
        blk = _block_with_padding(pad)
        self.assertEqual(block_storage_json_bytes(blk), MAX_BLOCK_BYTES)
        self.assertIsNone(block_byte_cap_reason(blk))

    def test_block_one_byte_over_cap_is_rejected(self):
        pad = _find_padding_for_target(MAX_BLOCK_BYTES)
        self.assertEqual(block_storage_json_bytes(_block_with_padding(pad)), MAX_BLOCK_BYTES)
        lo, hi = pad + 1, pad + 200_000
        while lo < hi:
            mid = (lo + hi) // 2
            if block_storage_json_bytes(_block_with_padding(mid)) <= MAX_BLOCK_BYTES:
                lo = mid + 1
            else:
                hi = mid
        over = _block_with_padding(lo)
        self.assertGreater(block_storage_json_bytes(over), MAX_BLOCK_BYTES)
        engine = TauConsensusEngine()
        view = MagicMock()
        parent = _parent_snapshot()
        with self.assertRaises(BlockByteCapExceeded):
            engine.apply_block(view, over, parent)


class TestGetBlocksReplyAtCap(unittest.TestCase):
    def test_single_block_reply_under_sync_cap(self):
        pad = _find_padding_for_target(MAX_BLOCK_BYTES)
        blk = _block_with_padding(pad)
        self.assertEqual(block_storage_json_bytes(blk), MAX_BLOCK_BYTES)
        reply = {"blocks": [blk.to_dict()]}
        n = len(json.dumps(reply).encode("utf-8"))
        self.assertLess(n, SYNC_BLOCKS_REPLY_CAP)


class TestCreateblockByteCap(unittest.TestCase):
    def setUp(self):
        self._tmpdir = tempfile.mkdtemp()
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(os.path.join(self._tmpdir, "cap.sqlite"))
        db.init_db()
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()

    def tearDown(self):
        config.set_database_path(self.original_db_path)
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_producer_trims_oversized_mempool(self):
        from commands.createblock import _fit_transactions_to_byte_cap

        txs, ex, ids = [], [], []
        for i in range(2500):
            tx = {
                "tx_type": "user_tx",
                "sender_pubkey": PROPOSER,
                "sequence_number": i,
                "padding": "y" * 8000,
            }
            txs.append(tx)
            ex.append(dict(tx, tx_id=f"h{i}"))
            ids.append(i + 1)
        kept_tx, kept_ex, kept_ids = _fit_transactions_to_byte_cap(
            txs, ex, ids,
            block_number=1,
            previous_hash=PREV,
            proposer_pubkey=PROPOSER,
            timestamp=BASE_TS,
        )
        self.assertLess(len(kept_tx), len(txs))
        kept_block = Block.create(
            1, PREV, kept_tx, PROPOSER, timestamp=BASE_TS, consensus_proof=PROOF,
            state_locator=f"{config.STATE_LOCATOR_NAMESPACE}:{block_mod.EMPTY_STATE_HASH}",
        )
        self.assertLessEqual(block_storage_json_bytes(kept_block), MAX_BLOCK_BYTES)


def _accept_every_tx(self, view, blk, *args, **kwargs):
    from consensus.engine import ApplyBlockResult

    return ApplyBlockResult(
        next_snapshot=TauStateSnapshot(
            state_hash="a" * 64,
            tau_bytes=b"",
            metadata={
                "source": "test",
                "balances": dict(chain_state._balances),
                "sequence_numbers": dict(chain_state._sequence_numbers),
                "lifecycle_manager": chain_state._lifecycle_manager,
                "consensus_rules_state": chain_state._consensus_rules_state,
                "active_consensus_id": chain_state._active_consensus_id,
            },
        ),
        outcomes=[],
        accepted_tx_ids=[tx["tx_id"] for tx in blk.transactions],
        skipped_tx_ids=[],
        invalid_tx_ids=[],
        governance_changes={},
        mempool_hints={},
    )


def test_createblock_returns_cap_dropped_rows_to_pending(node_state, monkeypatch):
    from commands import createblock
    from test_block_production_serialization import _mining_allowed

    payloads = {}
    for i in range(12):
        tx = {
            "tx_type": "user_tx",
            "sender_pubkey": f"{i:096x}",
            "sequence_number": 0,
            "padding": "z" * (2 * 1024 * 1024),
        }
        tx_hash = block_mod.compute_tx_hash(tx)
        payloads[tx_hash] = tx
        db.add_mempool_tx(json.dumps(tx), tx_hash, i)

    built = []
    monkeypatch.setattr(chain_state, "process_new_block", lambda blk: built.append(blk) or True)
    monkeypatch.setattr(TauConsensusEngine, "apply_block", _accept_every_tx)
    with _mining_allowed():
        createblock.create_block_from_mempool()

    assert len(built) == 1
    assert block_storage_json_bytes(built[0]) <= MAX_BLOCK_BYTES
    # Nine 2 MiB transactions with their JSON overhead are over 18 MiB.
    assert len(built[0].tx_ids) == 8
    dropped = [h for h in payloads if h not in set(built[0].tx_ids)]
    assert len(dropped) == 4
    for tx_hash in dropped:
        assert db.get_mempool_entry(tx_hash)["status"] == "pending"


def _over_cap_child_of_genesis() -> Block:
    return _block_with_padding(MAX_BLOCK_BYTES, previous_hash=db.get_genesis_hash())


def test_process_new_block_refuses_over_cap_block(node_state):
    blk = _over_cap_child_of_genesis()
    with patch.object(chain_state.logger, "error") as log_error:
        assert chain_state.process_new_block(blk) is False
    assert db.get_block_by_hash(blk.block_hash) is None
    assert any("consensus cap" in str(call.args) for call in log_error.call_args_list)


def test_ingest_block_does_not_store_over_cap_block(node_state):
    blk = _over_cap_child_of_genesis()
    assert chain_state.ingest_block(blk).status == "invalid"
    assert db.get_block_by_hash(blk.block_hash) is None


def test_rebuild_stops_on_over_cap_block(node_state):
    blk = _block_with_padding(MAX_BLOCK_BYTES)
    with patch("db.get_canonical_blocks_at_or_after_height", return_value=[blk.to_dict()]):
        result = chain_state.rebuild_state_from_blockchain(start_block=1)
    assert not result.ok
    assert "consensus cap" in result.reason


def _cap_child_of_genesis(extra_bytes: int) -> Block:
    pad = _find_padding_for_target(MAX_BLOCK_BYTES) + extra_bytes
    return _block_with_padding(pad, previous_hash=db.get_genesis_hash())


@pytest.mark.parametrize("extra_bytes,status", [(0, "added"), (1, "invalid")])
def test_ingest_block_at_cap(node_state, extra_bytes, status):
    from test_block_production_serialization import _mining_allowed

    blk = _cap_child_of_genesis(extra_bytes)
    assert block_storage_json_bytes(blk) == MAX_BLOCK_BYTES + extra_bytes
    with _mining_allowed():
        assert chain_state.ingest_block(blk).status == status
    assert (db.get_block_by_hash(blk.block_hash) is not None) == (status == "added")


def _signed_cap_tx(target_bytes: int) -> dict:
    """A signed transfer whose unsigned `padding` makes the next produced block `target_bytes`."""
    from test_block_production_serialization import _seed_senders, _sign_tx
    from py_ecc.bls import G2Basic as bls

    (sk, pk), = _seed_senders(1, "cap_apply")
    recipient = bls.SkToPk(bls.KeyGen(b"cap_apply_recipient")).hex()
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": pk,
        "sequence_number": 0,
        "expiration_time": int(time.time()) + 3600,
        "expire_at_height": 5000,
        "operations": {"1": [[pk, recipient, "10"]]},
        "fee_limit": "100",
    }
    tx = json.loads(_sign_tx(tx, sk))
    state = "f" * 64

    def size(pad_len: int) -> int:
        return block_storage_json_bytes(Block.create(
            1, db.get_genesis_hash(), [dict(tx, padding="p" * pad_len)], config.MINER_PUBKEY,
            timestamp=int(time.time()), state_hash=state,
            state_locator=f"{config.STATE_LOCATOR_NAMESPACE}:{state}",
            consensus_proof="f" * 192,
        ))

    tx["padding"] = "p" * (target_bytes - size(0))
    assert size(len(tx["padding"])) == target_bytes
    return tx


def test_block_at_cap_is_produced_and_applied(node_state, monkeypatch):
    from commands import createblock
    from test_block_production_serialization import _mining_allowed

    tx = _signed_cap_tx(MAX_BLOCK_BYTES)
    tx_hash = block_mod.compute_tx_hash(tx)
    db.add_mempool_tx(json.dumps(tx), tx_hash, 1)

    real_apply = TauConsensusEngine.apply_block
    applied = []

    def counting_apply(self, view, blk, *args, **kwargs):
        applied.append(blk.header.block_number)
        return real_apply(self, view, blk, *args, **kwargs)

    monkeypatch.setattr(TauConsensusEngine, "apply_block", counting_apply)
    with _mining_allowed():
        result = createblock.create_block_from_mempool()

    head = db.get_canonical_head_block()
    assert head["tx_ids"] == [tx_hash], result
    assert block_storage_json_bytes(head) == MAX_BLOCK_BYTES
    # process_new_block applies the block again unless it reuses the producer evaluation.
    assert applied and set(applied) == {1}


def test_process_new_block_refuses_block_one_byte_over_cap(node_state):
    blk = _cap_child_of_genesis(1)
    assert block_storage_json_bytes(blk) == MAX_BLOCK_BYTES + 1
    with patch.object(chain_state.logger, "error") as log_error:
        assert chain_state.process_new_block(blk) is False
    assert db.get_block_by_hash(blk.block_hash) is None
    assert any("consensus cap" in str(call.args) for call in log_error.call_args_list)


def test_apply_refuses_block_one_byte_over_cap():
    blk = _block_with_padding(_find_padding_for_target(MAX_BLOCK_BYTES) + 1)
    assert block_storage_json_bytes(blk) == MAX_BLOCK_BYTES + 1
    with pytest.raises(BlockByteCapExceeded):
        TauConsensusEngine().apply_block(MagicMock(), blk, _parent_snapshot())
