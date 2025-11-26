import json

import pytest

import config
import db
from miner import SoleMiner
from poa import mempool as mempool_utils
from poa.state import StateStore
from poa.tau_engine import MockTauEngine


def test_mempool_reconcile_with_block(temp_database):
    tx_payload = {"sender_pubkey": config.MINER_PUBKEY, "sequence_number": 0}
    db.add_mempool_tx(json.dumps(tx_payload))
    stats = mempool_utils.reconcile_with_block({"transactions": [tx_payload]})
    assert stats["removed"] == 1
    assert stats["kept"] == 0


def test_sole_miner_mines_block_when_threshold_met(temp_database):
    # Seed mempool with a placeholder transaction
    sample_tx = {
        "sender_pubkey": config.MINER_PUBKEY,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "operations": {"1": []},
        "fee_limit": "0",
        "signature": "00",
    }
    db.add_mempool_tx(json.dumps(sample_tx))

    mined_blocks = []

    def _capture_block(new_block):
        mined_blocks.append(new_block.to_dict())

    miner = SoleMiner(
        threshold=1,
        max_block_interval=1.0,
        state_store=StateStore(),
        tau_engine=MockTauEngine(),
        block_committer=_capture_block,
    )

    block_obj = miner.try_mine()
    assert block_obj is not None
    assert block_obj.header.state_hash
    assert len(mined_blocks) == 1
    assert db.get_mempool_txs() == []

