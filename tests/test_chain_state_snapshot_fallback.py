from __future__ import annotations

from types import SimpleNamespace

import chain_state
from poa.state import compute_consensus_state_hash


def test_process_new_block_falls_back_to_replay_when_dht_snapshot_missing(monkeypatch):
    old_balances = dict(chain_state._balances)
    old_sequences = dict(chain_state._sequence_numbers)
    old_rules = chain_state._current_rules_state
    old_last_hash = chain_state._canonical_head_hash
    old_tau_hash = chain_state._tau_engine_state_hash

    try:
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._current_rules_state = ""
        chain_state._canonical_head_hash = ""
        chain_state._tau_engine_state_hash = ""

        target_balances = {"addr1": 7}
        target_sequences = {"addr1": 1}
        target_rules = "always (o1[t]:bv[16] = i1[t]:bv[16])."

        accounts_hash = chain_state.compute_accounts_hash(target_balances, target_sequences)
        expected_state_hash = compute_consensus_state_hash(target_rules.encode("utf-8"), accounts_hash)

        from block import Block
        import config
        block = Block.create(
            block_number=1,
            previous_hash=config.GENESIS_HASH,
            transactions=[{"tx_id": "tx-1", "operations": {}}],
            state_hash=expected_state_hash,
            timestamp=1700000000
        )
        block.tx_ids = ["tx-1"]

        block_dict = block.to_dict()

        block_added = False
        def mock_add_block(_block):
            nonlocal block_added
            block_added = True

        monkeypatch.setattr(chain_state.db, "get_block_by_hash", lambda h: block_dict if h == block.block_hash and block_added else None)
        monkeypatch.setattr(chain_state.db, "get_candidate_heads", lambda: [(block.block_hash, block.header.block_number)] if block_added else [])
        monkeypatch.setattr(chain_state.db, "get_chain_path", lambda *args: [block.block_hash])
        monkeypatch.setattr(chain_state.db, "get_canonical_blocks_at_or_after_height", lambda *args: [block_dict] if block_added else [])
        monkeypatch.setattr(chain_state.db, "add_block", mock_add_block)
        monkeypatch.setattr(chain_state.db, "save_canonical_state_atomically", lambda *args, **kwargs: None)
        monkeypatch.setattr(chain_state.db, "remove_mempool_by_hashes", lambda _tx_hashes: 0)

        monkeypatch.setattr(chain_state, "fetch_accounts_snapshot", lambda _block_hash: None)
        monkeypatch.setattr(chain_state, "fetch_tau_state_snapshot", lambda _state_hash: None)
        monkeypatch.setattr(chain_state, "publish_accounts_snapshot", lambda _block_hash: True)
        monkeypatch.setattr(
            chain_state,
            "publish_tau_state_snapshot",
            lambda _state_hash, _tau_bytes, _accounts_hash: True,
        )
        monkeypatch.setattr(
            chain_state,
            "save_rules_state",
            lambda rules: setattr(chain_state, "_current_rules_state", rules),
        )

        # Mock tau_manager
        monkeypatch.setattr(chain_state.tau_manager.tau_ready, "is_set", lambda: True)
        monkeypatch.setattr(chain_state.tau_manager, "communicate_with_tau", lambda *args, **kwargs: None)

        class _FakeEngine:
            def verify_block(self, _block):
                return True

            def apply(self, _snapshot, transactions, block_timestamp=None, target_balances=None, target_sequences=None):
                if target_balances is None:
                    with chain_state._balance_lock, chain_state._sequence_lock:
                        chain_state._balances.clear()
                        chain_state._balances.update({"addr1": 7})
                        chain_state._sequence_numbers.clear()
                        chain_state._sequence_numbers.update({"addr1": 1})
                else:
                    target_balances.clear()
                    target_balances.update({"addr1": 7})
                    target_sequences.clear()
                    target_sequences.update({"addr1": 1})

                return SimpleNamespace(
                    snapshot=SimpleNamespace(tau_bytes=target_rules.encode("utf-8")),
                    accepted_transactions=list(transactions),
                    rejected_transactions=[],
                )

        monkeypatch.setattr(chain_state, "PoATauEngine", lambda: _FakeEngine())

        # Avoid the real 8-second DHT wait loop by advancing time immediately.
        time_state = {"tick": 0.0}

        def _fake_time() -> float:
            time_state["tick"] += 10.0
            return time_state["tick"]

        monkeypatch.setattr("time.time", _fake_time)
        monkeypatch.setattr("time.sleep", lambda _seconds: None)

        assert chain_state.process_new_block(block) is True
        assert chain_state._canonical_head_hash == block.block_hash
        assert chain_state._current_rules_state == target_rules
        assert chain_state._balances == target_balances
        assert chain_state._sequence_numbers == target_sequences
    finally:
        chain_state._balances.clear()
        chain_state._balances.update(old_balances)
        chain_state._sequence_numbers.clear()
        chain_state._sequence_numbers.update(old_sequences)
        chain_state._current_rules_state = old_rules
        chain_state._canonical_head_hash = old_last_hash
        chain_state._tau_engine_state_hash = old_tau_hash
