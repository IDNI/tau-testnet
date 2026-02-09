from __future__ import annotations

from types import SimpleNamespace

import chain_state
from poa.state import compute_consensus_state_hash


def test_process_new_block_falls_back_to_replay_when_dht_snapshot_missing(monkeypatch):
    old_balances = dict(chain_state._balances)
    old_sequences = dict(chain_state._sequence_numbers)
    old_rules = chain_state._current_rules_state
    old_last_hash = chain_state._last_processed_block_hash
    old_tau_hash = chain_state._tau_engine_state_hash

    try:
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._current_rules_state = ""
        chain_state._last_processed_block_hash = ""
        chain_state._tau_engine_state_hash = ""

        target_balances = {"addr1": 7}
        target_sequences = {"addr1": 1}
        target_rules = "always (o1[t]:bv[16] = i1[t]:bv[16])."

        accounts_hash = chain_state.compute_accounts_hash(target_balances, target_sequences)
        expected_state_hash = compute_consensus_state_hash(target_rules.encode("utf-8"), accounts_hash)

        block = SimpleNamespace(
            block_hash="b" * 64,
            header=SimpleNamespace(block_number=1, state_hash=expected_state_hash),
            transactions=[{"tx_id": "tx-1", "operations": {}}],
            tx_ids=["tx-1"],
        )

        monkeypatch.setattr(chain_state.db, "get_block_by_hash", lambda _block_hash: None)
        monkeypatch.setattr(chain_state.db, "add_block", lambda _block: None)
        monkeypatch.setattr(chain_state.db, "save_chain_state", lambda **_kwargs: None)
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

        class _FakeEngine:
            def verify_block(self, _block):
                return True

            def apply(self, _snapshot, transactions):
                with chain_state._balance_lock, chain_state._sequence_lock:
                    chain_state._balances.clear()
                    chain_state._balances.update(target_balances)
                    chain_state._sequence_numbers.clear()
                    chain_state._sequence_numbers.update(target_sequences)
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
        assert chain_state._last_processed_block_hash == block.block_hash
        assert chain_state._current_rules_state == target_rules
        assert chain_state._balances == target_balances
        assert chain_state._sequence_numbers == target_sequences
    finally:
        chain_state._balances.clear()
        chain_state._balances.update(old_balances)
        chain_state._sequence_numbers.clear()
        chain_state._sequence_numbers.update(old_sequences)
        chain_state._current_rules_state = old_rules
        chain_state._last_processed_block_hash = old_last_hash
        chain_state._tau_engine_state_hash = old_tau_hash
