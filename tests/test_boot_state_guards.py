"""Boot-time guards in chain_state that need no native engine."""
import json
from unittest.mock import patch

import pytest

import chain_state
import db

GENESIS = "data/genesis.json"


def _rows():
    with db._db_lock:
        return json.dumps({
            "blocks": [list(r) for r in db._db_conn.execute(
                "SELECT block_hash, block_number FROM blocks ORDER BY 1").fetchall()],
            "state": [list(r) for r in db._db_conn.execute(
                "SELECT key, value FROM chain_state ORDER BY 1").fetchall()],
            "accounts": [list(r) for r in db._db_conn.execute(
                "SELECT * FROM accounts ORDER BY 1").fetchall()],
        }, sort_keys=True, default=str)


@pytest.mark.parametrize("keep_accounts", [True, False])
def test_a_missing_head_key_does_not_reprovision_genesis(node_state, keep_accounts):
    with db._db_lock:
        db._db_conn.execute("DELETE FROM chain_state WHERE key = 'canonical_head_hash'")
        if not keep_accounts:
            db._db_conn.execute("DELETE FROM accounts")
        db._db_conn.commit()
    before = _rows()
    with pytest.raises(ValueError, match="FATAL: Canonical head is missing or unreadable"):
        chain_state.load_genesis(GENESIS)
    assert _rows() == before


def test_an_empty_database_still_provisions_genesis(node_state):
    with db._db_lock:
        for table in ("blocks", "chain_state", "accounts"):
            db._db_conn.execute(f"DELETE FROM {table}")
        db._db_conn.commit()
    chain_state.load_genesis(GENESIS)
    assert db.get_canonical_head_block()["header"]["block_number"] == 0


def _stale_head(monkeypatch):
    monkeypatch.setattr(chain_state, "load_genesis", lambda *a, **k: None)
    monkeypatch.setattr(chain_state, "_canonical_head_hash", "ab" * 32)


def test_a_mismatch_still_rebuilds_without_authority(node_state, monkeypatch):
    genesis = db.get_canonical_head_block()["block_hash"]
    _stale_head(monkeypatch)
    with patch.object(chain_state, "_rebuild_state_from_blockchain_internal",
                      wraps=chain_state._rebuild_state_from_blockchain_internal) as rebuild:
        chain_state.initialize_persistent_state(GENESIS)
    assert rebuild.called
    assert db.get_chain_state_value("canonical_head_hash", "") == genesis


def test_a_mismatch_fails_closed_under_authority(node_state, monkeypatch):
    _stale_head(monkeypatch)
    before = _rows()
    with patch.object(chain_state, "_rebuild_state_from_blockchain_internal") as rebuild, \
         patch.object(chain_state, "commit_state_to_db") as commit:
        with pytest.raises(ValueError, match="FATAL: Canonical head .* disagrees"):
            chain_state.initialize_persistent_state(GENESIS, authority=True)
    assert not rebuild.called and not commit.called
    assert _rows() == before
