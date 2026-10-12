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


def _exec(sql, *args):
    with db._db_lock:
        db._db_conn.execute(sql, args)
        db._db_conn.commit()


def _damage_validator_row(damage):
    assert json.loads(db.get_chain_state_value("active_validators", ""))
    if damage == "deleted":
        _exec("DELETE FROM chain_state WHERE key = 'active_validators'")
    else:
        _exec("UPDATE chain_state SET value = ? WHERE key = 'active_validators'", "{not json")


def _genesis_validators():
    with open(GENESIS, encoding="utf-8") as f:
        return json.load(f)["consensus_meta"]["active_validators"]


@pytest.mark.parametrize("damage", ["deleted", "malformed"])
def test_a_damaged_validator_row_on_a_committed_chain_refuses_under_authority(
        node_state, monkeypatch, damage):
    _damage_validator_row(damage)
    monkeypatch.setattr(db, "latest_block_commit", lambda: {"tip": "ab" * 32})
    before = _rows()
    with patch.object(chain_state, "commit_state_to_db") as commit:
        with pytest.raises(ValueError, match="FATAL: "):
            chain_state.load_genesis(GENESIS, authority=True)
    assert not commit.called
    assert _rows() == before


@pytest.mark.parametrize("damage", ["deleted", "malformed"])
def test_a_damaged_validator_row_without_a_commit_record_is_left_to_the_authority(
        node_state, damage):
    _damage_validator_row(damage)
    assert db.latest_block_commit() is None
    before = _rows()
    with patch.object(chain_state, "commit_state_to_db") as commit:
        chain_state.load_genesis(GENESIS, authority=True)
    assert not commit.called
    assert _rows() == before
    assert not chain_state._lifecycle_manager.active_validators


def test_a_genesis_without_validators_has_nothing_to_restore_under_authority(
        node_state, monkeypatch, tmp_path):
    with open(GENESIS, encoding="utf-8") as f:
        genesis = json.load(f)
    genesis["consensus_meta"]["active_validators"] = []
    path = tmp_path / "genesis.json"
    path.write_text(json.dumps(genesis), encoding="utf-8")
    for name in ("_genesis_accounts_state", "_genesis_active_validators",
                 "_genesis_vote_quorum", "_genesis_eligibility_mode",
                 "_genesis_fee_beneficiary", "_genesis_application_rules",
                 "_genesis_consensus_rules"):
        monkeypatch.setattr(chain_state, name, getattr(chain_state, name))
    _damage_validator_row("deleted")
    monkeypatch.setattr(db, "latest_block_commit", lambda: {"tip": "ab" * 32})
    before = _rows()
    chain_state.load_genesis(str(path), authority=True)
    assert _rows() == before


@pytest.mark.parametrize("damage", ["deleted", "malformed"])
def test_a_validator_backfill_without_authority_keeps_the_persisted_policy_rows(
        node_state, damage):
    persisted = {
        "quorum_policy": "majority",
        "eligibility_mode": "tau_validator_set",
        "fee_beneficiary": "ab" * 48,
    }
    for key, value in persisted.items():
        db.set_chain_state_value(key, value)
    _damage_validator_row(damage)
    chain_state.load_genesis(GENESIS)
    validators = _genesis_validators()
    assert json.loads(db.get_chain_state_value("active_validators", "")) == sorted(validators)
    assert chain_state._lifecycle_manager.active_validators == set(validators)
    for key, value in persisted.items():
        assert db.get_chain_state_value(key, None) == value
        assert getattr(chain_state._lifecycle_manager, key) == value
