"""Tests for launch-hardening work: schema versioning, production flag guard,
mempool cap/prune, and admission size limits."""

import json
import os
import sqlite3
import time
from unittest.mock import patch

import pytest

import config
import db
from errors import DatabaseError


@pytest.fixture
def temp_db(tmp_path):
    """Point db at a temp file and re-init; restore the previous connection after."""
    prev_path = config.STRING_DB_PATH
    prev_conn = db._db_conn
    config.STRING_DB_PATH = str(tmp_path / "hardening.sqlite")
    db._db_conn = None
    db.init_db()
    yield
    if db._db_conn is not None:
        db._db_conn.close()
    config.STRING_DB_PATH = prev_path
    db._db_conn = prev_conn


class TestSchemaVersion:
    def test_fresh_db_stamped_with_schema_version(self, temp_db):
        row = db._db_conn.execute("SELECT version FROM schema_version").fetchone()
        assert row[0] == db.SCHEMA_VERSION

    def test_version_mismatch_refuses_to_start(self, tmp_path):
        prev_path = config.STRING_DB_PATH
        prev_conn = db._db_conn
        config.STRING_DB_PATH = str(tmp_path / "future.sqlite")
        db._db_conn = None
        try:
            db.init_db()
            db._db_conn.execute("UPDATE schema_version SET version = ?", (db.SCHEMA_VERSION + 1,))
            db._db_conn.commit()
            db._db_conn.close()
            db._db_conn = None
            with pytest.raises(DatabaseError, match="schema_version"):
                db.init_db()
        finally:
            if db._db_conn is not None:
                db._db_conn.close()
            config.STRING_DB_PATH = prev_path
            db._db_conn = prev_conn

    def test_legacy_blocks_schema_refuses_instead_of_dropping(self, tmp_path):
        prev_path = config.STRING_DB_PATH
        prev_conn = db._db_conn
        legacy = str(tmp_path / "legacy.sqlite")
        conn = sqlite3.connect(legacy)
        # Pre-fork-choice schema: no block_hash primary key.
        conn.execute("CREATE TABLE blocks (block_number INTEGER PRIMARY KEY, block_data TEXT)")
        conn.execute("INSERT INTO blocks VALUES (0, 'precious')")
        conn.commit()
        conn.close()
        config.STRING_DB_PATH = legacy
        db._db_conn = None
        try:
            with pytest.raises(DatabaseError, match="predates schema_version"):
                db.init_db()
            # Data must survive the refusal.
            conn = sqlite3.connect(legacy)
            assert conn.execute("SELECT block_data FROM blocks").fetchone()[0] == "precious"
            conn.close()
        finally:
            if db._db_conn is not None:
                db._db_conn.close()
            config.STRING_DB_PATH = prev_path
            db._db_conn = prev_conn

    def test_wal_mode_enabled(self, temp_db):
        mode = db._db_conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"


class TestProductionFlagGuard:
    def test_force_test_refused_in_production(self):
        import server
        from errors import ConfigurationError

        container = type("C", (), {})()
        container.settings = type("S", (), {"env": "production"})()
        with patch.dict(os.environ, {"TAU_FORCE_TEST": "1"}):
            with pytest.raises(ConfigurationError, match="TAU_FORCE_TEST"):
                server._run_server(container)

    def test_force_test_allowed_outside_production(self):
        import server

        container = type("C", (), {})()
        container.settings = type("S", (), {"env": "test"})()
        # Guard passes; the next access (container.tau_manager) raises AttributeError,
        # proving we got past the flag check.
        with patch.dict(os.environ, {"TAU_FORCE_TEST": "1"}):
            with pytest.raises(AttributeError):
                server._run_server(container)


def _mk_payload(expiration_time):
    return json.dumps({"tx_type": "user_tx", "expiration_time": expiration_time})


class TestMempoolBounds:
    def test_expired_pending_pruned_on_insert(self, temp_db):
        past = int(time.time()) - 100
        future = int(time.time()) + 10000
        db.add_mempool_tx(_mk_payload(past), "expired1", 1)
        db.add_mempool_tx(_mk_payload(future), "fresh1", 2)
        # The insert of fresh2 prunes expired1.
        db.add_mempool_tx(_mk_payload(future), "fresh2", 3)
        rows = db._db_conn.execute("SELECT tx_hash FROM mempool").fetchall()
        hashes = {r[0] for r in rows}
        assert "expired1" not in hashes
        assert {"fresh1", "fresh2"} <= hashes

    def test_cap_evicts_oldest_pending_only(self, temp_db, monkeypatch):
        monkeypatch.setattr(db, "MEMPOOL_MAX_TXS", 3)
        future = int(time.time()) + 10000
        db.add_mempool_tx(_mk_payload(future), "old", 1)
        db.add_mempool_tx(_mk_payload(future), "mid", 2)
        # Reserve 'old' — reserved rows must never be evicted.
        db._db_conn.execute("UPDATE mempool SET status='reserved', reserved_at=999 WHERE tx_hash='old'")
        db._db_conn.commit()
        db.add_mempool_tx(_mk_payload(future), "new1", 3)
        db.add_mempool_tx(_mk_payload(future), "new2", 4)  # over cap → evict oldest pending ('mid')
        hashes = {r[0] for r in db._db_conn.execute("SELECT tx_hash FROM mempool").fetchall()}
        assert "old" in hashes  # reserved survived
        assert "mid" not in hashes  # oldest pending evicted
        assert "new2" in hashes


class TestAdmissionLimits:
    def _tip_view(self):
        from consensus.facade import TipAdmissionView
        return TipAdmissionView()

    def test_too_many_transfers_rejected(self):
        from consensus.admission import validate_user_tx_reserved_domains, MAX_TRANSFERS_PER_TX
        tx = {"operations": {"1": [["a", "b", "1"]] * (MAX_TRANSFERS_PER_TX + 1)}}
        result = validate_user_tx_reserved_domains(tx, self._tip_view())
        assert not result.is_valid
        assert "MAX_TRANSFERS_PER_TX" in result.error

    def test_too_many_custom_streams_rejected(self):
        from consensus.admission import validate_user_tx_reserved_domains, MAX_CUSTOM_INPUT_STREAMS
        # digit keys >= 12 avoid the reserved 6-11 band and the 0/1 exclusions
        ops = {str(12 + i): "x" for i in range(MAX_CUSTOM_INPUT_STREAMS + 1)}
        result = validate_user_tx_reserved_domains({"operations": ops}, self._tip_view())
        assert not result.is_valid
        assert "MAX_CUSTOM_INPUT_STREAMS" in result.error

    def test_transfers_at_limit_accepted(self):
        from consensus.admission import validate_user_tx_reserved_domains, MAX_TRANSFERS_PER_TX
        tx = {"operations": {"1": [["a", "b", "1"]] * MAX_TRANSFERS_PER_TX}}
        assert validate_user_tx_reserved_domains(tx, self._tip_view()).is_valid

    def test_too_many_rule_revisions_rejected(self):
        from consensus.admission import validate_consensus_rule_update_payload, MAX_RULE_REVISIONS
        tx = {
            "sender_pubkey": "ab" * 48,
            "rule_revisions": ["r"] * (MAX_RULE_REVISIONS + 1),
            "activate_at_height": 10,
        }
        with patch("consensus.admission._open_governance_admission", return_value=True):
            result = validate_consensus_rule_update_payload(tx, self._tip_view())
        assert not result.is_valid

    def test_rule_revisions_total_bytes_rejected(self):
        from consensus.admission import validate_consensus_rule_update_payload, MAX_RULE_REVISIONS_BYTES
        big = "x" * (MAX_RULE_REVISIONS_BYTES + 1)
        tx = {"sender_pubkey": "ab" * 48, "rule_revisions": [big], "activate_at_height": 10}
        with patch("consensus.admission._open_governance_admission", return_value=True):
            result = validate_consensus_rule_update_payload(tx, self._tip_view())
        assert not result.is_valid
        assert "MAX_RULE_REVISIONS_BYTES" in result.error
