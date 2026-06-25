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
        # The cap counts pending-only, so reserved rows neither count toward it nor get evicted.
        monkeypatch.setattr(config, "MAX_MEMPOOL_TXS", 2)
        future = int(time.time()) + 10000
        db.add_mempool_tx(_mk_payload(future), "old", 1)
        db.add_mempool_tx(_mk_payload(future), "mid", 2)
        # Reserve 'old' — reserved rows must never be evicted and don't count toward the cap.
        db._db_conn.execute("UPDATE mempool SET status='reserved', reserved_at=999 WHERE tx_hash='old'")
        db._db_conn.commit()
        db.add_mempool_tx(_mk_payload(future), "new1", 3)
        db.add_mempool_tx(_mk_payload(future), "new2", 4)  # pending over cap → evict oldest pending ('mid')
        hashes = {r[0] for r in db._db_conn.execute("SELECT tx_hash FROM mempool").fetchall()}
        assert "old" in hashes  # reserved survived
        assert "mid" not in hashes  # oldest pending evicted
        assert "new2" in hashes

    def test_env_max_mempool_txs_caps_stored_pending(self, temp_db, monkeypatch):
        """A low TAU_MAX_MEMPOOL_TXS must actually cap the stored (pending) mempool at the
        DB layer, not only the soft sendtx pre-check. Drives the env var through
        reload_settings into add_mempool_tx's eviction."""
        prev_settings = config.settings
        prev_limit = config.MAX_MEMPOOL_TXS
        try:
            monkeypatch.setenv("TAU_MAX_MEMPOOL_TXS", "3")
            config.reload_settings()
            assert config.MAX_MEMPOOL_TXS == 3  # env wired through config

            future = int(time.time()) + 10000
            for i in range(10):
                db.add_mempool_tx(_mk_payload(future), f"tx{i}", i + 1)

            # Capped at the configured 3, not the hardcoded MEMPOOL_MAX_TXS fallback (5000).
            assert db.count_mempool_txs() == 3
            stored = db._db_conn.execute(
                "SELECT COUNT(*) FROM mempool WHERE status='pending'"
            ).fetchone()[0]
            assert stored == 3
        finally:
            config.settings = prev_settings
            config.MAX_MEMPOOL_TXS = prev_limit


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

    # --- Apply-time-mocked input streams (i2/i3/i4) screen ---------------------
    # i2 (balance), i3/i4 (from/to) are fed real values at admission but mocked
    # to "0" at block apply. A fee/application rule reading them computes a
    # different fee at admission than at inclusion -> admitted then rejected at
    # block build. Both the user-rule screen and the consensus-revision screen
    # hard-reject such rule text. Fee/policy rules scope on i12 / compare i1.

    def test_user_rule_reading_apply_mocked_streams_rejected(self):
        from consensus.admission import validate_user_tx_reserved_domains
        for stream in ("i2", "i3", "i4"):
            rule = f"always (o8[t]:bv[24] = {stream}[t]:bv[24])."
            result = validate_user_tx_reserved_domains({"operations": {"0": rule}}, self._tip_view())
            assert not result.is_valid, f"stream {stream} not screened"
            assert stream in result.error

    def test_user_flat_fee_and_ladder_rules_pass(self):
        from consensus.admission import validate_user_tx_reserved_domains
        flat = "always (o8[t]:bv[24] = { #x000003 }:bv[24])."
        # Tiered fee on the real amount stream i1 (fed at apply) — the supported
        # alternative to rules keyed on a mocked stream.
        ladder = (
            "always ((i1[t]:bv[24] > { #x0003e8 }:bv[24] && o8[t]:bv[24] = { #x000005 }:bv[24]) "
            "|| (i1[t]:bv[24] <= { #x0003e8 }:bv[24] && o8[t]:bv[24] = { #x000001 }:bv[24]))."
        )
        for rule in (flat, ladder):
            result = validate_user_tx_reserved_domains({"operations": {"0": rule}}, self._tip_view())
            assert result.is_valid, f"benign rule rejected: {rule} -> {result.error}"

    def test_user_rule_mocked_stream_only_in_comment_passes(self):
        # A mocked stream named only in a '#' comment must not trip the screen.
        from consensus.admission import validate_user_tx_reserved_domains
        rule = "always (o8[t]:bv[24] = { #x000003 }:bv[24]). # flat fee, not scaled by i2 balance"
        result = validate_user_tx_reserved_domains({"operations": {"0": rule}}, self._tip_view())
        assert result.is_valid, f"comment false-positive: {result.error}"

    def test_user_rule_custom_stream_not_mistaken_for_mocked(self):
        # Custom input stream i23 must not be screened as i2 (word boundary).
        from consensus.admission import validate_user_tx_reserved_domains
        rule = "always (o8[t]:bv[24] = i23[t]:bv[24])."
        result = validate_user_tx_reserved_domains({"operations": {"0": rule}}, self._tip_view())
        assert result.is_valid, f"i23 mis-screened as i2: {result.error}"

    def test_consensus_revision_reading_mocked_input_rejected(self):
        from consensus.admission import stage_and_validate_consensus_revisions
        for stream in ("i2", "i3", "i4"):
            tx = {"rule_revisions": [f"always (o9[t]:bv[24] = {stream}[t]:bv[24])."]}
            result = stage_and_validate_consensus_revisions(tx, self._tip_view())
            assert not result.is_valid, f"stream {stream} not screened"
            assert stream in result.error

    def test_consensus_revision_flat_fee_passes(self):
        from consensus.admission import stage_and_validate_consensus_revisions
        tx = {"rule_revisions": ["always (o9[t]:bv[24] = { #x00000a }:bv[24])."]}
        # Skip the isolated staging compile (no live Tau in this unit test); the
        # i2/i3/i4 screen runs before it regardless.
        with patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = False
            result = stage_and_validate_consensus_revisions(tx, self._tip_view())
        assert result.is_valid, f"flat consensus fee rejected: {result.error}"
