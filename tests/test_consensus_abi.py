import os
import tempfile
from types import SimpleNamespace
from unittest.mock import patch

import config
import db
from consensus.engine import TauConsensusEngine

ORIGINAL_QUERY_ELIGIBILITY = TauConsensusEngine.query_eligibility
ORIGINAL_VERIFY_BLOCK_HEADER = TauConsensusEngine.verify_block_header


def _reset_db(path: str) -> None:
    config.set_database_path(path)
    if db._db_conn:
        db._db_conn.close()
        db._db_conn = None
    db.init_db()


def test_query_eligibility_uses_consensus_abi_streams():
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    original_path = config.STRING_DB_PATH
    try:
        _reset_db(path)
        engine = TauConsensusEngine()
        pubkey = "a" * 96
        prev_hash = "b" * 64

        with patch("tau_manager.tau_ready.is_set", return_value=True), patch(
            "tau_manager.communicate_with_tau", return_value="1"
        ) as mock_tau:
            assert ORIGINAL_QUERY_ELIGIBILITY(engine, pubkey, 7, 123456, prev_hash) is True

        kwargs = mock_tau.call_args.kwargs
        assert kwargs["target_output_stream_index"] == 7
        streams = kwargs["input_stream_values"]
        assert streams[6] == "7"
        assert streams[7] == "123456"
        assert streams[10] == "1"
        assert streams[8].startswith("y")
        assert streams[9].startswith("y")
        assert streams[11].startswith("y")
        assert db.get_text_by_id(streams[8]) == pubkey
        assert db.get_text_by_id(streams[9]) == prev_hash
        assert db.get_text_by_id(streams[11]) == "{}"
    finally:
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(original_path)
        if os.path.exists(path):
            os.remove(path)


def test_verify_block_header_uses_o6_and_validates_bv_widths():
    fd, path = tempfile.mkstemp(suffix=".sqlite")
    os.close(fd)
    original_path = config.STRING_DB_PATH
    try:
        _reset_db(path)
        engine = TauConsensusEngine()
        block = SimpleNamespace(
            header=SimpleNamespace(
                proposer_pubkey="c" * 96,
                block_number=9,
                timestamp=654321,
                previous_hash="d" * 64,
                canonical_bytes=lambda: b"header",
            ),
            consensus_proof="deadbeef",
        )

        with patch("tau_manager.tau_ready.is_set", return_value=True), patch(
            "tau_manager.communicate_with_tau", return_value="1"
        ) as mock_tau:
            assert ORIGINAL_VERIFY_BLOCK_HEADER(engine, block, {"proof_ok": True}) is True

        kwargs = mock_tau.call_args.kwargs
        assert kwargs["target_output_stream_index"] == 6
        streams = kwargs["input_stream_values"]
        assert streams[6] == "9"
        assert streams[7] == "654321"
        assert streams[10] == "1"
        assert db.get_text_by_id(streams[8]) == "c" * 96
        assert db.get_text_by_id(streams[9]) == "d" * 64
        assert db.get_text_by_id(streams[11]) == "{}"

        try:
            engine._build_consensus_input_streams(
                proposer_pubkey="c" * 96,
                block_number=1 << 64,
                timestamp=1,
                previous_hash="d" * 64,
                proof_ok=True,
                claims={},
            )
            assert False, "Expected width validation failure for block_number"
        except ValueError as exc:
            assert "bv[64]" in str(exc)
    finally:
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(original_path)
        if os.path.exists(path):
            os.remove(path)
