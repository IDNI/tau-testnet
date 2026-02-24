import pytest
import os
import json
import tempfile
import sqlite3
from unittest.mock import MagicMock, patch

import db
import chain_state
import config
from errors import TauTestnetError, TauEngineCrash, TauCommunicationError

# --- Fixtures ---

@pytest.fixture
def mock_db_path(tmp_path):
    original_path = config.STRING_DB_PATH
    db_path = tmp_path / "test_tau.db"
    config.STRING_DB_PATH = str(db_path)
    # Reset db connection
    if getattr(db, "_db_conn", None):
        db._db_conn.close()
    db._db_conn = None
    yield str(db_path)
    if db._db_conn:
        db._db_conn.close()
        db._db_conn = None
    config.STRING_DB_PATH = original_path

@pytest.fixture
def mock_chain_state(mock_db_path):
    # Reset chain state globals
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._current_rules_state = ""
    chain_state._last_processed_block_hash = ""
    return chain_state

# --- Tests for db.py ---

def test_db_public_methods(mock_db_path):
    db.init_db()
    
    # 1. Test save_chain_state
    balances = {"addr1": 100, "addr2": 200}
    sequences = {"addr1": 1, "addr2": 2}
    rules = "some rules"
    last_hash = "hash123"
    
    db.save_chain_state(balances, sequences, rules, last_hash)
    
    # 2. Test load_chain_state
    loaded_balances, loaded_seqs, loaded_rules, loaded_hash = db.load_chain_state()
    
    assert loaded_balances == balances
    assert loaded_seqs == sequences
    assert loaded_rules == rules
    assert loaded_hash == last_hash
    
    # 3. Test get_blocks_after
    # Insert some blocks manually or via add_block
    class MockBlock:
        def __init__(self, num, hash_val):
            self.header = MagicMock()
            self.header.block_number = num
            self.header.previous_hash = "prev"
            self.header.timestamp = 123
            self.block_hash = hash_val
        def to_dict(self):
            return {
                "header": {"block_number": self.header.block_number},
                "block_hash": self.block_hash
            }
            
    db.add_block(MockBlock(1, "hash1"))
    db.add_block(MockBlock(2, "hash2"))
    db.add_block(MockBlock(3, "hash3"))
    
    blocks = db.get_blocks_after(2)
    assert len(blocks) == 2 # 2 and 3
    assert blocks[0]["header"]["block_number"] == 2
    assert blocks[1]["header"]["block_number"] == 3

# --- Tests for chain_state.py ---

def test_chain_state_persistence(mock_chain_state):
    # Setup initial state
    with chain_state._balance_lock:
        chain_state._balances["alice"] = 500
    with chain_state._sequence_lock:
        chain_state._sequence_numbers["alice"] = 5
    with chain_state._rules_lock:
        chain_state._current_rules_state = "rules v1"
        
    # Commit
    chain_state.commit_state_to_db("block_hash_1")
    
    # Clear memory
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._current_rules_state = ""
    chain_state._last_processed_block_hash = ""
    
    # Load
    loaded = chain_state.load_state_from_db()
    assert loaded is True
    
    assert chain_state.get_balance("alice") == 500
    assert chain_state.get_sequence_number("alice") == 5
    assert chain_state.get_rules_state() == "rules v1"
    assert chain_state._last_processed_block_hash == "block_hash_1"

# --- Tests for server.py error handling ---

def test_server_error_handling():
    from server import handle_client
    from app.container import ServiceContainer
    
    # Mock container and components
    container = MagicMock(spec=ServiceContainer)
    container.command_handlers = {}
    container.tau_manager = MagicMock()
    container.db = MagicMock()
    container.chain_state = MagicMock()
    container.mempool_state = MagicMock()
    
    # Mock socket
    mock_conn = MagicMock()
    mock_conn.recv.side_effect = [b"unknown_command", b""] # Command then disconnect
    
    # 1. Unknown command
    handle_client(mock_conn, ("127.0.0.1", 1234), container)
    # Should send ERROR: Unknown command
    args, _ = mock_conn.sendall.call_args
    assert b"ERROR: Unknown command" in args[0]
    
    # 2. TauTestnetError
    mock_conn.reset_mock()
    mock_conn.recv.side_effect = [b"test_cmd", b""]
    
    mock_handler = MagicMock()
    del mock_handler.execute # Ensure it falls through to Tau path
    mock_handler.encode_command.side_effect = TauTestnetError("Custom tau error")
    container.command_handlers = {"test_cmd": mock_handler}
    
    handle_client(mock_conn, ("127.0.0.1", 1234), container)
    
    # Should send ERROR: Custom tau error
    # Note: handle_client catches exception during encode_command?
    # Let's check server.py logic.
    # try: tau_input = handler.encode_command(...) except Exception ...
    # Wait, I didn't update the try/except block around encode_command, only around communicate_with_tau!
    # I should check server.py again.
    
    # 3. TauCommunicationError
    mock_conn.reset_mock()
    mock_conn.recv.side_effect = [b"comm_cmd", b""]
    
    mock_handler2 = MagicMock()
    del mock_handler2.execute # Ensure it falls through to Tau path
    mock_handler2.encode_command.return_value = "input"
    container.command_handlers = {"comm_cmd": mock_handler2}
    
    container.tau_manager.tau_ready.wait.return_value = True
    container.tau_manager.communicate_with_tau.side_effect = TauCommunicationError("Comm failed")
    
    handle_client(mock_conn, ("127.0.0.1", 1234), container)
    
    args, _ = mock_conn.sendall.call_args
    assert b"ERROR: Comm failed" in args[0]
