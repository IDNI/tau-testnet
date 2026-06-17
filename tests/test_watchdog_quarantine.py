import os
import sys
import shutil
import tempfile
import json
import time
from unittest.mock import patch
import pytest

import watchdog


def test_quarantine_creates_dir():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_node.db")
        # Create a dummy db file
        with open(db_path, "w") as f:
            f.write("dummy db content")
            
        quarantine_dir = watchdog.quarantine_database(db_path)
        assert quarantine_dir != ""
        assert os.path.exists(quarantine_dir)
        # Check that the base folder name matches the pattern
        basename = os.path.basename(quarantine_dir)
        assert basename.startswith("quarantine_")
        # Check that the file was moved
        assert not os.path.exists(db_path)
        moved_db = os.path.join(quarantine_dir, "test_node.db")
        assert os.path.exists(moved_db)
        with open(moved_db, "r") as f:
            assert f.read() == "dummy db content"


def test_quarantine_moves_files():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_node.db")
        sidecars = ["", "-wal", "-shm", "-journal"]
        for ext in sidecars:
            with open(db_path + ext, "w") as f:
                f.write(f"dummy {ext}")
                
        quarantine_dir = watchdog.quarantine_database(db_path)
        assert quarantine_dir != ""
        assert os.path.exists(quarantine_dir)
        
        for ext in sidecars:
            assert not os.path.exists(db_path + ext)
            moved_file = os.path.join(quarantine_dir, "test_node.db" + ext)
            assert os.path.exists(moved_file)
            with open(moved_file, "r") as f:
                assert f.read() == f"dummy {ext}"


def test_quarantine_skips_missing_sidecars():
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_node.db")
        # Only db exists, no sidecars
        with open(db_path, "w") as f:
            f.write("dummy db")
            
        quarantine_dir = watchdog.quarantine_database(db_path)
        assert quarantine_dir != ""
        assert os.path.exists(quarantine_dir)
        assert not os.path.exists(db_path)
        assert os.path.exists(os.path.join(quarantine_dir, "test_node.db"))
        
        # Check sidecars don't exist in quarantine
        for ext in ["-wal", "-shm", "-journal"]:
            assert not os.path.exists(os.path.join(quarantine_dir, "test_node.db" + ext))


def test_quarantine_logs_loudly(monkeypatch):
    log_messages = []
    monkeypatch.setattr(watchdog, "_log", lambda msg: log_messages.append(msg))
    
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = os.path.join(tmpdir, "test_node.db")
        with open(db_path, "w") as f:
            f.write("dummy db")
            
        quarantine_dir = watchdog.quarantine_database(db_path)
        assert quarantine_dir != ""
        
        # Check logs
        assert any("Quarantined" in msg for msg in log_messages)


def test_watchdog_timeout_quarantines_not_deletes(monkeypatch):
    # Test that when main() triggers a timeout, it quarantines the DB instead of deleting it.
    with tempfile.TemporaryDirectory() as tmpdir:
        status_file = os.path.join(tmpdir, "tau_status.json")
        db_path = os.path.join(tmpdir, "test_node.db")
        
        with open(db_path, "w") as f:
            f.write("dummy db")
            
        # Write status file with expired last_start_time
        status_data = {
            "pid": 12345,
            "db_path": db_path,
            "last_start_time": time.time() - 100.0,
            "watchdog_timeout_name": "comm_timeout",
            "watchdog_timeout_seconds": 1.0,
        }
        with open(status_file, "w") as f:
            json.dump(status_data, f)
            
        # Mock kill_process_tree, sys.exit
        killed_pid = []
        monkeypatch.setattr(watchdog, "kill_process_tree", lambda pid: killed_pid.append(pid))
        
        exit_codes = []
        def mock_exit(code):
            exit_codes.append(code)
            raise SystemExit(code)
            
        monkeypatch.setattr(sys, "exit", mock_exit)
        
        log_messages = []
        monkeypatch.setattr(watchdog, "_log", lambda msg: log_messages.append(msg))
        
        # Mock sys.argv
        monkeypatch.setattr(sys, "argv", ["watchdog.py", status_file, "1.0", "12345"])
        
        # Mock os.kill to avoid checking real pid
        monkeypatch.setattr(os, "kill", lambda pid, sig: None)
        
        # Run one iteration of the main loop. Since it ends with sys.exit, we catch it.
        # We mock time.sleep to not block
        monkeypatch.setattr(time, "sleep", lambda secs: None)
        
        with pytest.raises(SystemExit) as excinfo:
            watchdog.main()
            
        assert excinfo.value.code == 0
        assert 12345 in killed_pid
        assert 0 in exit_codes
        
        # Verify db was moved to watchdog_quarantine, not deleted
        assert not os.path.exists(db_path)
        
        quarantine_base = os.path.join(tmpdir, "watchdog_quarantine")
        assert os.path.exists(quarantine_base)
        contents = os.listdir(quarantine_base)
        assert len(contents) == 1
        q_dir = os.path.join(quarantine_base, contents[0])
        assert os.path.exists(os.path.join(q_dir, "test_node.db"))
        
        # Check critical log
        assert any("CRITICAL: Database quarantined to" in msg for msg in log_messages)
