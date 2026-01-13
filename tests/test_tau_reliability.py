
import threading
import time
import pytest
import subprocess
import os
import sys
from unittest.mock import MagicMock, patch, ANY
import tau_manager
import config

# --- Utilities ---

@pytest.fixture
def reset_tau_manager_globals():
    """Resets tau_manager globals to a clean state before each test."""
    tau_manager.tau_process = None
    tau_manager.tau_ready.clear()
    tau_manager.tau_process_ready.clear()
    tau_manager.restart_in_progress.clear()
    tau_manager.server_should_stop.clear()
    tau_manager.tau_test_mode = False
    tau_manager._state_restore_callback = None
    tau_manager.current_cidfile_path = None
    # Reset lock state if possible (cleanest way is to just assume they are free or make new ones, 
    # but they are global instances. pytest-forked or similar would be better, but we don't have it.
    # We rely on tests releasing them.)
    yield
    # Cleanup
    if tau_manager.tau_process:
        tau_manager.kill_tau_process()


# --- Tests ---

# --- Tests ---

def test_timeout_triggers_kill_once_and_releases_lock(reset_tau_manager_globals):
    """
    Verifies that upon timeout:
    1. kill_tau_process is called.
    2. Only the initiator calls it (thundering herd protection).
    3. The high-level `tau_comm_lock` is NOT held during the kill.
    """
    # 1. Setup Mock Process
    tau_manager.tau_ready.set()
    tau_manager.tau_process_ready.set()
    mock_popen = MagicMock()
    mock_popen.poll.return_value = None
    mock_popen.stdout.closed = False
    mock_popen.stdout.fileno.return_value = 10
    mock_popen.stdin.closed = False
    
    with tau_manager.tau_process_lock:
        tau_manager.tau_process = mock_popen

    # 2. Mock environment to force timeout
    with patch.object(config, 'COMM_TIMEOUT', 0.1):
        with patch('select.select', return_value=([], [], [])):
            # Fixed list of times to ensure test doesn't loop forever
            # Start: 100.0
            # Loop 1: 100.05
            # Loop 2: 100.15 (triggers timeout > 0.1)
            # Extra values for subsequent calls
            times = [100.0, 100.05, 100.15, 100.2, 100.2] 
            with patch('time.monotonic', side_effect=times) as mock_time:
                
                with patch('tau_manager.kill_tau_process') as mock_kill:
                    def verify_no_locks_held():
                        # Explicitly check that the comm lock is released
                        assert not tau_manager.tau_comm_lock.locked(), "tau_comm_lock should be released before calling kill_tau_process"
                    
                    mock_kill.side_effect = verify_no_locks_held
                    
                    with pytest.raises(tau_manager.TauCommunicationError):
                        tau_manager.communicate_with_tau(target_output_stream_index=0)
                    
                    assert mock_kill.call_count == 1
                    
                    # Verify `restart_in_progress` is set
                    assert tau_manager.restart_in_progress.is_set()


def test_thundering_herd_protection(reset_tau_manager_globals):
    """
    Simulate multiple concurrent timeouts. Ensure `kill_tau_process` is only called once.
    """
    tau_manager.tau_ready.set()
    tau_manager.tau_process_ready.set()
    mock_popen = MagicMock()
    mock_popen.poll.return_value = None
    mock_popen.stdout.fileno.return_value = 10
    mock_popen.stdout.closed = False
    mock_popen.stdin.closed = False # Fix: explicitly set closed=False
    
    with tau_manager.tau_process_lock:
        tau_manager.tau_process = mock_popen

    # Force timeout
    with patch.object(config, 'COMM_TIMEOUT', 0.01):
        # We need `select` to timeout
        with patch('select.select', return_value=([], [], [])):
            with patch('time.monotonic', side_effect=lambda: time.time()): # Real time is fine with short timeout
               with patch('tau_manager.kill_tau_process') as mock_kill:
                   
                   # Case 1: Initiator
                   tau_manager.restart_in_progress.clear()
                   try:
                       tau_manager.communicate_with_tau(target_output_stream_index=0)
                   except tau_manager.TauCommunicationError:
                       pass
                   assert mock_kill.call_count == 1
                   assert tau_manager.restart_in_progress.is_set()
                   
                   # Case 2: Follower
                   mock_kill.reset_mock()
                   # restart_in_progress is already set
                   try:
                       tau_manager.communicate_with_tau(target_output_stream_index=0)
                   except tau_manager.TauCommunicationError:
                       pass
                   
                   # Should NOT have called kill again
                   assert mock_kill.call_count == 0


def test_kill_process_uses_cid_file(reset_tau_manager_globals):
    """
    Verify robust docker cleanup using CID file.
    """
    cid_val = "test_cid_123"
    cid_path = "test.cid"
    tau_manager.current_cidfile_path = cid_path
    
    with open(cid_path, "w") as f:
        f.write(cid_val)
        
    try:
        with patch("subprocess.run") as mock_run:
            with patch("os.remove") as mock_remove:
                tau_manager.kill_tau_process()
                
                # Check for docker kill <cid>
                cmd_args_list = [c[0][0] for c in mock_run.call_args_list]
                
                # Look for the kill command
                kill_cmds = [cmd for cmd in cmd_args_list if 'kill' in cmd and cid_val in cmd]
                assert len(kill_cmds) > 0, "Docker kill command with CID not found"
                
                # Look for the rm command
                rm_cmds = [cmd for cmd in cmd_args_list if 'rm' in cmd and cid_val in cmd]
                assert len(rm_cmds) > 0, "Docker rm command with CID not found"
                
                # Check confirm file removal
                mock_remove.assert_called_with(cid_path)
    finally:
        if os.path.exists(cid_path):
            os.remove(cid_path)


def test_comm_lock_serialization_concurrency(reset_tau_manager_globals):
    """
    Verify `tau_comm_lock` effectively serializes access using real threads.
    """
    tau_manager.tau_ready.set()
    tau_manager.tau_process_ready.set()
    
    # Mock Process
    mock_popen = MagicMock()
    mock_popen.poll.return_value = None
    mock_popen.stdout.closed = False
    mock_popen.stdout.fileno.return_value = 10
    mock_popen.stdin.closed = False
    with tau_manager.tau_process_lock:
         tau_manager.tau_process = mock_popen

    # We need a mock execution that takes time
    # We patch `select.select` to be slow
    
    concurrent_executions = 0
    max_concurrent = 0
    monitor_lock = threading.Lock()
    
    def slow_select(*args):
        nonlocal concurrent_executions, max_concurrent
        with monitor_lock:
            concurrent_executions += 1
            max_concurrent = max(max_concurrent, concurrent_executions)
        
        time.sleep(0.05) # Hold the lock for a bit
        
        with monitor_lock:
            concurrent_executions -= 1
        return ([1], [], []) # Return readable
            
    with patch('select.select', side_effect=slow_select):
        with patch('os.read', return_value=b"o0 := 0\n"):
             threads = []
             for _ in range(3):
                 t = threading.Thread(target=tau_manager.communicate_with_tau)
                 t.start()
                 threads.append(t)
             
             for t in threads:
                 t.join()
                 
    # If serialized, max_concurrent inside the critical section (select) should remain 1.
    # Note: `concurrent_executions` tracks entry into `slow_select`, which happens INSIDE `communicate_with_tau`'s lock.
    assert max_concurrent == 1, f"Concurrency violation: {max_concurrent} threads entered critical section simultaneously"


def test_tau_ready_refuses_on_callback_failure(reset_tau_manager_globals):
    """
    Verify that if state restore callback raises exception, `tau_ready` is NOT set
    and `kill_tau_process` is called to trigger restart.
    """
    # 1. Setup global state
    tau_manager.tau_ready.clear()
    tau_manager.tau_process_ready.clear()
    tau_manager.server_should_stop.clear()
    
    # 2. Mock state restore callback to fail
    mock_callback = MagicMock(side_effect=Exception("Restore Failed"))
    tau_manager.set_state_restore_callback(mock_callback)

    # 3. Mock Process and IO
    mock_popen = MagicMock()
    mock_popen.poll.return_value = None
    mock_popen.stdout.fileno.return_value = 10
    mock_popen.stderr.readline.side_effect = [''] # Ensure stderr thread exits
    
    # Logic in start_and_manage... reads stdout looking for signal
    # We'll feed it the signal immediately
    ready_signal_bytes = (config.TAU_READY_SIGNAL + "\n").encode()
    
    
    # Explicitly set signal to known value
    tau_manager.config.TAU_READY_SIGNAL = "TEST_READY_SIGNAL"
    ready_bytes = b"TEST_READY_SIGNAL\n"
    
    # Ensure we don't accidentally enter the infinite test loop in start_and_manage_tau_process
    with patch.dict(os.environ, {"TAU_FORCE_TEST": "0"}):
        with patch('subprocess.Popen', return_value=mock_popen):
            with patch('select.select', return_value=([1], [], [])):
                with patch('os.read', return_value=ready_bytes): 
                     with patch('tau_manager.kill_tau_process') as mock_kill:
                         with patch('time.sleep'): # skip sleep
                              # Make kill raise SystemExit to immediately break strict loop and verify call
                              mock_kill.side_effect = SystemExit("Kill called")
                              
                              # Patch monotonic to ensure loop terminates even if logic misses signal
                              # Start large enough
                              t = [100.0] 
                              def fake_monotonic():
                                  t[0] += 1.0 # Advance 1s per call
                                  return t[0]
                                  
                              with patch('time.monotonic', side_effect=fake_monotonic):
                                  # Run it
                                  # Expect SystemExit if kill is called (Pass)
                                  # If not called, it will timeout and finish (Fail assertion)
                                  try:
                                      tau_manager.start_and_manage_tau_process()
                                  except SystemExit:
                                      pass
                              
                              # Verification
                              assert mock_callback.called, "State restore callback should have been called"
                              assert mock_kill.called, "kill_tau_process should have been called"
                              assert not tau_manager.tau_ready.is_set(), "tau_ready should NOT be set on restore failure"



