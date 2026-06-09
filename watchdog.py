#!/usr/bin/env python3
import os
import sys
import time
import json
import signal
from datetime import datetime, timezone

DEFAULT_TIMEOUT_NAME = "comm_timeout"
DEFAULT_CONFIG_KEY = "COMM_TIMEOUT"
DEFAULT_ENV_VAR = "TAU_COMM_TIMEOUT"


def _log(message: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} [WATCHDOG] {message}", flush=True)


def kill_process_tree(pid):
    _log(f"Sending SIGKILL to child processes of PID {pid}...")
    try:
        import subprocess
        subprocess.run(["pkill", "-9", "-P", str(pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        _log(f"Error running pkill: {e}")

    _log(f"Sending SIGKILL to PID {pid}...")
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError as e:
        _log(f"Error sending SIGKILL: {e}")

def main():
    if len(sys.argv) < 3:
        print("Usage: watchdog.py <status_file_path> <timeout_seconds> [parent_pid]")
        sys.exit(1)

    status_file = sys.argv[1]
    timeout = float(sys.argv[2])

    parent_pid = None
    if len(sys.argv) > 3:
        parent_pid = int(sys.argv[3])

    _log(
        f"Started. status_file={status_file} "
        f"timeout_name={DEFAULT_TIMEOUT_NAME} limit={timeout}s "
        f"({DEFAULT_CONFIG_KEY} / {DEFAULT_ENV_VAR}) parent_pid={parent_pid}"
    )
    
    while True:
        time.sleep(1.0)
        
        # Check if parent process (main server) is still running
        if parent_pid:
            try:
                os.kill(parent_pid, 0)
            except OSError:
                _log("Parent process exited. Exiting watchdog.")
                break
                
        if not os.path.exists(status_file):
            continue
            
        try:
            with open(status_file, "r") as f:
                data = json.load(f)
        except Exception:
            # File might be in the middle of being written, skip this tick
            continue
            
        pid = data.get("pid")
        db_path = data.get("db_path")
        last_start_time = data.get("last_start_time")
        
        if not pid:
            continue
            
        # If parent_pid not passed, use the one from status file
        if not parent_pid:
            parent_pid = pid
            
        if last_start_time:
            elapsed = time.time() - last_start_time
            if elapsed > timeout:
                timeout_name = data.get("watchdog_timeout_name", DEFAULT_TIMEOUT_NAME)
                limit_seconds = data.get("watchdog_timeout_seconds", timeout)
                config_key = data.get("watchdog_config_key", DEFAULT_CONFIG_KEY)
                env_var = data.get("watchdog_env_var", DEFAULT_ENV_VAR)
                comm_source = data.get("comm_source", "unknown")

                killed_at = time.time()
                kill_report = {
                    "reason": "watchdog_comm_timeout",
                    "timeout_name": timeout_name,
                    "timeout_seconds": limit_seconds,
                    "config_key": config_key,
                    "env_var": env_var,
                    "elapsed_seconds": round(elapsed, 3),
                    "comm_source": comm_source,
                    "parent_pid": parent_pid,
                    "killed_at": killed_at,
                    "killed_at_iso": datetime.fromtimestamp(
                        killed_at, tz=timezone.utc
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                }
                report_path = os.path.join(
                    os.path.dirname(status_file), "watchdog_kill_report.json"
                )
                try:
                    with open(report_path, "w", encoding="utf-8") as rf:
                        json.dump(kill_report, rf, indent=2)
                        rf.write("\n")
                    _log(f"Wrote kill report: {report_path}")
                except Exception as e:
                    _log(f"Failed to write kill report: {e}")

                _log(
                    "CRITICAL: Tau communication exceeded watchdog limit. "
                    f"timeout_name={timeout_name!r} "
                    f"({config_key}={limit_seconds}s, override via {env_var}); "
                    f"elapsed={elapsed:.1f}s; comm_source={comm_source!r}"
                )
                _log(f"Terminating main server PID {parent_pid} and cleaning database...")

                # 1. Forcefully kill the main process tree (ensuring no zombies)
                kill_process_tree(parent_pid)
                
                # 2. Clean/delete the database node.db and its temp files
                if db_path:
                    for ext in ["", "-wal", "-shm", "-journal"]:
                        path = db_path + ext
                        if os.path.exists(path):
                            try:
                                os.remove(path)
                                _log(f"Removed database file: {path}")
                            except Exception as e:
                                _log(f"Failed to remove database file {path}: {e}")

                _log("Cleanup finished. Watchdog exiting.")
                sys.exit(0)

if __name__ == "__main__":
    main()
