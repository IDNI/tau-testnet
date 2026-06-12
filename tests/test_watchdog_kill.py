"""
Regression test for the watchdog self-kill bug.

`kill_process_tree` used to run `pkill -9 -P <server_pid>` *before* signalling
the server. The watchdog is itself a direct child of the server, so that pkill
killed the watchdog first; the server then survived (spinning, frozen) with the
watchdog dead (observed 2026-06-12: server PID 3813774 still running 8h after
"Terminating main server PID 3813774", with no "Sending SIGKILL to PID" line).

The fix kills the server first and reaps its children explicitly, skipping the
watchdog's own PID.
"""

import os
import subprocess
from types import SimpleNamespace

import watchdog


def test_kill_targets_server_and_skips_self(monkeypatch):
    SERVER_PID = 4242
    WATCHDOG_PID = 9999  # the watchdog itself, a child of SERVER_PID
    OTHER_CHILD = 5555

    monkeypatch.setattr(os, "getpid", lambda: WATCHDOG_PID)

    # pgrep -P <server> lists the server's children, including the watchdog.
    def fake_run(cmd, *args, **kwargs):
        assert cmd[:2] == ["pgrep", "-P"]
        assert cmd[2] == str(SERVER_PID)
        return SimpleNamespace(stdout=f"{WATCHDOG_PID}\n{OTHER_CHILD}\n", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(pid))

    watchdog.kill_process_tree(SERVER_PID)

    # The server must be killed.
    assert SERVER_PID in killed, "server PID was never SIGKILLed"
    # The watchdog must never signal itself.
    assert WATCHDOG_PID not in killed, "watchdog killed itself"
    # Other children are reaped.
    assert OTHER_CHILD in killed
    # Server is killed before its children are reaped.
    assert killed.index(SERVER_PID) < killed.index(OTHER_CHILD)


def test_kill_still_kills_server_when_pgrep_fails(monkeypatch):
    SERVER_PID = 4242
    monkeypatch.setattr(os, "getpid", lambda: 9999)

    def boom(*args, **kwargs):
        raise FileNotFoundError("pgrep not found")

    monkeypatch.setattr(subprocess, "run", boom)

    killed = []
    monkeypatch.setattr(os, "kill", lambda pid, sig: killed.append(pid))

    watchdog.kill_process_tree(SERVER_PID)

    # Even with no child enumeration, the server itself is still killed.
    assert killed == [SERVER_PID]
