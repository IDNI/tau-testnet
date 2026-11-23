"""A stop request that comes before the manager thread runs is not lost."""
import threading
from unittest.mock import patch

import pytest

import tau_manager
from conftest import tau_manager_threads


@pytest.fixture
def force_test_mode(monkeypatch):
    monkeypatch.setenv("TAU_FORCE_TEST", "1")
    yield
    tau_manager.request_shutdown()
    tau_manager.server_should_stop.clear()
    tau_manager.tau_test_mode = False


def test_a_shutdown_before_the_thread_runs_stops_it(force_test_mode, monkeypatch):
    original = tau_manager.start_and_manage_tau_process
    release = threading.Event()

    def _late_start():
        # Hold the thread before its first line, so the stop request comes first.
        release.wait(timeout=5)
        return original()

    monkeypatch.setattr(tau_manager, "start_and_manage_tau_process", _late_start)
    thread = tau_manager.start_manager_thread()
    tau_manager.request_shutdown()
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive(), "the manager thread lost the stop request"


def test_a_shutdown_right_after_the_start_stops_the_thread(force_test_mode):
    thread = tau_manager.start_manager_thread()
    tau_manager.request_shutdown()
    thread.join(timeout=5)
    assert not thread.is_alive(), "the manager thread lost the stop request"


def test_the_thread_is_a_daemon_that_the_fixtures_find(force_test_mode):
    thread = tau_manager.start_manager_thread()
    try:
        assert thread.daemon
        assert thread in tau_manager_threads()
        assert tau_manager.tau_ready.wait(timeout=5)
    finally:
        tau_manager.request_shutdown()
        thread.join(timeout=5)
    assert not thread.is_alive()


def test_a_shutdown_before_the_thread_runs_leaves_no_readiness(force_test_mode, monkeypatch):
    original = tau_manager.start_and_manage_tau_process
    release = threading.Event()

    def _late_start():
        release.wait(timeout=5)
        return original()

    monkeypatch.setattr(tau_manager, "start_and_manage_tau_process", _late_start)
    thread = tau_manager.start_manager_thread()
    tau_manager.request_shutdown()
    release.set()
    thread.join(timeout=5)
    assert not thread.is_alive()
    assert not tau_manager.tau_ready.is_set(), "a stopped manager published readiness"


def test_a_shutdown_during_the_engine_build_leaves_no_engine(monkeypatch):
    monkeypatch.setenv("TAU_FORCE_TEST", "0")
    restored = []
    tau_manager.set_state_restore_callback(lambda: restored.append(True))

    class _Interface:
        def __init__(self, *a, **k):
            tau_manager.request_shutdown()

    try:
        with patch("tau_native.TauInterface", _Interface):
            thread = tau_manager.start_manager_thread()
            thread.join(timeout=5)
        assert not thread.is_alive()
        assert not tau_manager.tau_ready.is_set(), "a stopped manager published readiness"
        assert tau_manager.tau_direct_interface is None, "a stopped manager kept its engine"
        assert not restored, "a stopped manager restored the state"
    finally:
        tau_manager.request_shutdown()
        tau_manager.server_should_stop.clear()
        tau_manager.set_state_restore_callback(None)
