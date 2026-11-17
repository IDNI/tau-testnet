"""The shutdown path of `_run_server` stops the Tau manager and builds no new engine."""
import threading
from unittest.mock import patch

import pytest
from conftest import stop_tau_manager_thread, tau_manager_threads

import chain_state
import config
import db
import server
import tau_manager
import tau_native


class _FakeSocket:
    def setsockopt(self, *args):
        pass

    def bind(self, addr):
        pass

    def listen(self, *args):
        pass

    def accept(self):
        # BaseException passes the `except Exception` handlers of the main loop.
        raise KeyboardInterrupt

    def close(self):
        pass


def _container():
    container = type("C", (), {})()
    container.settings = type("S", (), {"env": "test"})()
    container.tau_manager = tau_manager
    container.db = db
    container.chain_state = chain_state
    container.miner = None
    return container


@pytest.fixture
def isolated_manager(monkeypatch):
    monkeypatch.setenv("TAU_FORCE_TEST", "1")
    monkeypatch.setattr(server, "NETWORK_THREAD", None)
    monkeypatch.setattr(config, "SHUTDOWN_TIMEOUT", 1)
    monkeypatch.setattr(tau_manager, "_rules_handler", tau_manager._rules_handler)
    monkeypatch.setattr(tau_manager, "_state_restore_callback", tau_manager._state_restore_callback)
    monkeypatch.setattr(tau_manager, "tau_test_mode", tau_manager.tau_test_mode)
    tau_manager.server_should_stop.clear()
    tau_manager.tau_ready.clear()
    before = set(tau_manager_threads())
    yield
    for thread in tau_manager_threads():
        if thread not in before:
            stop_tau_manager_thread(thread)
    tau_manager.request_shutdown()
    tau_manager.server_should_stop.clear()


def test_a_main_loop_exception_stops_the_manager_without_a_rebuild(isolated_manager, monkeypatch):
    stop_flag_at_join = []
    manager_threads = []
    real_thread = threading.Thread

    class _RecordingThread(real_thread):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            if kwargs.get("target") is tau_manager.start_and_manage_tau_process:
                manager_threads.append(self)

        def join(self, timeout=None):
            if self in manager_threads:
                stop_flag_at_join.append(tau_manager.server_should_stop.is_set())
            return super().join(timeout)

    built = []

    class _Interface:
        def __init__(self, *args, **kwargs):
            built.append(self)

    monkeypatch.setattr(server.threading, "Thread", _RecordingThread)
    monkeypatch.setattr(tau_native, "TauInterface", _Interface)
    with patch.object(db, "init_db"), \
         patch.object(chain_state, "initialize_persistent_state"), \
         patch.object(server, "_start_network_and_websocket", return_value=frozenset()), \
         patch.object(server.socket, "socket", return_value=_FakeSocket()):
        with pytest.raises(KeyboardInterrupt):
            server._run_server(_container())

    assert manager_threads, "the manager thread was not started"
    assert stop_flag_at_join == [True], "the stop flag was not set before the join"
    manager_threads[0].join(timeout=5)
    assert not manager_threads[0].is_alive()
    assert built == [], "the shutdown path built a new Tau interface"
    assert tau_manager.tau_direct_interface is None
    assert not tau_manager.tau_ready.is_set()
