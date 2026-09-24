"""Startup fails closed.

Two ways a node used to come up answering for a chain it never loaded:

* a native init failure switched the manager into MOCK mode and published
  readiness, so a production node with a broken binding went on accepting
  transactions against fabricated Tau verdicts;
* a failed state restore was logged and ignored, then readiness was published
  for an interpreter describing some other state.

Mock execution is only ever the explicitly requested test configuration.
"""
import threading
import time
from unittest.mock import patch

import pytest

import tau_manager


@pytest.fixture
def manager_thread(monkeypatch):
    monkeypatch.setenv("TAU_FORCE_TEST", "0")
    tau_manager.server_should_stop.clear()
    tau_manager.tau_ready.clear()
    tau_manager.tau_test_mode = False
    threads = []

    def _start():
        t = threading.Thread(target=tau_manager.start_and_manage_tau_process, daemon=True)
        t.start()
        threads.append(t)
        return t

    yield _start
    tau_manager.request_shutdown()
    for t in threads:
        t.join(timeout=5)
    tau_manager.server_should_stop.clear()
    tau_manager.tau_test_mode = False
    tau_manager.set_state_restore_callback(None)


def test_a_broken_native_binding_does_not_become_mock_mode(manager_thread):
    with patch("tau_native.TauInterface", side_effect=RuntimeError("binding is broken")):
        manager_thread()
        published = tau_manager.tau_ready.wait(timeout=1.5)
    assert not published, "readiness was published for an engine that never started"
    assert tau_manager.tau_test_mode is False, (
        "a native failure silently switched the node to mock execution"
    )


def test_a_failed_restore_does_not_publish_readiness(manager_thread):
    class _Interface:
        def __init__(self, *a, **k):
            pass

    def _restore():
        raise RuntimeError("could not reload the committed rules")

    tau_manager.set_state_restore_callback(_restore)
    with patch("tau_native.TauInterface", _Interface):
        manager_thread()
        published = tau_manager.tau_ready.wait(timeout=1.5)
    assert not published, (
        "readiness was published for an interpreter whose restore failed"
    )


def test_requested_test_mode_still_comes_up(monkeypatch):
    """The explicit mock configuration is unchanged -- guard the guard."""
    monkeypatch.setenv("TAU_FORCE_TEST", "1")
    tau_manager.server_should_stop.clear()
    tau_manager.tau_ready.clear()
    t = threading.Thread(target=tau_manager.start_and_manage_tau_process, daemon=True)
    t.start()
    try:
        assert tau_manager.tau_ready.wait(timeout=5)
        assert tau_manager.tau_test_mode is True
    finally:
        tau_manager.request_shutdown()
        t.join(timeout=5)
        tau_manager.server_should_stop.clear()
        tau_manager.tau_test_mode = False


# --- the server wiring ---------------------------------------------------------

def _container(tmp_path):
    import chain_state
    import db

    container = type("C", (), {})()
    container.settings = type("S", (), {"env": "test"})()
    container.tau_manager = tau_manager
    container.db = db
    container.chain_state = chain_state
    return container


def test_the_server_refuses_to_start_when_the_authority_cannot_be_built(
        tmp_path, monkeypatch):
    """Not "start anyway on the in-process restore". A node whose committed
    anchors disagree, or whose authority cannot be reconstructed, is not ready
    -- and at startup, not ready means not starting."""
    import server
    import tau_authority
    from errors import TauEngineCrash

    monkeypatch.setenv("TAU_FORCE_TEST", "0")
    container = _container(tmp_path)
    boom = RuntimeError("committed anchors disagree")
    with patch.object(container.db, "init_db"), \
         patch.object(container.chain_state, "initialize_persistent_state"), \
         patch.object(tau_authority.AuthoritativeTauOwner, "initialize",
                      side_effect=boom), \
         patch.object(tau_manager, "set_state_restore_callback") as restore_cb, \
         patch("threading.Thread") as thread:
        with pytest.raises(TauEngineCrash, match="committed anchors disagree"):
            server._run_server(container)
    assert not thread.called, "the in-process manager was started anyway"
    assert not restore_cb.called, "the in-process restore was armed anyway"


def test_requested_test_mode_does_not_enable_the_authority(tmp_path, monkeypatch):
    """Mock mode has no native engine to be authoritative about."""
    import server
    import tau_authority

    monkeypatch.setenv("TAU_FORCE_TEST", "1")
    container = _container(tmp_path)
    with patch.object(container.db, "init_db"), \
         patch.object(container.chain_state, "initialize_persistent_state"), \
         patch.object(tau_authority.AuthoritativeTauOwner, "initialize") as init, \
         patch("threading.Thread") as thread:
        thread.return_value.start.side_effect = RuntimeError("stop here")
        with pytest.raises(RuntimeError, match="stop here"):
            server._run_server(container)
    assert not init.called
