"""Shared pytest fixtures and libp2p test helpers for the Tau Testnet test-suite.

Test helpers (`wait_for_addrs`, `connect_peers`, `stream_rpc`) live here and
delegate to `network.libp2p_compat` for the underlying primitives. Tests should
import these instead of inlining their own listen-addr / connect / RPC helpers.
"""
from __future__ import annotations

import errno
import os
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import List

import multiaddr
import pytest
import trio

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import config
import db
import tau_logging


@pytest.fixture(scope="session", autouse=True)
def test_environment() -> Iterator[None]:
    """Ensure tests run with the dedicated 'test' configuration and logging."""
    original_env = os.environ.get("TAU_ENV")
    os.environ["TAU_ENV"] = "test"
    # Orchestration/network/state tests default to the deterministic test
    # validator (mock) — running the real engine on them is meaningless and,
    # for rule-accumulating stress tests, pathologically slow. The tests that
    # actually validate Tau semantics opt into the real engine themselves,
    # either by instantiating tau_native.TauInterface directly or by setting
    # TAU_FORCE_TEST=0 in their own setup.
    os.environ.setdefault("TAU_FORCE_TEST", "1")

    config.reload_settings(env="test")
    tau_logging.configure(config.LOGGING, force=True)

    yield

    if original_env is None:
        os.environ.pop("TAU_ENV", None)
        config.reload_settings(env="development")
    else:
        os.environ["TAU_ENV"] = original_env
        config.reload_settings(env=original_env)

@pytest.fixture(autouse=True)
def mock_consensus_for_unrelated_tests(monkeypatch, request):
    """Automatically allow block creation turns in non-consensus tests to avoid breaking mempool/faucet tests."""
    if hasattr(request, "module") and request.module and "test_poa" not in request.module.__name__ and "test_network" not in request.module.__name__:
        try:
            monkeypatch.setattr("consensus.engine.TauConsensusEngine.query_eligibility", lambda *args, **kwargs: True)
        except AttributeError:
            pass


class FakeEngine:
    """Stand-in for `tau_native.TauInterface` that fails on concurrent entry.

    Mimics the FD-1 corruption the real capture produced: whoever finds another
    thread already inside raises the exact OSError. Shared by the engine-
    serialization and block-production-serialization suites; `dwell` widens the
    race window.
    """

    def __init__(self, dwell: float = 0.02):
        self._dwell = dwell
        self._counter_lock = threading.Lock()
        self._inside = 0
        self.max_concurrent = 0
        self.calls = 0
        self.overlaps: List[str] = []
        self.sources: List[str] = []

    def _enter(self, what: str) -> None:
        with self._counter_lock:
            self._inside += 1
            self.calls += 1
            self.max_concurrent = max(self.max_concurrent, self._inside)
            overlapping = self._inside > 1
        if overlapping:
            self.overlaps.append(what)
            with self._counter_lock:
                self._inside -= 1
            raise OSError(errno.EBADF, "Bad file descriptor")

    def _exit(self) -> None:
        with self._counter_lock:
            self._inside -= 1

    def _run(self, what: str, source: str = "-"):
        self.sources.append(source)
        self._enter(what)
        try:
            time.sleep(self._dwell)  # widen the race window
        finally:
            self._exit()

    # --- TauInterface surface used by tau_manager ---
    def communicate(self, rule_text=None, target_output_stream_index=0,
                    input_stream_values=None, source="unknown",
                    apply_rules_update=True):
        self._run(f"communicate(o{target_output_stream_index})", source)
        return "1"

    def communicate_multi(self, rule_text=None, input_stream_values=None,
                          source="unknown", apply_rules_update=True):
        self._run("communicate_multi", source)
        return {1: "1", 6: "1", 7: "1"}

    def update_spec(self, new_spec):
        self._run("update_spec")

    def get_current_spec(self):
        return "always o0[t] = 1."

    @staticmethod
    def preprocess_spec_text(spec_text: str) -> str:
        return (spec_text or "").replace("\n", " ")


@pytest.fixture
def fake_engine(monkeypatch):
    """Install a FakeEngine under tau_manager's real (locking) comm paths."""
    import tau_manager

    engine = FakeEngine()
    monkeypatch.setattr(tau_manager, "tau_direct_interface", engine)
    monkeypatch.setattr(tau_manager, "tau_test_mode", False)
    monkeypatch.setattr(tau_manager, "_rules_handler", None)
    was_ready = tau_manager.tau_ready.is_set()
    tau_manager.tau_ready.set()
    yield engine
    if not was_ready:
        tau_manager.tau_ready.clear()


@pytest.fixture
def node_state(tmp_path, monkeypatch, fake_engine):
    """Minimal in-process node: temp DB, genesis, dummy miner key, fake engine."""
    import chain_state

    prev_db_path = config.STRING_DB_PATH
    prev_conn = db._db_conn
    prev_privkey = config.MINER_PRIVKEY
    prev_chain_globals = (
        chain_state._balances,
        chain_state._sequence_numbers,
        chain_state._application_rules_state,
        chain_state._lifecycle_manager,
    )

    config.set_database_path(str(tmp_path / "node_state.sqlite"))
    db._db_conn = None
    db.init_db()
    db.clear_mempool()
    config.MINER_PRIVKEY = "0" * 63 + "1"
    # conftest defaults the suite to the mock validator; these tests exercise the
    # real admission / block-production paths, so they must actually call Tau.
    monkeypatch.setenv("TAU_FORCE_TEST", "0")

    from consensus.governance import ConsensusLifecycleManager
    chain_state._balances = {}
    chain_state._sequence_numbers = {}
    chain_state._application_rules_state = ""
    # A prior test that loaded genesis leaves active_validators populated, which
    # makes the PoA gate refuse to propose for our dummy miner.
    chain_state._lifecycle_manager = ConsensusLifecycleManager()
    chain_state.load_genesis("data/genesis.json")
    chain_state._lifecycle_manager = ConsensusLifecycleManager()

    yield fake_engine

    if db._db_conn is not None:
        db._db_conn.close()
    db._db_conn = prev_conn
    config.set_database_path(prev_db_path)
    config.MINER_PRIVKEY = prev_privkey
    (
        chain_state._balances,
        chain_state._sequence_numbers,
        chain_state._application_rules_state,
        chain_state._lifecycle_manager,
    ) = prev_chain_globals


@pytest.fixture()
def temp_database(tmp_path) -> Iterator[str]:
    """Provide a temporary SQLite database path and ensure cleanup."""
    original_path = config.STRING_DB_PATH
    db_path = tmp_path / "node.sqlite"
    config.set_database_path(str(db_path))

    if getattr(db, "_db_conn", None) is not None:
        db._db_conn.close()
        db._db_conn = None

    db.init_db()
    yield str(db_path)

    if getattr(db, "_db_conn", None) is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(original_path)

# --------------------------------------------------------------------------
# libp2p test helpers (A8) — single source of truth, sourced from
# network.libp2p_compat where possible.
# --------------------------------------------------------------------------


async def wait_for_addrs(host, *, timeout: float = 5.0) -> List[multiaddr.Multiaddr]:
    """Poll until the host reports at least one observed listen address.

    Thin wrapper over `network.libp2p_compat.wait_for_listening` so tests can
    import this single name from conftest.
    """
    from network.libp2p_compat import wait_for_listening
    return await wait_for_listening(host, timeout=timeout)


async def connect_peers(host_a, host_b) -> None:
    """Resolve host_b's listen addrs, register them in host_a's peerstore, connect."""
    from libp2p.peer.peerinfo import PeerInfo
    addrs_b = await wait_for_addrs(host_b)
    peer_info = PeerInfo(host_b.get_id(), addrs_b)
    host_a.get_peerstore().add_addrs(peer_info.peer_id, peer_info.addrs, 60)
    await host_a.connect(peer_info)


async def stream_rpc(
    host,
    peer_id,
    protocol: str,
    payload: bytes,
    *,
    read_timeout: float = 5.0,
) -> bytes:
    """Open a new stream to `peer_id`, write payload, read response, close."""
    stream = await host.new_stream(peer_id, [protocol])
    await stream.write(payload)
    try:
        with trio.fail_after(read_timeout):
            data = await stream.read()
    finally:
        await stream.close()
    return data or b""


_exit_status = 0

def pytest_sessionfinish(session, exitstatus):
    global _exit_status
    _exit_status = exitstatus

def pytest_unconfigure(config):
    """
    Bypass standard Python exit to avoid native segfaults caused by 
    upstream tau-lang destructors when tearing down global test state.
    """
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(_exit_status)
