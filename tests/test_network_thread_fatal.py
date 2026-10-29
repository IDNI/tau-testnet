"""A NetworkService thread that dies after a successful start must end the process.

Without this the node keeps mining while gossiping nothing: the main thread is
parked in a blocking accept() and nothing watches the network thread.
"""
import logging
import signal
import sys
import threading
import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import config
import server
from network import NetworkListenError, bus


class _Recorder:
    def __init__(self):
        self.events = []

    def kill(self):
        self.events.append(("kill",))

    def hard_exit(self, code):
        self.events.append(("hard_exit", code))

    def arm_timer(self, grace):
        self.events.append(("arm_timer", grace))

    def names(self):
        return [event[0] for event in self.events]


@pytest.fixture(autouse=True)
def _isolated_globals(monkeypatch):
    monkeypatch.setattr(server, "NETWORK_THREAD", None)
    monkeypatch.setattr(server, "_NETWORK_FATAL", None)
    server.NETWORK_STOP_FLAG.clear()
    bus.unregister(bus.get())
    yield
    server.NETWORK_STOP_FLAG.clear()
    bus.unregister(bus.get())


@pytest.fixture
def recorder(monkeypatch):
    rec = _Recorder()
    monkeypatch.setattr(server, "_deliver_sigint", rec.kill)
    monkeypatch.setattr(server, "_hard_exit", rec.hard_exit)
    monkeypatch.setattr(server, "_arm_hard_exit_timer", rec.arm_timer)
    return rec


def _runner_and_service(
    monkeypatch, *, start_error=None, stop_error=None, post_start_error=None, real_thread=False
):
    """The `_runner` closure from `_start_network_background` plus its fake service.

    With `real_thread` the thread is really started and its handle is returned instead.
    """
    service = MagicMock()
    service._dht_manager = MagicMock()
    service.start = AsyncMock(side_effect=start_error)
    service.stop = AsyncMock(side_effect=stop_error)
    service.listen_addrs.return_value = []

    container = MagicMock()
    container.chain_state = MagicMock()
    # The first call is the pre-start injection; the second runs right after startup finished.
    container.chain_state.set_dht_client.side_effect = [None, post_start_error]
    if post_start_error is None:
        container.chain_state.set_dht_client.side_effect = None

    # _runner looks NetworkService up when it runs, so the patch must outlive this helper.
    monkeypatch.setattr(server, "NetworkService", lambda cfg: service)
    if real_thread:
        server._start_network_background(container)
        return server.NETWORK_THREAD, service
    with patch("server.threading.Thread") as thread_cls:
        server._start_network_background(container)
    return thread_cls.call_args.kwargs["target"], service


# --------------------------------------------------------------------------
# _runner: when a trio crash is fatal
# --------------------------------------------------------------------------


def test_crash_after_successful_startup_invokes_handler_and_propagates(monkeypatch):
    handled = []
    monkeypatch.setattr(server, "_on_network_thread_crash", handled.append)
    boom = RuntimeError("boom")
    runner, _ = _runner_and_service(monkeypatch, post_start_error=boom)

    with pytest.raises(RuntimeError) as excinfo:
        runner()

    assert excinfo.value is boom
    assert handled == [boom]


def test_crash_while_stop_flag_set_is_not_fatal(monkeypatch):
    handled = []
    monkeypatch.setattr(server, "_on_network_thread_crash", handled.append)
    runner, _ = _runner_and_service(monkeypatch, stop_error=RuntimeError("stop failed"))
    server.NETWORK_STOP_FLAG.set()

    with pytest.raises(RuntimeError, match="stop failed"):
        runner()

    assert handled == []


def test_startup_failure_is_not_fatal(monkeypatch):
    handled = []
    monkeypatch.setattr(server, "_on_network_thread_crash", handled.append)
    runner, _ = _runner_and_service(monkeypatch, start_error=RuntimeError("start failed"))

    with pytest.raises(RuntimeError, match="start failed"):
        runner()

    assert handled == []


def test_listen_failure_is_not_fatal(monkeypatch):
    handled = []
    monkeypatch.setattr(server, "_on_network_thread_crash", handled.append)
    runner, _ = _runner_and_service(monkeypatch, start_error=NetworkListenError("port taken"))

    runner()

    assert handled == []


def test_clean_run_after_stop_flag_does_not_invoke_handler(monkeypatch):
    handled = []
    monkeypatch.setattr(server, "_on_network_thread_crash", handled.append)
    runner, service = _runner_and_service(monkeypatch)
    server.NETWORK_STOP_FLAG.set()

    runner()

    assert handled == []
    service.stop.assert_awaited_once()


def test_crash_after_startup_reaches_kill_through_runner(monkeypatch, recorder):
    runner, _ = _runner_and_service(monkeypatch, post_start_error=RuntimeError("boom"))

    with pytest.raises(RuntimeError, match="boom"):
        runner()

    assert recorder.names() == ["arm_timer", "kill"]
    assert isinstance(server._NETWORK_FATAL, RuntimeError)


def test_crash_after_startup_reaches_thread_excepthook(monkeypatch, recorder):
    hooked = []
    monkeypatch.setattr(threading, "excepthook", hooked.append)
    thread, _ = _runner_and_service(
        monkeypatch, post_start_error=RuntimeError("boom"), real_thread=True
    )

    thread.join(timeout=10.0)

    assert not thread.is_alive()
    (args,) = hooked
    assert args.exc_type is RuntimeError
    assert args.thread.name == "NetworkServiceThread"
    assert recorder.names() == ["arm_timer", "kill"]


# --------------------------------------------------------------------------
# _on_network_thread_crash
# --------------------------------------------------------------------------


def test_handler_records_fatal_arms_timer_then_signals(recorder, caplog):
    exc = RuntimeError("boom")

    with caplog.at_level(logging.CRITICAL, logger="tau.server"):
        server._on_network_thread_crash(exc)

    assert server._NETWORK_FATAL is exc
    assert recorder.events == [
        ("arm_timer", 2 * config.SHUTDOWN_TIMEOUT + 5.0),
        ("kill",),
    ]
    critical = [r for r in caplog.records if r.levelno == logging.CRITICAL]
    assert len(critical) == 1
    assert "RuntimeError('boom')" in critical[0].getMessage()
    assert critical[0].exc_info is None


def test_handler_hard_exits_when_signal_cannot_be_delivered(monkeypatch, recorder):
    def failing_kill():
        raise PermissionError("no kill")

    monkeypatch.setattr(server, "_deliver_sigint", failing_kill)

    server._on_network_thread_crash(RuntimeError("boom"))

    assert recorder.events[-1] == ("hard_exit", 70)


def test_hard_exit_timer_is_a_daemon_that_exits_with_code_70(monkeypatch):
    exits = []
    monkeypatch.setattr(server, "_hard_exit", exits.append)
    created = []

    class FakeTimer:
        def __init__(self, interval, function):
            self.interval, self.function = interval, function
            self.daemon = False
            self.started = False
            created.append(self)

        def start(self):
            self.started = True

    monkeypatch.setattr(server.threading, "Timer", FakeTimer)

    server._arm_hard_exit_timer(12.5)

    (timer,) = created
    assert (timer.interval, timer.daemon, timer.started) == (12.5, True, True)
    assert exits == []
    timer.function()
    assert exits == [70]


def test_hard_exit_timer_fires_after_grace(monkeypatch):
    fired = threading.Event()
    codes = []
    monkeypatch.setattr(server, "_hard_exit", lambda code: (codes.append(code), fired.set()))

    server._arm_hard_exit_timer(0.01)

    assert fired.wait(5.0)
    assert codes == [70]


@pytest.mark.skipif(
    threading.current_thread() is not threading.main_thread(),
    reason="signal handlers can only be installed from the main thread",
)
def test_deliver_sigint_interrupts_main_thread():
    received = []
    previous = signal.signal(signal.SIGINT, lambda signum, frame: received.append(signum))
    try:
        server._deliver_sigint()
        deadline = time.monotonic() + 2.0
        while not received and time.monotonic() < deadline:
            time.sleep(0.01)
    finally:
        signal.signal(signal.SIGINT, previous)

    assert received == [signal.SIGINT]


# --------------------------------------------------------------------------
# main(): exit status
# --------------------------------------------------------------------------


@pytest.fixture
def main_env(monkeypatch):
    tau_module = MagicMock()
    container = MagicMock()
    container.tau_manager = tau_module
    monkeypatch.setattr(sys, "argv", ["server.py"])
    monkeypatch.setattr(server.tau_logging, "configure", lambda *_a, **_k: None)
    monkeypatch.setattr(server, "_start_watchdog", lambda: None)
    monkeypatch.setattr(server.ServiceContainer, "build", lambda *a, **k: container)
    monkeypatch.setattr(server, "_run_server", MagicMock(side_effect=KeyboardInterrupt))
    return tau_module


def test_main_exits_nonzero_when_network_thread_died(main_env, monkeypatch):
    monkeypatch.setattr(server, "_NETWORK_FATAL", RuntimeError("boom"))

    with pytest.raises(SystemExit) as excinfo:
        server.main()

    assert excinfo.value.code == 1
    main_env.request_shutdown.assert_called_once_with()


def test_main_keyboard_interrupt_without_network_failure_exits_normally(main_env):
    assert server.main() is None
    main_env.request_shutdown.assert_called_once_with()
