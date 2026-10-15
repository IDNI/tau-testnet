"""M1/C1: the speculative evaluator's two lifecycles and its result protocol.

Why a separate process at all is a measured fact, not a preference: stepping a
second interpreter in one process permanently wedges the first, a stream's width
is committed by the first ACCEPTED revision and outlives the rule that introduced
it, and the binding exposes no checkpoint. Rejection is disposal.

The protocol tests drive a FAKE worker, so they run without the native engine and
can produce responses a real worker never would.
"""
import inspect
import json
import os
import struct
import subprocess
import sys
import textwrap
import threading
import time

import pytest

import tau_preflight
import tau_speculation as spec

_HDR = struct.Struct("!I")


def _fake_worker(tmp_path, body: str, name="fake_worker.py"):
    """A worker that speaks the framing but answers however the test wants."""
    src = textwrap.dedent('''
        import json, os, struct, sys
        _HDR = struct.Struct("!I")
        FD = int(os.environ["TAU_WORKER_RESULT_FD"])
        def read():
            head = sys.stdin.buffer.read(_HDR.size)
            if not head or len(head) < _HDR.size: return None
            (n,) = _HDR.unpack(head)
            return json.loads(sys.stdin.buffer.read(n).decode())
        def write(payload):
            blob = json.dumps(payload).encode()
            os.write(FD, _HDR.pack(len(blob)) + blob)
    ''') + textwrap.dedent(body)
    path = tmp_path / name
    path.write_text(src)
    return str(path)


def _session(tmp_path, body, **kwargs):
    return spec.SpeculationSession(worker=_fake_worker(tmp_path, body), **kwargs)


# --- the result protocol fails closed -----------------------------------------

def test_a_response_for_another_request_is_rejected(tmp_path):
    s = _session(tmp_path, '''
        while True:
            req = read()
            if req is None: break
            write({"ok": True, "request_id": 999, "state_revision": 1})
    ''')
    with pytest.raises(spec.SpeculationProtocolError):
        s.state()
    s.kill()


def test_a_backwards_state_revision_is_rejected(tmp_path):
    s = _session(tmp_path, '''
        n = 10
        while True:
            req = read()
            if req is None: break
            write({"ok": True, "request_id": req["request_id"], "state_revision": n})
            n -= 5
    ''')
    assert s.state()["ok"]
    with pytest.raises(spec.SpeculationProtocolError):
        s.state()
    s.kill()


def _assert_lost_and_reaped(s):
    """The loss is reported once, the worker is gone for good, and the session
    refuses every following request the same way instead of reading a dead channel."""
    assert s._proc.returncode is not None, "the dead worker was not reaped"
    with pytest.raises(spec.WorkerLost):
        s.state()


def test_worker_loss_is_not_an_exception():
    """The point of the type: no `except Exception` in transaction logic may
    absorb it and report a verdict."""
    assert issubclass(spec.WorkerLost, BaseException)
    assert not issubclass(spec.WorkerLost, Exception)
    assert issubclass(spec.SpeculationProtocolError, Exception)
    assert not issubclass(spec.SpeculationProtocolError, spec.WorkerLost)


def test_a_truncated_frame_is_a_lost_worker(tmp_path):
    s = _session(tmp_path, '''
        req = read()
        blob = json.dumps({"ok": True, "request_id": req["request_id"], "state_revision": 1}).encode()
        os.write(FD, _HDR.pack(len(blob) + 50) + blob)   # claims more than it sends
    ''')
    with pytest.raises(spec.WorkerLost, match="truncated"):
        s.state()
    _assert_lost_and_reaped(s)


def test_a_dead_worker_is_an_operational_failure(tmp_path):
    s = _session(tmp_path, '''
        sys.exit(3)
    ''')
    with pytest.raises(spec.WorkerLost):
        s.state()
    _assert_lost_and_reaped(s)


def test_a_worker_that_reads_the_request_and_exits_without_answering(tmp_path):
    s = _session(tmp_path, '''
        read()
        os._exit(0)
    ''')
    with pytest.raises(spec.WorkerLost, match="result channel"):
        s.state()
    _assert_lost_and_reaped(s)


def test_a_worker_killed_from_another_thread_unblocks_the_caller(tmp_path):
    """The caller is parked in a blocking read when the process dies -- an OOM
    kill, or another thread disposing the session. It must come back promptly
    and with the loss, not hang and not read a verdict out of it."""
    s = _session(tmp_path, '''
        import time
        read()
        time.sleep(60)
    ''')
    seen = {}

    def _call():
        try:
            s.state()
        except BaseException as exc:    # noqa: BLE001 - the type is the subject
            seen["exc"] = exc

    caller = threading.Thread(target=_call, daemon=True)
    caller.start()
    time.sleep(0.5)
    assert caller.is_alive(), "the request was not blocked on the worker"
    started = time.monotonic()
    s._proc.kill()
    caller.join(timeout=10)
    assert not caller.is_alive(), "the caller stayed blocked after the worker died"
    assert time.monotonic() - started < 5
    assert isinstance(seen.get("exc"), spec.WorkerLost), seen
    _assert_lost_and_reaped(s)


def test_a_session_disposed_from_another_thread_unblocks_the_caller(tmp_path):
    s = _session(tmp_path, '''
        import time
        read()
        time.sleep(60)
    ''')
    seen = {}

    def _call():
        try:
            s.state()
        except BaseException as exc:    # noqa: BLE001
            seen["exc"] = exc

    caller = threading.Thread(target=_call, daemon=True)
    caller.start()
    time.sleep(0.5)
    s.kill()
    caller.join(timeout=10)
    assert not caller.is_alive()
    assert isinstance(seen.get("exc"), spec.WorkerLost), seen
    _assert_lost_and_reaped(s)


def test_a_request_on_a_closed_session_is_a_lost_worker(tmp_path):
    s = _session(tmp_path, '''
        while True:
            req = read()
            if req is None: break
            write({"ok": True, "request_id": req["request_id"], "state_revision": 1})
    ''')
    assert s.state()["ok"]
    s.close()
    with pytest.raises(spec.WorkerLost, match="closed"):
        s.state()


def test_closing_a_session_whose_worker_already_died_does_not_raise(tmp_path):
    s = _session(tmp_path, '''
        sys.exit(0)
    ''')
    s._proc.wait(timeout=10)
    assert s.close() == 0


def test_unavailable_native_is_operational_not_a_verdict(tmp_path):
    s = _session(tmp_path, '''
        req = read()
        write({"ok": False, "unavailable": True, "error": "native tau unavailable",
               "request_id": req["request_id"], "state_revision": 1})
    ''')
    with pytest.raises(spec.SpeculationError) as exc:
        s.state()
    assert "unavailable" in str(exc.value)
    s.kill()


def test_a_receipt_naming_another_candidate_is_rejected(tmp_path):
    s = _session(tmp_path, '''
        while True:
            req = read()
            if req is None: break
            write({"ok": True, "outcome": "ACCEPTED_CHANGED", "candidate_id": "other",
                   "request_id": req["request_id"], "state_revision": 1})
    ''')
    with pytest.raises(spec.SpeculationProtocolError):
        s.revise("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", "mine")
    s.kill()


# --- request deadlines ---------------------------------------------------------

def _slow_session(tmp_path, delay, **kwargs):
    """A worker that answers every request, but only after `delay` seconds."""
    return _session(tmp_path, f'''
        import time
        while True:
            req = read()
            if req is None or req.get("op") == "close": break
            time.sleep({delay})
            write({{"ok": True, "request_id": req["request_id"], "state_revision": 1}})
    ''', **kwargs)


class _ChannelSpy:
    """Stands in for the result reader and records which thread closes it."""

    def __init__(self, real):
        self._real = real
        self.closed_by = []

    def fileno(self):
        return self._real.fileno()

    def read(self, size):
        return self._real.read(size)

    @property
    def closed(self):
        return self._real.closed

    def close(self):
        self.closed_by.append(threading.current_thread())
        self._real.close()


def _in_flight(session, call):
    """Run `call(session)` on a thread and return once its request is parked on
    the worker."""
    seen = {}

    def _run():
        try:
            seen["result"] = call(session)
        except BaseException as exc:    # noqa: BLE001 - the type is the subject
            seen["exc"] = exc

    caller = threading.Thread(target=_run, daemon=True)
    caller.start()
    give_up = time.monotonic() + 5
    while not session._lock.locked() and time.monotonic() < give_up:
        time.sleep(0.01)
    time.sleep(0.3)
    assert caller.is_alive(), "the request was not blocked on the worker"
    return caller, seen


def test_a_timeout_is_a_lost_worker_and_not_an_exception():
    assert issubclass(spec.WorkerTimeout, spec.WorkerLost)
    assert not issubclass(spec.WorkerTimeout, Exception)


def test_a_session_has_no_deadline_unless_it_is_given_one():
    assert inspect.signature(spec.SpeculationSession).parameters["timeout"].default is None
    assert inspect.signature(spec.validate_once).parameters["timeout"].default == 120.0


def test_a_worker_past_its_deadline_is_killed_and_reported(tmp_path):
    s = _slow_session(tmp_path, 30, timeout=0.5)
    started = time.monotonic()
    with pytest.raises(spec.WorkerTimeout, match="no answer within"):
        s.state()
    elapsed = time.monotonic() - started
    assert 0.45 <= elapsed < 2.5, elapsed
    assert s._closed and s._result.closed
    _assert_lost_and_reaped(s)


@pytest.mark.parametrize("call", [
    lambda s: s.init("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", timeout=0.4),
    lambda s: s.revise("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", "c", timeout=0.4),
    lambda s: s.step({}, timeout=0.4),
    lambda s: s.state(timeout=0.4),
], ids=["init", "revise", "step", "state"])
def test_a_call_can_set_a_deadline_on_a_session_without_one(tmp_path, call):
    s = _slow_session(tmp_path, 30)
    with pytest.raises(spec.WorkerTimeout):
        call(s)
    _assert_lost_and_reaped(s)


def test_an_explicit_none_disables_the_session_deadline_for_one_call(tmp_path):
    s = _slow_session(tmp_path, 1.2, timeout=0.3)
    assert s.state(timeout=None)["ok"]
    with pytest.raises(spec.WorkerTimeout):
        s.state()
    _assert_lost_and_reaped(s)


def test_an_answer_inside_the_deadline_is_unaffected(tmp_path):
    """The reply is small enough to sit in the reader's buffer behind the header,
    where a wait on the fd would see nothing and report a timeout."""
    s = _slow_session(tmp_path, 0.2, timeout=10)
    assert s.state()["ok"]
    assert s.state(timeout=10)["ok"]
    assert s.close() == 0


def test_a_session_without_a_deadline_waits_for_a_slow_worker(tmp_path):
    s = _slow_session(tmp_path, 1.5)
    assert s.state()["ok"]
    assert s.close() == 0


def test_a_response_larger_than_the_pipe_reads_under_a_deadline(tmp_path):
    s = _session(tmp_path, '''
        while True:
            req = read()
            if req is None or req.get("op") == "close": break
            write({"ok": True, "request_id": req["request_id"], "state_revision": 1,
                   "diagnostics": "x" * 200_000})
    ''', timeout=10)
    assert len(s.state()["diagnostics"]) == 200_000
    assert len(s.state()["diagnostics"]) == 200_000
    assert s.close() == 0


def test_an_external_kill_under_a_deadline_is_a_lost_worker_not_a_timeout(tmp_path):
    s = _slow_session(tmp_path, 60, timeout=30)
    caller, seen = _in_flight(s, lambda session: session.state())
    started = time.monotonic()
    s.kill()
    caller.join(timeout=10)
    assert not caller.is_alive()
    assert time.monotonic() - started < 5
    assert isinstance(seen.get("exc"), spec.WorkerLost), seen
    assert not isinstance(seen["exc"], spec.WorkerTimeout)
    assert s._result.closed
    _assert_lost_and_reaped(s)


def test_the_request_thread_closes_a_channel_that_is_in_flight(tmp_path):
    """Closing the reader's fd from another thread while it waits would free the
    number for reuse, and the wait would then watch an unrelated file."""
    s = _slow_session(tmp_path, 60, timeout=30)
    spy = s._result = _ChannelSpy(s._result)
    caller, seen = _in_flight(s, lambda session: session.state())
    s._release_result()
    assert spy.closed_by == []
    s._proc.kill()
    caller.join(timeout=10)
    assert not caller.is_alive()
    assert isinstance(seen.get("exc"), spec.WorkerLost), seen
    assert spy.closed_by == [caller]
    _assert_lost_and_reaped(s)


@pytest.mark.parametrize("dispose", ["kill", "close"])
def test_an_idle_session_closes_its_channel_when_disposed(tmp_path, dispose):
    s = _slow_session(tmp_path, 0)
    assert s.state()["ok"]
    getattr(s, dispose)()
    assert s._result.closed


def test_one_shot_validation_past_its_deadline_is_a_timeout(tmp_path):
    worker = _fake_worker(tmp_path, '''
        import time
        read()
        time.sleep(60)
    ''')
    started = time.monotonic()
    with pytest.raises(spec.WorkerTimeout):
        spec.validate_once("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", "c",
                           timeout=0.5, worker=worker)
    assert time.monotonic() - started < 2.5


def test_a_preflight_past_its_deadline_is_unavailable(tmp_path):
    worker = _fake_worker(tmp_path, '''
        import time
        read()
        time.sleep(60)
    ''')
    result = tau_preflight.preflight_rule(
        "always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", "always ( o8[t]:bv[24] = { #x3 }:bv[24] ).",
        worker=worker, timeout=0.5)
    assert result.verdict == tau_preflight.UNAVAILABLE
    assert "no answer within" in result.detail


# --- one-shot vs persistent lifecycles (C1) -----------------------------------

def test_one_shot_requires_a_clean_exit_after_reporting(tmp_path):
    """A success message followed by a crash is not success."""
    worker = _fake_worker(tmp_path, '''
        n = 0
        while True:
            req = read()
            if req is None: break
            n += 1
            write({"ok": True, "outcome": "ACCEPTED_CHANGED", "candidate_id": req.get("candidate_id",""),
                   "request_id": req["request_id"], "state_revision": n, "capture_complete": True})
            if req.get("op") == "revise":
                os._exit(7)          # reports success, then dies
    ''')
    with pytest.raises(spec.SpeculationError) as exc:
        spec.validate_once("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", "c", worker=worker)
    assert "exited" in str(exc.value)


def test_a_persistent_session_is_not_required_to_exit_per_response(tmp_path):
    """The exit-zero rule belongs to one-shot workers only; a session that had to
    exit after each answer could not serve a second request at all."""
    s = _session(tmp_path, '''
        n = 0
        while True:
            req = read()
            if req is None: break
            n += 1
            if req.get("op") == "close":
                write({"ok": True, "request_id": req["request_id"], "state_revision": n})
                break
            write({"ok": True, "outcome": "ACCEPTED_CHANGED",
                   "candidate_id": req.get("candidate_id", ""), "capture_complete": True,
                   "request_id": req["request_id"], "state_revision": n})
    ''')
    first = s.revise("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", "a")
    second = s.revise("always ( o8[t]:bv[24] = { #x3 }:bv[24] ).", "b")
    assert first.accepted and second.accepted
    assert second["state_revision"] > first["state_revision"]
    assert s.close() == 0


def test_acceptance_needs_a_complete_diagnostic_capture(tmp_path):
    """An unreadable or truncated capture must not read as 'no error occurred'."""
    s = _session(tmp_path, '''
        while True:
            req = read()
            if req is None: break
            write({"ok": True, "outcome": "ACCEPTED_CHANGED",
                   "candidate_id": req.get("candidate_id", ""), "capture_complete": False,
                   "request_id": req["request_id"], "state_revision": 1})
    ''')
    receipt = s.revise("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).", "a")
    assert receipt.accepted           # the engine said yes
    assert not receipt.usable         # but we could not read the diagnostics
    s.kill()


# --- the real worker ----------------------------------------------------------

def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_two_consecutive_revisions_in_one_real_session(tmp_path):
    """C1's specific case: the contradiction a per-response exit rule would hide."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "genesis.tau")) as fh:
        router = fh.read().strip()
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    s = spec.SpeculationSession(cwd=repo_root, env=env)
    try:
        s.init(f"always ( {router} ).")
        first = s.revise("always ( o5[t]:bv[24] = { #x000007 }:bv[24] ).", "c1")
        second = s.revise("always ( o8[t]:bv[24] = { #x000003 }:bv[24] ).", "c2")
        assert first["outcome"] == spec.ACCEPTED_CHANGED, first
        assert second["outcome"] == spec.ACCEPTED_CHANGED, second
        assert second["spec_revision"] > first["spec_revision"]
        assert first.usable and second.usable
        # both rules are live in the same session
        out = s.step({})["outputs"]
        assert out.get("o5") == "7" and out.get("o8") == "3", out
        assert s.close() == 0
    except BaseException:
        s.kill()
        raise


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
@pytest.mark.parametrize("candidate,expected", [
    ("always ( o5[t]:bv[24] = o5[t]:bv[24] ).", spec.ACCEPTED_NOOP),
    ("always ( garbage nonsense (", "REJECTED_RULE"),
    ("always ( o5[t]:bv[24] = { #x000001 }:bv[24] && o5[t]:bv[24] = { #x000002 }:bv[24] ).",
     "REJECTED_NOT_ROUTED"),
])
def test_revision_outcomes_are_separated(tmp_path, candidate, expected):
    """A no-op, an unroutable (unsatisfiable) rule and a parse failure are three
    different answers -- not one 'nothing changed'."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "genesis.tau")) as fh:
        router = fh.read().strip()
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    s = spec.SpeculationSession(cwd=repo_root, env=env)
    try:
        s.init(f"always ( {router} ).")
        receipt = s.revise(candidate, "c")
        assert receipt["outcome"] == expected, receipt
    finally:
        s.kill()


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_a_refusal_reaches_the_receipt_through_the_subprocess(tmp_path):
    """Native output is fully buffered when stdout is not a tty, which it never is
    for a worker. Without an explicit flush before the captured fds are restored,
    the buffer drains to the original destination afterwards and every receipt
    reads back empty -- indistinguishable from "the engine said nothing", which is
    the one reading that must never be possible.
    """
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "genesis.tau")) as fh:
        router = fh.read().strip()
    baseline = (f"always ( {router} && "
                "( i12[t]:bv[8] = { 1 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] ) ).")
    clashing = ("always ( i12[t]:bv[384] = { #x" + "bb" * 48 + " }:bv[384] -> "
                "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    s = spec.SpeculationSession(cwd=repo_root, env=env)
    try:
        s.init(baseline)
        receipt = s.revise(clashing, "c")
        assert receipt["outcome"] == "REJECTED_RULE", receipt
        assert receipt["capture_complete"] is True
        assert "Incompatible type information in i12" in receipt["diagnostics"], receipt
    finally:
        s.kill()


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_an_unconsumed_candidate_is_incomplete_not_accepted(tmp_path):
    """"The engine never asked for i0" says nothing about the candidate, so it
    must not be reported as acceptance. Bounding the offers to zero reproduces
    that state deterministically."""
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "genesis.tau")) as fh:
        router = fh.read().strip()
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    s = spec.SpeculationSession(cwd=repo_root, env=env)
    try:
        s.init(f"always ( {router} ).")
        # a rule that makes the next prompt ask for i1 alone
        s.revise("always ( o5[t]:bv[24] = i1[t-1]:bv[24] ).", "hist")
        resp = s._request({"op": "revise", "candidate": "always ( o8[t]:bv[24] = { #x3 }:bv[24] ).",
                           "candidate_id": "c", "max_offers": 0})
        assert resp["outcome"] == "INCOMPLETE", resp
        assert resp["ok"] is False
    finally:
        s.kill()


@pytest.mark.skipif(not _native_available(), reason="native tau module not built")
def test_a_real_revision_past_its_deadline_is_a_timeout(tmp_path):
    """An o5 composite of this many authors compiles for several seconds, far
    past the one-second deadline."""
    from consensus.rule_offers import compose_stream_rule

    def bv24(n):
        return "{ #x" + format(n, "06x") + " }:bv[24]"

    def bv384(h):
        return "{ #x" + h + " }:bv[384]"

    def o5(v):
        return "(o5[t]:bv[24] = " + bv24(v) + ")"

    def key(prefix, i):
        return (prefix + f"{i:04x}") * 16

    def clause(a, s, p):
        return ("( ( (i1[t]:bv[24] > " + bv24(100000) + " && !(i20[t]:bv[384] = " + bv384(p) + "))"
                " || (i1[t]:bv[24] > " + bv24(10000) + " && !(i19[t]:bv[384] = " + bv384(s) + "))"
                " || (i1[t]:bv[24] > " + bv24(1000) + " && !(i18[t]:bv[384] = " + bv384(a) + ")) )"
                " ? " + o5(0) + " : " + o5(1) + " )")

    composite = compose_stream_rule(5, {
        key("ab", i): clause(key("ca", i), key("cb", i), key("cc", i))
        for i in range(20)
    })
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(repo_root, "genesis.tau")) as fh:
        router = fh.read().strip()
    env = dict(os.environ)
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    s = spec.SpeculationSession(cwd=repo_root, env=env)
    try:
        s.init(f"always ( {router} ).")
        started = time.monotonic()
        with pytest.raises(spec.WorkerTimeout):
            s.revise(composite, "slow", timeout=1.0)
        elapsed = time.monotonic() - started
        assert 0.9 <= elapsed < 6.0, elapsed
        assert s._proc.returncode is not None, "the slow worker was not reaped"
        _assert_lost_and_reaped(s)
    finally:
        s.kill()
