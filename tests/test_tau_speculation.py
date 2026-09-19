"""M1/C1: the speculative evaluator's two lifecycles and its result protocol.

Why a separate process at all is a measured fact, not a preference: stepping a
second interpreter in one process permanently wedges the first, a stream's width
is committed by the first ACCEPTED revision and outlives the rule that introduced
it, and the binding exposes no checkpoint. Rejection is disposal.

The protocol tests drive a FAKE worker, so they run without the native engine and
can produce responses a real worker never would.
"""
import json
import os
import struct
import subprocess
import sys
import textwrap

import pytest

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


def _session(tmp_path, body):
    return spec.SpeculationSession(worker=_fake_worker(tmp_path, body))


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


def test_a_truncated_frame_is_rejected(tmp_path):
    s = _session(tmp_path, '''
        req = read()
        blob = json.dumps({"ok": True, "request_id": req["request_id"], "state_revision": 1}).encode()
        os.write(FD, _HDR.pack(len(blob) + 50) + blob)   # claims more than it sends
    ''')
    with pytest.raises(spec.SpeculationProtocolError):
        s.state()
    s.kill()


def test_a_dead_worker_is_an_operational_failure(tmp_path):
    s = _session(tmp_path, '''
        sys.exit(3)
    ''')
    with pytest.raises(spec.SpeculationProtocolError):
        s.state()
    s.kill()


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
