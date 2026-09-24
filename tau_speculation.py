"""Client for the speculative Tau evaluator (see tau_speculation_worker.py).

Two lifecycles, deliberately distinct (C1):

* **one-shot validation** -- a worker that answers once and must then EXIT 0. A
  success message followed by a crash is not success.
* **persistent session** -- a worker that stays alive to serve later requests. Its
  success condition is a valid per-request receipt with matching identities and an
  operational session; requiring process exit per response would make a session
  impossible.

Responses are read from a dedicated fd, so native chatter on stdout can never be
parsed as an authoritative result. Every response must carry back the request id
and a state revision that has not gone backwards.
"""
from __future__ import annotations

import json
import os
import struct
import subprocess
import sys
import threading

_HDR = struct.Struct("!I")

ACCEPTED_CHANGED = "ACCEPTED_CHANGED"
ACCEPTED_NOOP = "ACCEPTED_NOOP"
ACCEPTED = (ACCEPTED_CHANGED, ACCEPTED_NOOP)


class SpeculationError(RuntimeError):
    """The session could not answer. Operational: never a verdict about a rule."""


class SpeculationProtocolError(SpeculationError):
    """A malformed, mismatched or stale response. Fails closed."""


class RevisionReceipt(dict):
    """Positive evidence about ONE revision request."""

    @property
    def accepted(self) -> bool:
        return self.get("outcome") in ACCEPTED

    @property
    def changed(self) -> bool:
        return self.get("outcome") == ACCEPTED_CHANGED

    @property
    def usable(self) -> bool:
        """Acceptance is only meaningful when the diagnostics were fully read."""
        return self.accepted and bool(self.get("capture_complete"))


class SpeculationSession:
    """A persistent worker owning exactly one native execution history."""

    def __init__(self, *, python=None, cwd=None, env=None, timeout=120.0,
                 stderr=None, worker=None):
        self._timeout = timeout
        self._next_id = 0
        self._last_state_revision = -1
        self._closed = False
        self._lock = threading.Lock()
        read_fd, write_fd = os.pipe()
        child_env = dict(env or os.environ)
        # `pass_fds` does NOT renumber: the child sees the fd at its original
        # number, so tell it which one rather than assuming 3.
        child_env["TAU_WORKER_RESULT_FD"] = str(write_fd)
        worker = worker or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "tau_speculation_worker.py"
        )
        self._proc = subprocess.Popen(
            [python or sys.executable, worker],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,   # diagnostics only; never a result channel
            stderr=(subprocess.DEVNULL if stderr is None else stderr),
            pass_fds=(write_fd,),
            cwd=cwd,
            env=child_env,
        )
        os.close(write_fd)
        self._result = os.fdopen(read_fd, "rb")

    # --- framing --------------------------------------------------------------

    def _send(self, payload: dict) -> None:
        blob = json.dumps(payload).encode("utf-8")
        assert self._proc.stdin is not None
        self._proc.stdin.write(_HDR.pack(len(blob)) + blob)
        self._proc.stdin.flush()

    def _recv(self) -> dict:
        head = self._result.read(_HDR.size)
        if not head or len(head) < _HDR.size:
            raise SpeculationProtocolError("worker closed the result channel")
        (size,) = _HDR.unpack(head)
        body = self._result.read(size)
        if body is None or len(body) < size:
            raise SpeculationProtocolError("truncated result frame")
        return json.loads(body.decode("utf-8"))

    def _request(self, payload: dict) -> dict:
        with self._lock:
            if self._closed:
                raise SpeculationError("session is closed")
            self._next_id += 1
            rid = self._next_id
            payload["request_id"] = rid
            self._send(payload)
            resp = self._recv()
        if resp.get("request_id") != rid:
            raise SpeculationProtocolError(
                f"response is for request {resp.get('request_id')!r}, expected {rid}"
            )
        state = resp.get("state_revision")
        if not isinstance(state, int) or state < self._last_state_revision:
            raise SpeculationProtocolError(
                f"state revision went backwards: {state} < {self._last_state_revision}"
            )
        self._last_state_revision = state
        if resp.get("unavailable"):
            raise SpeculationError(resp.get("error", "native tau unavailable"))
        return resp

    # --- operations -----------------------------------------------------------

    def init(self, spec_text: str) -> dict:
        resp = self._request({"op": "init", "spec": spec_text})
        if not resp.get("ok"):
            raise SpeculationError(
                f"interpreter construction failed: {resp.get('diagnostics', '')[:200]}"
            )
        return resp

    def revise(self, candidate: str, candidate_id: str = "") -> RevisionReceipt:
        resp = self._request(
            {"op": "revise", "candidate": candidate, "candidate_id": candidate_id}
        )
        if resp.get("candidate_id") != candidate_id:
            raise SpeculationProtocolError("receipt names a different candidate")
        if not resp.get("session_healthy", True):
            raise SpeculationError("session became unusable during the revision")
        return RevisionReceipt(resp)

    def step(self, inputs: dict) -> dict:
        return self._request({"op": "step", "inputs": inputs or {}})

    def state(self) -> dict:
        return self._request({"op": "state"})

    # --- disposal -------------------------------------------------------------

    def close(self, *, timeout: float = 5.0) -> int | None:
        """Close cleanly. A persistent session exits only here."""
        if self._closed:
            return self._proc.returncode
        self._closed = True
        try:
            self._send({"op": "close", "request_id": -1})
            self._proc.stdin.close()
        except Exception:
            pass
        try:
            return self._proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return self.kill()
        finally:
            try:
                self._result.close()
            except Exception:
                pass

    def kill(self) -> int | None:
        """Disposal for a rejected speculative attempt: there is no rollback, so
        the process IS the unit of rollback."""
        self._closed = True
        try:
            self._proc.kill()
        except Exception:
            pass
        try:
            return self._proc.wait(timeout=5.0)
        except Exception:
            return None
        finally:
            try:
                self._result.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        # An attempt that raised is disposed of, not reused.
        self.kill() if exc_type else self.close()
        return False


def validate_once(spec_text: str, candidate: str, *, cwd=None, env=None,
                  timeout: float = 120.0, worker=None) -> RevisionReceipt:
    """One-shot validation: build, revise, and require a CLEAN PROCESS EXIT.

    This is the lifecycle where exit status is part of the success condition.
    """
    session = SpeculationSession(cwd=cwd, env=env, timeout=timeout, worker=worker)
    try:
        session.init(spec_text)
        receipt = session.revise(candidate, candidate_id="one-shot")
    except BaseException:
        session.kill()
        raise
    code = session.close()
    if code != 0:
        raise SpeculationError(
            f"validation worker exited {code!r} after reporting a result"
        )
    return receipt
