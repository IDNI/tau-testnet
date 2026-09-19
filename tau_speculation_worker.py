"""Speculative Tau evaluator: one native interpreter, one process, one owner.

Why a process and not an object (W0, measured):

* Stepping a SECOND interpreter in the same process permanently wedges the first
  -- it starts failing with "Found clause containing non-equation" and then asks
  for no inputs at all. Multiple interpreter objects are not an isolation
  mechanism; serialization does not help.
* A stream's bitvector width is committed by the first ACCEPTED revision that
  mentions it and is never re-typed, and the commitment OUTLIVES the rule (it
  still applies after that rule is superseded and no longer appears in the spec).
  So a speculative attempt cannot be "undone" inside a process.
* Nothing in the binding exposes a checkpoint: `interpreter_t` offers only
  `time_point`, `spec_revision` and `current_spec()`. Reconstruction is replay.

Rejection is therefore disposal: kill the worker. Acceptance is a receipt, not a
returned value.

Protocol: length-prefixed JSON requests on stdin; length-prefixed JSON responses
on a DEDICATED result fd (default 3), never on stdout. Native chatter is captured
per request and reported with an explicit completeness flag -- a capture that
could not be read is an operational failure, never evidence that no error
occurred.
"""
from __future__ import annotations

import ctypes
import json
import os
import struct
import sys
import tempfile

RESULT_FD = 3
_HDR = struct.Struct("!I")

# Outcomes. Derived from measured engine behaviour on the genesis router, where
# o0 reports whether the revision branch was taken:
#   o0='F' + spec_revision advanced  -> the spec changed
#   o0='F' + spec_revision unchanged -> a genuine no-op (u normalises to T)
#   o0='T' while a candidate was sent -> not routed at all (e.g. unsatisfiable)
#   step returned None               -> refused outright, nothing advanced
ACCEPTED_CHANGED = "ACCEPTED_CHANGED"
ACCEPTED_NOOP = "ACCEPTED_NOOP"
REJECTED_NOT_ROUTED = "REJECTED_NOT_ROUTED"
REJECTED_RULE = "REJECTED_RULE"
INCOMPLETE = "INCOMPLETE"


def _read_frame(fh):
    head = fh.read(_HDR.size)
    if not head or len(head) < _HDR.size:
        return None
    (size,) = _HDR.unpack(head)
    body = fh.read(size)
    if body is None or len(body) < size:
        return None
    return json.loads(body.decode("utf-8"))


def _write_frame(fd: int, payload: dict) -> None:
    blob = json.dumps(payload).encode("utf-8")
    os.write(fd, _HDR.pack(len(blob)) + blob)


def _flush_native_streams() -> bool:
    """Flush the C/C++ stdio buffers before the captured fds are restored.

    Native output is fully buffered when stdout is not a tty, which it never is
    for a worker. Restoring the fds first means the buffer drains to the ORIGINAL
    destination afterwards and the capture reads back empty -- indistinguishable
    from "the engine said nothing", which is exactly the reading that must never
    be possible. `fflush(NULL)` flushes every open C stream; the C++ streams are
    sync'd with stdio by default.
    """
    try:
        ctypes.CDLL(None).fflush(None)
        return True
    except Exception:
        return False


class _Capture:
    """Capture fd 1 and 2 around a native call, reporting completeness.

    Temp files, not pipes: a pipe's buffer deadlocks the engine on a large spec
    dump. `complete` is False when the capture could not be read back or could not
    be flushed -- the caller must treat that as operational, not as "no
    diagnostic".
    """

    def __init__(self):
        self.text = ""
        self.complete = False

    def __enter__(self):
        self._saved = (os.dup(1), os.dup(2))
        self._tmp = (tempfile.TemporaryFile(), tempfile.TemporaryFile())
        os.dup2(self._tmp[0].fileno(), 1)
        os.dup2(self._tmp[1].fileno(), 2)
        return self

    def __exit__(self, *exc):
        flushed = _flush_native_streams()
        os.dup2(self._saved[0], 1)
        os.dup2(self._saved[1], 2)
        os.close(self._saved[0])
        os.close(self._saved[1])
        try:
            chunks = []
            for tf in self._tmp:
                tf.seek(0)
                chunks.append(tf.read().decode("utf-8", "replace"))
                tf.close()
            self.text = "".join(chunks)
            self.complete = flushed
        except Exception:
            self.text = ""
            self.complete = False
        return False


class _Session:
    def __init__(self, tau_module, binding_id: str):
        self.tau = tau_module
        self.binding_id = binding_id
        self.itp = None
        self.state_revision = 0          # advances whenever execution advances
        self.healthy = True

    def _bump(self):
        self.state_revision += 1

    def observe(self):
        if self.itp is None:
            return {"time_point": None, "spec_revision": None}
        return {"time_point": self.itp.time_point,
                "spec_revision": self.itp.spec_revision}

    def init(self, spec_text: str) -> dict:
        with _Capture() as cap:
            self.itp = self.tau.get_interpreter(spec_text)
        self._bump()
        if self.itp is None:
            self.healthy = False
            return {"ok": False, "phase": "interpreter_construction",
                    "diagnostics": cap.text, "capture_complete": cap.complete}
        return {"ok": True, "phase": "interpreter_construction",
                "diagnostics": cap.text, "capture_complete": cap.complete,
                **self.observe()}

    def _one_step(self, assignments: dict):
        """One prompt+step, both boundaries captured together."""
        with _Capture() as cap:
            asked = self.tau.get_inputs_for_step(self.itp)
            vals = {}
            for slot in asked or []:
                vals[slot] = assignments.get(slot.name, "F" if slot.name == "i0" else "0")
            outs = self.tau.step(self.itp, vals) if asked is not None else None
        self._bump()
        named = {k.name: str(v) for k, v in (outs or {}).items()} if outs else None
        return named, [s.name for s in (asked or [])], cap

    def revise(self, candidate: str, candidate_id: str, max_offers: int = 16) -> dict:
        """Offer a candidate until the engine actually asks for i0.

        Inputs are requested lazily and i0 is NOT requested on every step: after a
        rule that introduces an input dependency, the next prompt asks for that
        input alone. Treating the first step as the only chance to deliver reports
        INCOMPLETE for a candidate the engine would have taken one step later.
        The live wrapper loops for the same reason.

        Filler steps advance logical time, so they are reported: a step log that
        omits them cannot be replayed faithfully.
        """
        before = self.itp.spec_revision
        filler = []
        for _ in range(max_offers):
            with _Capture() as peek:
                asked = self.tau.get_inputs_for_step(self.itp)
            names = [s.name for s in (asked or [])]
            if "i0" in names:
                break
            # Not offered i0 yet: advance with fallbacks and try again.
            named, step_asked, cap = self._one_step({})
            filler.append({"asked": step_asked, "outputs": named})
            if named is None:
                return {
                    "ok": False, "outcome": INCOMPLETE, "candidate_id": candidate_id,
                    "consumed": False, "asked": step_asked, "outputs": None,
                    "filler_steps": filler, "diagnostics": cap.text,
                    "deferred_diagnostics": "", "capture_complete": cap.complete,
                    "binding_id": self.binding_id, **self.observe(),
                }

        named, asked, cap = self._one_step({"i0": candidate})
        delivered = "i0" in asked
        if not delivered:
            outcome = INCOMPLETE
        elif named is None:
            outcome = REJECTED_RULE
        elif named.get("o0") != "F":
            outcome = REJECTED_NOT_ROUTED
        elif self.itp.spec_revision > before:
            outcome = ACCEPTED_CHANGED
        else:
            outcome = ACCEPTED_NOOP
        # A drain: deferred diagnostics surface at the NEXT prompt, so ask for it
        # and keep the attribution on this revision.
        with _Capture() as drain:
            try:
                self.tau.get_inputs_for_step(self.itp)
            except Exception:
                pass
        return {
            "ok": outcome in (ACCEPTED_CHANGED, ACCEPTED_NOOP),
            "outcome": outcome,
            "candidate_id": candidate_id,
            "consumed": delivered and named is not None and named.get("o0") == "F",
            "asked": asked,
            "outputs": named,
            "filler_steps": filler,
            "diagnostics": cap.text,
            "deferred_diagnostics": drain.text,
            "capture_complete": bool(cap.complete and drain.complete),
            "binding_id": self.binding_id,
            **self.observe(),
        }

    def step(self, assignments: dict) -> dict:
        named, asked, cap = self._one_step(assignments or {})
        return {"ok": named is not None, "outputs": named, "asked": asked,
                "diagnostics": cap.text, "capture_complete": cap.complete,
                **self.observe()}


def main(argv=None) -> int:
    fd = int(os.environ.get("TAU_WORKER_RESULT_FD", RESULT_FD))
    try:
        import tau_native
        tau_module = tau_native.load_tau_module()
        binding_id = getattr(tau_module, "__file__", "unknown")
    except Exception as exc:
        _write_frame(fd, {"ok": False, "phase": "startup", "unavailable": True,
                          "error": f"native tau unavailable: {exc}"})
        return 0

    session = _Session(tau_module, binding_id)
    stdin = sys.stdin.buffer
    while True:
        req = _read_frame(stdin)
        if req is None:
            return 0
        op = req.get("op")
        rid = req.get("request_id")
        try:
            if op == "init":
                body = session.init(req.get("spec", ""))
            elif op == "revise":
                if not session.healthy or session.itp is None:
                    body = {"ok": False, "phase": "session", "error": "session unusable"}
                else:
                    body = session.revise(req.get("candidate", ""), req.get("candidate_id", ""))
            elif op == "step":
                if not session.healthy or session.itp is None:
                    body = {"ok": False, "phase": "session", "error": "session unusable"}
                else:
                    body = session.step(req.get("inputs") or {})
            elif op == "state":
                body = {"ok": True, **session.observe()}
            elif op == "close":
                _write_frame(fd, {"ok": True, "request_id": rid, "closing": True})
                return 0
            else:
                body = {"ok": False, "phase": "protocol", "error": f"unknown op {op!r}"}
        except Exception as exc:  # never let the loop die silently
            session.healthy = False
            body = {"ok": False, "phase": "worker", "error": repr(exc)}
        body["request_id"] = rid
        body["state_revision"] = session.state_revision
        body["session_healthy"] = session.healthy
        _write_frame(fd, body)


if __name__ == "__main__":
    sys.exit(main())
