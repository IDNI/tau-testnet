"""Policy clause worker: many stateless interpreters in one single-threaded process.

Each interpreter is built from `always ( <body> ).` and keyed by the host's hash
of the body. A clause body reads the current step only, so a verdict is a pure
function of (body, inputs) and a cache entry can be dropped or rebuilt at will.

Protocol and framing are those of tau_speculation_worker: length-prefixed JSON on
stdin, responses on the dedicated result fd. The native module is loaded only
when the loop starts, so the cache can be imported and tested without it.
"""
from __future__ import annotations

import os
import re
import resource
import sys
import time
from collections import OrderedDict

from tau_evaluator_state import INPUT, OUTPUT, ProcessTypeCommitments, qualified
from tau_speculation_worker import (
    RESULT_FD,
    _Capture,
    _diag,
    _read_frame,
    _report_summary,
    _unwrap,
    _write_frame,
)

DEFAULT_CAPACITY = 256
DEFAULT_PIN_SECONDS = 0.100
_ERROR_LIMIT = 2000

_STREAM_WIDTH = re.compile(r"\b([io])(\d+)\[[^\]]*\]\s*:\s*bv\[(\d+)\]")


class _InterpreterCache:
    """Recency-ordered cache. Pinned entries are never evicted, so the cache may
    exceed its capacity when every older entry is pinned."""

    def __init__(self, capacity: int):
        self.capacity = max(int(capacity), 1)
        self.evictions = 0
        self._items: OrderedDict = OrderedDict()
        self._pinned: set = set()

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, key) -> bool:
        return key in self._items

    def keys(self) -> list:
        """Least recently used first."""
        return list(self._items)

    def pinned_count(self) -> int:
        return len(self._pinned)

    def is_pinned(self, key) -> bool:
        return key in self._pinned

    def get(self, key):
        if key not in self._items:
            return None
        self._items.move_to_end(key)
        return self._items[key]

    def put(self, key, value, *, pinned: bool = False) -> None:
        self._items[key] = value
        self._items.move_to_end(key)
        if pinned:
            self._pinned.add(key)
        self._evict(keep=key)

    def _evict(self, keep) -> None:
        for key in list(self._items):
            if len(self._items) <= self.capacity:
                return
            if key == keep or key in self._pinned:
                continue
            del self._items[key]
            self.evictions += 1


def _rss_bytes() -> int:
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    # Peak, not current: the only figure available without psutil.
    return int(peak if sys.platform == "darwin" else peak * 1024)


def _spec(text: str) -> str:
    return f"always ( {text} )."


class _PolicyWorker:
    def __init__(self, tau_module, capacity: int, pin_seconds: float):
        self.tau = tau_module
        self.cache = _InterpreterCache(capacity)
        self.pin_seconds = pin_seconds
        self.commitments = ProcessTypeCommitments()
        self.state_revision = 0
        self.healthy = True
        self.builds = 0
        self.build_failures = 0
        self.steps = 0

    def _record_widths(self, text: str) -> None:
        for io, index, width in _STREAM_WIDTH.findall(text):
            side = INPUT if io == "i" else OUTPUT
            try:
                self.commitments.commit(qualified(side, int(index)), int(width))
            except ValueError:
                pass

    def _build(self, key: str, text: str):
        """Returns (itp, info). `itp` is None when the clause does not build."""
        hit = self.cache.get(key)
        if hit is not None:
            return hit, {"built": False, "build_seconds": 0.0,
                         "pinned": self.cache.is_pinned(key), "diagnostics": "",
                         "report": None, "capture_complete": True}
        started = time.monotonic()
        with _Capture() as cap:
            res = self.tau.get_interpreter(_spec(text))
        elapsed = time.monotonic() - started
        itp, report = _unwrap(res)
        info = {"built": itp is not None, "build_seconds": elapsed, "pinned": False,
                "diagnostics": _diag(cap.text, res.report),
                "report": _report_summary(report), "capture_complete": cap.complete}
        if itp is None:
            self.build_failures += 1
            info["error"] = info["diagnostics"][:_ERROR_LIMIT]
            return None, info
        self.builds += 1
        self._record_widths(text)
        pinned = elapsed > self.pin_seconds
        info["pinned"] = pinned
        self.cache.put(key, itp, pinned=pinned)
        return itp, info

    def build(self, key: str, text: str) -> dict:
        self.state_revision += 1
        itp, info = self._build(key, text)
        if itp is None:
            return {"ok": False, "phase": "build", **info}
        return {"ok": True, "phase": "build", **info}

    def step(self, key: str, text: str, inputs: dict) -> dict:
        self.state_revision += 1
        itp, info = self._build(key, text)
        if itp is None:
            return {"ok": False, "phase": "build", "o5": None, "asked": [], **info}
        reports = []
        outs = None
        asked = None
        with _Capture() as cap:
            asked, prep = _unwrap(self.tau.get_inputs_for_step(itp))
            reports.append(prep)
            if asked is not None:
                vals = {slot: str(inputs.get(slot.name, "0")) for slot in asked}
                outs, srep = _unwrap(self.tau.step(itp, vals))
                reports.append(srep)
        self.steps += 1
        names = [s.name for s in (asked or [])]
        info["diagnostics"] = _diag(cap.text, *reports)
        info["report"] = _report_summary(*reports)
        info["capture_complete"] = bool(info["capture_complete"] and cap.complete)
        if outs is None:
            return {"ok": False, "phase": "step", "o5": None, "asked": names,
                    "error": info["diagnostics"][:_ERROR_LIMIT], **info}
        named = {k.name: str(v) for k, v in outs.items()}
        return {"ok": True, "phase": "step", "o5": named.get("o5"), "asked": names,
                **info}

    def stats(self) -> dict:
        self.state_revision += 1
        return {
            "ok": True, "builds": self.builds, "build_failures": self.build_failures,
            "steps": self.steps, "live": len(self.cache),
            "pinned": self.cache.pinned_count(), "evictions": self.cache.evictions,
            "rss_bytes": _rss_bytes(),
            "widths": {f"{io}{idx}": w
                       for (io, idx), w in self.commitments.committed().items()},
        }


def main(argv=None) -> int:
    fd = int(os.environ.get("TAU_WORKER_RESULT_FD", RESULT_FD))
    try:
        import tau_native
        tau_module = tau_native.load_tau_module()
    except Exception as exc:
        _write_frame(fd, {"ok": False, "phase": "startup", "unavailable": True,
                          "error": f"native tau unavailable: {exc}"})
        return 0

    worker = _PolicyWorker(
        tau_module,
        int(os.environ.get("TAU_POLICY_CACHE_SIZE", DEFAULT_CAPACITY)),
        float(os.environ.get("TAU_POLICY_PIN_SECONDS", DEFAULT_PIN_SECONDS)),
    )
    stdin = sys.stdin.buffer
    while True:
        req = _read_frame(stdin)
        if req is None:
            return 0
        op = req.get("op")
        rid = req.get("request_id")
        try:
            if op == "build":
                body = worker.build(req.get("key", ""), req.get("text", ""))
            elif op == "step":
                body = worker.step(req.get("key", ""), req.get("text", ""),
                                   req.get("inputs") or {})
            elif op == "stats":
                body = worker.stats()
            elif op == "close":
                _write_frame(fd, {"ok": True, "request_id": rid, "closing": True})
                return 0
            else:
                body = {"ok": False, "phase": "protocol", "error": f"unknown op {op!r}"}
        except Exception as exc:  # never let the loop die silently
            worker.healthy = False
            body = {"ok": False, "phase": "worker", "error": repr(exc)}
        body["request_id"] = rid
        body["state_revision"] = worker.state_revision
        body["session_healthy"] = worker.healthy
        _write_frame(fd, body)


if __name__ == "__main__":
    sys.exit(main())
