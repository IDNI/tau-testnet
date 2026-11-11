"""Policy clause evaluator: one build or one step of `always ( <body> ).`.

A clause body reads the current step only, so its verdict is a pure function of
(body, inputs). The evaluator owns a worker process holding a cache of built
interpreters and replaces it on loss, on a build failure that a fresh process
might not share, and when it has served enough builds, steps or memory.
"""
from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass

from blake3 import blake3

from tau_speculation import (
    _SESSION_DEFAULT,
    SpeculationError,
    SpeculationProtocolError,
    SpeculationSession,
    WorkerLost,
)

DEFAULT_CACHE_SIZE = 256
PIN_BUILD_SECONDS = 0.100
RECYCLE_BUILDS = 500
RECYCLE_STEPS = 20_000
RECYCLE_RSS_BYTES = 1 << 30
POOL_NAMES = ("apply", "admission")

# Without an injected probe, worker memory is read this often (in requests).
RSS_PROBE_EVERY = 64

_O5_VALUE = re.compile(
    r"^\{?\s*(?:#x([0-9a-fA-F]+)|#b([01]+)|(\d+))\s*\}?(?::bv\[\d+\])?$"
)


class PolicyBuildError(SpeculationError):
    """A clause failed to build even in a fresh worker."""

    def __init__(self, error: str):
        super().__init__(f"policy clause does not build: {error[:200]}")
        self.error = error


@dataclass(frozen=True)
class PolicyBuild:
    ok: bool
    error: str = ""
    built: bool = False
    build_seconds: float = 0.0
    pinned: bool = False


@dataclass(frozen=True)
class PolicyVerdict:
    blocked: bool
    o5: str | None
    built: bool


def clause_key(body: str) -> str:
    return blake3(body.encode("utf-8")).hexdigest()


def clause_spec(body: str) -> str:
    return f"always ( {body} )."


def parse_o5(value: str | None) -> int | None:
    if value is None:
        return None
    match = _O5_VALUE.match(str(value).strip())
    if not match:
        raise SpeculationProtocolError(f"unreadable o5 value {value!r}")
    hex_digits, bin_digits, dec_digits = match.groups()
    if hex_digits is not None:
        return int(hex_digits, 16)
    if bin_digits is not None:
        return int(bin_digits, 2)
    return int(dec_digits)


class _Worker(SpeculationSession):
    """A session plus what the host has seen it do."""

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.builds = 0
        self.steps = 0
        self.requests = 0

    @property
    def pid(self) -> int:
        return self._proc.pid

    def dispose(self) -> None:
        self.kill()
        try:
            self._proc.stdin.close()
        except (OSError, ValueError):
            pass

    def call(self, payload: dict, timeout) -> dict:
        self.requests += 1
        return self._request(payload, timeout=timeout)


class PolicyEvaluator:
    def __init__(self, *, pool="apply", cache_size=DEFAULT_CACHE_SIZE,
                 pin_build_seconds=PIN_BUILD_SECONDS, recycle_builds=RECYCLE_BUILDS,
                 recycle_steps=RECYCLE_STEPS, recycle_rss_bytes=RECYCLE_RSS_BYTES,
                 timeout=None, rss_probe=None, worker=None, python=None, cwd=None,
                 env=None):
        self.pool = pool
        self._cache_size = cache_size
        self._pin_build_seconds = pin_build_seconds
        self._recycle_builds = recycle_builds
        self._recycle_steps = recycle_steps
        self._recycle_rss_bytes = recycle_rss_bytes
        self._timeout = timeout
        self._rss_probe = rss_probe
        self._worker_path = worker or os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "tau_policy_worker.py"
        )
        self._python = python
        self._cwd = cwd
        self._env = env
        self._lock = threading.RLock()
        self._worker: _Worker | None = None
        self._closed = False
        self.spawns = 0
        self.recycles = 0
        self.retries = 0
        self.fresh_fallbacks = 0

    # --- public ---------------------------------------------------------------

    def validate(self, body: str, *, timeout=_SESSION_DEFAULT) -> PolicyBuild:
        resp = self._run(
            {"op": "build", "key": clause_key(body), "text": body}, timeout
        )
        if resp.get("ok"):
            return PolicyBuild(
                ok=True, built=bool(resp.get("built")),
                build_seconds=float(resp.get("build_seconds") or 0.0),
                pinned=bool(resp.get("pinned")),
            )
        if resp.get("phase") != "build":
            raise SpeculationError(_failure_text(resp))
        return PolicyBuild(ok=False, error=str(resp.get("error") or ""))

    def verdict(self, body: str, inputs: dict, *,
                timeout=_SESSION_DEFAULT) -> PolicyVerdict:
        resp = self._run(
            {"op": "step", "key": clause_key(body), "text": body,
             "inputs": dict(inputs or {})},
            timeout,
        )
        if not resp.get("ok"):
            if resp.get("phase") == "build":
                raise PolicyBuildError(str(resp.get("error") or ""))
            raise SpeculationError(f"policy step failed: {_failure_text(resp)}")
        o5 = resp.get("o5")
        value = parse_o5(o5)
        return PolicyVerdict(blocked=value == 0, o5=o5, built=bool(resp.get("built")))

    def stats(self) -> dict:
        with self._lock:
            out = {}
            if self._worker is not None:
                out = dict(self._worker.call({"op": "stats"}, self._timeout))
                for field in ("request_id", "state_revision", "session_healthy", "ok"):
                    out.pop(field, None)
            out.update(pool=self.pool, spawns=self.spawns, recycles=self.recycles,
                       retries=self.retries, fresh_fallbacks=self.fresh_fallbacks)
            return out

    def worker_pid(self) -> int | None:
        with self._lock:
            return self._worker.pid if self._worker is not None else None

    def close(self) -> None:
        with self._lock:
            self._closed = True
            worker, self._worker = self._worker, None
        if worker is not None:
            worker.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()
        return False

    # --- worker lifecycle -----------------------------------------------------

    def _spawn(self) -> _Worker:
        env = dict(self._env or os.environ)
        env["TAU_POLICY_CACHE_SIZE"] = str(self._cache_size)
        env["TAU_POLICY_PIN_SECONDS"] = str(self._pin_build_seconds)
        self.spawns += 1
        return _Worker(python=self._python, cwd=self._cwd, env=env,
                       timeout=self._timeout, worker=self._worker_path)

    def _replace(self) -> _Worker:
        old = self._worker
        self._worker = self._spawn()
        if old is not None:
            old.dispose()
        return self._worker

    def _current(self) -> _Worker:
        if self._closed:
            raise WorkerLost("policy evaluator is closed")
        if self._worker is None:
            self._worker = self._spawn()
        return self._worker

    def _needs_recycle(self, worker: _Worker) -> bool:
        if worker.builds >= self._recycle_builds or worker.steps >= self._recycle_steps:
            return True
        if self._rss_probe is not None:
            return self._rss_probe() >= self._recycle_rss_bytes
        if worker.requests and worker.requests % RSS_PROBE_EVERY == 0:
            try:
                rss = worker.call({"op": "stats"}, self._timeout).get("rss_bytes")
            except WorkerLost:
                return True
            return isinstance(rss, int) and rss >= self._recycle_rss_bytes
        return False

    # --- request path ---------------------------------------------------------

    def _exchange(self, payload: dict, timeout):
        """One request with a single respawn-and-retry on a lost worker. Returns
        the response and how many clauses the answering worker had built before."""
        worker = self._current()
        prior = worker.builds
        try:
            return worker.call(dict(payload), timeout), worker, prior
        except WorkerLost as first:
            self.retries += 1
            worker = self._replace()
            try:
                return worker.call(dict(payload), timeout), worker, 0
            except WorkerLost:
                worker.dispose()
                self._worker = None
                raise first from None

    @staticmethod
    def _tally(worker: _Worker, resp: dict) -> None:
        if resp.get("built"):
            worker.builds += 1
        if resp.get("phase") == "step" and resp.get("ok"):
            worker.steps += 1

    def _run(self, payload: dict, timeout) -> dict:
        with self._lock:
            worker = self._current()
            if self._needs_recycle(worker):
                self.recycles += 1
                self._replace()
            resp, worker, prior = self._exchange(payload, timeout)
            if not resp.get("ok") and resp.get("phase") == "build" and prior >= 1:
                self.fresh_fallbacks += 1
                self._replace()
                resp, worker, _ = self._exchange(payload, timeout)
            self._tally(worker, resp)
            return resp


def _failure_text(resp: dict) -> str:
    return str(resp.get("error") or resp.get("diagnostics") or resp.get("phase"))[:200]


_pools: dict = {}
_pools_lock = threading.Lock()


def get_policy_evaluator(pool: str) -> PolicyEvaluator:
    if pool not in POOL_NAMES:
        raise ValueError(f"unknown policy pool {pool!r}; expected one of {POOL_NAMES}")
    with _pools_lock:
        if pool not in _pools:
            _pools[pool] = PolicyEvaluator(pool=pool)
        return _pools[pool]


def close_policy_evaluators() -> None:
    with _pools_lock:
        evaluators = list(_pools.values())
        _pools.clear()
    for evaluator in evaluators:
        evaluator.close()
