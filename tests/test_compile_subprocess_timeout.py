"""
Regression tests for `tau_native.compile_revisions_isolated_subprocess`.

Background: a `user_tx` carrying an `always(...)` rule (operations["0"]) used to
run the isolated rule compile *in-process*. Native Tau could hang there with no
status stamp for the server watchdog to catch, freezing the whole server
(observed 2026-06-08, block #240). The compile now runs in a throwaway
subprocess with a hard timeout; an overrun is SIGKILLed and the transaction is
rejected instead of hanging.

These tests exercise the wrapper's branches without depending on a native
tau-lang build (except one end-to-end plumbing check that is timeout-bounded
either way).
"""

import os
import time

import pytest

import tau_native

STUB_MODULE = "_compile_stub_worker"
SENTINEL = "__TAU_COMPILE_RESULT__"


@pytest.fixture
def stub_worker(monkeypatch):
    """
    Write a stub compile worker into the repo root (the subprocess cwd, so it is
    importable via `python -m`) and point the wrapper at it. Behaviour is chosen
    at run time via the WF_STUB_MODE env var, which the child inherits.
    """
    repo_root = os.path.dirname(os.path.abspath(tau_native.__file__))
    stub_path = os.path.join(repo_root, STUB_MODULE + ".py")

    stub_src = (
        "import os, sys, time, json\n"
        "S = '" + SENTINEL + "'\n"
        "mode = os.environ.get('WF_STUB_MODE', 'ok')\n"
        "if mode == 'sleep':\n"
        "    time.sleep(60)\n"
        "elif mode == 'nosentinel':\n"
        "    sys.stderr.write('boom\\n'); sys.exit(1)\n"
        "elif mode == 'ok':\n"
        "    print(S + json.dumps({'ok': True, 'error': None}))\n"
        "elif mode == 'bad':\n"
        "    print(S + json.dumps({'ok': False, 'error': 'rule is garbage'}))\n"
        "elif mode == 'unavail':\n"
        "    print(S + json.dumps({'ok': False, 'unavailable': True, 'error': 'no native'}))\n"
    )
    with open(stub_path, "w") as f:
        f.write(stub_src)

    monkeypatch.setattr(tau_native, "_COMPILE_WORKER_MODULE", STUB_MODULE)
    try:
        yield
    finally:
        try:
            os.remove(stub_path)
        except OSError:
            pass


def test_success_returns_none(stub_worker, monkeypatch):
    monkeypatch.setenv("WF_STUB_MODE", "ok")
    assert tau_native.compile_revisions_isolated_subprocess("spec", ["r"], timeout=10) is None


def test_bad_rule_returns_error_string(stub_worker, monkeypatch):
    monkeypatch.setenv("WF_STUB_MODE", "bad")
    err = tau_native.compile_revisions_isolated_subprocess("spec", ["r"], timeout=10)
    assert err == "rule is garbage"


def test_native_unavailable_raises_for_fallback(stub_worker, monkeypatch):
    monkeypatch.setenv("WF_STUB_MODE", "unavail")
    # unavailable must NOT reject the tx: it raises so the caller degrades to
    # the live validation path instead of returning a rejection string.
    with pytest.raises(tau_native.NativeTauUnavailable):
        tau_native.compile_revisions_isolated_subprocess("spec", ["r"], timeout=10)


def test_no_sentinel_is_rejected(stub_worker, monkeypatch):
    monkeypatch.setenv("WF_STUB_MODE", "nosentinel")
    err = tau_native.compile_revisions_isolated_subprocess("spec", ["r"], timeout=10)
    assert err is not None
    assert "no result" in err


def test_timeout_is_killed_and_rejected(stub_worker, monkeypatch):
    """A hung compile is SIGKILLed at the timeout and rejected — the bug that froze the server."""
    monkeypatch.setenv("WF_STUB_MODE", "sleep")
    start = time.time()
    err = tau_native.compile_revisions_isolated_subprocess("spec", ["r"], timeout=2)
    elapsed = time.time() - start
    assert err is not None
    assert "timed out" in err
    # killed near the deadline, not after the full 60s sleep
    assert elapsed < 15, f"wrapper did not kill promptly (elapsed={elapsed:.1f}s)"


def test_real_worker_plumbing_empty_rules(monkeypatch):
    """
    End-to-end against the real tau_compile_worker. Empty consensus rules return
    None when native tau is present (no baseline -> early return); when native
    is absent the worker raises NativeTauUnavailable. Either outcome exercises
    the real subprocess + sentinel parsing path without requiring a build.
    """
    monkeypatch.delenv("WF_STUB_MODE", raising=False)
    try:
        result = tau_native.compile_revisions_isolated_subprocess(
            "", ["always o5[t]:bv[16] = 0."], timeout=30
        )
    except tau_native.NativeTauUnavailable:
        return  # no native build in this environment; plumbing still exercised
    assert result is None
