"""Policy evaluator host logic, driven against a fake worker (no native engine)."""
import os
import subprocess
import sys
import textwrap

import pytest

import tau_policy
import tau_policy_worker
from consensus.policy_mock import MockPolicyEvaluator
from tau_speculation import SpeculationError, WorkerLost, WorkerTimeout

FAKE = textwrap.dedent('''
    import json, os, struct, sys, time
    _HDR = struct.Struct("!I")
    FD = int(os.environ["TAU_WORKER_RESULT_FD"])
    MARKER = os.environ.get("FAKE_MARKER_DIR", "")

    def read():
        head = sys.stdin.buffer.read(_HDR.size)
        if not head or len(head) < _HDR.size:
            return None
        (n,) = _HDR.unpack(head)
        return json.loads(sys.stdin.buffer.read(n).decode())

    def write(payload):
        blob = json.dumps(payload).encode()
        os.write(FD, _HDR.pack(len(blob)) + blob)

    def first_time(name):
        path = os.path.join(MARKER, name)
        if os.path.exists(path):
            return False
        open(path, "w").close()
        return True

    built = {}
    steps = 0
    rev = 0
    while True:
        req = read()
        if req is None:
            break
        rev += 1
        op = req["op"]
        text = req.get("text", "")
        out = {"ok": True}
        if op in ("build", "step"):
            if "DIE_ONCE" in text and first_time("die"):
                os._exit(1)
            if "DIE" in text and "DIE_ONCE" not in text:
                os._exit(1)
            if "SLOW_ONCE" in text and first_time("slow"):
                time.sleep(30)
            if "SLOW" in text and "SLOW_ONCE" not in text:
                time.sleep(30)
            key = req["key"]
            hit = key in built
            failed = "FAIL_ALWAYS" in text or ("FAIL_WARM" in text and len(built) > 0)
            if not hit and failed:
                out = {"ok": False, "phase": "build", "error": "fake build failure",
                       "built": False, "pid": os.getpid()}
            else:
                built[key] = True
                out.update(phase="build", built=not hit, build_seconds=0.001,
                           pinned=False, pid=os.getpid())
                if op == "step":
                    if "STEPFAIL" in text:
                        out.update(ok=False, phase="step", error="fake step failure")
                    else:
                        steps += 1
                        out["phase"] = "step"
                        out["o5"] = ("#x000000" if "BLOCKHEX" in text else
                                     "0" if "BLOCK" in text else
                                     None if "ABSENT" in text else "1")
        elif op == "stats":
            out.update(builds=len(built), steps=steps, rss_bytes=0)
        elif op == "close":
            write({"ok": True, "request_id": req["request_id"], "closing": True})
            break
        out["request_id"] = req["request_id"]
        out["state_revision"] = rev
        out["session_healthy"] = True
        write(out)
''')


@pytest.fixture
def fake_worker(tmp_path):
    path = tmp_path / "fake_policy_worker.py"
    path.write_text(FAKE)
    return str(path)


@pytest.fixture
def make(fake_worker, tmp_path):
    made = []
    marker = tmp_path / "markers"
    marker.mkdir()

    def factory(**kwargs):
        env = dict(os.environ)
        env["FAKE_MARKER_DIR"] = str(marker)
        kwargs.setdefault("worker", fake_worker)
        kwargs.setdefault("env", env)
        evaluator = tau_policy.PolicyEvaluator(**kwargs)
        made.append(evaluator)
        return evaluator

    yield factory
    for evaluator in made:
        evaluator.close()


# --- worker cache ---------------------------------------------------------------

def test_cache_evicts_least_recently_used_first():
    cache = tau_policy_worker._InterpreterCache(3)
    for key in "abc":
        cache.put(key, object())
    cache.get("a")
    cache.put("d", object())
    assert cache.keys() == ["c", "a", "d"]
    assert cache.evictions == 1
    assert "b" not in cache


def test_cache_never_evicts_pinned_entries():
    cache = tau_policy_worker._InterpreterCache(2)
    cache.put("slow", object(), pinned=True)
    for key in "abcd":
        cache.put(key, object())
    assert "slow" in cache
    assert cache.pinned_count() == 1
    assert len(cache) == 2
    assert cache.evictions == 3


def test_cache_keeps_the_newest_entry_when_everything_else_is_pinned():
    cache = tau_policy_worker._InterpreterCache(1)
    cache.put("p", object(), pinned=True)
    cache.put("n", object())
    assert "n" in cache and "p" in cache
    assert len(cache) == 2


def test_importing_the_worker_does_not_load_the_native_module():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    code = "import sys, tau_policy_worker; sys.exit(1 if 'tau_native' in sys.modules else 0)"
    done = subprocess.run([sys.executable, "-c", code], cwd=repo, timeout=60)
    assert done.returncode == 0


# --- verdict mapping ------------------------------------------------------------

def test_verdict_blocked_allowed_and_absent(make):
    ev = make()
    blocked = ev.verdict("BLOCK", {})
    assert blocked.blocked and blocked.o5 == "0" and blocked.built
    assert ev.verdict("BLOCKHEX", {}).blocked
    allowed = ev.verdict("PASS", {})
    assert not allowed.blocked and allowed.o5 == "1"
    absent = ev.verdict("ABSENT", {})
    assert not absent.blocked and absent.o5 is None
    assert not ev.verdict("PASS", {}).built


def test_step_failure_is_not_a_build_error(make):
    ev = make()
    with pytest.raises(SpeculationError) as info:
        ev.verdict("STEPFAIL", {})
    assert not isinstance(info.value, tau_policy.PolicyBuildError)


def test_validate_reports_build_failure_without_raising(make):
    ev = make()
    ok = ev.validate("PASS")
    assert ok.ok and ok.built
    bad = ev.validate("FAIL_ALWAYS")
    assert not bad.ok and "fake build failure" in bad.error


def test_verdict_raises_policy_build_error(make):
    ev = make()
    with pytest.raises(tau_policy.PolicyBuildError) as info:
        ev.verdict("FAIL_ALWAYS", {})
    assert "fake build failure" in info.value.error
    assert isinstance(info.value, SpeculationError)


def test_o5_parsing():
    assert tau_policy.parse_o5("0") == 0
    assert tau_policy.parse_o5("#x000000") == 0
    assert tau_policy.parse_o5("{ #x000001 }:bv[24]") == 1
    assert tau_policy.parse_o5(None) is None
    with pytest.raises(SpeculationError):
        tau_policy.parse_o5("maybe")


def test_clause_helpers():
    assert tau_policy.clause_spec("x") == "always ( x )."
    key = tau_policy.clause_key("x")
    assert len(key) == 64 and key == tau_policy.clause_key("x")
    assert key != tau_policy.clause_key("y")


# --- recycling ------------------------------------------------------------------

def test_recycle_after_builds(make):
    ev = make(recycle_builds=2)
    pids = set()
    for i in range(5):
        ev.verdict(f"PASS{i}", {})
        pids.add(ev.worker_pid())
    assert ev.stats()["recycles"] >= 2
    assert len(pids) >= 3


def test_recycle_after_steps(make):
    ev = make(recycle_steps=3)
    ev.verdict("PASS", {})
    first = ev.worker_pid()
    for _ in range(3):
        ev.verdict("PASS", {})
    assert ev.worker_pid() != first
    assert ev.stats()["recycles"] == 1


def test_recycle_on_rss(make):
    readings = [10, 10, 5000]
    ev = make(recycle_rss_bytes=1000, rss_probe=lambda: readings.pop(0) if len(readings) > 1 else readings[0])
    ev.verdict("PASS", {})
    first = ev.worker_pid()
    ev.verdict("PASS", {})
    assert ev.worker_pid() == first
    ev.verdict("PASS", {})
    assert ev.worker_pid() != first
    assert ev.stats()["recycles"] == 1


def test_no_recycle_below_limits(make):
    ev = make(rss_probe=lambda: 1)
    for _ in range(4):
        ev.verdict("PASS", {})
    assert ev.stats()["recycles"] == 0
    assert ev.stats()["spawns"] == 1


# --- lost and timed-out workers -------------------------------------------------

def test_lost_worker_is_respawned_and_retried(make):
    ev = make()
    ev.verdict("PASS", {})
    first = ev.worker_pid()
    assert not ev.verdict("DIE_ONCE", {}).blocked
    assert ev.worker_pid() != first
    stats = ev.stats()
    assert stats["retries"] == 1 and stats["spawns"] == 2


def test_lost_twice_raises_worker_lost(make):
    ev = make()
    with pytest.raises(WorkerLost) as info:
        ev.verdict("DIE", {})
    assert not isinstance(info.value, WorkerTimeout)
    assert ev.stats()["retries"] == 1


def test_timeout_once_is_retried(make):
    ev = make(timeout=1.0)
    assert not ev.verdict("SLOW_ONCE", {}).blocked
    assert ev.stats()["retries"] == 1


def test_timeout_twice_stays_a_timeout(make):
    ev = make(timeout=0.5)
    with pytest.raises(WorkerTimeout):
        ev.verdict("SLOW", {})
    assert ev.stats()["retries"] == 1


def test_per_call_timeout_overrides_default(make):
    ev = make(timeout=None)
    with pytest.raises(WorkerTimeout):
        ev.verdict("SLOW", {}, timeout=0.5)


# --- fresh-worker fallback ------------------------------------------------------

def test_warm_build_failure_succeeds_in_a_fresh_worker(make):
    ev = make()
    ev.verdict("PASS", {})
    warm = ev.worker_pid()
    result = ev.verdict("FAIL_WARM BLOCK", {})
    assert result.blocked
    assert ev.worker_pid() != warm
    assert ev.stats()["fresh_fallbacks"] == 1


def test_warm_build_failure_that_fails_fresh_is_the_answer(make):
    ev = make()
    ev.verdict("PASS", {})
    with pytest.raises(tau_policy.PolicyBuildError):
        ev.verdict("FAIL_ALWAYS", {})
    stats = ev.stats()
    assert stats["fresh_fallbacks"] == 1 and stats["spawns"] == 2


def test_validate_falls_back_to_a_fresh_worker(make):
    ev = make()
    ev.validate("PASS")
    assert ev.validate("FAIL_WARM").ok
    assert ev.stats()["fresh_fallbacks"] == 1


def test_build_failure_in_a_fresh_worker_is_final(make):
    ev = make()
    bad = ev.validate("FAIL_ALWAYS")
    assert not bad.ok
    stats = ev.stats()
    assert stats["fresh_fallbacks"] == 0 and stats["spawns"] == 1


# --- pools ----------------------------------------------------------------------

def test_pools_never_share_a_worker(make):
    apply_pool = make(pool="apply")
    admission = make(pool="admission")
    apply_pool.verdict("PASS", {})
    admission.verdict("PASS", {})
    assert apply_pool.worker_pid() != admission.worker_pid()
    assert apply_pool.stats()["pool"] == "apply"
    assert admission.stats()["pool"] == "admission"


def test_pool_registry_is_a_singleton_per_name():
    try:
        a = tau_policy.get_policy_evaluator("apply")
        assert a is tau_policy.get_policy_evaluator("apply")
        b = tau_policy.get_policy_evaluator("admission")
        assert b is not a
        with pytest.raises(ValueError):
            tau_policy.get_policy_evaluator("other")
    finally:
        tau_policy.close_policy_evaluators()
    assert tau_policy.get_policy_evaluator("apply") is not a
    tau_policy.close_policy_evaluators()


# --- mock parity ----------------------------------------------------------------

def test_mock_has_the_same_public_surface():
    real = {n for n in dir(tau_policy.PolicyEvaluator) if not n.startswith("_")}
    mock = {n for n in dir(MockPolicyEvaluator) if not n.startswith("_")}
    assert {"validate", "verdict", "stats", "close"} <= real & mock


def test_mock_behaviour():
    mock = MockPolicyEvaluator()
    assert mock.validate("x").ok
    assert not mock.validate("").ok
    mock.fail_build("bad", "nope")
    assert mock.validate("bad").error == "nope"
    with pytest.raises(tau_policy.PolicyBuildError):
        mock.verdict("bad", {})
    assert not mock.verdict("x", {"i1": "1"}).blocked
    mock.set_verdict("x", "0")
    assert mock.verdict("x", {}).blocked
    mock.set_verdict("y", lambda inputs: "0" if inputs.get("i1") == "9" else "1")
    assert mock.verdict("y", {"i1": "9"}).blocked
    assert not mock.verdict("y", {"i1": "8"}).blocked
    assert mock.verdict_calls[1] == ("x", {"i1": "1"})
    assert set(mock.stats()) >= {"pool", "spawns", "recycles", "retries", "fresh_fallbacks"}
    mock.close()
    assert mock.closed
