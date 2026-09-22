"""Accepted A, dirty-rejected B, accepted C.

A transaction whose rule the engine accepted but whose TRANSACTION was rejected
must not change what the next transaction computes. Canonical rollback alone does
not achieve that: the hashed state is restored while the evaluator still holds
B's rule, and the evaluator is what computes C.

The engine commits a stream's width on the first accepted revision and offers no
rollback, so the only way to not have applied something is to have applied it
somewhere disposable.
"""
import os

import pytest

import tau_session as ts
import tau_speculation as spec


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# A: everyone is allowed. B (later rejected): everyone is blocked.
RULE_A = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
RULE_B = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _authoritative():
    s = spec.SpeculationSession(cwd=REPO, env=_env())
    s.init(_router())
    return s


def _verdict_for_c(session):
    """C's policy verdict: what o5 says on the next ordinary step."""
    return (session.step({"i1": "#x000001"}).get("outputs") or {}).get("o5")


def test_control_a_then_c():
    s = _authoritative()
    try:
        assert s.revise(RULE_A, "A")["outcome"] == "ACCEPTED_CHANGED"
        assert _verdict_for_c(s) == "1"
    finally:
        s.kill()


def test_a_rejected_rule_applied_in_place_changes_the_next_verdict():
    """The defect, pinned. B's transaction is rejected and its canonical effect
    rolled back, but C is still evaluated against B's rule."""
    s = _authoritative()
    try:
        s.revise(RULE_A, "A")
        s.revise(RULE_B, "B")          # accepted by the engine; tx rejected later
        contaminated = _verdict_for_c(s)
    finally:
        s.kill()
    assert contaminated == "0", (
        "expected C to see B's policy, which is the whole problem"
    )


def test_evaluating_the_rejected_rule_in_a_disposable_worker_leaves_c_clean():
    """The fix: B is evaluated somewhere disposable, so C computes as if B never
    happened -- matching the control exactly."""
    authoritative = _authoritative()
    try:
        authoritative.revise(RULE_A, "A")

        speculative = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env())
        try:
            speculative.apply_rule(RULE_A)
            outcome = speculative.apply_rule(RULE_B)
            assert outcome == "ok", "B must really have been evaluated"
        finally:
            speculative.dispose()          # disposal IS the rollback

        assert _verdict_for_c(authoritative) == "1"
    finally:
        authoritative.kill()


def test_the_speculative_session_declares_itself():
    """The apply path must be able to tell that a session commits nothing, so it
    does not demand evidence of persistence from one."""
    speculative = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env())
    try:
        assert speculative.is_speculative is True
        assert ts.InProcessSession(manager=__import__("tau_manager")).is_speculative is False
    finally:
        speculative.dispose()


def test_a_worker_session_answers_the_session_contract():
    """Outputs come back keyed by stream index, and inputs go in bare -- the
    `{ .. }:bv[N]` wrapper is in-spec literal syntax and does not parse as input."""
    speculative = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env())
    try:
        speculative.apply_rule("always ( o5[t]:bv[24] = i1[t]:bv[24] ).")
        multi = speculative.evaluate({1: "{ #x000007 }:bv[24]"}, multi=True)
        assert multi.get(5) == "7", multi
        single = speculative.evaluate({1: "#x000009"}, target=5)
        assert single == "9", single
    finally:
        speculative.dispose()


# --- the miner's own path -----------------------------------------------------

_CHILD_MINER = r'''
import os, sys, tempfile
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import config
config.set_database_path(os.environ["PROBE_DB"])
import db; db.init_db()
import tau_native, tau_manager
from commands.createblock import _speculative_proposal

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(open(os.path.join(os.environ["REPO_ROOT"], "genesis.tau")).read()); boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager.tau_ready.set()
tau_manager.communicate_with_tau(
    rule_text="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).",
    target_output_stream_index=0)

before = iface.interpreter.time_point
prop = _speculative_proposal()
sess = prop.session if prop is not None else None
kind = type(sess).__name__ if sess is not None else "None"
sess.apply_rule("always ( o5[t]:bv[24] = { #x000000 }:bv[24] ).")
sess.evaluate({1: "{ #x000007 }:bv[24]"}, multi=True)
prop.dispose()
after = iface.interpreter.time_point
o5 = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    input_stream_values={1: "#x000001"}, target_output_stream_index=5)))
print("MINER_RESULT", kind, before, after, o5)
sys.stdout.flush(); os._exit(0)
'''


def test_the_miner_simulation_runs_somewhere_disposable(tmp_path):
    """`createblock` used to simulate against the live interpreter and undo it
    with a restore that measurably does not undo it. The simulation now runs in a
    worker, so a rule it evaluates -- including one it goes on to reject -- leaves
    the authoritative evaluator exactly where it was."""
    import subprocess
    import sys as _sys

    script = tmp_path / "child_miner.py"
    script.write_text(_CHILD_MINER)
    env = dict(os.environ)
    env["PROBE_DB"] = str(tmp_path / "miner.db")
    env["REPO_ROOT"] = REPO
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([_sys.executable, str(script)], capture_output=True,
                          text=True, env=env, timeout=180)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("MINER_RESULT")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, kind, before, after, o5 = line.split()
    assert kind == "WorkerSession", f"the miner simulated in-process: {line}"
    assert before == after, f"the simulation advanced the authoritative evaluator: {line}"
    assert o5 == "1", f"the simulated blocking rule leaked into the live policy: {line}"


def test_the_worker_prepares_rules_in_its_own_representation():
    """Feeding canonical rule text to a worker whose inputs are runtime-encoded
    mixes representations: a granted sender's full-width literal never matches its
    interned input value, so the simulation rejects transfers the authoritative
    path accepts. Measured before the fix: o5 = 0 for a sender the rule grants."""
    import tau_manager
    import tau_shrink

    pk = "aa" * 48
    rule = (f"always ( i12[t]:bv[384] = {{ #x{pk} }}:bv[384] -> "
            f"o5[t]:bv[24] = {{ #x000001 }}:bv[24] ).")
    session = ts.WorkerSession.spawn(_router(), cwd=REPO, env=_env(),
                                     normalize=lambda i: tau_manager._normalize_inputs(
                                         i, frozenset({12})) or i)
    try:
        session.apply_rule(rule)
        out = session.evaluate({12: "{ #x" + pk + " }:bv[384]"}, multi=True)
        assert out.get(5) == "1", (
            f"granted sender was not allowed: {out} -- rule and input disagree "
            "on representation"
        )
        # and the journal keeps the CANONICAL text, with the runtime payload
        # only inside the identity
        entry = session.journal.entries()[0]
        assert "bv[384]" in entry.rule_text
        assert entry.identity is not None and entry.identity["runtime"] is not None
    finally:
        session.dispose()
