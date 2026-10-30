"""Real engine: a bare `i4` clause on a node that shrinks `i4` (builtin rule 02).

Each case runs in a fresh process: the engine types a stream once per process.
"""
import os
import subprocess
import sys

import pytest


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_CHILD = r'''
import os, sys
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = os.environ["PROBE_SHRINK"]
import config
config.set_database_path(os.environ["PROBE_DB"])
import db; db.init_db()
import tau_native, tau_manager, tau_shrink, chain_state
import commands.sendtx as sendtx

KEY = "a1" * 48
OTHER = "cd" * 48
BARE = (
    "always ((!(i4[t] = {#x" + KEY + "}:bv[384]))"
    " ? o5[t]:bv[24] = { #x000000 }:bv[24]"
    " : o5[t]:bv[24] = { #x000001 }:bv[24])."
)
CLAUSES = {"bare": BARE,
           "paren": BARE.replace("{#x" + KEY + "}:bv[384]", "({#x" + KEY + "}:bv[384])")}

iface = tau_native.TauInterface(os.path.join(os.environ["REPO_ROOT"], "genesis.tau"))
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager.tau_ready.set()
if config.TAU_SHRINK_ENABLED:
    tau_shrink.set_shrink_width_from_db()


def apply(label, text):
    try:
        out = tau_manager.communicate_with_tau(
            rule_text=text, target_output_stream_index=0, apply_rules_update=False)
        receipt = tau_manager._last_revision_receipt or {}
        print(f"APPLY {label}: o0={out!r} outcome={receipt.get('outcome')}")
        return True
    except Exception as exc:
        print(f"APPLY {label}: {type(exc).__name__}: {str(exc).splitlines()[0][:200]}")
        return False


def addr(hex_digits):
    # With shrink off, the engine takes the bare value, not the wrapped form.
    if not config.TAU_SHRINK_ENABLED:
        return "#x" + hex_digits
    return "{ #x" + hex_digits + " }:bv[384]"


for n, rule in enumerate(chain_state.load_builtin_rules_from_disk(), start=1):
    apply(f"builtin_{n}", chain_state._preprocess_tau_spec_text(rule))

which = os.environ["PROBE_CLAUSE"]
clause = CLAUSES[which]
sendtx._test_mode_was_requested = lambda: False  # TAU_ENV=test skips preflight
err = sendtx._preflight_prepared_rule(clause)
print(f"PREFLIGHT {which}: {'ADMIT' if err is None else err}")
if apply(which, clause):
    for label, to in (("to=KEY", KEY), ("to=OTHER", OTHER)):
        o5 = tau_manager.communicate_with_tau(
            target_output_stream_index=5,
            input_stream_values={
                1: "5", 2: "100", 3: addr(OTHER), 4: addr(to), 5: "1", 12: addr(OTHER),
            },
            apply_rules_update=False)
        print(f"EVAL o5 {label}: {o5!r}")
sys.stdout.flush(); os._exit(0)
'''


def _run(tmp_path, clause, shrink):
    script = tmp_path / "child_bare_ref.py"
    script.write_text(_CHILD)
    env = dict(os.environ, PROBE_CLAUSE=clause, PROBE_SHRINK=shrink,
               PROBE_DB=str(tmp_path / "probe.db"), REPO_ROOT=REPO)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, cwd=REPO, timeout=600,
    )
    lines = [line for line in out.stdout.splitlines()
             if line.startswith(("PREFLIGHT ", f"APPLY {clause}", "EVAL"))]
    return out.returncode, lines


@pytest.mark.parametrize("shrink", ["true", "false"])
def test_bare_clause_is_admitted_and_judged_the_same(tmp_path, shrink):
    rc, lines = _run(tmp_path, "bare", shrink)
    assert rc == 0, lines
    assert "PREFLIGHT bare: ADMIT" in lines
    assert any(line.startswith("APPLY bare: o0='F' outcome=ACCEPTED_CHANGED") for line in lines)
    assert "EVAL o5 to=KEY: '1'" in lines
    assert "EVAL o5 to=OTHER: '0'" in lines


def test_a_plain_bare_ref_of_a_shrunk_stream_is_node_local(tmp_path):
    rc, lines = _run(tmp_path, "paren", "true")
    assert rc == 0, lines
    preflight = next(line for line in lines if line.startswith("PREFLIGHT "))
    assert "ADMISSION_UNAVAILABLE" in preflight
    assert any(line.startswith("APPLY paren: ShrinkTypeConflict") for line in lines)


CUSTOM_KEY = "a1" * 48
SHRINKS_I13 = ("always ( i13[t]:bv[384] = { #x" + CUSTOM_KEY + " }:bv[384]"
               " -> o5[t]:bv[24] = { #x000001 }:bv[24] ).")


def _worker_after_shrinking_i13(candidate):
    import tau_reconstruction
    import tau_session

    with open(os.path.join(REPO, "genesis.tau")) as fh:
        router = f"always ( {fh.read().strip()} )."
    plan = tau_reconstruction.plan_representation(history_rules=[SHRINKS_I13],
                                                  candidate_rules=[candidate])
    assert 13 in plan.interned
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    session = tau_session.WorkerSession.spawn(router, cwd=REPO, env=env, plan=plan)
    session.apply_rule(SHRINKS_I13, record=False)
    assert session.last_receipt()["accepted"]
    return session


def test_a_bare_ref_of_a_shrunk_custom_stream_gets_a_clear_error(temp_database):
    import commands.sendtx as sendtx

    candidate = ("always ( i13[t] = ({ #x" + CUSTOM_KEY + " }:bv[384])"
                 " -> o6[t]:bv[24] = { #x000001 }:bv[24] ).")
    session = _worker_after_shrinking_i13(candidate)
    try:
        session.apply_rule(candidate, record=False)
        receipt = session.last_receipt()
    finally:
        session.dispose()
    assert not receipt["accepted"]
    assert receipt["outcome"] == "REJECTED_RULE"
    refusal = sendtx._revision_refusal(receipt)
    assert refusal["code"] == "TX_REJECTED"
    assert "Write i13[t]:bv[384]" in refusal["message"]
    assert "type inference produced no tree" not in refusal["message"]


def test_the_error_never_turns_an_accepted_bare_ref_into_a_refusal(temp_database):
    # The engine types this bare i13 from the shrunk width it already holds.
    candidate = "always ( i13[t] = i14[t] -> o6[t]:bv[24] = { #x000001 }:bv[24] )."
    session = _worker_after_shrinking_i13(candidate)
    try:
        session.apply_rule(candidate, record=False)
        receipt = session.last_receipt()
    finally:
        session.dispose()
    assert receipt["accepted"]
    assert not (receipt.get("report") or {}).get("errors")
