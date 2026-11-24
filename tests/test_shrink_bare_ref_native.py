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


def _run(tmp_path, clause):
    script = tmp_path / "child_bare_ref.py"
    script.write_text(_CHILD)
    env = dict(os.environ, PROBE_CLAUSE=clause,
               PROBE_DB=str(tmp_path / "probe.db"), REPO_ROOT=REPO)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    out = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, cwd=REPO, timeout=600,
    )
    lines = [line for line in out.stdout.splitlines()
             if line.startswith(("PREFLIGHT ", f"APPLY {clause}", "EVAL"))]
    return out.returncode, lines


def test_bare_clause_is_admitted_and_judged_the_same(tmp_path):
    rc, lines = _run(tmp_path, "bare")
    assert rc == 0, lines
    assert "PREFLIGHT bare: ADMIT" in lines
    assert any(line.startswith("APPLY bare: o0='F' outcome=ACCEPTED_CHANGED") for line in lines)
    assert "EVAL o5 to=KEY: '1'" in lines
    assert "EVAL o5 to=OTHER: '0'" in lines


def test_a_plain_bare_ref_of_a_shrunk_stream_is_node_local(tmp_path):
    rc, lines = _run(tmp_path, "paren")
    assert rc == 0, lines
    preflight = next(line for line in lines if line.startswith("PREFLIGHT "))
    assert "ADMISSION_UNAVAILABLE" in preflight
    assert any(line.startswith("APPLY paren: ShrinkTypeConflict") for line in lines)


CUSTOM_KEY = "a1" * 48
SHRINKS_I13 = ("always ( i13[t]:bv[384] = { #x" + CUSTOM_KEY + " }:bv[384]"
               " -> o5[t]:bv[24] = { #x000001 }:bv[24] ).")


def _worker_after_shrinking_i13(candidate):
    """A worker whose plan interns i13 before the candidate arrives. A plan over
    the candidate makes i13 plain, so only such a worker meets the hint."""
    import tau_reconstruction
    import tau_session

    with open(os.path.join(REPO, "genesis.tau")) as fh:
        router = f"always ( {fh.read().strip()} )."
    plan = tau_reconstruction.plan_representation(history_rules=[SHRINKS_I13])
    assert 13 in plan.interned
    assert 13 in tau_reconstruction.plan_representation(
        history_rules=[SHRINKS_I13], candidate_rules=[candidate]).plain
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


def test_a_bare_ref_rule_refused_for_another_reason_keeps_its_cause(temp_database):
    import commands.sendtx as sendtx

    # The bare i13 types, but o6 cannot be 1 and 2 at once.
    candidate = ("always ( i13[t] = i14[t]"
                 " && o6[t]:bv[24] = { #x000001 }:bv[24]"
                 " && o6[t]:bv[24] = { #x000002 }:bv[24] ).")
    session = _worker_after_shrinking_i13(candidate)
    try:
        session.apply_rule(candidate, record=False)
        receipt = session.last_receipt()
    finally:
        session.dispose()
    assert not receipt["accepted"]
    refusal = sendtx._revision_refusal(receipt)
    assert "Write i13[t]:bv[384]" not in refusal["message"]
    errors = (receipt.get("report") or {}).get("errors") or []
    assert not any("without a width" in str(e) for e in errors)


OTHER_KEY = "cd" * 48


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _width():
    import tau_shrink

    return tau_shrink.current_shrink_width()


def _no_shrink_plan(width):
    import tau_reconstruction

    return tau_reconstruction.RepresentationPlan(width=width, interned=frozenset(),
                                                 plain=frozenset())


def _addr(hex_digits):
    return "{ #x" + hex_digits + " }:bv[384]"


def _outputs(session, inputs):
    import tau_session

    outputs = []
    for step in inputs:
        try:
            outputs.append(session.evaluate(step, multi=True, record=False))
        except tau_session.StepRefused:
            outputs.append("refused")
    return outputs


def _run_rules(plan, rules, inputs):
    """The accepted flag of each rule, then the outputs of each input step."""
    import tau_session

    session = tau_session.WorkerSession.spawn(_router(), cwd=REPO, env=_env(), plan=plan)
    try:
        accepted = []
        for rule in rules:
            session.apply_rule(rule, record=False)
            accepted.append(session.last_receipt()["accepted"])
        outputs = _outputs(session, inputs)
    finally:
        session.dispose()
    return accepted, outputs


def _run_live(rules, inputs):
    """Each rule as a node meets it: a worker planned over the accepted history
    and this rule, which replays the history and then offers the rule."""
    import tau_reconstruction
    import tau_session

    history, accepted, session = [], [], None
    try:
        for rule in rules:
            plan = tau_reconstruction.plan_representation(history_rules=history,
                                                          candidate_rules=[rule])
            if session is not None:
                session.dispose()
            session = tau_session.WorkerSession.spawn(_router(), cwd=REPO, env=_env(),
                                                      plan=plan)
            for old in history:
                session.apply_rule(old, record=False)
            session.apply_rule(rule, record=False)
            ok = session.last_receipt()["accepted"]
            accepted.append(ok)
            if ok:
                history.append(rule)
        return accepted, _outputs(session, inputs)
    finally:
        if session is not None:
            session.dispose()


VERDICT_RULES = {
    "annotated": SHRINKS_I13,
    "bare_with_literal": ("always ( i13[t] = { #x" + CUSTOM_KEY + " }:bv[384]"
                          " -> o6[t]:bv[24] = { #x000001 }:bv[24] )."),
}


@pytest.mark.parametrize("name", sorted(VERDICT_RULES))
def test_a_rule_gives_the_same_verdict_with_and_without_shrink(temp_database, name):
    import tau_reconstruction

    rule = VERDICT_RULES[name]
    plan = tau_reconstruction.plan_representation(candidate_rules=[rule])
    assert 13 in plan.interned
    inputs = [{13: _addr(CUSTOM_KEY)}, {13: _addr(OTHER_KEY)}]
    shrunk = _run_rules(plan, [rule], inputs)
    canonical = _run_rules(_no_shrink_plan(plan.width), [rule], inputs)
    assert shrunk[0] == [True]
    assert shrunk == canonical


BARE_I13 = "always ( i13[t] = i14[t] -> o6[t]:bv[24] = { #x000001 }:bv[24] )."
PAIR_STEPS = [{13: _addr(CUSTOM_KEY), 14: _addr(CUSTOM_KEY)},
              {13: _addr(CUSTOM_KEY), 14: _addr(OTHER_KEY)},
              {13: _addr(OTHER_KEY), 14: _addr(OTHER_KEY)}]


def test_a_bare_ref_makes_its_stream_and_partners_plain(temp_database):
    import tau_reconstruction

    for rules in ([BARE_I13, SHRINKS_I13], [SHRINKS_I13, BARE_I13]):
        plan = tau_reconstruction.plan_representation(history_rules=rules)
        assert {13, 14} <= set(plan.plain)
        assert not ({13, 14} & set(plan.interned))


def test_annotated_then_bare_gives_the_no_shrink_verdict(temp_database):
    """B then A: the bare i14 takes its width from i13, so a shrunk i13 typed i14
    shrunk while its input stayed full width."""
    live = _run_live([SHRINKS_I13, BARE_I13], PAIR_STEPS)
    canonical = _run_rules(_no_shrink_plan(_width()), [SHRINKS_I13, BARE_I13], PAIR_STEPS)
    assert live[0] == [True, True]
    assert live == canonical
    assert [(out.get(5), out.get(6)) for out in canonical[1]] == [
        ("1", "1"), ("1", "0"), ("0", "1")]


def test_bare_then_annotated_gives_the_no_shrink_verdict(temp_database):
    """A then B: the engine refuses B also with no shrink."""
    live = _run_live([BARE_I13, SHRINKS_I13], PAIR_STEPS)
    canonical = _run_rules(_no_shrink_plan(_width()), [BARE_I13, SHRINKS_I13], PAIR_STEPS)
    assert live[0] == [True, False]
    assert live == canonical


def test_replay_of_a_bare_ref_rule_before_its_stream_is_annotated(temp_database):
    """A plan over a history with A and B, as a proposal plans over every candidate.
    Its replay gives the verdicts and the outputs of the live node and of no shrink."""
    import tau_reconstruction

    rules = [BARE_I13, SHRINKS_I13]
    plan = tau_reconstruction.plan_representation(history_rules=rules)
    assert {13, 14} <= set(plan.plain)
    replayed = _run_rules(plan, rules, PAIR_STEPS)
    assert replayed == _run_live(rules, PAIR_STEPS)
    assert replayed == _run_rules(_no_shrink_plan(plan.width), rules, PAIR_STEPS)
