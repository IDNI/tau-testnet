"""Real engine: a custom value on an interned stream gives the full-width result.

Each plan runs in its own worker process.
"""
import os

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
KEY = "a1" * 48
WIDE = ("always ( i13[t]:bv[384] = { #x" + KEY + " }:bv[384]"
        " -> o5[t]:bv[24] = { #x000001 }:bv[24] ).")
NARROW = ("always ( i13[t]:bv[8] = { #x05 }:bv[8]"
          " -> o5[t]:bv[24] = { #x000001 }:bv[24] ).")


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _o5_of_each(plan, rule, values):
    """o5 of each value on i13, or "refused"."""
    import tau_session

    session = tau_session.WorkerSession.spawn(_router(), cwd=REPO, env=_env(), plan=plan)
    try:
        session.apply_rule(rule, record=False)
        assert session.last_receipt()["accepted"]
        out = []
        for value in values:
            try:
                out.append(session.evaluate({13: value}, multi=True, record=False).get(5))
            except tau_session.StepRefused:
                out.append("refused")
        return out
    finally:
        session.dispose()


def _both_plans(rule, values):
    import tau_reconstruction

    plan = tau_reconstruction.plan_representation(candidate_rules=[rule])
    no_shrink = tau_reconstruction.RepresentationPlan(width=plan.width)
    return plan, _o5_of_each(plan, rule, values), _o5_of_each(no_shrink, rule, values)


def test_a_small_bare_value_is_never_read_as_an_interned_id(temp_database):
    values = ["0", "1", "2", "3", "{ #x" + KEY + " }:bv[384]"]
    plan, shrunk, full = _both_plans(WIDE, values)
    assert 13 in plan.interned
    assert shrunk == full == ["0", "0", "0", "0", "1"]


def test_leading_zeros_of_a_value_do_not_change_its_verdict(temp_database):
    values = ["#x" + KEY, "#x00" + KEY, "{ #x00" + KEY + " }:bv[384]"]
    _, shrunk, full = _both_plans(WIDE, values)
    assert shrunk == full == ["1", "1", "1"]


def test_a_value_that_fits_the_declared_width_is_not_refused(temp_database):
    values = ["300", "#x01ff", "{ #x01ff }:bv[16]"]
    _, shrunk, full = _both_plans(WIDE, values)
    assert shrunk == full == ["0", "0", "0"]


def test_a_value_wider_than_the_declared_width_is_refused_on_both_plans(temp_database):
    _, shrunk, full = _both_plans(WIDE, ["#x1" + "0" * 96])
    assert shrunk == full == ["refused"]


AT_256 = ("always ( i13[t]:bv[256] = { #x" + "b2" * 32 + " }:bv[256]"
          " -> o6[t]:bv[24] = { #x000001 }:bv[24] ).")


def _outcomes(rules):
    import tau_reconstruction
    import tau_session

    plan = tau_reconstruction.RepresentationPlan(width=8)
    session = tau_session.WorkerSession.spawn(_router(), cwd=REPO, env=_env(), plan=plan)
    try:
        out = []
        for rule in rules:
            session.apply_rule(rule, record=False)
            out.append(session.last_receipt()["accepted"])
        return out
    finally:
        session.dispose()


def test_the_engine_refuses_a_second_width_of_one_input_stream(temp_database):
    assert _outcomes([WIDE, AT_256]) == [True, False]
    assert _outcomes([AT_256, WIDE]) == [True, False]
    both = ("always ( (i13[t]:bv[384] = { #x" + KEY + " }:bv[384]"
            " -> o5[t]:bv[24] = { #x000001 }:bv[24])"
            " && (i13[t-1]:bv[256] = { #x01 }:bv[256] -> o6[t]:bv[24] = { #x000001 }:bv[24]) ).")
    assert _outcomes([both]) == [False]


def test_a_stream_of_a_rejected_candidate_at_another_width_gives_the_full_verdict(
        temp_database):
    """A plan covers the rejected candidates too, so it meets both widths."""
    import tau_reconstruction

    plan = tau_reconstruction.plan_representation(candidate_rules=[WIDE, AT_256])
    assert 13 in plan.plain and 13 not in plan.interned
    no_shrink = tau_reconstruction.RepresentationPlan(width=plan.width)
    values = ["1", "2", "{ #x" + KEY + " }:bv[384]"]
    assert _o5_of_each(plan, WIDE, values) == _o5_of_each(no_shrink, WIDE, values) == [
        "0", "0", "1"]


def test_a_value_too_wide_for_a_narrow_stream_is_refused_on_both_plans(temp_database):
    plan, shrunk, full = _both_plans(NARROW, ["5", "300"])
    assert 13 not in plan.interned
    assert shrunk == full == ["1", "refused"]
