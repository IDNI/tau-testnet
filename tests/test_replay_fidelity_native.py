"""C2/C5: is a recorded step log enough to reconstruct evaluator state?

The speculative-apply design turns on this. Promotion covers the committed path --
the worker that evaluated a block becomes the worker that serves it -- but a DIRTY
block attempt, one where a rejected transaction already touched the engine, can
only be re-run by replaying the accepted prefix into a fresh worker. W0 established
that spec text alone is NOT enough: a rebuild from `current_spec()` comes back at
`time_point=0` with the history gone. These ask whether the step log closes that
gap.

Real engine, one process per session. Each session is its own worker, so the
isolation is the thing under test rather than an assumption.
"""
import os

import pytest

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
HIST = "always ( o5[t]:bv[24] = i1[t-1]:bv[24] )."
DEEP = "always ( o8[t]:bv[24] = i1[t-3]:bv[24] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _router():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return f"always ( {fh.read().strip()} )."


def _session():
    s = spec.SpeculationSession(cwd=REPO, env=_env())
    s.init(_router())
    return s


def _run(session, trace):
    """Drive a step log, recording every observable it produces."""
    seen = []
    for kind, payload in trace:
        if kind == "revise":
            r = session.revise(payload, "c")
            seen.append(("rev", r.get("outcome"), r.get("spec_revision"), r.get("time_point")))
        else:
            r = session.step(payload)
            out = r.get("outputs") or {}
            seen.append(("step", out.get("o5"), out.get("o8"), r.get("time_point")))
    return seen


HISTORY = [
    ("revise", HIST), ("revise", DEEP),
    ("step", {"i1": "#x000005"}), ("step", {"i1": "#x000009"}),
    ("step", {"i1": "#x000011"}), ("step", {"i1": "#x000042"}),
]
CONTINUATION = [
    ("step", {"i1": "#x000001"}), ("step", {"i1": "#x000002"}),
    ("step", {"i1": "#x000003"}), ("step", {"i1": "#x000004"}),
]


def test_a_replayed_session_matches_a_live_one():
    """Including temporal depth: o5 echoes i1[t-1] and o8 echoes i1[t-3], so a
    reconstruction that lost history would diverge immediately."""
    live = _session()
    try:
        _run(live, HISTORY)
        live_out = _run(live, CONTINUATION)
    finally:
        live.kill()

    replayed = _session()
    try:
        _run(replayed, HISTORY)          # the same log, in a fresh process
        replayed_out = _run(replayed, CONTINUATION)
    finally:
        replayed.kill()

    assert live_out == replayed_out, f"live={live_out}\nreplayed={replayed_out}"
    # and the history is actually being exercised, not all None
    assert any(o5 is not None and o5 != "0" for _, o5, _, _ in live_out)
    assert any(o8 is not None and o8 != "0" for _, _, o8, _ in live_out)


def test_replay_is_deterministic():
    first, second = [], []
    for sink in (first, second):
        s = _session()
        try:
            sink.extend(_run(s, HISTORY) + _run(s, CONTINUATION))
        finally:
            s.kill()
    assert first == second


def test_type_commitments_are_reproduced_by_replay():
    """A commitment outlives the rule that made it, so replay has to recreate it
    or the reconstructed session would accept text the original refuses."""
    pin = "always ( i12[t]:bv[8] = { 1 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] )."
    wide = ("always ( i12[t]:bv[384] = { #x" + "bb" * 48 + " }:bv[384] -> "
            "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")
    log = [("revise", pin), ("step", {"i12": "1"}), ("step", {"i12": "2"})]

    live = _session()
    try:
        _run(live, log)
        live_verdict = live.revise(wide, "w")["outcome"]
    finally:
        live.kill()

    replayed = _session()
    try:
        _run(replayed, log)
        replayed_verdict = replayed.revise(wide, "w")["outcome"]
    finally:
        replayed.kill()

    assert live_verdict == "REJECTED_RULE"
    assert replayed_verdict == live_verdict


def test_a_discarded_candidate_leaves_no_residue():
    """The dirty-attempt case: a rejected transaction's rule typed a stream, and
    re-running the accepted prefix in a fresh worker must not inherit that."""
    pin20 = "always ( i20[t]:bv[8] = { 1 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] )."
    wide20 = ("always ( i20[t]:bv[384] = { #x" + "cc" * 48 + " }:bv[384] -> "
              "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")
    prefix = [("revise", HIST), ("step", {"i1": "#x000009"})]

    dirty = _session()
    try:
        _run(dirty, prefix)
        assert dirty.revise(pin20, "x")["outcome"] == "ACCEPTED_CHANGED"
        contaminated = dirty.revise(wide20, "w")["outcome"]
    finally:
        dirty.kill()                       # disposal is the only rollback there is
    assert contaminated == "REJECTED_RULE", "the candidate should have typed i20"

    clean = _session()
    try:
        _run(clean, prefix)                # the SAME prefix, without the candidate
        after_replay = clean.revise(wide20, "w")["outcome"]
    finally:
        clean.kill()
    assert after_replay == "ACCEPTED_CHANGED", "residue survived disposal + replay"


@pytest.mark.parametrize("width", [8, 16, 24])
def test_replaying_at_a_wider_width_preserves_the_policy(width):
    """A capacity retry re-runs the attempt at a wider shrink width. The ids are
    the same and only the declared widths change, so the verdicts must not."""
    log = [
        ("revise", f"always ( i12[t]:bv[{width}] = {{ 1 }}:bv[{width}] -> "
                   f"o5[t]:bv[24] = {{ #x000001 }}:bv[24] )."),
        ("revise", f"always ( i12[t]:bv[{width}] = {{ 2 }}:bv[{width}] -> "
                   f"o5[t]:bv[24] = {{ #x000000 }}:bv[24] )."),
    ]
    s = _session()
    try:
        outcomes = [s.revise(text, "r")["outcome"] for _, text in log]
        verdicts = [(s.step({"i12": v}).get("outputs") or {}).get("o5") for v in ("1", "2")]
    finally:
        s.kill()
    assert outcomes == ["ACCEPTED_CHANGED", "ACCEPTED_CHANGED"]
    assert verdicts == ["1", "0"], f"policy changed at bv[{width}]: {verdicts}"
