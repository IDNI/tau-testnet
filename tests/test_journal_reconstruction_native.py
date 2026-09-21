"""Reconstruct an evaluator from the committed journal, and compare everything.

Each state dimension was established separately: temporal history, type
commitments that outlive their rule, the revision counter, the lazy input
schedule. This exercises them together, because a reconstruction that gets three
of four right is still a reconstruction that computes the next block from a state
nobody has.
"""
import os

import pytest

import tau_journal as tj
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

R1 = "always ( i20[t]:bv[8] = { 1 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] )."
HIST = "always ( o8[t]:bv[24] = i1[t-3]:bv[24] )."
DEPTH1 = "always ( o9[t]:bv[24] = i1[t-1]:bv[24] )."
R2 = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."          # supersedes R1
NOOP = "always ( o5[t]:bv[24] = o5[t]:bv[24] )."
WIDE20 = ("always ( i20[t]:bv[384] = { #x" + "cc" * 48 + " }:bv[384] -> "
          "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")


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


#: Everything that defines the authoritative state, in order. R1 types i20 and is
#: then superseded, so its commitment is invisible in the spec text; the inputs
#: build t-1 and t-3 history; the no-op is a revision that changes nothing yet
#: still advances execution.
HISTORY = [
    ("revision", R1),
    ("revision", HIST),
    ("revision", DEPTH1),
    ("step", {"i1": "#x000005"}),
    ("step", {"i1": "#x000009"}),
    ("step", {"i1": "#x000042"}),
    ("revision", R2),
    ("revision", NOOP),
    ("step", {"i1": "#x000011"}),
]
CONTINUATION = [{"i1": "#x000001"}, {"i1": "#x000002"},
                {"i1": "#x000003"}, {"i1": "#x000004"}]


def _drive(session, journal=None):
    """Run the history, recording it the way the authoritative session does."""
    for kind, payload in HISTORY:
        if kind == "revision":
            receipt = session.revise(payload, "h")
            if journal is not None:
                journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text=payload,
                               outcome=receipt.get("outcome"),
                               result=receipt.get("outputs"))
        else:
            result = session.step(payload)
            if journal is not None:
                journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs=payload,
                               result=result.get("outputs"))


def _replay(session, journal):
    """Reconstruct by replaying the journal, checking each step against its
    recorded fingerprint rather than assuming it matched."""
    for entry, (seq, expected) in zip(journal.entries(), journal.fingerprints()):
        payload = entry.replayable()
        if payload["kind"] == tj.REVISION:
            receipt = session.revise(payload["rule_text"], "r")
            tj.compare(expected, receipt.get("outputs"), seq=seq)
        else:
            result = session.step(payload["inputs"])
            tj.compare(expected, result.get("outputs"), seq=seq)


def _observe(session):
    """Every dimension, after the same continuation."""
    state = session.state()
    seen = []
    for inputs in CONTINUATION:
        r = session.step(inputs)
        out = r.get("outputs") or {}
        seen.append((r.get("asked"), out.get("o8"), out.get("o9"), r.get("time_point")))
    return {
        "time_point": state.get("time_point"),
        "spec_revision": state.get("spec_revision"),
        "continuation": seen,
    }


def test_a_journal_reconstruction_matches_on_every_dimension():
    journal = tj.Journal(anchor="genesis")

    live = _session()
    try:
        _drive(live, journal)
        live_view = _observe(live)
        live_type_verdict = live.revise(WIDE20, "wide")["outcome"]
    finally:
        live.kill()

    rebuilt = _session()
    try:
        _replay(rebuilt, journal)            # raises DivergenceError on mismatch
        rebuilt_view = _observe(rebuilt)
        rebuilt_type_verdict = rebuilt.revise(WIDE20, "wide")["outcome"]
    finally:
        rebuilt.kill()

    assert rebuilt_view["time_point"] == live_view["time_point"]
    assert rebuilt_view["spec_revision"] == live_view["spec_revision"]
    assert rebuilt_view["continuation"] == live_view["continuation"]
    # the commitment R1 left behind, after R1 itself was superseded
    assert live_type_verdict == "REJECTED_RULE"
    assert rebuilt_type_verdict == live_type_verdict


def test_the_history_under_test_is_actually_exercised():
    """Guard the guard: if the continuation read all zeros, the comparison above
    would pass without testing anything."""
    journal = tj.Journal()
    live = _session()
    try:
        _drive(live, journal)
        view = _observe(live)
    finally:
        live.kill()
    depths = {o8 for _, o8, _, _ in view["continuation"]}
    shallow = {o9 for _, _, o9, _ in view["continuation"]}
    assert depths - {"0", None}, f"t-3 history never materialized: {view}"
    assert shallow - {"0", None}, f"t-1 history never materialized: {view}"
    assert any(e.kind == tj.REVISION for e in journal.entries())
    assert any(e.kind == tj.STEP for e in journal.entries())


def test_a_tampered_journal_is_detected_rather_than_replayed():
    """A reconstruction that diverges must fail loudly: continuing would mean
    computing the next block from a state nobody checked."""
    journal = tj.Journal()
    live = _session()
    try:
        _drive(live, journal)
    finally:
        live.kill()

    # drop one input step: the replay now diverges partway through
    kept = [e for e in journal.entries() if not (e.kind == tj.STEP
                                                 and e.inputs.get("i1") == "#x000009")]
    tampered = tj.Journal()
    for e in kept:
        tampered.record(e.kind, phase=tj.PHASE_APPLY, rule_text=e.rule_text,
                        inputs=e.inputs, target=e.target, outcome=e.outcome)
        tampered._entries[-1] = type(e)(**{**e.to_dict(), "seq": len(tampered)})

    rebuilt = _session()
    try:
        with pytest.raises(tj.DivergenceError):
            _replay(rebuilt, tampered)
    finally:
        rebuilt.kill()
