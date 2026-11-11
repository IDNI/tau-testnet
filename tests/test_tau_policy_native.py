"""Policy clauses against the real engine: verdicts, typing conflicts, worker loss."""
import hashlib
import os
import signal

import pytest

import tau_policy


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TIMEOUT = 120.0


def _key(label: str) -> str:
    """96 hex digits that are not all decimal digits (an all-digit key reads back
    as a number and breaks guards on the sender stream)."""
    digits = hashlib.sha256(label.encode()).hexdigest() + hashlib.sha256(
        label.encode() + b"x").hexdigest() + hashlib.sha256(label.encode() + b"y").hexdigest()
    digits = digits[:96]
    assert not digits.isdigit()
    return "#x" + digits


K1, K2, K3 = _key("slot-1"), _key("slot-2"), _key("slot-3")
OTHER = _key("other")

THREE_SLOT = (
    "( (i1[t]:bv[24] > { #x0003e8 }:bv[24] && !("
    f"i14[t]:bv[384] = {{ {K1} }}:bv[384] && "
    f"i15[t]:bv[384] = {{ {K2} }}:bv[384] && "
    f"i16[t]:bv[384] = {{ {K3} }}:bv[384])) ) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def evaluator():
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    yield ev
    ev.close()


def _approvers(a, b, c):
    return {"i14": a, "i15": b, "i16": c}


def test_three_slot_clause_blocks_and_allows(evaluator):
    assert evaluator.validate(THREE_SLOT).ok
    cases = [
        ({"i1": "#x0007d0", **_approvers(K1, K2, K3)}, False),
        ({"i1": "#x0007d0", **_approvers(OTHER, K2, K3)}, True),
        ({"i1": "#x0007d0", **_approvers(K1, OTHER, K3)}, True),
        ({"i1": "#x0007d0", **_approvers(K1, K2, OTHER)}, True),
        ({"i1": "#x0007d0", **_approvers(OTHER, OTHER, OTHER)}, True),
        ({"i1": "#x0003e8", **_approvers(OTHER, OTHER, OTHER)}, False),
        ({"i1": "#x000001", **_approvers(K1, K2, K3)}, False),
    ]
    for inputs, blocked in cases:
        verdict = evaluator.verdict(THREE_SLOT, inputs)
        assert verdict.blocked is blocked, (inputs, verdict)
        assert verdict.o5 is not None
    assert evaluator.stats()["widths"]["i14"] == 384


def test_undetermined_o5_reads_as_blocked(evaluator):
    body = "( i1[t]:bv[24] > { #x0003e8 }:bv[24] ) -> ( o5[t]:bv[24] = { #x000001 }:bv[24] )"
    assert evaluator.validate(body).ok
    assert evaluator.verdict(body, {"i1": "#x0000ff"}).blocked


def test_width_conflict_on_a_shared_stream_uses_a_fresh_worker(evaluator):
    narrow = ("( i13[t]:bv[16] = { #x0001 }:bv[16] ) "
              "? ( o5[t]:bv[24] = { #x000000 }:bv[24] ) : ( o5[t]:bv[24] = { #x000001 }:bv[24] )")
    wide = ("( i13[t]:bv[24] = { #x000001 }:bv[24] ) "
            "? ( o5[t]:bv[24] = { #x000000 }:bv[24] ) : ( o5[t]:bv[24] = { #x000001 }:bv[24] )")
    assert evaluator.verdict(narrow, {"i13": "#x0001"}).blocked
    assert not evaluator.verdict(narrow, {"i13": "#x0002"}).blocked
    assert evaluator.verdict(wide, {"i13": "#x000001"}).blocked
    assert not evaluator.verdict(wide, {"i13": "#x000002"}).blocked
    assert evaluator.stats()["fresh_fallbacks"] == 1


def test_killed_worker_is_replaced_and_verdicts_stay_right(evaluator):
    inputs = {"i1": "#x0007d0", **_approvers(OTHER, K2, K3)}
    assert evaluator.verdict(THREE_SLOT, inputs).blocked
    os.kill(evaluator.worker_pid(), signal.SIGKILL)
    assert evaluator.verdict(THREE_SLOT, inputs).blocked
    stats = evaluator.stats()
    assert stats["retries"] == 1 and stats["spawns"] == 2


def test_recycling_preserves_verdicts():
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT, recycle_builds=2)
    try:
        for n in range(1, 6):
            body = (f"( i1[t]:bv[24] > {{ #x{n:06x} }}:bv[24] ) "
                    "? ( o5[t]:bv[24] = { #x000000 }:bv[24] ) : ( o5[t]:bv[24] = { #x000001 }:bv[24] )")
            assert ev.verdict(body, {"i1": f"#x{n + 1:06x}"}).blocked
            assert not ev.verdict(body, {"i1": f"#x{n:06x}"}).blocked
        assert ev.stats()["recycles"] > 0
    finally:
        ev.close()
