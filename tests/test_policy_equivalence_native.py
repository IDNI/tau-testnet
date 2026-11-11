"""The shared o5 composite and the per-account evaluator agree on every clause body.

For one author, the composite verdict on a transfer from the author must equal
the verdict of `always ( body ).` on its own, and a transfer from anyone else
must be allowed by the composite (no clause means allow).
"""
import hashlib
import os

import pytest

import tau_defs
import tau_policy
import tau_speculation
from consensus.rule_offers import compose_stream_rule


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
O5 = tau_defs.USER_POLICY_STREAM_INDEX
SLOTS = tau_defs.approval_slot_indices()


def _key(label: str) -> str:
    """96 hex digits that are not all decimal digits (an all-digit key reads back
    as a number and breaks guards on the sender stream)."""
    digits = "".join(
        hashlib.sha256((label + str(n)).encode()).hexdigest() for n in range(2))[:96]
    assert not digits.isdigit()
    return digits


AUTHOR = _key("author")
STRANGER = _key("stranger")
K1, K2, K3 = _key("approver-1"), _key("approver-2"), _key("approver-3")
W1, W2 = _key("whitelisted-1"), _key("whitelisted-2")
NOBODY = _key("nobody")


def _lit(key: str) -> str:
    return "{ #x" + key + " }:bv[384]"


def _hexv(key: str) -> str:
    return "#x" + key


def _verdict_clause(condition: str, blocked_when: bool = True) -> str:
    block, allow = "(o5[t]:bv[24] = { #x000000 }:bv[24])", "(o5[t]:bv[24] = { #x000001 }:bv[24])"
    first, second = (block, allow) if blocked_when else (allow, block)
    return f"( {condition} ) ? {first} : {second}"


def _slot(n: int) -> str:
    return f"i{SLOTS[n]}"


AMOUNT = "i1[t]:bv[24]"
THRESHOLD = _verdict_clause(f"{AMOUNT} > {{ #x0003e8 }}:bv[24]")
ONE_SLOT = _verdict_clause(
    f"{AMOUNT} > {{ #x0003e8 }}:bv[24] && !({_slot(0)}[t]:bv[384] = {_lit(K1)})")
TWO_SLOTS = _verdict_clause(
    f"{AMOUNT} > {{ #x0003e8 }}:bv[24] && !({_slot(0)}[t]:bv[384] = {_lit(K1)} "
    f"&& {_slot(1)}[t]:bv[384] = {_lit(K2)})")
THREE_SLOTS = _verdict_clause(
    f"{AMOUNT} > {{ #x0003e8 }}:bv[24] && !({_slot(0)}[t]:bv[384] = {_lit(K1)} "
    f"&& {_slot(1)}[t]:bv[384] = {_lit(K2)} && {_slot(2)}[t]:bv[384] = {_lit(K3)})")
WHITELIST = _verdict_clause(
    f"i4[t]:bv[384] = {_lit(W1)} || i4[t]:bv[384] = {_lit(W2)}", blocked_when=False)
TIME_LOCK = _verdict_clause("i5[t]:bv[32] < { #x0000ff00 }:bv[32]")
CUSTOM_INPUT = _verdict_clause(
    f"i13[t]:bv[16] = {{ #x0001 }}:bv[16] && {AMOUNT} > {{ #x000010 }}:bv[24]")


def _amounts(*values):
    return [{"i1": f"#x{v:06x}"} for v in values]


def _slots(n_filled, key_order=(K1, K2, K3)):
    return {_slot(i): _hexv(key_order[i]) for i in range(n_filled)}


CORPUS = {
    "threshold": (THRESHOLD, _amounts(0, 1, 1000, 1001, 5000)),
    "one_slot": (ONE_SLOT, [
        {"i1": "#x0007d0"},
        {"i1": "#x0007d0", **_slots(1)},
        {"i1": "#x0007d0", _slot(0): _hexv(NOBODY)},
        {"i1": "#x0003e8"},
    ]),
    "two_slots": (TWO_SLOTS, [
        {"i1": "#x0007d0"},
        {"i1": "#x0007d0", **_slots(1)},
        {"i1": "#x0007d0", **_slots(2)},
        {"i1": "#x0007d0", _slot(0): _hexv(K1), _slot(1): _hexv(NOBODY)},
        {"i1": "#x0007d0", _slot(0): _hexv(K2), _slot(1): _hexv(K1)},
        {"i1": "#x0003e8", **_slots(2)},
    ]),
    "three_slots": (THREE_SLOTS, [
        {"i1": "#x0007d0"},
        {"i1": "#x0007d0", **_slots(2)},
        {"i1": "#x0007d0", **_slots(3)},
        {"i1": "#x0007d0", **_slots(3, (K1, K2, NOBODY))},
        {"i1": "#x0007d0", **_slots(3, (NOBODY, K2, K3))},
        {"i1": "#x000001", **_slots(0)},
    ]),
    "recipient_whitelist": (WHITELIST, [
        {"i1": "#x000005", "i4": _hexv(W1)},
        {"i1": "#x000005", "i4": _hexv(W2)},
        {"i1": "#x000005", "i4": _hexv(NOBODY)},
        {"i1": "#x000005", "i4": _hexv(AUTHOR)},
    ]),
    "time_lock": (TIME_LOCK, [
        {"i1": "#x000005", "i5": "#x00000000"},
        {"i1": "#x000005", "i5": "#x0000fe00"},
        {"i1": "#x000005", "i5": "#x0000ff00"},
        {"i1": "#x000005", "i5": "#x00010000"},
    ]),
    "custom_input": (CUSTOM_INPUT, [
        {"i1": "#x000020", "i13": "#x0001"},
        {"i1": "#x000020", "i13": "#x0002"},
        {"i1": "#x000001", "i13": "#x0001"},
        {"i1": "#x000020"},
    ]),
}


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _composite_blocks(session, inputs, sender):
    resp = session.step({**inputs, "i12": _hexv(sender)})
    assert resp.get("ok"), resp
    value = tau_policy.parse_o5((resp.get("outputs") or {}).get("o5"))
    return value == 0, (resp.get("outputs") or {}).get("o5")


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_composite_and_per_account_verdicts_agree(name):
    body, probes = CORPUS[name]
    composite = compose_stream_rule(O5, {AUTHOR: body})
    assert composite and composite.startswith("always (")

    mismatches = []
    seen = {"blocked": 0, "allowed": 0}
    session = tau_speculation.SpeculationSession(cwd=REPO, env=_env(), timeout=TIMEOUT)
    evaluator = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    try:
        session.init(composite)
        for inputs in probes:
            as_author, composite_o5 = _composite_blocks(session, inputs, AUTHOR)
            own = evaluator.verdict(body, inputs)
            as_stranger, stranger_o5 = _composite_blocks(session, inputs, STRANGER)
            seen["blocked" if own.blocked else "allowed"] += 1
            if as_author != own.blocked:
                mismatches.append(("author", body, inputs, composite_o5, own.o5))
            if as_stranger:
                mismatches.append(("stranger blocked by the composite", body, inputs,
                                   stranger_o5, "no clause: allow"))
    finally:
        session.kill()
        evaluator.close()

    for who, text, inputs, composite_o5, own_o5 in mismatches:
        print(f"MISMATCH ({who})\n  body: {text}\n  inputs: {inputs}\n"
              f"  composite o5: {composite_o5}\n  per-account o5: {own_o5}")
    assert not mismatches
    assert seen["blocked"] and seen["allowed"], f"corpus must exercise both branches: {seen}"
