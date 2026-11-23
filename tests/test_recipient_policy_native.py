"""Recipient policy (#47, #76) against the REAL Tau engine.

The mock suite (tests/test_recipient_policy.py) proves the node feeds the right
streams at the right sites. This file proves the other half: that clause text
written against the receive stream i17 really yields the o5 the docs promise
when the engine evaluates it, through the same helper the node calls.
"""
import hashlib
import os

import pytest

import tau_defs
import tau_policy
from consensus import sender_policy
from consensus.admission import _screen_clause_domains


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
POOL = "apply"


def _key(label: str) -> str:
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(hashlib.sha256(label.encode() + s).hexdigest() for s in (b"", b"x", b"y"))[:96]
    assert not digits.isdigit()
    return digits


A, B, C, R = _key("payer-a"), _key("payer-b"), _key("payee-c"), _key("recipient-r")


def _lit(pubkey):
    return "{ #x" + pubkey + " }:bv[384]"


ALLOW_ONLY_A = (
    "((i17[t]:bv[64] > { #x0000000000000000 }:bv[64]) && "
    f"!(i3[t]:bv[384] = {_lit(A)})) ? "
    "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def _cap(seconds):
    bound = format(tau_defs.RECIPIENT_HOLD_INSTANT + seconds, "016x")
    return (f"(i17[t]:bv[64] > {{ #x{bound} }}:bv[64]) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")


BOTH_WAYS = (
    "(((i17[t]:bv[64] = { #x0000000000000000 }:bv[64]) && "
    f"!(i4[t]:bv[384] = {_lit(C)})) || "
    "((i17[t]:bv[64] > { #x0000000000000000 }:bv[64]) && "
    f"!(i3[t]:bv[384] = {_lit(A)}))) ? "
    "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture(scope="module")
def engine():
    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    sender_policy.set_evaluator(POOL, ev)
    yield ev
    sender_policy.set_evaluator(POOL, None)
    ev.close()


def _transfer(sender, recipient, amount=500, ts=1_700_000_000):
    """The per-transfer map the node builds (same keys, same literal forms)."""
    values = {
        1: str(amount),
        3: _lit(sender),
        4: _lit(recipient),
        12: _lit(sender),
    }
    values.update({slot: "0" for slot in tau_defs.approval_slot_indices()})
    values[5] = str(ts)
    return values


def _receives(body, sender, hold=0):
    blocked, _ = sender_policy.recipient_clause_blocks(
        body, _transfer(sender, R), R, hold, pool=POOL)
    return not blocked


def _sends(body, recipient):
    blocked, _ = sender_policy.clause_blocks(
        body, sender_policy.sending_inputs(_transfer(R, recipient)), pool=POOL)
    return not blocked


@pytest.mark.parametrize("body", [ALLOW_ONLY_A, _cap(0), _cap(600), BOTH_WAYS,
                                  "BLOCK_CAP_100"])
def test_the_documented_clauses_pass_the_deploy_screens_and_build(engine, body):
    if body == "BLOCK_CAP_100":
        body = _block_cap(100)
    assert _screen_clause_domains(body) is None
    assert engine.validate(body).ok


def test_47_allowlist_admits_a_and_refuses_b(engine):
    assert _receives(ALLOW_ONLY_A, A) is True
    assert _receives(ALLOW_ONLY_A, B) is False


def test_47_the_allowlist_never_blocks_its_owner_sending(engine):
    assert _sends(ALLOW_ONLY_A, B) is True
    assert _sends(ALLOW_ONLY_A, C) is True


def test_47_one_clause_both_directions(engine):
    assert _receives(BOTH_WAYS, A) is True
    assert _receives(BOTH_WAYS, B) is False
    assert _sends(BOTH_WAYS, C) is True
    assert _sends(BOTH_WAYS, B) is False


def test_76_cap_zero_admits_only_instant(engine):
    assert _receives(_cap(0), A, hold=0) is True
    assert _receives(_cap(0), A, hold=1) is False
    assert _receives(_cap(0), A, hold=tau_defs.HeldBlocks(1)) is False


@pytest.mark.parametrize("hold, ok", [(0, True), (600, True), (601, False), (3600, False),
                                      (tau_defs.HeldBlocks(1), False)])
def test_76_cap_600_seconds_boundaries(engine, hold, ok):
    assert _receives(_cap(600), A, hold=hold) is ok


def test_76_the_cap_reported_to_the_payer_is_what_the_engine_enforces(engine):
    assert sender_policy.recipient_hold_cap(_cap(600), _transfer(A, R), R, pool=POOL) == 600
    assert sender_policy.recipient_hold_cap(_cap(0), _transfer(A, R), R, pool=POOL) == 0


def _block_cap(blocks):
    bound = format(tau_defs.RECIPIENT_HOLD_BLOCKS_BASE + blocks, "016x")
    return (f"(i17[t]:bv[64] > {{ #x{bound} }}:bv[64]) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")


@pytest.mark.parametrize("hold, ok", [(tau_defs.HeldBlocks(100), True), (tau_defs.HeldBlocks(101), False),
                                      (86_400, True), (0, True)])
def test_76_a_cap_in_blocks(engine, hold, ok):
    assert _receives(_block_cap(100), A, hold=hold) is ok


def test_76_the_block_cap_reported_is_what_the_engine_enforces(engine):
    assert sender_policy.recipient_hold_cap(
        _block_cap(100), _transfer(A, R), R, blocks=True, pool=POOL) == 100


def test_the_largest_hold_value_is_accepted_by_the_engine(engine):
    """The top of the blocks range must evaluate, not error: an error would
    fail closed and refuse every height-based park even with no cap."""
    # Refuses only an instant payment, so it is not a constant clause (the
    # engine refuses to step one, whatever the input).
    no_cap_reader = ("(i17[t]:bv[64] = { #x0000000000000001 }:bv[64]) ? "
                     "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")
    from consensus.retractable import MAX_RELEASE_WINDOW_BLOCKS
    assert _receives(no_cap_reader, A, hold=tau_defs.HeldBlocks(MAX_RELEASE_WINDOW_BLOCKS)) is True
    assert _receives(no_cap_reader, A, hold=0) is False


# --- `tau-testnet policy receive` clauses mean what they say -----------------

from tau_testnet_cli.recipient_rules import compose_receive_clause  # noqa: E402
from consensus.rule_offers import clause_body_v1  # noqa: E402


def _composed(**opts):
    return clause_body_v1(compose_receive_clause(**opts))


H = tau_defs.HeldBlocks


@pytest.mark.parametrize("opts, payer, hold, ok", [
    (dict(allow=[A]), A, 0, True),
    (dict(allow=[A]), B, 0, False),
    (dict(allow=[A, B]), B, 0, True),
    (dict(max_hold_seconds=0), A, 0, True),
    (dict(max_hold_seconds=0), A, 1, False),
    (dict(max_hold_seconds=600), A, 600, True),
    (dict(max_hold_seconds=600), A, 601, False),
    (dict(max_hold_seconds=600), A, H(1), False),
    (dict(max_hold_blocks=10), A, H(10), True),
    (dict(max_hold_blocks=10), A, H(11), False),
    (dict(max_hold_blocks=10), A, 10**6, True),
    (dict(max_hold_seconds=600, max_hold_blocks=10), A, 600, True),
    (dict(max_hold_seconds=600, max_hold_blocks=10), A, 601, False),
    (dict(max_hold_seconds=600, max_hold_blocks=10), A, H(10), True),
    (dict(max_hold_seconds=600, max_hold_blocks=10), A, H(11), False),
    (dict(allow=[A], max_hold_seconds=600), B, 0, False),
    (dict(allow=[A], max_hold_seconds=600), A, 3600, False),
    (dict(allow=[A], max_hold_seconds=600), A, 300, True),
])
def test_composed_inbound_semantics(engine, opts, payer, hold, ok):
    assert _receives(_composed(**opts), payer, hold=hold) is ok


@pytest.mark.parametrize("opts, payee, ok", [
    (dict(send_only_to=[C]), C, True),
    (dict(send_only_to=[C]), B, False),
    (dict(allow=[A]), B, True),                     # an inbound rule never limits sending
    (dict(max_hold_seconds=0), B, True),
    (dict(allow=[A], send_only_to=[C]), B, False),
])
def test_composed_outbound_semantics(engine, opts, payee, ok):
    assert _sends(_composed(**opts), payee) is ok



NON_MONOTONE = '(((i17[t]:bv[64] > { #x0000000000000065 }:bv[64]) && (i17[t]:bv[64] < { #x000000000000012d }:bv[64])) || (i17[t]:bv[64] > { #x0000000000000191 }:bv[64])) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])'


@pytest.mark.parametrize("hold, ok", [(0, True), (100, True), (101, False), (299, False),
                                      (300, True), (400, True), (401, False)])
def test_non_monotone_clause_semantics(engine, hold, ok):
    assert _receives(NON_MONOTONE, A, hold=hold) is ok


@pytest.mark.parametrize("held", [150, 250, 500])
def test_no_cap_is_reported_for_a_non_monotone_clause(engine, held):
    assert sender_policy.recipient_hold_cap(
        NON_MONOTONE, _transfer(A, R), R, pool=POOL, held=held) is None


@pytest.mark.parametrize("cap, held", [(0, 1), (600, 601), (600, 3600)])
def test_the_exact_cap_is_reported_for_a_cap_clause(engine, cap, held):
    assert sender_policy.recipient_hold_cap(
        _cap(cap), _transfer(A, R), R, pool=POOL, held=held) == cap


@pytest.mark.parametrize("cap, held", [(10, 11), (10, 500)])
def test_the_exact_block_cap_is_reported(engine, cap, held):
    assert sender_policy.recipient_hold_cap(
        _block_cap(cap), _transfer(A, R), R, blocks=True, pool=POOL, held=held) == cap



STREAM_COMPARED = ("(i17[t]:bv[64] > i26[t]:bv[64]) ? "
                   "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")


def test_a_stream_compared_clause_enforces_but_reports_no_cap(engine):
    values = _transfer(A, R)
    values[26] = "601"                          # an interior boundary set by i26
    blocked, _ = sender_policy.recipient_clause_blocks(STREAM_COMPARED, values, R, 900, pool=POOL)
    assert blocked is True
    blocked, _ = sender_policy.recipient_clause_blocks(STREAM_COMPARED, values, R, 100, pool=POOL)
    assert blocked is False
    assert sender_policy.recipient_hold_cap(STREAM_COMPARED, values, R, pool=POOL, held=900) is None
