"""Recipient-side o5 policy gate (issue #47 — Bounty 03, Recipient controls).

The gate itself lives in consensus/recipient_policy.py and is called from
admission (commands/sendtx.py) and apply (consensus/engine.py) with the
same inputs. These tests judge the gate against the issue's acceptance
cases, with the mock policy evaluator, following the conventions of
tests/test_clause_registration.py:

1. R deploys "allow incoming only from A": A -> R passes, B -> R is
   blocked by the recipient's clause.
2. R deploys nothing: everyone can still pay R (neutral default).
3. A pre-existing outbound-only clause (never reads the counterparty)
   must NOT start blocking inbound transfers — the opt-in screen.
4. An inbound amount cap ("refuse incoming above N") blocks above N.
5. A self-transfer is not judged by this gate (the sender pass owns it).
"""
import types

import pytest

import tau_defs
import tau_manager
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex
from consensus import recipient_policy, sender_policy
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import clause_body_v1

STREAM = tau_defs.USER_POLICY_STREAM_INDEX

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CAROL = pubkey_hex(SK_CAROL)

# "Allow incoming only from ALICE": reads the counterparty on i3, the
# stream that carries the sender's full public key (i12 may not be
# referenced by a clause body at all — rule_offers.SENDER_STREAM).
ALLOWLIST_RULE = (
    "always ( (i3[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
ALLOWLIST_BODY = clause_body_v1(ALLOWLIST_RULE)

# "Refuse incoming above 500": scopes itself to inbound transfers by
# reading the counterparty on i3 (any sender other than the owner),
# then caps the amount on i1.
CAP_RULE = (
    "always ( ((i3[t]:bv[384] = { #x" + CAROL + " }:bv[384]) "
    "|| (i1[t]:bv[24] <= { #x0001f4 }:bv[24])) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
CAP_BODY = clause_body_v1(CAP_RULE)

# A legacy outbound whitelist: reads only i4 (the destination). Its verdict
# blocks everything it is asked about — the point is that the recipient
# pass must never ask it about an inbound transfer.
OUTBOUND_RULE = (
    "always ( (i4[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
OUTBOUND_BODY = clause_body_v1(OUTBOUND_RULE)

# Issue #76: "never hold a payment to me longer than 600 seconds". Reads
# ONLY the hold stream i17 — no i3 — which is why the opt-in screen also
# treats a hold-stream read as recipient-relevant.
HOLD600_RULE = (
    "always ( (i17[t]:bv[64] <= { #x258 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
HOLD600_BODY = clause_body_v1(HOLD600_RULE)

# Issue #76: "only payments I get straight away" — a cap of 0.
HOLD0_RULE = (
    "always ( (i17[t]:bv[64] <= { #x0 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
HOLD0_BODY = clause_body_v1(HOLD0_RULE)

# Issue #76: a cap in BLOCKS, on i27.
HOLDB5_RULE = (
    "always ( (i27[t]:bv[64] <= { #x5 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
HOLDB5_BODY = clause_body_v1(HOLDB5_RULE)


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def _evaluator():
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.set_verdict(
        ALLOWLIST_BODY,
        lambda inputs: "1" if ALICE in str(inputs.get("i3", "")) else "0",
    )
    evaluator.set_verdict(
        CAP_BODY,
        lambda inputs: "0"
        if int(inputs.get("i1", "0")) > 500 and CAROL not in str(inputs.get("i3", ""))
        else "1",
    )
    evaluator.set_verdict(OUTBOUND_BODY, "0")
    evaluator.set_verdict(
        HOLD600_BODY,
        lambda inputs: "1" if int(inputs.get("i17", "0")) <= 600 else "0",
    )
    evaluator.set_verdict(
        HOLD0_BODY,
        lambda inputs: "1" if int(inputs.get("i17", "0")) == 0 else "0",
    )
    evaluator.set_verdict(
        HOLDB5_BODY,
        lambda inputs: "1" if int(inputs.get("i27", "0")) <= 5 else "0",
    )
    return evaluator


def _values(sender, recipient, amount):
    """The per-transfer input map, built the way commands/sendtx.py builds it."""
    return {
        1: str(amount),
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        5: "1700000000",
        12: "{ #x" + sender + " }:bv[384]",
    }


def _gate(clauses, sender, recipient, amount, pool="apply", hold=None):
    sender_policy.set_evaluator(pool, _evaluator())
    clause_for = lambda pubkey, stream: clauses.get((pubkey, stream))
    return recipient_policy.recipient_clause_blocks(
        clause_for, sender, recipient, _values(sender, recipient, amount),
        pool=pool, hold=hold,
    )


def test_allowlist_allows_the_listed_sender():
    blocked, _, _ = _gate({(CAROL, STREAM): ALLOWLIST_BODY}, ALICE, CAROL, 100)
    assert blocked is False


def test_allowlist_blocks_an_unlisted_sender():
    blocked, detail, refusal = _gate({(CAROL, STREAM): ALLOWLIST_BODY}, BOB, CAROL, 100)
    assert blocked is True
    assert detail  # the o5 output travels with the refusal
    assert refusal is not None
    assert refusal.reason == recipient_policy.REASON


def test_no_clause_is_neutral():
    blocked, _, _ = _gate({}, BOB, CAROL, 100)
    assert blocked is False


def test_outbound_only_clause_never_blocks_inbound():
    blocked, _, _ = _gate({(CAROL, STREAM): OUTBOUND_BODY}, BOB, CAROL, 100)
    assert blocked is False


def test_inbound_amount_cap():
    clauses = {(CAROL, STREAM): CAP_BODY}
    assert _gate(clauses, ALICE, CAROL, 500)[0] is False
    assert _gate(clauses, ALICE, CAROL, 501)[0] is True


def test_self_transfer_is_not_judged_here():
    blocked, _, _ = _gate({(ALICE, STREAM): ALLOWLIST_BODY}, ALICE, ALICE, 100)
    assert blocked is False


def test_counterparty_screen():
    assert recipient_policy.clause_is_counterparty_aware(ALLOWLIST_BODY)
    assert recipient_policy.clause_is_counterparty_aware(CAP_BODY)
    assert not recipient_policy.clause_is_counterparty_aware(OUTBOUND_BODY)
    # i13 is a custom stream, not the counterparty: the screen must not
    # mistake it for i3.
    assert not recipient_policy.clause_is_counterparty_aware(
        "(i13[t]:bv[24] > { #x000001 }:bv[24])"
    )
    assert not recipient_policy.clause_is_counterparty_aware("")
    assert not recipient_policy.clause_is_counterparty_aware(None)


# --- Issue #76: the recipient hold cap ------------------------------------
# Acceptance cases from the issue:
# 1. R caps holds at 600s: a 10-minute park is admitted; a 1-hour park is
#    refused with RECIPIENT_MAX_HOLD carrying R's cap.
# 2. A cap of 0 admits plain transfers, refuses every park.
# 3. A plain transfer to a capped recipient is admitted.
# 4. A recipient with no cap rule accepts parks of any length.
# (Retract/release non-gating is covered by the chain-level native test:
# retracts never call this gate, and releases call it with hold 0.)

def _hold(seconds=0, blocks=0):
    return {17: seconds, 27: blocks}


def test_hold_cap_admits_a_park_at_the_cap():
    blocked, _, _ = _gate(
        {(CAROL, STREAM): HOLD600_BODY}, ALICE, CAROL, 100, hold=_hold(600))
    assert blocked is False


def test_hold_cap_refuses_a_longer_park_with_the_cap():
    blocked, _, refusal = _gate(
        {(CAROL, STREAM): HOLD600_BODY}, ALICE, CAROL, 100, hold=_hold(3600))
    assert blocked is True
    assert refusal is not None
    assert refusal.reason == recipient_policy.REASON_MAX_HOLD
    assert refusal.max_hold_seconds == 600
    assert refusal.hold_seconds == 3600
    message = recipient_policy.refusal_message(refusal)
    assert "RECIPIENT_MAX_HOLD" in message
    assert "600" in message


def test_hold_cap_zero_admits_plain_refuses_every_park():
    clauses = {(CAROL, STREAM): HOLD0_BODY}
    assert _gate(clauses, ALICE, CAROL, 100)[0] is False
    blocked, _, refusal = _gate(clauses, ALICE, CAROL, 100, hold=_hold(1))
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON_MAX_HOLD
    assert refusal.max_hold_seconds == 0


def test_plain_transfer_to_a_capped_recipient_is_admitted():
    assert _gate({(CAROL, STREAM): HOLD600_BODY}, ALICE, CAROL, 100)[0] is False


def test_no_cap_rule_accepts_parks_of_any_length():
    assert _gate({}, ALICE, CAROL, 100, hold=_hold(7_776_000))[0] is False
    # An allow-list recipient without a cap also accepts long parks.
    assert _gate(
        {(CAROL, STREAM): ALLOWLIST_BODY}, ALICE, CAROL, 100,
        hold=_hold(7_776_000),
    )[0] is False


def test_hold_cap_in_blocks():
    clauses = {(CAROL, STREAM): HOLDB5_BODY}
    assert _gate(clauses, ALICE, CAROL, 100, hold=_hold(blocks=5))[0] is False
    blocked, _, refusal = _gate(clauses, ALICE, CAROL, 100, hold=_hold(blocks=6))
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON_MAX_HOLD
    assert refusal.max_hold_blocks == 5
    # A TIME park feeds 0 on the blocks stream: a blocks-only cap does not
    # bound it (a cap rule must bound both streams to bound both kinds).
    assert _gate(clauses, ALICE, CAROL, 100, hold=_hold(seconds=99999))[0] is False


def test_hold_stream_clause_opts_in_without_i3():
    assert recipient_policy.clause_reads_hold_stream(HOLD600_BODY)
    assert recipient_policy.clause_is_recipient_relevant(HOLD600_BODY)
    assert not recipient_policy.clause_is_counterparty_aware(HOLD600_BODY)
    assert not recipient_policy.clause_reads_hold_stream(ALLOWLIST_BODY)


def test_hold_values_measurement():
    from consensus.retractable import KIND_HEIGHT, KIND_TIME
    assert recipient_policy.hold_values(KIND_TIME, 2000, 50, 1400) == {17: 600, 27: 0}
    assert recipient_policy.hold_values(KIND_HEIGHT, 80, 50, 1400) == {17: 0, 27: 30}
    assert recipient_policy.hold_values(None, 0, 50, 1400) == {17: 0, 27: 0}
    # A release point already reached measures as no hold, never negative.
    assert recipient_policy.hold_values(KIND_TIME, 1000, 50, 1400) == {17: 0, 27: 0}


def test_extract_hold_caps_canonical_forms():
    assert recipient_policy.extract_hold_caps(HOLD600_BODY) == (600, None)
    assert recipient_policy.extract_hold_caps(HOLD0_BODY) == (0, None)
    assert recipient_policy.extract_hold_caps(HOLDB5_BODY) == (None, 5)
    # Strict inequality: hold < 601 caps at 600.
    assert recipient_policy.extract_hold_caps(
        "(i17[t]:bv[64] < { #x259 }:bv[64])") == (600, None)
    # Reversed comparison and a decimal literal.
    assert recipient_policy.extract_hold_caps(
        "({ #x258 }:bv[64] >= i17[t]:bv[64])") == (600, None)
    assert recipient_policy.extract_hold_caps(
        "(i27[t]:bv[64] <= { 42 }:bv[64])") == (None, 42)
    # The most restrictive of several caps is the enforced one.
    assert recipient_policy.extract_hold_caps(
        "(i17[t]:bv[64] <= { #x3e8 }:bv[64]) "
        "(i17[t]:bv[64] <= { #x258 }:bv[64])") == (600, None)
    # Non-canonical shapes extract nothing (the verdict still enforces).
    assert recipient_policy.extract_hold_caps(ALLOWLIST_BODY) == (None, None)
    assert recipient_policy.extract_hold_caps("") == (None, None)


def test_admission_and_apply_pools_agree():
    clauses = {(CAROL, STREAM): HOLD600_BODY}
    for hold, expected in ((_hold(600), False), (_hold(3600), True)):
        verdicts = {
            _gate(clauses, ALICE, CAROL, 100, pool=pool, hold=hold)[0]
            for pool in ("admission", "apply")
        }
        assert verdicts == {expected}


# --- Guarded mode (issue #47) ----------------------------------------------

def _guarded_spec(owner_blocks):
    """A fake accumulated-spec step: o5 blocks exactly when the policy
    owner named by i12 is in `owner_blocks`."""
    seen = []

    def evaluate(values):
        seen.append(dict(values))
        owner = str(values.get(12, ""))
        verdict = "0" if any(key in owner for key in owner_blocks) else "1"
        return {tau_defs.USER_POLICY_STREAM_INDEX: verdict}

    return evaluate, seen


_SPEC_WITH_CAROL = (
    "always ( (i12[t]:bv[384] = { #x" + CAROL + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def test_guarded_pass_blocks_for_the_recipient_unit():
    evaluate, seen = _guarded_spec({CAROL})
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(ALICE, CAROL, 100), ALICE, CAROL,
        spec_text=_SPEC_WITH_CAROL)
    assert blocked is True
    # i12 was re-pointed at the recipient; the counterparty stayed on i3.
    assert CAROL in str(seen[0][12])
    assert ALICE in str(seen[0][3])


def test_guarded_pass_allows_when_the_recipient_unit_allows():
    evaluate, _ = _guarded_spec({BOB})
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(ALICE, CAROL, 100), ALICE, CAROL,
        spec_text=_SPEC_WITH_CAROL)
    assert blocked is False


def test_guarded_pass_neutral_default_and_self_transfer():
    def explode(values):  # pragma: no cover - must never be called
        raise AssertionError("self-transfer must not be evaluated")
    blocked, raw = recipient_policy.guarded_recipient_blocks(
        explode, _values(ALICE, ALICE, 100), ALICE, ALICE)
    assert blocked is False and raw is None
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        lambda values: {}, _values(ALICE, CAROL, 100), ALICE, CAROL,
        spec_text=_SPEC_WITH_CAROL)
    assert blocked is False  # a missing o5 is the neutral default


def test_guarded_pass_prescreen_skips_stepping_without_a_unit():
    def explode(values):  # pragma: no cover - must never be called
        raise AssertionError("no unit for the recipient: must not step")
    # The recipient's key appears nowhere in the spec text: provably no
    # guarded unit, so the pass is skipped without a Tau step.
    blocked, raw = recipient_policy.guarded_recipient_blocks(
        explode, _values(ALICE, CAROL, 100), ALICE, CAROL,
        spec_text="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")
    assert blocked is False and raw is None
    # With the key in the text, the pass steps and can block.
    evaluate, _ = _guarded_spec({CAROL})
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(ALICE, CAROL, 100), ALICE, CAROL,
        spec_text="always ( (i12[t]:bv[384] = { #x" + CAROL + " }:bv[384]) ).")
    assert blocked is True


# --- Spec source of the guarded prescreen ----------------------------------
# Apply pins the prescreen to the parent snapshot (resolve_spec_text in
# consensus/engine.py); admission reads the live tip view (commands/
# sendtx.py passes tau_manager.last_known_tau_spec). That the snapshot
# wins over a moved-on live global is exercised by the adopted PoCs
# (tests/test_poc_live_spec.py); the fallback itself, and the agreement
# of the two entry points on the same state, are ours to keep green here.

def _snapshot(text):
    """Just the attribute resolve_spec_text reads off a snapshot."""
    return types.SimpleNamespace(tau_bytes=text.encode())


def test_resolve_spec_text_falls_back_to_the_live_value(monkeypatch):
    monkeypatch.setattr(tau_manager, "last_known_tau_spec", _SPEC_WITH_CAROL)
    assert recipient_policy.resolve_spec_text(None) == _SPEC_WITH_CAROL
    assert recipient_policy.resolve_spec_text() == _SPEC_WITH_CAROL
    # A snapshot carrying no text falls through to the live value too.
    empty = types.SimpleNamespace(tau_bytes=b"")
    assert recipient_policy.resolve_spec_text(empty) == _SPEC_WITH_CAROL


def test_resolve_spec_text_snapshot_wins_over_the_live_value(monkeypatch):
    monkeypatch.setattr(
        tau_manager, "last_known_tau_spec",
        "always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")
    assert recipient_policy.resolve_spec_text(
        _snapshot(_SPEC_WITH_CAROL)) == _SPEC_WITH_CAROL


def test_admission_and_apply_entry_points_agree(monkeypatch):
    # The same state judged through both call shapes — admission's
    # (spec_text = the live global) and apply's (spec_text =
    # resolve_spec_text(parent snapshot)). While the tip still matches
    # the block, the two must reach the same verdict.
    monkeypatch.setattr(tau_manager, "last_known_tau_spec", _SPEC_WITH_CAROL)
    for owner_blocks, expected in (({CAROL}, True), ({BOB}, False)):
        admission_eval, _ = _guarded_spec(owner_blocks)
        admission = recipient_policy.guarded_recipient_blocks(
            admission_eval, _values(ALICE, CAROL, 100), ALICE, CAROL,
            spec_text=tau_manager.last_known_tau_spec)
        apply_eval, _ = _guarded_spec(owner_blocks)
        applied = recipient_policy.guarded_recipient_blocks(
            apply_eval, _values(ALICE, CAROL, 100), ALICE, CAROL,
            spec_text=recipient_policy.resolve_spec_text(
                _snapshot(_SPEC_WITH_CAROL)))
        assert admission[0] is expected
        assert applied == admission


# --- Capability report (issues #47/#76) ------------------------------------

def test_capability_flags_default_on():
    assert recipient_policy.supported("recipient_policy") is True
    assert recipient_policy.supported("recipient_max_hold") is True
    assert tau_defs.HOST_CAPABILITIES["recipient_policy"] is True


def test_deploy_screen_refuses_a_hold_cap_without_the_gate(monkeypatch):
    from consensus.admission import _screen_clause_domains
    monkeypatch.setitem(tau_defs.HOST_CAPABILITIES, "recipient_max_hold", False)
    error = _screen_clause_domains(HOLD600_BODY)
    assert error is not None and "recipient_max_hold" in error
    # An i3-only inbound rule is not refused at deploy: statically it is a
    # sender-pass clause too; the capabilities report covers the rest.
    assert _screen_clause_domains(ALLOWLIST_BODY) is None


def test_deploy_screen_admits_a_hold_cap_with_the_gate():
    from consensus.admission import _screen_clause_domains
    assert _screen_clause_domains(HOLD600_BODY) is None
