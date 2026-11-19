"""Recipient-side o5 policy gate (issues #47/#76 — Bounty 03, recipient controls).

The gate lives in consensus/recipient_policy.py and is called from admission
(commands/sendtx.py) and apply (consensus/engine.py) with the same inputs.
These tests judge it against the acceptance cases of both issues, with the
mock policy evaluator, following the fixture conventions of
tests/test_approval_admission.py and tests/test_retractable_admission.py.
Chain-level apply semantics (hold caps, retract/release exemptions, replay)
live in tests/test_recipient_hold.py.

Rule shapes (the documented ones):
- A pure inbound allow-list is an i3 disjunction over the approved sender
  keys INCLUDING THE OWNER'S OWN KEY: the sender pass evaluates the same
  clause with i3 = owner, so without the owner every outbound transfer
  would block.
- A combined outbound+inbound unit discriminates direction on i3:
  (i3 = owner) ? <outbound body reading i4> : <inbound body reading i3>.
- o5 is bv[24]: ALLOW = { #x000001 }, BLOCK = { #x000000 }.
"""
import json
import threading
import time
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

import chain_state
import db
import tau_defs
import tau_manager
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from commands import getgovernance
from commands import sendtx as sendtx_module
from consensus import recipient_policy, sender_policy
from consensus.admission import (
    TipAdmissionView,
    _check_host_contract_patch,
    _screen_clause,
    validate_o5_clause_routing,
    validate_user_tx_reserved_domains,
)
from consensus.governance import (
    HOST_CONTRACT_PATCH_KEYS,
    ConsensusLifecycleManager,
    ConsensusRuleUpdate,
    build_mechanism_metadata,
    validate_recipient_policy_active,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import KIND_HEIGHT, KIND_TIME, MAX_RELEASE_WINDOW_SECONDS
from consensus.rule_offers import clause_body_v1

from test_approval_activation import _legacy_meta_hash
from test_approval_persistence import _reload, _seed_state
from test_retractable_admission import (
    _mempool_hashes,
    _retract_payload,
    _seed_open_entry,
)

SENDER = pubkey_hex(SK_ALICE)      # A — the listed payer
RECIPIENT = pubkey_hex(SK_BOB)     # R — the account deploying the rule
THIRD = pubkey_hex(SK_CAROL)       # B — the stranger
STREAM = tau_defs.USER_POLICY_STREAM_INDEX
NEXT_HEIGHT = 50
FAR = 9_999_999_999

# A time park's expiration_time is judged against the wall clock, so the tip
# AND the clock sendtx reads are both pinned to this instant: no test depends
# on how long the suite has run.
NOW = int(time.time())


class _PinnedClock:
    """`time`, with `time()` pinned."""

    def time(self):
        return float(NOW)

    def __getattr__(self, name):
        return getattr(time, name)


# --- the documented rule shapes, as clause bodies ----------------------------

ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def _is(stream, pubkey):
    return "(%s[t]:bv[384] = { #x%s }:bv[384])" % (stream, pubkey)


def allow_list_body(*senders):
    """Only these senders may pay the owner. The owner's own key belongs in
    the list: the sender pass judges the owner's outbound transfers on the
    same clause with i3 = owner."""
    listed = " || ".join(_is("i3", s) for s in senders)
    return "( ( %s ) ? %s : %s )" % (listed, ALLOW, BLOCK)


def allow_list_model(*senders):
    def decide(inputs):
        return "1" if any(s in str(inputs.get("i3", "")) for s in senders) else "0"
    return decide


def hold_cap_body(seconds=None, blocks=None):
    """A cap on the hold streams: i17 seconds, i27 blocks. A cap bounds
    whichever stream it reads; to bound both park kinds it bounds both."""
    conds = []
    if seconds is not None:
        conds.append("(i17[t]:bv[64] <= { %d }:bv[64])" % seconds)
    if blocks is not None:
        conds.append("(i27[t]:bv[64] <= { %d }:bv[64])" % blocks)
    return "( ( %s ) ? %s : %s )" % (" && ".join(conds), ALLOW, BLOCK)


def hold_cap_model(seconds=None, blocks=None):
    def decide(inputs):
        if seconds is not None and int(str(inputs.get("i17", "0")) or 0) > seconds:
            return "0"
        if blocks is not None and int(str(inputs.get("i27", "0")) or 0) > blocks:
            return "0"
        return "1"
    return decide


def one_unit_body(owner, pay_only, accept_only_from):
    """Outbound whitelist + inbound allow-list in ONE clause, discriminating
    direction on i3 (the sender pass feeds i3 = owner)."""
    outbound = "( %s && !%s )" % (_is("i3", owner), _is("i4", pay_only))
    inbound = "( !%s && !%s )" % (_is("i3", owner), _is("i3", accept_only_from))
    return "( ( %s || %s ) ? %s : %s )" % (outbound, inbound, BLOCK, ALLOW)


def one_unit_model(owner, pay_only, accept_only_from):
    def decide(inputs):
        if owner in str(inputs.get("i3", "")):
            return "1" if pay_only in str(inputs.get("i4", "")) else "0"
        return "1" if accept_only_from in str(inputs.get("i3", "")) else "0"
    return decide


# A legacy outbound whitelist reading only i4. Its verdict blocks everything
# it is asked about — the point is that the recipient pass must NEVER ask it
# about an inbound transfer (the opt-in screen).
OUTBOUND_BODY = "( ( %s ) ? %s : %s )" % (_is("i4", SENDER), ALLOW, BLOCK)

# The acceptance rules, pre-built.
ALLOWLIST_BODY = allow_list_body(SENDER, RECIPIENT)
ALLOWLIST_MODEL = allow_list_model(SENDER, RECIPIENT)
INSTANT_BODY = hold_cap_body(seconds=0, blocks=0)
INSTANT_MODEL = hold_cap_model(seconds=0, blocks=0)
HOLD600_BODY = hold_cap_body(seconds=600)
HOLD600_MODEL = hold_cap_model(seconds=600)
HOLDB5_BODY = hold_cap_body(blocks=5)
HOLDB5_MODEL = hold_cap_model(blocks=5)
ONE_UNIT_BODY = one_unit_body(RECIPIENT, THIRD, SENDER)
ONE_UNIT_MODEL = one_unit_model(RECIPIENT, THIRD, SENDER)


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


@pytest.fixture(autouse=True)
def _restore_genesis_recipient_flag(monkeypatch):
    """Keep the genesis recipient flag of one test out of the next (the
    approval-slot twin lives in conftest; this one belongs to this feature)."""
    monkeypatch.setattr(chain_state, "_genesis_recipient_policy_active",
                        chain_state._genesis_recipient_policy_active)


def _values(sender, recipient, amount=100):
    """The per-transfer input map, built the way commands/sendtx.py builds it."""
    return {
        1: str(amount),
        2: "1000000",
        3: "{ #x" + sender + " }:bv[384]",
        4: "{ #x" + recipient + " }:bv[384]",
        5: str(NOW),
        12: "{ #x" + sender + " }:bv[384]",
    }


def _hold(seconds=0, blocks=0):
    return {tau_defs.HOLD_SECONDS_STREAM_INDEX: seconds,
            tau_defs.HOLD_BLOCKS_STREAM_INDEX: blocks}


def _ask(ev, clauses, sender, recipient, amount=100, pool="apply", hold=None):
    sender_policy.set_evaluator(pool, ev)
    clause_for = lambda pubkey, stream: clauses.get((pubkey, stream))
    return recipient_policy.recipient_clause_blocks(
        clause_for, sender, recipient, _values(sender, recipient, amount),
        pool=pool, hold=hold,
    )


# --- #47: the gate itself -----------------------------------------------------

def test_allowlist_allows_the_listed_sender():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(ALLOWLIST_BODY, ALLOWLIST_MODEL)
    blocked, _, refusal = _ask(ev, {(RECIPIENT, STREAM): ALLOWLIST_BODY},
                               SENDER, RECIPIENT)
    assert blocked is False and refusal is None


def test_allowlist_blocks_a_stranger_with_the_recipient_reason():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(ALLOWLIST_BODY, ALLOWLIST_MODEL)
    blocked, detail, refusal = _ask(ev, {(RECIPIENT, STREAM): ALLOWLIST_BODY},
                                    THIRD, RECIPIENT)
    assert blocked is True
    assert detail  # the o5 output travels with the refusal
    assert refusal is not None
    assert refusal.reason == recipient_policy.REASON == "recipient_policy_block"
    assert "recipient policy" in recipient_policy.refusal_message(refusal)


def test_no_clause_is_neutral():
    ev = MockPolicyEvaluator(pool="apply")
    assert _ask(ev, {}, THIRD, RECIPIENT)[0] is False
    assert ev.verdict_calls == []


def test_outbound_only_clause_is_never_asked_inbound():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(OUTBOUND_BODY, "0")  # would block everything if asked
    assert _ask(ev, {(RECIPIENT, STREAM): OUTBOUND_BODY}, THIRD, RECIPIENT)[0] is False
    assert ev.verdict_calls == [], "the opt-in screen must skip a pure i4 clause"


def test_self_transfer_is_not_judged_here():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(ALLOWLIST_BODY, "0")
    assert _ask(ev, {(SENDER, STREAM): ALLOWLIST_BODY}, SENDER, SENDER)[0] is False
    assert ev.verdict_calls == []


def test_inbound_amount_cap_reads_i1():
    body = "( ( %s || (i1[t]:bv[24] <= { #x0001f4 }:bv[24]) ) ? %s : %s )" % (
        _is("i3", RECIPIENT), ALLOW, BLOCK)

    def model(inputs):
        if RECIPIENT in str(inputs.get("i3", "")):
            return "1"
        return "1" if int(str(inputs.get("i1", "0"))) <= 500 else "0"

    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(body, model)
    clauses = {(RECIPIENT, STREAM): body}
    assert _ask(ev, clauses, THIRD, RECIPIENT, amount=500)[0] is False
    assert _ask(ev, clauses, THIRD, RECIPIENT, amount=501)[0] is True


def test_sender_supplied_hold_values_never_reach_the_recipient_clause():
    ev = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", ev)
    ev.set_verdict(HOLD600_BODY, HOLD600_MODEL)
    values = _values(SENDER, RECIPIENT)
    values[17] = "999999"  # a forged custom value must be overwritten
    values[27] = "999999"
    clause_for = lambda pubkey, stream: HOLD600_BODY
    blocked, _, _ = recipient_policy.recipient_clause_blocks(
        clause_for, SENDER, RECIPIENT, values, pool="apply", hold=_hold(600))
    assert blocked is False
    (_, inputs), = ev.verdict_calls
    assert inputs["i17"] == "600" and inputs["i27"] == "0"
    assert values[17] == "999999", "the sender pass's map is not mutated"


def test_plain_transfer_forces_zero_on_both_hold_streams():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(INSTANT_BODY, INSTANT_MODEL)
    assert _ask(ev, {(RECIPIENT, STREAM): INSTANT_BODY}, SENDER, RECIPIENT)[0] is False
    (_, inputs), = ev.verdict_calls
    assert inputs["i17"] == "0" and inputs["i27"] == "0"


def test_admission_and_apply_pools_agree():
    clauses = {(RECIPIENT, STREAM): HOLD600_BODY}
    for hold, expected in ((_hold(600), False), (_hold(3600), True)):
        verdicts = set()
        for pool in ("admission", "apply"):
            ev = MockPolicyEvaluator(pool=pool)
            ev.set_verdict(HOLD600_BODY, HOLD600_MODEL)
            verdicts.add(_ask(ev, clauses, SENDER, RECIPIENT, pool=pool, hold=hold)[0])
        assert verdicts == {expected}


# --- #76: hold measurement and cap extraction ---------------------------------

def test_hold_values_measurement():
    assert recipient_policy.hold_values(KIND_TIME, 2000, 50, 1400) == {17: 600, 27: 0}
    assert recipient_policy.hold_values(KIND_HEIGHT, 80, 50, 1400) == {17: 0, 27: 30}
    assert recipient_policy.hold_values(None, 0, 50, 1400) == {17: 0, 27: 0}
    # A release point already reached measures as no hold, never negative.
    assert recipient_policy.hold_values(KIND_TIME, 1000, 50, 1400) == {17: 0, 27: 0}
    assert recipient_policy.hold_values(KIND_HEIGHT, 40, 50, 1400) == {17: 0, 27: 0}


def test_extract_hold_caps_canonical_forms():
    assert recipient_policy.extract_hold_caps(HOLD600_BODY) == (600, None)
    assert recipient_policy.extract_hold_caps(INSTANT_BODY) == (0, 0)
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
    # Comments do not declare caps; non-canonical shapes extract nothing.
    assert recipient_policy.extract_hold_caps(
        "# i17[t]:bv[64] <= { 5 }:bv[64]\n(i1[t]:bv[24] > { 0 }:bv[24])") == (None, None)
    assert recipient_policy.extract_hold_caps(ALLOWLIST_BODY) == (None, None)
    assert recipient_policy.extract_hold_caps("") == (None, None)


def test_hold_cap_refusal_carries_the_cap():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(HOLD600_BODY, HOLD600_MODEL)
    blocked, _, refusal = _ask(ev, {(RECIPIENT, STREAM): HOLD600_BODY},
                               SENDER, RECIPIENT, hold=_hold(3600))
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON_MAX_HOLD == "recipient_max_hold"
    assert refusal.max_hold_seconds == 600
    assert refusal.max_hold_blocks is None
    assert refusal.hold_seconds == 3600 and refusal.hold_blocks == 0
    message = recipient_policy.refusal_message(refusal)
    assert "RECIPIENT_MAX_HOLD" in message and "600" in message and "3600" in message


def test_hold_cap_in_blocks():
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(HOLDB5_BODY, HOLDB5_MODEL)
    clauses = {(RECIPIENT, STREAM): HOLDB5_BODY}
    assert _ask(ev, clauses, SENDER, RECIPIENT, hold=_hold(blocks=5))[0] is False
    blocked, _, refusal = _ask(ev, clauses, SENDER, RECIPIENT, hold=_hold(blocks=6))
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON_MAX_HOLD
    assert refusal.max_hold_blocks == 5 and refusal.hold_blocks == 6
    # A TIME park feeds 0 on the blocks stream: a blocks-only cap does not
    # bound it (a cap rule must bound both streams to bound both kinds).
    assert _ask(ev, clauses, SENDER, RECIPIENT, hold=_hold(seconds=99999))[0] is False


def test_allowlist_refusal_of_a_park_is_not_a_hold_refusal():
    """The allow-list refuses this sender whatever the hold: no cap to report."""
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(ALLOWLIST_BODY, ALLOWLIST_MODEL)
    blocked, _, refusal = _ask(ev, {(RECIPIENT, STREAM): ALLOWLIST_BODY},
                               THIRD, RECIPIENT, hold=_hold(600))
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON


def test_non_canonical_cap_still_enforces_without_a_numeric_cap():
    # A cap written as a negated comparison: the verdict decides, the textual
    # extractor finds no canonical cap, the refusal reports the measured hold.
    body = "( !(i17[t]:bv[64] > { #x258 }:bv[64]) ? %s : %s )" % (ALLOW, BLOCK)
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(body, HOLD600_MODEL)
    blocked, _, refusal = _ask(ev, {(RECIPIENT, STREAM): body},
                               SENDER, RECIPIENT, hold=_hold(3600))
    assert blocked is True
    assert refusal.reason == recipient_policy.REASON_MAX_HOLD
    assert refusal.max_hold_seconds is None
    assert refusal.hold_seconds == 3600
    assert "3600" in recipient_policy.refusal_message(refusal)


# --- the opt-in screen ---------------------------------------------------------

def test_clause_is_recipient_relevant():
    assert recipient_policy.clause_is_recipient_relevant(ALLOWLIST_BODY)
    assert recipient_policy.clause_is_recipient_relevant(HOLD600_BODY)
    assert recipient_policy.clause_is_recipient_relevant(HOLDB5_BODY)
    assert not recipient_policy.clause_is_recipient_relevant(OUTBOUND_BODY)
    # i13 is a custom stream, not the counterparty; i170 is not i17.
    assert not recipient_policy.clause_is_recipient_relevant(
        "(i13[t]:bv[24] > { #x000001 }:bv[24])")
    assert not recipient_policy.clause_is_recipient_relevant(
        "(i170[t]:bv[64] > { 0 }:bv[64])")
    # A stream named only in a comment does not opt in.
    assert not recipient_policy.clause_is_recipient_relevant(
        "# i3[t] and i17[t] later\n(i1[t]:bv[24] > { 0 }:bv[24])")
    assert not recipient_policy.clause_is_recipient_relevant("")
    assert not recipient_policy.clause_is_recipient_relevant(None)


# --- guarded mode (issue #47) ---------------------------------------------------

def _guarded_spec(owner_blocks):
    """A fake accumulated-spec step: o5 blocks exactly when the policy owner
    named by i12 is in `owner_blocks`."""
    seen = []

    def evaluate(values):
        seen.append(dict(values))
        owner = str(values.get(12, ""))
        verdict = "0" if any(key in owner for key in owner_blocks) else "1"
        return {tau_defs.USER_POLICY_STREAM_INDEX: verdict}

    return evaluate, seen


_SPEC_WITH_RECIPIENT = (
    "always ( (i12[t]:bv[384] = { #x" + RECIPIENT + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def test_guarded_pass_blocks_for_the_recipient_unit():
    evaluate, seen = _guarded_spec({RECIPIENT})
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(SENDER, RECIPIENT), SENDER, RECIPIENT,
        spec_text=_SPEC_WITH_RECIPIENT)
    assert blocked is True
    # i12 was re-pointed at the recipient; the counterparty stayed on i3.
    assert RECIPIENT in str(seen[0][12])
    assert SENDER in str(seen[0][3])


def test_guarded_pass_allows_when_the_recipient_unit_allows():
    evaluate, _ = _guarded_spec({THIRD})
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(SENDER, RECIPIENT), SENDER, RECIPIENT,
        spec_text=_SPEC_WITH_RECIPIENT)
    assert blocked is False


def test_guarded_pass_forces_the_hold_streams():
    evaluate, seen = _guarded_spec(set())
    recipient_policy.guarded_recipient_blocks(
        evaluate, _values(SENDER, RECIPIENT), SENDER, RECIPIENT,
        spec_text=_SPEC_WITH_RECIPIENT, hold=_hold(600))
    assert seen[0][17] == "600" and seen[0][27] == "0"
    recipient_policy.guarded_recipient_blocks(
        evaluate, _values(SENDER, RECIPIENT), SENDER, RECIPIENT,
        spec_text=_SPEC_WITH_RECIPIENT)
    assert seen[1][17] == "0" and seen[1][27] == "0"


def test_guarded_pass_neutral_default_and_self_transfer():
    def explode(values):  # pragma: no cover - must never be called
        raise AssertionError("self-transfer must not be evaluated")

    blocked, raw = recipient_policy.guarded_recipient_blocks(
        explode, _values(SENDER, SENDER), SENDER, SENDER)
    assert blocked is False and raw is None
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        lambda values: {}, _values(SENDER, RECIPIENT), SENDER, RECIPIENT,
        spec_text=_SPEC_WITH_RECIPIENT)
    assert blocked is False  # a missing o5 is the neutral default


def test_guarded_pass_prescreen_skips_stepping_without_a_unit():
    def explode(values):  # pragma: no cover - must never be called
        raise AssertionError("no unit for the recipient: must not step")

    # The recipient's key appears nowhere in the spec text: provably no
    # guarded unit, so the pass is skipped without a Tau step.
    blocked, raw = recipient_policy.guarded_recipient_blocks(
        explode, _values(SENDER, RECIPIENT), SENDER, RECIPIENT,
        spec_text="always ( o5[t]:bv[24] = { #x000001 }:bv[24] ).")
    assert blocked is False and raw is None
    # An unknown spec also skips: no spec, no units.
    blocked, raw = recipient_policy.guarded_recipient_blocks(
        explode, _values(SENDER, RECIPIENT), SENDER, RECIPIENT, spec_text=None)
    assert blocked is False and raw is None
    # With the key in the text, the pass steps and can block.
    evaluate, _ = _guarded_spec({RECIPIENT})
    blocked, _ = recipient_policy.guarded_recipient_blocks(
        evaluate, _values(SENDER, RECIPIENT), SENDER, RECIPIENT,
        spec_text=_SPEC_WITH_RECIPIENT)
    assert blocked is True


# --- admission end to end (queue_transaction / checktx) -------------------------

@pytest.fixture
def ev():
    evaluator = MockPolicyEvaluator(pool="admission")
    sender_policy.set_evaluator("admission", evaluator)
    yield evaluator
    sender_policy.set_evaluator("admission", None)


@pytest.fixture
def node(temp_database, monkeypatch, ev):
    """A real database, real signatures, a scriptable Tau, and a tip whose
    recipient-policy flag is ON with a patchable clause registry."""
    script = {"fee": 0, "custom": 0, "block_o5": False,
              "guarded_block_keys": set(), "calls": []}

    def multi(**kwargs):
        script["calls"].append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        owner = str(vals.get(12, ""))
        blocked = script["block_o5"] or any(
            key in owner for key in script["guarded_block_keys"])
        return {1: str(vals.get(1, "0")), 5: "0" if blocked else "1",
                8: str(script["custom"]), 9: str(script["fee"])}

    lm = ConsensusLifecycleManager()
    lm.activate_recipient_policy()
    clauses = {}

    patches = [
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau", return_value="x1001"),
        patch("tau_manager.communicate_with_tau_multi", side_effect=multi),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch("commands.sendtx.validate_bls_pubkey", return_value=None),
        patch.object(chain_state, "_lifecycle_manager", lm),
        patch.object(TipAdmissionView, "clause_for",
                     lambda _self, account, stream: clauses.get(
                         (str(account).lower(), int(stream)))),
        patch.object(TipAdmissionView, "next_block_height",
                     new_callable=PropertyMock, return_value=NEXT_HEIGHT),
        patch.object(TipAdmissionView, "tip_timestamp",
                     new_callable=PropertyMock, return_value=NOW),
        patch.object(TipAdmissionView, "next_block_timestamp",
                     new_callable=PropertyMock, return_value=NOW),
        patch.object(sendtx_module, "time", _PinnedClock()),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
    ]
    mocks = [p.start() for p in patches]
    mocks[0].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    monkeypatch.setitem(chain_state._balances, RECIPIENT, 1_000_000)
    monkeypatch.setitem(chain_state._balances, THIRD, 1_000_000)
    yield sendtx_module, script, lm, clauses
    for p in reversed(patches):
        p.stop()


def _rule(clauses, ev, account, body, model):
    clauses[(account, STREAM)] = body
    ev.set_verdict(body, model)
    return body


def _transfer(*legs, sender=SENDER, sk=SK_ALICE, seq=1, extra_ops=None):
    ops = {"1": [[sender, to, str(amount)] for to, amount in legs]}
    ops.update(extra_ops or {})
    return sign_payload({
        "tx_type": "user_tx", "sender_pubkey": sender, "sequence_number": seq,
        "expiration_time": NOW + 3600, "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "100", "operations": ops,
    }, sk)


def _park(release_at_time=None, release_at_height=None, recipient=RECIPIENT,
          amount=100, seq=1):
    tx = {
        "tx_type": "retractable_transfer", "sender_pubkey": SENDER,
        "sequence_number": seq, "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20, "fee_limit": "100",
        "recipient_pubkey": recipient, "amount": amount,
    }
    if release_at_time is not None:
        tx["release_at_time"] = release_at_time
        # The deadline must sit strictly before the release (and after NOW).
        tx["expiration_time"] = release_at_time - 1
    else:
        release = (release_at_height if release_at_height is not None
                   else NEXT_HEIGHT + 30)
        tx["release_at_height"] = release
        # A height park's deadline may equal but not exceed its release.
        tx["expire_at_height"] = min(NEXT_HEIGHT + 20, release)
    return sign_payload(tx, SK_ALICE)


def _queue(sendtx, payload, **kw):
    return sendtx.queue_transaction(json.dumps(payload), propagate=False, **kw)


# --- #47 acceptance at admission ------------------------------------------------

def test_admission_listed_sender_passes_and_stranger_is_refused(node, ev):
    """#47 case 1: A -> R passes, B -> R is refused with the recipient reason,
    A's own send policy is untouched."""
    sendtx, script, lm, clauses = node
    _rule(clauses, ev, RECIPIENT, ALLOWLIST_BODY, ALLOWLIST_MODEL)

    ok = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert ok["ok"], ok
    # The recipient clause was asked on the transfer's own inputs.
    asked = [inputs for body, inputs in ev.verdict_calls if body == ALLOWLIST_BODY]
    assert asked and asked[-1]["i3"] == "#x" + SENDER
    assert asked[-1]["i1"] == "25"

    refused = _queue(sendtx, _transfer((RECIPIENT, 25), sender=THIRD, sk=SK_CAROL))
    assert refused["ok"] is False
    assert refused["code"] == "TX_REJECTED"
    assert "Transaction rejected by recipient policy (o5)" in refused["message"]
    assert "transfer #1" in refused["message"]
    assert refused["details"]["transfer_index"] == 1

    # A's own payments elsewhere are untouched by R's rule.
    assert _queue(sendtx, _transfer((THIRD, 5), seq=2))["ok"]


def test_admission_neutral_default(node, ev):
    """#47 case 2: R deploys nothing — everyone can still pay R."""
    sendtx, script, lm, clauses = node
    assert _queue(sendtx, _transfer((RECIPIENT, 25)))["ok"]
    assert _queue(sendtx, _transfer((RECIPIENT, 25), sender=THIRD, sk=SK_CAROL))["ok"]
    assert ev.verdict_calls == []


def test_admission_batch_atomicity(node, ev):
    """#47 case 3: one refusing recipient fails the whole batch, naming the leg."""
    sendtx, script, lm, clauses = node
    # THIRD's allow-list does NOT name A: leg 2 refuses A.
    _rule(clauses, ev, THIRD, allow_list_body(THIRD), allow_list_model(THIRD))
    # Leg 1 to R (no rule) passes, leg 2 to THIRD refuses A.
    refused = _queue(sendtx, _transfer((RECIPIENT, 5), (THIRD, 5)))
    assert refused["ok"] is False
    assert refused["code"] == "TX_REJECTED"
    assert "recipient policy" in refused["message"]
    assert refused["details"]["transfer_index"] == 2
    assert _mempool_hashes() == []


def test_admission_one_unit_enforces_both_directions(node, ev):
    """#47 case 4: R's inbound rule and outbound whitelist live in ONE unit."""
    sendtx, script, lm, clauses = node
    _rule(clauses, ev, RECIPIENT, ONE_UNIT_BODY, ONE_UNIT_MODEL)

    # R pays THIRD (the whitelisted destination): allowed.
    assert _queue(sendtx, _transfer((THIRD, 7), sender=RECIPIENT, sk=SK_BOB))["ok"]
    # A pays R: allowed inbound.
    assert _queue(sendtx, _transfer((RECIPIENT, 7)))["ok"]
    # R pays anyone else: refused by R's own SENDER pass.
    out = _queue(sendtx, _transfer((SENDER, 7), sender=RECIPIENT, sk=SK_BOB, seq=2))
    assert out["ok"] is False and out["code"] == "TX_REJECTED"
    assert "sender's own policy clause" in out["message"]
    # Anyone else pays R: refused by the RECIPIENT pass.
    inc = _queue(sendtx, _transfer((RECIPIENT, 7), sender=THIRD, sk=SK_CAROL))
    assert inc["ok"] is False and inc["code"] == "TX_REJECTED"
    assert "recipient policy" in inc["message"]


def test_admission_checktx_dry_run_reports_the_same_refusal(node, ev):
    sendtx, script, lm, clauses = node
    _rule(clauses, ev, RECIPIENT, ALLOWLIST_BODY, ALLOWLIST_MODEL)
    payload = _transfer((RECIPIENT, 25), sender=THIRD, sk=SK_CAROL)
    refused = _queue(sendtx, payload, dry_run=True)
    assert refused["ok"] is False and refused["code"] == "TX_REJECTED"
    assert "recipient policy" in refused["message"]
    assert _mempool_hashes() == []
    # And the listed sender passes the same dry run.
    assert _queue(sendtx, _transfer((RECIPIENT, 25)), dry_run=True)["ok"]


def test_admission_senders_own_block_comes_first(node, ev):
    sendtx, script, lm, clauses = node
    body = _rule(clauses, ev, RECIPIENT, ALLOWLIST_BODY, ALLOWLIST_MODEL)
    spend = "( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? %s : %s )" % (BLOCK, ALLOW)
    _rule(clauses, ev, SENDER, spend,
          lambda inputs: "0" if int(str(inputs.get("i1", "0"))) > 1000 else "1")
    refused = _queue(sendtx, _transfer((RECIPIENT, 5000)))
    assert refused["ok"] is False and refused["code"] == "TX_REJECTED"
    assert "sender's own policy clause" in refused["message"]
    assert [i for b, i in ev.verdict_calls if b == body] == [], \
        "the recipient is not asked when the sender's side already refused"


def test_admission_owner_outbound_under_cap_clause_passes(node, ev):
    """Correction: the sender pass feeds i17=0/i27=0 while active, so the
    owner's own cap clause never blocks its outbound transfers."""
    sendtx, script, lm, clauses = node
    for seq, (body, model) in enumerate(
            ((HOLD600_BODY, HOLD600_MODEL),
             (INSTANT_BODY, INSTANT_MODEL),
             (ALLOWLIST_BODY, ALLOWLIST_MODEL)), start=1):
        clauses.clear()
        ev.set_verdict(body, model)
        clauses[(RECIPIENT, STREAM)] = body
        ok = _queue(sendtx, _transfer((THIRD, 9), sender=RECIPIENT, sk=SK_BOB, seq=seq))
        assert ok["ok"], (body, ok)
        # The sender pass saw explicit zeros on the hold streams.
        sender_inputs = script["calls"][-1]["input_stream_values"]
        assert sender_inputs[17] == "0" and sender_inputs[27] == "0"


def test_admission_nothing_is_asked_on_an_inactive_chain(node, ev):
    sendtx, script, lm, clauses = node
    lm.recipient_policy_active = False
    body = _rule(clauses, ev, RECIPIENT, ALLOWLIST_BODY, ALLOWLIST_MODEL)
    assert _queue(sendtx, _transfer((RECIPIENT, 25), sender=THIRD, sk=SK_CAROL))["ok"]
    assert [i for b, i in ev.verdict_calls if b == body] == []
    # And the sender pass does not feed the hold streams while inactive.
    assert 17 not in script["calls"][-1]["input_stream_values"]


def test_admission_guarded_recipient_unit_blocks_inbound(node, ev):
    sendtx, script, lm, clauses = node
    script["guarded_block_keys"] = {RECIPIENT}
    with patch.object(tau_manager, "last_known_tau_spec", _SPEC_WITH_RECIPIENT):
        refused = _queue(sendtx, _transfer((RECIPIENT, 25)))
        assert refused["ok"] is False and refused["code"] == "TX_REJECTED"
        assert "recipient policy" in refused["message"]
        # Two steps: the sender pass (i12 = sender) and the recipient pass
        # (i12 = recipient).
        owners = [str(c["input_stream_values"].get(12, "")) for c in script["calls"]]
        assert any(SENDER in o for o in owners)
        assert any(RECIPIENT in o for o in owners)
        # A payment to an account with no guarded unit is untouched: the
        # pre-screen finds THIRD's key absent from the spec and skips.
        assert _queue(sendtx, _transfer((THIRD, 25)))["ok"]


def test_admission_guarded_prescreen_skips_the_extra_step(node, ev):
    sendtx, script, lm, clauses = node
    script["guarded_block_keys"] = {RECIPIENT}
    # The recipient's key is absent from the spec: no extra step is spent.
    with patch.object(tau_manager, "last_known_tau_spec",
                      "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."):
        assert _queue(sendtx, _transfer((RECIPIENT, 25)))["ok"]
        assert len(script["calls"]) == 1, "only the sender pass stepped"


# --- #76 acceptance at admission -------------------------------------------------

def test_admission_cap_zero_plain_passes_every_park_refused(node, ev):
    """#76 cases 1 and 5: cap 0 admits plain transfers, refuses every park
    with RECIPIENT_MAX_HOLD carrying the cap."""
    sendtx, script, lm, clauses = node
    _rule(clauses, ev, RECIPIENT, INSTANT_BODY, INSTANT_MODEL)

    assert _queue(sendtx, _transfer((RECIPIENT, 25)))["ok"]

    # The plain transfer consumed sequence 1; refused parks do not bump it.
    for park in (_park(release_at_time=NOW + 300, seq=2),
                 _park(release_at_time=NOW + 86_400, seq=2),
                 _park(release_at_height=NEXT_HEIGHT + 30, seq=2)):
        refused = _queue(sendtx, park)
        assert refused["ok"] is False, refused
        assert refused["code"] == "RECIPIENT_MAX_HOLD"
        assert refused["details"]["max_hold_seconds"] == 0
        assert refused["details"]["max_hold_blocks"] == 0
        assert "RECIPIENT_MAX_HOLD" in refused["message"]
        assert "0" in refused["message"]
    # Only the plain transfer is in the mempool; no park was queued.
    assert len(_mempool_hashes()) == 1


def test_admission_cap_600_takes_ten_minutes_refuses_an_hour(node, ev):
    """#76 case 2, with the refusal details a wallet prints."""
    sendtx, script, lm, clauses = node
    _rule(clauses, ev, RECIPIENT, HOLD600_BODY, HOLD600_MODEL)

    inside = _queue(sendtx, _park(release_at_time=NOW + 600))
    assert inside["ok"], inside
    asked = [i for b, i in ev.verdict_calls if b == HOLD600_BODY]
    assert asked[-1]["i17"] == "600" and asked[-1]["i27"] == "0"

    hour = _queue(sendtx, _park(release_at_time=NOW + 3600, seq=2))
    assert hour["ok"] is False and hour["code"] == "RECIPIENT_MAX_HOLD"
    assert hour["details"]["max_hold_seconds"] == 600
    assert hour["details"]["hold_seconds"] == 3600
    assert hour["details"]["hold_blocks"] == 0
    assert hour["details"]["transfer_index"] == 1
    assert "600" in hour["message"] and "3600" in hour["message"]


def test_admission_height_park_under_a_blocks_cap(node, ev):
    sendtx, script, lm, clauses = node
    _rule(clauses, ev, RECIPIENT, HOLDB5_BODY, HOLDB5_MODEL)
    inside = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 5))
    assert inside["ok"], inside
    asked = [i for b, i in ev.verdict_calls if b == HOLDB5_BODY]
    assert asked[-1]["i27"] == "5" and asked[-1]["i17"] == "0"
    over = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 6, seq=2))
    assert over["ok"] is False and over["code"] == "RECIPIENT_MAX_HOLD"
    assert over["details"]["max_hold_blocks"] == 5
    assert over["details"]["hold_blocks"] == 6
    # A seconds-only cap does not bound a height park (it feeds i17 = 0).
    clauses[(RECIPIENT, STREAM)] = HOLD600_BODY
    ev.set_verdict(HOLD600_BODY, HOLD600_MODEL)
    assert _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 50, seq=2))["ok"]


def test_admission_neutral_recipient_takes_parks_of_any_length(node, ev):
    """#76 case 3: no cap deployed — parks of any length pass."""
    sendtx, script, lm, clauses = node
    longest = _queue(sendtx, _park(release_at_time=NOW + MAX_RELEASE_WINDOW_SECONDS))
    assert longest["ok"], longest
    by_height = _queue(sendtx, _park(seq=2))
    assert by_height["ok"], by_height
    assert ev.verdict_calls == []


def test_admission_retract_is_admitted_whatever_the_cap(node, ev):
    """#76 case 4: a retract never passes the gate."""
    sendtx, script, lm, clauses = node
    body = _rule(clauses, ev, RECIPIENT, INSTANT_BODY, INSTANT_MODEL)
    rid = _seed_open_entry(_park(release_at_time=NOW + 600))
    result = _queue(sendtx, _retract_payload(rid, sequence_number=1))
    assert result["ok"], result
    assert [i for b, i in ev.verdict_calls if b == body] == []


def test_admission_park_refused_for_a_non_hold_reason_is_not_max_hold(node, ev):
    sendtx, script, lm, clauses = node
    _rule(clauses, ev, RECIPIENT, ALLOWLIST_BODY, ALLOWLIST_MODEL)
    refused = _queue(sendtx, _park(release_at_time=NOW + 600, recipient=RECIPIENT))
    # A is listed, so this passes; the stranger's park is a plain policy block.
    assert refused["ok"], refused
    stranger = sign_payload({
        "tx_type": "retractable_transfer", "sender_pubkey": THIRD,
        "sequence_number": 1, "expiration_time": NOW + 599,
        "expire_at_height": NEXT_HEIGHT + 20, "fee_limit": "100",
        "recipient_pubkey": RECIPIENT, "amount": 100,
        "release_at_time": NOW + 600,
    }, SK_CAROL)
    refused = _queue(sendtx, stranger)
    assert refused["ok"] is False and refused["code"] == "TX_REJECTED"
    assert "max_hold_seconds" not in refused.get("details", {})


# --- deploy-time screens ----------------------------------------------------------

def _view(active):
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {SENDER}
    view.next_block_height = NEXT_HEIGHT
    view.next_block_timestamp = NOW
    view.eligibility_mode = ""
    view.approval_slots_active = False
    view.recipient_policy_active = active
    view.clause_for.return_value = None
    view.get_rule_change_request.return_value = None
    view.get_offer.return_value = None
    view.get_approval_request.return_value = None
    view.open_requests_for_sender.return_value = 0
    view.open_requests_for_approver.return_value = 0
    view.pending_offers_for_recipient.return_value = 0
    view.pending_offers_for_offerer.return_value = 0
    return view


def _rule_tx(body, extra_ops=None):
    ops = {"0": "always ( %s )." % body}
    ops.update(extra_ops or {})
    return {"tx_type": "user_tx", "sender_pubkey": SENDER, "operations": ops}


@pytest.mark.parametrize("body", [ALLOWLIST_BODY, INSTANT_BODY, HOLD600_BODY,
                                  HOLDB5_BODY, ONE_UNIT_BODY])
def test_documented_rules_register_on_an_active_chain(body):
    tx = _rule_tx(body)
    result = validate_o5_clause_routing(tx, _view(True), tx["operations"]["0"])
    assert result is not None and result.is_valid is True, getattr(result, "error", None)
    assert result.data["o5_clause_action"] == "declare"
    assert result.data["o5_clause_body"] == body


@pytest.mark.parametrize("body", [INSTANT_BODY, HOLD600_BODY, HOLDB5_BODY])
def test_a_hold_rule_is_refused_at_deploy_on_an_inactive_chain(body):
    """#47 case 5 / #76 case 6: the rule would register and never be asked."""
    tx = _rule_tx(body)
    result = validate_o5_clause_routing(tx, _view(False), tx["operations"]["0"])
    assert result is not None and result.is_valid is False
    assert result.code == "RECIPIENT_POLICY_INACTIVE"
    assert "not active" in result.error


def test_an_i3_only_inbound_rule_registers_without_the_feature():
    # Statically indistinguishable from a sender-pass clause; the capabilities
    # report is how a wallet learns whether the recipient pass will enforce it.
    tx = _rule_tx(ALLOWLIST_BODY)
    result = validate_o5_clause_routing(tx, _view(False), tx["operations"]["0"])
    assert result is not None and result.is_valid is True


def test_an_ordinary_clause_still_registers_without_the_feature():
    body = "( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? %s : %s )" % (BLOCK, ALLOW)
    tx = _rule_tx(body)
    result = validate_o5_clause_routing(tx, _view(False), tx["operations"]["0"])
    assert result is not None and result.is_valid is True


@pytest.mark.parametrize("mention, said", [
    ("i17[t]:bv[24]", "i17[t]:bv[64]"),
    ("i27[t]:bv[384]", "i27[t]:bv[64]"),
    # An untyped mention is caught by the generic explicit-width screen first.
    ("i17[t]", "explicit width"),
])
def test_a_wrongly_typed_hold_stream_is_refused_when_active(mention, said):
    body = "( (%s = { 1 }:bv[64]) ? %s : %s )" % (mention, ALLOW, BLOCK)
    tx = _rule_tx(body)
    result = validate_o5_clause_routing(tx, _view(True), tx["operations"]["0"])
    assert result is not None and result.is_valid is False
    assert said in result.error


def test_the_width_screen_is_gated_on_the_chain_flag():
    body = "( (i17[t]:bv[24] = { 1 }:bv[24]) ? %s : %s )" % (ALLOW, BLOCK)
    # Inactive: i17 is an ordinary custom stream; no width screen (and the
    # deploy refusal is a separate, admission-only check).
    assert _screen_clause(body, False) is None
    assert "i17[t]:bv[64]" in _screen_clause(body, True)
    # The documented shapes pass the active screen.
    for good in (ALLOWLIST_BODY, INSTANT_BODY, HOLD600_BODY, HOLDB5_BODY,
                 ONE_UNIT_BODY,
                 "( (i17[t] : bv[ 64 ] <= { 600 }:bv[64]) ? %s : %s )" % (ALLOW, BLOCK)):
        assert _screen_clause(good, True) is None, good


def test_only_the_node_writes_the_hold_streams():
    transfers = [[SENDER, RECIPIENT, "5"]]
    for key in ("17", "27"):
        tx = {"tx_type": "user_tx", "sender_pubkey": SENDER,
              "operations": {"1": transfers, key: "0"}}
        refused = validate_user_tx_reserved_domains(tx, _view(True))
        assert refused is not None and refused.is_valid is False
        assert key in refused.error
        before = validate_user_tx_reserved_domains(tx, _view(False))
        assert before is None or before.is_valid is True, \
            "an ordinary custom stream before activation"


def test_no_accumulated_rule_may_read_the_hold_streams_when_active():
    # An o5-writing rule routes to the clause registry, so use a custom output
    # to exercise the accumulated-rule screen itself.
    rule = ("always ( (i17[t]:bv[64] = { 1 }:bv[64]) -> "
            "(o13[t]:bv[24] = { #x000001 }:bv[24]) ).")
    tx = _rule_tx("dummy")
    tx["operations"]["0"] = rule
    refused = validate_user_tx_reserved_domains(tx, _view(True))
    assert refused is not None and refused.is_valid is False
    assert "hold stream" in refused.error
    # Before activation i17 is an ordinary custom stream: the same rule is a
    # legal accumulated rule (the audit holds activation back instead).
    before = validate_user_tx_reserved_domains(tx, _view(False))
    assert before is None or before.is_valid is True


def test_rule_change_request_screens_the_hold_streams():
    from consensus.admission import validate_rule_change_request_payload
    tx = {
        "tx_type": "rule_change_request", "sender_pubkey": SENDER,
        "sequence_number": 1, "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 100, "fee_limit": "100",
        "kind": tau_defs.RULE_CHANGE_KIND_SET_POLICY,
        "rule_text": "always ( %s )." % HOLD600_BODY,
        "approvers": {}, "custom_inputs": {},
    }
    refused = validate_rule_change_request_payload(tx, _view(False))
    assert refused.is_valid is False and refused.code == "RECIPIENT_POLICY_INACTIVE"
    # On an active chain the same request passes the screens.
    ok = validate_rule_change_request_payload(tx, _view(True))
    assert ok.is_valid is True, ok.error


# --- activation, audit, persistence ------------------------------------------------

A = "1a" * 48
B = "2b" * 48

_CLEAN = [
    ("consensus_rules", "always ( o6[t]:bv[16] = i10[t]:bv[16] )."),
    ("application_rules", "always ( o12[t]:bv[24] = i1[t]:bv[24] )."),
    ("clause_aaaaaaaaaa_o5", "( (i1[t]:bv[24] > { 0 }:bv[24]) ? %s : %s )" % (ALLOW, BLOCK)),
]


@pytest.mark.parametrize("mode", ["", "validator_set", "stake", "tau_validator_set"])
def test_an_untouched_chain_keeps_the_legacy_meta_hash(mode):
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.eligibility_mode = mode
    assert lm.recipient_policy_active is False
    assert lm.consensus_meta_hash() == _legacy_meta_hash(lm)


def test_the_genesis_shaped_call_is_unaffected():
    from consensus.retractable import RetractableBook
    assert build_mechanism_metadata("supermajority") == {
        "vote_quorum": "supermajority",
        "retractable_transfers_root": RetractableBook().root().hex(),
    }
    mech = build_mechanism_metadata("supermajority", recipient_policy_active=True)
    assert mech["recipient_policy_active"] is True


def test_activation_changes_the_hash_and_is_idempotent():
    lm = ConsensusLifecycleManager(active_validators=[A])
    base = lm.consensus_meta_hash()
    lm.activate_recipient_policy()
    active = lm.consensus_meta_hash()
    assert active != base
    lm.activate_recipient_policy()
    assert lm.consensus_meta_hash() == active


def test_the_two_feature_flags_are_bound_apart():
    slots, receive, both = (ConsensusLifecycleManager(active_validators=[A])
                            for _ in range(3))
    slots.activate_approval_slots()
    receive.activate_recipient_policy()
    both.activate_approval_slots()
    both.activate_recipient_policy()
    assert len({m.consensus_meta_hash() for m in (slots, receive, both)}) == 3


@pytest.mark.parametrize("value", [False, None, 0, 1, "true", "", []])
def test_only_true_is_a_legal_patch_value(value):
    assert validate_recipient_policy_active(value) is not None


def test_the_patch_activates_and_refuses_to_deactivate():
    assert "recipient_policy_active" in HOST_CONTRACT_PATCH_KEYS
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.apply_host_contract_patch({"recipient_policy_active": True},
                                 effective_spec_texts=_CLEAN)
    assert lm.recipient_policy_active is True
    with pytest.raises(ValueError, match="cannot be deactivated"):
        lm.apply_host_contract_patch({"recipient_policy_active": False})
    assert lm.recipient_policy_active is True


def test_one_patch_can_turn_on_both_features():
    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.apply_host_contract_patch(
        {"approval_slots_active": True, "recipient_policy_active": True},
        effective_spec_texts=_CLEAN)
    assert lm.approval_slots_active is True and lm.recipient_policy_active is True


@pytest.mark.parametrize("label", ["consensus_rules", "application_rules",
                                   "builtin_rule_3", "clause_bbbbbbbbbb_o5"])
def test_a_rule_that_already_reads_a_hold_stream_blocks_activation(label):
    texts = _CLEAN + [(label, "always ( (i17[t]:bv[24] = { #x01 }:bv[24]) -> "
                              "(o13[t]:bv[24] = { #x01 }:bv[24]) ).")]
    findings = recipient_policy.audit_receive_stream_collisions(texts)
    assert len(findings) == 1 and label in findings[0] and "i17" in findings[0]
    texts27 = _CLEAN + [(label, "(i27[t]:bv[64] <= { 5 }:bv[64])")]
    findings = recipient_policy.audit_receive_stream_collisions(texts27)
    assert len(findings) == 1 and "i27" in findings[0]


def test_neighbours_and_comments_are_not_collisions():
    for stream in ("i1", "i7", "i16", "i18", "i170", "i117", "i270"):
        texts = [("application_rules",
                  "always ( (%s[t]:bv[24] = { #x01 }:bv[24]) -> "
                  "(o13[t]:bv[24] = { #x01 }:bv[24]) )." % stream)]
        assert recipient_policy.audit_receive_stream_collisions(texts) == [], stream
    commented = [("application_rules", "# i17 will be a hold stream\n"
                                       "always ( o12[t]:bv[24] = i1[t]:bv[24] ).")]
    assert recipient_policy.audit_receive_stream_collisions(commented) == []


def test_a_collision_leaves_the_flag_false_on_every_node_alike():
    colliding = _CLEAN + [("clause_cccccccccc_o5", HOLD600_BODY)]
    one, two = (ConsensusLifecycleManager(active_validators=[A]) for _ in range(2))
    for lm in (one, two):
        lm.apply_host_contract_patch({"recipient_policy_active": True},
                                     effective_spec_texts=colliding)
    assert one.recipient_policy_active is two.recipient_policy_active is False
    assert one.consensus_meta_hash() == two.consensus_meta_hash()


def test_the_proposal_is_refused_loudly_when_the_tip_collides(
        temp_database, isolated_chain_state):
    chain_state._consensus_rules_state = "always ( o6[t]:bv[16] = i10[t]:bv[16] )."
    chain_state._application_rules_state = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
    assert _check_host_contract_patch({"recipient_policy_active": True}) is None

    chain_state._application_rules_state = (
        "always ( (i17[t]:bv[24] = { #x01 }:bv[24]) -> "
        "(o13[t]:bv[24] = { #x01 }:bv[24]) )."
    )
    err = _check_host_contract_patch({"recipient_policy_active": True})
    assert err is not None and "cannot be activated on this chain" in err
    assert "application_rules" in err

    err = _check_host_contract_patch({"recipient_policy_active": False})
    assert err is not None and "cannot be deactivated" in err


def test_i17_i27_are_write_reserved_only_when_active():
    for mode in ("", "validator_set", "stake", "tau_validator_set"):
        assert tau_defs.reserved_operation_keys(mode) == \
            tau_defs.reserved_operation_keys(mode, recipient_policy_active=False)
        assert 17 not in tau_defs.reserved_operation_keys(mode, approval_slots_active=True)
        assert 17 in tau_defs.reserved_operation_keys(mode, recipient_policy_active=True)
        assert 27 in tau_defs.reserved_operation_keys(mode, recipient_policy_active=True)


def test_a_clause_may_read_the_hold_streams_and_no_other_rule_may():
    kinds = {
        kind: tau_defs.rule_text_forbidden_input_streams(
            kind, "", approval_slots_active=True, recipient_policy_active=True)
        for kind in (tau_defs.RULE_TEXT_CONTEXT_USER, tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE,
                     tau_defs.RULE_TEXT_CONTEXT_CONSENSUS)
    }
    assert "i17" in kinds[tau_defs.RULE_TEXT_CONTEXT_USER]
    assert "i27" in kinds[tau_defs.RULE_TEXT_CONTEXT_USER]
    assert "i17" in kinds[tau_defs.RULE_TEXT_CONTEXT_CONSENSUS]
    assert "i17" not in kinds[tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE]
    assert "i27" not in kinds[tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE]
    inactive = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_USER, "", approval_slots_active=True)
    assert "i17" not in inactive and "i27" not in inactive


# --- persistence -------------------------------------------------------------------

@pytest.fixture
def neutral_genesis(monkeypatch):
    for name, value in (
        ("_genesis_faucet_amount", 0), ("_genesis_vote_quorum", ""),
        ("_genesis_eligibility_mode", ""), ("_genesis_fee_beneficiary", ""),
        ("_genesis_approval_slots_active", False),
        ("_genesis_recipient_policy_active", False),
    ):
        monkeypatch.setattr(chain_state, name, value)


def test_the_flag_survives_a_restart(temp_database, neutral_genesis):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    lm.activate_recipient_policy()
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.recipient_policy_active is True
    assert reloaded.approval_slots_active is False
    assert reloaded.consensus_meta_hash() == before


def test_an_inactive_chain_restarts_inactive(temp_database, neutral_genesis):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    before = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.recipient_policy_active is False
    assert reloaded.consensus_meta_hash() == before


def test_a_genesis_can_ship_with_it_on(temp_database, neutral_genesis, monkeypatch):
    _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    monkeypatch.setattr(chain_state, "_genesis_recipient_policy_active", True)
    reloaded = _reload()
    assert reloaded.recipient_policy_active is True
    assert db.get_chain_state_value("recipient_policy_active", None) == "1"


# --- capability reporting -----------------------------------------------------------

def test_capability_flags_default_on():
    assert recipient_policy.supported("recipient_policy") is True
    assert recipient_policy.supported("recipient_max_hold") is True
    assert recipient_policy.supported("recipient_guarded_pass") is True
    assert recipient_policy.supported("not_a_capability") is False
    assert tau_defs.HOST_CAPABILITIES["recipient_policy"] is True


def test_getgovernance_reports_the_chain_flag_and_capabilities(
        temp_database, isolated_chain_state, monkeypatch):
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    container = MagicMock()
    container.chain_state = chain_state
    container.db = db
    data = json.loads(getgovernance.execute("getgovernance", container))["data"]
    assert data["recipient_policy_active"] is False
    assert data["capabilities"] == tau_defs.HOST_CAPABILITIES
    lm.activate_recipient_policy()
    data = json.loads(getgovernance.execute("getgovernance", container))["data"]
    assert data["recipient_policy_active"] is True


def test_getgovernance_answers_while_a_recipient_patch_is_scheduled(
        temp_database, isolated_chain_state, monkeypatch):
    """The advisory precheck of this patch audits the rules in force, which
    takes _rules_lock — it must run after getgovernance releases its own
    locks, or the node deadlocks while holding the balance/sequence locks."""
    for name in ("_balance_lock", "_sequence_lock", "_rules_lock"):
        monkeypatch.setattr(chain_state, name, threading.Lock())
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    update = ConsensusRuleUpdate(
        rule_revisions=["consensus rules"], activate_at_height=50,
        host_contract_patch={"recipient_policy_active": True},
        proposer_pubkey="d" * 96)
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates.append((50, update.update_id))

    container = MagicMock()
    container.chain_state = chain_state
    container.db = db
    answer = []
    reader = threading.Thread(
        target=lambda: answer.append(getgovernance.execute("getgovernance", container)),
        daemon=True)
    reader.start()
    reader.join(30)
    assert answer, (
        "getgovernance did not return while a recipient patch was scheduled: "
        "its advisory check takes the rules lock the command already holds")
    data = json.loads(answer[0])["data"]
    (entry,) = data["scheduled_updates"]
    assert entry["host_contract_patch"] == {"recipient_policy_active": True}
    assert entry["precheck"] == "ok", entry


def test_the_scheduled_patch_is_flagged_when_a_rule_started_reading_i17(
        temp_database, isolated_chain_state, monkeypatch):
    import consensus.admission as admission
    for name in ("_balance_lock", "_sequence_lock", "_rules_lock"):
        monkeypatch.setattr(chain_state, name, threading.Lock())
    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    update = ConsensusRuleUpdate(
        rule_revisions=["consensus rules"], activate_at_height=50,
        host_contract_patch={"recipient_policy_active": True},
        proposer_pubkey="d" * 96)
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates.append((50, update.update_id))
    monkeypatch.setattr(admission, "_tip_effective_spec_texts", lambda: [
        ("clause_aaaaaaaaaa_o5", HOLD600_BODY),
    ])
    container = MagicMock()
    container.chain_state = chain_state
    container.db = db
    data = json.loads(getgovernance.execute("getgovernance", container))["data"]
    (entry,) = data["scheduled_updates"]
    assert entry["precheck"] == "fail"
    assert "cannot be activated on this chain" in entry["precheck_error"]