"""Recipient controls (issues #47 + #76): the recipient's own o5 clause as a
gate on inbound payments, judged at admission and at apply through one helper.

Coverage maps to the issues' acceptance cases: #47.1 allow-list, #47.2
neutral default, #47.3 batch atomicity, #47.4 one unit both directions,
#47.5 capability reporting + deploy refusal, #76.1 cap zero, #76.2 cap 600
seconds, #76.3 no rule no restriction, #76.4 retract never gated, #76.5
refusal carries the verified cap, #76.6 in force before the payment — plus
the design's parity, determinism, guarded-mode and sabotage checks.

Mock evaluator throughout (the native engine bindings are unavailable in
this environment, so — exactly like the neighbouring suites — clause
verdicts are scripted by input, keyed on i17/i16/i3).
"""
import json
import time
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

import pytest

import chain_state
import db
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_payload
from commands import sendtx
from consensus import sender_policy
from consensus.admission import TipAdmissionView, validate_o5_clause_routing
from consensus.approvals import screen_recipient_stream_widths
from consensus.governance import (
    ConsensusLifecycleManager,
    build_mechanism_metadata,
)
from consensus.policy_mock import MockPolicyEvaluator

import test_approval_apply as ap
import test_retractable_apply as ra

POOLS = ("apply", "admission")


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)


# --- clause bodies and their scripted semantics ------------------------------
#
# Bodies are written in the canonical annotated form the deploy screens and
# the cap extractor read. The mock verdict functions below are the semantics
# those texts declare; the two are kept side by side so a reader can check
# one against the other.

def allowlist_body(sender):
    """Admits only payments from `sender` — the design's standard shape:
    the outgoing branch (context 0) is untouched, every inbound context
    requires the sender to be listed. Reading i16 is what makes the clause
    inbound-capable; a clause reading only i3 keeps its outbound meaning
    and is never asked inbound."""
    return (
        "(i16[t]:bv[64] = { #x0000 }:bv[64] || "
        "i3[t]:bv[384] = { #x" + sender + " }:bv[384]) "
        "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
    )


def allowlist_verdict(sender):
    return lambda inputs: "1" if (
        str(inputs.get("i16")) == "0" or inputs.get("i3") == "#x" + sender
    ) else "0"


# Caps: 600 seconds for time parks, 100 blocks for height parks (refusal
# form: a hold strictly above the cap blocks).
CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0258 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def cap_verdict(inputs):
    ctx = int(inputs.get("i16") or 0)
    hold = int(inputs.get("i17") or 0)
    if ctx == 2:
        return "0" if hold > 600 else "1"
    if ctx == 3:
        return "0" if hold > 100 else "1"
    return "1"


ZERO_CAP_BODY = (
    "(i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0000 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def zero_cap_verdict(inputs):
    ctx = int(inputs.get("i16") or 0)
    hold = int(inputs.get("i17") or 0)
    if ctx == 2:
        return "0" if hold > 0 else "1"
    return "1"


# The text suggests a cap of 2; the rule itself admits 0 and 2 and refuses 1
# — non-monotonic, so no cap number may ever be printed for it.
NONMONOTONIC_BODY = (
    "(i17[t]:bv[64] <= { #x0002 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24])"
)


def nonmonotonic_verdict(inputs):
    return "0" if int(inputs.get("i17") or 0) == 1 else "1"


BLOCKALL_BODY = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def _ev(body, fn, pool="apply"):
    ev = MockPolicyEvaluator(pool=pool)
    ev.set_verdict(body, fn)
    return ev


def _clause_for(mapping):
    return lambda addr, stream: mapping.get((addr, stream))


# --- the gate helper ---------------------------------------------------------

def test_neutral_default_when_no_clause():
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({}), ap.BOB, {1: "5"}, hold=10 ** 9, context=2,
        pool="apply")
    assert blocked is False and info is None


def test_neutral_default_when_clause_never_reads_hold_or_context():
    sender_policy.set_evaluator("apply", _ev(BLOCKALL_BODY, "0"))
    # BLOCKALL_BODY reads neither i17 nor i16, so it is not inbound-capable:
    # the gate must not consult it at all (the evaluator would block).
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): BLOCKALL_BODY}), ap.BOB, {1: "5"},
        hold=0, context=1, pool="apply")
    assert blocked is False and info is None


def test_allowlist_refusal_is_not_a_hold_refusal():
    body = allowlist_body(ap.ALICE)
    sender_policy.set_evaluator("apply", _ev(body, allowlist_verdict(ap.ALICE)))
    values = {1: "5", 3: "{ #x" + ap.AUTH + " }:bv[384]"}
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): body}), ap.BOB, values,
        hold=0, context=1, pool="apply")
    assert blocked is True and info["reason"] == "recipient_policy_block"


def test_hold_refusal_carries_the_verified_cap():
    sender_policy.set_evaluator("apply", _ev(CAP_BODY, cap_verdict))
    values = {1: "5", 3: "{ #x" + ap.ALICE + " }:bv[384]"}
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): CAP_BODY}), ap.BOB, values,
        hold=700, context=2, pool="apply")
    assert blocked is True
    assert info["reason"] == "recipient_max_hold"
    assert info["code"] == "RECIPIENT_MAX_HOLD"
    assert info["hold"] == 700 and info["unit"] == "seconds"
    assert info["cap_kind"] == "threshold"
    assert info["max_hold_seconds"] == 600


def test_cap_is_per_branch_never_global():
    """The same clause caps blocks at 100: a 700-block refusal must report
    max_hold_blocks=100, not the 600 from the seconds branch."""
    sender_policy.set_evaluator("apply", _ev(CAP_BODY, cap_verdict))
    values = {1: "5", 3: "{ #x" + ap.ALICE + " }:bv[384]"}
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): CAP_BODY}), ap.BOB, values,
        hold=700, context=3, pool="apply")
    assert blocked is True and info["unit"] == "blocks"
    assert info["max_hold_blocks"] == 100
    assert "max_hold_seconds" not in info


def test_nonmonotonic_rule_reports_no_cap():
    sender_policy.set_evaluator(
        "apply", _ev(NONMONOTONIC_BODY, nonmonotonic_verdict))
    values = {1: "5", 3: "{ #x" + ap.ALICE + " }:bv[384]"}
    blocked, info = sender_policy.recipient_clause_blocks(
        _clause_for({(ap.BOB, 5): NONMONOTONIC_BODY}), ap.BOB, values,
        hold=1, context=3, pool="apply")
    assert blocked is True and info["reason"] == "recipient_max_hold"
    assert info["cap_kind"] == "rule"
    assert "max_hold_seconds" not in info and "max_hold_blocks" not in info


def test_park_hold_measures_in_the_parks_own_unit():
    from consensus.retractable import KIND_HEIGHT, KIND_TIME

    assert sender_policy.park_hold(KIND_TIME, 2000, 50, 1400) == (
        600, tau_defs.CONTEXT_INCOMING_TIME_PARK)
    assert sender_policy.park_hold(KIND_HEIGHT, 150, 50, 1400) == (
        100, tau_defs.CONTEXT_INCOMING_HEIGHT_PARK)
    # Saturates at 0 rather than going negative.
    assert sender_policy.park_hold(KIND_TIME, 1000, 50, 1400)[0] == 0


def test_sender_supplied_hold_streams_are_forced_not_merged():
    """recipient_hold_inputs overwrites i17/i16 on the copy it returns and
    leaves the caller's map untouched: a value the sender supplied can never
    survive into the recipient pass."""
    values = {1: "5", 17: "999999", 16: "2"}
    out = sender_policy.recipient_hold_inputs(values, hold=3, context=3)
    assert out[17] == "3" and out[16] == "3"
    assert values[17] == "999999" and values[16] == "2"
    sender_out = sender_policy.sender_pass_inputs(values)
    assert sender_out[17] == "0" and sender_out[16] == "0"


# --- deploy screens ----------------------------------------------------------

BLIND_RULE = (
    "always ( (i17[t]:bv[64] > { #x0258 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
CAP_RULE = "always ( %s )." % CAP_BODY


@pytest.fixture
def routing_view():
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {ap.ALICE}
    view.next_block_height = 50
    view.eligibility_mode = ""
    view.approval_slots_active = True
    view.recipient_policy_active = True
    view.clause_for.return_value = None
    return view


def _route(rule, view, sender=None):
    tx = {"tx_type": "user_tx", "sender_pubkey": sender or ap.BOB,
          "operations": {"0": rule}}
    return validate_o5_clause_routing(tx, view, rule)


def test_unit_blind_hold_rule_is_refused_at_deploy(routing_view):
    """#47.5/#76.6: a clause reading i17 without i16 cannot be registered —
    it would silently misjudge one unit as the other."""
    result = _route(BLIND_RULE, routing_view)
    assert result.is_valid is False
    assert "unit-blind" in result.error


def test_inbound_clause_is_refused_before_activation(routing_view):
    routing_view.recipient_policy_active = False
    result = _route(CAP_RULE, routing_view)
    assert result.is_valid is False
    assert result.code == "RECIPIENT_POLICY_INACTIVE"


def test_inbound_clause_registers_after_activation(routing_view):
    result = _route(CAP_RULE, routing_view)
    assert result is not None and result.is_valid is True, getattr(
        result, "error", None)
    assert result.data["o5_clause_action"] == "declare"


def test_recipient_stream_widths_must_be_declared_64():
    assert screen_recipient_stream_widths(CAP_BODY) is None
    unannotated = "(i17[t] > { #x0258 }:bv[64])"
    err = screen_recipient_stream_widths(unannotated)
    assert err is not None and "bv[64]" in err
    wrong = "(i17[t]:bv[32] > { #x0258 }:bv[32])"
    assert screen_recipient_stream_widths(wrong) is not None
    assert screen_recipient_stream_widths(BLOCKALL_BODY) is None


def test_shipped_wallet_templates_screen_clean_with_recipient_streams():
    """Regression (found by independent cross-check of the first build):
    the context tag originally sat on i26 — the documented start of the
    clause custom-input space (REQUEST_CUSTOM_INPUT_MIN) — and the
    recipient width screen then rejected the shipped wallet templates
    that type i26 at bv[24] as a sender custom input: '2FA for High
    Value Transfers', 'Escrow Contract' and 'Require a specific custom
    input'. The tag now sits on i16. Every shipped o5 template must pass
    _screen_clause_domains, and a recipient-control clause must still
    screen clean in the same process — per-stream typing is
    process-global, so the two have to coexist."""
    from consensus.admission import _screen_clause_domains
    from consensus.rule_offers import clause_body_v1
    from wallet_templates import shipped_templates, writes

    templates = shipped_templates()
    for name in ("2FA for High Value Transfers", "Escrow Contract",
                 "Require a specific custom input"):
        assert name in templates, name
        assert _screen_clause_domains(
            clause_body_v1(templates[name])) is None, name
    for name, template in sorted(templates.items()):
        if writes(template, "o5"):
            assert _screen_clause_domains(
                clause_body_v1(template)) is None, name
    # The recipient-control clause itself, in the same process.
    assert _screen_clause_domains(CAP_RULE) is None


# --- activation --------------------------------------------------------------

def test_legacy_metahash_pinned_flag_off():
    """With the flag off, the mechanism metadata and the consensus meta
    hash are exactly what they were before this feature existed."""
    assert "recipient_policy_active" not in build_mechanism_metadata(
        "supermajority")
    assert build_mechanism_metadata(
        "supermajority", recipient_policy_active=True
    )["recipient_policy_active"] is True
    lm = ConsensusLifecycleManager(active_validators=[bytes.fromhex(ap.ALICE)])
    base = lm.consensus_meta_hash()
    lm.activate_recipient_policy()
    assert lm.consensus_meta_hash() != base
    activated = lm.consensus_meta_hash()
    lm.activate_recipient_policy()  # idempotent
    assert lm.consensus_meta_hash() == activated


def test_activation_is_one_way_through_the_patch():
    lm = ConsensusLifecycleManager(active_validators=[bytes.fromhex(ap.ALICE)])
    lm.apply_host_contract_patch({"recipient_policy_active": True})
    assert lm.recipient_policy_active is True
    with pytest.raises(ValueError):
        lm.apply_host_contract_patch({"recipient_policy_active": False})


def test_activation_collision_audit_refuses_and_leaves_the_flag_off():
    lm = ConsensusLifecycleManager(active_validators=[bytes.fromhex(ap.ALICE)])
    corpus = [("application_rules",
               "always ( i17[t]:bv[64] = { #x0005 }:bv[64] ).")]
    lm.apply_host_contract_patch(
        {"recipient_policy_active": True}, effective_spec_texts=corpus)
    assert lm.recipient_policy_active is False
    lm.apply_host_contract_patch(
        {"recipient_policy_active": True},
        effective_spec_texts=[("application_rules", "always ( o0[t] = 1 ).")])
    assert lm.recipient_policy_active is True


# --- apply: plain transfers (test_approval_apply harness) --------------------

def _lm_ap(clause=None, recipient=None, active=True):
    lm = ap._lm()
    if active:
        lm.activate_recipient_policy()
    if clause is not None:
        lm.rule_offers.accepted_clauses[(recipient or ap.BOB, 5)] = clause
    return lm


def _transfer_tx(sender, recipient, amount, seq=0, sk=None):
    return ap._sign({
        "tx_id": f"rc-{next(ap._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[sender, recipient, str(amount)]]},
    }, sk if sk is not None else ap.SK_ALICE)


def _reason(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.reason


def _refusal(result, tx):
    """(reason, {key: value}) for a refused tx, parsed from its receipt log
    trail — the persisted surface a dropped transaction leaves behind."""
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    details = {}
    for log in outcome.receipt_logs or []:
        for part in str(log).split():
            if "=" in part:
                k, v = part.split("=", 1)
                details[k] = v
    return outcome.reason, details


def test_allowlist_admission_and_apply():
    """#47.1 at apply: the vendor's clause admits only the allow-listed
    payer; anyone else's payment is refused, at no fee."""
    body = allowlist_body(ap.ALICE)
    sender_policy.set_evaluator("apply", _ev(body, allowlist_verdict(ap.ALICE)))
    lm = _lm_ap(clause=body)

    ok_tx = _transfer_tx(ap.ALICE, ap.BOB, 500)
    result, _lm, _calls = ap._apply([ok_tx], lm=lm)
    assert ok_tx["tx_id"] in result.accepted_tx_ids
    assert ap._balances(result)[ap.BOB] == 500

    bad_tx = _transfer_tx(ap.STRANGER, ap.BOB, 500, sk=ap.SK_STRANGER)
    result, _lm, _calls = ap._apply(
        [bad_tx], lm=lm,
        balances={ap.ALICE: 100000, ap.STRANGER: 1000, ap.BOB: 0})
    assert bad_tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, bad_tx) == "recipient_policy_block"
    assert ap._balances(result)[ap.BOB] == 0
    assert ap._balances(result)[ap.STRANGER] == 1000, \
        "a refused payment pays no fee"


def test_neutral_default_at_apply():
    """#47.2/#76.3: a recipient with no inbound-capable clause is paid
    exactly as before the feature existed."""
    sender_policy.set_evaluator("apply", _ev(BLOCKALL_BODY, "0"))
    tx = _transfer_tx(ap.ALICE, ap.BOB, 500)
    result, _lm, _calls = ap._apply([tx], lm=_lm_ap(clause=BLOCKALL_BODY))
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ap._balances(result)[ap.BOB] == 500


def test_gate_is_inert_before_activation():
    body = allowlist_body(ap.ALICE)
    ev = _ev(body, allowlist_verdict(ap.ALICE))
    sender_policy.set_evaluator("apply", ev)
    tx = _transfer_tx(ap.STRANGER, ap.BOB, 500, sk=ap.SK_STRANGER)
    result, _lm, _calls = ap._apply(
        [tx], lm=_lm_ap(clause=body, active=False),
        balances={ap.ALICE: 100000, ap.STRANGER: 1000, ap.BOB: 0})
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ev.verdict_calls == [], "no clause is consulted before activation"


def test_batch_atomicity():
    """#47.3: one refused leg refuses the whole batch — the accepted leg's
    balance does not move and no partial park or credit survives."""
    body = allowlist_body(ap.ALICE)
    sender_policy.set_evaluator("apply", _ev(body, allowlist_verdict(ap.ALICE)))
    tx = ap._sign({
        "tx_id": f"rc-{next(ap._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": ap.STRANGER,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[ap.STRANGER, ap.ALICE, "100"],
                             [ap.STRANGER, ap.BOB, "100"]]},
    }, ap.SK_STRANGER)
    result, _lm, _calls = ap._apply(
        [tx], lm=_lm_ap(clause=body),
        balances={ap.ALICE: 100000, ap.STRANGER: 1000, ap.BOB: 0})
    assert tx["tx_id"] in result.invalid_tx_ids
    balances = ap._balances(result)
    assert balances[ap.ALICE] == 100000, "the good leg must not settle either"
    assert balances[ap.BOB] == 0
    assert balances[ap.STRANGER] == 1000


def test_one_unit_both_directions():
    """#47.4: BOB's cap clause governs payments TO Bob; Bob's own outgoing
    payment is judged by the other side's policy (none) — his clause never
    fires on it."""
    sender_policy.set_evaluator("apply", _ev(CAP_BODY, cap_verdict))
    lm = _lm_ap(clause=CAP_BODY)
    tx = _transfer_tx(ap.BOB, ap.ALICE, 500, sk=ap.SK_BOB)
    result, _lm, _calls = ap._apply(
        [tx], lm=lm, balances={ap.ALICE: 100000, ap.BOB: 1000})
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ap._balances(result)[ap.ALICE] == 100500


def test_self_transfer_exempt():
    """A self-transfer never reaches the recipient gate (the engine refuses
    self-transfers on its own, before any policy pass): the outcome is the
    engine's own invalid_transfer, never a recipient-policy refusal, and
    the recipient pass is not consulted."""
    body = allowlist_body(ap.ALICE)
    ev = _ev(body, "0")
    sender_policy.set_evaluator("apply", ev)
    lm = _lm_ap(clause=body, recipient=ap.ALICE)
    tx = _transfer_tx(ap.ALICE, ap.ALICE, 500)
    result, _lm, _calls = ap._apply([tx], lm=lm)
    assert _reason(result, tx) == "invalid_transfer"
    assert "recipient policy" not in ap._logs(result)
    assert ev.verdict_calls == []


# --- apply: parks, retracts, releases (test_retractable_apply harness) -------

def _ra_chain(clause=None, verdict=None):
    chain = ra.Chain({ra.ALICE: 100000, ra.BOB: 0, ra.CAROL: 0})
    chain.lm.activate_recipient_policy()
    if clause is not None:
        chain.lm.rule_offers.accepted_clauses[(ra.BOB, 5)] = clause
        sender_policy.set_evaluator("apply", _ev(clause, verdict))
    return chain


def test_cap_600_seconds():
    """#76.2: a time park held 700 s is refused with the verified cap; one
    held exactly 600 s is admitted."""
    chain = _ra_chain(CAP_BODY, cap_verdict)
    refused = ra.park_tx(amount=100, at_time=ra.TS + 700)
    result = chain.block([refused])
    assert refused["tx_id"] in result.invalid_tx_ids
    reason, details = _refusal(result, refused)
    assert reason == "recipient_max_hold"
    assert details["max_hold_seconds"] == "600"
    assert details["hold"] == "700" and details["unit"] == "seconds"
    assert not chain.book.open, "a refused park leaves nothing parked"
    assert chain.bal[ra.ALICE] == 100000, "and charges no fee"

    chain2 = _ra_chain(CAP_BODY, cap_verdict)
    admitted = ra.park_tx(amount=100, at_time=ra.TS + 600)
    result = chain2.block([admitted])
    assert admitted["tx_id"] in result.accepted_tx_ids
    assert len(chain2.book.open) == 1


def test_cap_zero():
    """#76.1: cap 0 refuses every park and still admits plain payments."""
    chain = _ra_chain(ZERO_CAP_BODY, zero_cap_verdict)
    park = ra.park_tx(amount=100, at_time=ra.TS + 1)
    result = chain.block([park])
    assert park["tx_id"] in result.invalid_tx_ids
    _reason_out, details = _refusal(result, park)
    assert details["max_hold_seconds"] == "0"

    spend = ra.spend_tx(ra.ALICE, ra.BOB, 100, seq=0)
    result = chain.block([spend])
    assert spend["tx_id"] in result.accepted_tx_ids
    assert chain.bal[ra.BOB] == 100


def test_cap_in_blocks():
    chain = _ra_chain(CAP_BODY, cap_verdict)
    refused = ra.park_tx(amount=100, at_height=ra.HEIGHT + 700)
    result = chain.block([refused])
    assert refused["tx_id"] in result.invalid_tx_ids
    _reason_out, details = _refusal(result, refused)
    assert details["unit"] == "blocks" and details["hold"] == "700"
    assert details["max_hold_blocks"] == "100"

    chain2 = _ra_chain(CAP_BODY, cap_verdict)
    admitted = ra.park_tx(amount=100, at_height=ra.HEIGHT + 100)
    result = chain2.block([admitted])
    assert admitted["tx_id"] in result.accepted_tx_ids


def test_cross_unit_no_silent_admission():
    """A near-maximum height park (99999 blocks, the largest the park shape
    admits) to the capped vendor is refused AS a block park, with the block
    cap — never acknowledged as if it were a 600-second hold. This is the
    failure mode of acknowledging a height park in the seconds unit."""
    chain = _ra_chain(CAP_BODY, cap_verdict)
    park = ra.park_tx(amount=100, at_height=ra.HEIGHT + 99999,
                      expire_at_height=ra.HEIGHT + 199999)
    result = chain.block([park])
    assert park["tx_id"] in result.invalid_tx_ids
    _reason_out, details = _refusal(result, park)
    assert details["unit"] == "blocks" and details["hold"] == "99999"
    assert details["max_hold_blocks"] == "100"
    assert "max_hold_seconds" not in details


def test_retract_never_gated():
    """#76.4: the recipient tightens their rule after the park; the sender's
    retract still refunds in full."""
    chain = _ra_chain(CAP_BODY, cap_verdict)
    park = ra.park_tx(amount=100, at_height=ra.HEIGHT + 10)
    result = chain.block([park])
    assert park["tx_id"] in result.accepted_tx_ids
    rid = ra.rid_of(park)
    # The recipient's clause now blocks everything (same inbound-capable
    # body, verdict flipped) — a retract that consulted it would fail.
    sender_policy.set_evaluator("apply", _ev(CAP_BODY, "0"))
    retract = ra.retract_tx(rid, seq=1)
    result = chain.block([retract], height=ra.HEIGHT + 1)
    assert retract["tx_id"] in result.accepted_tx_ids
    assert chain.bal[ra.ALICE] == 100000, "the retract refunds in full"


def test_release_not_rechecked():
    """A release at maturity pays the recipient even if their rule changed
    after the park was admitted — the gate judges parks, not releases."""
    chain = _ra_chain(CAP_BODY, cap_verdict)
    park = ra.park_tx(amount=100, at_height=ra.HEIGHT + 10)
    result = chain.block([park])
    assert park["tx_id"] in result.accepted_tx_ids
    # A release that re-checked the (now blocking) clause would not pay out.
    sender_policy.set_evaluator("apply", _ev(CAP_BODY, "0"))
    result = chain.block([], height=ra.HEIGHT + 10)
    assert chain.bal[ra.BOB] == 100, "the release credits the recipient"
    assert not chain.book.open


def test_replay_determinism():
    """The same block applied by two independent chains reaches the same
    state, verdicts included."""
    outcomes = []
    for _ in range(2):
        chain = _ra_chain(CAP_BODY, cap_verdict)
        refused = ra.park_tx(amount=100, at_time=ra.TS + 700)
        admitted = ra.park_tx(amount=50, seq=1, at_time=ra.TS + 10)
        result = chain.block([refused, admitted])
        outcomes.append((
            refused["tx_id"] in result.invalid_tx_ids,
            admitted["tx_id"] in result.accepted_tx_ids,
            chain.snapshot(),
            _refusal(result, refused),
        ))
    assert outcomes[0] == outcomes[1]


# --- admission: plain transfers (sendtx queue, scripted Tau) -----------------

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
CLAUSE_VIEW = "consensus.facade.TipAdmissionView.clause_for"


@pytest.fixture
def admission(temp_database):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state.load_genesis("data/genesis.json")
    chain_state._lifecycle_manager.activate_recipient_policy()
    db.clear_mempool()
    chain_state._balances[SENDER] = 100000
    with ExitStack() as stack:
        for target, kwargs in (
            ("commands.sendtx.validate_bls_pubkey", {"return_value": None}),
            ("tau_manager.is_force_test_enabled", {"return_value": False}),
            ("tau_manager.communicate_with_tau_multi",
             {"return_value": {1: "1", 5: "1"}}),
        ):
            stack.enter_context(patch(target, **kwargs))
        ready = stack.enter_context(patch("tau_manager.tau_ready"))
        ready.is_set.return_value = True
        yield


def _queue_transfer(sender=SENDER, recipient=RECIPIENT, amount="1", sk=SK_ALICE):
    tx = {
        "sender_pubkey": sender,
        "sequence_number": chain_state.get_sequence_number(sender),
        "expiration_time": int(time.time()) + 1000,
        "expire_at_height": 5000,
        "operations": {"1": [[sender, recipient, amount]]},
        "fee_limit": "1000",
    }
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, sk)))


def _clause_side_effect(mapping):
    def _for(*args):
        addr = args[-2] if len(args) >= 2 else None
        stream = args[-1] if args else None
        return mapping.get((addr, stream))
    return _for


def test_admission_allowlist_refuses_an_unlisted_payer(admission):
    """#47.1 at admission: the same refusal apply gives, before the tx is
    queued — and nothing reaches the mempool."""
    from bls_keys import SK_CAROL
    carol = pubkey_hex(SK_CAROL)
    body = allowlist_body(carol)
    sender_policy.set_evaluator(
        "admission", _ev(body, allowlist_verdict(carol), pool="admission"))
    with patch(CLAUSE_VIEW, side_effect=_clause_side_effect({(RECIPIENT, 5): body})):
        res = _queue_transfer()
    assert res["ok"] is False and res["code"] == "TX_REJECTED"
    assert "recipient's policy" in res["message"]
    assert db.get_mempool_txs() == []


def test_admission_allowlist_admits_the_listed_payer(admission):
    body = allowlist_body(SENDER)
    sender_policy.set_evaluator(
        "admission", _ev(body, allowlist_verdict(SENDER), pool="admission"))
    with patch(CLAUSE_VIEW, side_effect=_clause_side_effect({(RECIPIENT, 5): body})):
        res = _queue_transfer()
    assert res["ok"] is True, res


def test_capability_reporting_and_deploy_refusal(admission):
    """#47.5: getgovernance reports the feature and its streams in the
    capabilities block; the frozen HOST_STREAM_WIDTHS table is unchanged,
    so pre-existing rules see no new widths."""
    from types import SimpleNamespace

    from commands import getgovernance

    container = SimpleNamespace(chain_state=chain_state, db=db)
    resp = getgovernance.execute("getgovernance", container)
    if isinstance(resp, str):
        resp = json.loads(resp)
    payload = resp["data"] if "data" in resp else resp
    assert payload["recipient_policy_active"] is True
    controls = payload["capabilities"]["recipient_controls"]
    assert controls["hold_stream"] == 17 and controls["context_stream"] == 16
    assert controls["hold_stream_width"] == 64
    assert "i17" not in payload["stream_widths"]
    assert "i16" not in payload["stream_widths"]
    # The frozen table itself, pinned exactly as it was before this feature.
    assert tau_defs.HOST_STREAM_WIDTHS == {
        "i1": 24, "i2": 24, "o5": 24, "o8": 24, "o9": 24,
    }


# --- admission: parks (retractable queue harness) ----------------------------

PARK_NEXT_HEIGHT = 50
PARK_TIP_TS = 1_700_000_000


@pytest.fixture
def park_node(temp_database, monkeypatch):
    from unittest.mock import PropertyMock

    from commands import sendtx as sendtx_mod

    script = {"fee": 0, "custom": 0, "calls": []}

    def multi(**kwargs):
        script["calls"].append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        return {1: str(vals.get(1, "0")), 5: "1",
                8: str(script["custom"]), 9: str(script["fee"])}

    patches = [
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau", return_value="x1001"),
        patch("tau_manager.communicate_with_tau_multi", side_effect=multi),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch("commands.sendtx.validate_bls_pubkey", return_value=None),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
        patch.object(TipAdmissionView, "next_block_height",
                     new_callable=PropertyMock, return_value=PARK_NEXT_HEIGHT),
        patch.object(TipAdmissionView, "tip_timestamp",
                     new_callable=PropertyMock, return_value=PARK_TIP_TS),
        patch.object(TipAdmissionView, "next_block_timestamp",
                     new_callable=PropertyMock, return_value=PARK_TIP_TS),
        patch.object(TipAdmissionView, "clause_for",
                     lambda self, addr, stream: CAP_BODY
                     if addr == RECIPIENT else None),
        # Pin the wall clock to the tip clock: the structural expiration
        # check reads time.time(), and a timed park's expiration must sit
        # between the tip timestamp and its release.
        patch("time.time", return_value=PARK_TIP_TS),
    ]
    mocks = [p.start() for p in patches]
    mocks[0].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    chain_state._lifecycle_manager.activate_recipient_policy()
    yield sendtx_mod, script
    for p in reversed(patches):
        p.stop()


def _park_payload(release_at_time):
    tx = {
        "tx_type": "retractable_transfer",
        "sender_pubkey": SENDER,
        "sequence_number": 1,
        "expiration_time": PARK_TIP_TS + 100,
        "expire_at_height": PARK_NEXT_HEIGHT + 20,
        "fee_limit": "100",
        "recipient_pubkey": RECIPIENT,
        "amount": 100,
        "release_at_time": release_at_time,
    }
    return sign_payload(tx, SK_ALICE)


def test_admission_apply_parity_for_a_capped_park(park_node):
    """The 700 s park is refused at admission with the same verified cap
    apply reports (#76.5 on both surfaces); the 600 s park is admitted."""
    sendtx_mod, _script = park_node
    sender_policy.set_evaluator(
        "admission", _ev(CAP_BODY, cap_verdict, pool="admission"))

    refused = sendtx_mod.queue_transaction(
        json.dumps(_park_payload(PARK_TIP_TS + 700)), propagate=False)
    assert refused["ok"] is False, refused
    assert refused["code"] == "RECIPIENT_MAX_HOLD", refused
    details = refused["details"]["recipient_policy"]
    assert details["max_hold_seconds"] == 600
    assert details["hold"] == 700 and details["unit"] == "seconds"
    assert db.get_mempool_txs() == []

    admitted = sendtx_mod.queue_transaction(
        json.dumps(_park_payload(PARK_TIP_TS + 600)), propagate=False)
    assert admitted["ok"] is True, admitted


# --- guarded mode ------------------------------------------------------------

GUARDED_SPEC = (
    "always ( (i12[t]:bv[384] = { #x" + ap.BOB + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


def _apply_with_spec(txs, *, spec_text, multi, lm, balances=None, height=20):
    from block import Block
    from consensus.engine import ActiveConsensusView, TauConsensusEngine
    from consensus.state import TauStateSnapshot

    bal = balances if balances is not None else {
        ap.ALICE: 100000, ap.AUTH: 10, ap.SCAN: 10, ap.BOB: 0}
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=spec_text.encode(),
        metadata={
            "balances": dict(bal),
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    active_view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(ap.ALICE)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block_obj = Block.create(
        block_number=height, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=ap.ALICE, timestamp=1234567890,
    )
    calls = []

    def _multi(**kwargs):
        calls.append(kwargs)
        return multi(kwargs.get("input_stream_values") or {})

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", return_value="T"), \
            patch("tau_manager.communicate_with_tau_multi", side_effect=_multi), \
            patch("chain_state.get_application_rules_state", return_value=""), \
            patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply_block(active_view, block_obj, parent_snapshot)
    return result, calls


def _guarded_multi(guarded_o5, guarded_fee="999"):
    def _multi(vals):
        amount = int(str(vals.get(1, "0")) or 0)
        out = {1: str(amount), 8: "0", 9: "7", 5: "1"}
        if ap.BOB in str(vals.get(12, "")):
            # The recipient pass: i12 carries the recipient's key.
            out[5] = guarded_o5
            out[9] = guarded_fee
        return out
    return _multi


def test_guarded_mode_recipient_pass():
    """An existing guarded unit of the recipient's vetoes the payment in a
    second pass — no clause registration needed."""
    tx = _transfer_tx(ap.ALICE, ap.BOB, 500)
    result, calls = _apply_with_spec(
        [tx], spec_text=GUARDED_SPEC, multi=_guarded_multi("0"),
        lm=_lm_ap())
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == "recipient_policy_block"
    assert ap._balances(result)[ap.BOB] == 0
    assert any(ap.BOB in str((c.get("input_stream_values") or {}).get(12, ""))
               for c in calls), "the recipient pass must have run"


def test_guarded_pass_fee_isolation():
    """The recipient pass's outputs never reach fee accounting: it reports
    a fee of 999, the transfer is still charged exactly the sender pass's
    7 — the regression shape that hit the competitor's guarded mode."""
    tx = _transfer_tx(ap.ALICE, ap.BOB, 500)
    result, calls = _apply_with_spec(
        [tx], spec_text=GUARDED_SPEC, multi=_guarded_multi("1"),
        lm=_lm_ap())
    assert tx["tx_id"] in result.accepted_tx_ids
    logs = ap._logs(result)
    assert "Fee charged: 7" in logs and "999" not in logs
    balances = ap._balances(result)
    assert balances[ap.BOB] == 500
    assert balances[ap.ALICE] == 100000 - 500, "fee 7 nets out via the proposer"


def test_guarded_pass_skipped_when_spec_never_mentions_recipient():
    tx = _transfer_tx(ap.ALICE, ap.BOB, 500)
    result, calls = _apply_with_spec(
        [tx], spec_text="always (o0[t]=1).", multi=_guarded_multi("0"),
        lm=_lm_ap())
    assert tx["tx_id"] in result.accepted_tx_ids
    assert not any(ap.BOB in str((c.get("input_stream_values") or {}).get(12, ""))
                   for c in calls)


# --- sabotage check ----------------------------------------------------------

def test_sabotage_gate_noop_admits_what_the_gate_refuses():
    """Load-bearing check: with the gate stubbed to a no-op, the park the
    acceptance tests refuse sails through — so those tests fail if the
    gate ever stops gating."""
    chain = _ra_chain(CAP_BODY, cap_verdict)
    park = ra.park_tx(amount=100, at_time=ra.TS + 700)
    result = chain.block([park])
    assert park["tx_id"] in result.invalid_tx_ids

    with patch.object(sender_policy, "recipient_clause_blocks",
                      return_value=(False, None)):
        chain2 = _ra_chain(CAP_BODY, cap_verdict)
        park2 = ra.park_tx(amount=100, at_time=ra.TS + 700)
        result2 = chain2.block([park2])
        assert park2["tx_id"] in result2.accepted_tx_ids
