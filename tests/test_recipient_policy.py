"""Recipient-side o5 policy (#47) and the recipient's hold cap (#76), mock mode.

The recipient's clause is judged by the same evaluator pools the sender's
clause uses, so every verdict here is scripted through MockPolicyEvaluator by
the clause's own logic over the inputs the node feeds it. The bodies are real
clause text (they pass the admission screens); the mock decides by reading the
same streams the body reads.

Acceptance cases are named after the issue numbers: test_47_case_N, test_76_case_N.
"""
import json
import time
from contextlib import ExitStack
from unittest.mock import PropertyMock, patch

import pytest

import chain_state
import db
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_payload
from commands import getgovernance, sendtx
from consensus import sender_policy
from consensus.admission import validate_o5_clause_routing
from consensus.approvals import (
    audit_recipient_stream_collisions,
    screen_receive_stream,
)
from consensus.governance import (
    ConsensusLifecycleManager,
    build_mechanism_metadata,
    validate_recipient_policy_active,
)
from consensus.policy_mock import MockPolicyEvaluator

import test_retractable_apply as ra

I17 = f"i{tau_defs.RECIPIENT_HOLD_STREAM_INDEX}"
POOLS = ("apply", "admission")


def _lit(pubkey: str) -> str:
    return "{ #x" + pubkey + " }:bv[384]"


def allowlist_body(allowed: str) -> str:
    """'Accept incoming money only from <allowed>', outbound untouched."""
    return (
        f"((i17[t]:bv[64] > {{ #x0000000000000000 }}:bv[64]) && "
        f"!(i3[t]:bv[384] = {_lit(allowed)})) ? "
        f"(o5[t]:bv[24] = {{ #x000000 }}:bv[24]) : (o5[t]:bv[24] = {{ #x000001 }}:bv[24])"
    )


def block_cap_body(cap_blocks: int) -> str:
    """'Accept height-based parks held at most <cap> blocks; time-based parks
    and plain transfers are fine.'"""
    base = tau_defs.RECIPIENT_HOLD_BLOCKS_BASE
    bound = format(base + cap_blocks, "016x")
    return (
        f"(i17[t]:bv[64] > {{ #x{bound} }}:bv[64]) ? "
        f"(o5[t]:bv[24] = {{ #x000000 }}:bv[24]) : (o5[t]:bv[24] = {{ #x000001 }}:bv[24])"
    )


def hold_cap_body(cap_seconds: int) -> str:
    """'Accept payments held at most <cap> seconds'; a cap of 0 = instant only."""
    bound = format(tau_defs.RECIPIENT_HOLD_INSTANT + cap_seconds, "016x")
    return (
        f"(i17[t]:bv[64] > {{ #x{bound} }}:bv[64]) ? "
        f"(o5[t]:bv[24] = {{ #x000000 }}:bv[24]) : (o5[t]:bv[24] = {{ #x000001 }}:bv[24])"
    )


def both_ways_body(allowed_in: str, allowed_out: str) -> str:
    """One unit, both directions (#47 case 4): send only to <allowed_out>,
    receive only from <allowed_in>."""
    return (
        f"(((i17[t]:bv[64] = {{ #x0000000000000000 }}:bv[64]) && "
        f"!(i4[t]:bv[384] = {_lit(allowed_out)})) || "
        f"((i17[t]:bv[64] > {{ #x0000000000000000 }}:bv[64]) && "
        f"!(i3[t]:bv[384] = {_lit(allowed_in)}))) ? "
        f"(o5[t]:bv[24] = {{ #x000000 }}:bv[24]) : (o5[t]:bv[24] = {{ #x000001 }}:bv[24])"
    )


OUTBOUND_ONLY_BODY = (
    "(i1[t]:bv[24] > { #x0003e8 }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


def _hex(value) -> str:
    return str(value).replace("#x", "").lower()


class ScriptedPolicies(MockPolicyEvaluator):
    """Decides each known body by the same logic the clause text expresses."""

    def __init__(self, pool):
        super().__init__(pool=pool)
        self.rules = {}

    def add_allowlist(self, body, allowed):
        self.rules[body] = lambda i: "0" if (
            int(i.get(I17, "0")) > 0 and _hex(i.get("i3")) != allowed.lower()) else "1"

    def add_hold_cap(self, body, cap):
        self.rules[body] = lambda i: "0" if (
            int(i.get(I17, "0")) > tau_defs.RECIPIENT_HOLD_INSTANT + cap) else "1"

    def add_block_cap(self, body, cap):
        self.rules[body] = lambda i: "0" if (
            int(i.get(I17, "0")) > tau_defs.RECIPIENT_HOLD_BLOCKS_BASE + cap) else "1"

    def add_both_ways(self, body, allowed_in, allowed_out):
        def rule(i):
            sending = int(i.get(I17, "0")) == 0
            if sending:
                return "0" if _hex(i.get("i4")) != allowed_out.lower() else "1"
            return "0" if _hex(i.get("i3")) != allowed_in.lower() else "1"
        self.rules[body] = rule

    def add_outbound_cap(self, body, cap_amount):
        self.rules[body] = lambda i: "0" if int(i.get("i1", "0")) > cap_amount else "1"

    def verdict(self, body, inputs, *, timeout=None):
        if body in self.rules:
            self.set_verdict(body, self.rules[body])
        return super().verdict(body, inputs, timeout=timeout)


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)


# =============================================================================
# Stream encoding and helpers
# =============================================================================

def test_hold_values_encode_side_and_hold():
    base = tau_defs.RECIPIENT_HOLD_BLOCKS_BASE
    assert base == 1 << 63
    assert tau_defs.recipient_hold_value(0) == 1
    assert tau_defs.recipient_hold_value(600) == 601
    assert tau_defs.recipient_hold_value(-5) == 1
    assert tau_defs.recipient_hold_value(tau_defs.HeldBlocks(0)) == base
    assert tau_defs.recipient_hold_value(tau_defs.HeldBlocks(100)) == base + 100


def test_the_seconds_and_blocks_ranges_never_meet():
    from consensus.retractable import MAX_RELEASE_WINDOW_BLOCKS, MAX_RELEASE_WINDOW_SECONDS
    top_seconds = tau_defs.recipient_hold_value(MAX_RELEASE_WINDOW_SECONDS)
    assert top_seconds < tau_defs.recipient_hold_value(tau_defs.HeldBlocks(0))
    assert tau_defs.recipient_hold_value(10 ** 30) < tau_defs.RECIPIENT_HOLD_BLOCKS_BASE
    assert tau_defs.recipient_hold_value(tau_defs.HeldBlocks(MAX_RELEASE_WINDOW_BLOCKS)) < (1 << 64)


def test_i17_is_reserved_only_once_active():
    assert 17 not in tau_defs.reserved_operation_keys()
    assert 17 in tau_defs.reserved_operation_keys(recipient_policy_active=True)


def test_i17_is_readable_from_a_clause_only():
    clause = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_O5_CLAUSE, recipient_policy_active=True)
    user = tau_defs.rule_text_forbidden_input_streams(
        tau_defs.RULE_TEXT_CONTEXT_USER, recipient_policy_active=True)
    assert "i17" not in clause and "i17" in user


def test_a_clause_opts_in_only_by_reading_i17():
    assert sender_policy.reads_receive_stream(allowlist_body("ab"))
    assert not sender_policy.reads_receive_stream(OUTBOUND_ONLY_BODY)
    assert not sender_policy.reads_receive_stream("# i17 only in a comment\n" + OUTBOUND_ONLY_BODY)
    assert not sender_policy.reads_receive_stream("(i170[t]:bv[64] > x)")
    assert not sender_policy.reads_receive_stream(None)


def test_receiving_inputs_swap_the_owner_and_set_the_hold():
    values = {1: "5", 3: _lit("aa"), 4: _lit("bb"), 12: _lit("aa"), 5: "100"}
    out = sender_policy.receiving_inputs(values, "bb", 600)
    assert out[12] == _lit("bb") and out[17] == "601"
    assert out[3] == _lit("aa") and out[4] == _lit("bb") and out[1] == "5"
    assert values[12] == _lit("aa"), "the caller's map must not change"


def test_sending_inputs_mark_the_sender_pass():
    assert sender_policy.sending_inputs({1: "5"}) == {1: "5", 17: "0"}


def test_recipient_without_clause_never_reaches_an_evaluator():
    class _Exploding:
        def verdict(self, *a, **k):
            raise AssertionError("must not be consulted")
    sender_policy.set_evaluator("apply", _Exploding())
    assert sender_policy.recipient_clause_blocks(None, {}, "bb", 0, pool="apply") == (False, "")
    assert sender_policy.recipient_clause_blocks(
        OUTBOUND_ONLY_BODY, {}, "bb", 0, pool="apply") == (False, "")


def test_a_block_cap_is_found_in_blocks():
    ev = ScriptedPolicies("admission")
    body = block_cap_body(100)
    ev.add_block_cap(body, 100)
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(body, {}, "bb", blocks=True, pool="admission") == 100
    # in seconds this clause has no cap at all
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission") is None


def test_the_hold_cap_is_found_by_asking_the_clause():
    ev = ScriptedPolicies("admission")
    for cap in (0, 1, 600, 86_400):
        body = hold_cap_body(cap)
        ev.add_hold_cap(body, cap)
        sender_policy.set_evaluator("admission", ev)
        assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission") == cap


def test_no_cap_is_stated_when_the_refusal_is_not_about_the_hold():
    ev = ScriptedPolicies("admission")
    body = allowlist_body("aa")
    ev.add_allowlist(body, "aa")
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(body, {3: _lit("cc")}, "bb", pool="admission") is None


# =============================================================================
# Governance activation
# =============================================================================

def test_activation_is_one_way():
    assert validate_recipient_policy_active(True) is None
    assert validate_recipient_policy_active(False)
    assert validate_recipient_policy_active(1)


def test_the_flag_enters_the_meta_hash_only_once_set():
    off = build_mechanism_metadata("2/3")
    on = build_mechanism_metadata("2/3", recipient_policy_active=True)
    assert "recipient_policy_active" not in off
    assert on["recipient_policy_active"] is True
    lm = ConsensusLifecycleManager(active_validators=[ra.ALICE])
    before = lm.consensus_meta_hash()
    lm.activate_recipient_policy()
    assert lm.consensus_meta_hash() != before


def test_patch_activates_when_the_spec_never_mentions_i17():
    lm = ConsensusLifecycleManager(active_validators=[ra.ALICE])
    lm.apply_host_contract_patch({"recipient_policy_active": True},
                                 effective_spec_texts=[("application_rules", "always (o8[t]:bv[24] = { #x0 }:bv[24]).")])
    assert lm.recipient_policy_active is True


def test_patch_is_refused_when_the_spec_already_uses_i17():
    lm = ConsensusLifecycleManager(active_validators=[ra.ALICE])
    lm.apply_host_contract_patch(
        {"recipient_policy_active": True},
        effective_spec_texts=[("clause alice", "(i17[t]:bv[16] = { #x1 }:bv[16]) ? a : b")])
    assert lm.recipient_policy_active is False
    assert audit_recipient_stream_collisions([("x", "i17[t]:bv[8]")])
    assert audit_recipient_stream_collisions([("x", "# i17\n i4[t]:bv[384]")]) == []


def test_patch_rejects_a_downgrade_value():
    lm = ConsensusLifecycleManager(active_validators=[ra.ALICE])
    with pytest.raises(ValueError):
        lm.apply_host_contract_patch({"recipient_policy_active": False})


def test_activation_survives_a_fork_copy():
    lm = ConsensusLifecycleManager(active_validators=[ra.ALICE])
    lm.activate_recipient_policy()
    assert lm.fork().recipient_policy_active is True


# =============================================================================
# Deploy-time screening (#47 case 5, #76 case 6)
# =============================================================================

def test_receive_stream_screen():
    assert screen_receive_stream(OUTBOUND_ONLY_BODY, False) is None
    assert "not active" in screen_receive_stream(allowlist_body("aa"), False)
    assert screen_receive_stream(allowlist_body("aa"), True) is None
    assert "bv[64]" in screen_receive_stream("(i17[t]:bv[16] > x)", True)


class _Tip:
    def __init__(self, active):
        self.recipient_policy_active = active
        self.next_block_timestamp = 0
        self.eligibility_mode = ""

    def clause_for(self, *_a):
        return None


def _rule_tx(body):
    return {"sender_pubkey": ra.ALICE, "operations": {"0": f"always ( {body} )."}}


def test_47_case_5_a_node_without_activation_refuses_an_inbound_rule_at_deploy():
    body = allowlist_body(ra.CAROL)
    with patch("consensus.admission._rule_change_refusal", return_value=None):
        res = validate_o5_clause_routing(_rule_tx(body), _Tip(False), f"always ( {body} ).")
        assert res is not None and not res.is_valid
        assert res.code == "RECIPIENT_POLICY_INACTIVE"
        assert "recipient_policy_active" in res.error
        ok = validate_o5_clause_routing(_rule_tx(body), _Tip(True), f"always ( {body} ).")
        assert ok.is_valid and ok.data["o5_clause_action"] == "declare"


def test_an_outbound_only_rule_deploys_either_way():
    body = OUTBOUND_ONLY_BODY
    with patch("consensus.admission._rule_change_refusal", return_value=None):
        for active in (False, True):
            res = validate_o5_clause_routing(_rule_tx(body), _Tip(active), f"always ( {body} ).")
            assert res.is_valid


def test_47_case_5_the_node_reports_whether_recipient_policy_is_active(temp_database):
    from types import SimpleNamespace
    container = SimpleNamespace(chain_state=chain_state, db=db)
    chain_state.load_genesis("data/genesis.json")
    for active in (False, True):
        lm = ConsensusLifecycleManager(active_validators=[ra.ALICE])
        if active:
            lm.activate_recipient_policy()
        with patch.object(chain_state, "_lifecycle_manager", lm):
            out = getgovernance.execute("getgovernance", container)
        data = json.loads(out) if isinstance(out, str) else out
        rp = data["data"]["recipient_policy"]
        assert rp["supported"] is True and rp["active"] is active
        assert rp["receive_stream"] == "i17" and rp["receive_stream_width"] == 64


# =============================================================================
# Block apply
# =============================================================================

def _chain(active=True, balances=None):
    ch = ra.Chain(balances or {ra.ALICE: 10_000, ra.CAROL: 10_000, ra.MALLORY: 10_000, ra.BOB: 0})
    if active:
        ch.lm.activate_recipient_policy()
    return ch


def _register(ch, owner, body):
    ch.lm.rule_offers.accepted_clauses[(owner.lower(), tau_defs.USER_POLICY_STREAM_INDEX)] = body


def _outcome(result, tx):
    (o,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return o


def _send(sender_sk, sender, recipients, seq=0):
    ops = [[sender, to, str(amount)] for to, amount in recipients]
    return ra._sign({
        "tx_id": f"send-{next(ra._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": ra.FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": ops},
    }, sender_sk)


def _policies(pool="apply"):
    ev = ScriptedPolicies(pool)
    sender_policy.set_evaluator(pool, ev)
    return ev


def test_47_case_1_allowlist_admits_the_listed_payer_and_refuses_another():
    ch = _chain()
    body = allowlist_body(ra.ALICE)
    _policies().add_allowlist(body, ra.ALICE)
    _register(ch, ra.BOB, body)
    ok = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 300)])
    bad = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 300)])
    result = ch.block([ok, bad])
    assert ok["tx_id"] in result.accepted_tx_ids
    assert bad["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, bad).reason == "recipient_policy_block"
    assert "recipient policy" in " ".join(_outcome(result, bad).receipt_logs)
    assert ch.bal[ra.BOB] == 300 and ch.bal[ra.CAROL] == 10_000


def test_47_case_1_the_payers_own_send_policy_is_untouched():
    """A's outbound clause is judged as before, with i17 = 0 marking the send."""
    ch = _chain()
    ev = _policies()
    in_body = allowlist_body(ra.ALICE)
    ev.add_allowlist(in_body, ra.ALICE)
    ev.add_outbound_cap(OUTBOUND_ONLY_BODY, 1000)
    _register(ch, ra.BOB, in_body)
    _register(ch, ra.ALICE, OUTBOUND_ONLY_BODY)
    small = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 500)], seq=0)
    big = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 5000)], seq=1)
    result = ch.block([small, big])
    assert small["tx_id"] in result.accepted_tx_ids
    assert big["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, big).reason == "user_policy_block"
    sender_passes = [inp for body, inp in ev.verdict_calls if body == OUTBOUND_ONLY_BODY]
    assert sender_passes and all(inp[I17] == "0" for inp in sender_passes)
    assert all(inp["i12"] == "#x" + ra.ALICE for inp in sender_passes)


def test_the_recipient_pass_sees_the_counterparty_and_owns_i12():
    ch = _chain()
    ev = _policies()
    body = allowlist_body(ra.ALICE)
    ev.add_allowlist(body, ra.ALICE)
    _register(ch, ra.BOB, body)
    ch.block([_send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 7)])])
    (inputs,) = [inp for b, inp in ev.verdict_calls if b == body]
    assert inputs["i3"] == "#x" + ra.ALICE
    assert inputs["i4"] == "#x" + ra.BOB
    assert inputs["i12"] == "#x" + ra.BOB
    assert inputs["i1"] == "7" and inputs[I17] == "1"


def test_47_case_2_a_recipient_without_policy_can_be_paid():
    ch = _chain()
    _policies()
    tx = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 250)])
    result = ch.block([tx])
    assert tx["tx_id"] in result.accepted_tx_ids and ch.bal[ra.BOB] == 250


def test_47_case_2_an_outbound_only_clause_never_judges_incoming_money():
    ch = _chain()
    ev = _policies()
    ev.add_outbound_cap(OUTBOUND_ONLY_BODY, 1)  # would refuse anything if consulted
    _register(ch, ra.BOB, OUTBOUND_ONLY_BODY)
    tx = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 250)])
    result = ch.block([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert not [b for b, _ in ev.verdict_calls if b == OUTBOUND_ONLY_BODY]


def test_47_case_3_a_batch_fails_whole_when_one_recipient_refuses():
    ch = _chain()
    body = allowlist_body(ra.CAROL)          # MALLORY accepts only CAROL
    _policies().add_allowlist(body, ra.CAROL)
    _register(ch, ra.MALLORY, body)
    tx = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 100), (ra.MALLORY, 100)])
    before = dict(ch.bal)
    result = ch.block([tx])
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, tx).reason == "recipient_policy_block"
    assert ch.bal[ra.BOB] == before[ra.BOB] and ch.bal[ra.ALICE] == before[ra.ALICE]
    assert ch.bal[ra.MALLORY] == before[ra.MALLORY]


def test_47_case_4_one_unit_carries_outbound_and_inbound_rules():
    ch = _chain()
    body = both_ways_body(allowed_in=ra.ALICE, allowed_out=ra.CAROL)
    _policies().add_both_ways(body, ra.ALICE, ra.CAROL)
    _register(ch, ra.BOB, body)
    ch.bal[ra.BOB] = 5_000
    in_ok = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 10)])
    in_bad = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 10)])
    out_ok = _send(ra.SK_BOB, ra.BOB, [(ra.CAROL, 10)], seq=0)
    out_bad = _send(ra.SK_BOB, ra.BOB, [(ra.MALLORY, 10)], seq=1)
    result = ch.block([in_ok, in_bad, out_ok, out_bad])
    assert in_ok["tx_id"] in result.accepted_tx_ids
    assert out_ok["tx_id"] in result.accepted_tx_ids
    assert in_bad["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, in_bad).reason == "recipient_policy_block"
    assert out_bad["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, out_bad).reason == "user_policy_block"


def test_before_activation_no_recipient_clause_is_consulted():
    ch = _chain(active=False)
    ev = _policies()
    body = allowlist_body(ra.ALICE)
    ev.add_allowlist(body, ra.ALICE)
    _register(ch, ra.BOB, body)
    tx = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 300)])
    result = ch.block([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert not [b for b, _ in ev.verdict_calls if b == body]
    # and the sender pass is byte-identical to the pre-feature one: no i17 fed
    assert all(I17 not in inp for _b, inp in ev.verdict_calls)


def test_a_recipient_clause_that_does_not_build_blocks_the_payment():
    ch = _chain()
    ev = _policies()
    body = allowlist_body(ra.ALICE)
    ev.fail_build(body, "broken")
    _register(ch, ra.BOB, body)
    tx = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 1)])
    result = ch.block([tx])
    assert tx["tx_id"] in result.invalid_tx_ids


def test_a_refused_payment_charges_no_fee():
    ch = _chain()
    ch.fee = 7
    body = allowlist_body(ra.ALICE)
    _policies().add_allowlist(body, ra.ALICE)
    _register(ch, ra.BOB, body)
    tx = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 10)])
    ch.block([tx])
    assert ch.bal[ra.CAROL] == 10_000


# --- #76 at apply -------------------------------------------------------------

def test_76_case_1_cap_zero_admits_plain_and_refuses_any_park():
    ch = _chain()
    body = hold_cap_body(0)
    _policies().add_hold_cap(body, 0)
    _register(ch, ra.BOB, body)
    plain = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 100)], seq=0)
    park = ra.park_tx(seq=1, at_time=ra.TS + 60, amount=100)
    result = ch.block([plain, park])
    assert plain["tx_id"] in result.accepted_tx_ids
    assert park["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, park).reason == "recipient_max_hold"
    assert ch.book.open_count() == 0


@pytest.mark.parametrize("hold, admitted", [(600, True), (601, False), (3600, False)])
def test_76_case_2_a_600_second_cap(hold, admitted):
    ch = _chain()
    body = hold_cap_body(600)
    _policies().add_hold_cap(body, 600)
    _register(ch, ra.BOB, body)
    park = ra.park_tx(at_time=ra.TS + hold, amount=100)
    result = ch.block([park])
    assert (park["tx_id"] in result.accepted_tx_ids) is admitted
    assert ch.book.open_count() == (1 if admitted else 0)


def test_76_a_seconds_cap_refuses_a_height_based_park():
    ch = _chain()
    body = hold_cap_body(10**6)
    ev = _policies()
    ev.add_hold_cap(body, 10**6)
    _register(ch, ra.BOB, body)
    park = ra.park_tx(at_height=ra.HEIGHT + 3, amount=100)
    result = ch.block([park])
    assert park["tx_id"] in result.invalid_tx_ids
    assert "held 3 blocks" in " ".join(_outcome(result, park).receipt_logs)
    inputs = [inp for b, inp in ev.verdict_calls if b == body][0]
    assert inputs[I17] == str(tau_defs.RECIPIENT_HOLD_BLOCKS_BASE + 3)


@pytest.mark.parametrize("blocks, admitted", [(50, True), (100, True), (101, False)])
def test_76_a_cap_in_blocks_bounds_height_based_parks(blocks, admitted):
    ch = _chain()
    body = block_cap_body(100)
    _policies().add_block_cap(body, 100)
    _register(ch, ra.BOB, body)
    park = ra.park_tx(at_height=ra.HEIGHT + blocks, amount=100)
    result = ch.block([park])
    assert (park["tx_id"] in result.accepted_tx_ids) is admitted


def test_76_a_cap_in_blocks_leaves_time_based_parks_alone():
    ch = _chain()
    body = block_cap_body(0)
    _policies().add_block_cap(body, 0)
    _register(ch, ra.BOB, body)
    park = ra.park_tx(at_time=ra.TS + 80 * 86_400, amount=100)
    result = ch.block([park])
    assert park["tx_id"] in result.accepted_tx_ids


def test_76_case_5_the_apply_receipt_names_a_hold_refusal_cheaply():
    """At apply a hold refusal is named (reason recipient_max_hold, the hold in
    the log, which gettxstatus returns as the detail) with ONE extra evaluation;
    the numeric cap is left to admission/checktx/getrecipientpolicy, so an
    attacker-chosen clause cannot multiply block-building work."""
    ch = _chain()
    body = hold_cap_body(600)
    ev = _policies()
    ev.add_hold_cap(body, 600)
    _register(ch, ra.BOB, body)
    park = ra.park_tx(at_time=ra.TS + 3600, amount=100)
    result = ch.block([park])
    out = _outcome(result, park)
    assert out.reason == "recipient_max_hold"
    logs = " ".join(out.receipt_logs)
    assert "payment held 3600 seconds" in logs and "checktx" in logs
    assert len([b for b, _ in ev.verdict_calls if b == body]) == 2


def test_an_allowlist_refusal_of_a_park_at_apply_is_a_policy_block():
    ch = _chain()
    body = allowlist_body(ra.CAROL)
    _policies().add_allowlist(body, ra.CAROL)
    _register(ch, ra.BOB, body)
    park = ra.park_tx(at_time=ra.TS + 600, amount=100)   # from ALICE, not CAROL
    result = ch.block([park])
    assert _outcome(result, park).reason == "recipient_policy_block"
    assert "at most" not in " ".join(_outcome(result, park).receipt_logs)


def test_the_recipient_pass_reads_the_recipients_own_balance_on_i2():
    """i-streams describe the clause owner in both passes: the sender pass sees
    the sender's parent balance, the recipient pass the recipient's."""
    ch = _chain(balances={ra.ALICE: 10_000, ra.CAROL: 10_000, ra.MALLORY: 10_000, ra.BOB: 4_242})
    ev = _policies()
    body = allowlist_body(ra.ALICE)
    ev.add_allowlist(body, ra.ALICE)
    _register(ch, ra.BOB, body)
    ch.block([_send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 7)])])
    (inputs,) = [inp for b, inp in ev.verdict_calls if b == body]
    assert inputs["i2"] == "4242"


def test_76_case_3_no_policy_accepts_parks_of_any_length():
    ch = _chain()
    _policies()
    short = ra.park_tx(seq=0, at_time=ra.TS + 60, amount=10)
    long_ = ra.park_tx(seq=1, at_time=ra.TS + 80 * 86_400, amount=10)
    by_height = ra.park_tx(seq=2, at_height=ra.HEIGHT + 50, amount=10)
    result = ch.block([short, long_, by_height])
    assert {short["tx_id"], long_["tx_id"], by_height["tx_id"]} <= set(result.accepted_tx_ids)


def test_76_case_4_the_payers_retract_is_never_gated():
    ch = _chain()
    _policies()
    park = ra.park_tx(seq=0, at_time=ra.TS + 600, amount=100)
    ch.block([park])
    assert ch.book.open_count() == 1
    body = hold_cap_body(0)                  # BOB tightens to instant-only afterwards
    ev = _policies()
    ev.add_hold_cap(body, 0)
    _register(ch, ra.BOB, body)
    retract = ra.retract_tx(ra.rid_of(park), seq=1)
    result = ch.block([retract], height=ra.HEIGHT + 1, ts=ra.TS + 10)
    assert retract["tx_id"] in result.accepted_tx_ids
    assert ch.bal[ra.ALICE] == 10_000
    assert not [b for b, _ in ev.verdict_calls if b == body]


def test_76_a_matured_release_is_not_rechecked():
    ch = _chain()
    _policies()
    park = ra.park_tx(seq=0, at_time=ra.TS + 600, amount=100)
    ch.block([park])
    body = hold_cap_body(0)
    ev = _policies()
    ev.add_hold_cap(body, 0)
    _register(ch, ra.BOB, body)
    ch.block([], height=ra.HEIGHT + 1, ts=ra.TS + 601)
    assert ch.bal[ra.BOB] == 100
    assert not [b for b, _ in ev.verdict_calls if b == body]


def test_the_park_hold_is_measured_from_the_block_that_carries_it():
    ch = _chain()
    ev = _policies()
    body = hold_cap_body(10**6)
    ev.add_hold_cap(body, 10**6)
    _register(ch, ra.BOB, body)
    ch.block([ra.park_tx(at_time=ra.TS + 600, amount=10)])
    (inputs,) = [inp for b, inp in ev.verdict_calls if b == body]
    assert inputs[I17] == str(1 + 600)


# =============================================================================
# Mempool admission
# =============================================================================

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
OTHER = ra.CAROL
CLAUSE_VIEW = "consensus.facade.TipAdmissionView.clause_for"
ACTIVE_VIEW = "consensus.facade.TipAdmissionView.recipient_policy_active"
CLOCK_VIEW = "consensus.facade.TipAdmissionView.next_block_timestamp"
NOW = 1_800_000_000


@pytest.fixture
def admission(temp_database):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state.load_genesis("data/genesis.json")
    db.clear_mempool()
    chain_state._balances[SENDER] = 100000
    with ExitStack() as stack:
        for target, kwargs in (
            ("commands.sendtx.validate_bls_pubkey", {"return_value": None}),
            ("consensus.admission.validate_bls_pubkey", {"return_value": None}),
            ("tau_manager.is_force_test_enabled", {"return_value": False}),
            ("tau_manager.communicate_with_tau_multi", {"return_value": {1: "1", 5: "1"}}),
            ("commands.sendtx._admission_timestamp", {"return_value": NOW}),
        ):
            stack.enter_context(patch(target, **kwargs))
        stack.enter_context(patch(ACTIVE_VIEW, new_callable=PropertyMock, return_value=True))
        stack.enter_context(patch(CLOCK_VIEW, new_callable=PropertyMock, return_value=NOW))
        ready = stack.enter_context(patch("tau_manager.tau_ready"))
        ready.is_set.return_value = True
        yield stack


def _clauses(mapping):
    def clause_for(_self, pubkey, stream):
        return mapping.get(pubkey.lower()) if stream == 5 else None
    return patch(CLAUSE_VIEW, autospec=True, side_effect=clause_for)


def _queue_send(recipients):
    tx = {
        "sender_pubkey": SENDER,
        "sequence_number": chain_state.get_sequence_number(SENDER),
        "expiration_time": NOW + 100,
        "expire_at_height": 5000,
        "operations": {"1": [[SENDER, to, "1"] for to in recipients]},
        "fee_limit": "1000",
    }
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, SK_ALICE)))


HEIGHT_VIEW = "consensus.facade.TipAdmissionView.next_block_height"


def _queue_park(hold_seconds=None, at_height=None, seq=None):
    tx = {
        "tx_type": "retractable_transfer",
        "sender_pubkey": SENDER,
        "sequence_number": chain_state.get_sequence_number(SENDER) if seq is None else seq,
        "expiration_time": NOW + 1,
        "expire_at_height": 5000,
        "fee_limit": "1000",
        "recipient_pubkey": RECIPIENT,
        "amount": 1,
    }
    if at_height is not None:
        tx["release_at_height"] = at_height
        tx["expire_at_height"] = at_height - 1   # must not be after the release
        tx["expiration_time"] = NOW + 100
    else:
        tx["release_at_time"] = NOW + hold_seconds
    return sendtx.queue_transaction(json.dumps(sign_payload(tx, SK_ALICE)))


def test_47_case_1_admission_refuses_an_unlisted_payer_with_a_distinct_reason(admission):
    body = allowlist_body(OTHER)
    ev = _policies("admission")
    ev.add_allowlist(body, OTHER)
    with _clauses({RECIPIENT: body}):
        res = _queue_send([RECIPIENT])
    assert res["ok"] is False and res["code"] == "RECIPIENT_POLICY"
    assert "recipient policy (o5)" in res["message"] and "#1" in res["message"]
    assert db.get_mempool_txs() == []


def test_47_case_1_admission_admits_the_listed_payer(admission):
    body = allowlist_body(SENDER)
    _policies("admission").add_allowlist(body, SENDER)
    with _clauses({RECIPIENT: body}):
        assert _queue_send([RECIPIENT])["ok"] is True


def test_47_case_2_admission_neutral_default(admission):
    _policies("admission")
    with _clauses({}):
        assert _queue_send([RECIPIENT])["ok"] is True


def test_47_case_3_admission_refuses_the_whole_batch(admission):
    body = allowlist_body(OTHER)
    _policies("admission").add_allowlist(body, OTHER)
    with _clauses({OTHER: body}):
        res = _queue_send([RECIPIENT, OTHER])
    assert res["ok"] is False and res["code"] == "RECIPIENT_POLICY"
    assert "#2" in res["message"]
    assert db.get_mempool_txs() == []


def test_admission_and_apply_feed_the_recipient_the_same_streams(admission):
    chain_state._balances[RECIPIENT] = 777
    body = allowlist_body(SENDER)
    ev = _policies("admission")
    ev.add_allowlist(body, SENDER)
    with _clauses({RECIPIENT: body}):
        _queue_send([RECIPIENT])
    (inputs,) = [inp for b, inp in ev.verdict_calls if b == body]
    assert inputs["i12"] == "#x" + RECIPIENT and inputs["i3"] == "#x" + SENDER
    assert inputs[I17] == "1" and inputs["i1"] == "1"
    assert inputs["i2"] == "777", "the recipient's own balance"


def test_76_case_1_and_5_admission_refuses_a_park_with_the_cap_in_the_message(admission):
    body = hold_cap_body(0)
    _policies("admission").add_hold_cap(body, 0)
    with _clauses({RECIPIENT: body}):
        assert _queue_send([RECIPIENT])["ok"] is True
        res = _queue_park(hold_seconds=600, seq=1)
    assert res["ok"] is False and res["code"] == "RECIPIENT_MAX_HOLD"
    assert "only payments that arrive instantly" in res["message"]
    assert res["details"]["max_hold_seconds"] == 0
    assert res["details"]["hold_seconds"] == 600


@pytest.mark.parametrize("hold, ok", [(600, True), (3600, False)])
def test_76_case_2_and_5_admission_with_a_600_second_cap(admission, hold, ok):
    body = hold_cap_body(600)
    _policies("admission").add_hold_cap(body, 600)
    with _clauses({RECIPIENT: body}):
        res = _queue_park(hold_seconds=hold)
    assert res["ok"] is ok
    if not ok:
        assert res["code"] == "RECIPIENT_MAX_HOLD"
        assert "at most 600 seconds" in res["message"]
        assert res["details"]["max_hold_seconds"] == 600


def test_76_admission_states_a_block_cap_in_blocks(admission):
    admission.enter_context(patch(HEIGHT_VIEW, new_callable=PropertyMock, return_value=10))
    body = block_cap_body(100)
    _policies("admission").add_block_cap(body, 100)
    with _clauses({RECIPIENT: body}):
        res = _queue_park(at_height=10 + 500)
    assert res["ok"] is False and res["code"] == "RECIPIENT_MAX_HOLD"
    assert "at most 100 blocks" in res["message"]
    assert res["details"]["max_hold_blocks"] == 100 and res["details"]["hold_blocks"] == 500


def test_76_admission_a_seconds_cap_explains_a_height_based_park(admission):
    admission.enter_context(patch(HEIGHT_VIEW, new_callable=PropertyMock, return_value=10))
    body = hold_cap_body(600)
    _policies("admission").add_hold_cap(body, 600)
    with _clauses({RECIPIENT: body}):
        res = _queue_park(at_height=10 + 5)
    assert res["ok"] is False and res["code"] == "RECIPIENT_MAX_HOLD"
    assert "does not accept a hold counted in blocks" in res["message"]


def test_76_case_3_admission_without_policy_admits_any_park(admission):
    _policies("admission")
    with _clauses({}):
        assert _queue_park(hold_seconds=80 * 86_400)["ok"] is True


def test_an_allowlist_refusal_of_a_park_is_not_called_a_hold_refusal(admission):
    body = allowlist_body(OTHER)
    _policies("admission").add_allowlist(body, OTHER)
    with _clauses({RECIPIENT: body}):
        res = _queue_park(hold_seconds=600)
    assert res["ok"] is False and res["code"] == "RECIPIENT_POLICY"


def test_admission_before_activation_never_consults_the_recipient(admission):
    admission.enter_context(patch(ACTIVE_VIEW, new_callable=PropertyMock, return_value=False))
    body = allowlist_body(OTHER)
    ev = _policies("admission")
    ev.add_allowlist(body, OTHER)
    with _clauses({RECIPIENT: body}):
        assert _queue_send([RECIPIENT])["ok"] is True
    assert not [b for b, _ in ev.verdict_calls if b == body]


def test_47_case_5_checktx_refuses_an_inbound_rule_on_an_inactive_chain(admission):
    """The wallet-facing check: a dry run reports the refusal, it does not
    silently admit a rule that would never run."""
    from commands import checktx

    admission.enter_context(patch(ACTIVE_VIEW, new_callable=PropertyMock, return_value=False))
    body = allowlist_body(OTHER)
    tx = sign_payload({
        "sender_pubkey": SENDER,
        "sequence_number": chain_state.get_sequence_number(SENDER),
        "expiration_time": NOW + 100,
        "expire_at_height": 5000,
        "operations": {"0": f"always ( {body} )."},
        "fee_limit": "1000",
    }, SK_ALICE)
    out = json.loads(checktx.execute("checktx " + json.dumps(tx), None))
    assert out["status"] == "error"
    assert "RECIPIENT_POLICY_INACTIVE" in json.dumps(out)
    assert "recipient_policy_active" in json.dumps(out)


# =============================================================================
# Restart: the one-way flag survives, with a byte-identical meta hash
# =============================================================================

import test_approval_persistence as persist


@pytest.mark.usefixtures("isolated_chain_state")
@pytest.mark.parametrize("active", [True, False])
def test_the_activation_flag_round_trips_a_restart(temp_database, active):
    lm = persist._seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    if active:
        lm.activate_recipient_policy()
    before = lm.consensus_meta_hash()
    reloaded = persist._reload()
    assert reloaded.recipient_policy_active is active
    assert reloaded.consensus_meta_hash() == before


# =============================================================================
# Fresh genesis and the admission-side activation audit
# =============================================================================

def test_a_fresh_genesis_can_ship_active(tmp_path):
    import subprocess
    import sys
    from py_ecc.bls import G2Basic as bls

    repo = __import__("os").path.dirname(__import__("os").path.dirname(__file__))
    sk = format(bls.KeyGen(b"recipient-genesis-test"), "064x")
    out = tmp_path / "genesis.json"
    subprocess.run([sys.executable, "scripts/gen_genesis.py", "--validator-privkey", sk,
                    "--recipient-policy-active", "--out", str(out)],
                   cwd=repo, check=True, capture_output=True, timeout=120)
    mech = json.loads(out.read_text())["consensus_meta"]["mechanism_specific_metadata"]
    assert mech["recipient_policy_active"] is True
    out2 = tmp_path / "plain.json"
    subprocess.run([sys.executable, "scripts/gen_genesis.py", "--validator-privkey", sk,
                    "--out", str(out2)], cwd=repo, check=True, capture_output=True, timeout=120)
    plain = json.loads(out2.read_text())["consensus_meta"]["mechanism_specific_metadata"]
    assert "recipient_policy_active" not in plain


def test_loading_an_active_genesis_turns_the_flag_on(temp_database, tmp_path):
    genesis = json.loads(open("data/genesis.json").read())
    genesis["consensus_meta"]["mechanism_specific_metadata"]["recipient_policy_active"] = True
    path = tmp_path / "g.json"
    path.write_text(json.dumps(genesis))
    chain_state.load_genesis(str(path))
    assert chain_state._genesis_recipient_policy_active is True


def test_the_activation_proposal_is_refused_when_the_tip_spec_uses_i17(temp_database):
    from consensus.admission import _check_host_contract_patch

    chain_state._consensus_rules_state = "always ( o6[t]:bv[16] = i10[t]:bv[16] )."
    chain_state._application_rules_state = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
    assert _check_host_contract_patch({"recipient_policy_active": True}) is None
    chain_state._application_rules_state = (
        "always ( (i17[t]:bv[24] = { #x01 }:bv[24]) -> (o13[t]:bv[24] = { #x01 }:bv[24]) ).")
    err = _check_host_contract_patch({"recipient_policy_active": True})
    assert err and "i17" in err
    assert "must be true" in _check_host_contract_patch({"recipient_policy_active": False})


# =============================================================================
# getrecipientpolicy: the wallet pre-flight
# =============================================================================

def _preflight(args):
    from commands import getrecipientpolicy
    return json.loads(getrecipientpolicy.execute("getrecipientpolicy " + args, None))


def test_preflight_describes_the_recipient(admission):
    body = allowlist_body(SENDER)
    _policies("admission").add_allowlist(body, SENDER)
    with _clauses({RECIPIENT: body}):
        out = _preflight(RECIPIENT)["data"]
    assert out["recipient_policy_active"] is True
    assert out["has_policy_clause"] is True and out["judges_incoming"] is True


def test_preflight_matches_admission_for_an_allowlist(admission):
    body = allowlist_body(OTHER)
    _policies("admission").add_allowlist(body, OTHER)
    with _clauses({RECIPIENT: body}):
        refused = _preflight(f"{RECIPIENT} {SENDER} 5")["data"]
        admitted = _preflight(f"{RECIPIENT} {OTHER} 5")["data"]
        res = _queue_send([RECIPIENT])
    assert refused["allowed"] is False and refused["code"] == "RECIPIENT_POLICY"
    assert admitted["allowed"] is True
    assert res["code"] == refused["code"]


@pytest.mark.parametrize("hold, unit, allowed, cap_key, cap", [
    (600, "seconds", True, None, None),
    (3600, "seconds", False, "max_hold_seconds", 600),
])
def test_preflight_states_the_cap(admission, hold, unit, allowed, cap_key, cap):
    body = hold_cap_body(600)
    _policies("admission").add_hold_cap(body, 600)
    with _clauses({RECIPIENT: body}):
        out = _preflight(f"{RECIPIENT} {SENDER} 5 {hold} {unit}")["data"]
    assert out["allowed"] is allowed
    if cap_key:
        assert out["code"] == "RECIPIENT_MAX_HOLD" and out[cap_key] == cap


def test_preflight_neutral_default_without_an_inbound_clause(admission):
    class _Exploding:
        def verdict(self, *a, **k):
            raise AssertionError("must not be consulted")
    sender_policy.set_evaluator("admission", _Exploding())
    with _clauses({RECIPIENT: OUTBOUND_ONLY_BODY}):
        out = _preflight(f"{RECIPIENT} {SENDER} 5")["data"]
    assert out["allowed"] is True and out["neutral_default"] is True
    assert out["judges_incoming"] is False


@pytest.mark.parametrize("args", ["", "zz", f"{RECIPIENT} {SENDER}", f"{RECIPIENT} {SENDER} 5 10 weeks",
                                  f"{RECIPIENT} {SENDER} -1"])
def test_preflight_rejects_bad_arguments(admission, args):
    out = _preflight(args)
    assert out["status"] == "error"


# =============================================================================
# `tau-testnet policy receive`: the composed clause deploys
# =============================================================================

from tau_testnet_cli.recipient_rules import compose_receive_clause

_COMPOSE_CASES = [
    dict(allow=[ra.ALICE]),
    dict(allow=[ra.ALICE, ra.CAROL]),
    dict(max_hold_seconds=0),
    dict(max_hold_seconds=600),
    dict(max_hold_blocks=10),
    dict(max_hold_seconds=600, max_hold_blocks=10),
    dict(allow=[ra.ALICE], max_hold_seconds=600, send_only_to=[ra.CAROL]),
    dict(send_only_to=[ra.CAROL]),
]


@pytest.mark.parametrize("opts", _COMPOSE_CASES)
def test_every_composed_clause_passes_the_deploy_screens(opts):
    rule = compose_receive_clause(**opts)
    with patch("consensus.admission._rule_change_refusal", return_value=None):
        res = validate_o5_clause_routing({"sender_pubkey": ra.BOB, "operations": {"0": rule}},
                                         _Tip(True), rule)
    assert res.is_valid, res.error
    assert res.data["o5_clause_action"] == "declare"
    # an inbound clause opts in by reading i17; a pure outbound one too (it
    # needs i17 = 0 to tell sending from receiving)
    assert sender_policy.reads_receive_stream(res.data["o5_clause_body"])


def test_compose_refuses_nothing_to_do_and_bad_values():
    with pytest.raises(ValueError):
        compose_receive_clause()
    with pytest.raises(ValueError):
        compose_receive_clause(max_hold_seconds=-1)
    with pytest.raises(ValueError):
        compose_receive_clause(allow=["not-a-key"])


def test_cli_policy_receive_prints_and_writes(tmp_path, capsys):
    from tau_testnet_cli import cli
    out = tmp_path / "rule.tau"
    code = cli.main(["policy", "receive", "--allow", ra.ALICE,
                     "--max-hold-seconds", "600", "--out", str(out)])
    assert code == 0
    printed = capsys.readouterr().out.strip()
    assert printed == out.read_text().strip()
    assert printed == compose_receive_clause(allow=[ra.ALICE], max_hold_seconds=600)


# =============================================================================
# Properties (hypothesis)
# =============================================================================

from hypothesis import given, settings, strategies as st

from consensus.retractable import MAX_RELEASE_WINDOW_BLOCKS, MAX_RELEASE_WINDOW_SECONDS


@settings(max_examples=200, deadline=None)
@given(cap=st.integers(0, MAX_RELEASE_WINDOW_SECONDS - 1))
def test_property_the_reported_seconds_cap_is_exact(cap):
    """For ANY seconds cap below the release window, the search returns it:
    the clause admits `cap` and refuses `cap + 1`."""
    ev = ScriptedPolicies("admission")
    body = hold_cap_body(cap)
    ev.add_hold_cap(body, cap)
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission") == cap
    sender_policy.set_evaluator("admission", None)


@settings(max_examples=200, deadline=None)
@given(cap=st.integers(0, MAX_RELEASE_WINDOW_BLOCKS - 1))
def test_property_the_reported_blocks_cap_is_exact(cap):
    ev = ScriptedPolicies("admission")
    body = block_cap_body(cap)
    ev.add_block_cap(body, cap)
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(
        body, {}, "bb", blocks=True, pool="admission") == cap
    sender_policy.set_evaluator("admission", None)


@settings(max_examples=300, deadline=None)
@given(seconds=st.integers(0, MAX_RELEASE_WINDOW_SECONDS),
       blocks=st.integers(0, MAX_RELEASE_WINDOW_BLOCKS))
def test_property_receive_values_keep_their_order(seconds, blocks):
    """sending < plain < any seconds hold < any blocks hold, and each range is
    monotone in its hold: what makes a cap one comparison."""
    v_sec = tau_defs.recipient_hold_value(seconds)
    v_blk = tau_defs.recipient_hold_value(tau_defs.HeldBlocks(blocks))
    assert tau_defs.RECIPIENT_HOLD_SENDING < tau_defs.RECIPIENT_HOLD_INSTANT <= v_sec < v_blk
    assert v_sec == tau_defs.RECIPIENT_HOLD_INSTANT + seconds
    assert v_blk == tau_defs.RECIPIENT_HOLD_BLOCKS_BASE + blocks
    assert v_blk < 1 << tau_defs.RECIPIENT_HOLD_BV_WIDTH


@settings(max_examples=40, deadline=None)
@given(payers=st.lists(st.sampled_from([ra.ALICE, ra.CAROL, ra.MALLORY]), min_size=1,
                       max_size=3, unique=True),
       allowed=st.sampled_from([ra.ALICE, ra.CAROL, ra.MALLORY]))
def test_property_apply_admits_exactly_the_allowed_payers(payers, allowed):
    ch = _chain()
    body = allowlist_body(allowed)
    _policies().add_allowlist(body, allowed)
    _register(ch, ra.BOB, body)
    keys = {ra.ALICE: ra.SK_ALICE, ra.CAROL: ra.SK_CAROL, ra.MALLORY: ra.SK_MALLORY}
    # one payment per payer: a refused payment uses no sequence number
    txs = [_send(keys[p], p, [(ra.BOB, 1)]) for p in payers]
    result = ch.block(txs)
    for p, tx in zip(payers, txs):
        if p == allowed:
            assert tx["tx_id"] in result.accepted_tx_ids
        else:
            assert tx["tx_id"] in result.invalid_tx_ids
            assert _outcome(result, tx).reason == "recipient_policy_block"


def test_a_refused_payment_uses_no_sequence_number():
    ch = _chain()
    body = allowlist_body(ra.ALICE)
    _policies().add_allowlist(body, ra.ALICE)
    _register(ch, ra.BOB, body)
    refused = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 5)], seq=0)
    ch.block([refused])
    retry = _send(ra.SK_CAROL, ra.CAROL, [(ra.MALLORY, 5)], seq=0)
    result = ch.block([retry], height=ra.HEIGHT + 1)
    assert retry["tx_id"] in result.accepted_tx_ids


# =============================================================================
# getgovernance with a flag patch scheduled (found by the live run)
# =============================================================================

@pytest.mark.parametrize("patch_", [{"recipient_policy_active": True},
                                    {"approval_slots_active": True}])
def test_getgovernance_returns_while_a_flag_patch_is_scheduled(temp_database, patch_):
    """The scheduled-update precheck audits the rules in force, which takes the
    rules lock; run inside getgovernance's own locks it never returned (and the
    node could apply no further block). It now runs after they are released."""
    import threading
    from types import SimpleNamespace
    from consensus.governance import ConsensusRuleUpdate

    chain_state.load_genesis("data/genesis.json")
    lm = ConsensusLifecycleManager(active_validators=[ra.ALICE])
    update = ConsensusRuleUpdate(
        rule_revisions=["always ( o6[t]:bv[16] = i10[t]:bv[16] )."],
        activate_at_height=50, host_contract_patch=dict(patch_), proposer_pubkey=ra.ALICE)
    uid = update.update_id
    lm.update_payloads[uid] = update
    lm.scheduled_updates.append((50, uid))
    out = {}

    def call():
        with patch.object(chain_state, "_lifecycle_manager", lm):
            out["res"] = getgovernance.execute(
                "getgovernance", SimpleNamespace(chain_state=chain_state, db=db))

    t = threading.Thread(target=call, daemon=True)
    t.start()
    t.join(timeout=20)
    assert not t.is_alive(), "getgovernance hung with a flag patch scheduled"
    data = json.loads(out["res"])["data"]
    (entry,) = data["scheduled_updates"]
    assert "precheck" in entry



# =============================================================================
# Findings of an adversarial review (non-monotone caps, forged i17, atomicity)
# =============================================================================

def test_a_non_monotone_clause_never_gets_a_reported_cap():
    """Admits holds up to 100 s and again from 300 s to 400 s: no single cap
    exists, so none may be reported, whatever the search lands on."""
    ev = ScriptedPolicies("admission")
    body = "NON_MONOTONE_i17"
    ev.rules[body] = lambda i: "1" if (
        int(i.get(I17, "0")) <= 101 or 301 <= int(i.get(I17, "0")) <= 401) else "0"
    sender_policy.set_evaluator("admission", ev)
    for held in (150, 250, 500):
        assert sender_policy.recipient_hold_cap(
            body, {}, "bb", pool="admission", held=held) is None


def test_a_cap_below_the_payments_hold_is_reported_only_when_it_is_the_boundary():
    ev = ScriptedPolicies("admission")
    body = hold_cap_body(600)
    ev.add_hold_cap(body, 600)
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission", held=601) == 600
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission", held=600) is None


def _forging_tx(sender_sk, sender, to):
    return ra._sign({
        "tx_id": f"forge-{next(ra._TX_SEQ)}", "tx_type": "user_tx",
        "sender_pubkey": sender, "sequence_number": 0,
        "expiration_time": ra.FAR, "expire_at_height": 1000, "fee_limit": "100",
        "operations": {"1": [[sender, to, "5"]], "17": "1"},
    }, sender_sk)


def test_a_sender_cannot_write_i17_at_apply():
    ch = _chain()
    body = hold_cap_body(0)
    _policies().add_hold_cap(body, 0)
    _register(ch, ra.BOB, body)
    tx = _forging_tx(ra.SK_ALICE, ra.ALICE, ra.BOB)
    result = ch.block([tx])
    assert tx["tx_id"] in result.invalid_tx_ids
    assert "reserved" in " ".join(_outcome(result, tx).receipt_logs).lower()


def test_a_sender_cannot_write_i17_at_admission(admission):
    tx = {
        "sender_pubkey": SENDER,
        "sequence_number": chain_state.get_sequence_number(SENDER),
        "expiration_time": NOW + 100, "expire_at_height": 5000,
        "operations": {"1": [[SENDER, RECIPIENT, "1"]], "17": "1"},
        "fee_limit": "1000",
    }
    res = sendtx.queue_transaction(json.dumps(sign_payload(tx, SK_ALICE)))
    assert res["ok"] is False and "reserved" in res["message"]


def test_before_activation_i17_stays_an_ordinary_custom_input(admission):
    admission.enter_context(patch(ACTIVE_VIEW, new_callable=PropertyMock, return_value=False))
    _policies("admission")
    tx = {
        "sender_pubkey": SENDER,
        "sequence_number": chain_state.get_sequence_number(SENDER),
        "expiration_time": NOW + 100, "expire_at_height": 5000,
        "operations": {"1": [[SENDER, RECIPIENT, "1"]], "17": "1"},
        "fee_limit": "1000",
    }
    with _clauses({}):
        assert sendtx.queue_transaction(json.dumps(sign_payload(tx, SK_ALICE)))["ok"] is True


def test_the_recipient_pass_overrides_any_sender_supplied_i17():
    out = sender_policy.receiving_inputs({17: "1", 1: "5"}, "bb", 3600)
    assert out[17] == str(1 + 3600)
    assert sender_policy.sending_inputs({17: "999"})[17] == "0"


def test_a_refused_batch_leaves_the_whole_state_untouched():
    """Output 1 passes, output 2 is refused (and the reverse order): balances,
    sequences and the retractable book are exactly as before."""
    for order in ((ra.BOB, ra.MALLORY), (ra.MALLORY, ra.BOB)):
        ch = _chain()
        body = allowlist_body(ra.CAROL)
        _policies().add_allowlist(body, ra.CAROL)
        _register(ch, ra.MALLORY, body)
        before = (dict(ch.bal), dict(ch.seq), ch.book.escrow_total(), ch.book.open_count())
        tx = _send(ra.SK_ALICE, ra.ALICE, [(order[0], 100), (order[1], 100)])
        result = ch.block([tx])
        assert tx["tx_id"] in result.invalid_tx_ids
        after = (dict(ch.bal), dict(ch.seq), ch.book.escrow_total(), ch.book.open_count())
        assert after == before


# Admits holds 0-100 s and 300-400 s (i17 1..101 and 301..401), refuses the rest.
NON_MONOTONE = '(((i17[t]:bv[64] > { #x0000000000000065 }:bv[64]) && (i17[t]:bv[64] < { #x000000000000012d }:bv[64])) || (i17[t]:bv[64] > { #x0000000000000191 }:bv[64])) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])'


def test_a_real_non_monotone_clause_gets_no_cap_from_change_point_analysis():
    ev = ScriptedPolicies("admission")
    ev.rules[NON_MONOTONE] = lambda i: "0" if (
        (101 < int(i.get(I17, "0")) < 301) or int(i.get(I17, "0")) > 401) else "1"
    sender_policy.set_evaluator("admission", ev)
    for held in (150, 250, 500):
        assert sender_policy.recipient_hold_cap(
            NON_MONOTONE, {}, "bb", pool="admission", held=held) is None
    # the analysis evaluated only the change points, never a search
    assert len(ev.verdict_calls) < 3 * 15


def test_a_clause_with_arithmetic_gets_no_cap():
    body = ("((i17[t]:bv[64] + { #x0000000000000001 }:bv[64]) > { #x0000000000000259 }:bv[64]) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")

    class _Exploding:
        def verdict(self, *a, **k):
            raise AssertionError("no evaluation needed")
    sender_policy.set_evaluator("admission", _Exploding())
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission", held=900) is None



STREAM_COMPARED = ("(i17[t]:bv[64] > i26[t]:bv[64]) ? "
                   "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")


@pytest.mark.parametrize("body", [
    STREAM_COMPARED,
    "(i17[t]:bv[64] = i26[t]:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])",
    "(i17[t]:bv[64] != i26[t]:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])",
    ("((i26[t]:bv[64] > { #x0000000000000001 }:bv[64]) ? (i17[t]:bv[64] > i26[t]:bv[64]) : "
     "(i17[t]:bv[64] > { #x0000000000000259 }:bv[64])) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : "
     "(o5[t]:bv[24] = { #x000001 }:bv[24])"),
])
def test_no_cap_when_i17_is_compared_with_another_stream(body):
    class _Exploding:
        def verdict(self, *a, **k):
            raise AssertionError("no evaluation needed: refused on structure")
    sender_policy.set_evaluator("admission", _Exploding())
    assert sender_policy.recipient_hold_cap(body, {26: "600"}, "bb", pool="admission", held=900) is None


def test_reversed_literal_comparison_still_gets_its_cap():
    body = ("({ #x0000000000000259 }:bv[64] < i17[t]:bv[64]) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])")
    ev = ScriptedPolicies("admission")
    ev.rules[body] = lambda i: "0" if int(i.get(I17, "0")) > 601 else "1"
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission", held=900) == 600


def _many_exceptions_body(k):
    lits = " && ".join("(i17[t]:bv[64] != { #x%016x }:bv[64])" % (1 + 1000 * j) for j in range(1, k + 1))
    return ("((i17[t]:bv[64] > { #x0000000000000001 }:bv[64]) && %s) ? "
            "(o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])" % lits)


class _Counting(ScriptedPolicies):
    def __init__(self, pool):
        super().__init__(pool)
        self.calls = 0

    def verdict(self, *a, **k):
        self.calls += 1
        return super().verdict(*a, **k)


def test_admission_spends_no_evaluation_on_a_cap_past_its_point_budget():
    """A refused park pays no fee: a clause with many constants must not make
    every refusal cost dozens of evaluations at sendtx."""
    body = _many_exceptions_body(28)
    ev = _Counting("admission")
    ev.rules[body] = lambda i: "1"
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(
        body, {}, "bb", pool="admission", held=600,
        max_points=sender_policy.ADMISSION_CAP_MAX_POINTS) is None
    assert ev.calls == 0


def test_the_cap_search_stops_at_the_first_verdict_that_rules_a_cap_out():
    """Refuse, then admit again: not a cap, and the remaining points are not
    evaluated."""
    body = _many_exceptions_body(28)
    excepted = {1 + 1000 * j for j in range(1, 29)}
    ev = _Counting("admission")
    ev.rules[body] = lambda i: ("0" if (lambda v: v > 1 and v not in excepted)(int(i.get(I17, "0"))) else "1")
    sender_policy.set_evaluator("admission", ev)
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission", held=600) is None
    assert ev.calls <= 4


def test_a_real_cap_fits_the_admission_budget_in_both_units():
    from tau_testnet_cli.recipient_rules import compose_receive_clause
    from consensus.rule_offers import clause_body_v1
    body = clause_body_v1(compose_receive_clause(max_hold_seconds=600, max_hold_blocks=10))
    ev = ScriptedPolicies("admission")
    base = 1 << 63
    ev.rules[body] = lambda i: ("0" if (lambda v: (601 < v < base) or v > base + 10)(int(i.get(I17, "0"))) else "1")
    sender_policy.set_evaluator("admission", ev)
    budget = sender_policy.ADMISSION_CAP_MAX_POINTS
    assert sender_policy.recipient_hold_cap(body, {}, "bb", pool="admission", held=900, max_points=budget) == 600
    from tau_defs import HeldBlocks
    assert sender_policy.recipient_hold_cap(body, {}, "bb", blocks=True, pool="admission",
                                            held=HeldBlocks(20), max_points=budget) == 10


# =============================================================================
# Reorg and replay across activation
# =============================================================================

import copy as _copy


def _branch(ch):
    """A sibling branch from the same parent: what a reorg replays on."""
    sib = ra.Chain(dict(ch.bal))
    sib.seq, sib.lts, sib.fee = dict(ch.seq), dict(ch.lts), ch.fee
    sib.lm = _copy.deepcopy(ch.lm)
    return sib


def test_a_reorg_to_a_branch_without_the_activation_does_not_enforce():
    """Branch A activates and refuses a payment; branch B, from the same
    pre-activation parent, never activated, so the same payment is accepted
    there. The parent is untouched by either."""
    parent = _chain(active=False)
    body = allowlist_body(ra.ALICE)
    _policies().add_allowlist(body, ra.ALICE)
    _register(parent, ra.BOB, body)
    pay = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 10)])

    branch_a = _branch(parent)
    branch_a.lm.activate_recipient_policy()
    assert pay["tx_id"] in branch_a.block([pay]).invalid_tx_ids

    branch_b = _branch(parent)
    assert pay["tx_id"] in branch_b.block([pay]).accepted_tx_ids
    assert parent.lm.recipient_policy_active is False
    assert branch_b.lm.recipient_policy_active is False
    assert branch_a.lm.recipient_policy_active is True
    assert branch_a.lm.consensus_meta_hash() != branch_b.lm.consensus_meta_hash()


@pytest.mark.parametrize("active", [True, False])
def test_replaying_the_same_block_gives_the_same_state(active):
    """Two nodes (or one node replaying after a reorg back) apply the same block
    on the same parent: same verdicts, same state hash, same flag."""
    parent = _chain(active=active)
    body = allowlist_body(ra.ALICE)
    _policies().add_allowlist(body, ra.ALICE)
    _register(parent, ra.BOB, body)
    txs = [_send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 3)]),
           _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 3), (ra.MALLORY, 3)]),
           ra.park_tx(seq=1, at_time=ra.TS + 600, amount=4)]
    r1 = _branch(parent).block(txs)
    r2 = _branch(parent).block(txs)
    assert r1.accepted_tx_ids == r2.accepted_tx_ids
    assert r1.invalid_tx_ids == r2.invalid_tx_ids
    assert r1.next_snapshot.state_hash == r2.next_snapshot.state_hash


def test_replay_mode_reaches_the_same_verdicts_as_live_apply():
    """Rebuild after a restart or reorg replays blocks in replay mode; the
    recipient gate must reach the same state there."""
    parent = _chain()
    body = allowlist_body(ra.ALICE)
    _policies().add_allowlist(body, ra.ALICE)
    _register(parent, ra.BOB, body)
    ok = _send(ra.SK_ALICE, ra.ALICE, [(ra.BOB, 3)])
    live = _branch(parent)
    live_result = live.block([ok])
    replay = _branch(parent)
    replay_result = replay.block([ok], replay=True)
    assert live_result.next_snapshot.state_hash == replay_result.next_snapshot.state_hash
    assert live.bal == replay.bal


# =============================================================================
# Admitted, then refused at apply (block order is the proposer's)
# =============================================================================

def _signed_rule_tx(sk, sender, rule, seq=0):
    return ra._sign({
        "tx_id": f"rule-{next(ra._TX_SEQ)}", "tx_type": "user_tx",
        "sender_pubkey": sender, "sequence_number": seq,
        "expiration_time": ra.FAR, "expire_at_height": 1000, "fee_limit": "100",
        "operations": {"0": rule},
    }, sk)


def test_a_rule_earlier_in_the_block_refuses_a_payment_admitted_before_it():
    """The payment was admitted while BOB had no rule; a proposer orders BOB's
    rule first in the block, so apply judges the payment by it and refuses it:
    recipient_policy_block, no fee, no sequence used, BOB unpaid."""
    from consensus.rule_offers import clause_body_v1

    ch = _chain(balances={ra.ALICE: 10_000, ra.CAROL: 10_000, ra.MALLORY: 10_000, ra.BOB: 1_000})
    ch.fee = 5
    rule = f"always ( {allowlist_body(ra.ALICE)} )."
    body = clause_body_v1(rule)
    _policies().add_allowlist(body, ra.ALICE)
    rule_tx = _signed_rule_tx(ra.SK_BOB, ra.BOB, rule)
    pay = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 7)])
    result = ch.block([rule_tx, pay])
    assert rule_tx["tx_id"] in result.accepted_tx_ids
    assert pay["tx_id"] in result.invalid_tx_ids
    assert _outcome(result, pay).reason == "recipient_policy_block"
    assert ch.bal[ra.CAROL] == 10_000 and ch.seq.get(ra.CAROL, 0) == 0
    assert ch.bal[ra.BOB] == 1_000 - 5          # BOB paid only his own rule's fee


def test_the_same_pair_in_the_other_order_pays_before_the_rule_exists():
    from consensus.rule_offers import clause_body_v1

    ch = _chain(balances={ra.ALICE: 10_000, ra.CAROL: 10_000, ra.MALLORY: 10_000, ra.BOB: 1_000})
    rule = f"always ( {allowlist_body(ra.ALICE)} )."
    _policies().add_allowlist(clause_body_v1(rule), ra.ALICE)
    pay = _send(ra.SK_CAROL, ra.CAROL, [(ra.BOB, 7)])
    rule_tx = _signed_rule_tx(ra.SK_BOB, ra.BOB, rule)
    result = ch.block([pay, rule_tx])
    assert pay["tx_id"] in result.accepted_tx_ids
    assert rule_tx["tx_id"] in result.accepted_tx_ids


# =============================================================================
# Approval requests: the request is not gated, the money it releases is
# =============================================================================

import test_approval_apply as aa


def _approval_lm(recipient_allows):
    lm = aa._lm()
    lm.activate_recipient_policy()
    body = allowlist_body(recipient_allows)
    _policies().add_allowlist(body, recipient_allows)
    lm.rule_offers.accepted_clauses[(aa.BOB.lower(), tau_defs.USER_POLICY_STREAM_INDEX)] = body
    return lm


def test_an_approval_request_to_a_refusing_recipient_is_still_parked():
    """#47: approval requests are not transfers and are not gated."""
    req = aa._request()
    result, post, _ = aa._apply([aa.request_tx(req)], lm=_approval_lm(aa.STRANGER))
    assert post.approval_requests.get_request(req.request_id) is not None


def test_a_vote_cannot_release_money_to_a_recipient_who_refuses_the_payer():
    """Without this, a payer BOB refuses pays BOB anyway through an approval."""
    req = aa._request()
    lm = _approval_lm(aa.STRANGER)
    lm.approval_requests.submit_request(req)
    result, post, _ = aa._apply([aa.vote_tx(req)], lm=lm)
    assert post.approval_requests.terminal_status[req.request_id] == aa.STATUS_FAILED
    assert "refused by the recipient's policy" in aa._logs(result)
    bal = aa._balances(result)
    assert bal[aa.BOB] == 0
    assert bal[aa.ALICE] == 100000, "no partial movement"
    (vote_outcome,) = result.outcomes
    assert vote_outcome.tx_id in result.accepted_tx_ids, "the vote itself stands"
    meta = result.next_snapshot.metadata
    assert meta["sequence_numbers"].get(aa.ALICE, 0) == 0, "the request sender's sequence is untouched"
    assert aa.ALICE not in meta["last_transfer_ts"], "no transfer is recorded for the sender"
    assert post.approval_requests.get_request(req.request_id) is None, "not left open either"


def test_a_vote_releases_money_to_a_recipient_who_accepts_the_payer():
    req = aa._request()
    lm = _approval_lm(aa.ALICE)
    lm.approval_requests.submit_request(req)
    result, post, _ = aa._apply([aa.vote_tx(req)], lm=lm)
    assert post.approval_requests.terminal_status[req.request_id] == aa.STATUS_EXECUTED
    assert aa._balances(result)[aa.BOB] == req.amount


def test_before_activation_a_vote_release_is_not_gated():
    req = aa._request()
    lm = aa._lm()
    body = allowlist_body(aa.STRANGER)
    _policies().add_allowlist(body, aa.STRANGER)
    lm.rule_offers.accepted_clauses[(aa.BOB.lower(), tau_defs.USER_POLICY_STREAM_INDEX)] = body
    lm.approval_requests.submit_request(req)
    result, post, _ = aa._apply([aa.vote_tx(req)], lm=lm)
    assert post.approval_requests.terminal_status[req.request_id] == aa.STATUS_EXECUTED
