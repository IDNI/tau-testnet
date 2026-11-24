"""Recipient-side policy at mempool admission, at deploy, and in the read RPCs.

Admission must refuse what block apply refuses, with a reason a wallet can act
on: the condition that failed (RECIPIENT_SENDER for the allow-list of #47,
RECIPIENT_HOLD and RECIPIENT_RECALL carrying the receiver's bound for #76,
RECIPIENT_COMBINED for a rule that ties two together).
"""
import json
import time
from contextlib import ExitStack
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

import chain_state
import db
import tau_defs
from bls_keys import SK_ALICE, pubkey_hex, sign_payload
from commands import getrecipientpolicy
from commands import sendtx as sendtx_module
from consensus import recipient_policy, sender_policy
from consensus.admission import (
    TipAdmissionView,
    validate_o5_clause_routing,
    validate_user_tx_reserved_domains,
)
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import MAX_RELEASE_WINDOW_BLOCKS, MAX_RELEASE_WINDOW_SECONDS
from tau_speculation import WorkerLost, WorkerTimeout

import recipient_rules as rules
import test_retractable_admission as ra
from test_retractable_admission import (  # noqa: F401 - `node` is a fixture
    FAR, NEXT_HEIGHT, RECIPIENT, SENDER, node,
)

THIRD = pubkey_hex(0x3C)
STRANGER = pubkey_hex(0x4D)


# A time-based park must expire before it releases, and `expiration_time` is
# judged against the wall clock. So the tip AND the clock sendtx reads are both
# pinned to this instant, and no test depends on how long the suite has run.
NOW = int(time.time())


class _PinnedClock:
    """`time`, with `time()` pinned."""

    def time(self):
        return float(NOW)

    def __getattr__(self, name):
        return getattr(time, name)


class Tip:
    """The chain feature flag, the clock and the clause registry, as admission
    reads them. A context manager, so it unwinds before the `node` fixture's own
    patches on the same class."""

    def __init__(self, ev, *, active=True):
        self.ev = ev
        self.clauses = {}
        self.lm = ConsensusLifecycleManager()
        if active:
            self.lm.activate_recipient_policy()
        self._stack = ExitStack()

    def __enter__(self):
        enter = self._stack.enter_context
        enter(patch.object(chain_state, "_lifecycle_manager", self.lm))
        enter(patch.object(
            TipAdmissionView, "clause_for",
            lambda _self, account, stream: self.clauses.get((account.lower(), int(stream))),
        ))
        for name in ("tip_timestamp", "next_block_timestamp"):
            enter(patch.object(TipAdmissionView, name,
                               new_callable=PropertyMock, return_value=NOW))
        enter(patch.object(sendtx_module, "time", _PinnedClock()))
        return self

    def __exit__(self, *exc):
        self._stack.close()

    def rule(self, account, body, model):
        self.clauses[(account, 5)] = body
        self.ev.set_verdict(body, model)
        return body

    def asked(self, body):
        return [inputs for called, inputs in self.ev.verdict_calls if called == body]


@pytest.fixture
def ev():
    evaluator = MockPolicyEvaluator(pool="admission")
    sender_policy.set_evaluator("admission", evaluator)
    yield evaluator
    sender_policy.set_evaluator("admission", None)


@pytest.fixture
def tip(node, ev):
    with Tip(ev) as tip:
        yield tip


@pytest.fixture
def inactive_tip(node, ev):
    with Tip(ev, active=False) as tip:
        yield tip


def _timed(seconds, **over):
    """A park released `seconds` after the tip's timestamp."""
    return ra._park_payload(release_at_height=None, release_at_time=NOW + seconds,
                            expiration_time=NOW + min(100, max(1, seconds - 1)), **over)


def _transfer(*legs, seq=1):
    return sign_payload({
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "100",
        "operations": {"1": [[SENDER, to, str(amount)] for to, amount in legs]},
    }, SK_ALICE)


def _queue(sendtx, payload, **kw):
    return sendtx.queue_transaction(json.dumps(payload), propagate=False, **kw)


def _record(inputs):
    """The receive record one evaluation was asked with: kind, hold, recall,
    limit, period, refund."""
    return tuple(inputs.get("i%d" % index) for index in tau_defs.RECEIVE_RECORD_INDICES)


def _refused_by(**more):
    return {"transfer_index": 1, "recipient": RECIPIENT, **more}


# --- #47: inbound allow-list --------------------------------------------------

def test_a_listed_sender_is_admitted(node, tip):
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.allow_list(SENDER), rules.allow_list_model(SENDER))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert result["ok"], result
    (inputs,) = tip.asked(body)
    assert inputs["i17"] == "1" and inputs["i1"] == "25"
    assert _record(inputs) == ("1", "0", "0", "0", "0", str(rules.NEVER))
    assert inputs["i3"] == "#x" + SENDER and inputs["i4"] == "#x" + RECIPIENT


def test_a_stranger_is_refused_with_the_recipient_reason(node, tip):
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert result["ok"] is False
    assert result["code"] == "RECIPIENT_SENDER"
    assert "rejected by recipient policy (o5)" in result["message"]
    assert "does not accept a payment from this sender" in result["message"]
    assert result["details"] == _refused_by(condition="sender")
    assert ra._mempool_hashes() == []


def test_the_dry_run_behind_checktx_reports_the_same_refusal(node, tip):
    """`checktx` is `queue_transaction(dry_run=True)`, so the code and details
    are the ones `sendtx` gives."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)), dry_run=True)
    assert result["ok"] is False and result["code"] == "RECIPIENT_SENDER"
    assert result["details"] == _refused_by(condition="sender")

    tip.rule(RECIPIENT, rules.allow_list(SENDER), rules.allow_list_model(SENDER))
    assert _queue(sendtx, _transfer((RECIPIENT, 25)), dry_run=True)["ok"]
    assert ra._mempool_hashes() == []


def test_one_refusing_recipient_fails_the_batch_and_names_the_leg(node, tip):
    sendtx, _script = node
    tip.rule(THIRD, rules.allow_list(STRANGER), rules.allow_list_model(STRANGER))
    result = _queue(sendtx, _transfer((RECIPIENT, 5), (THIRD, 5)))
    assert result["ok"] is False and result["code"] == "RECIPIENT_SENDER"
    assert result["details"]["transfer_index"] == 2
    assert result["details"]["recipient"] == THIRD
    assert ra._mempool_hashes() == []


def test_an_account_without_a_receive_rule_is_never_asked(node, tip):
    sendtx, _script = node
    limit = tip.rule(RECIPIENT, rules.SPEND_LIMIT, rules.spend_limit_model)
    result = _queue(sendtx, _transfer((RECIPIENT, 5_000), (THIRD, 1)))
    assert result["ok"], result
    assert tip.asked(limit) == []


def test_the_senders_own_block_comes_first(node, tip):
    sendtx, _script = node
    theirs = tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    tip.rule(SENDER, rules.SPEND_LIMIT, rules.spend_limit_model)
    result = _queue(sendtx, _transfer((RECIPIENT, 5_000)))
    assert result["ok"] is False and result["code"] == "TX_REJECTED"
    assert "sender's own policy clause" in result["message"]
    assert tip.asked(theirs) == []


def test_nothing_is_asked_on_a_chain_without_the_feature(node, inactive_tip):
    sendtx, _script = node
    tip = inactive_tip
    body = tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert result["ok"], result
    assert tip.asked(body) == []


@pytest.mark.parametrize("exc, code", [
    (WorkerLost("gone"), "ADMISSION_UNAVAILABLE"),
    (WorkerTimeout("slow"), "ADMISSION_TIMEOUT"),
])
def test_a_lost_evaluator_is_operational_not_a_refusal(node, tip, exc, code):
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.allow_list(SENDER), rules.allow_list_model(SENDER))

    class _Failing:
        def verdict(self, *a, **k):
            raise exc

    sender_policy.set_evaluator("admission", _Failing())
    result = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert result["ok"] is False and result["code"] == code
    assert ra._mempool_hashes() == []


# --- #76: maximum hold time ---------------------------------------------------

def _park(**over):
    return ra._park_payload(**over)


@pytest.mark.parametrize("make, unit", [
    (lambda: _timed(2), "seconds"), (lambda: _timed(86_400), "seconds"),
    (lambda: _park(release_at_height=NEXT_HEIGHT + 30), "blocks"),
])
def test_instant_only_refuses_every_park_and_carries_the_bound(node, tip, make, unit):
    """Acceptance cases 1 and 5 of #76."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.final_only(), rules.final_only_model())
    result = _queue(sendtx, make())
    assert result["ok"] is False
    assert result["code"] == "RECIPIENT_HOLD"
    assert result["details"]["condition"] == "hold"
    assert result["details"]["max_hold_" + unit] == 0
    assert "max_hold_%s=0" % unit in result["message"]
    assert "final at once" in result["message"]
    assert ra._mempool_hashes() == []

    plain = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert plain["ok"], plain


def test_a_cap_admits_ten_minutes_and_refuses_an_hour(node, tip):
    """Acceptance case 2 of #76."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    inside = _queue(sendtx, _timed(600))
    assert inside["ok"], inside
    # a park is held, and open to a recall, until its release
    assert _record(tip.asked(body)[-1]) == ("2", "600", "600", "0", "0", str(rules.NEVER))

    hour = _queue(sendtx, _timed(3_600, sequence_number=2))
    assert hour["ok"] is False and hour["code"] == "RECIPIENT_HOLD"
    assert hour["details"] == _refused_by(
        condition="hold", max_hold_seconds=600, hold_seconds=3_600)
    assert "at most 600 seconds" in hour["message"]
    assert "max_hold_seconds=600" in hour["message"]
    assert "held for 3600 seconds" in hour["message"]


def test_a_cap_in_seconds_alone_refuses_a_height_release_and_says_why(node, tip):
    """A length in blocks is not a length in seconds. The payer is told both
    halves: no height release, and the cap a timed one must respect."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    result = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 30))
    assert result["ok"] is False and result["code"] == "RECIPIENT_HOLD"
    assert result["details"] == _refused_by(
        condition="hold", max_hold_blocks=0, max_hold_seconds=600, hold_blocks=30)
    assert "max_hold_seconds=600" in result["message"]
    assert "max_hold_blocks=0" in result["message"]
    assert "release_at_time" in result["message"]
    assert _record(tip.asked(body)[0]) == ("3", "30", "30", "0", "0", str(rules.NEVER))


def test_a_cap_in_blocks_admits_a_height_release_inside_it_and_refuses_one_beyond(node, tip):
    """The hold of a height release is `release_at_height` minus the height of
    the next block, in blocks (#76)."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.max_hold_either(600, 100),
                    rules.max_hold_either_model(600, 100))
    inside = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 100))
    assert inside["ok"], inside
    assert _record(tip.asked(body)[-1])[:3] == ("3", "100", "100")

    beyond = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 101, sequence_number=2))
    assert beyond["ok"] is False and beyond["code"] == "RECIPIENT_HOLD"
    assert beyond["details"] == _refused_by(
        condition="hold", max_hold_blocks=100, hold_blocks=101)
    assert "at most 100 blocks" in beyond["message"]
    assert "max_hold_blocks=100" in beyond["message"]
    assert "held for 101 blocks" in beyond["message"]

    far = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + MAX_RELEASE_WINDOW_BLOCKS,
                               sequence_number=2))
    assert far["code"] == "RECIPIENT_HOLD" and far["details"]["max_hold_blocks"] == 100


def test_one_rule_caps_both_kinds_of_release_each_in_its_own_unit(node, tip):
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.max_hold_either(600, 100),
             rules.max_hold_either_model(600, 100))
    hour = _queue(sendtx, _timed(3_600))
    assert hour["code"] == "RECIPIENT_HOLD"
    assert hour["details"] == _refused_by(
        condition="hold", max_hold_seconds=600, hold_seconds=3_600)
    assert _queue(sendtx, _timed(600))["ok"]


# --- the recall window is its own number -----------------------------------------

def test_a_recall_window_over_the_bound_is_refused_as_that(node, tip):
    """Held at most 30 days, taken back within an hour at most. A park of two
    hours is inside the hold and outside the recall window, and the payer is
    told which of the two and the bound."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.hold_and_recall(2_592_000, 3_600),
                    rules.hold_and_recall_model(2_592_000, 3_600))
    inside = _queue(sendtx, _timed(3_600))
    assert inside["ok"], inside

    two_hours = _queue(sendtx, _timed(7_200, sequence_number=2))
    assert two_hours["ok"] is False and two_hours["code"] == "RECIPIENT_RECALL"
    assert two_hours["details"] == _refused_by(
        condition="recall", max_recall_seconds=3_600, recall_seconds=7_200)
    assert "open to a recall by the sender for at most 3600 seconds" in two_hours["message"]
    assert "max_recall_seconds=3600" in two_hours["message"]
    # the hold alone was asked first and passed
    asked = [_record(inputs)[:3] for inputs in tip.asked(body)]
    assert ("2", "7200", "0") in asked and ("2", "0", "7200") in asked
    assert asked.index(("2", "7200", "0")) < asked.index(("2", "0", "7200"))


def test_the_hold_is_named_before_the_recall_window(node, tip):
    """Both fail: the order of the design names the first, the hold."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.hold_and_recall(600, 60), rules.hold_and_recall_model(600, 60))
    result = _queue(sendtx, _timed(3_600))
    assert result["code"] == "RECIPIENT_HOLD"
    assert result["details"]["max_hold_seconds"] == 600


def test_a_rule_that_ties_two_conditions_is_refused_as_the_combination(node, tip):
    """Hold plus recall window at most an hour: a park of 40 minutes passes the
    hold alone and the recall alone, and fails together."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.hold_plus_recall(3_600), rules.hold_plus_recall_model(3_600))
    inside = _queue(sendtx, _timed(1_800))
    assert inside["ok"], inside

    result = _queue(sendtx, _timed(2_400, sequence_number=2))
    assert result["ok"] is False and result["code"] == "RECIPIENT_COMBINED"
    assert result["details"] == _refused_by(condition="combined")
    assert "conditions together" in result["message"]
    assert not any(key.startswith("max_") for key in result["details"])


def test_working_out_the_reason_has_one_budget_and_no_more(node, tip, monkeypatch):
    """A refusal costs the payer nothing, so the node bounds what it spends on
    one: when the time for the reason is used up the park is still refused, and
    the message says where the rest can be read."""
    import tau_admission

    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    monkeypatch.setattr(tau_admission, "default_budget", lambda: 0.0)
    result = _queue(sendtx, _timed(3_600))
    assert result["ok"] is False and result["code"] == "RECIPIENT_POLICY"
    assert "max_hold_seconds" not in result.get("details", {})
    assert "getrecipientpolicy" in result["message"]
    assert len(tip.asked(body)) == 1, "the verdict, and nothing after the time ran out"
    assert ra._mempool_hashes() == []


def test_a_bound_that_cannot_be_found_in_time_still_names_the_condition(node, tip, monkeypatch):
    """The time runs out after the condition is known and before the bound is."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))

    def out_of_time(*args, **kwargs):
        raise sendtx_module._CapSearchOver()

    monkeypatch.setattr(recipient_policy, "accepted_instead", out_of_time)
    result = _queue(sendtx, _timed(3_600))
    assert result["ok"] is False and result["code"] == "RECIPIENT_HOLD"
    assert result["details"] == _refused_by(condition="hold", hold_seconds=3_600)
    assert "getrecipientpolicy" in result["message"]


def test_a_park_refused_for_its_sender_is_not_a_hold_refusal(node, tip):
    """The allow-list refuses this sender whatever the hold, so there is no bound
    to report, and the sender learns nothing of the receiver's other terms."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.one_unit(SENDER, THIRD, 600),
                    rules.one_unit_model(SENDER, THIRD, 600))
    result = _queue(sendtx, _timed(3_600))
    assert result["ok"] is False and result["code"] == "RECIPIENT_SENDER"
    assert result["details"] == _refused_by(condition="sender")
    assert "600" not in result["message"]
    assert len(tip.asked(body)) == 2, "the verdict, then the same payment as final"


def test_a_refused_transfer_is_not_asked_a_second_time(node, tip):
    """A payment that is final at once carries no condition to isolate."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert result["code"] == "RECIPIENT_SENDER"
    assert len(tip.asked(body)) == 1


def test_without_a_cap_parks_of_any_length_are_admitted(node, tip):
    """Acceptance case 3 of #76."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.allow_list(SENDER), rules.allow_list_model(SENDER))
    longest = _queue(sendtx, _timed(MAX_RELEASE_WINDOW_SECONDS))
    assert longest["ok"], longest
    by_height = _queue(sendtx, _park(sequence_number=2))
    assert by_height["ok"], by_height


def test_a_retract_is_admitted_whatever_the_recipients_cap(node, tip):
    """Acceptance case 4 of #76."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.final_only(), rules.final_only_model())
    rid = ra._seed_open_entry(_park())
    result = _queue(sendtx, ra._retract_payload(rid, sequence_number=1))
    assert result["ok"], result
    assert tip.asked(body) == []


def test_finding_the_reason_costs_a_bounded_number_of_evaluations(node, tip):
    """The verdict, at most five for the condition, one for the clock, and the
    bisection of the bound (24 steps at most for 90 days in seconds)."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.hold_and_recall(2_592_000, 600),
                    rules.hold_and_recall_model(2_592_000, 600))
    refused = _queue(sendtx, _timed(MAX_RELEASE_WINDOW_SECONDS))
    assert refused["code"] == "RECIPIENT_HOLD"
    assert len(tip.asked(body)) <= 1 + 5 + 1 + 24

    tip.ev.verdict_calls.clear()
    refused = _queue(sendtx, _timed(2_592_000))
    assert refused["code"] == "RECIPIENT_RECALL"
    assert len(tip.asked(body)) <= 1 + 5 + 1 + 24


# --- deploying a receive rule ---------------------------------------------------

def _view(active, slots=True):
    view = MagicMock(spec=TipAdmissionView)
    view.active_validators = {SENDER}
    view.next_block_height = NEXT_HEIGHT
    view.eligibility_mode = ""
    view.approval_slots_active = slots
    view.recipient_policy_active = active
    view.clause_for.return_value = None
    return view


def _rule_tx(rule, extra_ops=None):
    ops = {"0": rule}
    ops.update(extra_ops or {})
    return {"tx_type": "user_tx", "sender_pubkey": SENDER, "operations": ops}


@pytest.mark.parametrize("body", [
    rules.allow_list(RECIPIENT), rules.final_only(), rules.max_hold(600),
    rules.max_hold_either(600, 100), rules.hold_and_recall(2_592_000, 3_600),
    rules.hold_plus_recall(3_600), rules.one_unit(THIRD, RECIPIENT, 600),
])
def test_the_documented_rules_register_on_an_active_chain(body):
    tx = _rule_tx("always ( %s )." % body)
    result = validate_o5_clause_routing(tx, _view(True), tx["operations"]["0"])
    assert result is not None and result.is_valid is True, getattr(result, "error", None)
    assert result.data["o5_clause_action"] == "declare"
    assert result.data["o5_clause_body"] == body


@pytest.mark.parametrize("body", [
    rules.allow_list(RECIPIENT), rules.final_only(), rules.max_hold(600),
    "( (i50[t]:bv[64] <= { 600 }:bv[64]) ? %s : %s )" % (rules.ALLOW, rules.BLOCK),
    "( (i54[t]:bv[64] >= { 600 }:bv[64]) ? %s : %s )" % (rules.ALLOW, rules.BLOCK),
])
def test_a_node_without_the_feature_refuses_the_rule_at_deploy(body):
    """Acceptance case 5 of #47 and case 6 of #76: the rule would register and
    then never be asked, so the node says so."""
    tx = _rule_tx("always ( %s )." % body)
    result = validate_o5_clause_routing(tx, _view(False), tx["operations"]["0"])
    assert result is not None and result.is_valid is False
    assert result.code == "RECIPIENT_POLICY_INACTIVE"
    assert "recipient-side policy is not active" in result.error


def test_an_ordinary_clause_still_registers_without_the_feature():
    tx = _rule_tx("always ( %s )." % rules.SPEND_LIMIT)
    result = validate_o5_clause_routing(tx, _view(False), tx["operations"]["0"])
    assert result is not None and result.is_valid is True


@pytest.mark.parametrize("mention, said", [
    ("i17[t]:bv[24]", "i17[t]:bv[64]"),       # the receive record's own screen
    ("i50[t]:bv[24]", "i50[t]:bv[64]"),
    ("i53[t]:bv[32]", "i53[t]:bv[64]"),
    ("i17[t]", "explicit width"),             # the screen every clause clears first
])
def test_a_wrongly_typed_receive_stream_is_refused_on_an_active_chain(mention, said):
    body = "( (%s = { 1 }:bv[64]) ? %s : %s )" % (mention, rules.ALLOW, rules.BLOCK)
    tx = _rule_tx("always ( %s )." % body)
    result = validate_o5_clause_routing(tx, _view(True), tx["operations"]["0"])
    assert result is not None and result.is_valid is False
    assert said in result.error


@pytest.mark.parametrize("key", [str(i) for i in tau_defs.RECEIVE_RECORD_INDICES])
def test_only_the_node_writes_the_receive_record(key):
    """A sender who could put "17" or "50" in `operations` would answer the
    recipient's question for them."""
    transfers = [[SENDER, RECIPIENT, "5"]]
    tx = {"tx_type": "user_tx", "sender_pubkey": SENDER,
          "operations": {"1": transfers, key: "0"}}
    refused = validate_user_tx_reserved_domains(tx, _view(True))
    assert refused is not None and refused.is_valid is False
    assert key in refused.error
    before = validate_user_tx_reserved_domains(tx, _view(False))
    assert before is None or before.is_valid is True, "an ordinary stream before activation"


@pytest.mark.parametrize("index", tau_defs.RECEIVE_RECORD_INDICES)
def test_no_other_rule_may_read_the_receive_record(index):
    rule = ("always ( (i%d[t]:bv[64] = { 1 }:bv[64]) -> "
            "(o13[t]:bv[24] = { #x000001 }:bv[24]) )." % index)
    refused = validate_user_tx_reserved_domains(_rule_tx(rule), _view(True))
    assert refused is not None and refused.is_valid is False
    assert "receive record" in refused.error and "i%d" % index in refused.error


# --- capability reporting -------------------------------------------------------

def _rpc(*args):
    parsed = json.loads(getrecipientpolicy.execute(
        " ".join(("getrecipientpolicy",) + tuple(str(a) for a in args)), None))
    assert parsed.get("status") == "ok", parsed
    return parsed["data"]


RECORD_NAMES = ["i17", "i50", "i51", "i52", "i53", "i54"]
FINAL_VIEW = {"kind": 1, "unit": None, "hold": 0, "recall": 0, "limit": 0,
              "period": 0, "refund": None}
NO_BOUNDS = {"max_hold_seconds": None, "max_hold_blocks": None,
             "max_recall_seconds": None, "max_recall_blocks": None}


def test_the_node_reports_an_inactive_chain(node, inactive_tip):
    tip = inactive_tip
    tip.rule(RECIPIENT, rules.SPEND_LIMIT, rules.spend_limit_model)
    data = _rpc(RECIPIENT)
    assert data["active"] is False and data["judges_incoming"] is False
    assert data["receive_stream"] == "i17" and data["receive_stream_width"] == 64
    assert data["receive_record"] == RECORD_NAMES
    assert data["has_clause"] is True and data["clause"] is None


def test_the_node_reports_whether_an_address_judges_incoming_payments(node, tip):
    assert _rpc(RECIPIENT) == {
        "active": True, "receive_stream": "i17", "receive_record": RECORD_NAMES,
        "receive_stream_width": 64,
        "address": RECIPIENT, "has_clause": False, "judges_incoming": False,
        "clause": None,
    }
    body = tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    data = _rpc(RECIPIENT)
    assert data["judges_incoming"] is True and data["clause"] == body
    assert "probe" not in data


def test_a_rule_that_reads_only_a_later_input_of_the_record_judges_incoming(node, tip):
    body = "( (i50[t]:bv[64] <= { 600 }:bv[64]) ? %s : %s )" % (rules.ALLOW, rules.BLOCK)
    tip.rule(RECIPIENT, body, lambda inputs: "1")
    assert _rpc(RECIPIENT)["judges_incoming"] is True


def test_the_probe_reports_the_bounds_a_wallet_must_respect(node, tip):
    tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe == {
        "sender": SENDER, "amount": 25, "advisory": True, "record": FINAL_VIEW,
        "accepts_payment": True, "refused_condition": None, "code": None,
        "max_hold_seconds": 600, "max_recall_seconds": None,
        "max_hold_blocks": 0, "max_recall_blocks": 0,
        "accepts_height_release": False,
    }
    tip.rule(RECIPIENT, rules.final_only(), rules.final_only_model())
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe["max_hold_seconds"] == 0 and probe["max_recall_seconds"] == 0


def test_the_probe_reports_a_cap_in_blocks(node, tip):
    tip.rule(RECIPIENT, rules.max_hold_either(600, 100),
             rules.max_hold_either_model(600, 100))
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe["max_hold_seconds"] == 600 and probe["max_hold_blocks"] == 100
    assert probe["max_recall_seconds"] is None and probe["max_recall_blocks"] is None
    assert probe["accepts_height_release"] is True


def test_the_probe_reports_the_hold_and_the_recall_window_apart(node, tip):
    tip.rule(RECIPIENT, rules.hold_and_recall(2_592_000, 3_600),
             rules.hold_and_recall_model(2_592_000, 3_600))
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe["max_hold_seconds"] == 2_592_000 and probe["max_recall_seconds"] == 3_600


def test_the_probe_has_one_budget_for_all_it_asks(node, tip, monkeypatch):
    import tau_admission

    tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    monkeypatch.setattr(tau_admission, "default_budget", lambda: 0.0)
    parsed = json.loads(getrecipientpolicy.execute(
        f"getrecipientpolicy {RECIPIENT} {SENDER} 25", None))
    assert parsed.get("status") != "ok" and "TAU_UNAVAILABLE" in json.dumps(parsed)
    assert tip.ev.verdict_calls == []


def test_the_probe_reports_an_allow_list(node, tip):
    tip.rule(RECIPIENT, rules.allow_list(SENDER), rules.allow_list_model(SENDER))
    listed = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert listed["accepts_payment"] is True and listed["refused_condition"] is None
    assert {name: listed[name] for name in NO_BOUNDS} == NO_BOUNDS
    assert listed["accepts_height_release"] is True
    stranger = _rpc(RECIPIENT, STRANGER, 25)["probe"]
    assert stranger["accepts_payment"] is False
    assert stranger["refused_condition"] == "sender"
    assert stranger["code"] == "RECIPIENT_SENDER"


def test_a_sender_who_is_not_accepted_learns_nothing_of_the_other_terms(node, tip):
    body = tip.rule(RECIPIENT, rules.one_unit(SENDER, THIRD, 600),
                    rules.one_unit_model(SENDER, THIRD, 600))
    probe = _rpc(RECIPIENT, STRANGER, 25, "seconds", "park=3600")["probe"]
    assert probe["accepts_payment"] is False and probe["code"] == "RECIPIENT_SENDER"
    assert {name: probe[name] for name in NO_BOUNDS} == NO_BOUNDS
    assert len(tip.asked(body)) == 2, "the payment, then the same payment as final"


def test_the_probe_of_an_account_without_a_receive_rule_accepts(node, tip):
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe["accepts_payment"] is True
    assert {name: probe[name] for name in NO_BOUNDS} == NO_BOUNDS
    assert probe["accepts_height_release"] is True
    assert tip.ev.verdict_calls == []


# --- asking about a payment with conditions before sending it -------------------

def test_the_probe_answers_for_a_park_before_it_is_sent(node, tip):
    """What a wallet does before a retractable transfer: ask, read the reason
    and the bound, change the terms, ask again. No fee is paid for any of it."""
    body = tip.rule(RECIPIENT, rules.hold_and_recall(2_592_000, 3_600),
                    rules.hold_and_recall_model(2_592_000, 3_600))
    probe = _rpc(RECIPIENT, SENDER, 25, "seconds", "park=7200")["probe"]
    assert probe["record"] == {"kind": 2, "unit": "seconds", "hold": 7_200,
                               "recall": 7_200, "limit": 0, "period": 0, "refund": None}
    assert probe["accepts_payment"] is False
    assert probe["refused_condition"] == "recall" and probe["code"] == "RECIPIENT_RECALL"
    assert probe["max_recall_seconds"] == 3_600 and probe["max_hold_seconds"] == 2_592_000
    assert _record(tip.asked(body)[0]) == ("2", "7200", "7200", "0", "0", str(rules.NEVER))

    again = _rpc(RECIPIENT, SENDER, 25, "seconds", "park=3600")["probe"]
    assert again["accepts_payment"] is True and again["refused_condition"] is None


def test_the_probe_takes_every_term_of_the_record(node, tip):
    """The terms are the record: the hold and the recall window apart, a limit
    with its period, and the refund."""
    seen = []

    def model(inputs):
        seen.append(_record(inputs))
        return "1"

    body = "( (i54[t]:bv[64] >= { 0 }:bv[64]) ? %s : %s )" % (rules.ALLOW, rules.BLOCK)
    tip.rule(RECIPIENT, body, model)
    probe = _rpc(RECIPIENT, SENDER, 25, "blocks", "hold=40", "recall=0",
                 "limit=500", "period=7000", "refund=90000")["probe"]
    assert seen[0] == ("3", "40", "0", "500", "7000", "90000")
    assert probe["record"] == {"kind": 3, "unit": "blocks", "hold": 40, "recall": 0,
                               "limit": 500, "period": 7_000, "refund": 90_000}
    seen.clear()
    _rpc(RECIPIENT, SENDER, 25, "seconds", "refund=never")
    assert seen[0] == ("2", "0", "0", "0", "0", str(rules.NEVER))


def test_the_probe_names_a_combination(node, tip):
    tip.rule(RECIPIENT, rules.hold_plus_recall(3_600), rules.hold_plus_recall_model(3_600))
    probe = _rpc(RECIPIENT, SENDER, 25, "seconds", "park=2400")["probe"]
    assert probe["accepts_payment"] is False
    assert probe["refused_condition"] == "combined" and probe["code"] == "RECIPIENT_COMBINED"
    assert probe["max_hold_seconds"] == 3_600 and probe["max_recall_seconds"] == 3_600


@pytest.mark.parametrize("terms, said", [
    ("park=600", "seconds or blocks"),
    ("hours park=600", "seconds or blocks"),
    ("seconds park", "unknown term"),
    ("seconds wait=5", "unknown term"),
    ("seconds hold=ten", "whole number"),
    ("seconds hold=-1", "whole number"),
    ("seconds hold=5 hold=6", "given twice"),
    ("seconds park=5 recall=6", "already sets"),
    ("seconds limit=500", "together with period"),
    ("seconds period=500", "together with period"),
    ("seconds hold=18446744073709551616", "at most"),
    ("seconds limit=16777216 period=60", "cannot be described"),
    ("seconds limit=5 period=31622401", "cannot be described"),
    ("blocks limit=5 period=1000001", "cannot be described"),
])
def test_the_rpc_refuses_malformed_terms(node, tip, terms, said):
    parsed = json.loads(getrecipientpolicy.execute(
        f"getrecipientpolicy {RECIPIENT} {SENDER} 25 {terms}", None))
    assert parsed["status"] == "error" and parsed["error"]["code"] == "INVALID_PARAMS"
    assert said in parsed["error"]["message"]
    assert tip.ev.verdict_calls == []


def test_the_ceilings_of_the_limit_are_inclusive(node, tip):
    record = getrecipientpolicy.parse_terms(
        ["seconds", "limit=16777215", "period=31622400"])
    assert (record.limit, record.period) == (16_777_215, 31_622_400)
    record = getrecipientpolicy.parse_terms(["blocks", "limit=1", "period=1000000"])
    assert record.kind == 3 and record.period == 1_000_000


@pytest.mark.parametrize("record", [
    recipient_policy.FINAL,
    recipient_policy.park_record(recipient_policy.SECONDS, 1_800),
    recipient_policy.park_record(recipient_policy.BLOCKS, 40),
    recipient_policy.park_record(recipient_policy.SECONDS, 0),
    recipient_policy.ReceiveRecord(kind=2, hold=5, recall=0, limit=2_000, period=2_592_000,
                                   refund=86_400),
    recipient_policy.ReceiveRecord(kind=3, limit=7, period=1_000, refund=0),
    recipient_policy.ReceiveRecord(kind=2, hold=tau_defs.RECEIVE_NEVER,
                                   recall=tau_defs.RECEIVE_NEVER),
])
def test_a_record_reads_back_from_its_terms(record):
    """What a block logs for a refused payment is what the lookup takes."""
    assert getrecipientpolicy.parse_terms(record.terms().split()) == record


@pytest.mark.parametrize("command", [
    "getrecipientpolicy", "getrecipientpolicy zz",
    "getrecipientpolicy " + RECIPIENT + " " + SENDER,
    "getrecipientpolicy " + RECIPIENT + " " + SENDER + " -1",
    "getrecipientpolicy " + RECIPIENT + " " + SENDER + " lots",
])
def test_the_rpc_refuses_malformed_calls(node, tip, command):
    parsed = json.loads(getrecipientpolicy.execute(command, None))
    assert parsed["status"] == "error" and parsed["error"]["code"] == "INVALID_PARAMS"


def test_getgovernance_reports_the_flag(node, tip):
    from commands import getgovernance

    container = MagicMock()
    container.chain_state = chain_state
    container.db = db
    data = json.loads(getgovernance.execute("getgovernance", container))["data"]
    assert data["recipient_policy_active"] is True
