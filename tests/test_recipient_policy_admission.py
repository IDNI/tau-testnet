"""Recipient-side policy at mempool admission, at deploy, and in the read RPCs.

Admission must refuse what block apply refuses, with a reason a wallet can act
on: RECIPIENT_POLICY for the allow-list of #47, RECIPIENT_MAX_HOLD carrying the
cap for #76.
"""
import json
import time
from contextlib import ExitStack
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

import chain_state
import db
from bls_keys import SK_ALICE, pubkey_hex, sign_payload
from commands import getrecipientpolicy
from commands import sendtx as sendtx_module
from consensus import sender_policy
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


# --- #47: inbound allow-list --------------------------------------------------

def test_a_listed_sender_is_admitted(node, tip):
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.allow_list(SENDER), rules.allow_list_model(SENDER))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert result["ok"], result
    (inputs,) = tip.asked(body)
    assert inputs["i17"] == "1" and inputs["i1"] == "25"
    assert inputs["i3"] == "#x" + SENDER and inputs["i4"] == "#x" + RECIPIENT


def test_a_stranger_is_refused_with_the_recipient_reason(node, tip):
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)))
    assert result["ok"] is False
    assert result["code"] == "RECIPIENT_POLICY"
    assert "rejected by recipient policy (o5)" in result["message"]
    assert result["details"] == {"transfer_index": 1, "recipient": RECIPIENT}
    assert ra._mempool_hashes() == []


def test_the_dry_run_behind_checktx_reports_the_same_refusal(node, tip):
    """`checktx` is `queue_transaction(dry_run=True)`, so the code and details
    are the ones `sendtx` gives."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    result = _queue(sendtx, _transfer((RECIPIENT, 25)), dry_run=True)
    assert result["ok"] is False and result["code"] == "RECIPIENT_POLICY"
    assert result["details"] == {"transfer_index": 1, "recipient": RECIPIENT}

    tip.rule(RECIPIENT, rules.allow_list(SENDER), rules.allow_list_model(SENDER))
    assert _queue(sendtx, _transfer((RECIPIENT, 25)), dry_run=True)["ok"]
    assert ra._mempool_hashes() == []


def test_one_refusing_recipient_fails_the_batch_and_names_the_leg(node, tip):
    sendtx, _script = node
    tip.rule(THIRD, rules.allow_list(STRANGER), rules.allow_list_model(STRANGER))
    result = _queue(sendtx, _transfer((RECIPIENT, 5), (THIRD, 5)))
    assert result["ok"] is False and result["code"] == "RECIPIENT_POLICY"
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


@pytest.mark.parametrize("make", [
    lambda: _timed(2), lambda: _timed(86_400),
    lambda: _park(release_at_height=NEXT_HEIGHT + 30),
])
def test_instant_only_refuses_every_park_and_carries_the_cap(node, tip, make):
    """Acceptance cases 1 and 5 of #76."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.max_hold(0), rules.max_hold_model(0))
    result = _queue(sendtx, make())
    assert result["ok"] is False
    assert result["code"] == "RECIPIENT_MAX_HOLD"
    assert result["details"]["max_hold_seconds"] == 0
    assert "max_hold_seconds=0" in result["message"]
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
    assert tip.asked(body)[-1]["i17"] == "601"

    hour = _queue(sendtx, _timed(3_600, sequence_number=2))
    assert hour["ok"] is False and hour["code"] == "RECIPIENT_MAX_HOLD"
    assert hour["details"] == {
        "transfer_index": 1, "recipient": RECIPIENT,
        "max_hold_seconds": 600, "hold_seconds": 3_600,
    }
    assert "at most 600 seconds" in hour["message"]
    assert "max_hold_seconds=600" in hour["message"]
    assert "held for 3600 seconds" in hour["message"]


def test_a_cap_in_seconds_alone_refuses_a_height_release_and_says_why(node, tip):
    """A length in blocks is not a length in seconds. The payer is told both
    halves: no height release, and the cap a timed one must respect."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    result = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 30))
    assert result["ok"] is False and result["code"] == "RECIPIENT_MAX_HOLD"
    assert result["details"] == {
        "transfer_index": 1, "recipient": RECIPIENT,
        "max_hold_blocks": 0, "max_hold_seconds": 600, "hold_blocks": 30,
    }
    assert "max_hold_seconds=600" in result["message"]
    assert "max_hold_blocks=0" in result["message"]
    assert "release_at_time" in result["message"]
    assert tip.asked(body)[0]["i17"] == str(rules.BLOCKS + 30)


def test_a_cap_in_blocks_admits_a_height_release_inside_it_and_refuses_one_beyond(node, tip):
    """The hold of a height release is `release_at_height` minus the height of
    the next block, in blocks (#76)."""
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.max_hold_either(600, 100),
                    rules.max_hold_either_model(600, 100))
    inside = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 100))
    assert inside["ok"], inside
    assert tip.asked(body)[-1]["i17"] == str(rules.BLOCKS + 100)

    beyond = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + 101, sequence_number=2))
    assert beyond["ok"] is False and beyond["code"] == "RECIPIENT_MAX_HOLD"
    assert beyond["details"] == {
        "transfer_index": 1, "recipient": RECIPIENT,
        "max_hold_blocks": 100, "hold_blocks": 101,
    }
    assert "at most 100 blocks ahead" in beyond["message"]
    assert "max_hold_blocks=100" in beyond["message"]
    assert "held for 101 blocks" in beyond["message"]

    far = _queue(sendtx, _park(release_at_height=NEXT_HEIGHT + MAX_RELEASE_WINDOW_BLOCKS,
                               sequence_number=2))
    assert far["code"] == "RECIPIENT_MAX_HOLD" and far["details"]["max_hold_blocks"] == 100


def test_one_rule_caps_both_kinds_of_release_each_in_its_own_unit(node, tip):
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.max_hold_either(600, 100),
             rules.max_hold_either_model(600, 100))
    hour = _queue(sendtx, _timed(3_600))
    assert hour["code"] == "RECIPIENT_MAX_HOLD"
    assert hour["details"] == {
        "transfer_index": 1, "recipient": RECIPIENT,
        "max_hold_seconds": 600, "hold_seconds": 3_600,
    }
    assert _queue(sendtx, _timed(600))["ok"]


def test_working_out_the_cap_has_one_budget_and_no_more(node, tip, monkeypatch):
    """A refusal costs the payer nothing, so the node bounds what it spends on
    one: when the time for the cap is used up the park is still refused, and
    the message says where the cap can be read."""
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


def test_a_park_refused_for_another_reason_is_not_a_hold_refusal(node, tip):
    """The allow-list refuses this sender whatever the hold, so there is no cap
    to report."""
    sendtx, _script = node
    tip.rule(RECIPIENT, rules.allow_list(THIRD), rules.allow_list_model(THIRD))
    result = _queue(sendtx, _timed(600))
    assert result["ok"] is False and result["code"] == "RECIPIENT_POLICY"
    assert "max_hold_seconds" not in result.get("details", {})


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
    body = tip.rule(RECIPIENT, rules.max_hold(0), rules.max_hold_model(0))
    rid = ra._seed_open_entry(_park())
    result = _queue(sendtx, ra._retract_payload(rid, sequence_number=1))
    assert result["ok"], result
    assert tip.asked(body) == []


def test_finding_the_cap_costs_a_bounded_number_of_evaluations(node, tip):
    sendtx, _script = node
    body = tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    refused = _queue(sendtx, _timed(3_600))
    assert refused["code"] == "RECIPIENT_MAX_HOLD"
    assert len(tip.asked(body)) <= 26


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
    rules.allow_list(RECIPIENT), rules.max_hold(0), rules.max_hold(600),
    rules.one_unit(THIRD, RECIPIENT, 600),
])
def test_the_documented_rules_register_on_an_active_chain(body):
    tx = _rule_tx("always ( %s )." % body)
    result = validate_o5_clause_routing(tx, _view(True), tx["operations"]["0"])
    assert result is not None and result.is_valid is True, getattr(result, "error", None)
    assert result.data["o5_clause_action"] == "declare"
    assert result.data["o5_clause_body"] == body


@pytest.mark.parametrize("body", [rules.allow_list(RECIPIENT), rules.max_hold(0)])
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
    ("i17[t]:bv[24]", "i17[t]:bv[64]"),       # the receive stream's own screen
    ("i17[t]", "explicit width"),             # the screen every clause clears first
])
def test_a_wrongly_typed_receive_stream_is_refused_on_an_active_chain(mention, said):
    body = "( (%s = { 1 }:bv[64]) ? %s : %s )" % (mention, rules.ALLOW, rules.BLOCK)
    tx = _rule_tx("always ( %s )." % body)
    result = validate_o5_clause_routing(tx, _view(True), tx["operations"]["0"])
    assert result is not None and result.is_valid is False
    assert said in result.error


def test_only_the_node_writes_the_receive_stream():
    """A sender who could put "17" in `operations` would answer the recipient's
    question for them."""
    transfers = [[SENDER, RECIPIENT, "5"]]
    tx = {"tx_type": "user_tx", "sender_pubkey": SENDER,
          "operations": {"1": transfers, "17": "0"}}
    refused = validate_user_tx_reserved_domains(tx, _view(True))
    assert refused is not None and refused.is_valid is False
    assert "17" in refused.error
    before = validate_user_tx_reserved_domains(tx, _view(False))
    assert before is None or before.is_valid is True, "an ordinary stream before activation"


def test_no_other_rule_may_read_the_receive_stream():
    rule = ("always ( (i17[t]:bv[64] = { 1 }:bv[64]) -> "
            "(o13[t]:bv[24] = { #x000001 }:bv[24]) ).")
    refused = validate_user_tx_reserved_domains(_rule_tx(rule), _view(True))
    assert refused is not None and refused.is_valid is False
    assert "receive stream" in refused.error


# --- capability reporting -------------------------------------------------------

def _rpc(*args):
    parsed = json.loads(getrecipientpolicy.execute(
        " ".join(("getrecipientpolicy",) + tuple(str(a) for a in args)), None))
    assert parsed.get("status") == "ok", parsed
    return parsed["data"]


def test_the_node_reports_an_inactive_chain(node, inactive_tip):
    tip = inactive_tip
    tip.rule(RECIPIENT, rules.SPEND_LIMIT, rules.spend_limit_model)
    data = _rpc(RECIPIENT)
    assert data["active"] is False and data["judges_incoming"] is False
    assert data["receive_stream"] == "i17" and data["receive_stream_width"] == 64
    assert data["has_clause"] is True and data["clause"] is None


def test_the_node_reports_whether_an_address_judges_incoming_payments(node, tip):
    assert _rpc(RECIPIENT) == {
        "active": True, "receive_stream": "i17", "receive_stream_width": 64,
        "address": RECIPIENT, "has_clause": False, "judges_incoming": False,
        "clause": None,
    }
    body = tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    data = _rpc(RECIPIENT)
    assert data["judges_incoming"] is True and data["clause"] == body
    assert "probe" not in data


def test_the_probe_reports_the_cap_a_wallet_must_respect(node, tip):
    tip.rule(RECIPIENT, rules.max_hold(600), rules.max_hold_model(600))
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe == {
        "sender": SENDER, "amount": 25, "advisory": True,
        "accepts_payment": True, "max_hold_seconds": 600,
        "max_hold_blocks": 0, "accepts_height_release": False,
    }
    tip.rule(RECIPIENT, rules.max_hold(0), rules.max_hold_model(0))
    assert _rpc(RECIPIENT, SENDER, 25)["probe"]["max_hold_seconds"] == 0


def test_the_probe_reports_a_cap_in_blocks(node, tip):
    tip.rule(RECIPIENT, rules.max_hold_either(600, 100),
             rules.max_hold_either_model(600, 100))
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe["max_hold_seconds"] == 600 and probe["max_hold_blocks"] == 100
    assert probe["accepts_height_release"] is True


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
    assert listed["accepts_payment"] is True
    assert listed["max_hold_seconds"] is None and listed["max_hold_blocks"] is None
    assert listed["accepts_height_release"] is True
    stranger = _rpc(RECIPIENT, STRANGER, 25)["probe"]
    assert stranger["accepts_payment"] is False


def test_the_probe_of_an_account_without_a_receive_rule_accepts(node, tip):
    probe = _rpc(RECIPIENT, SENDER, 25)["probe"]
    assert probe["accepts_payment"] is True and probe["max_hold_seconds"] is None
    assert probe["max_hold_blocks"] is None and probe["accepts_height_release"] is True
    assert tip.ev.verdict_calls == []


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
