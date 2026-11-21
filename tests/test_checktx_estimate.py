"""checktx estimate: the fee of a draft, from an isolated admission context.

The estimate runs the Tau steps of admission in a context of its own, on a
single slot apart from the sendtx slots, and never touches the standby. The plain
form runs no Tau and says that the fee check was skipped.
"""
import json
from unittest.mock import PropertyMock, patch

import pytest

import chain_state
import db
import tau_admission
from commands import checktx
from consensus.admission import TipAdmissionView
from consensus.rule_offers import RuleOffer
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
APPROVER = pubkey_hex(SK_CAROL)
SECRET_KEYS = {SENDER: SK_ALICE, RECIPIENT: SK_BOB}
NEXT_HEIGHT = 50
TIP_TS = 1_700_000_000
FAR = 9_999_999_999
BASE_FEE = 10
CUSTOM_FEE = 3
OFFER_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


class _Session:
    """A worker that answers every step with the transfer echo and a flat fee."""

    def __init__(self, script):
        self.script = script

    def evaluate(self, inputs, *, multi, record):
        self.script["steps"].append(dict(inputs))
        return {1: str(inputs.get(1, "0")), 5: self.script["o5"],
                8: str(CUSTOM_FEE), 9: str(BASE_FEE)}

    def apply_rule(self, rule_text, *, target, record):
        self.script["revisions"].append(rule_text)

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        self.script["disposed"] += 1


class _Standby:
    enabled = True

    def __init__(self):
        self.taken = 0
        self.refills = 0

    def take(self, **kwargs):
        self.taken += 1
        return None

    def refill(self, **kwargs):
        self.refills += 1


@pytest.fixture
def node(temp_database, mock_policy_evaluators, monkeypatch):
    """Worker-backed admission with a fake worker, and a real database."""
    # o5 allows, except where a test needs a policy that asks for approval.
    script = {"steps": [], "revisions": [], "built": 0, "disposed": 0, "o5": "1"}

    def build(**kwargs):
        script["built"] += 1
        script["labels"] = script.get("labels", []) + [kwargs["label"]]
        return _Session(script), {"journal_head": "h", "journal_sequence": 0,
                                  "epoch": 0, "high_water": 0}, None

    standby = _Standby()
    patches = [
        patch("tau_admission.enabled", return_value=True),
        patch("tau_admission._build", side_effect=build),
        patch("tau_admission._standby", standby),
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau_multi",
              side_effect=AssertionError("the in-process evaluator was used")),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch("tau_native.compile_revisions_isolated_subprocess", return_value=None),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
        patch.object(TipAdmissionView, "next_block_height",
                     new_callable=PropertyMock, return_value=NEXT_HEIGHT),
        patch.object(TipAdmissionView, "tip_timestamp",
                     new_callable=PropertyMock, return_value=TIP_TS),
        patch.object(TipAdmissionView, "approval_slots_active",
                     new_callable=PropertyMock, return_value=True),
        patch.object(TipAdmissionView, "get_offer", return_value=_offer_row()),
    ]
    mocks = [p.start() for p in patches]
    mocks[3].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    monkeypatch.setitem(chain_state._balances, RECIPIENT, 1_000_000)
    yield script, standby
    for p in reversed(patches):
        p.stop()


def _offer():
    return RuleOffer(offerer_pubkey=SENDER, recipient_pubkey=RECIPIENT,
                     rule_text=OFFER_RULE, expire_at_height=NEXT_HEIGHT + 100)


def _offer_row():
    offer = _offer()
    return {"offer_id": offer.offer_id_hex, "offerer_pubkey": SENDER,
            "recipient_pubkey": RECIPIENT, "rule_text": OFFER_RULE,
            "expire_at_height": offer.expire_at_height, "status": "offered"}


def _envelope(tx_type, sender, fee_limit, **fields):
    tx = {"tx_type": tx_type, "sender_pubkey": sender, "sequence_number": 1,
          "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 20,
          "fee_limit": fee_limit}
    tx.update(fields)
    return tx


def _payload(kind, fee_limit="0"):
    offer_id = _offer().offer_id_hex
    if kind == "user_tx":
        return _envelope(kind, SENDER, fee_limit,
                         operations={"1": [[SENDER, RECIPIENT, "100"]]})
    if kind == "retractable_transfer":
        return _envelope(kind, SENDER, fee_limit, recipient_pubkey=RECIPIENT,
                         amount=100, release_at_height=NEXT_HEIGHT + 30)
    if kind == "rule_offer":
        return _envelope(kind, SENDER, fee_limit, recipient_pubkey=RECIPIENT,
                         rule_text=OFFER_RULE)
    if kind == "rule_offer_accept":
        return _envelope(kind, RECIPIENT, fee_limit, offer_id=offer_id,
                         rule_text=OFFER_RULE)
    if kind == "rule_offer_reject":
        return _envelope(kind, RECIPIENT, fee_limit, offer_id=offer_id)
    if kind == "approval_request":
        return _envelope(kind, SENDER, fee_limit, recipient_pubkey=RECIPIENT,
                         amount=500, approvers={"18": APPROVER}, custom_inputs={})
    if kind == "rule_change_request":
        return _envelope(kind, SENDER, fee_limit, kind=1, rule_text=OFFER_RULE,
                         approvers={"18": APPROVER})
    if kind == "install_receive_route":
        return _envelope(kind, SENDER, fee_limit,
                         route_destination_pubkey=RECIPIENT, route_bps=2000)
    if kind == "remove_receive_route":
        _seed_installed_route()
        return _envelope(kind, SENDER, fee_limit)
    if kind == "create_standing_payment":
        return _envelope(kind, SENDER, fee_limit,
                         standing_recipient_pubkey=APPROVER, standing_amount=100,
                         standing_schedule="weekly", standing_anchor_ts=TIP_TS,
                         standing_window_seconds=604800,
                         standing_max_occurrences=10000)
    if kind == "cancel_standing_payment":
        return _envelope(kind, SENDER, fee_limit,
                         standing_auth_id=_seed_standing_payment())
    if kind == "execute_standing_payment":
        return _envelope(kind, SENDER, fee_limit,
                         standing_auth_id=_seed_standing_payment())
    if kind == "install_payout_rule":
        return _envelope(kind, SENDER, fee_limit, **_payout_install_fields())
    if kind == "remove_payout_rule":
        _seed_installed_payout_rule()
        return _envelope(kind, SENDER, fee_limit)
    if kind == "execute_payout_rule":
        return _envelope(kind, SENDER, fee_limit,
                         payout_rule_id=_seed_installed_payout_rule(),
                         payout_settlement_id="11" * 32,
                         payout_base_amount=101)
    raise AssertionError(kind)


def _check(payload, *, estimate=True):
    sign_payload(payload, SECRET_KEYS[payload["sender_pubkey"]])
    word = "checktx estimate" if estimate else "checktx"
    return json.loads(checktx.execute(f"{word} {json.dumps(payload)}", None))


FEE_BEARING = ["user_tx", "retractable_transfer", "rule_offer",
               "rule_offer_accept", "rule_offer_reject", "approval_request",
               "rule_change_request", "install_receive_route",
               "remove_receive_route", "create_standing_payment",
               "cancel_standing_payment", "execute_standing_payment",
               "install_payout_rule", "remove_payout_rule",
               "execute_payout_rule"]


def test_the_cases_cover_every_fee_bearing_type():
    from commands.sendtx import FEE_BEARING_TX_TYPES
    assert set(FEE_BEARING) == set(FEE_BEARING_TX_TYPES)


@pytest.mark.parametrize("kind", FEE_BEARING)
def test_the_estimate_of_each_fee_bearing_type(node, kind):
    script, _ = node
    if kind == "approval_request":
        script["o5"] = "0"
    env = _check(_payload(kind, fee_limit="0"))
    data = env["data"]
    assert data["estimated_fee"] == str(BASE_FEE + CUSTOM_FEE), env
    assert data["fee_limit"] == "0"
    assert data["admissible"] is False
    assert data["fee_checked"] is True
    assert data["tau_evaluated"] is True
    assert data["checks_skipped"] == []
    assert "note" not in data
    assert script["steps"]
    assert script["labels"] == ["estimate"]
    assert script["disposed"] == 1


@pytest.mark.parametrize("fee_limit", ["0", "13", "1000"])
def test_the_fee_limit_does_not_change_the_estimate(node, fee_limit):
    env = _check(_payload("rule_offer", fee_limit=fee_limit))
    assert env["data"]["estimated_fee"] == str(BASE_FEE + CUSTOM_FEE)
    assert env["data"]["admissible"] is (int(fee_limit) >= BASE_FEE + CUSTOM_FEE)


def test_a_busy_estimate_slot_answers_at_once(node):
    script, _ = node
    assert tau_admission._estimate_slot.acquire(blocking=False)
    try:
        env = _check(_payload("user_tx"))
    finally:
        tau_admission._estimate_slot.release()
    assert env["error"]["code"] == "ESTIMATE_BUSY", env
    assert script["built"] == 0


def test_an_estimate_does_not_take_a_sendtx_slot(node):
    held = [tau_admission._slots.acquire(blocking=False)
            for _ in range(tau_admission.MAX_CONCURRENT)]
    try:
        assert all(held)
        env = _check(_payload("user_tx"))
    finally:
        for _ in held:
            tau_admission._slots.release()
    assert env["data"]["estimated_fee"] == str(BASE_FEE + CUSTOM_FEE), env


def test_an_estimate_never_uses_the_standby(node):
    script, standby = node
    _check(_payload("user_tx"))
    assert standby.taken == 0
    assert standby.refills == 0
    assert script["built"] == 1


def test_the_estimate_slot_is_free_after_an_answer(node):
    _check(_payload("user_tx"))
    assert tau_admission._estimate_slot.acquire(blocking=False)
    tau_admission._estimate_slot.release()


def test_no_isolated_context_means_no_estimate(node):
    script, _ = node
    with patch("tau_admission.enabled", return_value=False):
        env = _check(_payload("user_tx"))
    assert env["error"]["code"] == "ADMISSION_UNAVAILABLE", env
    assert script["steps"] == []


def test_the_plain_form_says_the_fee_check_was_skipped(node):
    script, _ = node
    env = _check(_payload("user_tx", fee_limit="0"), estimate=False)
    data = env["data"]
    assert data["admissible"] is None
    assert data["fee_checked"] is False
    assert "fee_limit" in data["checks_skipped"]
    assert "tau_eval" in data["checks_skipped"]
    assert "fee check was skipped" in data["note"]
    assert "estimated_fee" not in data
    assert script["steps"] == [] and script["built"] == 0


def test_the_plain_form_rejection_names_the_skipped_fee_check(node):
    payload = _payload("user_tx")
    payload["sequence_number"] = 7
    env = _check(payload, estimate=False)
    assert env["error"]["code"] == "INVALID_SEQUENCE"
    assert env["error"]["details"]["checks_skipped"] == ["tau_eval", "fee_limit"]
    assert env["error"]["details"]["fee_checked"] is False


def test_an_estimate_with_no_payload_shows_the_usage(node):
    env = json.loads(checktx.execute("checktx estimate", None))
    assert env["error"]["code"] == "INVALID_PARAMS"
    assert "checktx [estimate]" in env["error"]["message"]


def _seed_installed_route():
    """Install the sender's receive route in the tip's book, as a mined
    install would leave it, so a removal has something to remove."""
    from consensus.receive_routes import ReceiveRouteEntry
    book = chain_state._lifecycle_manager.receive_routes
    if book.get(SENDER) is None:
        book.install(ReceiveRouteEntry(
            owner_pubkey=SENDER, destination_pubkey=RECIPIENT, bps=2000,
            min_amount=0, activation_ts=0, expiry_ts=0, locked_until_ts=0,
            version=1), TIP_TS)


def _seed_standing_payment():
    """Create the sender's standing payment in the tip's book, as a mined
    creation would leave it, and return its authorization id hex.

    Weekly from TIP_TS with a full-period window, so the current period is
    due at any later tip time and an execution always has a period to settle.
    The estimate mutates nothing, so the one authorization serves both the
    cancel and the execute case.
    """
    from consensus.standing_payments import (
        SCHEDULE_WEEKLY, StandingPaymentEntry)
    book = chain_state._lifecycle_manager.standing_payments
    entry = StandingPaymentEntry(
        payer_pubkey=SENDER, recipient_pubkey=RECIPIENT, amount=100,
        schedule_kind=SCHEDULE_WEEKLY, signed_day=0, anchor_ts=TIP_TS,
        window_seconds=604800, final_ts=0, max_occurrences=10000,
        max_total=0, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1)
    if book.get(entry.auth_id) is None:
        book.create(entry, TIP_TS)
    return entry.auth_id.hex()


def _payout_install_fields():
    """Root fields for an install the tip book admits, whichever case ran
    first: version 1 on an empty book, the next version (with a changed
    cap) once the seed rule is installed. The estimate mutates nothing, so
    the book state a case sees is exactly what the seed helpers left."""
    book = chain_state._lifecycle_manager.payout_rules
    current = book.get(SENDER)
    fields = {"payout_recipients": [RECIPIENT],
              "payout_legs": [[RECIPIENT, 2, 500]],
              "payout_period_seconds": 604800,
              "payout_period_anchor_ts": TIP_TS,
              "payout_version": 1}
    if current is not None:
        fields["payout_max_per_execution"] = 1000
        fields["payout_version"] = current.version + 1
    return fields


def _seed_installed_payout_rule():
    """Install the sender's payout rule in the tip's book, as a mined
    install would leave it, and return its rule id hex.

    A 5%-of-base royalty to RECIPIENT, anchored at TIP_TS, so an execution
    on a base of 101 computes a 5-unit leg at any later run time. The
    estimate mutates nothing, so the one rule serves both the remove and
    the execute case.
    """
    from consensus.payout_rules import PayoutLeg, PayoutRuleEntry
    book = chain_state._lifecycle_manager.payout_rules
    entry = PayoutRuleEntry(
        owner_pubkey=SENDER, recipients=(RECIPIENT,),
        legs=(PayoutLeg(RECIPIENT, 2, 500),),
        max_per_execution=0, max_per_period=0,
        period_seconds=604800, period_anchor_ts=TIP_TS, version=1)
    if book.get(SENDER) is None:
        book.install(entry, TIP_TS)
    return entry.rule_id.hex()


def _seed_open_park():
    from consensus.retractable import parse_retractable_transfer
    entry = parse_retractable_transfer(_payload("retractable_transfer"))
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT INTO retractable_transfers_v1 (retractable_id, sender_pubkey, "
            "recipient_pubkey, amount, sequence_number, release_kind, release_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.retractable_id.hex(), entry.sender_pubkey, entry.recipient_pubkey,
             entry.amount, entry.sequence_number, entry.kind, entry.release_at))
    return entry.retractable_id.hex()


def test_a_fee_exempt_type_ran_no_step_and_says_so(node):
    script, _ = node
    payload = _envelope("retract_transfer", SENDER, "0",
                        retractable_id=_seed_open_park())
    env = _check(payload)
    data = env["data"]
    assert data["admissible"] is True, env
    assert data["tau_evaluated"] is False
    assert data["fee_checked"] is False
    assert data["checks_skipped"] == ["tau_eval", "fee_limit"]
    assert data["note"].startswith("fee_exempt")
    assert "estimated_fee" not in data
    assert script["steps"] == [] and script["revisions"] == []


def test_a_refusal_before_any_tau_step_has_both_flags_false(node):
    script, _ = node
    payload = _payload("user_tx")
    payload["sequence_number"] = 7
    env = _check(payload)
    details = env["error"]["details"]
    assert env["error"]["code"] == "INVALID_SEQUENCE"
    assert details["tau_evaluated"] is False
    assert details["fee_checked"] is False
    assert details["checks_skipped"] == ["tau_eval", "fee_limit"]
    assert script["built"] == 0


def test_a_refusal_by_a_tau_step_says_tau_ran_but_no_fee_was_estimated(node):
    script, _ = node
    script["o5"] = "0"
    env = _check(_payload("user_tx"))
    details = env["error"]["details"]
    assert env["error"]["code"] == "TX_REJECTED", env
    assert details["tau_evaluated"] is True
    assert details["fee_checked"] is False
    assert details["checks_skipped"] == ["fee_limit"]
    assert len(script["steps"]) == 1


def test_an_estimate_of_a_request_the_policy_does_not_gate_is_refused(node):
    script, _ = node
    script["o5"] = "1"
    env = _check(_payload("approval_request"))
    details = env["error"]["details"]
    assert env["error"]["code"] == "APPROVAL_NOT_NEEDED", env
    assert details["request_id"]
    assert details["tau_evaluated"] is True
    assert details["fee_checked"] is False
    assert details["checks_skipped"] == ["fee_limit"]


def test_the_plain_form_on_an_accept_opens_no_admission_context(node):
    script, standby = node
    with patch("tau_admission.open_context",
               side_effect=AssertionError("the plain form opened an admission context")):
        env = _check(_payload("rule_offer_accept"), estimate=False)
    data = env["data"]
    assert data["admissible"] is None, env
    assert data["tau_evaluated"] is False
    assert data["checks_skipped"] == ["tau_eval", "fee_limit"]
    assert script["built"] == 0 and script["revisions"] == []
    assert standby.taken == 0


@pytest.mark.parametrize("kind", ["user_tx", "rule_offer"])
def test_an_estimate_under_force_test_does_not_say_admissible(node, kind):
    script, _ = node
    with patch("tau_manager.is_force_test_enabled", return_value=True):
        env = _check(_payload(kind))
    data = env["data"]
    assert data["admissible"] is None, env
    assert data["fee_checked"] is False
    assert "fee_limit" in data["checks_skipped"]
    assert "estimated_fee" not in data
    assert data["note"].startswith("The fee check was skipped")
    assert script["steps"] == []


def _fee_rule():
    return ("always ( (i12[t]:bv[384] = { #x%s }:bv[384]) "
            "? (o8[t]:bv[24] = { #x000002 }:bv[24]) "
            ": (o8[t]:bv[24] = { #x000000 }:bv[24]) )." % SENDER)


def test_the_plain_form_on_a_user_rule_opens_no_admission_context(node):
    script, standby = node
    payload = _envelope("user_tx", SENDER, "0", operations={"0": _fee_rule()})
    with patch("tau_admission.open_context",
               side_effect=AssertionError("the plain form opened an admission context")), \
            patch("commands.sendtx._preflight_prepared_rule",
                  side_effect=AssertionError("the plain form ran the preflight")):
        env = _check(payload, estimate=False)
    data = env["data"]
    assert data["admissible"] is None, env
    assert data["tau_evaluated"] is False
    assert data["checks_skipped"] == ["tau_eval", "fee_limit"]
    assert script["built"] == 0 and script["revisions"] == []
    assert standby.taken == 0


def test_the_estimate_of_a_user_tx_with_a_rule(node):
    script, _ = node
    rule = _fee_rule()
    env = _check(_envelope("user_tx", SENDER, "0", operations={"0": rule}))
    data = env["data"]
    assert data["estimated_fee"] == str(BASE_FEE + CUSTOM_FEE), env
    assert data["admissible"] is False
    assert data["tau_evaluated"] is True and data["fee_checked"] is True
    assert data["checks_skipped"] == []
    assert script["revisions"] == [rule]
    # the custom step after the rule, then the fee query
    assert len(script["steps"]) == 2
    assert script["labels"] == ["estimate"] and script["disposed"] == 1


def test_the_estimate_of_a_user_tx_with_custom_inputs(node):
    script, _ = node
    env = _check(_envelope("user_tx", SENDER, "1000", operations={"30": "7"}))
    data = env["data"]
    assert data["estimated_fee"] == str(BASE_FEE + CUSTOM_FEE), env
    assert data["admissible"] is True
    assert data["tau_evaluated"] is True and data["fee_checked"] is True
    assert data["checks_skipped"] == []
    assert script["revisions"] == []
    custom_step, fee_query = script["steps"]
    assert custom_step[30] == ["7"] and custom_step[5]
    assert fee_query[30] == ["7"]


def test_an_unfunded_sender_is_refused_before_the_estimate_slot(node, monkeypatch):
    """Unfunded keys with valid signatures must not hold the one estimate slot."""
    script, _ = node
    monkeypatch.setitem(chain_state._balances, SENDER, 0)
    with patch("tau_admission._estimate_slot.acquire",
               side_effect=AssertionError("the estimate slot was taken")):
        env = _check(_payload("rule_offer", fee_limit="1000"))
    assert env["error"]["code"] == "INSUFFICIENT_FUNDS", env
    assert env["error"]["details"]["required"] == 1
    assert "estimated_fee" not in env["error"]["details"]
    assert script["built"] == 0 and script["steps"] == []

    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    env = _check(_payload("rule_offer", fee_limit="1000"))
    assert env["data"]["estimated_fee"] == str(BASE_FEE + CUSTOM_FEE), env
    assert script["built"] == 1


def test_a_sender_who_cannot_pay_the_fee_gets_no_estimate(node, monkeypatch):
    monkeypatch.setitem(chain_state._balances, SENDER, 100 + 1)
    env = _check(_payload("user_tx", fee_limit="1000"))
    assert env["error"]["code"] == "INSUFFICIENT_FUNDS", env
    assert env["error"]["details"]["required"] == 100 + BASE_FEE + CUSTOM_FEE
    assert "estimated_fee" not in env["error"]["details"]
