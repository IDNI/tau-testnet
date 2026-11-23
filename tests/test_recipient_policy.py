"""Recipient-side o5 policy (#47) and the max-hold cap (#76): the shared gate,
the cap probe, and the admission, apply and checktx sites that go through it
(mock mode).

Test names carry their acceptance case: 47-1..47-5 and 76-1..76-6.
"""
import json
import time
from contextlib import ExitStack
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

import chain_state
import db
import tau_defs
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload
from commands import checktx, sendtx
from consensus import sender_policy
from consensus.admission import (
    TipAdmissionView,
    _admission_from_domain_error,
    _screen_clause_domains,
    is_feature_inactive_error,
    validate_o5_clause_routing,
)
from consensus.approvals import screen_hold_widths
from consensus.policy_mock import MockPolicyEvaluator
from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    hold_lengths,
    hold_stream_and_value,
)

import test_approval_apply as ap
import test_retractable_apply as rp

POOLS = ("apply", "admission")

# --- admission keys (bls_keys) ------------------------------------------------
SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
THIRD = pubkey_hex(SK_CAROL)
NEXT_HEIGHT = 50
# The tip clock sits ahead of the wall clock: a time park's envelope
# expiration must be in the wall-clock future while staying before its
# release, so the tip cannot be a fixed date in the past. Only differences
# from this clock are ever asserted (holds), never its absolute value.
TIP_TS = int(time.time()) + 100_000
FAR = 9_999_999_999

ADMISSION_CLAUSE_VIEW = "consensus.facade.TipAdmissionView.clause_for"

_ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
_BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def _allow_list_body(allowed):
    """Block unless the sender (i3) is `allowed`."""
    return (
        "(i3[t]:bv[384] = { #x" + allowed + " }:bv[384]) ? "
        + _ALLOW + " : " + _BLOCK
    )


def _cap_seconds_body(cap):
    """Block when the hold in seconds (i17) exceeds `cap`."""
    return (
        "(i17[t]:bv[64] > { #x%016x }:bv[64]) ? " % cap
        + _BLOCK + " : " + _ALLOW
    )


def _cap_blocks_body(cap):
    """Block when the hold in blocks (i27) exceeds `cap`."""
    return (
        "(i27[t]:bv[64] > { #x%016x }:bv[64]) ? " % cap
        + _BLOCK + " : " + _ALLOW
    )


_CAP_ZERO_BODY = (
    "((i17[t]:bv[64] > { #x0000000000000000 }:bv[64])"
    " || (i27[t]:bv[64] > { #x0000000000000000 }:bv[64])) ? "
    + _BLOCK + " : " + _ALLOW
)

# Blocks every nonzero transfer, whatever the hold: the refusal is not about
# the hold at all, so no cap may be reported for it.
_BLOCK_ALL_BODY = (
    "(i1[t]:bv[24] > { #x000000 }:bv[24]) ? " + _BLOCK + " : " + _ALLOW
)

# Blocks only when the sender is the clause's own owner and the amount is big:
# an outbound-only condition, which must never refuse an inbound transfer.
def _outbound_only_body(owner):
    return (
        "((i3[t]:bv[384] = { #x" + owner + " }:bv[384])"
        " && (i1[t]:bv[24] > { #x0003e8 }:bv[24])) ? "
        + _BLOCK + " : " + _ALLOW
    )


_OUTBOUND_ONLY_BODY = _outbound_only_body(RECIPIENT)

# Blocks holds in [100, 110] only: non-monotone, so no single cap exists.
_NON_MONOTONE_BODY = (
    "((i17[t]:bv[64] >= { #x0000000000000064 }:bv[64])"
    " && (i17[t]:bv[64] <= { #x000000000000006e }:bv[64])) ? "
    + _BLOCK + " : " + _ALLOW
)


def _rule(body):
    return f"always ( {body} )."


# --- mock clause semantics ----------------------------------------------------
# The mock evaluator does not parse Tau: each decide function implements the
# clause body above it, reading the same inputs the real worker would see.

def _allow_list_decide(allowed):
    def decide(inputs):
        return "1" if inputs.get("i3") == "#x" + allowed else "0"
    return decide


def _cap_seconds_decide(cap):
    def decide(inputs):
        return "0" if int(inputs.get("i17", "0")) > cap else "1"
    return decide


def _cap_blocks_decide(cap):
    def decide(inputs):
        return "0" if int(inputs.get("i27", "0")) > cap else "1"
    return decide


def _cap_zero_decide(inputs):
    return (
        "0"
        if int(inputs.get("i17", "0")) > 0 or int(inputs.get("i27", "0")) > 0
        else "1"
    )


def _outbound_only_decide_for(owner):
    def decide(inputs):
        blocked = (
            inputs.get("i3") == "#x" + owner
            and int(inputs.get("i1", "0")) > 1000
        )
        return "0" if blocked else "1"
    return decide


def _outbound_only_decide(inputs):
    return _outbound_only_decide_for(RECIPIENT)(inputs)


def _non_monotone_decide(inputs):
    return "0" if 100 <= int(inputs.get("i17", "0")) <= 110 else "1"


@pytest.fixture(autouse=True)
def _reset_overrides():
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in POOLS:
        sender_policy.set_evaluator(pool, None)


@pytest.fixture
def active():
    """The feature switched on, the way a coordinated upgrade would."""
    with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", True):
        yield


class _Exploding:
    def verdict(self, *a, **k):
        raise AssertionError("the evaluator must not be consulted")


def _evaluator(pool, body, decide):
    ev = MockPolicyEvaluator(pool=pool)
    ev.set_verdict(body, decide)
    sender_policy.set_evaluator(pool, ev)
    return ev


# --- hold_lengths / hold_stream_and_value -------------------------------------

def test_hold_lengths_time_kind_is_seconds_and_zero_blocks():
    assert hold_lengths(KIND_TIME, TIP_TS + 600, NEXT_HEIGHT, TIP_TS) == (600, 0)


def test_hold_lengths_height_kind_is_blocks_and_zero_seconds():
    assert hold_lengths(KIND_HEIGHT, NEXT_HEIGHT + 50, NEXT_HEIGHT, TIP_TS) == (0, 50)


def test_hold_lengths_clamps_a_release_at_or_before_the_clock_to_zero():
    assert hold_lengths(KIND_TIME, TIP_TS, NEXT_HEIGHT, TIP_TS) == (0, 0)
    assert hold_lengths(KIND_HEIGHT, NEXT_HEIGHT - 1, NEXT_HEIGHT, TIP_TS) == (0, 0)


def test_hold_lengths_unknown_kind_is_zero():
    assert hold_lengths(9, TIP_TS + 600, NEXT_HEIGHT, TIP_TS) == (0, 0)


def test_hold_stream_and_value_names_the_nonzero_unit():
    assert hold_stream_and_value(600, 0) == (tau_defs.HOLD_SECONDS_STREAM_INDEX, 600)
    assert hold_stream_and_value(0, 50) == (tau_defs.HOLD_BLOCKS_STREAM_INDEX, 50)
    assert hold_stream_and_value(0, 0) == (None, 0)


# --- screen_hold_widths ---------------------------------------------------------

def test_hold_streams_must_be_typed_bv64():
    assert screen_hold_widths(_cap_seconds_body(600)) is None
    assert screen_hold_widths(_cap_blocks_body(100)) is None
    assert screen_hold_widths(_CAP_ZERO_BODY) is None


def test_hold_streams_at_another_width_are_refused():
    body = "(i17[t]:bv[24] > { #x0258 }:bv[24]) ? " + _BLOCK + " : " + _ALLOW
    error = screen_hold_widths(body)
    assert error and "bv[64]" in error and "bv[24]" in error
    body = "(i27[t]:bv[384] > { #x64 }:bv[384]) ? " + _BLOCK + " : " + _ALLOW
    error = screen_hold_widths(body)
    assert error and "bv[64]" in error and "bv[384]" in error


def test_an_untyped_hold_mention_is_refused():
    body = "(i17[t] > 600) ? " + _BLOCK + " : " + _ALLOW
    error = screen_hold_widths(body)
    assert error and "i17[t]:bv[64]" in error


def test_a_body_without_hold_streams_passes_and_a_comment_does_not_count():
    assert screen_hold_widths(_allow_list_body(SENDER)) is None
    assert screen_hold_widths("# i17[t]:bv[24] in a comment\n" + _allow_list_body(SENDER)) is None


# --- probe_hold_cap -------------------------------------------------------------

def _probe(body, decide, hold_stream, hold_value):
    ev = _evaluator("apply", body, decide)
    cap = sender_policy.probe_hold_cap(
        body, {1: "100", 17: str(hold_value) if hold_stream == 17 else "0",
               27: str(hold_value) if hold_stream == 27 else "0"},
        pool="apply", hold_stream=hold_stream, hold_value=hold_value,
    )
    return cap, ev


def test_probe_finds_a_seconds_cap():
    cap, ev = _probe(_cap_seconds_body(600), _cap_seconds_decide(600), 17, 3600)
    assert cap == 600
    assert len(ev.verdict_calls) <= sender_policy.MAX_HOLD_PROBES


def test_probe_finds_a_blocks_cap():
    cap, _ = _probe(_cap_blocks_body(100), _cap_blocks_decide(100), 27, 200)
    assert cap == 100


def test_probe_finds_cap_zero():
    cap, _ = _probe(_CAP_ZERO_BODY, _cap_zero_decide, 17, 600)
    assert cap == 0


def test_probe_is_bounded_at_the_max_window():
    cap, ev = _probe(
        _cap_seconds_body(600), _cap_seconds_decide(600), 17, 7_776_000
    )
    assert cap == 600
    assert len(ev.verdict_calls) <= sender_policy.MAX_HOLD_PROBES


def test_probe_reports_no_cap_when_the_clause_also_blocks_a_plain_transfer():
    cap, ev = _probe(_BLOCK_ALL_BODY, lambda inputs: "0", 17, 600)
    assert cap is None
    # Only the hold-0 probe ran: the refusal is not about the hold.
    assert len(ev.verdict_calls) == 1


def test_probe_reports_no_cap_for_a_non_monotone_clause():
    cap, _ = _probe(_NON_MONOTONE_BODY, _non_monotone_decide, 17, 150)
    assert cap is None


def test_probe_reports_no_cap_without_a_body_or_a_hold():
    ev = _evaluator("apply", _cap_seconds_body(600), _cap_seconds_decide(600))
    assert sender_policy.probe_hold_cap(
        None, {}, pool="apply", hold_stream=17, hold_value=600
    ) is None
    assert sender_policy.probe_hold_cap(
        _cap_seconds_body(600), {}, pool="apply", hold_stream=17, hold_value=0
    ) is None
    assert ev.verdict_calls == []


# --- recipient_blocks -----------------------------------------------------------

def _clause_for(body):
    def lookup(pubkey, stream):
        assert stream == tau_defs.USER_POLICY_STREAM_INDEX
        return body
    return lookup


def test_47_inactive_gate_is_inert_and_touches_nothing():
    """The flag off means no lookup and no evaluation, whatever clause exists."""
    def _forbidden(pubkey, stream):
        raise AssertionError("clause_for must not be called while inactive")

    sender_policy.set_evaluator("apply", _Exploding())
    assert sender_policy.recipient_blocks(
        _forbidden, RECIPIENT, {1: "100"}, pool="apply"
    ) == (False, "", None)


def test_47_no_recipient_clause_allows_everything(active):
    sender_policy.set_evaluator("apply", _Exploding())
    assert sender_policy.recipient_blocks(
        _clause_for(None), RECIPIENT, {1: "100"}, pool="apply"
    ) == (False, "", None)


def test_47_a_blocking_recipient_clause_blocks_a_plain_transfer(active):
    ev = _evaluator("apply", _BLOCK_ALL_BODY, lambda inputs: "0")
    blocked, detail, cap = sender_policy.recipient_blocks(
        _clause_for(_BLOCK_ALL_BODY), RECIPIENT, {1: "100"}, pool="apply"
    )
    assert (blocked, detail, cap) == (True, "0", None)
    # A plain transfer has no hold to probe.
    assert len(ev.verdict_calls) == 1


def test_76_a_blocking_park_clause_reports_its_cap(active):
    body = _cap_seconds_body(600)
    ev = _evaluator("apply", body, _cap_seconds_decide(600))
    blocked, detail, cap = sender_policy.recipient_blocks(
        _clause_for(body), RECIPIENT, {1: "100", 17: "3600", 27: "0"},
        pool="apply", hold_stream=17, hold_value=3600,
    )
    assert blocked is True and detail == "0" and cap == 600
    assert len(ev.verdict_calls) <= 1 + sender_policy.MAX_HOLD_PROBES


def test_76_an_allowing_park_clause_never_probes(active):
    body = _cap_seconds_body(600)
    ev = _evaluator("apply", body, _cap_seconds_decide(600))
    blocked, detail, cap = sender_policy.recipient_blocks(
        _clause_for(body), RECIPIENT, {1: "100", 17: "300", 27: "0"},
        pool="apply", hold_stream=17, hold_value=300,
    )
    assert (blocked, detail, cap) == (False, "1", None)
    assert len(ev.verdict_calls) == 1, "probing runs only on the refusal path"


# --- clause screen: deploy refusal on an inactive node ------------------------

def _mock_view():
    view = MagicMock(spec=TipAdmissionView)
    view.clause_for.return_value = None
    return view


def _routing_tx(rule_text):
    return {
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "operations": {"0": rule_text},
    }


def test_47_5_an_inactive_node_refuses_a_hold_cap_rule_at_deploy():
    """#47 case 5 / #76 case 6: a rule that would never run is refused with a
    clear reason, not silently admitted."""
    # Pinned off explicitly: the test is about the inactive behaviour, not
    # about the module default.
    with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
        result = validate_o5_clause_routing(
            _routing_tx(_rule(_cap_seconds_body(600))), _mock_view(),
            _rule(_cap_seconds_body(600)),
        )
    assert result.is_valid is False
    assert result.code == "FEATURE_INACTIVE"
    assert "i17" in result.error


def test_76_6_an_inactive_node_refuses_a_blocks_cap_rule_at_deploy():
    with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
        result = validate_o5_clause_routing(
            _routing_tx(_rule(_cap_blocks_body(100))), _mock_view(),
            _rule(_cap_blocks_body(100)),
        )
    assert result.is_valid is False
    assert result.code == "FEATURE_INACTIVE"
    assert "i27" in result.error


def test_47_5_an_active_node_admits_a_hold_cap_rule(active):
    result = validate_o5_clause_routing(
        _routing_tx(_rule(_cap_seconds_body(600))), _mock_view(),
        _rule(_cap_seconds_body(600)),
    )
    assert result.is_valid, result.error
    assert result.data["o5_clause_action"] == "declare"


def test_76_6_an_active_node_refuses_a_wrong_width_hold_stream(active):
    body = "(i17[t]:bv[24] > { #x0258 }:bv[24]) ? " + _BLOCK + " : " + _ALLOW
    error = _screen_clause_domains(body)
    assert error and "bv[64]" in error
    result = _admission_from_domain_error(error)
    assert result.code == "WIDTH_MISMATCH"


def test_a_clause_that_never_mentions_a_hold_stream_is_unaffected_by_the_flag():
    body = _allow_list_body(SENDER)
    assert _screen_clause_domains(body) is None
    with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", True):
        assert _screen_clause_domains(body) is None


def test_the_feature_inactive_phrase_matches_only_that_refusal():
    assert is_feature_inactive_error("Recipient policy i17 is not active on this chain")
    assert not is_feature_inactive_error("Co-signature approvals are not active on this chain.")
    assert not is_feature_inactive_error("rule reads a step other than the current one")
    assert not is_feature_inactive_error(None)


# --- admission ------------------------------------------------------------------

@pytest.fixture
def node(temp_database, monkeypatch):
    """Admission end to end: real DB, real signatures, scripted Tau, and a
    fixed tip clock so park holds are exact."""
    script = {"fee": 0, "custom": 0, "block_o5": False, "calls": []}

    def multi(**kwargs):
        script["calls"].append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        return {
            1: str(vals.get(1, "0")),
            5: "0" if script["block_o5"] else "1",
            8: str(script["custom"]),
            9: str(script["fee"]),
        }

    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state.load_genesis("data/genesis.json")
    db.clear_mempool()
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    with ExitStack() as stack:
        for target, kwargs in (
            ("commands.sendtx.validate_bls_pubkey", {"return_value": None}),
            ("tau_manager.is_force_test_enabled", {"return_value": False}),
            ("tau_manager.communicate_with_tau_multi", {"side_effect": multi}),
        ):
            stack.enter_context(patch(target, **kwargs))
        ready = stack.enter_context(patch("tau_manager.tau_ready"))
        ready.is_set.return_value = True
        stack.enter_context(patch.object(
            TipAdmissionView, "next_block_height",
            new_callable=PropertyMock, return_value=NEXT_HEIGHT))
        stack.enter_context(patch.object(
            TipAdmissionView, "tip_timestamp",
            new_callable=PropertyMock, return_value=TIP_TS))
        stack.enter_context(patch.object(
            TipAdmissionView, "next_block_timestamp",
            new_callable=PropertyMock, return_value=TIP_TS))
        yield script


def _clauses(mapping):
    """clause_for side effect: mapping pubkey -> body (None = no clause)."""
    def _for(pubkey, stream):
        assert stream == tau_defs.USER_POLICY_STREAM_INDEX
        return mapping.get(str(pubkey).lower())
    return _for


def _queue(payload, **kw):
    return sendtx.queue_transaction(json.dumps(payload), propagate=False, **kw)


def _next_seq():
    """The sequence a fresh payload needs: chain state, past any queued tx."""
    expected = chain_state.get_sequence_number(SENDER)
    pending = db.get_pending_sequence(SENDER)
    if pending is not None and pending >= expected:
        expected = pending + 1
    return expected


def _mempool_hashes():
    with db._db_lock:
        return [r[0] for r in db._db_conn.execute("SELECT tx_hash FROM mempool")]


def _transfer_payload(outputs, amount="1"):
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "sequence_number": _next_seq(),
        "expiration_time": int(time.time()) + 1000,
        "expire_at_height": 5000,
        "operations": {"1": [[SENDER, to, amount] for to in outputs]},
        "fee_limit": "1000",
    }
    return sign_payload(tx, SK_ALICE)


def _park_payload(*, release_at_time=None, release_at_height=None, amount=100):
    tx = {
        "tx_type": "retractable_transfer",
        "sender_pubkey": SENDER,
        "sequence_number": _next_seq(),
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "100",
        "recipient_pubkey": RECIPIENT,
        "amount": amount,
    }
    if release_at_time is not None:
        tx["release_at_time"] = release_at_time
        # A time park's wall-clock deadline must be strictly before release.
        tx["expiration_time"] = TIP_TS + 100
    else:
        tx["release_at_height"] = release_at_height
    return sign_payload(tx, SK_ALICE)


def test_47_1_admission_blocks_an_unlisted_sender(active, node):
    """#47 case 1: the recipient's allow-list is evaluated at admission, after
    the sender-side checks, with the counterparty on i3 and amount on i1."""
    body = _allow_list_body(THIRD)
    ev = _evaluator("admission", body, _allow_list_decide(THIRD))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        res = _queue(_transfer_payload([RECIPIENT]))
    assert res["ok"] is False
    assert res["code"] == "RECIPIENT_POLICY_BLOCK"
    assert "recipient's policy clause" in res["message"]
    assert res["details"]["transfer_index"] == 1
    assert _mempool_hashes() == []
    _body, inputs = ev.verdict_calls[-1]
    assert inputs["i3"] == "#x" + SENDER and inputs["i1"] == "1"


def test_47_1_admission_allows_a_listed_sender(active, node):
    body = _allow_list_body(SENDER)
    _evaluator("admission", body, _allow_list_decide(SENDER))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        assert _queue(_transfer_payload([RECIPIENT]))["ok"] is True


def test_47_2_admission_without_a_recipient_clause_allows(active, node):
    sender_policy.set_evaluator("admission", _Exploding())
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({})):
        assert _queue(_transfer_payload([RECIPIENT]))["ok"] is True


def test_47_3_admission_batch_one_refused_output_fails_the_tx(active, node):
    """#47 case 3: each output is checked against its own recipient; one
    refusal fails the whole transaction, with nothing queued."""
    body = _allow_list_body(THIRD)
    _evaluator("admission", body, _allow_list_decide(THIRD))
    mapping = {RECIPIENT: _allow_list_body(SENDER), THIRD: body}
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses(mapping)):
        res = _queue(_transfer_payload([RECIPIENT, THIRD]))
    assert res["ok"] is False
    assert res["code"] == "RECIPIENT_POLICY_BLOCK"
    assert res["details"]["transfer_index"] == 2
    assert _mempool_hashes() == []


def test_47_4_admission_an_outbound_only_clause_does_not_block_inbound(active, node):
    """#47 case 4: one unit judges both directions; a clause that only speaks
    about outbound transfers (i3 is its owner) does not refuse inbound ones."""
    body = _OUTBOUND_ONLY_BODY
    ev = _evaluator("admission", body, _outbound_only_decide)
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        res = _queue(_transfer_payload([RECIPIENT], amount="5000"))
    assert res["ok"] is True, res
    _body, inputs = ev.verdict_calls[-1]
    assert inputs["i3"] == "#x" + SENDER
    assert inputs["i1"] == "5000"


def test_47_the_sender_check_runs_first(active, node):
    """The sender's own clause is judged before the recipient's: when it
    blocks, the recipient's clause is never consulted."""
    sender_body = _BLOCK_ALL_BODY
    recipient_body = _allow_list_body(THIRD)
    ev = MockPolicyEvaluator(pool="admission")
    ev.set_verdict(sender_body, "0")
    ev.set_verdict(recipient_body, "0")
    sender_policy.set_evaluator("admission", ev)
    mapping = {SENDER: sender_body, RECIPIENT: recipient_body}
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses(mapping)):
        res = _queue(_transfer_payload([RECIPIENT]))
    assert res["ok"] is False
    assert res["code"] == "TX_REJECTED"
    assert "sender's own policy clause" in res["message"]
    assert [b for b, _ in ev.verdict_calls] == [sender_body]


def test_47_admission_is_inert_while_inactive(node):
    # Pinned off explicitly: the test is about the inactive behaviour, not
    # about the module default.
    with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
        sender_policy.set_evaluator("admission", _Exploding())
        with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: _BLOCK_ALL_BODY})):
            assert _queue(_transfer_payload([RECIPIENT]))["ok"] is True


def test_76_1_admission_cap_zero_admits_plain_and_refuses_every_park(active, node):
    """#76 case 1: cap 0 admits plain transfers, refuses every park, and the
    refusal carries the cap."""
    body = _CAP_ZERO_BODY
    _evaluator("admission", body, _cap_zero_decide)
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        # A plain transfer has hold 0 and passes the cap.
        assert _queue(_transfer_payload([RECIPIENT]))["ok"] is True
        queued = _mempool_hashes()
        assert len(queued) == 1, "the plain transfer is queued"
        # Every park is refused, with the cap carried in the details.
        res = _queue(_park_payload(release_at_time=TIP_TS + 600))
    assert res["ok"] is False
    assert res["code"] == "RECIPIENT_MAX_HOLD"
    assert res["details"]["max_hold_seconds"] == 0
    assert res["details"]["hold_seconds"] == 600
    assert res["details"]["hold_blocks"] == 0
    assert "caps the hold at 0 seconds" in res["message"]
    assert _mempool_hashes() == queued, "the refused park added nothing"


def test_76_2_admission_cap_600_admits_ten_minutes_and_refuses_an_hour(active, node):
    """#76 case 2: a 600-second cap admits a 10-minute park and refuses a
    1-hour park, carrying the cap."""
    body = _cap_seconds_body(600)
    ev = _evaluator("admission", body, _cap_seconds_decide(600))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        assert _queue(_park_payload(release_at_time=TIP_TS + 600))["ok"] is True
        res = _queue(_park_payload(release_at_time=TIP_TS + 3600))
    assert res["ok"] is False
    assert res["code"] == "RECIPIENT_MAX_HOLD"
    assert res["details"]["max_hold_seconds"] == 600
    assert res["details"]["hold_seconds"] == 3600
    assert "600 seconds" in res["message"]
    # The clause saw the hold on i17 and 0 on i27.
    assert any(
        inputs.get("i17") == "3600" and inputs.get("i27") == "0"
        for _body, inputs in ev.verdict_calls
    ), ev.verdict_calls


def test_76_2_admission_height_parks_are_capped_in_blocks(active, node):
    body = _cap_blocks_body(100)
    ev = _evaluator("admission", body, _cap_blocks_decide(100))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        assert _queue(_park_payload(release_at_height=NEXT_HEIGHT + 50))["ok"] is True
        res = _queue(_park_payload(release_at_height=NEXT_HEIGHT + 200))
    assert res["ok"] is False
    assert res["code"] == "RECIPIENT_MAX_HOLD"
    assert res["details"]["max_hold_blocks"] == 100
    assert res["details"]["hold_blocks"] == 200
    assert res["details"]["hold_seconds"] == 0
    assert any(
        inputs.get("i27") == "200" and inputs.get("i17") == "0"
        for _body, inputs in ev.verdict_calls
    ), ev.verdict_calls


def test_76_2_admission_hold_equals_cap_passes_and_cap_plus_one_refuses(active, node):
    body = _cap_seconds_body(600)
    _evaluator("admission", body, _cap_seconds_decide(600))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        assert _queue(_park_payload(release_at_time=TIP_TS + 600))["ok"] is True
        res = _queue(_park_payload(release_at_time=TIP_TS + 601))
    assert res["ok"] is False
    assert res["code"] == "RECIPIENT_MAX_HOLD"
    assert res["details"]["max_hold_seconds"] == 600


def test_76_3_admission_no_policy_passes_parks_of_any_length(active, node):
    """#76 case 3: no policy (or no cap mentioned) means parks of any length
    pass, up to the window."""
    sender_policy.set_evaluator("admission", _Exploding())
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({})):
        assert _queue(_park_payload(release_at_time=TIP_TS + 3600))["ok"] is True
        assert _queue(_park_payload(release_at_height=NEXT_HEIGHT + 100_000))["ok"] is True


def test_76_4_admission_a_retract_is_never_gated(active, node):
    """#76 case 4: a retract is not a transfer to the recipient; the
    recipient's clause -- even one that blocks everything -- cannot stop it."""
    from consensus.retractable import parse_retractable_transfer

    parked = _park_payload(release_at_height=NEXT_HEIGHT + 30)
    entry = parse_retractable_transfer(
        {k: v for k, v in parked.items() if k != "signature"}
    )
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT INTO retractable_transfers_v1 (retractable_id, sender_pubkey, "
            "recipient_pubkey, amount, sequence_number, release_kind, release_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.retractable_id.hex(), entry.sender_pubkey,
             entry.recipient_pubkey, entry.amount, entry.sequence_number,
             entry.kind, entry.release_at),
        )
    retract = sign_payload({
        "tx_type": "retract_transfer",
        "sender_pubkey": SENDER,
        "sequence_number": _next_seq(),
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "0",
        "retractable_id": entry.retractable_id.hex(),
    }, SK_ALICE)
    sender_policy.set_evaluator("admission", _Exploding())
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: _BLOCK_ALL_BODY})):
        res = _queue(retract)
    assert res["ok"] is True, res
    assert _mempool_hashes(), "the retract is queued"


def test_76_a_refused_park_costs_nothing_at_admission(active, node):
    """A refusal at admission queues nothing and moves no funds."""
    body = _cap_seconds_body(600)
    _evaluator("admission", body, _cap_seconds_decide(600))
    before = chain_state.get_balance(SENDER)
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        res = _queue(_park_payload(release_at_time=TIP_TS + 3600))
    assert res["ok"] is False and res["code"] == "RECIPIENT_MAX_HOLD"
    assert _mempool_hashes() == []
    assert chain_state.get_balance(SENDER) == before


# --- apply --------------------------------------------------------------------

def _register(ch, pubkey, body):
    ch.lm.rule_offers.accepted_clauses[(pubkey, 5)] = body


def _reason(result, tx):
    (outcome,) = [o for o in result.outcomes if o.tx_id == tx["tx_id"]]
    return outcome.reason


def _batch_tx(outputs, seq=0):
    tx = {
        "tx_id": f"batch-{next(rp._TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": rp.ALICE,
        "sequence_number": seq,
        "expiration_time": rp.FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "operations": {"1": [[rp.ALICE, to, amount] for to, amount in outputs]},
    }
    return rp._sign(tx, rp.SK_ALICE)


def test_47_1_apply_blocks_an_unlisted_sender(active):
    """#47 case 1 at apply: the recipient's allow-list refuses with a distinct
    receipt reason, and no funds move."""
    ch = rp.Chain(rp._balances())
    body = _allow_list_body(rp.CAROL)
    _register(ch, rp.BOB, body)
    ev = _evaluator("apply", body, _allow_list_decide(rp.CAROL))
    tx = rp.spend_tx(rp.ALICE, rp.BOB, 100, seq=0)
    result = ch.block([tx])
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == "recipient_policy_block"
    assert "recipient's policy clause" in rp._logs(result)
    assert ch.bal[rp.ALICE] == 10_000 and ch.bal[rp.BOB] == 0
    _body, inputs = ev.verdict_calls[-1]
    assert inputs["i3"] == "#x" + rp.ALICE and inputs["i1"] == "100"


def test_47_1_apply_allows_a_listed_sender(active):
    ch = rp.Chain(rp._balances())
    body = _allow_list_body(rp.ALICE)
    _register(ch, rp.BOB, body)
    _evaluator("apply", body, _allow_list_decide(rp.ALICE))
    tx = rp.spend_tx(rp.ALICE, rp.BOB, 100, seq=0)
    result = ch.block([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ch.bal[rp.BOB] == 100


def test_47_2_apply_without_a_recipient_clause_allows(active):
    ch = rp.Chain(rp._balances())
    sender_policy.set_evaluator("apply", _Exploding())
    tx = rp.spend_tx(rp.ALICE, rp.BOB, 100, seq=0)
    result = ch.block([tx])
    assert tx["tx_id"] in result.accepted_tx_ids


def test_47_3_apply_batch_one_refused_output_fails_the_tx(active):
    """#47 case 3 at apply: atomic -- the first output is not credited when
    the second recipient refuses."""
    ch = rp.Chain(rp._balances())
    allow_body = _allow_list_body(rp.ALICE)
    block_body = _allow_list_body(rp.CAROL)
    _register(ch, rp.BOB, allow_body)
    _register(ch, rp.CAROL, block_body)
    ev = MockPolicyEvaluator(pool="apply")
    ev.set_verdict(allow_body, _allow_list_decide(rp.ALICE))
    ev.set_verdict(block_body, _allow_list_decide(rp.CAROL))
    sender_policy.set_evaluator("apply", ev)
    tx = _batch_tx([(rp.BOB, 100), (rp.CAROL, 100)])
    result = ch.block([tx])
    assert tx["tx_id"] in result.invalid_tx_ids
    assert _reason(result, tx) == "recipient_policy_block"
    assert ch.bal[rp.BOB] == 0 and ch.bal[rp.CAROL] == 0
    assert ch.bal[rp.ALICE] == 10_000


def test_47_4_apply_an_outbound_only_clause_does_not_block_inbound(active):
    """#47 case 4 at apply: one unit judges both directions."""
    ch = rp.Chain(rp._balances())
    body = _outbound_only_body(rp.BOB)
    _register(ch, rp.BOB, body)
    ev = _evaluator("apply", body, _outbound_only_decide_for(rp.BOB))
    tx = rp.spend_tx(rp.ALICE, rp.BOB, 5000, seq=0)
    result = ch.block([tx])
    assert tx["tx_id"] in result.accepted_tx_ids
    assert ch.bal[rp.BOB] == 5000
    _body, inputs = ev.verdict_calls[-1]
    assert inputs["i3"] == "#x" + rp.ALICE


def test_47_apply_is_inert_while_inactive():
    ch = rp.Chain(rp._balances())
    _register(ch, rp.BOB, _BLOCK_ALL_BODY)
    sender_policy.set_evaluator("apply", _Exploding())
    tx = rp.spend_tx(rp.ALICE, rp.BOB, 100, seq=0)
    # Pinned off explicitly: the test is about the inactive behaviour, not
    # about the module default.
    with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
        result = ch.block([tx])
    assert tx["tx_id"] in result.accepted_tx_ids


def test_47_apply_an_approval_vote_execution_skips_the_recipient_gate(active):
    """The gate applies at park time, not when a vote executes an already
    parked transfer: a recipient clause tightened after parking must not
    strand an approved transfer."""
    req = ap._request()
    lm = ap._lm()
    lm.rule_offers.accepted_clauses[(ap.BOB, 5)] = _BLOCK_ALL_BODY
    sender_policy.set_evaluator("apply", _Exploding())
    result, post, _ = ap._apply([ap.request_tx(req), ap.vote_tx(req)], lm=lm)
    assert post.approval_requests.terminal_status[req.request_id] == ap.STATUS_EXECUTED
    assert "Parked transfer executed" in ap._logs(result)
    assert ap._balances(result)[ap.BOB] == req.amount


def test_76_1_apply_cap_zero_admits_plain_and_refuses_every_park(active):
    """#76 case 1 at apply: cap 0 admits a plain transfer and refuses a park
    with the cap in the receipt."""
    ch = rp.Chain(rp._balances())
    _register(ch, rp.BOB, _CAP_ZERO_BODY)
    _evaluator("apply", _CAP_ZERO_BODY, _cap_zero_decide)
    spend = rp.spend_tx(rp.ALICE, rp.BOB, 100, seq=0)
    result = ch.block([spend])
    assert spend["tx_id"] in result.accepted_tx_ids
    park = rp.park_tx(at_time=rp.TS + 600, seq=1)
    result = ch.block([park])
    assert park["tx_id"] in result.invalid_tx_ids
    assert _reason(result, park) == "recipient_max_hold"
    assert "(0 seconds; hold 600 seconds)" in rp._logs(result)
    assert ch.book.open_count() == 0
    assert ch.bal[rp.ALICE] == 10_000 - 100


def test_76_2_apply_cap_600_admits_ten_minutes_and_refuses_an_hour(active):
    """#76 case 2 at apply."""
    ch = rp.Chain(rp._balances())
    body = _cap_seconds_body(600)
    _register(ch, rp.BOB, body)
    _evaluator("apply", body, _cap_seconds_decide(600))
    short = rp.park_tx(at_time=rp.TS + 600, seq=0)
    result = ch.block([short])
    assert short["tx_id"] in result.accepted_tx_ids
    assert ch.book.escrow_total() == 100
    long = rp.park_tx(at_time=rp.TS + 3600, seq=1)
    result = ch.block([long])
    assert long["tx_id"] in result.invalid_tx_ids
    assert _reason(result, long) == "recipient_max_hold"
    assert "(600 seconds; hold 3600 seconds)" in rp._logs(result)
    assert ch.book.open_count() == 1, "only the short park is open"


def test_76_2_apply_height_parks_are_capped_in_blocks(active):
    ch = rp.Chain(rp._balances())
    body = _cap_blocks_body(100)
    _register(ch, rp.BOB, body)
    _evaluator("apply", body, _cap_blocks_decide(100))
    short = rp.park_tx(at_height=rp.HEIGHT + 50, seq=0)
    result = ch.block([short])
    assert short["tx_id"] in result.accepted_tx_ids
    long = rp.park_tx(at_height=rp.HEIGHT + 200, seq=1)
    result = ch.block([long])
    assert long["tx_id"] in result.invalid_tx_ids
    assert _reason(result, long) == "recipient_max_hold"
    assert "(100 blocks; hold 200 blocks)" in rp._logs(result)


def test_76_2_apply_hold_equals_cap_passes_and_cap_plus_one_refuses(active):
    ch = rp.Chain(rp._balances())
    body = _cap_seconds_body(600)
    _register(ch, rp.BOB, body)
    _evaluator("apply", body, _cap_seconds_decide(600))
    exact = rp.park_tx(at_time=rp.TS + 600, seq=0)
    result = ch.block([exact])
    assert exact["tx_id"] in result.accepted_tx_ids
    over = rp.park_tx(at_time=rp.TS + 601, seq=1)
    result = ch.block([over])
    assert over["tx_id"] in result.invalid_tx_ids
    assert _reason(result, over) == "recipient_max_hold"


def test_76_3_apply_no_policy_passes_parks_of_any_length(active):
    """#76 case 3 at apply."""
    ch = rp.Chain(rp._balances())
    sender_policy.set_evaluator("apply", _Exploding())
    hour = rp.park_tx(at_time=rp.TS + 3600, seq=0)
    result = ch.block([hour])
    assert hour["tx_id"] in result.accepted_tx_ids
    far = rp.park_tx(at_height=rp.HEIGHT + 100_000, seq=1)
    result = ch.block([far])
    assert far["tx_id"] in result.accepted_tx_ids
    assert ch.book.open_count() == 2


def test_76_4_apply_a_retract_is_never_gated(active):
    """#76 case 4 at apply: a retract never touches the transfer executor, so
    the recipient's clause cannot stop it."""
    ch = rp.Chain(rp._balances())
    park = rp.park_tx()
    ch.block([park])
    assert ch.book.open_count() == 1
    _register(ch, rp.BOB, _BLOCK_ALL_BODY)
    sender_policy.set_evaluator("apply", _Exploding())
    retract = rp.retract_tx(rp.rid_of(park), seq=1)
    result = ch.block([retract])
    assert retract["tx_id"] in result.accepted_tx_ids
    assert ch.bal[rp.ALICE] == 10_000, "the escrow is refunded"
    assert ch.book.open_count() == 0


def test_76_4_apply_a_release_is_never_rechecked(active):
    """#76 case 4 at apply: the release sweep is a plain credit; a recipient
    clause tightened after parking does not block it."""
    ch = rp.Chain(rp._balances())
    park = rp.park_tx(at_height=rp.HEIGHT + 10)
    ch.block([park])
    assert ch.book.open_count() == 1
    _register(ch, rp.BOB, _BLOCK_ALL_BODY)
    sender_policy.set_evaluator("apply", _Exploding())
    result = ch.block([], height=rp.HEIGHT + 10)
    assert result is not None
    assert ch.bal[rp.BOB] == 100, "the release pays the recipient"
    assert ch.book.open_count() == 0


def test_76_a_refused_park_pays_no_fee_at_apply(active):
    """A hard reject at apply charges no fee and moves no funds."""
    ch = rp.Chain(rp._balances(), fee=10)
    body = _cap_seconds_body(600)
    _register(ch, rp.BOB, body)
    _evaluator("apply", body, _cap_seconds_decide(600))
    park = rp.park_tx(at_time=rp.TS + 3600)
    result = ch.block([park])
    assert park["tx_id"] in result.invalid_tx_ids
    assert _reason(result, park) == "recipient_max_hold"
    assert ch.bal[rp.ALICE] == 10_000, "a refused park pays no fee"
    assert ch.bal[rp.PROPOSER] == 0
    assert ch.book.escrow_total() == 0


# --- admission/apply parity ---------------------------------------------------

def test_admission_and_apply_agree_on_the_cap(active, node):
    """Parity: the same park and the same recipient clause report the same
    cap on both paths -- admission in RECIPIENT_MAX_HOLD details, apply in
    the receipt log."""
    body = _cap_seconds_body(600)
    _evaluator("admission", body, _cap_seconds_decide(600))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        res = _queue(_park_payload(release_at_time=TIP_TS + 3600))
    assert res["ok"] is False and res["code"] == "RECIPIENT_MAX_HOLD"
    assert res["details"]["max_hold_seconds"] == 600
    assert res["details"]["hold_seconds"] == 3600

    ch = rp.Chain(rp._balances())
    _register(ch, rp.BOB, body)
    _evaluator("apply", body, _cap_seconds_decide(600))
    park = rp.park_tx(at_time=rp.TS + 3600)
    result = ch.block([park])
    assert park["tx_id"] in result.invalid_tx_ids
    assert _reason(result, park) == "recipient_max_hold"
    assert "(600 seconds; hold 3600 seconds)" in rp._logs(result)


# --- checktx --------------------------------------------------------------------

class _EstimateSession:
    """A worker that answers every step with the transfer echo and no fee."""

    def __init__(self, script):
        self.script = script

    def evaluate(self, inputs, *, multi, record):
        self.script["steps"].append(dict(inputs))
        return {1: str(inputs.get(1, "0")), 5: "1", 8: "0", 9: "0"}

    def apply_rule(self, rule_text, *, target, record):
        self.script["revisions"].append(rule_text)

    def last_receipt(self):
        return {"accepted": True, "outcome": "ACCEPTED_CHANGED"}

    def dispose(self):
        self.script["disposed"] += 1


class _EstimateStandby:
    enabled = True

    def take(self, **kwargs):
        return None

    def refill(self, **kwargs):
        pass


@pytest.fixture
def estimate_node(temp_database, mock_policy_evaluators, monkeypatch):
    """Worker-backed admission with a fake worker, so checktx estimate runs.

    An estimate needs an isolated admission context (sendtx refuses it
    otherwise), so this mirrors the fixture in tests/test_checktx_estimate.py:
    tau_admission.enabled() is true, contexts are built from a fake session,
    and the in-process evaluator is wired to explode if it is ever used.
    """
    script = {"steps": [], "revisions": [], "built": 0, "disposed": 0}

    def build(**kwargs):
        script["built"] += 1
        return _EstimateSession(script), {"journal_head": "h", "journal_sequence": 0,
                                          "epoch": 0, "high_water": 0}, None

    patches = [
        patch("tau_admission.enabled", return_value=True),
        patch("tau_admission._build", side_effect=build),
        patch("tau_admission._standby", _EstimateStandby()),
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
    ]
    mocks = [p.start() for p in patches]
    mocks[3].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    yield script
    for p in reversed(patches):
        p.stop()


def _estimate(payload):
    return json.loads(checktx.execute("checktx estimate " + json.dumps(payload), None))


def _check_plain(payload):
    return json.loads(checktx.execute("checktx " + json.dumps(payload), None))


def test_47_5_checktx_estimate_surfaces_a_recipient_refusal(active, estimate_node):
    """#47 case 5: a recipient-policy refusal surfaces through checktx
    estimate with the same code and details as sendtx."""
    body = _allow_list_body(THIRD)
    _evaluator("admission", body, _allow_list_decide(THIRD))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        env = _estimate(_transfer_payload([RECIPIENT]))
    assert env["status"] == "error", env
    assert env["error"]["code"] == "RECIPIENT_POLICY_BLOCK"
    assert env["error"]["details"]["transfer_index"] == 1
    assert env["error"]["details"]["recipient_policy_active"] is True
    assert env["error"]["details"]["tau_evaluated"] is True
    assert _mempool_hashes() == []


def test_76_5_checktx_estimate_surfaces_the_cap(active, estimate_node):
    """#76 case 5: the cap travels with the checktx refusal."""
    body = _cap_seconds_body(600)
    _evaluator("admission", body, _cap_seconds_decide(600))
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: body})):
        env = _estimate(_park_payload(release_at_time=TIP_TS + 3600))
    assert env["status"] == "error", env
    assert env["error"]["code"] == "RECIPIENT_MAX_HOLD"
    assert env["error"]["details"]["max_hold_seconds"] == 600
    assert env["error"]["details"]["hold_seconds"] == 3600
    assert env["error"]["details"]["recipient_policy_active"] is True


def test_47_5_checktx_reports_whether_recipient_policy_is_active(active, estimate_node):
    """#47 case 5: a wallet can tell 'the recipient has no cap' from 'this
    node does not enforce one' without submitting anything."""
    sender_policy.set_evaluator("admission", _Exploding())
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({})):
        env = _estimate(_transfer_payload([RECIPIENT]))
    assert env["status"] == "ok", env
    assert env["data"]["recipient_policy_active"] is True
    assert env["data"]["admissible"] is True


def test_47_5_checktx_reports_an_inactive_node(estimate_node):
    sender_policy.set_evaluator("admission", _Exploding())
    # Pinned off explicitly: the test is about the inactive behaviour, not
    # about the module default.
    with patch.object(tau_defs, "RECIPIENT_POLICY_ACTIVE", False):
        with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: _BLOCK_ALL_BODY})):
            env = _estimate(_transfer_payload([RECIPIENT]))
    assert env["status"] == "ok", env
    assert env["data"]["recipient_policy_active"] is False


def test_47_5_the_plain_checktx_form_reports_the_flag_without_a_verdict(active, node):
    """The plain form runs no Tau step, so it gives no policy verdict -- but
    the capability flag is still reported."""
    with patch(ADMISSION_CLAUSE_VIEW, side_effect=_clauses({RECIPIENT: _BLOCK_ALL_BODY})):
        env = _check_plain(_transfer_payload([RECIPIENT]))
    assert env["status"] == "ok", env
    assert env["data"]["admissible"] is None
    assert env["data"]["tau_evaluated"] is False
    assert env["data"]["recipient_policy_active"] is True
