"""Bounty 01, FIX 10 (stage 2, S-3): the deciding-rule form of a
standing payment, at book level.

Stage 1 (FIX 2) split the work as: the clause decides WHAT a due
execution pays (its legs), the book's Python decides WHEN and WHETHER
(due, window, settled, catch-up, capacity). The audit of 2026-11-24
(AUDIT-178-DUE-FIX8, S-3) named that split the andrei-axis gap against
#178/#160, whose rules decide in the rule itself.

This file pins the stage-2 answer: FORM_TAU_DECIDING_RULE (3). The
clause is stepped over the stage-1 map PLUS the book's derived facts
(i27..i36: current period, window open, settleable count, next due,
missed count, capacity, retry state, cancelled, due-unsettled count)
and reports a verdict (o29) and a period count (o28) with its legs.
The clause decides; the book enforces — the named periods against the
same facts it published, the legs through the one cap enforcer both
clause forms share. Covered: parse/validate and the id domain (a
stage-2 rule over a stage-1 clause's text is a different
authorization); the verdict as the decision of record (executes /
declines / absent); the period count as the clause's choice (catch-up
elects one of two settleable periods, then both); the facts map's
values across a scripted life; every cap still binding under a
willing verdict; cancellation and end conditions as state integrity
a verdict cannot override; the retry/discovery paths deciding by
verdict; restore round-trip; the approvals payload binding the
clause; the capability record.
"""
import pytest

from consensus.approvals import standing_payload_entry, standing_payload_text
from consensus.serialization import compute_standing_payment_rule_id
from consensus.standing_payments import (
    FORM_DECLARED,
    FORM_TAU_CLAUSE,
    FORM_TAU_DECIDING_RULE,
    INSUFFICIENT_FUNDS_REASON_PREFIX,
    SCHEDULE_DAILY,
    StandingPaymentBook,
    StandingPaymentEntry,
    StandingPaymentShapeError,
    parse_create_standing_payment,
    standing_payment_capabilities,
    validate_standing_payment_shape,
)

PAYER = "aa" * 48
RECIPIENT = "bb" * 48
OTHER = "dd" * 48
DAY = 86_400
TS = 1_800_000_000
RETRY_WEEK = 7 * DAY

CLAUSE = (
    "((o29[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o28[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 500 }:bv[64]))"
)

LEGS = ((RECIPIENT, 500),)


def _rule_entry(**kw):
    fields = dict(
        payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=500,
        schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=TS,
        window_seconds=3600, final_ts=0, max_occurrences=0,
        max_total=100_000, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1,
        form=FORM_TAU_DECIDING_RULE, clause_text=CLAUSE,
    )
    fields.update(kw)
    return StandingPaymentEntry(**fields)


def _installed(**kw):
    book = StandingPaymentBook()
    entry = _rule_entry(**kw)
    book.create(entry, TS - 100)
    return book, entry


def _tx(**kw):
    tx = dict(
        sender_pubkey=PAYER,
        standing_recipient_pubkey=RECIPIENT,
        standing_amount=500,
        standing_schedule="daily",
        standing_signed_day=0,
        standing_anchor_ts=TS,
        standing_window_seconds=3600,
        standing_final_ts=0,
        standing_max_occurrences=0,
        standing_max_total=100_000,
        standing_fee_limit=0,
        standing_policy_version_ref=0,
        standing_allow_catch_up=0,
        standing_version=1,
        standing_form=FORM_TAU_DECIDING_RULE,
        standing_clause=CLAUSE,
    )
    tx.update(kw)
    return tx


# --- Form selection: parse, validate, identity ---------------------------------


def test_parse_reads_the_deciding_form():
    entry = parse_create_standing_payment(_tx())
    assert entry.form == FORM_TAU_DECIDING_RULE
    assert entry.clause_text == CLAUSE
    assert validate_standing_payment_shape(entry, TS - 100) is None


def test_parse_refuses_a_clause_on_the_declared_form():
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment(_tx(standing_form=FORM_DECLARED))


def test_deciding_form_without_a_clause_is_refused():
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment(_tx(standing_clause=""))
    entry = _rule_entry(clause_text="")
    assert validate_standing_payment_shape(entry, TS - 100) is not None


def test_the_deciding_id_is_its_own_domain():
    entry = _rule_entry()
    expected = compute_standing_payment_rule_id(
        PAYER, RECIPIENT, 500, SCHEDULE_DAILY, 0, TS, 3600, 0, 0,
        100_000, 0, 0, 0, CLAUSE, 1, 0,
    )
    assert entry.auth_id == expected
    # The same terms and the same clause text under the stage-1 form
    # are a different authorization: who decides is signed.
    stage1 = _rule_entry(form=FORM_TAU_CLAUSE)
    assert stage1.auth_id != entry.auth_id


def test_the_approvals_payload_binds_the_clause():
    entry = _rule_entry()
    body = standing_payload_text(entry)
    assert '"standing_form":3' in body.replace(" ", "")
    assert "standing_clause" in body
    assert standing_payload_entry(body, PAYER) == entry


# --- The verdict is the decision of record --------------------------------------


def test_a_willing_verdict_executes_and_records_the_fact():
    book, entry = _installed()
    decision = book.execute(
        entry.auth_id, TS + 10, 1000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert decision.executed and decision.amount == 500
    fact = book.paid_for_period(entry.auth_id, 0)
    assert fact is not None and fact.amount == 500


def test_no_verdict_no_payment():
    book, entry = _installed()
    decision = book.execute(
        entry.auth_id, TS + 10, 1000,
        clause_legs=LEGS, clause_verdict=None, clause_periods=1,
    )
    assert not decision.executed
    assert "was not evaluated" in decision.reason
    assert book.paid_for_period(entry.auth_id, 0) is None


def test_a_declining_verdict_is_the_decision():
    book, entry = _installed()
    for verdict in (0, 2):
        decision = book.execute(
            entry.auth_id, TS + 10, 1000,
            clause_legs=LEGS, clause_verdict=verdict, clause_periods=1,
        )
        assert not decision.executed
        assert "declined" in decision.reason
    assert book.total_executed(entry.auth_id) == (0, 0)


def test_a_verdict_without_a_period_count_decides_nothing():
    book, entry = _installed()
    decision = book.execute(
        entry.auth_id, TS + 10, 1000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=None,
    )
    assert not decision.executed
    assert "did not report how many periods" in decision.reason
    decision = book.execute(
        entry.auth_id, TS + 10, 1000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=0,
    )
    assert not decision.executed
    assert "named no periods" in decision.reason


def test_the_rule_cannot_name_periods_the_terms_do_not_offer():
    book, entry = _installed()
    # Only period 0 is settleable at TS+10 (no catch-up signed).
    decision = book.execute(
        entry.auth_id, TS + 10, 1000,
        clause_legs=((RECIPIENT, 1000),), clause_verdict=1, clause_periods=2,
    )
    assert not decision.executed
    assert "more periods than the signed terms let settle" in decision.reason


def test_the_period_count_is_the_clauses_choice_under_catch_up():
    book, entry = _installed(allow_catch_up=True)
    first = book.execute(
        entry.auth_id, TS + 10, 5000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert first.executed and first.periods_collected == 1
    # Two periods are now due and unsettled (1 and 2); the rule elects
    # to settle ONE — the oldest — and the book settles exactly that.
    ts2 = TS + 2 * DAY + 10
    facts = book.rule_facts(entry.auth_id, ts2)
    assert facts.settleable_periods == (1, 2)
    one = book.execute(
        entry.auth_id, ts2, 5000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert one.executed and one.periods_collected == 1
    assert book.paid_for_period(entry.auth_id, 1) is not None
    assert book.paid_for_period(entry.auth_id, 2) is None
    # A second election of one settles the remaining period.
    last = book.execute(
        entry.auth_id, ts2, 5000,
        clause_legs=((RECIPIENT, 500),), clause_verdict=1, clause_periods=1,
    )
    assert last.executed
    assert book.paid_for_period(entry.auth_id, 2) is not None


# --- The facts the clause reads ---------------------------------------------------


def test_the_facts_map_tracks_the_rules_life():
    book, entry = _installed()
    before = book.clause_inputs_for(entry, "", TS - 10, 1000)
    assert before[27] == "0" and before[28] == "0" and before[29] == "0"
    assert before[30] == str(TS)  # the first due date is next
    due = book.clause_inputs_for(entry, "", TS + 10, 1000)
    assert due[1] == "500" and due[26] == "0"  # the stage-1 streams, verbatim
    assert due[27] == "1" and due[28] == "1" and due[29] == "1"
    assert due[30] == str(TS + DAY) and due[31] == "0" and due[33] == "0"
    assert due[35] == "0" and due[36] == "1"
    book.execute(
        entry.auth_id, TS + 10, 1000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    after = book.clause_inputs_for(entry, "", TS + 20, 500)
    assert after[26] == "500" and after[33] == "500"
    assert after[29] == "0" and after[36] == "0"
    # The window lapses unsettled on a fresh rule: the fact says so,
    # and a verdict that ignores it settles nothing.
    book2, entry2 = _installed()
    lapsed = book2.clause_inputs_for(entry2, "", TS + 7200, 1000)
    assert lapsed[28] == "0" and lapsed[29] == "0" and lapsed[31] == "1"
    decision = book2.execute(
        entry2.auth_id, TS + 7200, 1000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert not decision.executed


def test_the_stage1_map_is_unchanged_for_the_stage1_form():
    book = StandingPaymentBook()
    entry = _rule_entry(form=FORM_TAU_CLAUSE)
    book.create(entry, TS - 100)
    inputs = book.clause_inputs_for(entry, "", TS + 10, 1000)
    assert 27 not in inputs and inputs[26] == "0"


# --- Enforcement: a willing verdict cannot break a signed cap ---------------------


def test_caps_bind_under_a_willing_verdict():
    book, entry = _installed()
    over = book.execute(
        entry.auth_id, TS + 10, 5000,
        clause_legs=((RECIPIENT, 501),), clause_verdict=1, clause_periods=1,
    )
    assert not over.executed and "per-execution cap" in over.reason
    outside = book.execute(
        entry.auth_id, TS + 10, 5000,
        clause_legs=((OTHER, 500),), clause_verdict=1, clause_periods=1,
    )
    assert not outside.executed and "outside the declared set" in outside.reason
    short = book.execute(
        entry.auth_id, TS + 10, 300,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert not short.executed
    assert short.reason.startswith(INSUFFICIENT_FUNDS_REASON_PREFIX)


def test_max_total_and_capacity_bind_under_a_willing_verdict():
    book, entry = _installed(max_total=700)
    assert book.execute(
        entry.auth_id, TS + 10, 5000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    ).executed
    second = book.execute(
        entry.auth_id, TS + DAY + 10, 5000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert not second.executed and "end condition" in second.reason

    book2, entry2 = _installed(max_occurrences=1)
    assert book2.execute(
        entry2.auth_id, TS + 10, 5000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    ).executed
    capped = book2.execute(
        entry2.auth_id, TS + DAY + 10, 5000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert not capped.executed and "end condition" in capped.reason


def test_a_verdict_cannot_revive_a_cancelled_rule():
    book, entry = _installed()
    book.cancel(entry.auth_id, TS + 5)
    decision = book.execute(
        entry.auth_id, TS + 10, 5000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert not decision.executed and "cancelled" in decision.reason
    facts = book.rule_facts(entry.auth_id, TS + 10)
    assert facts.cancelled  # the clause could see it; it changes nothing


# --- Discovery and retry decide by verdict too -------------------------------------


def _retry_book():
    book, entry = _installed(due_retry_seconds=RETRY_WEEK)
    return book, entry


def test_discovery_decides_by_verdict():
    book, entry = _retry_book()
    short = book.discovery_decision(
        entry.auth_id, 0, TS + 50, 300,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert not short.executed
    assert short.reason.startswith(INSUFFICIENT_FUNDS_REASON_PREFIX)
    declined = book.discovery_decision(
        entry.auth_id, 0, TS + 50, 300,
        clause_legs=LEGS, clause_verdict=0,
    )
    assert not declined.executed and "declined" in declined.reason
    payable = book.discovery_decision(
        entry.auth_id, 0, TS + 50, 1000,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert payable.executed


def test_an_owed_retry_runs_on_the_rules_verdict():
    book, entry = _retry_book()
    book.note_retry_owed(entry.auth_id, 0, TS + 10, 1)
    retry = book.owed_retries()[0]
    declined = book.execute_retry(
        retry, TS + 100, 1000, clause_legs=LEGS, clause_verdict=0,
    )
    assert not declined.executed and "declined" in declined.reason
    assert book.paid_for_period(entry.auth_id, 0) is None
    paid = book.execute_retry(
        retry, TS + 100, 1000, clause_legs=LEGS, clause_verdict=1,
    )
    assert paid.executed and paid.amount == 500
    facts = book.rule_facts(entry.auth_id, TS + 100)
    assert facts.retry_state == 0  # settled: nothing owed any more


def test_the_discovery_step_reads_the_candidate_as_a_live_retry():
    # At a discovery step nothing is owed yet (i34 = 0 on the plain
    # map), but the run being decided IS the candidate period's retry
    # run: stepped for that period, the fact reads 1 while the period
    # is due, unpaid and inside its retry window.
    book, entry = _retry_book()
    plain = book.clause_inputs_for(entry, "", TS + 50, 300)
    assert plain[34] == "0"
    stepped = book.clause_inputs_for(
        entry, "", TS + 50, 300, retry_period=0)
    assert stepped[34] == "1"


def test_retry_candidates_include_the_deciding_form():
    book, entry = _retry_book()
    candidates = book.retry_candidates(TS + 50)
    assert (entry, 0) in candidates


# --- Restore ------------------------------------------------------------------------


def test_restore_round_trips_a_deciding_rule():
    book, entry = _installed()
    book.execute(
        entry.auth_id, TS + 10, 1000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    restored = StandingPaymentBook.restore(
        book.rows(), book.fact_rows(), book.retry_rows()
    )
    assert restored.root() == book.root()
    again = restored.execute(
        entry.auth_id, TS + DAY + 10, 1000,
        clause_legs=LEGS, clause_verdict=1, clause_periods=1,
    )
    assert again.executed


def test_capabilities_report_the_deciding_form():
    caps = standing_payment_capabilities()
    assert caps["forms"]["tau_deciding_rule"] == FORM_TAU_DECIDING_RULE
    deciding = caps["deciding_rule_form"]
    assert "o29" in deciding["verdict_stream"]
    assert "o28" in deciding["periods_stream"]
    assert deciding["fact_streams"]["i29"]
