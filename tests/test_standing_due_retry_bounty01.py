"""Bounty 01, FIX 5 (due_retry): a signed retry term in clause form, at
book level.

The competitor's #160 commit 7722a42 ("Payout rules: several rules per
account, and a due point tried again (#63)") adds a signed `due_retry`
term: a due point refused because the account holds less than the rule
pays is run again in each later block, at most 4 a block, longest
waiting first, until it pays / its window closes / the next due point
comes / the rule ends. Only a run refused for insufficient balance is
tried again; a run the rule answers 0, or one a cap refuses, is not.

This file pins FIX 5's answer to that term, in clause form, on the
standing-payment book — the contested structure (due points, one
execution window per period, rule end) already lives there; the
payout-rule book has no due points. The multi-rule-per-account half
of #160 (8 places, signed rule_index) is NOT implemented here — an
explicit bound, recorded in FIX5-CLAUSE-GRANTS-LOG.md.

Covered: the byte-for-byte pin (a clause-form entry carrying a retry
term: its id, record bytes and book root; a retry owed moves the root
and dropping it returns the root exactly — the root is gated, the
retries section appears only while a retry is owed); shape bounds
(1 second..366 days, clause form only — the declared form refuses a
non-zero term); note idempotence and longest-waiting-first ordering;
execute_retry paying / staying short / ending on window close /
next due point / rule end; a tx execution settling the period clears
the retry; cancel and supersede drop retries; discovery_decision
(would-pay / short / cap refusal / window closed / next due point);
retry_candidates; restore round-trips with retries; the capability
record.
"""
import pytest

from consensus.serialization import (
    compute_standing_payment_book_root,
    compute_standing_payment_tau_id,
    encode_standing_payment_record,
)
from consensus.standing_payments import (
    FORM_DECLARED,
    FORM_TAU_CLAUSE,
    INSUFFICIENT_FUNDS_REASON_PREFIX,
    MAX_DUE_RETRIES_PER_BLOCK,
    MAX_DUE_RETRY_SECONDS,
    SCHEDULE_DAILY,
    StandingDueRetry,
    StandingPaymentBook,
    StandingPaymentEntry,
    StandingPaymentShapeError,
    decode_clause_legs,
    due_ts,
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
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 200 }:bv[64]))"
)

# Pins for the canonical retry entry below, measured on this tree.
# The record's trailing field is the retry term (604800 = 7 days).
GOLDEN_RETRY_AUTH_ID = (
    "2d6a51d336b1b2fafe96a1b8387b27d6283e140c5b3971ddced0415c7a2d975f"
)
GOLDEN_RETRY_ROOT_UNSETTLED = (
    "c3e0225c148f191e7530508374f3401d8b8c2ac6fb70a6240cb9a6c5a0549d62"
)
GOLDEN_RETRY_ROOT_WITH_RETRY = (
    "48508bec2754130c97df79ca276dc7584537ddeb89a04756c4ae2503a23c4b8e"
)
GOLDEN_RETRY_ROOT_SETTLED = (
    "5949e1bd73ab55966c02d8340d124d840bc4928599f2c4fa1926b48fbabdec17"
)
GOLDEN_RETRY_RECORD = (
    "2d6a51d336b1b2fafe96a1b8387b27d6283e140c5b3971ddced0415c7a2d975f"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    "00000000000001f4" "0000000000000001" "0000000000000000"
    "000000006b49d19c" "0000000000000e10" "0000000000000000"
    "0000000000000000" "00000000000186a0" "0000000000000000"
    "0000000000000000" "0000000000000000" "0000000000000001"
    "00000000" "0000000000000000"
    "0000000000000000" "0000000000000000" "0000000000000000"
    "0000000000000002"
    "0000006628286f33305b745d3a62765b36345d203d207b2031207d3a62765b36345d29"
    "20262620286f33315b745d3a62765b36345d203d207b2030207d3a62765b36345d29"
    "20262620286f33325b745d3a62765b36345d203d207b20323030207d3a62765b36345d2929"
    "0000000000093a80"
)


def _retry_entry(**kw):
    fields = dict(
        payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=500,
        schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=TS - 100,
        window_seconds=3600, final_ts=0, max_occurrences=0,
        max_total=100_000, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1,
        form=FORM_TAU_CLAUSE, clause_text=CLAUSE,
        due_retry_seconds=RETRY_WEEK,
    )
    fields.update(kw)
    return StandingPaymentEntry(**fields)


def _declared_entry(**kw):
    fields = dict(
        payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=500,
        schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=TS - 100,
        window_seconds=3600, final_ts=0, max_occurrences=0,
        max_total=100_000, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1,
    )
    fields.update(kw)
    return StandingPaymentEntry(**fields)


def _book_with(entry, ts=None):
    book = StandingPaymentBook()
    book.create(entry, ts if ts is not None else entry.anchor_ts)
    return book


# --- the byte-for-byte pin ------------------------------------------------------


def test_retry_entry_id_record_and_roots_pinned():
    entry = _retry_entry()
    assert entry.auth_id.hex() == GOLDEN_RETRY_AUTH_ID
    assert compute_standing_payment_tau_id(
        PAYER, RECIPIENT, 500, SCHEDULE_DAILY, 0, TS - 100, 3600, 0, 0,
        100_000, 0, 0, False, CLAUSE, 1,
        due_retry_seconds=RETRY_WEEK,
    ).hex() == GOLDEN_RETRY_AUTH_ID
    book = _book_with(entry)
    assert book.root().hex() == GOLDEN_RETRY_ROOT_UNSETTLED
    assert encode_standing_payment_record(*book.rows()[0]).hex() == (
        GOLDEN_RETRY_RECORD
    )
    # The retry term is covered by the id and the record: zeroing it
    # moves both.
    assert _retry_entry(due_retry_seconds=0).auth_id.hex() != (
        GOLDEN_RETRY_AUTH_ID
    )


def test_retry_owed_moves_the_root_and_dropping_restores_it():
    entry = _retry_entry()
    book = _book_with(entry)
    assert book.note_retry_owed(entry.auth_id, 0, TS, 20)
    assert book.root().hex() == GOLDEN_RETRY_ROOT_WITH_RETRY
    assert book.drop_retry(entry.auth_id, 0)
    # The retries section appears only while a retry is owed: a book
    # with no retry roots exactly as before.
    assert book.root().hex() == GOLDEN_RETRY_ROOT_UNSETTLED
    assert not book.drop_retry(entry.auth_id, 0)


def test_no_retry_means_no_retries_section_in_the_root():
    entry = _retry_entry()
    book = _book_with(entry)
    rows, facts = book.rows(), book.fact_rows()
    assert book.root() == compute_standing_payment_book_root(rows, facts)
    assert book.root() == compute_standing_payment_book_root(
        rows, facts, retries=()
    )


# --- shape bounds ----------------------------------------------------------------


def test_shape_bounds_for_the_retry_term():
    # The shape check returns None when fine, a problem string when not.
    assert validate_standing_payment_shape(_retry_entry(), TS) is None
    assert validate_standing_payment_shape(
        _retry_entry(due_retry_seconds=1), TS) is None
    assert validate_standing_payment_shape(
        _retry_entry(due_retry_seconds=MAX_DUE_RETRY_SECONDS), TS) is None
    assert validate_standing_payment_shape(
        _retry_entry(due_retry_seconds=MAX_DUE_RETRY_SECONDS + 1), TS
    ) is not None
    assert validate_standing_payment_shape(
        _retry_entry(due_retry_seconds=-1), TS) is not None
    # The declared form refuses a non-zero term, mirroring grants'
    # periods_from_ts: the term is a clause-form field.
    assert validate_standing_payment_shape(
        _declared_entry(due_retry_seconds=RETRY_WEEK), TS) is not None
    # The parse reads the field; the shape check is what refuses it.
    tx = {
        "sender_pubkey": PAYER,
        "standing_recipient_pubkey": RECIPIENT,
        "standing_amount": 500,
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": TS - 100,
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": 100_000,
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
        "standing_form": FORM_DECLARED,
        "standing_due_retry_seconds": RETRY_WEEK,
    }
    problem = validate_standing_payment_shape(
        parse_create_standing_payment(tx), TS)
    assert problem is not None and "due_retry" in problem


def test_parse_reads_the_signed_retry_term():
    tx = {
        "sender_pubkey": PAYER,
        "standing_recipient_pubkey": RECIPIENT,
        "standing_amount": 500,
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": TS - 100,
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": 100_000,
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
        "standing_form": FORM_TAU_CLAUSE,
        "standing_clause": CLAUSE,
        "standing_due_retry_seconds": RETRY_WEEK,
    }
    entry = parse_create_standing_payment(tx)
    assert entry.due_retry_seconds == RETRY_WEEK
    assert entry.auth_id.hex() == GOLDEN_RETRY_AUTH_ID


# --- note / ordering / liveness ---------------------------------------------------


def test_note_retry_owed_is_idempotent_per_period():
    entry = _retry_entry()
    book = _book_with(entry)
    assert book.note_retry_owed(entry.auth_id, 0, TS, 20)
    assert not book.note_retry_owed(entry.auth_id, 0, TS + 10, 21)
    assert len(book.owed_retries()) == 1
    retry = book.owed_retries()[0]
    assert retry.due_ts == TS - 100
    assert retry.retry_until == TS - 100 + RETRY_WEEK
    assert retry.recorded_height == 20


def test_note_refuses_periods_that_cannot_be_retried():
    entry = _retry_entry()
    book = _book_with(entry)
    # Settled already: execute period 0 first (the clause names 200).
    decision = book.execute(
        entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 200),))
    assert decision.executed
    assert not book.note_retry_owed(entry.auth_id, 0, TS, 20)
    # Not yet due.
    assert not book.note_retry_owed(entry.auth_id, 1, TS, 20)
    # Window closed.
    assert not book.note_retry_owed(
        entry.auth_id, 1, TS - 100 + DAY + RETRY_WEEK, 20)
    # The next due point has come.
    assert not book.note_retry_owed(entry.auth_id, 0, TS + DAY, 20)
    # A declared-form authorization owes no retry at all (a different
    # payer, so it is its own series rather than a version bump).
    declared = _declared_entry(payer_pubkey=OTHER)
    book.create(declared, TS - 100)
    assert not book.note_retry_owed(declared.auth_id, 0, TS, 20)


def test_owed_retries_are_longest_waiting_first():
    from consensus.standing_payments import SCHEDULE_WEEKLY
    first = _retry_entry()
    # Weekly, anchored three days earlier: its period 0 is due three
    # days before the first entry's, and its next due point (a week
    # later) has not come yet — so the retry is still live at TS.
    second = _retry_entry(
        payer_pubkey=OTHER, schedule_kind=SCHEDULE_WEEKLY,
        anchor_ts=TS - 100 - 3 * DAY,
    )
    book = StandingPaymentBook()
    book.create(first, TS - 100)
    book.create(second, TS - 100 - 3 * DAY)
    book.note_retry_owed(first.auth_id, 0, TS, 20)
    book.note_retry_owed(second.auth_id, 0, TS, 20)
    owed = book.owed_retries()
    # The second entry's due point is three days older: it runs first.
    assert [r.auth_id for r in owed] == [second.auth_id, first.auth_id]
    assert MAX_DUE_RETRIES_PER_BLOCK == 4


def test_retry_live_and_drop_reasons():
    entry = _retry_entry()
    book = _book_with(entry)
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    retry = book.owed_retries()[0]
    live, _reason = book.retry_live(retry, TS)
    assert live
    live, reason = book.retry_live(retry, TS - 100 + RETRY_WEEK)
    assert not live and reason == "the retry window for this period has closed"
    live, reason = book.retry_live(retry, TS + DAY)
    assert not live and reason == "the next due point has come"
    book.cancel(entry.auth_id, TS)
    live, reason = book.retry_live(retry, TS)
    assert not live and "cancelled" in reason


# --- execute_retry -----------------------------------------------------------------


def test_execute_retry_pays_and_clears_the_retry():
    entry = _retry_entry()
    book = _book_with(entry)
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    decision = book.execute_retry(
        book.owed_retries()[0], TS, 10_000, ((RECIPIENT, 200),))
    assert decision.executed and decision.amount == 200
    assert decision.period_index == 0 and decision.periods_collected == 1
    assert decision.total_paid_after == 200
    assert book.owed_retries() == []
    assert book.root().hex() == GOLDEN_RETRY_ROOT_SETTLED


def test_execute_retry_short_stays_owed():
    entry = _retry_entry()
    book = _book_with(entry)
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    decision = book.execute_retry(
        book.owed_retries()[0], TS, 100, ((RECIPIENT, 200),))
    assert not decision.executed
    assert decision.reason.startswith(INSUFFICIENT_FUNDS_REASON_PREFIX)
    assert len(book.owed_retries()) == 1
    assert book.root().hex() == GOLDEN_RETRY_ROOT_WITH_RETRY


def test_execute_retry_refused_for_other_reasons_leaves_it_to_the_caller():
    # The book returns the refusal; the CALLER (the sweep) drops the
    # retry — the book never drops on a refusal it did not cause, so a
    # caller that disagrees cannot lose the retry silently.
    entry = _retry_entry()
    book = _book_with(entry)
    # A cap refusal: the clause names 600 against the 500 per-period cap.
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    decision = book.execute_retry(
        book.owed_retries()[0], TS, 10_000, ((RECIPIENT, 600),))
    assert not decision.executed
    assert "cap" in decision.reason
    assert len(book.owed_retries()) == 1
    # A window-closed retry: execute_retry refuses it outright.
    decision = book.execute_retry(
        book.owed_retries()[0], TS - 100 + RETRY_WEEK, 10_000,
        ((RECIPIENT, 200),))
    assert not decision.executed
    assert "retry window" in decision.reason
    assert len(book.owed_retries()) == 1


def test_execute_retry_needs_an_owed_retry():
    entry = _retry_entry()
    book = _book_with(entry)
    retry = StandingDueRetry(
        entry.auth_id, 0, TS - 100, TS - 100 + RETRY_WEEK, 20)
    decision = book.execute_retry(retry, TS, 10_000, ((RECIPIENT, 200),))
    assert not decision.executed
    assert "no retry is owed" in decision.reason


def test_a_tx_execution_settles_the_period_and_clears_the_retry():
    entry = _retry_entry()
    book = _book_with(entry)
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    decision = book.execute(
        entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 200),))
    assert decision.executed
    assert book.owed_retries() == []


def test_cancel_and_supersede_drop_retries():
    entry = _retry_entry()
    book = _book_with(entry)
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    book.cancel(entry.auth_id, TS)
    assert book.owed_retries() == []
    # Supersede: a version bump of the same payer/recipient/schedule.
    book2 = _book_with(entry)
    book2.note_retry_owed(entry.auth_id, 0, TS, 20)
    book2.create(_retry_entry(version=2), TS - 100)
    assert book2.owed_retries() == []


# --- discovery ---------------------------------------------------------------------


def test_discovery_decision():
    entry = _retry_entry()
    book = _book_with(entry)
    # Payable: the clause names 200 and the balance covers it.
    decision = book.discovery_decision(
        entry.auth_id, 0, TS, 10_000, ((RECIPIENT, 200),))
    assert decision.executed
    # Short: the same period, a balance below the named legs.
    decision = book.discovery_decision(
        entry.auth_id, 0, TS, 100, ((RECIPIENT, 200),))
    assert not decision.executed
    assert decision.reason.startswith(INSUFFICIENT_FUNDS_REASON_PREFIX)
    # A cap refusal owes no retry.
    decision = book.discovery_decision(
        entry.auth_id, 0, TS, 10_000, ((RECIPIENT, 600),))
    assert not decision.executed and "cap" in decision.reason
    # Window closed / next due point: no discovery at all.
    decision = book.discovery_decision(
        entry.auth_id, 0, TS - 100 + RETRY_WEEK, 100, ((RECIPIENT, 200),))
    assert "retry window" in decision.reason
    decision = book.discovery_decision(
        entry.auth_id, 0, TS + DAY, 100, ((RECIPIENT, 200),))
    assert "next due point" in decision.reason


def test_retry_candidates():
    entry = _retry_entry()
    book = _book_with(entry)
    candidates = book.retry_candidates(TS)
    assert candidates == [(entry, 0)]
    # Settled: no longer a candidate.
    book.execute(entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 200),))
    assert book.retry_candidates(TS) == []
    # Owed already: no longer a candidate (the sweep does not
    # re-evaluate what it already owes).
    book2 = _book_with(entry)
    book2.note_retry_owed(entry.auth_id, 0, TS, 20)
    assert book2.retry_candidates(TS) == []
    # A declared-form authorization is never a candidate.
    book3 = StandingPaymentBook()
    book3.create(_declared_entry(), TS - 100)
    assert book3.retry_candidates(TS) == []
    # A clause-form authorization without a retry term is not one either.
    book4 = StandingPaymentBook()
    book4.create(_retry_entry(due_retry_seconds=0), TS - 100)
    assert book4.retry_candidates(TS) == []


# --- restore / capabilities ---------------------------------------------------------


def test_restore_round_trip_with_retries():
    entry = _retry_entry()
    book = _book_with(entry)
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    restored = StandingPaymentBook.restore(
        book.rows(), book.fact_rows(), book.retry_rows())
    assert restored.root() == book.root()
    assert restored.owed_retries() == book.owed_retries()
    assert restored.get(entry.auth_id).due_retry_seconds == RETRY_WEEK


def test_restore_refuses_a_retry_whose_entry_is_missing():
    entry = _retry_entry()
    book = _book_with(entry)
    book.note_retry_owed(entry.auth_id, 0, TS, 20)
    with pytest.raises(ValueError):
        StandingPaymentBook.restore(
            [], book.fact_rows(), book.retry_rows())


def test_capabilities_record_names_the_retry_term():
    record = standing_payment_capabilities()
    due_retry = record["clause_form"]["due_retry"]
    assert due_retry["term"] == "standing_due_retry_seconds"
    assert due_retry["range_seconds"] == f"0..{MAX_DUE_RETRY_SECONDS}"
    assert "insufficient funds" in due_retry["semantics"]
    assert f"at most {MAX_DUE_RETRIES_PER_BLOCK} a block" in (
        due_retry["semantics"]
    )
