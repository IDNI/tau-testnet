"""Bounty 01, FIX 5: grants in Tau clause form, at book level.

The clause form of grants, beside the declared forms stages 2-5
shipped: the funder's own Tau clause, stepped by the node through the
existing policy-evaluation path, names the cumulative amount released
in o30; the book re-checks that answer against the declared schedule
cap (release x periods begun from the signed periods_from, capped at
the total) and settles atomically or not at all. The release grid for
a clause-form grant is anchored at the signed periods_from, not the
install day. The refund stays the book's own invariant (total -
spent, once) — never a clause computation, so a clause cannot
under-refund.

Covered: the byte-for-byte pin (a declared entry's id, record bytes
and book root are the values the pre-clause code computed — the
goldens below were measured on the base tree before this form
existed, and a clause entry beside a declared one moves none of
them); id domain separation with the clause and the anchor inside the
hash; parse form selection and the cross-field refusals; shape bounds
(incl. the monthly day check following the clause grid); the input
map and the released-amount decoder; clause evaluation under every
shared check (schedule cap, total cap, spendable, shared cap,
at-most-once per period); the named case 5 in clause form (500 x 3
draws, 4th refused, refund exactly 3500); boundaries from the signed
periods_from and install-day independence; restore round-trips and
the Tau-form restore invariant; the capability record.
"""
from datetime import datetime, timezone

import pytest

from consensus.grants import (
    FORM_DECLARED,
    FORM_TAU_CLAUSE,
    GRANT_FORMS,
    MAX_GRANT_CLAUSE_BYTES,
    GrantBook,
    GrantEntry,
    GrantShapeError,
    GrantSharedCapEntry,
    decode_clause_released,
    grant_capabilities,
    grant_clause_inputs,
    parse_create_grant,
    period_index_at,
    released_by,
    validate_grant_shape,
)
from consensus.serialization import (
    compute_grant_tau_id,
    encode_grant_record,
)
from consensus.standing_payments import SCHEDULE_MONTHLY, SCHEDULE_WEEKLY

FUNDER = "aa" * 48
BOB = "bb" * 48
CAROL = "cc" * 48

WEEK = 604_800
DAY = 86_400
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
DEADLINE = DEC1 + 8 * WEEK
TS = DEC1


def _grant_clause(anchor, release=500, total=5000, weeks=8):
    """The canonical grants clause: cumulative released per period band.

    Band k (from the signed periods_from anchor) names release*k,
    capped at the total; before the anchor nothing is released. The
    nested-ternary shape is the payout clause's
    (tests/test_payout_tau_rule_native.py): comparisons on i5,
    constant o30 outputs. The book re-checks the answer against the
    declared schedule cap, so a band the funder wrote past the
    schedule settles nothing.
    """
    def rel(amount):
        return f"((o30[t]:bv[64] = {{ {amount} }}:bv[64]))"

    clause = rel(total)
    for k in range(weeks, 0, -1):
        clause = (
            f"((i5[t]:bv[64] < {{ {anchor + k * WEEK} }}:bv[64]) "
            f"? {rel(min(total, release * k))} : {clause})"
        )
    return (
        f"((i5[t]:bv[64] < {{ {anchor} }}:bv[64]) "
        f"? {rel(0)} : {clause})"
    )


CLAUSE = _grant_clause(DEC1)


# Goldens measured on the base tree BEFORE the clause form existed,
# for exactly the entry built by _entry below. The byte-for-byte pin:
# the clause form's arrival must not move any of these values.
GOLDEN_GRANT_ID = (
    "c567959b6fa336a064262b091588850bf4a1bc1704c06119fdb5955d2ab77eb8"
)
GOLDEN_RECORD = (
    "c567959b6fa336a064262b091588850bf4a1bc1704c06119fdb5955d2ab77eb8"
    + "aa" * 48  # funder
    + "bb" * 48  # beneficiary
    + "0000000000001388"  # total 5000
    + "00000000000001f4"  # release 500
    + "0000000000000002"  # weekly
    + "0000000000000000"  # signed_day 0
    + "000000006b0e0e00"  # start DEC1
    + "000000006b57e200"  # deadline DEC1 + 8w
    + "0000000000000000"  # locked_until 0
    + "0000000000000000"  # window_start 0
    + "0000000000000000"  # window_end 0
    + "0000000000000000"  # inactivity 0
    + "0000000000000001"  # version 1
    + "0000000000000000"  # spent 0
    + "0000000000000000"  # last_draw 0
    + "0000000000000000"  # refunded 0
    + "0000000000000000"  # refunded_amount 0
    + "0000000000000000"  # refunded_ts 0
)
GOLDEN_ROOT = (
    "c1f906c66724688d96c9f9b284cd333d0c8706b80ecad35282ee346bc0ec68e4"
)


def _entry(**kw):
    fields = dict(
        funder_pubkey=FUNDER,
        beneficiary_pubkey=BOB,
        total_amount=5000,
        release_per_period=500,
        schedule_kind=SCHEDULE_WEEKLY,
        signed_day=0,
        start_ts=DEC1,
        deadline_ts=DEADLINE,
        locked_until_ts=0,
        window_start_ts=0,
        window_end_ts=0,
        inactivity_seconds=0,
        version=1,
    )
    fields.update(kw)
    return GrantEntry(**fields)


def _clause_entry(**kw):
    fields = dict(form=FORM_TAU_CLAUSE, clause_text=CLAUSE, periods_from_ts=DEC1)
    fields.update(kw)
    return _entry(**fields)


def _book_with(entry=None, **kw):
    book = GrantBook()
    entry = entry if entry is not None else _entry(**kw)
    book.create(entry, DEC1 - 100)
    return book, entry


def _create_tx(**kw):
    tx = {
        "sender_pubkey": FUNDER,
        "grant_beneficiary_pubkey": BOB,
        "grant_total_amount": 5000,
        "grant_release_per_period": 500,
        "grant_schedule": "weekly",
        "grant_signed_day": 0,
        "grant_start_ts": DEC1,
        "grant_deadline_ts": DEADLINE,
        "grant_locked_until_ts": 0,
        "grant_window_start_ts": 0,
        "grant_window_end_ts": 0,
        "grant_inactivity_seconds": 0,
        "grant_version": 1,
    }
    tx.update(kw)
    return tx


# --- the byte-for-byte pin ----------------------------------------------------


def test_declared_grant_id_record_and_root_are_pinned():
    entry = _entry()
    assert entry.grant_id.hex() == GOLDEN_GRANT_ID
    book, _ = _book_with(entry)
    row = book.rows()[0]
    assert len(row) == 22
    assert encode_grant_record(*row).hex() == GOLDEN_RECORD
    assert book.root().hex() == GOLDEN_ROOT


def test_clause_entry_beside_a_declared_one_moves_no_declared_value():
    book, declared = _book_with()
    clause = _clause_entry()
    book.create(clause, DEC1 - 100)
    row = next(r for r in book.rows() if r[0] == declared.grant_id)
    assert encode_grant_record(*row).hex() == GOLDEN_RECORD
    assert declared.grant_id.hex() == GOLDEN_GRANT_ID


# --- ids: domain separation ---------------------------------------------------


def test_clause_id_differs_from_declared_over_the_same_terms():
    assert _entry().grant_id != _clause_entry().grant_id


def test_clause_id_is_the_tau_domain_hash_of_all_signed_fields():
    entry = _clause_entry()
    assert entry.grant_id == compute_grant_tau_id(
        entry.funder_pubkey, entry.beneficiary_pubkey, entry.total_amount,
        entry.release_per_period, entry.schedule_kind, entry.signed_day,
        entry.start_ts, entry.deadline_ts, entry.locked_until_ts,
        entry.window_start_ts, entry.window_end_ts, entry.inactivity_seconds,
        entry.version, entry.form, entry.clause_text, entry.periods_from_ts,
    )


def test_tampering_with_the_clause_or_the_anchor_changes_the_id():
    base = _clause_entry()
    assert _clause_entry(clause_text=CLAUSE + " ").grant_id != base.grant_id
    assert _clause_entry(periods_from_ts=DEC1 + WEEK).grant_id != base.grant_id
    assert _clause_entry(form=FORM_DECLARED).grant_id != base.grant_id


# --- parsing and shape ----------------------------------------------------------


def test_parse_create_grant_defaults_to_declared_and_reads_the_clause_form():
    entry = parse_create_grant(_create_tx())
    assert entry.form == FORM_DECLARED
    assert entry.clause_text == "" and entry.periods_from_ts == 0
    entry = parse_create_grant(_create_tx(
        grant_form=2, grant_clause=CLAUSE, grant_periods_from_ts=DEC1))
    assert entry.form == FORM_TAU_CLAUSE
    assert entry.clause_text == CLAUSE and entry.periods_from_ts == DEC1


def test_parse_create_grant_refuses_a_bad_form_or_clause():
    with pytest.raises(GrantShapeError, match="grant_form must be 1"):
        parse_create_grant(_create_tx(grant_form=3))
    with pytest.raises(GrantShapeError, match="grant_form must be 1"):
        parse_create_grant(_create_tx(grant_form=True))
    with pytest.raises(GrantShapeError, match="grant_clause must be a string"):
        parse_create_grant(_create_tx(grant_clause=7))


def test_grant_shape_clause_bounds():
    assert validate_grant_shape(_clause_entry(), TS) is None
    problem = validate_grant_shape(_clause_entry(clause_text=""), TS)
    assert "must carry a clause" in problem
    problem = validate_grant_shape(_clause_entry(clause_text="   "), TS)
    assert "must carry a clause" in problem
    problem = validate_grant_shape(_clause_entry(clause_text="x" * 8193), TS)
    assert "at most 8192 bytes" in problem
    assert validate_grant_shape(
        _clause_entry(clause_text="x" * 8192), TS) is None
    problem = validate_grant_shape(_clause_entry(periods_from_ts=0), TS)
    assert "must carry a signed periods_from" in problem
    problem = validate_grant_shape(_entry(clause_text=CLAUSE), TS)
    assert "carries no clause" in problem
    problem = validate_grant_shape(_entry(periods_from_ts=DEC1), TS)
    assert "carries no periods_from" in problem
    problem = validate_grant_shape(_entry(form=9), TS)
    assert "grant_form must be 1" in problem


def test_grant_shape_monthly_day_check_follows_the_clause_grid():
    # Monthly, signed day 15: the declared form checks the start, the
    # clause form checks periods_from — a clause grid anchored on the
    # 15th is fine even when the grant itself opens on the 1st.
    dec1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
    dec15 = int(datetime(2026, 12, 15, tzinfo=timezone.utc).timestamp())
    entry = _entry(
        schedule_kind=SCHEDULE_MONTHLY, signed_day=15, start_ts=dec1,
        deadline_ts=dec1 + 8 * WEEK,
        form=FORM_TAU_CLAUSE, clause_text=CLAUSE, periods_from_ts=dec15,
    )
    assert validate_grant_shape(entry, TS) is None
    bad = _entry(
        schedule_kind=SCHEDULE_MONTHLY, signed_day=15, start_ts=dec1,
        deadline_ts=dec1 + 8 * WEEK,
        form=FORM_TAU_CLAUSE, clause_text=CLAUSE, periods_from_ts=dec1,
    )
    assert "periods_from must be the first release date" in (
        validate_grant_shape(bad, TS) or "")
    declared_bad = _entry(
        schedule_kind=SCHEDULE_MONTHLY, signed_day=15, start_ts=dec1,
        deadline_ts=dec1 + 8 * WEEK,
    )
    assert "the start must be the first release date" in (
        validate_grant_shape(declared_bad, TS) or "")


# --- input map and decoder ------------------------------------------------------


def test_grant_clause_inputs_are_node_built_and_exact():
    entry = _clause_entry()
    inputs = grant_clause_inputs(entry, BOB, 500, DEC1 + WEEK, 4500, 500)
    assert inputs == {
        1: "500",
        2: "4500",
        3: "{ #x" + FUNDER + " }:bv[384]",
        4: "{ #x" + BOB + " }:bv[384]",
        5: str(DEC1 + WEEK),
        27: "500",
    }


def test_decode_clause_released():
    entry = _clause_entry()
    released, why = decode_clause_released(entry, {"o30": "1500"})
    assert released == 1500 and why == ""
    released, _ = decode_clause_released(entry, {"o30": "{ #x5dc }:bv[64]"})
    assert released == 1500
    released, why = decode_clause_released(entry, {"o30": "0"})
    assert released == 0
    released, why = decode_clause_released(entry, {})
    assert released is None and "did not report" in why
    released, why = decode_clause_released(entry, {"o30": "not-a-number"})
    assert released is None and "did not report" in why


# --- evaluation: the clause names, the book checks --------------------------------


def test_clause_form_without_a_stepped_value_is_refused():
    book, entry = _book_with(_clause_entry())
    decision = book.evaluate_draw(entry.grant_id, 500, DEC1)
    assert not decision.drawn
    assert "must be stepped" in decision.reason


def test_clause_released_within_the_schedule_cap_draws():
    book, entry = _book_with(_clause_entry())
    decision = book.evaluate_draw(
        entry.grant_id, 500, DEC1 + 2 * WEEK, clause_released=1500)
    assert decision.drawn
    assert decision.amount == 500 and decision.spendable_after == 1000
    assert decision.period_index == 2


def test_clause_released_above_the_schedule_cap_settles_nothing():
    book, entry = _book_with(_clause_entry())
    decision = book.evaluate_draw(
        entry.grant_id, 500, DEC1 + 2 * WEEK, clause_released=2000)
    assert not decision.drawn
    assert "above the declared schedule's 1500" in decision.reason
    assert book.accounting(entry.grant_id)["drawn"] == 0


def test_clause_released_above_the_grant_total_settles_nothing():
    book, entry = _book_with(_clause_entry())
    decision = book.evaluate_draw(
        entry.grant_id, 500, DEC1, clause_released=6000)
    assert not decision.drawn
    assert "above the grant total" in decision.reason


def test_clause_released_below_the_draw_is_not_spendable():
    book, entry = _book_with(_clause_entry())
    decision = book.evaluate_draw(
        entry.grant_id, 500, DEC1, clause_released=400)
    assert not decision.drawn
    assert "exceeds the released-but-unspent amount 400" in decision.reason


def test_named_case_5_in_clause_form():
    """Case 5 as a clause: 5000 releasing 500/week from Dec 1; Bob
    draws 500 in each of three weeks (1500 spent); a 4th draw in the
    third week is refused (nothing left released); the deadline refund
    returns exactly 3500."""
    book, entry = _book_with(_clause_entry())
    for week in range(3):
        ts = DEC1 + week * WEEK
        released = 500 * (week + 1)
        decision = book.draw(
            entry.grant_id, 500, ts, clause_released=released)
        assert decision.drawn, (week, decision.reason)
        assert decision.spendable_after == 0
    assert book.accounting(entry.grant_id)["drawn"] == 1500
    fourth = book.evaluate_draw(
        entry.grant_id, 500, DEC1 + 2 * WEEK, clause_released=1500)
    assert not fourth.drawn
    assert "exceeds the released-but-unspent amount 0" in fourth.reason
    assert book.settle_expiry_refund(entry.grant_id, DEADLINE) == 3500
    assert book.accounting(entry.grant_id)["refunded"] == 3500


def test_clause_and_declared_forms_agree_on_the_same_schedule():
    """The same draws on the same terms: the clause form's decisions
    are the declared form's decisions, period for period."""
    clause_book, clause = _book_with(_clause_entry())
    declared_book, declared = _book_with()
    for week in range(4):
        ts = DEC1 + week * WEEK
        released = 500 * (week + 1)
        c = clause_book.draw(clause.grant_id, 500, ts, clause_released=released)
        d = declared_book.draw(declared.grant_id, 500, ts)
        assert (c.drawn, c.amount, c.spendable_after) == (
            d.drawn, d.amount, d.spendable_after)
    assert clause_book.accounting(clause.grant_id) == (
        declared_book.accounting(declared.grant_id))


def test_period_boundaries_come_from_periods_from_not_the_install_day():
    """The clause grid is anchored at the signed periods_from: a grant
    installed Dec 1 whose periods_from is Dec 15 releases nothing on
    Dec 1 (the declared form would release 500 there) and releases its
    first 500 on Dec 15."""
    anchor = DEC1 + 2 * WEEK
    book, entry = _book_with(_clause_entry(periods_from_ts=anchor))
    assert released_by(entry, DEC1) == 0
    assert released_by(_entry(), DEC1) == 500
    assert period_index_at(entry, DEC1) == -1
    assert period_index_at(entry, anchor) == 0
    early = book.evaluate_draw(
        entry.grant_id, 500, DEC1, clause_released=500)
    assert not early.drawn
    assert "above the declared schedule's 0" in early.reason
    first = book.draw(entry.grant_id, 500, anchor, clause_released=500)
    assert first.drawn and first.spendable_after == 0
    second = book.evaluate_draw(
        entry.grant_id, 500, anchor, clause_released=500)
    assert not second.drawn
    assert "exceeds the released-but-unspent amount 0" in second.reason


def test_shared_cap_still_binds_clause_form_draws():
    book, entry = _book_with(_clause_entry())
    cap = GrantSharedCapEntry(
        funder_pubkey=FUNDER, cap_amount=800,
        period_seconds=4 * WEEK, period_anchor_ts=DEC1, version=1,
    )
    book.set_shared_cap(cap, DEC1 - 100)
    first = book.draw(entry.grant_id, 500, DEC1, clause_released=500)
    assert first.drawn
    # The clause would allow a second 500 (released 1000, spendable
    # 500) but the funder's shared cap counts 500 already drawn: 500 +
    # 500 > 800, so the book refuses.
    second = book.evaluate_draw(
        entry.grant_id, 500, DEC1 + WEEK, clause_released=1000)
    assert not second.drawn
    assert "past the shared cap 800" in second.reason


def test_clause_form_time_conditions_still_apply():
    locked = _clause_entry(locked_until_ts=DEC1 + WEEK)
    book, entry = _book_with(locked)
    decision = book.evaluate_draw(
        entry.grant_id, 500, DEC1, clause_released=500)
    assert not decision.drawn
    assert "locked until" in decision.reason
    window = _clause_entry(
        window_start_ts=DEC1 + WEEK, window_end_ts=DEC1 + 3 * WEEK)
    book, entry = _book_with(window)
    decision = book.evaluate_draw(
        entry.grant_id, 500, DEC1, clause_released=500)
    assert not decision.drawn
    assert "outside the grant's scheduled window" in decision.reason


# --- restore ----------------------------------------------------------------------


def test_restore_round_trips_a_clause_form_grant():
    book, entry = _book_with(_clause_entry())
    book.draw(entry.grant_id, 500, DEC1, clause_released=500)
    restored = GrantBook.restore(book.rows(), book.shared_cap_rows())
    assert restored.get(entry.grant_id) is not None
    again = restored.get(entry.grant_id)
    assert again.form == FORM_TAU_CLAUSE
    assert again.clause_text == CLAUSE
    assert again.periods_from_ts == DEC1
    assert again.grant_id == entry.grant_id
    assert restored.root() == book.root()
    assert restored.accounting(entry.grant_id)["drawn"] == 500


def test_restore_refuses_a_row_whose_clause_was_tampered():
    book, entry = _book_with(_clause_entry())
    row = list(book.rows()[0])
    row[20] = CLAUSE + " "
    with pytest.raises(ValueError, match="does not match its fields"):
        GrantBook.restore([tuple(row)], [])


def test_two_clause_entries_differing_only_in_clause_have_different_roots():
    book_a, _ = _book_with(_clause_entry())
    other = _clause_entry(clause_text=_grant_clause(DEC1 + WEEK))
    book_b, _ = _book_with(other)
    assert book_a.root() != book_b.root()


# --- capabilities -------------------------------------------------------------------


def test_grant_capabilities_records_the_tau_clause_form():
    caps = grant_capabilities()
    assert caps["supported"] is True
    tau_clause = caps["tau_clause"]
    assert tau_clause["forms"] == {
        "declared_program": FORM_DECLARED,
        "tau_clause": FORM_TAU_CLAUSE,
    }
    assert tau_clause["inputs"]["i27"] == "what this grant has already spent"
    assert tau_clause["inputs"]["i5"] == "the block timestamp"
    assert tau_clause["outputs"]["o30"] == (
        "the cumulative amount released by the draw's timestamp"
    )
    assert tau_clause["max_clause_bytes"] == MAX_GRANT_CLAUSE_BYTES
    assert "refund" in tau_clause
    assert "total - spent" in tau_clause["refund"]
    assert GRANT_FORMS == frozenset({FORM_DECLARED, FORM_TAU_CLAUSE})
