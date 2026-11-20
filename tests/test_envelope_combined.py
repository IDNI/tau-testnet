"""Combined conditions: reading every condition of an envelope together, and the
proofs that the reading is right.

consensus/envelope_plan.py tells a sender, before signing, what the conditions
add up to: the plan (unlock, first spend, first due point and where the rest goes
then, the limit's reach), the notes (a condition that changes nothing for this
envelope, a combination that may surprise), the refusal in plain words, and the
conditions as sentences. None of it is consensus, so all of it must agree with
the node's own checks. What is proved here:

  E6, the never-spendable check is exact ....... test_never_spendable_is_exact_on_the_block_clock,
                                                 test_never_spendable_is_exact_with_windows
      On every envelope of a block-clock universe (48,000 term sets) and on
      random seconds-clock envelopes with windows, the node refuses a send
      exactly when no clock exists at which a spend of 1 lands (tried at every
      height, or the unlock and every hour boundary, through the book's own
      spend check; windows read with Python's datetime).

  a "never_decides" note is sound ............... test_never_decides_notes_are_sound_on_the_block_clock,
                                                 test_never_decides_notes_are_sound_with_windows
      The envelope with and without that condition is bisimilar: for EVERY
      sequence of spends at every block clock, both give the same accepts,
      refusals and closes. The search walks pairs of book states, so it covers
      all sequences without listing them.

  ... and exact where the docs say so ........... test_a_condition_without_a_note_decides_something
      On the block clock without refund_idle, a not_before, hold, limit or
      recurring with no such note does change something, and the search finds
      the spend that shows it; refund_idle itself is exact everywhere.

  the proof has teeth ............................. test_the_proof_catches_planted_bugs
      Nine planted bugs in the notes (a lock or idle point one tick off, a cap
      one short, the last period forgotten, the last hour unread, a tie
      missed) are each rejected by the searches above.

  the walkthrough ................................ test_alice_sends_bob_5000_with_four_conditions
      Alice -> Bob 5,000: at most 500 a week from 1 December, only on working
      days, unused for 14 days or left on 29 December it comes back. Built with
      the CLI's own flags, run through the real apply_block.
"""
import copy
import datetime as dt
import itertools
import json
import random
import shlex
from dataclasses import replace

import pytest

from consensus.envelope import (
    AT_END_REFUND,
    AT_END_RELEASE,
    KIND_BLOCKS,
    KIND_SECONDS,
    EnvelopeBook,
    EnvelopeRefused,
    EnvelopeSpend,
    EnvelopeState,
    EnvelopeTerms,
    first_spend_point,
    parse_envelope_send,
    terms_problem,
    validate_send_shape,
)
from consensus.envelope_plan import (
    INFO,
    NEVER_DECIDES,
    WARNING,
    clock_text,
    days_text,
    explain,
    hours_text,
    longest_gap,
    notes,
    per_text,
    plan,
    refusal,
    span_text,
    window_runs,
    windows_text,
)

A, B, C = "a" * 96, "b" * 96, "c" * 96
HOUR, DAY = 3600, 86400


def utc(*parts) -> int:
    return int(dt.datetime(*parts, tzinfo=dt.timezone.utc).timestamp())


SENT = utc(2026, 11, 17, 9)          # a Tuesday
DEC1, DEC29 = utc(2026, 12, 1), utc(2026, 12, 29)
MON = utc(2026, 11, 16)               # a Monday 00:00 UTC


def terms(amount=100, caps=(), kind=KIND_SECONDS, period=0, recurring=False, *, ends,
          **conditions) -> EnvelopeTerms:
    return EnvelopeTerms(A, 1, B, amount, tuple(caps), kind, period, recurring, ends,
                         **conditions)


def codes(t, sent):
    return {(n["condition"], n["code"]) for n in notes(t, sent)}


# --- Formatting --------------------------------------------------------------------------

def test_spans_points_and_windows_read_naturally():
    t, b = terms(ends=SENT + DAY), terms(kind=KIND_BLOCKS, ends=900)
    assert [span_text(t, v) for v in (1, 90, 3600, 6 * HOUR, 7 * DAY, 69 * HOUR,
                                      DAY + 90 * 60)] == [
        "1 s", "1 min 30 s", "1 hour", "6 hours", "1 week", "69 hours", "1 d 1 h 30 min"]
    assert [per_text(t, v) for v in (7 * DAY, 30 * DAY)] == ["week", "30 days"]
    assert [per_text(t, v) for v in (6000, 1, 3600)] == ["1 h 40 min", "1 s", "hour"]   # never "per h 40 min"
    assert (span_text(b, 1), span_text(b, 5000), per_text(b, 1), per_text(b, 10)) == (
        "1 block", "5,000 blocks", "block", "10 blocks")
    assert clock_text(t, DEC1) == "Tue 2026-12-01 00:00 UTC"
    assert clock_text(t, DEC1 + 1) == "Tue 2026-12-01 00:00:01 UTC"
    assert clock_text(b, 12345) == "block 12,345"


@pytest.mark.parametrize("days, text", [
    (["mon", "tue", "wed", "thu", "fri"], "Mon-Fri"),
    (["sat", "sun"], "Sat, Sun"),
    (["fri", "sat", "sun", "mon"], "Fri-Mon"),
    (["mon", "sun"], "Mon, Sun"),
    (["mon", "wed", "fri", "sun"], "Mon, Wed, Fri, Sun"),
    (["mon", "tue", "wed", "thu", "fri", "sun"], "Sun-Fri"),
    (["wed"], "Wed"),
])
def test_weekdays_read_as_runs(days, text):
    names = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
    assert days_text(sum(1 << names.index(d) for d in days)) == text


@pytest.mark.parametrize("hours, text", [
    (range(9, 17), "09:00-17:00 UTC"),
    ([22, 23, 0, 1, 2, 3, 4, 5], "22:00-06:00 UTC"),
    ([9, 12, 13], "09:00-10:00, 12:00-14:00 UTC"),
])
def test_hours_read_as_ranges(hours, text):
    assert hours_text(sum(1 << h for h in hours)) == text


def test_windows_name_where_they_are_read():
    office = terms(ends=SENT + 9 * DAY, days=0b0011111, hours=0xFF << 9, utc_offset=8)
    assert hours_text(office.hours, office.utc_offset) == "09:00-17:00 UTC+02:00"
    assert windows_text(office) == "Mon-Fri and 09:00-17:00 UTC+02:00"
    weekend = terms(ends=SENT + 9 * DAY, days=0b1100000, utc_offset=-20)
    assert windows_text(weekend) == "Sat, Sun UTC-05:00"
    assert windows_text(terms(ends=SENT + 9 * DAY, days=0b1100000)) == "Sat, Sun"
    assert "only on Mon-Fri and only 09:00-17:00 UTC+02:00, to anyone" in \
        explain(office, unlock=SENT, sent=SENT)
    assert "only on Sat, Sun (UTC-05:00), to anyone" in explain(weekend, unlock=SENT, sent=SENT)
    noon = terms(ends=SENT + 9 * DAY, hours=1 << 12, utc_offset=23)
    assert "only 12:00-13:00 UTC+05:45, to anyone" in explain(noon, unlock=SENT, sent=SENT)


def test_the_week_of_an_offset_envelope_is_its_own():
    """Runs and gaps are counted on the envelope's own week, so a quarter-hour
    offset shifts nothing in them."""
    for offset in (0, 8, -22, 23, 56, -48):
        lunch = terms(ends=SENT + 9 * DAY, days=0b0011111, hours=0b111 << 11,
                      utc_offset=offset)
        assert window_runs(lunch)[0] == (11 * HOUR, 14 * HOUR), offset
        assert longest_gap(lunch) == 69 * HOUR, offset


def test_notes_and_refusals_follow_the_offset():
    # Saturday at UTC+14:00 began Friday 10:00 UTC: an envelope living Friday 12:00
    # to Friday 20:00 UTC lies wholly in that Saturday, and in no UTC Saturday.
    fri = MON + 4 * DAY
    east = terms(ends=fri + 20 * HOUR, days=1 << 5, utc_offset=56, hold=HOUR)
    assert ("days", "DAYS_COVER_LIFE") in codes(east, fri + 11 * HOUR)
    assert any("Sat UTC+14:00" in n["text"] for n in notes(east, fri + 11 * HOUR))
    utc_sat = terms(ends=fri + 20 * HOUR, days=1 << 5, hold=HOUR)
    assert "No spending window (Sat) opens" in refusal(utc_sat, fri + 11 * HOUR)
    # Noon at UTC+05:45 is 06:15 to 07:15 UTC.
    noon = terms(ends=MON + 7 * HOUR, hours=1 << 12, utc_offset=23, refund_idle=30 * 60)
    assert ("hours", "HOURS_COVER_LIFE") in codes(noon, MON + 6 * HOUR + 15 * 60)
    shut = terms(ends=MON + 6 * HOUR + 15 * 60, hours=1 << 12, utc_offset=23, hold=60)
    assert "No spending window (12:00-13:00 UTC+05:45) opens" in refusal(shut, MON)
    opens = terms(ends=MON + 7 * HOUR, hours=1 << 12, utc_offset=23, hold=60)
    assert plan(opens, MON)["first_spend_at"] == MON + 6 * HOUR + 15 * 60


def test_window_runs_and_the_longest_gap():
    weekdays = terms(ends=SENT + 9 * DAY, days=0b0011111)
    assert window_runs(weekdays) == [(0, 5 * DAY)]
    assert longest_gap(weekdays) == 2 * DAY
    lunch = terms(ends=SENT + 9 * DAY, days=0b0011111, hours=0b111 << 11)
    assert longest_gap(lunch) == 69 * HOUR   # Friday 14:00 to Monday 11:00
    night = terms(ends=SENT + 9 * DAY, days=0b1000000, hours=(1 << 23) | 1)
    # Sunday 23:00 to Monday 00:00 is open, then the hour 00:00-01:00 on Sunday.
    assert window_runs(night) == [(6 * DAY, 6 * DAY + HOUR), (6 * DAY + 23 * HOUR, 7 * DAY)]
    assert longest_gap(terms(ends=SENT + DAY, hold=HOUR)) == 0


# --- The plan, notes and refusal on worked cases ------------------------------------------

def test_the_plan_of_the_walkthrough_envelope():
    t = terms(5000, (500,), KIND_SECONDS, 7 * DAY, True, ends=DEC29, not_before=DEC1,
              at_end=AT_END_REFUND)
    assert plan(t, SENT) == {
        "sent": SENT, "unlocks_at": DEC1, "unlocked_by": ["not_before"],
        "first_spend_at": DEC1, "spendable": True, "first_due_at": DEC29,
        "first_due_by": "end", "first_due_outcome": "refunded", "expires_at": DEC29,
        "limit_periods": 4, "limit_caps": [500], "most_spendable": 2000,
        "limit_lapses_at": None,
    }
    assert codes(t, SENT) == {("caps", "LIMIT_LEAVES_REST")}


def test_the_plan_names_the_idle_point_and_both_locks():
    t = terms(ends=SENT + 30 * DAY, not_before=SENT + 6 * HOUR, hold=6 * HOUR,
              refund_idle=2 * DAY)
    p = plan(t, SENT)
    assert p["unlocked_by"] == ["not_before", "hold"]
    assert (p["first_due_at"], p["first_due_by"], p["first_due_outcome"]) == (
        SENT + 6 * HOUR + 2 * DAY, "refund_idle", "refunded_idle")
    lapsing = terms(1000, (100, 200), KIND_BLOCKS, 10, ends=200)
    q = plan(lapsing, 100)
    assert (q["limit_periods"], q["limit_caps"], q["limit_lapses_at"], q["most_spendable"]) \
        == (10, [100, 200], 120, 1000)


@pytest.mark.parametrize("t, sent, expected", [
    (terms(ends=SENT + DAY, not_before=SENT - DAY), SENT,
     {("not_before", "NOT_BEFORE_PASSED")}),
    (terms(ends=SENT + DAY, not_before=SENT + HOUR, hold=2 * HOUR), SENT,
     {("not_before", "NOT_BEFORE_COVERED")}),
    (terms(ends=SENT + DAY, not_before=SENT + 3 * HOUR, hold=2 * HOUR), SENT,
     {("hold", "HOLD_COVERED")}),
    (terms(ends=SENT + DAY, not_before=SENT + 2 * HOUR, hold=2 * HOUR), SENT,
     {("not_before", "NOT_BEFORE_COVERED"), ("hold", "HOLD_COVERED")}),
    (terms(100, (100,), KIND_SECONDS, HOUR, True, ends=SENT + DAY), SENT,
     {("caps", "LIMIT_NEVER_BINDS"), ("recurring", "RECURRING_UNUSED")}),
    (terms(100, (10, 20, 30), KIND_SECONDS, DAY, True, ends=SENT + 2 * DAY), SENT,
     {("caps", "CAPS_UNREACHED"), ("recurring", "RECURRING_UNUSED"),
      ("caps", "LIMIT_LEAVES_REST")}),
    (terms(100, (10, 200), KIND_SECONDS, DAY, True, ends=SENT + 5 * DAY), SENT,
     {("recurring", "RECURRING_UNUSED")}),
    (terms(100, (10,), KIND_SECONDS, DAY, False, ends=SENT + 5 * DAY), SENT,
     {("caps", "LIMIT_LAPSES")}),
    (terms(ends=SENT + DAY, days=0b0011111), SENT, {("days", "DAYS_COVER_LIFE")}),
    (terms(ends=SENT + 3 * HOUR, hours=0xFFF << 8), SENT, {("hours", "HOURS_COVER_LIFE")}),
    (terms(ends=SENT + DAY, refund_idle=DAY), SENT, {("refund_idle", "IDLE_NEVER_FIRES")}),
    (terms(ends=SENT + 30 * DAY, days=0b0011111, refund_idle=2 * DAY), SENT,
     {("refund_idle", "IDLE_BETWEEN_WINDOWS")}),
    (terms(ends=SENT + 30 * DAY, days=0b0011111, refund_idle=3 * DAY), SENT, set()),
])
def test_notes_on_worked_cases(t, sent, expected):
    assert codes(t, sent) == expected
    levels = {n["code"]: n["level"] for n in notes(t, sent)}
    assert all(levels[c] == (INFO if c in ("LIMIT_LAPSES", "LIMIT_LEAVES_REST") else
                             WARNING if c == "IDLE_BETWEEN_WINDOWS" else NEVER_DECIDES)
               for c in levels)


def test_a_refused_envelope_gets_no_notes_and_a_named_refusal():
    held = terms(ends=utc(2026, 11, 18), hold=2 * DAY)
    assert notes(held, SENT) == [] and plan(held, SENT)["spendable"] is False
    assert refusal(held, SENT) == (
        "It would unlock at Thu 2026-11-19 09:00 UTC (the hold of 2 days), but it ends "
        "at Wed 2026-11-18 00:00 UTC: it could never be spent.")
    weekend = terms(ends=SENT + 30 * DAY, days=0b1100000, refund_idle=DAY)
    assert refusal(weekend, SENT) == (
        "No spending window (Sat, Sun) opens between the moment it unlocks at Tue "
        "2026-11-17 09:00 UTC and Wed 2026-11-18 09:00 UTC (the refund after 1 day "
        "unused): it could never be spent.")
    morning = terms(ends=utc(2026, 11, 20), not_before=utc(2026, 11, 18),
                    days=0b1100000, hours=0b1111 << 9)
    assert "(Sat, Sun and 09:00-13:00 UTC)" in refusal(morning, SENT)
    assert "(not_before)" in refusal(morning, SENT) and "(its end)" in refusal(morning, SENT)
    assert refusal(terms(ends=SENT + DAY, hold=HOUR), SENT) is None


# --- In plain words ----------------------------------------------------------------------

def test_the_walkthrough_in_plain_words():
    t = terms(5000, (500,), KIND_SECONDS, 7 * DAY, True, ends=DEC29, not_before=DEC1,
              days=0b0011111, refund_idle=14 * DAY, at_end=AT_END_REFUND)
    assert explain(t, unlock=t.unlock_at(SENT), sent=SENT, sender="Alice",
                   recipient="Bob") == (
        "Bob may spend 5,000 from Tue 2026-12-01 00:00 UTC, only on Mon-Fri (UTC), to "
        "anyone. At most 500 per week, every period; the periods count from the unlock, "
        "and nothing carries over. If Bob spends nothing for 2 weeks, what is left goes "
        "back to Alice. At Tue 2026-12-29 00:00 UTC what is left goes back to Alice. "
        "Alice cannot take it back earlier, only release the rest to Bob at once.")


def test_a_day_hold_in_plain_words():
    t = terms(100, ends=utc(2026, 11, 18), hold=6 * HOUR, at_end=AT_END_REFUND)
    sent = utc(2026, 11, 17, 10)
    assert explain(t, unlock=t.unlock_at(sent), sent=sent) == (
        "The recipient may spend 100 from Tue 2026-11-17 16:00 UTC (6 hours after it "
        "arrives), to anyone. At Wed 2026-11-18 00:00 UTC what is left goes back to the "
        "sender. The sender cannot take it back earlier, only release the rest to the "
        "recipient at once.")


def test_schedules_windows_and_blocks_in_plain_words():
    advance = terms(4000, (1000, 500), KIND_SECONDS, 30 * DAY, True, ends=SENT + 210 * DAY)
    text = explain(advance, unlock=SENT, sent=SENT)
    assert "may spend 4,000 at once" in text
    assert ("At most 1,000 and 500 in the first 2 periods of 30 days, then 500 per "
            "30 days") in text
    ramp = terms(4000, (100, 200, 400), KIND_BLOCKS, 10, ends=900)
    assert "At most 100, 200 and 400 in the first 3 periods of 10 blocks, then no limit" \
        in explain(ramp, unlock=500, sent=500)
    once = terms(100, (40,), KIND_SECONDS, HOUR, ends=SENT + DAY)
    assert "At most 40 per hour, in the first hour only" in explain(once, unlock=SENT)
    lunch = terms(300, ends=SENT + 90 * DAY, days=0b0011111, hours=0b111 << 11)
    assert "only on Mon-Fri and only 11:00-14:00 UTC, to anyone" in \
        explain(lunch, unlock=SENT, sent=SENT)
    held = terms(900, kind=KIND_BLOCKS, ends=7000, hold=100)
    assert explain(held, unlock=5100, sent=5000, remaining=850).startswith(
        "The recipient may spend 850 from block 5,100 (100 blocks after it arrives)")


# --- E6: the never-spendable check is exact --------------------------------------------------

S = 10   # the sending height of the block-clock universe


def _block_universe():
    for nb, hold, idle, end, caps, period, rec, at_end, amount in itertools.product(
            (None, 8, 10, 11, 13, 15), (None, 1, 2, 5), (None, 1, 2, 4, 7),
            (S + 1, S + 3, S + 6, S + 9), ((), (1,), (2,), (1, 3), (3, 1, 2)), (1, 2, 4),
            (False, True), (AT_END_RELEASE, AT_END_REFUND), (2, 3)):
        if not caps and (period != 1 or rec):
            continue
        yield terms(amount, caps, KIND_BLOCKS, period if caps else 0, rec and bool(caps),
                    ends=end, not_before=nb, hold=hold, refund_idle=idle, at_end=at_end)


BLOCK_UNIVERSE = list(_block_universe())


def _hw(t, clock):
    return (clock, 0) if t.kind == KIND_BLOCKS else (0, clock)


def _first_landing(t, sent, clocks):
    """The first of `clocks` at which a spend of 1 lands, through the book's check."""
    book = EnvelopeBook()
    eid = book.send(t, *_hw(t, sent))
    for clock in clocks:
        try:
            book.check_spend(EnvelopeSpend(B, eid, C, 1), *_hw(t, clock))
            return clock
        except EnvelopeRefused:
            pass
    return None


def test_never_spendable_is_exact_on_the_block_clock():
    refused = shaped = 0
    for t in BLOCK_UNIVERSE:
        if terms_problem(t):
            continue  # no condition at all: refused for its shape, not its timing
        shaped += 1
        landing = _first_landing(t, S, range(S, t.expires_at + 1))
        verdict = validate_send_shape(t, S, 0)
        assert (verdict is None) == (landing is not None), (t, verdict)
        if verdict is None:
            assert first_spend_point(t, S) == landing
            assert refusal(t, S) is None and plan(t, S)["first_spend_at"] == landing
        else:
            refused += 1
            assert "could never be spent" in refusal(t, S)
    assert len(BLOCK_UNIVERSE) == 48_000 and shaped > 47_000 and refused > 15_000


def _utc_allowed(t, ts):
    when = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc)
    return ((not t.days or (t.days >> when.weekday()) & 1)
            and (not t.hours or (t.hours >> when.hour) & 1))


def _random_seconds_envelope(r, aligned):
    unit = HOUR if aligned else 1
    sent = MON + r.randrange(7 * 24) * HOUR + (0 if aligned else r.randrange(HOUR))
    days = r.randrange(1, 127) if r.random() < 0.6 else 0
    hours = r.randrange(1, (1 << 24) - 1) if r.random() < 0.5 else 0
    if hours and r.random() < 0.3:
        start, n = r.randrange(24), r.randrange(1, 23)
        hours = sum(1 << ((start + i) % 24) for i in range(n))
    end = sent + r.randrange(1, 10 * 24) * HOUR + (0 if aligned else r.randrange(HOUR))
    nb = r.choice([None, sent - r.randrange(48) * HOUR,
                   sent + r.randrange(96) * HOUR + r.randrange(HOUR // unit) * unit])
    hold = r.choice([None, r.randrange(1, 72) * HOUR, r.randrange(1, 4) * DAY])
    idle = r.choice([None, None, r.randrange(1, 72) * HOUR, r.randrange(1, 5) * DAY])
    caps = r.choice([(), (), (1,), (2,), (1, 2)])
    period = r.choice([HOUR, 6 * HOUR, DAY, 7 * DAY]) if caps else 0
    return sent, terms(r.choice([2, 3]), caps, KIND_SECONDS, period,
                       bool(caps) and r.random() < 0.5, ends=end, not_before=nb,
                       hold=hold, days=days, hours=hours, refund_idle=idle,
                       at_end=r.choice([AT_END_RELEASE, AT_END_REFUND]))


def test_never_spendable_is_exact_with_windows():
    """Windows change only on whole hours, so the unlock and every hour boundary
    before the first due point are every moment that can differ."""
    r = random.Random(20261117)
    compared = windowed = never = 0
    while compared < 6000:
        sent, t = _random_seconds_envelope(r, aligned=r.random() < 0.5)
        unlock = t.unlock_at(sent)
        if unlock >= t.expires_at or terms_problem(t):
            continue
        due = EnvelopeState(anchor=unlock, remaining=t.amount).due_point(t)
        moments = [unlock] + list(range((unlock // HOUR + 1) * HOUR, due, HOUR))
        naive = next((m for m in moments if m < due and _utc_allowed(t, m)), None)
        assert first_spend_point(t, sent) == naive, (t, sent)
        assert (validate_send_shape(t, 0, sent) is None) == (naive is not None)
        if t.windowed:
            assert _first_landing(t, sent, moments) == naive
        compared += 1
        windowed += t.windowed
        never += naive is None
    assert windowed > 4000 and never > 300


# --- Bisimulation: a condition that "never decides" changes nothing ---------------------------

def _without(t, condition):
    return {
        "not_before": lambda: replace(t, not_before=None),
        "hold": lambda: replace(t, hold=None),
        "refund_idle": lambda: replace(t, refund_idle=None),
        "days": lambda: replace(t, days=0),
        "hours": lambda: replace(t, hours=0),
        "recurring": lambda: replace(t, recurring=False),
        "caps": lambda: replace(t, caps=(), period=0, recurring=False),
    }[condition]()


def _step(book, eid, t, clock, amount):
    """One block at `clock`: a spend of `amount` (0 = none), then the closes."""
    out = []
    if amount and eid in book.open:
        try:
            book.check_spend(EnvelopeSpend(B, eid, C, amount), *_hw(t, clock))
            book.record_spend(eid, amount, *_hw(t, clock))
            out.append(("spent", amount))
        except EnvelopeRefused:
            out.append(("refused", amount))
    out.extend(("closed", left, outcome) for _, left, outcome in book.end_due(*_hw(t, clock)))
    return out


def _where(book, eid):
    if eid not in book.open:
        return None
    st = book.state[eid]
    return (st.remaining, st.period_index, st.spent_in_period,
            st.last_clock if st.spends else None)


def bisimilar(t1, t2, sent, clocks):
    """True when, for every sequence of spends at `clocks` (each block: no spend, or
    a spend of 1 .. what the envelope holds), both envelopes accept and refuse the
    same spends and close the same way at the same clock. Pairs of states already
    seen are not walked again, so the search is exhaustive and finite. Otherwise
    the first difference: (clock, amount, what one did, what the other did)."""
    b1, b2 = EnvelopeBook(), EnvelopeBook()
    e1, e2 = b1.send(t1, *_hw(t1, sent)), b2.send(t2, *_hw(t2, sent))
    seen, stack = set(), [(0, b1, b2)]
    while stack:
        i, b1, b2 = stack.pop()
        if i == len(clocks) or (e1 not in b1.open and e2 not in b2.open):
            continue
        key = (i, _where(b1, e1), _where(b2, e2))
        if key in seen:
            continue
        seen.add(key)
        held = b1.state[e1].remaining if e1 in b1.open else 1
        for amount in range(held + 1):
            c1, c2 = copy.deepcopy(b1), copy.deepcopy(b2)
            r1, r2 = _step(c1, e1, t1, clocks[i], amount), _step(c2, e2, t2, clocks[i], amount)
            if r1 != r2:
                return False, (clocks[i], amount, r1, r2)
            stack.append((i + 1, c1, c2))
    return True, None


def _present(t):
    return [c for c, on in (("not_before", t.not_before is not None),
                            ("hold", t.hold is not None),
                            ("refund_idle", t.refund_idle is not None),
                            ("recurring", t.recurring), ("caps", bool(t.caps))) if on]


def _claimed(t, sent):
    return {n["condition"] for n in notes(t, sent)
            if n["level"] == NEVER_DECIDES and n["code"] != "CAPS_UNREACHED"}


def test_never_decides_notes_are_sound_on_the_block_clock():
    """Every condition of every spendable envelope in the universe is tried: with a
    never_decides note the pair must be bisimilar (exhaustively, at every height)."""
    pairs = notes_checked = 0
    for t in BLOCK_UNIVERSE:
        if validate_send_shape(t, S, 0) is not None:
            continue
        clocks = list(range(S, t.expires_at + 2))
        claimed = _claimed(t, S)
        for condition in claimed:
            same, why = bisimilar(t, _without(t, condition), S, clocks)
            assert same, (condition, t, why)
            notes_checked += 1
        pairs += len(claimed)
    assert notes_checked > 20_000


def test_a_condition_without_a_note_decides_something():
    """Exactness: without refund_idle on the block clock, every not_before, hold,
    limit and recurring the notes do not call idle changes some outcome; and every
    refund_idle the notes do not call idle changes one, with or without others."""
    checked = 0
    for t in BLOCK_UNIVERSE:
        if validate_send_shape(t, S, 0) is not None:
            continue
        clocks = list(range(S, t.expires_at + 2))
        claimed = _claimed(t, S)
        for condition in _present(t):
            if condition in claimed:
                continue
            if t.refund_idle is not None and condition != "refund_idle":
                continue
            same, _ = bisimilar(t, _without(t, condition), S, clocks)
            assert not same, (condition, t)
            checked += 1
    assert checked > 15_000


def test_never_decides_notes_are_sound_with_windows():
    """Random seconds-clock envelopes on whole hours (sent, conditions and blocks on
    hour boundaries), with weekdays and hours: every never_decides note holds."""
    r = random.Random(4)
    envelopes = notes_checked = 0
    seen_codes = set()
    while envelopes < 250:
        sent, t = _random_seconds_envelope(r, aligned=True)
        if (t.unlock_at(sent) >= t.expires_at or first_spend_point(t, sent) is None
                or t.expires_at - sent > 6 * DAY):
            continue
        envelopes += 1
        clocks = list(range(sent, t.expires_at + HOUR + 1, HOUR))
        for n in notes(t, sent):
            seen_codes.add(n["code"])
            if n["level"] != NEVER_DECIDES or n["code"] == "CAPS_UNREACHED":
                continue
            same, why = bisimilar(t, _without(t, n["condition"]), sent, clocks)
            assert same, (n, t, sent, why)
            notes_checked += 1
    assert {"DAYS_COVER_LIFE", "IDLE_NEVER_FIRES", "NOT_BEFORE_COVERED",
            "IDLE_BETWEEN_WINDOWS"} <= seen_codes
    assert notes_checked > 200


def test_the_search_finds_a_difference_when_there_is_one():
    """The bisimulation is not vacuous: a hold that does lock is caught at once."""
    t = terms(3, kind=KIND_BLOCKS, ends=S + 6, hold=2)
    same, why = bisimilar(t, _without(t, "hold"), S, list(range(S, S + 8)))
    assert not same and why[0] == S and why[2] == [("refused", why[1])]


# --- The walkthrough: Alice -> Bob 5,000 ---------------------------------------------------

def _cli_payload(flags, *, now, tip=0):
    from tau_testnet_cli import tx as tx_mod
    from tau_testnet_cli.cli import _envelope_terms, build_parser

    from tests.test_standing_apply import ALICE, BOB

    args = build_parser().parse_args(["envelope", "send", "--key", "alice", "--to", BOB]
                                     + shlex.split(flags))
    return tx_mod.build_envelope_send_tx(
        sender_pubkey=ALICE, sequence_number=0, expiration_time=9_999_999_999,
        expire_at_height=10_000, recipient_pubkey=BOB, amount=int(args.amount),
        fee_limit="100", **_envelope_terms(args, tip, now))


def test_alice_sends_bob_5000_with_four_conditions():
    """At most 500 a week from 1 December, only on working days, unused for 14 days
    the rest comes back, and what is left on 29 December comes back too."""
    from tests.test_envelope_apply import _accepted, _events, eid_of, env_spend
    from tests.test_envelope_conditions_apply import CondOracle
    from tests.test_standing_apply import ALICE, BOB, CAROL, PROPOSER, SKS, Chain, _logs, _sign

    payload = _cli_payload(
        "--amount 5000 --cap 500 --recurring --period 7d --not-before 2026-12-01 "
        "--days mon-fri --refund-idle 14d --ends-at 2026-12-29 --at-end refund", now=SENT)
    send = _sign({**payload, "tx_id": "walkthrough-send"}, SKS[ALICE])
    t = parse_envelope_send(send)
    assert (t.not_before, t.days, t.refund_idle, t.expires_at, t.caps, t.period) == (
        DEC1, 0b0011111, 14 * DAY, DEC29, (500,), 7 * DAY)
    assert codes(t, SENT) == {("caps", "LIMIT_LEAVES_REST")}

    bal = {ALICE: 10_000, BOB: 50, CAROL: 0, PROPOSER: 0}
    ch, oracle = Chain(dict(bal)), CondOracle(dict(bal))
    height = 100
    result = ch.block([send], height=height, ts=SENT)
    assert _accepted(result, send)
    oracle.sent(send, ts=SENT)
    eid = eid_of(send)
    seq = 0

    def block(ts, amount=None, *, lands=True, says=None, check=True):
        nonlocal height, seq
        height += 1
        txs = [] if amount is None else [env_spend(eid, amount, seq)]
        result = ch.block(txs, height=height, ts=ts)
        if amount is not None:
            assert _accepted(result, txs[0]) is lands, _logs(result)
            if lands:
                oracle.spent(eid, BOB, CAROL, amount, ts=ts)
                seq += 1
            if says:
                assert says in _logs(result)
        if check:
            oracle.check(ch)

    block(utc(2026, 11, 30, 12), 100, lands=False, says=f"locked until {DEC1}")
    block(utc(2026, 12, 1, 9), 300)                       # Tuesday, week 1
    block(utc(2026, 12, 4, 9), 250, lands=False, says="the cap 500 leaves 200")
    block(utc(2026, 12, 4, 10), 200)                      # Friday: the week is full
    block(utc(2026, 12, 5, 9), 10, lands=False, says="outside its spending window")
    block(utc(2026, 12, 8, 9), 500)                       # Tuesday, week 2
    # Nothing more: 14 days after the last spend, the rest goes back to Alice.
    block(utc(2026, 12, 22, 8, 59, 59))
    assert ch.lm.envelopes.open_count() == 1
    block(utc(2026, 12, 22, 9), check=False)
    oracle.refunded(eid, ALICE)
    oracle.check(ch)
    assert _events(ch)[-1] == {"outcome": "refunded_idle", "envelope_id": eid,
                               "sender_pubkey": ALICE, "recipient_pubkey": BOB,
                               "paid_out": 4000, "paid_to": "sender"}
    assert ch.bal[ALICE] == 10_000 - 5000 + 4000 and ch.bal[CAROL] == 1000


def test_the_walkthrough_left_alone_comes_back_at_the_end():
    """The same envelope with no idle refund: two full weeks spent, the rest is back
    on 29 December, exactly as the plan said (at most 2,000 can be spent)."""
    from tests.test_envelope_apply import _accepted, _events, eid_of, env_spend
    from tests.test_envelope_conditions_apply import CondOracle
    from tests.test_standing_apply import ALICE, BOB, CAROL, PROPOSER, SKS, Chain, _sign

    payload = _cli_payload("--amount 5000 --cap 500 --recurring --period 7d "
                           "--not-before 2026-12-01 --ends-at 2026-12-29 --at-end refund",
                           now=SENT)
    send = _sign({**payload, "tx_id": "walkthrough-end"}, SKS[ALICE])
    assert plan(parse_envelope_send(send), SENT)["most_spendable"] == 2000
    bal = {ALICE: 10_000, BOB: 50, CAROL: 0, PROPOSER: 0}
    ch, oracle = Chain(dict(bal)), CondOracle(dict(bal))
    assert _accepted(ch.block([send], height=100, ts=SENT), send)
    oracle.sent(send, ts=SENT)
    eid = eid_of(send)
    for i, day in enumerate((1, 8, 15, 22)):
        spend = env_spend(eid, 500, i)
        assert _accepted(ch.block([spend], height=101 + i, ts=utc(2026, 12, day, 9)), spend)
        oracle.spent(eid, BOB, CAROL, 500, ts=utc(2026, 12, day, 9))
    ch.block([], height=110, ts=DEC29)
    oracle.refunded(eid, ALICE)
    oracle.check(ch)
    assert _events(ch)[-1]["outcome"] == "refunded" and _events(ch)[-1]["paid_out"] == 3000


def test_the_5000_grant_500_a_week_from_1_december_and_the_rest_returns_at_the_deadline():
    """The grant with exactly its three conditions: Alice sends Bob 5,000, he can
    spend at most 500 a week, only from 1 December, and what he has not spent by the
    deadline (29 December here) returns to Alice. One `envelope send`."""
    from tests.test_envelope_apply import _accepted, _events, eid_of, env_spend
    from tests.test_envelope_conditions_apply import CondOracle
    from tests.test_standing_apply import ALICE, BOB, CAROL, PROPOSER, SKS, Chain, _logs, _sign

    payload = _cli_payload("--amount 5000 --cap 500 --recurring --period 7d "
                           "--not-before 2026-12-01 --ends-at 2026-12-29 --at-end refund",
                           now=SENT)
    send = _sign({**payload, "tx_id": "grant-send"}, SKS[ALICE])
    t = parse_envelope_send(send)
    assert (t.amount, t.caps, t.period, t.not_before, t.expires_at) == (
        5000, (500,), 7 * DAY, DEC1, DEC29)
    assert (t.hold, t.days, t.hours, t.refund_idle) == (None, 0, 0, None)

    bal = {ALICE: 10_000, BOB: 50, CAROL: 0, PROPOSER: 0}
    ch, oracle = Chain(dict(bal)), CondOracle(dict(bal))
    height, seq = 100, 0
    assert _accepted(ch.block([send], height=height, ts=SENT), send)
    oracle.sent(send, ts=SENT)
    eid = eid_of(send)

    def spend(ts, amount, *, lands=True, says=None):
        nonlocal height, seq
        height += 1
        tx = env_spend(eid, amount, seq)
        result = ch.block([tx], height=height, ts=ts)
        assert _accepted(result, tx) is lands, _logs(result)
        if lands:
            oracle.spent(eid, BOB, CAROL, amount, ts=ts)
            seq += 1
        if says:
            assert says in _logs(result)
        oracle.check(ch)

    # Not before 1 December.
    spend(utc(2026, 11, 30, 23, 59, 59), 1, lands=False, says=f"locked until {DEC1}")
    # Week 1 starts with the unlock: 500 and not one more.
    spend(DEC1, 500)
    spend(utc(2026, 12, 3, 12), 1, lands=False, says="the cap 500 leaves 0")
    spend(utc(2026, 12, 7, 23, 59, 59), 1, lands=False)
    # Week 2 starts on 8 December, on its own.
    spend(utc(2026, 12, 8), 300)
    spend(utc(2026, 12, 10), 201, lands=False, says="the cap 500 leaves 200")
    spend(utc(2026, 12, 10), 200)
    # Week 3 passes unused, and week 4 still allows 500, not 1,000.
    spend(utc(2026, 12, 22), 501, lands=False, says="the cap 500 leaves 500")
    spend(utc(2026, 12, 22), 500)
    # The deadline: no spend lands in that block, and the rest returns to Alice
    # with no transaction and no fee.
    height += 1
    late = env_spend(eid, 1, seq)
    assert not _accepted(ch.block([late], height=height, ts=DEC29), late)
    oracle.refunded(eid, ALICE)
    oracle.check(ch)
    assert _events(ch)[-1] == {"outcome": "refunded", "envelope_id": eid,
                               "sender_pubkey": ALICE, "recipient_pubkey": BOB,
                               "paid_out": 3500, "paid_to": "sender"}
    assert ch.bal[ALICE] == 10_000 - 5000 + 3500 and ch.bal[CAROL] == 1500
    assert ch.lm.envelopes.open_count() == 0


# --- Where a wallet reads it -------------------------------------------------------------

def test_the_send_preview_carries_plan_notes_and_words():
    from unittest.mock import MagicMock

    from consensus.admission import validate_envelope_send_payload
    from consensus.facade import TipAdmissionView

    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height, view.next_block_timestamp = 50, SENT
    view.envelope_book.return_value = EnvelopeBook()
    from bls_keys import pubkey_hex

    tx = {"tx_type": "envelope_send", "sender_pubkey": pubkey_hex(0x1A),
          "sequence_number": 1, "expiration_time": 9_999_999_999, "expire_at_height": 55,
          "fee_limit": "10", "recipient_pubkey": pubkey_hex(0x2B), "amount": 100,
          "clock": "seconds", "hold": 6 * HOUR, "refund_idle": DAY,
          "expires_at": SENT + DAY, "at_end": "refund"}
    result = validate_envelope_send_payload(tx, view)
    assert result.is_valid, result.error
    data = result.data
    assert data["plan"]["unlocks_at"] == SENT + 6 * HOUR
    assert data["plan"]["first_due_by"] == "end"
    assert [n["code"] for n in data["notes"]] == ["IDLE_NEVER_FIRES"]
    assert data["text"].startswith("The recipient may spend 100 from Tue 2026-11-17 15:00 UTC")
    json.dumps(data)


def test_getenvelope_answers_in_plain_words(monkeypatch):
    from commands import getenvelope

    book = EnvelopeBook()
    t = terms(600, (100,), KIND_BLOCKS, 10, True, ends=500, hold=5)
    book.send(t, 40, 0)
    book.record_spend(t.envelope_id, 60, 46, 0)
    out = getenvelope.describe_open(book, t.envelope_id, 47, 0)
    assert out["text"].startswith("The recipient may spend 540 from block 45, to anyone. "
                                  "At most 100 per 10 blocks, every period")


def test_the_cli_check_reads_without_a_key_or_a_node(capsys):
    from tau_testnet_cli.cli import main

    status = main(["envelope", "check", "--amount", "100", "--hold", "6h", "--ends-at",
                   "2026-11-18", "--at-end", "refund", "--at-time", "2026-11-17T10:00"])
    out = capsys.readouterr().out
    assert status == 0 and out.startswith("The recipient may spend 100 from Tue 2026-11-17 "
                                          "16:00 UTC (6 hours after it arrives)")
    status = main(["envelope", "check", "--amount", "100", "--hold", "2d", "--ends-at",
                   "2026-11-18", "--at-time", "2026-11-17T10:00"])
    assert status != 0 and "(the hold of 2 days)" in capsys.readouterr().out
    status = main(["--json", "envelope", "check", "--amount", "3", "--cap", "5", "--period",
                   "1h", "--ends-in", "1d", "--at-time", "2026-11-17T10:00"])
    data = json.loads(capsys.readouterr().out)
    assert status == 0 and [n["code"] for n in data["notes"]] == ["LIMIT_NEVER_BINDS"]
    status = main(["envelope", "check", "--amount", "9", "--hold-blocks", "3",
                   "--ends-in-blocks", "20"])
    assert status != 0 and "--at-height" in capsys.readouterr().err
    status = main(["envelope", "check", "--amount", "100", "--days", "mon-fri", "--hours",
                   "9-17", "--utc-offset", "+05:45", "--ends-in", "4w", "--at-time",
                   "2026-11-17T10:00"])
    out = capsys.readouterr().out
    assert status == 0 and "only on Mon-Fri and only 09:00-17:00 UTC+05:45, to anyone" in out
    status = main(["--json", "envelope", "check", "--amount", "100", "--days", "sat",
                   "--utc-offset", "-05:00", "--ends-in", "4w", "--at-time",
                   "2026-11-17T10:00"])
    data = json.loads(capsys.readouterr().out)
    # The first Saturday at UTC-05:00 starts Saturday 05:00 UTC.
    assert status == 0 and data["plan"]["first_spend_at"] == utc(2026, 11, 21, 5)


# --- The proof has teeth -------------------------------------------------------------------

MUTANTS = {
    # Unsound: a note that claims too much.
    "not_before_one_tick_late": ("terms.not_before <= held:",
                                 "terms.not_before <= held + (terms.hold is not None):"),
    "hold_one_tick_late": ("held <= terms.not_before:", "held <= terms.not_before + 1:"),
    "limit_one_short": ("min(caps) >= terms.amount", "min(caps) >= terms.amount - 1"),
    "last_period_forgotten": ("// terms.period + 1", "// terms.period"),
    "recurring_one_short": ("terms.caps[-1] >= terms.amount:", "terms.caps[-1] >= terms.amount - 1:"),
    "idle_one_tick_early": ("unlock + terms.refund_idle >= terms.expires_at",
                            "unlock + terms.refund_idle + 1 >= terms.expires_at"),
    "days_last_hour_unread": ("    while t < end:", "    while t < end - SECONDS_PER_HOUR:"),
    # Inexact: a note that is missing where the docs promise it.
    "idle_tie_missed": ("unlock + terms.refund_idle >= terms.expires_at",
                        "unlock + terms.refund_idle > terms.expires_at"),
    "not_before_tie_missed": ("terms.not_before <= held:", "terms.not_before < held:"),
}


def _mutant_notes(old, new):
    import consensus.envelope_plan as real
    import types

    with open(real.__file__) as fh:
        source = fh.read()
    assert source.count(old) == 1, old
    module = types.ModuleType("envelope_plan_mutant")
    exec(compile(source.replace(old, new), "envelope_plan_mutant", "exec"), module.__dict__)
    return module.notes


def _caught(mutant_notes):
    """Run the proofs above with the mutant's notes, only where they differ from the
    real notes (nowhere else can they fail). True when a proof rejects the mutant."""
    def claimed(fn, t, sent):
        return {n["condition"] for n in fn(t, sent)
                if n["level"] == NEVER_DECIDES and n["code"] != "CAPS_UNREACHED"}

    for t in BLOCK_UNIVERSE:
        if validate_send_shape(t, S, 0) is not None:
            continue
        real, bad = claimed(notes, t, S), claimed(mutant_notes, t, S)
        if real == bad:
            continue
        clocks = list(range(S, t.expires_at + 2))
        for condition in bad - real:            # soundness
            if not bisimilar(t, _without(t, condition), S, clocks)[0]:
                return True
        for condition in real - bad:            # exactness, where promised
            if t.refund_idle is None or condition == "refund_idle":
                return True                     # the real note is proved sound above
    r = random.Random(4)
    for _ in range(3000):
        sent, t = _random_seconds_envelope(r, aligned=True)
        if (t.unlock_at(sent) >= t.expires_at or first_spend_point(t, sent) is None
                or t.expires_at - sent > 6 * DAY):
            continue
        real, bad = claimed(notes, t, sent), claimed(mutant_notes, t, sent)
        clocks = list(range(sent, t.expires_at + HOUR + 1, HOUR))
        for condition in bad - real:
            if not bisimilar(t, _without(t, condition), sent, clocks)[0]:
                return True
    return False


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_the_proof_catches_planted_bugs(name):
    assert _caught(_mutant_notes(*MUTANTS[name])), name
