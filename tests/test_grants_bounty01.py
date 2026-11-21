"""Bounty 01, stages 2-5: the grant book (consensus/grants.py), pure state.

Slice 6 of DESIGN-01-TAKEOVER.md: a funder's total is custodied by the
book at creation; the beneficiary draws against calendar-anchored
releases (a per-period cap in release form); time conditions combine by
AND at draw time; at the effective deadline the sweep refunds exactly
total - spent, once. The funder's shared cap counts every settled draw
exactly once across all their grants — the property the maintainer's
design gate asked to see proven over 108 interleavings of two grants'
draws.

Named case 5 lives here at book level and again at engine level
(test_grants_engine_bounty01.py): the 5,000 grant releasing 500/week from
Dec 1; Bob draws 500 in each of three weeks (1,500 spent); the deadline
refund returns exactly 3,500.
"""
from datetime import datetime, timezone

import pytest

from consensus.grants import (
    GrantBook,
    GrantEntry,
    GrantSharedCapEntry,
    GrantShapeError,
    effective_deadline,
    grant_capabilities,
    parse_create_grant,
    parse_draw_grant,
    parse_set_grant_shared_cap,
    period_index_at,
    release_due_ts,
    released_by,
    validate_grant_shape,
    validate_shared_cap_shape,
)
from consensus.governance import build_mechanism_metadata
from consensus.standing_payments import SCHEDULE_MONTHLY, SCHEDULE_WEEKLY

FUNDER = "aa" * 48
BOB = "bb" * 48
CAROL = "cc" * 48
OTHER_FUNDER = "dd" * 48

WEEK = 604_800
DAY = 86_400
DEC1 = int(datetime(2026, 12, 1, tzinfo=timezone.utc).timestamp())
DEADLINE = DEC1 + 8 * WEEK


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


def _book_with(entry=None, **kw):
    book = GrantBook()
    entry = entry if entry is not None else _entry(**kw)
    book.create(entry, DEC1 - 100)
    return book, entry


def _cap(**kw):
    fields = dict(
        funder_pubkey=FUNDER,
        cap_amount=500,
        period_seconds=WEEK,
        period_anchor_ts=DEC1,
        version=1,
    )
    fields.update(kw)
    return GrantSharedCapEntry(**fields)


# --- named case 5 at book level ---------------------------------------------------


def test_named_case_5_book_level():
    """5000 from Dec 1, 500/week; Bob draws 500 x 3; 3500 returns."""
    book, entry = _book_with()
    gid = entry.grant_id

    for week in range(3):
        ts = DEC1 + week * WEEK + 10
        decision = book.draw(gid, 500, ts)
        assert decision.drawn, decision.reason
        assert decision.period_index == week
    assert book.accounting(gid) == {
        "principal": 5000, "drawn": 1500, "held": 3500, "refunded": 0,
    }
    assert book.held_total() == 3500

    (expired,) = book.expired_grants(DEADLINE)
    assert expired.grant_id == gid
    refunded = book.settle_expiry_refund(gid, DEADLINE)
    assert refunded == 3500
    assert book.accounting(gid) == {
        "principal": 5000, "drawn": 1500, "held": 0, "refunded": 3500,
    }
    assert book.held_total() == 0
    assert book.status(gid, DEADLINE) == "refunded"

    # The refund settles exactly once, and nothing is drawable after it.
    with pytest.raises(ValueError):
        book.settle_expiry_refund(gid, DEADLINE)
    assert book.expired_grants(DEADLINE + WEEK) == []
    assert not book.draw(gid, 1, DEADLINE + 10).drawn


def test_refund_returns_the_unreleased_remainder_too():
    """Deadline at week 2: refund = 5000 - 500 spent = 4500, not just the
    released-but-unspent 500 — unreleased funds were held, never Bob's."""
    book, entry = _book_with(deadline_ts=DEC1 + 2 * WEEK)
    gid = entry.grant_id
    assert book.draw(gid, 500, DEC1 + 10).drawn
    assert released_by(entry, DEC1 + 2 * WEEK) == 1500
    assert book.settle_expiry_refund(gid, DEC1 + 2 * WEEK) == 4500


def test_refund_refused_before_the_deadline():
    book, entry = _book_with()
    with pytest.raises(ValueError):
        book.settle_expiry_refund(entry.grant_id, DEADLINE - 1)
    assert book.expired_grants(DEADLINE - 1) == []


# --- releases: calendar-anchored, counted exactly once -----------------------------


def test_released_by_is_a_pure_function_of_time():
    entry = _entry()
    assert released_by(entry, DEC1 - 1) == 0
    assert released_by(entry, DEC1) == 500
    assert released_by(entry, DEC1 + WEEK - 1) == 500
    assert released_by(entry, DEC1 + WEEK) == 1000
    # Capped at the total: the schedule never releases more than exists.
    assert released_by(entry, DEC1 + 52 * WEEK) == 5000
    assert period_index_at(entry, DEC1 - 1) == -1
    assert period_index_at(entry, DEC1 + 3 * WEEK + 5) == 3


def test_unreleased_funds_are_never_spendable():
    book, entry = _book_with()
    gid = entry.grant_id
    assert not book.draw(gid, 501, DEC1 + 10).drawn
    assert book.draw(gid, 500, DEC1 + 10).drawn
    # The same period's release is spent: not one more unit until week 2.
    assert not book.draw(gid, 1, DEC1 + 20).drawn
    assert book.spendable(gid, DEC1 + 20) == 0
    # Week 2 releases exactly one more 500 — the period-0 release is not
    # counted a second time by arriving at a later timestamp.
    assert book.spendable(gid, DEC1 + WEEK + 10) == 500
    assert book.draw(gid, 500, DEC1 + WEEK + 10).drawn
    assert book.accounting(gid)["drawn"] == 1000


def test_monthly_releases_clamp_and_return():
    """Signed day 31 from Jan 31: Feb releases on the 28th, March on the 31st."""
    jan31 = int(datetime(2027, 1, 31, tzinfo=timezone.utc).timestamp())
    feb28 = int(datetime(2027, 2, 28, tzinfo=timezone.utc).timestamp())
    mar31 = int(datetime(2027, 3, 31, tzinfo=timezone.utc).timestamp())
    entry = _entry(
        schedule_kind=SCHEDULE_MONTHLY, signed_day=31, start_ts=jan31,
        total_amount=10000, release_per_period=100,
        deadline_ts=jan31 + 200 * DAY,
    )
    assert validate_grant_shape(entry, jan31 - 100) is None
    assert release_due_ts(entry, 1) == feb28
    assert release_due_ts(entry, 2) == mar31
    assert released_by(entry, feb28 - 1) == 100
    assert released_by(entry, feb28) == 200
    assert released_by(entry, mar31 - 1) == 200
    assert released_by(entry, mar31) == 300


# --- time conditions -----------------------------------------------------------------


def test_conditions_combine_by_and():
    book, entry = _book_with(
        locked_until_ts=DEC1 + WEEK,
        window_start_ts=DEC1 + 2 * WEEK,
        window_end_ts=DEC1 + 3 * WEEK,
    )
    gid = entry.grant_id
    # Locked: refused even though a release has landed.
    assert not book.draw(gid, 100, DEC1 + 10).drawn
    # Unlocked but before the window: refused.
    assert not book.draw(gid, 100, DEC1 + WEEK + 10).drawn
    # Inside the window: drawn (released by then is 1500).
    assert book.draw(gid, 100, DEC1 + 2 * WEEK + 10).drawn
    # After the window closes: refused again.
    assert not book.draw(gid, 100, DEC1 + 3 * WEEK + 10).drawn


def test_never_drawable_combinations_are_refused_at_creation():
    book = GrantBook()
    cases = [
        _entry(beneficiary_pubkey=FUNDER),                    # own grant
        _entry(total_amount=0),
        _entry(release_per_period=0),
        _entry(deadline_ts=DEC1),                             # no term
        _entry(locked_until_ts=DEADLINE),                     # lock to deadline
        _entry(window_start_ts=DEADLINE, window_end_ts=DEADLINE + WEEK),
        _entry(window_start_ts=DEC1 - 2 * WEEK, window_end_ts=DEC1 - WEEK),
        _entry(version=0),
        _entry(schedule_kind=SCHEDULE_MONTHLY, signed_day=31),  # anchor is the 1st
        _entry(signed_day=15),                                # weekly takes no day
    ]
    for entry in cases:
        ok, reason = book.can_create(entry, DEC1 - 100)
        assert not ok, (entry, reason)
    ok, _ = book.can_create(_entry(), DEC1 - 100)
    assert ok


def test_inactivity_shortens_the_deadline_and_the_refund_wins():
    book, entry = _book_with(inactivity_seconds=WEEK)
    gid = entry.grant_id
    progress_deadline = DEC1 + WEEK  # no draws: last activity is the start
    assert book.deadline_of(gid) == progress_deadline
    assert book.expired_grants(progress_deadline - 1) == []
    assert book.settle_expiry_refund(gid, progress_deadline) == 5000

    # A draw moves the inactivity deadline with it.
    book, entry = _book_with(inactivity_seconds=WEEK)
    gid = entry.grant_id
    assert book.draw(gid, 500, DEC1 + 3 * DAY).drawn
    assert book.deadline_of(gid) == DEC1 + 3 * DAY + WEEK
    # One second before the moved deadline the next release is drawable...
    assert book.draw(gid, 500, DEC1 + 3 * DAY + WEEK - 1).drawn
    # ...and that draw moves the deadline again.
    assert book.deadline_of(gid) == DEC1 + 3 * DAY + 2 * WEEK - 1


def test_draw_at_the_deadline_is_refused_the_refund_wins():
    book, entry = _book_with()
    assert not book.draw(entry.grant_id, 1, DEADLINE).drawn


# --- the shared cap: the 108-history check --------------------------------------------


def _shared_cap_book():
    book = GrantBook()
    book.set_shared_cap(_cap(), DEC1 - 100)
    bob = _entry(total_amount=2000, release_per_period=2000,
                 deadline_ts=DEC1 + 52 * WEEK)
    carol = _entry(beneficiary_pubkey=CAROL, total_amount=2000,
                   release_per_period=2000, deadline_ts=DEC1 + 52 * WEEK)
    book.create(bob, DEC1 - 100)
    book.create(carol, DEC1 - 100)
    return book, bob, carol


def test_shared_cap_counts_exactly_once_across_108_histories():
    """The maintainer's design-gate check, against this book.

    Alice's shared cap is 500 for the period; her grants to Bob and Carol
    each allow 2000 of their own, so only the shared cap binds. 108
    histories = 2 (which grant draws first) x 6 (first amount 100..600)
    x 9 (second amount 100..900). In every history the sum drawn stays
    within the cap and the book's shared counter equals the true sum —
    counted exactly once. The check has teeth: some second draws are
    refused, and a per-grant-counter model would have let the sum pass
    the cap in some histories.
    """
    histories = 0
    refused_seconds = 0
    naive_would_exceed = 0
    for first_is_bob in (True, False):
        for first_amount in range(100, 700, 100):
            for second_amount in range(100, 1000, 100):
                histories += 1
                book, bob, carol = _shared_cap_book()
                first, second = (bob, carol) if first_is_bob else (carol, bob)
                d1 = book.draw(first.grant_id, first_amount, DEC1 + 10)
                d2 = book.draw(second.grant_id, second_amount, DEC1 + 10)
                total_drawn = ((first_amount if d1.drawn else 0)
                               + (second_amount if d2.drawn else 0))
                assert total_drawn <= 500, (first_amount, second_amount)
                assert book.shared_period_total(FUNDER, 0) == total_drawn
                if not d2.drawn:
                    refused_seconds += 1
                naive = min(first_amount, 2000) + min(second_amount, 2000)
                if naive > 500:
                    naive_would_exceed += 1
    assert histories == 108
    assert refused_seconds > 0
    assert naive_would_exceed > 0


def test_shared_cap_replacement_keeps_the_count():
    book, bob, _carol = _shared_cap_book()
    assert book.draw(bob.grant_id, 400, DEC1 + 10).drawn
    # Only the amount may change, and only to the next version.
    ok, _ = book.can_set_shared_cap(_cap(cap_amount=600, version=2), DEC1)
    assert ok
    ok, _ = book.can_set_shared_cap(
        _cap(cap_amount=600, version=2, period_seconds=DAY), DEC1)
    assert not ok
    ok, _ = book.can_set_shared_cap(_cap(cap_amount=600, version=3), DEC1)
    assert not ok
    book.set_shared_cap(_cap(cap_amount=600, version=2), DEC1)
    # The 400 already drawn still counts: 200 more fits, 201 does not.
    assert book.shared_period_total(FUNDER, 0) == 400
    assert not book.draw(bob.grant_id, 201, DEC1 + 20).drawn
    assert book.draw(bob.grant_id, 200, DEC1 + 20).drawn
    assert book.shared_period_total(FUNDER, 0) == 600


def test_shared_cap_is_per_funder_and_per_period():
    book, bob, _carol = _shared_cap_book()
    other = _entry(funder_pubkey=OTHER_FUNDER, total_amount=2000,
                   release_per_period=2000, deadline_ts=DEC1 + 52 * WEEK)
    book.create(other, DEC1 - 100)
    assert book.draw(bob.grant_id, 500, DEC1 + 10).drawn
    # Another funder has no cap: their draw is not counted against Alice's.
    assert book.draw(other.grant_id, 900, DEC1 + 10).drawn
    assert book.shared_period_total(OTHER_FUNDER, 0) == 0
    # Next shared period, the count starts over.
    assert book.draw(bob.grant_id, 500, DEC1 + WEEK + 10).drawn
    assert book.shared_period_total(FUNDER, 1) == 500
    assert book.shared_period_total(FUNDER, 0) == 500


# --- restore / root / accounting --------------------------------------------------------


def test_restore_recomputes_ids_and_refuses_inconsistent_rows():
    book, bob, carol = _shared_cap_book()
    book.draw(bob.grant_id, 500, DEC1 + 10)
    restored = GrantBook.restore(book.rows(), book.shared_cap_rows())
    assert restored.root() == book.root()
    assert restored.shared_period_total(FUNDER, 0) == 500

    rows = book.rows()
    tampered = [tuple(r) for r in rows]
    bad = list(tampered[0])
    bad[14] = bad[3] + 1  # total_spent beyond the total
    tampered[0] = tuple(bad)
    with pytest.raises(ValueError):
        GrantBook.restore(tampered, book.shared_cap_rows())

    bad = list(rows[0])
    bad[0] = b"\x07" * 32  # an id that does not recompute
    with pytest.raises(ValueError):
        GrantBook.restore([tuple(bad)], [])


def test_root_is_deterministic_and_tracks_progress():
    book1, bob1, _ = _shared_cap_book()
    book2, bob2, _ = _shared_cap_book()
    assert book1.root() == book2.root()
    before = book1.root()
    book1.draw(bob1.grant_id, 100, DEC1 + 10)
    assert book1.root() != before


def test_accounting_invariant_under_mixed_operations():
    book, entry = _book_with()
    gid = entry.grant_id
    book.draw(gid, 500, DEC1 + 10)
    book.draw(gid, 500, DEC1 + WEEK + 10)
    acct = book.accounting(gid)
    assert acct["principal"] == acct["drawn"] + acct["held"] + acct["refunded"]
    book.settle_expiry_refund(gid, DEADLINE)
    acct = book.accounting(gid)
    assert acct == {"principal": 5000, "drawn": 1000, "held": 0, "refunded": 4000}
    assert acct["principal"] == acct["drawn"] + acct["held"] + acct["refunded"]


def test_grants_never_supersede_and_duplicates_are_refused():
    book, entry = _book_with()
    ok, _ = book.can_create(entry, DEC1)
    assert not ok  # the exact grant already exists
    # A second, different grant between the same parties is fine: version
    # distinguishes it, and neither strands the other's held funds.
    ok, _ = book.can_create(_entry(version=2), DEC1)
    assert ok


# --- parsing ------------------------------------------------------------------------------


def test_parse_reads_root_fields_only():
    tx = {
        "sender_pubkey": FUNDER,
        "grant_beneficiary_pubkey": BOB,
        "grant_total_amount": 5000,
        "grant_release_per_period": 500,
        "grant_schedule": "weekly",
        "grant_signed_day": 0,
        "grant_start_ts": DEC1,
        "grant_deadline_ts": DEADLINE,
        "grant_version": 1,
        # Unsigned nested data must not steer the parse.
        "payload": {"grant_total_amount": 1},
    }
    entry = parse_create_grant(tx)
    assert entry.total_amount == 5000
    assert entry.grant_id == _entry().grant_id

    grant_id, amount = parse_draw_grant(
        {"grant_id": entry.grant_id.hex(), "grant_draw_amount": 250})
    assert grant_id == entry.grant_id and amount == 250

    cap = parse_set_grant_shared_cap({
        "sender_pubkey": FUNDER,
        "grant_shared_cap_amount": 500,
        "grant_shared_cap_period_seconds": WEEK,
        "grant_shared_cap_anchor_ts": DEC1,
        "grant_shared_cap_version": 1,
    })
    assert cap.cap_id == _cap().cap_id

    with pytest.raises(GrantShapeError):
        parse_create_grant({"sender_pubkey": FUNDER, "grant_schedule": "yearly"})
    with pytest.raises(GrantShapeError):
        parse_draw_grant({"grant_id": "zz", "grant_draw_amount": 1})


def test_shape_validators_are_stateless_and_shared():
    assert validate_grant_shape(_entry(), DEC1 - 100) is None
    assert validate_shared_cap_shape(_cap(), DEC1 - 100) is None
    assert validate_shared_cap_shape(_cap(cap_amount=0), DEC1) is not None
    assert validate_shared_cap_shape(_cap(period_seconds=0), DEC1) is not None


# --- capability record + meta-hash gate ------------------------------------------------------


def test_capability_record_matches_the_design_table():
    caps = grant_capabilities()
    assert caps["supported"] is True
    assert caps["draw_credit_class"] == "grant_draw"
    assert caps["refund_credit_class"] == "refund"
    assert "weekly" in caps["schedules"] and "monthly" in caps["schedules"]


def test_meta_hash_gate_grantless_chains_hash_as_before():
    plain = build_mechanism_metadata("supermajority")
    assert "grants_root" not in plain
    gated = build_mechanism_metadata("supermajority", grants_root="ab" * 32)
    assert gated["grants_root"] == "ab" * 32

    from consensus.governance import ConsensusLifecycleManager

    lm = ConsensusLifecycleManager(active_validators=[bytes.fromhex(FUNDER)])
    before = lm.consensus_meta_hash()
    lm.grants.create(_entry(), DEC1 - 100)
    assert lm.consensus_meta_hash() != before
