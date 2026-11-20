"""Shared cap across grants (Bounty 01, issues #63/#34).

Grants naming the same cap group share one per-period draw budget
on top of their own caps. The book-level half: combined draws bind
at the group cap even when each draw fits its own grant's cap, the
own cap still binds on its own, groups do not interfere, the period
rollover resets the shared counter, and a 108-case two-draw matrix
agrees with a plain reference counter.
"""

import pytest

import db
from consensus.grants import (
    GrantBook,
    GrantShapeError,
    GrantTerms,
    validate_grant_shape,
)

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48

DEC1 = 1764547200  # 2025-12-01 UTC
WEEK = 604800


def _terms(**kw):
    base = dict(
        sender=A, recipient=B, total=5000, cap_per_period=500,
        opens_at=DEC1, deadline=DEC1 + 4 * WEEK, sequence_number=1,
        cap_group="team-budget", cap_group_cap=600,
    )
    base.update(kw)
    return GrantTerms(**base)


def _group_book():
    book = GrantBook()
    ga = book.create(_terms())
    gb = book.create(_terms(recipient=C, sequence_number=2))
    return book, ga, gb


def test_shared_cap_combined_draws_refused():
    book, ga, gb = _group_book()
    book.apply_draw(ga.terms.grant_id, 400, ts=DEC1 + 60)
    # 400 + 200 = 600: exactly the shared cap, allowed.
    book.apply_draw(gb.terms.grant_id, 200, ts=DEC1 + 120)
    # One more unit fits gb's own cap (201 of 500) but the combined
    # 601 exceeds the shared cap.
    with pytest.raises(GrantShapeError):
        book.apply_draw(gb.terms.grant_id, 1, ts=DEC1 + 180)
    assert ga.remaining == 4600
    assert gb.remaining == 4800


def test_shared_cap_own_cap_still_binds():
    book = GrantBook()
    state = book.create(_terms(cap_group_cap=100_000))
    # The group has room for 100,000 but the grant's own cap is 500.
    with pytest.raises(GrantShapeError):
        book.apply_draw(state.terms.grant_id, 501, ts=DEC1 + 60)
    book.apply_draw(state.terms.grant_id, 500, ts=DEC1 + 60)
    assert state.remaining == 4500


def test_shared_cap_groups_do_not_interfere():
    book, ga, gb = _group_book()
    other = book.create(_terms(
        recipient=C, sequence_number=3,
        cap_group="other-budget", cap_group_cap=300))
    free = book.create(_terms(
        recipient=C, sequence_number=4, cap_group="", cap_group_cap=0))
    book.apply_draw(ga.terms.grant_id, 500, ts=DEC1 + 60)
    book.apply_draw(gb.terms.grant_id, 100, ts=DEC1 + 60)  # group full
    # A different group and an ungrouped grant are unaffected.
    book.apply_draw(other.terms.grant_id, 300, ts=DEC1 + 60)
    book.apply_draw(free.terms.grant_id, 500, ts=DEC1 + 60)
    with pytest.raises(GrantShapeError):
        book.apply_draw(other.terms.grant_id, 1, ts=DEC1 + 120)


def test_shared_cap_period_rollover_resets():
    book, ga, gb = _group_book()
    book.apply_draw(ga.terms.grant_id, 500, ts=DEC1 + 60)
    book.apply_draw(gb.terms.grant_id, 100, ts=DEC1 + 120)
    with pytest.raises(GrantShapeError):
        book.apply_draw(gb.terms.grant_id, 1, ts=DEC1 + 180)
    # Next week the shared counter starts over, under the same
    # window rule as the per-grant cap.
    book.apply_draw(gb.terms.grant_id, 500, ts=DEC1 + WEEK + 60)
    book.apply_draw(ga.terms.grant_id, 100, ts=DEC1 + WEEK + 120)
    with pytest.raises(GrantShapeError):
        book.apply_draw(ga.terms.grant_id, 1, ts=DEC1 + WEEK + 180)


def test_shared_cap_two_draw_108_cases():
    caps = [120, 240, 360]
    first_draws = [30, 60, 90, 120]
    second_draws = [30, 60, 90, 120, 150, 180, 210, 240, 270]
    cases = 0
    for cap in caps:
        for draw1 in first_draws:
            for draw2 in second_draws:
                cases += 1
                book = GrantBook()
                ga = book.create(_terms(
                    total=100_000, cap_per_period=100_000,
                    cap_group_cap=cap, sequence_number=1))
                gb = book.create(_terms(
                    recipient=C, total=100_000, cap_per_period=100_000,
                    cap_group_cap=cap, sequence_number=2))
                # draw1 always fits: it never exceeds the smallest cap.
                book.apply_draw(ga.terms.grant_id, draw1, ts=DEC1 + 60)
                # Reference counter: the second draw is accepted iff
                # the combined draws stay within the shared cap.
                try:
                    book.check_draw(gb.terms.grant_id, draw2, ts=DEC1 + 120)
                    accepted = True
                except GrantShapeError:
                    accepted = False
                assert accepted == (draw1 + draw2 <= cap), (
                    cap, draw1, draw2)
    assert cases == 108


def test_shared_cap_group_terms_must_agree():
    book, ga, gb = _group_book()
    with pytest.raises(GrantShapeError):
        book.create(_terms(recipient=C, sequence_number=5,
                           cap_group_cap=700))
    with pytest.raises(GrantShapeError):
        book.create(_terms(recipient=C, sequence_number=6,
                           opens_at=DEC1 + WEEK,
                           deadline=DEC1 + 5 * WEEK))
    # The same group name under another sender is an independent
    # group with its own cap.
    other_sender = book.create(_terms(
        sender=C, recipient=B, sequence_number=7, cap_group_cap=50))
    book.apply_draw(other_sender.terms.grant_id, 50, ts=DEC1 + 60)
    with pytest.raises(GrantShapeError):
        book.apply_draw(other_sender.terms.grant_id, 1, ts=DEC1 + 120)


def test_shared_cap_shape_rules():
    validate_grant_shape(_terms())
    validate_grant_shape(_terms(cap_group="", cap_group_cap=0))
    with pytest.raises(GrantShapeError):
        validate_grant_shape(_terms(cap_group=""))  # cap without a group
    with pytest.raises(GrantShapeError):
        validate_grant_shape(_terms(cap_group_cap=0))  # group without a cap
    with pytest.raises(GrantShapeError):
        validate_grant_shape(_terms(cap_group="has space"))


def test_shared_cap_snapshot_restore_round_trip():
    book, ga, gb = _group_book()
    book.apply_draw(ga.terms.grant_id, 400, ts=DEC1 + 60)
    book.apply_draw(gb.terms.grant_id, 200, ts=DEC1 + 120)
    restored = GrantBook.restore(book.snapshot_rows())
    assert restored.root() == book.root()
    r = restored.get(gb.terms.grant_id)
    assert r.terms.cap_group == "team-budget"
    assert r.terms.cap_group_cap == 600
    # The shared counter survived the round trip: 600 of 600 spent.
    with pytest.raises(GrantShapeError):
        restored.apply_draw(gb.terms.grant_id, 1, ts=DEC1 + 180)


@pytest.mark.usefixtures("isolated_chain_state")
def test_shared_cap_db_round_trip():
    book, ga, gb = _group_book()
    book.apply_draw(ga.terms.grant_id, 400, ts=DEC1 + 60)
    db.init_db()
    with db._db_lock:
        db._write_grant_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()
    restored = GrantBook.restore(db.load_grant_state())
    assert restored.root() == book.root()
    # 400 of the shared 600 is spent; 201 more breaks the group cap,
    # 200 exactly fills it.
    with pytest.raises(GrantShapeError):
        restored.apply_draw(gb.terms.grant_id, 201, ts=DEC1 + 120)
    restored.apply_draw(gb.terms.grant_id, 200, ts=DEC1 + 120)
    assert restored.get(gb.terms.grant_id).remaining == 4800
