"""Conditional-grant book semantics (Bounty 01, issue #63).

The book-level half of the grant cases: the per-period draw cap,
the open/deadline window, and the expiry refund of the exact
remainder -- including the bounty page's worked example.
"""

import pytest

from consensus.grants import (
    GrantBook,
    GrantShapeError,
    GrantTerms,
    validate_grant_shape,
)

A = "aa" * 48
B = "bb" * 48

DEC1 = 1764547200  # 2025-12-01 UTC
WEEK = 604800


def _terms(**kw):
    base = dict(
        sender=A, recipient=B, total=5000, cap_per_period=500,
        opens_at=DEC1, deadline=DEC1 + 4 * WEEK, sequence_number=1,
    )
    base.update(kw)
    return GrantTerms(**base)


def test_grant_5000_week_cap_refund_returns_remainder():
    # The page's demo: Alice -> Bob 5,000, cap 500/week, draws open
    # December 1, unspent remainder refunds at the deadline.
    book = GrantBook()
    state = book.create(_terms())
    state.apply_draw(500, ts=DEC1 + 60)
    with pytest.raises(GrantShapeError):
        state.apply_draw(1, ts=DEC1 + 120)  # week cap binds
    state.apply_draw(500, ts=DEC1 + WEEK + 60)
    state.apply_draw(500, ts=DEC1 + 2 * WEEK + 60)
    assert state.remaining == 3500
    assert book.due_refunds(ts=DEC1 + 3 * WEEK) == []
    due = book.due_refunds(ts=DEC1 + 4 * WEEK)
    assert due == [(state.terms.grant_id, A, 3500)]
    assert state.apply_refund() == 3500
    assert state.remaining == 0
    assert book.due_refunds(ts=DEC1 + 5 * WEEK) == []


def test_grant_draw_window():
    book = GrantBook()
    state = book.create(_terms())
    with pytest.raises(GrantShapeError):
        state.check_draw(1, ts=DEC1 - 1)  # not open yet
    with pytest.raises(GrantShapeError):
        state.check_draw(1, ts=DEC1 + 4 * WEEK)  # expired; refund wins
    with pytest.raises(GrantShapeError):
        state.check_draw(5001, ts=DEC1)  # more than the grant holds
    with pytest.raises(GrantShapeError):
        state.check_draw(0, ts=DEC1)


def test_grant_shape_refuses_undrawable_combinations():
    validate_grant_shape(_terms())
    with pytest.raises(GrantShapeError):
        validate_grant_shape(_terms(opens_at=DEC1 + 4 * WEEK))  # opens at deadline
    with pytest.raises(GrantShapeError):
        validate_grant_shape(_terms(cap_per_period=0))
    with pytest.raises(GrantShapeError):
        validate_grant_shape(_terms(total=0))
    with pytest.raises(GrantShapeError):
        validate_grant_shape(_terms(recipient=A))  # to oneself


def test_grant_snapshot_restore_round_trip():
    book = GrantBook()
    state = book.create(_terms())
    state.apply_draw(500, ts=DEC1 + 60)
    restored = GrantBook.restore(book.snapshot_rows())
    assert restored.root() == book.root()
    r = restored.get(state.terms.grant_id)
    assert r.remaining == 4500
    assert r.drawn_in_period == 500
    assert r.last_draw_ts == DEC1 + 60
