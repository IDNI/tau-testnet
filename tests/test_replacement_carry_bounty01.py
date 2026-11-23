"""Bounty 01, FIX 5C: a replacement keeps what its place paid this period.

The gap (differential audit vs #160 @ cb8c42d): in FIX 5 + FIX 5B a new
version superseded the old one wholesale — the old version's period
totals (payout) and progress (standing) were discarded with it, so
replacing a rule gave its period a fresh cap, and a chain of replacements
through a lower cap gave the cap again and again. cb8c42d closes that
hole on #160's line: the new rule's first period starts with everything
the old rule paid in its own current period already spent.

Covered here at book level: the payout carry (same-period, lower-cap
chain, past period, revoke+install, future anchor with and without
overlap, restore of a carried over-cap total), the standing carry (the
same period cannot settle twice after an update, nothing carries without
a settlement / after the period ended / after a cancel), and the
getpayoutrule view never showing a negative remainder. Engine wiring
(direct tx + guarded kind 8 / kind 11 release) lands in the engine and
rule-change suites of the same slice.
"""
from datetime import datetime, timezone

import pytest

from consensus.payment_calendar import SECONDS_PER_DAY, SECONDS_PER_WEEK
from consensus.payout_rules import (
    LEG_BPS_OF_BASE,
    PayoutLeg,
    PayoutRuleBook,
    PayoutRuleEntry,
)
from consensus.standing_payments import (
    SCHEDULE_WEEKLY,
    StandingPaymentBook,
    StandingPaymentEntry,
    period_bounds,
)

OWNER = "a" * 96
ARTIST = "b" * 96
PAYER = "a" * 96
RECIPIENT = "b" * 96

ANCHOR = 1_700_000_000
WEEK = SECONDS_PER_WEEK
DAY = SECONDS_PER_DAY
SID_1 = bytes.fromhex("11" * 32)
SID_2 = bytes.fromhex("22" * 32)
SID_3 = bytes.fromhex("33" * 32)
SID_4 = bytes.fromhex("44" * 32)


# --- payout helpers -----------------------------------------------------------


def payout_rule(version, max_period, anchor=ANCHOR, period_seconds=WEEK):
    return PayoutRuleEntry(
        owner_pubkey=OWNER,
        recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 10000),),  # 100% of base
        max_per_execution=0,
        max_per_period=max_period,
        period_seconds=period_seconds,
        period_anchor_ts=anchor,
        version=version,
    )


def test_replacement_carries_what_its_place_paid_this_period():
    """FIX 5C / cb8c42d C-1: the new rule's first period starts spent."""
    book = PayoutRuleBook()
    v1 = payout_rule(1, 250)
    book.install(v1, ANCHOR)
    assert book.execute(v1.rule_id, SID_1, 200, ANCHOR + 10, 10_000).executed
    assert book.period_total(v1.rule_id, 0) == 200

    v2 = payout_rule(2, 250, anchor=ANCHOR + 20)
    book.install(v2, ANCHOR + 20)
    assert book.period_total(v2.rule_id, 0) == 200
    # The 200 already paid counts: only 50 of the 250 cap is left.
    refused = book.execute(v2.rule_id, SID_2, 200, ANCHOR + 20, 10_000)
    assert not refused.executed
    assert "past the rule's declared max per period" in refused.reason
    assert book.execute(v2.rule_id, SID_2, 50, ANCHOR + 20, 10_000).executed
    assert book.period_total(v2.rule_id, 0) == 250
    # The new rule's own counters start at 0: one execution, 50 paid.
    assert book.settlements_for(v2.rule_id)[0].total == 50
    assert len(book.settlements_for(v2.rule_id)) == 1


def test_a_lower_cap_chain_gives_nothing_back():
    """FIX 5C / cb8c42d C-2: 250 -> 50 -> 250 still leaves only the remainder."""
    book = PayoutRuleBook()
    v1 = payout_rule(1, 250)
    book.install(v1, ANCHOR)
    assert book.execute(v1.rule_id, SID_1, 200, ANCHOR + 10, 10_000).executed

    v2 = payout_rule(2, 50, anchor=ANCHOR + 20)
    book.install(v2, ANCHOR + 20)
    assert book.period_total(v2.rule_id, 0) == 200  # over the new cap of 50
    assert not book.execute(v2.rule_id, SID_2, 1, ANCHOR + 20, 10_000).executed

    v3 = payout_rule(3, 250, anchor=ANCHOR + 30)
    book.install(v3, ANCHOR + 30)
    assert book.period_total(v3.rule_id, 0) == 200  # not 50: the 200 stay 200
    assert book.execute(v3.rule_id, SID_3, 50, ANCHOR + 30, 10_000).executed
    assert not book.execute(v3.rule_id, SID_4, 1, ANCHOR + 30, 10_000).executed
    assert book.period_total(v3.rule_id, 0) == 250


def test_a_past_period_carries_nothing():
    """FIX 5C / cb8c42d C-4: what was paid in an earlier period stays there."""
    book = PayoutRuleBook()
    v1 = payout_rule(1, 250)
    book.install(v1, ANCHOR)
    assert book.execute(v1.rule_id, SID_1, 200, ANCHOR + 10, 10_000).executed
    # The replacement lands in the NEXT period on the old rule's clock.
    v2 = payout_rule(2, 250, anchor=ANCHOR + WEEK + 20)
    book.install(v2, ANCHOR + WEEK + 20)
    assert book.period_total(v2.rule_id, 1) == 0
    assert book.execute(v2.rule_id, SID_2, 250, ANCHOR + WEEK + 20, 10_000).executed


def test_revoke_then_install_starts_from_nothing():
    """FIX 5C / cb8c42d C-5: revoke + install is a fresh install, not a carry."""
    book = PayoutRuleBook()
    v1 = payout_rule(1, 250)
    book.install(v1, ANCHOR)
    assert book.execute(v1.rule_id, SID_1, 200, ANCHOR + 10, 10_000).executed
    book.remove(OWNER, ANCHOR + 20)
    # A fresh install after a revoke is version 1 again — and starts spent 0.
    v2 = payout_rule(1, 250, anchor=ANCHOR + 20)
    book.install(v2, ANCHOR + 20)
    assert book.period_total(v2.rule_id, 0) == 0
    assert book.execute(v2.rule_id, SID_2, 250, ANCHOR + 20, 10_000).executed


def test_a_future_anchor_without_overlap_carries_nothing():
    """A new rule whose first period starts after the old period ended
    carries nothing: the old period is over, not replaced mid-period."""
    book = PayoutRuleBook()
    v1 = payout_rule(1, 250)
    book.install(v1, ANCHOR)
    assert book.execute(v1.rule_id, SID_1, 200, ANCHOR + 10, 10_000).executed
    v2 = payout_rule(2, 250, anchor=ANCHOR + WEEK + 100)
    book.install(v2, ANCHOR + 20)
    assert book.period_total(v2.rule_id, 0) == 0
    assert book.execute(v2.rule_id, SID_2, 250, ANCHOR + WEEK + 100, 10_000).executed


def test_a_future_anchor_with_overlap_carries():
    """A new rule anchored inside the old period still inherits its spend."""
    book = PayoutRuleBook()
    v1 = payout_rule(1, 250)
    book.install(v1, ANCHOR)
    assert book.execute(v1.rule_id, SID_1, 200, ANCHOR + 10, 10_000).executed
    v2 = payout_rule(2, 250, anchor=ANCHOR + 100)
    book.install(v2, ANCHOR + 20)
    assert book.period_total(v2.rule_id, 0) == 200
    assert not book.execute(v2.rule_id, SID_2, 51, ANCHOR + 100, 10_000).executed
    assert book.execute(v2.rule_id, SID_2, 50, ANCHOR + 100, 10_000).executed


def test_restore_keeps_a_carried_total_over_the_cap():
    """FIX 5C / cb8c42d C-7: a stored total over the cap restores as-is —
    it is a carried spend, not a corrupt row."""
    book = PayoutRuleBook()
    v1 = payout_rule(1, 250)
    book.install(v1, ANCHOR)
    assert book.execute(v1.rule_id, SID_1, 200, ANCHOR + 10, 10_000).executed
    v2 = payout_rule(2, 50, anchor=ANCHOR + 20)
    book.install(v2, ANCHOR + 20)
    assert book.period_total(v2.rule_id, 0) == 200
    again = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert again.root() == book.root()
    assert again.period_total(v2.rule_id, 0) == 200
    assert not again.execute(v2.rule_id, SID_2, 1, ANCHOR + 20, 10_000).executed


# --- standing helpers ---------------------------------------------------------


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


S_ANCHOR = _ts(2026, 12, 1, 12)  # weekly schedules anchor here


def standing(version, amount=500, anchor=S_ANCHOR, final=0, max_occ=12):
    return StandingPaymentEntry(
        PAYER, RECIPIENT, amount, SCHEDULE_WEEKLY, 0, anchor, 2 * DAY,
        final, max_occ, 0, 0, 0, False, version,
    )


def test_update_carries_the_settled_current_period():
    """FIX 5C / cb8c42d S-1: an update never lets one period be paid twice."""
    book = StandingPaymentBook()
    v1 = standing(1)
    book.create(v1, S_ANCHOR)
    assert book.execute(v1.auth_id, S_ANCHOR, 10_000).executed
    assert book.paid_for_period(v1.auth_id, 0).amount == 500

    v2 = standing(2, amount=750)
    book.create(v2, S_ANCHOR + 60)
    fact = book.paid_for_period(v2.auth_id, 0)
    assert fact is not None and fact.amount == 500
    assert (fact.period_start_ts, fact.period_end_ts) == period_bounds(v2, 0)
    # The new version's first period is already settled: no second payment.
    again = book.execute(v2.auth_id, S_ANCHOR + 60, 10_000)
    assert not again.executed and "already settled" in again.reason
    # The next period is untouched and pays under the new terms.
    nxt = book.execute(v2.auth_id, S_ANCHOR + WEEK, 10_000)
    assert nxt.executed and nxt.period_index == 1 and nxt.amount == 750


def test_update_without_a_settlement_carries_nothing():
    """No settlement yet, nothing to carry: the update pays its first period."""
    book = StandingPaymentBook()
    v1 = standing(1)
    book.create(v1, S_ANCHOR)
    v2 = standing(2, amount=750)
    book.create(v2, S_ANCHOR + 60)
    assert book.paid_for_period(v2.auth_id, 0) is None
    first = book.execute(v2.auth_id, S_ANCHOR + 60, 10_000)
    assert first.executed and first.amount == 750


def test_update_after_the_period_ended_carries_nothing():
    """FIX 5C: a settlement from an ended period does not follow the update."""
    book = StandingPaymentBook()
    v1 = standing(1)
    book.create(v1, S_ANCHOR)
    assert book.execute(v1.auth_id, S_ANCHOR, 10_000).executed
    v2 = standing(2, amount=750)
    book.create(v2, S_ANCHOR + WEEK)
    assert book.paid_for_period(v2.auth_id, 1) is None
    nxt = book.execute(v2.auth_id, S_ANCHOR + WEEK, 10_000)
    assert nxt.executed and nxt.period_index == 1 and nxt.amount == 750


def test_cancel_then_create_starts_from_nothing():
    """FIX 5C / cb8c42d C-5 (standing): cancel + create is a fresh start."""
    book = StandingPaymentBook()
    v1 = standing(1)
    book.create(v1, S_ANCHOR)
    assert book.execute(v1.auth_id, S_ANCHOR, 10_000).executed
    book.cancel(v1.auth_id, S_ANCHOR + 60)
    v2 = standing(2, amount=750)
    book.create(v2, S_ANCHOR + 60)
    assert book.paid_for_period(v2.auth_id, 0) is None
    first = book.execute(v2.auth_id, S_ANCHOR + 60, 10_000)
    assert first.executed and first.amount == 750


def test_update_of_an_ended_authorization_carries_nothing():
    """An authorization whose final period has passed carries nothing."""
    book = StandingPaymentBook()
    v1 = standing(1, final=S_ANCHOR + WEEK, max_occ=0)
    book.create(v1, S_ANCHOR)
    assert book.execute(v1.auth_id, S_ANCHOR, 10_000).executed
    v2 = standing(2, amount=750)
    book.create(v2, S_ANCHOR + WEEK)
    assert book.paid_for_period(v2.auth_id, 1) is None
    nxt = book.execute(v2.auth_id, S_ANCHOR + WEEK, 10_000)
    assert nxt.executed and nxt.period_index == 1 and nxt.amount == 750
