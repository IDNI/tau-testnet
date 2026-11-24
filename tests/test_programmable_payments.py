"""Programmable payments through the real apply_block.

The cases maintainers asked to see by name:

- 101 routed at 20% gives 20 and 81 with one fee
- a 5% royalty on 101 pays 5, once
- a routed share never triggers another route
- a monthly payment on the 31st runs on the last day of a shorter month
- the 5,000 allowance (500 a week from 1 December) returns the right remainder

Plus the acceptance cases of #34 and #35 that this version can decide without
spend-total (#31) or protected-admin (#33) features, which are not on main.
"""
import datetime as dt

import pytest

from consensus.governance import build_mechanism_metadata
from consensus.payments import (
    TX_ALLOWANCE_DRAW,
    TX_ALLOWANCE_OPEN,
    TX_PAYOUT_EXECUTE,
    TX_PAYOUT_SET,
    TX_ROUTE_SET,
    TX_STANDING_CANCEL,
    TX_STANDING_CREATE,
    TX_STANDING_EXECUTE,
    PaymentBooks,
    restore_books,
)
from consensus.periods import DAY, WEEK, add_months, civil_to_unix, unix_parts
from tests.payment_chain import (
    ALICE,
    BOB,
    CAROL,
    CHAIN,
    PROPOSER,
    REVIEW,
    SAVE,
    SK_ALICE,
    SK_BOB,
    SK_CAROL,
    SK_SAVE,
    Chain,
    tx,
)

DEC1 = civil_to_unix(2026, 12, 1)
JAN1 = civil_to_unix(2027, 1, 1)
JAN31 = civil_to_unix(2027, 1, 31)


def _user(sender, to, amount, seq, sk, fee_limit="0"):
    return tx(
        "user_tx", sender, seq, sk, fee_limit=fee_limit,
        operations={"1": [[sender, to, amount]]},
    )


def _route(owner, seq, sk, dest, bps, **extra):
    fields = dict(
        destinations=[{"pubkey": dest, "bps": bps}],
        min_incoming=0, activate_at=0, expires_at=0, locked_until=0,
    )
    fields.update(extra)
    return tx(TX_ROUTE_SET, owner, seq, sk, **fields)


def _standing(seq, *, kind, interval, first_due, window, occurrences=3, amount=100):
    return tx(
        TX_STANDING_CREATE, ALICE, seq, SK_ALICE,
        recipient_pubkey=BOB, amount=amount, schedule_kind=kind,
        interval=interval, first_due=first_due, window=window,
        max_occurrences=occurrences, max_fee_per_execution=0,
    )


def _allowance(seq, **over):
    fields = dict(
        grantee_pubkey=BOB, amount=5000, start_at=DEC1, hold_seconds=0,
        spend_cap=500, cap_period="week", cap_length=0, per_draw_cap=0,
        weekday_mask=0, hour_mask=0, utc_offset_quarters=0,
        expires_at=JAN1, refund_idle=0, shared_key="", shared_cap=0,
        shared_period="", shared_length=0, shared_anchor=0,
    )
    fields.update(over)
    return tx(TX_ALLOWANCE_OPEN, ALICE, seq, SK_ALICE, **fields)


def _draw(seq, allowance_id, amount, dest=CAROL):
    return tx(
        TX_ALLOWANCE_DRAW, BOB, seq, SK_BOB,
        allowance_id=allowance_id, recipient_pubkey=dest, amount=amount,
    )


def _royalty(seq):
    return tx(
        TX_PAYOUT_SET, ALICE, seq, SK_ALICE,
        legs=[{"pubkey": REVIEW, "expr": {"op": "bps", "bps": 500}}],
        max_per_execution=1000, max_per_period=1000, period="week",
        period_length=0, period_anchor=0, max_executions=10,
        expires_at=JAN1 + 366 * DAY, bounded_by_gross=True, clause="",
    )


def _execute(seq, gross, event, sk=SK_CAROL, sender=CAROL):
    return tx(
        TX_PAYOUT_EXECUTE, sender, seq, sk,
        owner_pubkey=ALICE, event_id=event, gross=gross,
    )


def test_calendar_matches_datetime_and_clamps_the_31st():
    sample = dt.datetime(2026, 12, 1, tzinfo=dt.timezone.utc)
    assert civil_to_unix(2026, 12, 1) == int(sample.timestamp())
    assert unix_parts(DEC1)[:3] == (2026, 12, 1)
    feb = add_months(JAN31, 1)
    march = add_months(JAN31, 2)
    assert unix_parts(feb)[:3] == (2027, 2, 28)
    assert unix_parts(march)[:3] == (2027, 3, 31)
    leap = add_months(civil_to_unix(2028, 1, 31), 1)
    assert unix_parts(leap)[:3] == (2028, 2, 29)


def test_empty_book_does_not_change_the_meta_hash():
    mech = build_mechanism_metadata("supermajority")
    assert "programmable_payments_root" not in mech
    chain = Chain({ALICE: 1000})
    assert "programmable_payments_root" not in build_mechanism_metadata(
        "supermajority",
        programmable_payments_root="" if chain.book.is_empty() else "ff" * 32,
    )


def test_route_101_at_20pct_gives_20_and_81_one_fee():
    chain = Chain({ALICE: 1000, BOB: 0, SAVE: 0}, fee=0)
    chain.block([_route(BOB, 0, SK_BOB, SAVE, 2000)], ts=DEC1)
    chain.fee = 10
    chain.block([_user(ALICE, BOB, 101, 0, SK_ALICE, fee_limit="50")], height=21, ts=DEC1 + 10)
    assert chain.bal[BOB] == 81
    assert chain.bal[SAVE] == 20
    assert chain.bal[ALICE] == 1000 - 101 - 10
    assert chain.bal[PROPOSER] == 10
    assert chain.supply() == 1000


def test_routed_share_never_triggers_route():
    chain = Chain({ALICE: 500, BOB: 0, SAVE: 0, CAROL: 0})
    # Bob saves 20% to SAVE. SAVE would forward 50% to Carol, but a routed
    # credit is not income and must not take that hop.
    chain.block([
        _route(BOB, 0, SK_BOB, SAVE, 2000),
        _route(SAVE, 0, SK_SAVE, CAROL, 5000),
    ], ts=DEC1)
    chain.block([_user(ALICE, BOB, 101, 0, SK_ALICE)], height=21, ts=DEC1 + 1)
    assert (chain.bal[BOB], chain.bal[SAVE], chain.bal[CAROL]) == (81, 20, 0)


def test_self_route_and_over_cap_are_rejected():
    chain = Chain({BOB: 10})
    chain.block([_route(BOB, 0, SK_BOB, BOB, 1000)], ts=DEC1)
    assert chain.book.routes == {}
    assert chain.seq.get(BOB, 0) == 0
    chain.block([_route(
        BOB, 0, SK_BOB, SAVE, 9000,
        destinations=[{"pubkey": SAVE, "bps": 5000}, {"pubkey": CAROL, "bps": 5000}],
    )], ts=DEC1)
    assert BOB not in chain.book.routes


def test_royalty_5pct_on_101_pays_5_once():
    chain = Chain({ALICE: 1000, REVIEW: 0, CAROL: 0})
    chain.block([_royalty(0)], ts=DEC1)
    event = "12" * 32
    chain.block([_execute(0, 101, event)], height=21, ts=DEC1 + 1)
    assert chain.bal[REVIEW] == 5
    assert chain.bal[ALICE] == 995
    chain.block([_execute(1, 101, event)], height=22, ts=DEC1 + 2)
    assert chain.bal[REVIEW] == 5
    assert chain.bal[ALICE] == 995
    assert chain.last.outcomes[0].reason == "duplicate_event"


def test_payout_is_atomic_when_the_owner_cannot_cover_it():
    chain = Chain({ALICE: 4, REVIEW: 0, CAROL: 0})
    chain.block([_royalty(0)], ts=DEC1)
    chain.block([_execute(0, 101, "ab" * 32)], height=21, ts=DEC1 + 1)
    assert chain.bal[ALICE] == 4
    assert chain.bal[REVIEW] == 0
    assert chain.book.payouts[ALICE]["executions"] == 0


def test_monthly_on_31st_runs_last_day_short_month():
    chain = Chain({ALICE: 1000, BOB: 0})
    chain.block([_standing(
        0, kind="months", interval=1, first_due=JAN31, window=DAY, occurrences=3,
    )], ts=JAN31 - DAY)
    # The day before the 31st pays nothing.
    chain.block([], height=21, ts=JAN31 - 1)
    assert chain.bal[BOB] == 0
    chain.block([], height=22, ts=JAN31 + 10)
    assert chain.bal[BOB] == 100
    # February 2027 has no 31st. The occurrence is due on the 28th, not the 1st of March.
    feb28 = civil_to_unix(2027, 2, 28)
    chain.block([], height=23, ts=feb28 - 1)
    assert chain.bal[BOB] == 100
    chain.block([], height=24, ts=feb28 + 10)
    assert chain.bal[BOB] == 200
    march31 = civil_to_unix(2027, 3, 31)
    chain.block([], height=25, ts=march31 + 10)
    assert chain.bal[BOB] == 300
    assert chain.book.standing == {}
    assert chain.supply() == 1000


def test_standing_window_cancel_and_insufficient_funds():
    chain = Chain({ALICE: 150, BOB: 0})
    start = DEC1
    chain.block([_standing(
        0, kind="seconds", interval=WEEK, first_due=start, window=DAY, occurrences=2, amount=100,
    )], ts=start - 10)
    sid = next(iter(chain.book.standing))
    chain.block([tx(
        TX_STANDING_EXECUTE, CAROL, 0, SK_CAROL, standing_id=sid, occurrence=0,
    )], height=21, ts=start - 1)
    assert chain.last.outcomes[0].reason == "standing_not_due"
    assert chain.bal[BOB] == 0
    chain.block([], height=22, ts=start + 10)
    assert chain.bal[BOB] == 100
    # A second execution of the same occurrence is refused, and the sweep does not pay it again.
    chain.block([tx(
        TX_STANDING_EXECUTE, CAROL, 1, SK_CAROL, standing_id=sid, occurrence=0,
    )], height=23, ts=start + 20)
    assert chain.bal[BOB] == 100
    chain.block([tx(TX_STANDING_CANCEL, ALICE, 1, SK_ALICE, standing_id=sid)], height=24, ts=start + 30)
    chain.block([], height=25, ts=start + WEEK + 10)
    assert chain.bal[BOB] == 100
    assert chain.supply() == 150

    poor = Chain({ALICE: 50, BOB: 0})
    poor.block([_standing(
        0, kind="seconds", interval=WEEK, first_due=start, window=DAY, occurrences=1, amount=100,
    )], ts=start - 10)
    poor.block([], height=21, ts=start + 10)
    assert poor.bal[BOB] == 0
    assert poor.bal[ALICE] == 50
    # Still open: the window has not closed, so a top-up can pay it.
    assert poor.book.standing
    poor.bal[ALICE] = 150
    poor.block([], height=22, ts=start + 20)
    assert poor.bal[BOB] == 100


def test_wrong_chain_is_rejected_and_replay_matches():
    chain = Chain({ALICE: 1000, BOB: 0})
    bad = tx(
        TX_STANDING_CREATE, ALICE, 0, SK_ALICE, chain_id="cd" * 32,
        recipient_pubkey=BOB, amount=100, schedule_kind="seconds", interval=WEEK,
        first_due=DEC1, window=DAY, max_occurrences=1, max_fee_per_execution=0,
    )
    chain.block([bad], ts=DEC1)
    assert chain.last.outcomes[0].reason == "wrong_chain"
    assert chain.book.standing == {}
    good = Chain({ALICE: 1000, BOB: 0})
    created = _standing(0, kind="seconds", interval=WEEK, first_due=DEC1, window=DAY, occurrences=1)
    first = good.block([created], ts=DEC1 - 1)
    replay = Chain({ALICE: 1000, BOB: 0})
    second = replay.block([created], ts=DEC1 - 1, replay=True)
    assert first.next_snapshot.state_hash == second.next_snapshot.state_hash
    assert good.book.root() == replay.book.root()


def test_allowance_5000_returns_3800_after_1200_drawn():
    """Alice sends Bob 5,000. He may spend 500 a week from 1 December.

    Draws: 300 and 200 in week one (201 refused), 500 in week two, 200 in
    week three. 1,200 spent. On 1 January the remaining 3,800 returns to Alice,
    once.
    """
    chain = Chain({ALICE: 5000, BOB: 0, CAROL: 0})
    chain.block([_allowance(0)], ts=DEC1 - DAY)
    assert chain.bal[ALICE] == 0
    assert chain.book.escrow_total() == 5000
    aid = next(iter(chain.book.allowances))
    # Before 1 December the coins are locked.
    chain.block([_draw(0, aid, 1)], height=21, ts=DEC1 - 1)
    assert chain.last.outcomes[0].reason == "allowance_locked"
    assert chain.book.escrow_total() == 5000
    chain.block([_draw(0, aid, 300)], height=22, ts=DEC1 + 3600)
    chain.block([_draw(1, aid, 200), _draw(2, aid, 201)], height=23, ts=DEC1 + 3 * DAY)
    assert chain.bal[CAROL] == 500
    assert chain.last.outcomes[1].reason == "period_cap"
    chain.block([_draw(2, aid, 500)], height=24, ts=DEC1 + WEEK + 1)
    chain.block([_draw(3, aid, 200)], height=25, ts=DEC1 + 2 * WEEK + 1)
    assert chain.bal[CAROL] == 1200
    assert chain.book.escrow_total() == 3800
    chain.block([], height=26, ts=JAN1)
    assert chain.bal[ALICE] == 3800
    assert chain.book.escrow_total() == 0
    assert chain.supply() == 5000
    chain.block([], height=27, ts=JAN1 + DAY)
    assert chain.bal[ALICE] == 3800


def test_schedule_and_hold_and_idle_refund():
    # Tuesday 2026-12-01. Monday is the only open day, so that draw is refused.
    chain = Chain({ALICE: 100, BOB: 0, CAROL: 0})
    opened = chain.block([_allowance(
        0, amount=100, spend_cap=100, start_at=0, hold_seconds=2 * DAY,
        weekday_mask=1 << 0, expires_at=DEC1 + 30 * DAY, refund_idle=10 * DAY,
    )], ts=DEC1)
    assert opened.outcomes[0].status != "invalid"
    aid = next(iter(chain.book.allowances))
    chain.block([_draw(0, aid, 10)], height=21, ts=DEC1 + DAY)
    assert chain.last.outcomes[0].reason == "allowance_locked"
    # Hold ends DEC1+2d, which is a Thursday, and only Monday is allowed.
    chain.block([_draw(0, aid, 10)], height=22, ts=DEC1 + 3 * DAY)
    assert chain.last.outcomes[0].reason == "outside_schedule"
    # No draw arrives. The idle refund is measured from the unlock.
    unlock = DEC1 + 2 * DAY
    chain.block([], height=23, ts=unlock + 10 * DAY)
    assert chain.bal[ALICE] == 100
    assert chain.book.escrow_total() == 0


def test_conditions_that_can_never_be_spent_are_refused():
    chain = Chain({ALICE: 100})
    chain.block([_allowance(0, amount=100, start_at=JAN1, expires_at=DEC1)], ts=DEC1 - DAY)
    assert chain.book.allowances == {}
    assert chain.bal[ALICE] == 100
    assert chain.last.outcomes[0].reason == "never_spendable"


def test_snapshot_round_trip_preserves_the_root():
    chain = Chain({ALICE: 100, BOB: 0})
    chain.block([_standing(
        0, kind="seconds", interval=WEEK, first_due=DEC1, window=DAY, occurrences=2,
    )], ts=DEC1 - 1)
    raw = chain.book.snapshot()
    restored = restore_books(raw)
    assert restored.root() == chain.book.root()
    assert restored.standing.keys() == chain.book.standing.keys()


def test_shared_cap_two_allowances_on_one_chain():
    chain = Chain({ALICE: 2000, BOB: 0, CAROL: 0})
    common = dict(
        amount=1000, spend_cap=10_000, shared_key="week", shared_cap=500,
        shared_period="week", shared_length=0, shared_anchor=DEC1,
    )
    chain.block([
        _allowance(0, **common),
        _allowance(1, **common),
    ], ts=DEC1 - 1)
    ids = list(chain.book.allowances)
    chain.block([_draw(0, ids[0], 300)], height=21, ts=DEC1 + 1)
    chain.block([_draw(1, ids[1], 300)], height=22, ts=DEC1 + 2)
    assert chain.last.outcomes[0].reason == "shared_cap"
    assert chain.bal[CAROL] == 300
    assert chain.book.escrow_total() == 1700


def test_shared_cap_108_histories():
    """Two draws, six amounts, three arrangements. 6 * 6 * 3 = 108.

    A per-allowance counter would allow the second grant to ignore what the
    first already spent. The shared meter must refuse those.
    """
    amounts = [100, 200, 300, 400, 500, 600]
    modes = ("same", "other", "next")
    seen = 0
    for first in amounts:
        for second in amounts:
            for mode in modes:
                seen += 1
                book = PaymentBooks()
                common = dict(
                    grantee_pubkey=BOB, amount=10_000, start_at=0, hold_seconds=0,
                    spend_cap=10_000, cap_period="week", cap_length=0, per_draw_cap=0,
                    weekday_mask=0, hour_mask=0, utc_offset_quarters=0,
                    expires_at=DEC1 + 60 * DAY, refund_idle=0,
                    shared_key="cap", shared_cap=500, shared_period="week",
                    shared_length=0, shared_anchor=DEC1,
                )
                one = book.add_allowance(ALICE, 0, CHAIN, {**common}, DEC1 - 1)
                two = book.add_allowance(ALICE, 1, CHAIN, {**common}, DEC1 - 1)
                ts1 = DEC1 + 1
                ts2 = ts1 if mode != "next" else DEC1 + WEEK + 1
                target = one["id"] if mode == "same" else two["id"]
                first_reason = book.draw_block_reason(book.allowances[one["id"]], ts1, first, CAROL)
                if not first_reason:
                    book.commit_draw(one["id"], ts1, first)
                row = book.allowances.get(target)
                if row is None:
                    second_reason = "allowance_closed"
                else:
                    second_reason = book.draw_block_reason(row, ts2, second, CAROL)
                expect_first = "" if first <= 500 else "shared_cap"
                if mode == "next":
                    expect_second = "" if second <= 500 else "shared_cap"
                else:
                    spent = 0 if expect_first else first
                    expect_second = "" if spent + second <= 500 else "shared_cap"
                assert first_reason == expect_first
                assert second_reason == expect_second
                if mode == "other" and first <= 500 and first + second > 500:
                    # The case a per-grant counter gets wrong.
                    assert second_reason == "shared_cap"
    assert seen == 108


def test_direct_cycle_is_refused_but_a_later_route_cannot_loop():
    chain = Chain({ALICE: 0, BOB: 0, SAVE: 0})
    chain.block([_route(BOB, 0, SK_BOB, SAVE, 2000)], ts=DEC1)
    back = _route(SAVE, 0, SK_SAVE, BOB, 2000)
    chain.block([back], height=21, ts=DEC1 + 1)
    assert chain.last.outcomes[0].reason == "route_cycle"
    assert SAVE not in chain.book.routes
