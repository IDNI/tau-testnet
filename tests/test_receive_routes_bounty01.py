"""Bounty 01, issue #35: receive routes — the book level (slice 1).

The named tests below carry the exact names the jr11ikhsan design posted on
issue #34 promised, for the cases a pure book can prove. Engine-seam cases
(#35-5 admin at apply, #35-6 receipts, #35-8 capability endpoints) land with
the wiring slice; the names are reserved there, not faked here.
"""
import copy

import pytest

from consensus.payment_calendar import (
    clamped_day,
    last_day_of_month,
    month_index_containing,
    monthly_due_ts,
)
from consensus.receive_routes import (
    CREDIT_CLAIMED_PAYMENT,
    CREDIT_ORDINARY_TRANSFER,
    CREDIT_ROUTE_OUTPUT,
    PRODUCT_CAP_BPS,
    ReceiveRouteBook,
    ReceiveRouteEntry,
    ReceiveRouteShapeError,
    parse_install_receive_route,
    split_credit,
    validate_route_shape,
)

ALICE = "a" * 96
BOB = "b" * 96
CAROL = "c" * 96

T0 = 1_764_000_000  # an arbitrary fixed "now" for shape checks


def route(owner=ALICE, dest=BOB, bps=2000, min_amount=0, act=0, exp=0, lock=0, ver=1):
    return ReceiveRouteEntry(owner, dest, bps, min_amount, act, exp, lock, ver)


def book_with(entry, now=T0):
    book = ReceiveRouteBook()
    book.install(entry, now)
    return book


# --- The five named cases (gmikeyg) that this slice can prove -----------------


def test_route_101_at_20pct_gives_20_and_81_one_fee():
    """Named case 1 / #35 case 1: 101 at 20% -> 20 routed, 81 net.

    "One fee" at book level: the split is a single division of the gross —
    routed + net == gross exactly, one application, no second movement the
    engine could charge for. The seam slice asserts the fee itself.
    """
    book = book_with(route())
    app = book.apply_route(ALICE, 101, CREDIT_ORDINARY_TRANSFER, T0)
    assert app.applied and app.routed == 20 and app.net == 81
    assert app.routed + app.net == 101
    assert split_credit(101, 2000) == (20, 81)


def test_routed_share_never_triggers_another_route():
    """Named case 3: a routed share is a route_output credit; presenting it
    to the destination's own route must not split it again — even A->B->A."""
    book = book_with(route())  # Alice routes 20% to Bob
    book.install(route(owner=BOB, dest=ALICE), T0)  # Bob routes 20% back to Alice
    app = book.apply_route(ALICE, 101, CREDIT_ORDINARY_TRANSFER, T0)
    assert app.routed == 20
    follow = book.apply_route(BOB, app.routed, CREDIT_ROUTE_OUTPUT, T0)
    assert not follow.applied and follow.net == 20 and follow.routed == 0


def test_monthly_on_31st_runs_on_last_day_of_short_month():
    """Named case 4 (calendar core): signed day 31 clamps to the last day of
    a shorter month and returns to the 31st the month after — no drift."""
    anchor = monthly_due_ts(_ts(2026, 1, 31, 12), 31, 0)
    assert _ymd(anchor) == (2026, 1, 31)
    feb = monthly_due_ts(anchor, 31, 1)
    assert _ymd(feb) == (2026, 2, 28)  # 2026 is not a leap year
    mar = monthly_due_ts(anchor, 31, 2)
    assert _ymd(mar) == (2026, 3, 31)  # back to the signed day, not the 28th
    leap_feb = monthly_due_ts(_ts(2028, 1, 31, 12), 31, 1)
    assert _ymd(leap_feb) == (2028, 2, 29)
    assert clamped_day(2026, 4, 31) == 30 and last_day_of_month(2026, 4) == 30
    # Period membership follows the same clamped due dates.
    assert month_index_containing(anchor, 31, feb) == 1
    assert month_index_containing(anchor, 31, feb - 1) == 0


# --- #35 cases at book level ---------------------------------------------------


def test_route_applies_identically_online_or_offline():
    """#35 case 2: the split is a pure function of book state — no wallet
    input exists in the API, so two identical books decide identically."""
    left, right = book_with(route()), book_with(route())
    for gross in (1, 50, 101, 10_000):
        assert left.apply_route(ALICE, gross, CREDIT_ORDINARY_TRANSFER, T0) == (
            right.apply_route(ALICE, gross, CREDIT_ORDINARY_TRANSFER, T0)
        )


def test_normal_transfer_cannot_bypass_route():
    """#35 case 3: every ordinary transfer (and claimed payment) presented
    to an account with an active route splits; there is no opt-out field —
    an install-shaped attempt to smuggle one is ignored by the parser."""
    book = book_with(route())
    for cls in (CREDIT_ORDINARY_TRANSFER, CREDIT_CLAIMED_PAYMENT):
        app = book.apply_route(ALICE, 500, cls, T0)
        assert app.applied and app.routed == 100 and app.net == 400
    tx = {
        "sender_pubkey": ALICE,
        "route_destination_pubkey": BOB,
        "route_bps": 2000,
        "skip_route": True,
    }
    entry = parse_install_receive_route(tx)
    assert not hasattr(entry, "skip_route")


def test_invalid_and_recursive_route_sets_rejected_safely():
    """#35 case 4: self-routes, malformed destinations, over-cap shares and
    locked-without-expiry routes all fail closed at installation."""
    book = ReceiveRouteBook()
    bad = [
        route(dest=ALICE),  # self-route
        route(bps=PRODUCT_CAP_BPS + 1),  # above the v1 product cap
        route(bps=10_001),  # above 100%
        route(lock=T0 + 1000),  # locked but no expiry
        route(lock=T0 + 2000, exp=T0 + 1000),  # lock outlives expiry
        route(exp=T0 - 1),  # already expired
    ]
    for entry in bad:
        ok, reason = book.can_install(entry, T0)
        assert not ok and reason
        with pytest.raises(ValueError):
            book.install(entry, T0)
    assert book.route_count() == 0  # nothing half-installed
    with pytest.raises(ReceiveRouteShapeError):
        parse_install_receive_route(
            {"sender_pubkey": ALICE, "route_destination_pubkey": "zz", "route_bps": 1}
        )
    # Recursion across accounts is stopped by the class rule, tested above in
    # test_routed_share_never_triggers_another_route.


# --- Book mechanics --------------------------------------------------------------


def test_replacement_must_be_next_version_and_lock_binds_owner_alone():
    book = book_with(route(lock=T0 + 5000, exp=T0 + 9000))
    # While locked, the owner alone cannot replace or remove the route...
    ok, reason = book.can_install(route(bps=3000, exp=T0 + 9000, ver=2), T0)
    assert not ok and "locked" in reason
    ok, reason = book.can_remove(ALICE, T0)
    assert not ok and "locked" in reason
    # ...but the destination's authorization releases the lock...
    removed = book.remove(ALICE, T0, destination_authorized=True)
    assert removed.bps == 2000 and book.route_count() == 0
    # ...and after the lock runs out the owner acts alone again.
    book.install(route(lock=T0 + 5000, exp=T0 + 9000), T0)
    nxt = route(bps=3000, exp=T0 + 9000, ver=2)
    assert book.install(nxt, T0 + 5000) == nxt.route_id
    with pytest.raises(ValueError):
        book.install(route(bps=1000, ver=2), T0 + 5000)  # stale version


def test_activation_expiry_and_minimum_gate_the_split():
    book = book_with(route(min_amount=100, act=T0 + 100, exp=T0 + 1000))
    assert not book.apply_route(ALICE, 500, CREDIT_ORDINARY_TRANSFER, T0).applied
    assert not book.apply_route(ALICE, 50, CREDIT_ORDINARY_TRANSFER, T0 + 100).applied
    assert book.apply_route(ALICE, 500, CREDIT_ORDINARY_TRANSFER, T0 + 100).applied
    assert not book.apply_route(ALICE, 500, CREDIT_ORDINARY_TRANSFER, T0 + 1000).applied


def test_restore_recomputes_ids_and_root_is_deterministic():
    book = book_with(route())
    book.install(route(owner=BOB, dest=CAROL, bps=500), T0)
    clone = ReceiveRouteBook.restore(book.rows())
    assert clone.root() == book.root()
    assert copy.deepcopy(book).root() == book.root()
    rows = book.rows()
    tampered = [(b"\x00" * 32,) + rows[0][1:]] + rows[1:]
    with pytest.raises(ValueError):
        ReceiveRouteBook.restore(tampered)


def test_split_credit_never_burns_or_duplicates():
    for gross in (0, 1, 3, 101, 999_983):
        for bps in (0, 1, 2000, 9000, 10_000):
            routed, net = split_credit(gross, bps)
            assert routed + net == gross and 0 <= routed <= gross


def _ts(year, month, day, hour=0):
    from datetime import datetime, timezone

    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


def _ymd(ts):
    from datetime import datetime, timezone

    dt = datetime.fromtimestamp(ts, tz=timezone.utc)
    return dt.year, dt.month, dt.day
