"""Conditional grant book: terms validation, draws, caps, windows, expiry."""
import copy
from datetime import datetime, timezone

import pytest

from consensus import grants as G
from consensus import periods as P

ALICE = "a1" * 48
BOB = "b0" * 48
CAROL = "c0" * 48
SHOP = "d0" * 48


def ts(*args):
    return int(datetime(*args, tzinfo=timezone.utc).timestamp())


NOW = ts(2026, 11, 20)
DEC1 = ts(2026, 12, 1)
DEADLINE = ts(2027, 3, 1)


def create_tx(**over):
    tx = {
        "tx_type": G.TX_TYPE_GRANT_CREATE,
        "sender_pubkey": ALICE,
        "grantee_pubkey": BOB,
        "amount": 5000,
        "sequence_number": 7,
        "start_at": DEC1,
        "expires_at": DEADLINE,
        "spend_cap": 500,
        "cap_period_kind": P.PERIOD_WEEK,
    }
    tx.update(over)
    return tx


def demo_book():
    book = G.GrantBook()
    terms = G.parse_grant_create(create_tx())
    ok, reason = book.can_admit_create(terms, NOW)
    assert ok, reason
    gid = book.submit(terms, NOW)
    return book, gid


def draw(gid, amount, sender=BOB, to=SHOP):
    return G.GrantDraw(sender, gid, to, amount)


# --- parsing and terms ---------------------------------------------------------


def test_defaults_refund_to_grantor_and_allow_every_slot():
    t = G.parse_grant_create(create_tx())
    assert t.refund_to_pubkey == ALICE
    assert t.weekday_mask == P.ALL_WEEKDAYS_MASK and t.hour_mask == P.ALL_HOURS_MASK
    assert t.revocable is False


def test_grant_id_depends_on_every_signed_term():
    base = G.parse_grant_create(create_tx()).grant_id
    for field, value in [
        ("amount", 5001), ("sequence_number", 8), ("start_at", DEC1 + 1),
        ("expires_at", DEADLINE + 1), ("spend_cap", 499), ("hour_mask", 1),
        ("weekday_mask", 1), ("per_payment_cap", 100), ("revocable", True),
        ("refund_to_pubkey", CAROL), ("grantee_pubkey", CAROL),
    ]:
        assert G.parse_grant_create(create_tx(**{field: value})).grant_id != base, field


@pytest.mark.parametrize(
    "over,needle",
    [
        ({"amount": 0}, "amount"),
        ({"grantee_pubkey": ALICE}, "differ"),
        ({"expires_at": NOW}, "future"),
        ({"expires_at": NOW + G.MAX_GRANT_HORIZON_SECONDS + 1}, "ahead"),
        ({"start_at": DEADLINE}, "before expires_at"),
        ({"spend_cap": 5001}, "spend_cap"),
        ({"per_payment_cap": 5001}, "per_payment_cap"),
        ({"cap_period_kind": 9}, "cap period"),
        ({"cap_period_kind": P.PERIOD_FIXED, "cap_period_seconds": 10}, "cap period"),
        ({"weekday_mask": 0}, "weekday_mask"),
        ({"hour_mask": 0}, "hour_mask"),
        ({"hour_mask": 1 << 24}, "hour_mask"),
    ],
)
def test_invalid_terms_are_rejected(over, needle):
    reason = G.validate_grant_terms(G.parse_grant_create(create_tx(**over)), NOW)
    assert reason and needle in reason


@pytest.mark.parametrize(
    "over",
    [{"sender_pubkey": "zz"}, {"amount": -1}, {"amount": True}, {"revocable": 1},
     {"expires_at": None}, {"refund_to_pubkey": "nope"}],
)
def test_malformed_create_raises_shape_error(over):
    with pytest.raises(G.GrantShapeError):
        G.parse_grant_create(create_tx(**over))


def test_malformed_draw_and_cancel_raise():
    with pytest.raises(G.GrantShapeError):
        G.parse_grant_draw({"sender_pubkey": BOB, "grant_id": "xy", "recipient_pubkey": SHOP, "amount": 1})
    with pytest.raises(G.GrantShapeError):
        G.parse_grant_cancel({"sender_pubkey": ALICE})


# --- the Alice/Bob demo ---------------------------------------------------------


def test_demo_time_lock_weekly_cap_and_refund():
    book, gid = demo_book()
    assert book.escrow_total() == 5000

    ok, reason = book.can_admit_draw(draw(gid, 100), ts(2026, 11, 30, 23, 59))
    assert not ok and "time-locked" in reason

    tue = ts(2026, 12, 1, 10)  # week of Mon 2026-11-30
    book.draw(draw(gid, 300), tue)
    book.draw(draw(gid, 200), tue + 3600)
    ok, reason = book.can_admit_draw(draw(gid, 1), ts(2026, 12, 6, 23, 59))
    assert not ok and "spending cap" in reason

    mon = ts(2026, 12, 7)  # new ISO week: cap resets
    assert book.get(gid).drawable_now(mon) == 500
    book.draw(draw(gid, 500), mon)
    assert book.get(gid).remaining == 4000
    assert book.escrow_total() == 4000

    ok, reason = book.can_admit_draw(draw(gid, 1), DEADLINE)
    assert not ok and "expired" in reason
    assert not book.has_due(DEADLINE - 1) and book.has_due(DEADLINE)
    expired = book.expire_due(DEADLINE)
    assert [s.remaining for s in expired] == [4000]
    assert expired[0].terms.refund_to_pubkey == ALICE
    assert book.open_count() == 0 and book.escrow_total() == 0
    assert book.resolved_count == 1


def test_only_grantee_draws_and_only_within_remaining():
    book, gid = demo_book()
    ok, reason = book.can_admit_draw(draw(gid, 1, sender=CAROL), DEC1)
    assert not ok and "grantee" in reason
    ok, reason = book.can_admit_draw(G.GrantDraw(BOB, b"\x00" * 32, SHOP, 1), DEC1)
    assert not ok and "unknown" in reason
    with pytest.raises(ValueError):
        book.draw(draw(gid, 501), DEC1)


def test_per_payment_cap_and_time_window():
    book = G.GrantBook()
    terms = G.parse_grant_create(create_tx(
        spend_cap=0, per_payment_cap=50,
        weekday_mask=1 << 0,  # Mondays
        hour_mask=(1 << 9) | (1 << 10),  # 09:00-10:59 UTC
    ))
    gid = book.submit(terms, NOW)
    monday_9 = ts(2026, 12, 7, 9, 30)
    assert book.can_admit_draw(draw(gid, 50), monday_9)[0]
    ok, reason = book.can_admit_draw(draw(gid, 51), monday_9)
    assert not ok and "per-payment" in reason
    for when in (ts(2026, 12, 7, 11), ts(2026, 12, 8, 9, 30)):
        ok, reason = book.can_admit_draw(draw(gid, 1), when)
        assert not ok and "days or hours" in reason


def test_draw_that_empties_the_grant_resolves_it():
    book = G.GrantBook()
    gid = book.submit(G.parse_grant_create(create_tx(amount=100, spend_cap=0)), NOW)
    book.draw(draw(gid, 100), DEC1)
    assert book.get(gid) is None and book.resolved_count == 1 and book.escrow_total() == 0


def test_cancel_needs_revocable_and_grantor():
    book = G.GrantBook()
    gid = book.submit(G.parse_grant_create(create_tx()), NOW)
    ok, reason = book.can_admit_cancel(G.GrantCancel(ALICE, gid), NOW)
    assert not ok and "revocable" in reason

    gid2 = book.submit(G.parse_grant_create(create_tx(revocable=True, sequence_number=8)), NOW)
    ok, reason = book.can_admit_cancel(G.GrantCancel(BOB, gid2), NOW)
    assert not ok and "grantor" in reason
    assert book.can_admit_cancel(G.GrantCancel(ALICE, gid2), NOW)[0]
    state = book.cancel(gid2)
    assert state.remaining == 5000 and book.open_count() == 1


def test_fixed_period_cap_anchored_at_start():
    book = G.GrantBook()
    terms = G.parse_grant_create(create_tx(
        cap_period_kind=P.PERIOD_FIXED, cap_period_seconds=3 * 86_400, spend_cap=100,
    ))
    gid = book.submit(terms, NOW)
    book.draw(draw(gid, 100), DEC1)
    assert not book.can_admit_draw(draw(gid, 1), DEC1 + 3 * 86_400 - 1)[0]
    assert book.can_admit_draw(draw(gid, 100), DEC1 + 3 * 86_400)[0]


# --- limits, determinism, persistence ---------------------------------------------


def test_per_grantor_limit():
    book = G.GrantBook()
    for seq in range(G.MAX_OPEN_GRANTS_PER_GRANTOR):
        book.submit(G.parse_grant_create(create_tx(sequence_number=seq)), NOW)
    ok, reason = book.can_admit_create(
        G.parse_grant_create(create_tx(sequence_number=999)), NOW
    )
    assert not ok and "open grants" in reason


def test_duplicate_grant_rejected():
    book, gid = demo_book()
    ok, reason = book.can_admit_create(G.parse_grant_create(create_tx()), NOW)
    assert not ok and "exists" in reason


def test_root_tracks_state_and_is_order_independent():
    a, gid = demo_book()
    r0 = a.root()
    a.draw(draw(gid, 10), DEC1)
    assert a.root() != r0

    t1 = G.parse_grant_create(create_tx(sequence_number=1))
    t2 = G.parse_grant_create(create_tx(sequence_number=2))
    x, y = G.GrantBook(), G.GrantBook()
    x.submit(t1, NOW); x.submit(t2, NOW)
    y.submit(t2, NOW); y.submit(t1, NOW)
    assert x.root() == y.root()


def test_deepcopy_is_independent():
    book, gid = demo_book()
    clone = copy.deepcopy(book)
    clone.draw(draw(gid, 10), DEC1)
    assert book.get(gid).remaining == 5000
    assert clone.get(gid).remaining == 4990
    assert book.root() != clone.root()


def test_restore_roundtrip_and_tamper_detection():
    book, gid = demo_book()
    book.draw(draw(gid, 123), DEC1)
    rows = [
        (bytes.fromhex(r["grant_id"]), G.parse_grant_create({
            "sender_pubkey": r["grantor_pubkey"], "grantee_pubkey": r["grantee_pubkey"],
            "refund_to_pubkey": r["refund_to_pubkey"], "amount": r["amount"],
            "sequence_number": r["sequence_number"], "start_at": r["start_at"],
            "expires_at": r["expires_at"], "spend_cap": r["spend_cap"],
            "cap_period_kind": r["cap_period_kind"], "cap_period_seconds": r["cap_period_seconds"],
            "per_payment_cap": r["per_payment_cap"], "weekday_mask": r["weekday_mask"],
            "hour_mask": r["hour_mask"], "revocable": r["revocable"],
        }), r["remaining"], r["cap_period_index"], r["spent_in_period"])
        for r in book.snapshot_rows()
    ]
    restored = G.GrantBook.restore(rows, *book.resolved_state())
    assert restored.root() == book.root()
    assert restored.escrow_total() == book.escrow_total() == 4877

    bad = [(b"\x01" * 32,) + rows[0][1:]]
    with pytest.raises(ValueError):
        G.GrantBook.restore(bad, 0, G.ZERO_ACC)
    with pytest.raises(ValueError):
        G.GrantBook.restore([rows[0][:2] + (0,) + rows[0][3:]], 0, G.ZERO_ACC)
