"""Envelope time conditions: parsing, ids, signing, the book,
admission, storage, RPC, the miner wake and the CLI.

The block-apply behaviour is in test_envelope_conditions_apply.py and the random
search against a reference model in test_envelope_conditions_model.py.
"""
import argparse
import hashlib
import json
from unittest.mock import MagicMock

import pytest

import chain_state
import db
from commands import getenvelope
from consensus.admission import (
    validate_envelope_send_payload,
    validate_envelope_spend_payload,
)
from consensus.envelope import (
    ALL_DAYS,
    ALL_HOURS,
    KIND_BLOCKS,
    KIND_SECONDS,
    OUTCOME_ENDED,
    EnvelopeBook,
    EnvelopeRefused,
    EnvelopeShapeError,
    EnvelopeSpend,
    EnvelopeTerms,
    describe,
    first_spend_point,
    hour_of,
    parse_envelope_send,
    weekday,
)
from consensus.facade import TipAdmissionView
from consensus.governance import ConsensusLifecycleManager
from consensus.tx_signing import signing_message_bytes
from errors import DatabaseError
from network.service import NetworkService

from bls_keys import pubkey_hex

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
C = pubkey_hex(0x3C)
NEXT_HEIGHT = 50
TS = 1_767_225_600            # Thursday 2026-01-01 00:00 UTC
HOUR, DAY = 3600, 86400
FAR = 9_999_999_999


def send(**over):
    """A conditioned envelope_send: no caps, seconds clock, unless overridden."""
    tx = {
        "tx_type": "envelope_send", "sender_pubkey": A, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
        "recipient_pubkey": B, "amount": 1000, "clock": "seconds",
        "expires_at": TS + 10 * DAY,
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def spend(eid, amount=50, signer=B, to=C):
    return {"tx_type": "envelope_spend", "sender_pubkey": signer, "sequence_number": 0,
            "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
            "envelope_id": eid, "to_pubkey": to, "amount": amount}


@pytest.fixture
def book():
    return EnvelopeBook()


@pytest.fixture
def tip_view(book):
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = TS
    view.next_block_timestamp = TS
    view.envelope_book.return_value = book
    view.clause_for.return_value = None
    return view


def _opened(book, height=NEXT_HEIGHT - 5, ts=TS, **over):
    terms = parse_envelope_send(send(**over))
    book.send(terms, height, ts)
    return terms


# --- the clock arithmetic ---------------------------------------------------------------

def test_weekday_and_hour_are_utc():
    assert weekday(0) == 3                       # 1970-01-01 was a Thursday
    assert weekday(TS) == 3 and weekday(TS + 4 * DAY) == 0
    assert weekday(TS + 3 * DAY - 1) == 5        # Saturday 23:59:59
    assert [hour_of(TS + h * HOUR + 59) for h in (0, 9, 23)] == [0, 9, 23]


def test_windows_are_read_at_the_envelopes_offset():
    """TS is Thursday 2026-01-01 00:00 UTC."""
    office = parse_envelope_send(send(days=["mon", "tue", "wed", "thu", "fri"],
                                      hours=list(range(9, 17)), utc_offset=4))   # UTC+01:00
    assert not office.in_window(TS + 8 * HOUR - 1) and office.in_window(TS + 8 * HOUR)
    assert office.in_window(TS + 16 * HOUR - 1) and not office.in_window(TS + 16 * HOUR)
    # A Friday at UTC+01:00 runs from Thursday 23:00 UTC to Friday 23:00 UTC ...
    friday = parse_envelope_send(send(days=["fri"], utc_offset=4))
    assert not friday.in_window(TS + 23 * HOUR - 1) and friday.in_window(TS + 23 * HOUR)
    assert friday.in_window(TS + DAY + 23 * HOUR - 1)
    assert not friday.in_window(TS + DAY + 23 * HOUR)
    # ... and a Thursday at UTC-05:00 from Thursday 05:00 UTC to Friday 05:00 UTC.
    thursday = parse_envelope_send(send(days=["thu"], utc_offset=-20))
    assert not thursday.in_window(TS + 5 * HOUR - 1) and thursday.in_window(TS + 5 * HOUR)
    assert thursday.in_window(TS + DAY + 5 * HOUR - 1)
    assert not thursday.in_window(TS + DAY + 5 * HOUR)
    # Noon at UTC+05:45 is 06:15 to 07:15 UTC: windows open on a quarter hour of UTC.
    noon = parse_envelope_send(send(hours=[12], utc_offset=23))
    opens = TS + 6 * HOUR + 15 * 60
    assert not noon.in_window(opens - 1) and noon.in_window(opens)
    assert noon.in_window(opens + HOUR - 1) and not noon.in_window(opens + HOUR)
    assert noon.next_window(TS) == opens and noon.next_window(opens + 7) == opens + 7
    assert noon.next_window(opens + HOUR) == opens + DAY
    # Both ends of the range, and the same wall-clock hour is 26 hours apart in UTC.
    east = parse_envelope_send(send(hours=[0], utc_offset=56))      # UTC+14:00
    west = parse_envelope_send(send(hours=[0], utc_offset=-48))     # UTC-12:00
    assert east.next_window(TS + 1) == TS + 10 * HOUR
    assert west.next_window(TS + 1) == TS + 12 * HOUR
    assert west.next_window(TS + 1) - (east.next_window(TS + 1) - DAY) == 26 * HOUR
    # Left out, the windows are UTC as before.
    utc = parse_envelope_send(send(hours=[12]))
    assert utc.utc_offset == 0 and utc.next_window(TS) == TS + 12 * HOUR


def test_the_first_spend_point_follows_the_offset():
    # Noon at UTC+05:45 opens 06:15 UTC: an envelope ending 06:30 UTC can be spent,
    # one ending 06:15 UTC cannot (the end itself is never spendable).
    spendable = parse_envelope_send(send(hours=[12], utc_offset=23,
                                         expires_at=TS + 6 * HOUR + 30 * 60))
    assert first_spend_point(spendable, TS) == TS + 6 * HOUR + 15 * 60
    never = parse_envelope_send(send(hours=[12], utc_offset=23,
                                     expires_at=TS + 6 * HOUR + 15 * 60))
    assert first_spend_point(never, TS) is None


def test_unlock_takes_the_later_of_not_before_and_hold():
    t = parse_envelope_send(send(hold=HOUR))
    assert t.unlock_at(TS) == TS + HOUR
    t = parse_envelope_send(send(not_before=TS + 5 * HOUR, hold=HOUR))
    assert t.unlock_at(TS) == TS + 5 * HOUR and t.unlock_at(TS + 5 * HOUR) == TS + 6 * HOUR
    assert parse_envelope_send(send(days=["mon"])).unlock_at(TS) == TS


def test_next_window():
    t = parse_envelope_send(send(days=["sat", "sun"], hours=[10]))
    assert t.next_window(TS) == TS + 2 * DAY + 10 * HOUR
    assert t.next_window(TS + 2 * DAY + 10 * HOUR + 3599) == TS + 2 * DAY + 10 * HOUR + 3599
    assert t.next_window(TS + 2 * DAY + 11 * HOUR) == TS + 3 * DAY + 10 * HOUR
    assert t.next_window(TS + 3 * DAY + 11 * HOUR) == TS + 9 * DAY + 10 * HOUR
    assert parse_envelope_send(send(hold=1)).next_window(TS + 7) == TS + 7


def test_first_spend_point():
    assert first_spend_point(parse_envelope_send(send(hold=HOUR)), TS) == TS + HOUR
    t = parse_envelope_send(send(days=["mon"], expires_at=TS + 2 * DAY))
    assert first_spend_point(t, TS) is None                  # Thursday + 2 days < Monday
    t = parse_envelope_send(send(days=["mon"], expires_at=TS + 4 * DAY))
    assert first_spend_point(t, TS) is None                  # it ends at Monday 00:00
    t = parse_envelope_send(send(days=["mon"], expires_at=TS + 4 * DAY + 1))
    assert first_spend_point(t, TS) == TS + 4 * DAY


# --- parsing and shape --------------------------------------------------------------------

def test_the_conditions_parse():
    t = parse_envelope_send(send(not_before=TS + 5, hold=7, days=["mon", "fri"],
                                 hours=[0, 9, 23]))
    assert (t.not_before, t.hold) == (TS + 5, 7)
    assert t.days == 0b10001 and t.hours == (1 | 1 << 9 | 1 << 23)
    assert t.caps == () and t.period == 0 and t.kind == KIND_SECONDS and t.extended


@pytest.mark.parametrize("over, why", [
    ({"clock": None}, "names its clock"),
    ({"clock": "hours"}, "clock must be one of"),
    ({"caps": [10], "clock": "blocks", "period_seconds": 60}, "does not match"),
    ({"period_blocks": 10}, "needs caps"),
    ({"recurring": True}, "recurring needs caps"),
    ({"days": "mon"}, "days must be a list"),
    ({"days": []}, "days must be a list"),
    ({"days": ["monday"]}, "days must be a list"),
    ({"days": ["fri", "mon"]}, "Monday first"),
    ({"days": ["mon", "mon"]}, "Monday first"),
    ({"hours": [24]}, "hours must be a list"),
    ({"hours": [True]}, "hours must be a list"),
    ({"hours": [9, 8]}, "increasing order"),
    ({"hold": -1}, "hold must be"),
    ({"not_before": 2 ** 64}, "not_before must be"),
    ({"hours": [9], "utc_offset": 57}, "utc_offset must be a whole number of quarter hours"),
    ({"hours": [9], "utc_offset": -49}, "utc_offset must be"),
    ({"hours": [9], "utc_offset": 1.5}, "utc_offset must be"),
    ({"hours": [9], "utc_offset": "8"}, "utc_offset must be"),
    ({"hours": [9], "utc_offset": True}, "utc_offset must be"),
    ({"hours": [9], "utc_offset": 0}, "leave utc_offset out"),
])
def test_malformed_conditions(over, why):
    with pytest.raises(EnvelopeShapeError, match=why):
        parse_envelope_send(send(**over))


def test_every_condition_changes_the_envelope_id():
    base = parse_envelope_send(send(hold=5)).envelope_id
    seen = {base}
    for over in ({"not_before": TS}, {"hold": 1}, {"days": ["mon"]}, {"hours": [1]},
                 {"clock": "blocks", "expires_at": 900},
                 {"days": ["tue"]}, {"hours": [2]}, {"hold": 2}, {"not_before": TS + 1},
                 {"hours": [1], "utc_offset": 8}, {"hours": [1], "utc_offset": -8},
                 {"days": ["mon"], "utc_offset": 8}):
        eid = parse_envelope_send(send(**{"hold": 5, **over})).envelope_id
        assert eid not in seen, over
        seen.add(eid)


def test_a_spending_limit_envelope_keeps_its_id_signature_and_root():
    """Pinned from the spending-limit release: the time conditions change nothing
    for an envelope that does not use them (no id, signature or commitment moves)."""
    tx = {"tx_type": "envelope_send", "sender_pubkey": A, "sequence_number": 1,
          "expiration_time": FAR, "expire_at_height": 55, "fee_limit": "10",
          "recipient_pubkey": B, "amount": 1000, "caps": [300, 100], "period_blocks": 10,
          "recurring": True, "expires_at": 550, "genesis_hash": "5a" * 32}
    tx2 = {k: v for k, v in dict(tx, sequence_number=2, period_seconds=3600,
                                 expires_at=1_767_312_000, recurring=False).items()
           if k != "period_blocks"}
    t1, t2 = parse_envelope_send(tx), parse_envelope_send(tx2)
    assert t1.envelope_id.hex() == \
        "1b8af9c6ad0ab93acfbdca9902276e65c0861a6b1e61cd72f39c5bc93880664c"
    assert t2.envelope_id.hex() == \
        "ffd7cb57579e3ef4ae109048c15af1b067ce2ee1ff462a7c19b7724eb8942687"
    assert hashlib.sha256(signing_message_bytes(tx)).hexdigest() == \
        "acb68214bb16a1166516cf2b7109ff270b0f49030b8232158855d230dbd89cc2"
    assert hashlib.sha256(signing_message_bytes(tx2)).hexdigest() == \
        "6668ba8eb983cb64ec7b14916a31a924d5a060d96d8468bf3871d02d0bf9572f"
    book = EnvelopeBook()
    book.send(t1, 45, TS)
    book.send(t2, 45, TS)
    book.record_spend(t1.envelope_id, 250, 50, TS + 100)
    assert book.root().hex() == \
        "27762612f231f658156b68aab0c73f2d6549c054456bdc7bdbcf03814d38eaca"
    book.end_due(10**6, 10**10)
    assert book.root().hex() == \
        "cfa0235aafe2b4decd627047938c652e06762cfd2b7a9cbfe74e0d8361615f28"


def test_a_time_conditioned_envelope_keeps_its_id_signature_and_root():
    """Pinned at the release of the time conditions. A later release that adds
    conditions must leave these values as they are, so no stored envelope, no id
    and no commitment changes for an envelope that is already open."""
    tx = {"tx_type": "envelope_send", "sender_pubkey": A, "sequence_number": 1,
          "expiration_time": FAR, "expire_at_height": 55, "fee_limit": "10",
          "recipient_pubkey": B, "amount": 1000, "caps": [300, 100],
          "period_seconds": 3600, "recurring": True, "expires_at": TS + 30 * 86_400,
          "not_before": TS + 7200, "hold": 600,
          "days": ["mon", "tue", "wed", "thu", "fri"], "hours": [9, 10, 11, 22],
          "utc_offset": 23, "genesis_hash": "5a" * 32}
    tx2 = {"tx_type": "envelope_send", "sender_pubkey": A, "sequence_number": 2,
           "expiration_time": FAR, "expire_at_height": 55, "fee_limit": "10",
           "recipient_pubkey": B, "amount": 500, "clock": "blocks", "hold": 5,
           "expires_at": 550, "genesis_hash": "5a" * 32}
    t1, t2 = parse_envelope_send(tx), parse_envelope_send(tx2)
    assert t1.envelope_id.hex() == \
        "06b973acea2055a4da3bbcb90e8a6862e02fa96f339aa2c0c59377133d9f5da6"
    assert t2.envelope_id.hex() == \
        "2dfcbd8de0e5c15109de8cd7d35ff34a66e25b5032ef5754fdfcceee8a908293"
    assert hashlib.sha256(signing_message_bytes(tx)).hexdigest() == \
        "4fc50d9a5106b9307da892183b9cca455b42ef1b098c87ca83df04e85f82af17"
    assert hashlib.sha256(signing_message_bytes(tx2)).hexdigest() == \
        "d6707fccb69a3606f543e2aaf435b5cfb6d9a54ac9c334caeb896fc8a3d51bb9"
    book = EnvelopeBook()
    book.send(t1, 45, TS)
    book.send(t2, 45, TS)
    assert book.root().hex() == \
        "9c474985a07d0a7db22cd910247b2524cffe7e219f3c1869458691da47881dce"
    book.record_spend(t1.envelope_id, 250, 60, TS + 86_400 + 9 * 3600)
    book.record_spend(t2.envelope_id, 120, 51, TS + 100)
    assert book.root().hex() == \
        "f6c151ac3b1cf9f71ccd6e2e481b0507ff1a301ca7a8ee83456a0d97200bd0dd"
    book.end_due(10**6, 10**10)
    assert book.root().hex() == \
        "07c3e59ce1b4b9afd1ae3f1ba7793e4d59cb87b746a15615f94bcac9ad07ac09"


@pytest.mark.parametrize("field, value", [
    ("clock", "blocks"), ("not_before", TS + 1), ("hold", 61), ("days", ["tue"]),
    ("hours", [10]), ("utc_offset", -8),
])
def test_every_condition_is_signed_and_cannot_be_stripped(field, value):
    tx = send(not_before=TS, hold=60, days=["mon"], hours=[9], utc_offset=8)
    signed = signing_message_bytes(tx)
    assert signing_message_bytes({**tx, field: value}) != signed
    assert signing_message_bytes({k: v for k, v in tx.items() if k != field}) != signed


# --- the book -------------------------------------------------------------------------------

def test_the_due_index_holds_the_end_of_each_envelope(book):
    t = _opened(book, hold=HOUR, expires_at=TS + DAY)
    assert book.due_points() == {t.envelope_id.hex(): (KIND_SECONDS, TS + DAY)}
    assert not book.has_due(0, TS + DAY - 1) and book.has_due(0, TS + DAY)
    book.record_spend(t.envelope_id, 10, NEXT_HEIGHT, TS + 2 * HOUR)
    assert book.state_of(t.envelope_id).last_clock == TS + 2 * HOUR
    assert book.due_points() == {t.envelope_id.hex(): (KIND_SECONDS, TS + DAY)}
    assert book.end_due(0, TS + DAY) == [(t, 990, OUTCOME_ENDED)]
    assert book.is_empty() is False and book.escrow_total() == 0


def test_a_spending_limit_envelope_keeps_no_last_clock(book):
    t = parse_envelope_send(send(caps=[100], clock=None, period_blocks=10,
                                 expires_at=NEXT_HEIGHT + 100))
    book.send(t, NEXT_HEIGHT, TS)
    book.record_spend(t.envelope_id, 10, NEXT_HEIGHT + 1, TS + 9)
    assert book.state_of(t.envelope_id).last_clock == 0


@pytest.mark.parametrize("over, height, ts, why", [
    ({"hold": HOUR}, 0, TS + HOUR - 1,
     f"locked until {TS + HOUR} \\(seconds, Thu 2026-01-01 01:00 UTC\\)"),
    ({"days": ["fri"]}, 0, TS, f"next window opens at {TS + DAY} \\(Fri 2026-01-02 00:00 UTC\\)"),
    ({"hours": [3]}, 0, TS + 4 * HOUR, f"next window opens at {TS + DAY + 3 * HOUR}"),
    ({"hours": [9], "utc_offset": 8}, 0, TS,
     f"hours 9 UTC\\+02:00\\); the next window opens at {TS + 7 * HOUR} "
     "\\(Thu 2026-01-01 07:00 UTC, Thu 09:00 UTC\\+02:00\\)"),
    ({"days": ["fri"], "utc_offset": -22}, 0, TS,
     f"fri UTC-05:30\\); the next window opens at {TS + DAY + 5 * HOUR + 1800} "
     "\\(Fri 2026-01-02 05:30 UTC, Fri 00:00 UTC-05:30\\)"),
    ({"hold": 60, "expires_at": TS + HOUR}, 0, TS + HOUR, "reached its end$"),
])
def test_check_spend_reasons(book, over, height, ts, why):
    t = _opened(book, **over)
    with pytest.raises(EnvelopeRefused, match=why):
        book.check_spend(EnvelopeSpend(B, t.envelope_id, C, 1), height, ts)


def test_the_order_of_refusals(book):
    """The end, then lock, then window, then what it holds, then the cap."""
    t = _opened(book, caps=[5], clock=None, period_seconds=DAY, hold=HOUR, days=["fri"],
                amount=20)
    sp = EnvelopeSpend(B, t.envelope_id, C, 21)
    with pytest.raises(EnvelopeRefused, match="locked"):
        book.check_spend(sp, 0, TS + 1)
    with pytest.raises(EnvelopeRefused, match="window"):
        book.check_spend(sp, 0, TS + 2 * HOUR)
    with pytest.raises(EnvelopeRefused, match="holds 20"):
        book.check_spend(sp, 0, TS + DAY)
    with pytest.raises(EnvelopeRefused, match="the cap 5"):
        book.check_spend(EnvelopeSpend(B, t.envelope_id, C, 6), 0, TS + DAY)
    with pytest.raises(EnvelopeRefused, match="reached its end"):
        book.check_spend(sp, 0, TS + HOUR + 10 * DAY)


def test_the_periods_of_a_held_envelope_start_at_the_unlock(book):
    t = _opened(book, caps=[5], clock=None, period_seconds=DAY, recurring=True,
                hold=HOUR)
    state = book.state_of(t.envelope_id)
    assert state.anchor == TS + HOUR
    assert state.next_reset(t, TS + HOUR) == TS + HOUR + DAY


def test_describe_tells_a_wallet_what_it_may_do(book):
    t = _opened(book, hold=HOUR, days=["mon", "tue", "wed", "thu", "fri"], hours=[9, 10])
    s = book.state_of(t.envelope_id)
    locked = describe(t, s, height=1, ts=TS + 60)
    assert locked["status"] == "locked" and locked["locked"] is True
    assert locked["spendable_now"] is False and locked["next_window"] == TS + 9 * HOUR
    assert (locked["unlocks_at"], locked["expires_at"]) == (TS + HOUR, TS + 10 * DAY)
    assert (locked["days"], locked["hours"]) == (["mon", "tue", "wed", "thu", "fri"], [9, 10])
    assert locked["caps"] == [] and locked["period"] is None and locked["clock"] == "seconds"
    open_now = describe(t, s, height=1, ts=TS + 9 * HOUR + 5)
    assert open_now["status"] == "open" and open_now["spendable_now"] is True
    closed_hour = describe(t, s, height=1, ts=TS + 12 * HOUR)
    assert closed_hour["in_window"] is False and closed_hour["next_window"] == \
        TS + DAY + 9 * HOUR
    ended = describe(t, s, height=1, ts=TS + 10 * DAY)
    assert ended["status"] == "ended" and ended["next_window"] is None
    assert (locked["utc_offset"], locked["windows_read_at"]) == (None, "UTC")
    there = _opened(book, sequence_number=2, hours=[9, 10], utc_offset=-14)
    seen = describe(there, book.state_of(there.envelope_id), height=1, ts=TS)
    assert (seen["utc_offset"], seen["windows_read_at"]) == (-14, "UTC-03:30")
    assert seen["in_window"] is False and seen["next_window"] == TS + 12 * HOUR + 1800
    plain = _opened(book, sequence_number=3, hold=HOUR)
    assert describe(plain, book.state_of(plain.envelope_id))["windows_read_at"] is None


# --- restore ---------------------------------------------------------------------------------

def _row(terms, anchor, remaining, spends=0, last_clock=0, period_index=0, spent=0):
    return (terms.envelope_id, terms.sender_pubkey, terms.sequence_number,
            terms.recipient_pubkey, terms.amount, terms.caps, terms.kind, terms.period,
            terms.recurring, terms.expires_at, anchor, remaining, period_index, spent,
            spends, 0, terms.conditions, last_clock)


def test_restore_a_conditioned_envelope():
    t = parse_envelope_send(send(hold=HOUR, days=["fri"]))
    restored = EnvelopeBook.restore([_row(t, TS + HOUR, 900, spends=1,
                                          last_clock=TS + 2 * HOUR)], 0, bytes(32))
    assert restored.get(t.envelope_id) == t
    assert restored.due_points()[t.envelope_id.hex()] == (KIND_SECONDS, TS + 10 * DAY)


def test_restore_keeps_the_offset():
    t = parse_envelope_send(send(days=["sat", "sun"], hours=[10, 11], utc_offset=38))
    restored = EnvelopeBook.restore([_row(t, TS, 1000)], 0, bytes(32))
    assert restored.get(t.envelope_id) == t and restored.get(t.envelope_id).utc_offset == 38
    offset_alone = EnvelopeTerms(A, 1, B, 1000, (), KIND_SECONDS, 0, False, TS + DAY,
                                 hold=HOUR, utc_offset=8)
    with pytest.raises(ValueError, match="impossible"):             # an offset, no window
        EnvelopeBook.restore([_row(offset_alone, TS + HOUR, 1000)], 0, bytes(32))


def test_restore_refuses_impossible_conditioned_rows():
    t = parse_envelope_send(send(hold=HOUR))
    with pytest.raises(ValueError, match="inconsistent"):           # a clock, no spend
        EnvelopeBook.restore([_row(t, TS + HOUR, 1000, last_clock=TS + 9)], 0, bytes(32))
    with pytest.raises(ValueError, match="inconsistent"):           # spent before unlock
        EnvelopeBook.restore([_row(t, TS + HOUR, 900, spends=1, last_clock=TS)], 0, bytes(32))
    with pytest.raises(ValueError, match="inconsistent"):           # unlocked past the end
        EnvelopeBook.restore([_row(t, t.expires_at, 1000)], 0, bytes(32))
    windows = EnvelopeTerms(A, 1, B, 1000, (), KIND_BLOCKS, 0, False, 900, days=1)
    with pytest.raises(ValueError, match="impossible"):             # windows on blocks
        EnvelopeBook.restore([_row(windows, 10, 1000)], 0, bytes(32))
    every_day = EnvelopeTerms(A, 1, B, 1000, (), KIND_SECONDS, 0, False, TS + DAY,
                              days=ALL_DAYS)
    with pytest.raises(ValueError, match="impossible"):
        EnvelopeBook.restore([_row(every_day, TS, 1000)], 0, bytes(32))
    bare = EnvelopeTerms(A, 1, B, 1000, (), KIND_SECONDS, 0, False, TS + DAY)
    with pytest.raises(ValueError, match="impossible"):             # no condition at all
        EnvelopeBook.restore([_row(bare, TS, 1000)], 0, bytes(32))
    limit = EnvelopeTerms(A, 1, B, 1000, (10,), KIND_SECONDS, 60, True, TS + DAY)
    with pytest.raises(ValueError, match="inconsistent"):           # a clock on a 01 row
        EnvelopeBook.restore([_row(limit, TS, 990, spends=1, last_clock=TS + 5, spent=10)],
                             0, bytes(32))
    for free in ((None, HOUR, 0, 0, DAY, 0, 0), (None, HOUR, 0, 0, None, 1, 0)):
        row = _row(t, TS + HOUR, 1000)
        with pytest.raises(ValueError, match="does not know"):      # a free place filled
            EnvelopeBook.restore([row[:16] + (free,) + row[17:]], 0, bytes(32))
    assert ALL_HOURS == (1 << 24) - 1


def _seed():
    lm = ConsensusLifecycleManager(active_validators=[A])
    # Run on the loaded genesis, as the restarted node will: other modules may
    # leave a genesis faucet grant or slot flag set, and a restart reads both.
    lm.faucet_amount = chain_state._genesis_faucet_amount
    if chain_state._genesis_approval_slots_active:
        lm.activate_approval_slots()
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 5000, B: 7})
    chain_state._sequence_numbers.update({A: 3})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    book = lm.envelopes
    first = _opened(book, hold=HOUR, days=["thu", "fri"], hours=[1, 2], utc_offset=4)
    book.record_spend(first.envelope_id, 250, NEXT_HEIGHT, TS + HOUR + 60)
    _opened(book, sequence_number=2, caps=[50], clock=None, period_blocks=10,
            expires_at=NEXT_HEIGHT + 50)
    _opened(book, sequence_number=3, clock="blocks", not_before=NEXT_HEIGHT + 3,
            expires_at=NEXT_HEIGHT + 90)
    return lm, first


def _reload():
    chain_state.commit_state_to_db("head-hash", 60)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_conditioned_book_round_trips(temp_database):
    lm, first = _seed()
    meta = lm.consensus_meta_hash()
    book = lm.envelopes
    reloaded = _reload().envelopes
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded._due == book._due
    assert reloaded.state_of(first.envelope_id).last_clock == TS + HOUR + 60
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


@pytest.mark.usefixtures("isolated_chain_state")
@pytest.mark.parametrize("column, value", [
    ("conditions_json", "[null, 7200, 24, 6, null, 0, 4]"),
    ("conditions_json", "[null, 3600, 24, 6, 86400, 0, 4]"),    # a free place filled
    ("conditions_json", "[null, 3600, 24, 6, null, 1, 4]"),     # the other one
    ("conditions_json", "[null, 3600, 24, 6, null, 0, -4]"),    # the offset turned round
    ("conditions_json", "[null, 3600, 24, 6, null, 0, 0]"),     # the offset removed
    ("conditions_json", "[null, 3600, 24, 6, null, 0]"),        # a field short
    ("conditions_json", "not json"),
    ("conditions_json", ""),
    ("last_clock", 5),
    ("anchor", TS + 10 * DAY),          # unlocked only at its end
])
def test_a_tampered_conditioned_row_refuses_to_load(temp_database, column, value):
    _, first = _seed()
    chain_state.commit_state_to_db("head-hash", 60)
    with db._db_conn as conn:
        conn.execute(f"UPDATE envelopes_v1 SET {column} = ? WHERE envelope_id = ?",
                     (value, first.envelope_id.hex()))
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="envelope"):
        chain_state.load_state_from_db()


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_miner_hint_reads_due_points(temp_database):
    lm, first = _seed()
    chain_state.commit_state_to_db("head-hash", 60)
    end = TS + 10 * DAY
    assert db.has_due_envelopes(NEXT_HEIGHT, end - 1) is False
    assert db.has_due_envelopes(NEXT_HEIGHT, end) is True
    assert db.has_due_envelopes(NEXT_HEIGHT + 50, TS) is True     # the block-clock end


def test_an_old_table_gains_the_new_columns(tmp_path):
    import sqlite3

    import config

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE envelopes_v1 (envelope_id TEXT PRIMARY KEY, sender_pubkey "
                 "TEXT NOT NULL, sequence_number INTEGER NOT NULL, recipient_pubkey TEXT NOT "
                 "NULL, amount INTEGER NOT NULL, caps_json TEXT NOT NULL, period_kind INTEGER "
                 "NOT NULL, period INTEGER NOT NULL, recurring INTEGER NOT NULL, expires_at "
                 "INTEGER NOT NULL, anchor INTEGER NOT NULL, remaining INTEGER NOT NULL, "
                 "period_index INTEGER NOT NULL, spent_in_period INTEGER NOT NULL, spends "
                 "INTEGER NOT NULL, last_height INTEGER NOT NULL)")
    conn.execute("INSERT INTO envelopes_v1 VALUES ('ab', 'a', 0, 'b', 5, '[1]', 0, 1, 0, 9, "
                 "1, 5, 0, 0, 0, 0)")
    conn.commit()
    conn.close()
    original = config.STRING_DB_PATH
    if db._db_conn is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(str(path))
    try:
        db.init_db()
        cols = {r[1] for r in db._db_conn.execute("PRAGMA table_info(envelopes_v1)")}
        assert {"conditions_json", "last_clock", "due_at"} <= cols
        assert db.has_due_envelopes(9, 0) is True and db.has_due_envelopes(8, 0) is False
    finally:
        db._db_conn.close()
        db._db_conn = None
        config.set_database_path(original)


def test_the_miner_wakes_an_idle_chain_for_envelopes(monkeypatch):
    from miner import service

    calls = []
    monkeypatch.setattr(service.db, "get_canonical_head_block",
                        lambda: {"header": {"block_number": 41}})
    monkeypatch.setattr(service.db, "has_due_retractables", lambda h, n: False)
    monkeypatch.setattr(service.db, "has_due_standing_payments", lambda h, n: False)
    monkeypatch.setattr(service.db, "has_due_envelopes",
                        lambda h, n: calls.append(h) or True)
    miner = service.SoleMiner.__new__(service.SoleMiner)
    miner._last_due_attempt = 0.0
    assert miner._due_wake_allowed() is True and calls == [42]


# --- admission ------------------------------------------------------------------------------

def test_a_conditioned_send_is_admitted_with_its_unlock(tip_view):
    result = validate_envelope_send_payload(send(hold=HOUR), tip_view)
    assert result.is_valid, result.error
    assert (result.data["unlocks_at"], result.data["status"]) == (TS + HOUR, "locked")


@pytest.mark.parametrize("over, code", [
    ({"hold": 11 * DAY}, "ENVELOPE_NEVER_SPENDABLE"),
    ({"days": ["sun"], "expires_at": TS + DAY}, "ENVELOPE_NEVER_SPENDABLE"),
    ({"clock": "blocks", "days": ["sun"], "expires_at": NEXT_HEIGHT + 9}, "INVALID_ENVELOPE"),
    ({}, "INVALID_ENVELOPE"),                                # no condition at all
    ({"days": ["sundays"]}, "INVALID_ENVELOPE"),
    ({"hold": HOUR, "utc_offset": 8}, "INVALID_ENVELOPE"),
    ({"clock": "blocks", "utc_offset": 8, "expires_at": NEXT_HEIGHT + 9, "hold": 2},
     "INVALID_ENVELOPE"),
    ({"hours": [9], "utc_offset": 99}, "INVALID_ENVELOPE"),
    # Noon at UTC+05:45 opens 06:15 UTC, after this envelope's end at 06:00 UTC.
    ({"hours": [12], "utc_offset": 23, "expires_at": TS + 6 * HOUR}, "ENVELOPE_NEVER_SPENDABLE"),
])
def test_conditioned_send_refusals_carry_a_code(tip_view, over, code):
    assert validate_envelope_send_payload(send(**over), tip_view).code == code


def test_spend_admission_codes(tip_view, book):
    locked = _opened(book, hold=HOUR).envelope_id.hex()
    weekend = _opened(book, sequence_number=2, days=["sat"]).envelope_id.hex()
    over = _opened(book, sequence_number=3, hold=1, expires_at=TS, ts=TS - 60).envelope_id.hex()
    assert validate_envelope_spend_payload(spend(locked), tip_view).code == "ENVELOPE_LOCKED"
    assert validate_envelope_spend_payload(spend(weekend), tip_view).code == \
        "ENVELOPE_OUTSIDE_WINDOW"
    assert validate_envelope_spend_payload(spend(over), tip_view).code == "ENVELOPE_ENDED"
    tip_view.next_block_timestamp = TS + 2 * DAY
    assert validate_envelope_spend_payload(spend(weekend), tip_view).is_valid


# --- reads, routes, gossip ------------------------------------------------------------------

def test_the_capability_report_names_every_condition():
    sem = getenvelope.semantics()
    assert sem["version"] == 2
    assert sem["conditions"] == ["spending_limit", "not_before", "hold", "days", "hours",
                                 "utc_offset"]
    for word in ("120 s", "UTC", "quarter hours east of UTC", "no daylight saving"):
        assert word in json.dumps(sem), word


def test_gossip_takes_a_send_without_caps_when_it_names_its_clock():
    check = NetworkService._process_gossip_payload
    assert check is not None
    import inspect

    src = inspect.getsource(NetworkService)
    assert 'p_dict.get("clock") is None' in src


# --- the CLI -------------------------------------------------------------------------------------

def test_the_cli_builder_makes_what_the_node_parses():
    from tau_testnet_cli.tx import build_envelope_send_tx

    tx = build_envelope_send_tx(
        sender_pubkey=A, sequence_number=4, expiration_time=FAR, expire_at_height=60,
        recipient_pubkey=B, amount=100, expires_at=TS + DAY, clock="seconds",
        hold=6 * HOUR, days=["Friday", "mon"], hours=[10, 9, 9])
    assert tx["days"] == ["mon", "fri"] and tx["hours"] == [9, 10]
    assert "caps" not in tx and "recurring" not in tx
    t = parse_envelope_send(tx)
    assert t.hold == 6 * HOUR
    assert "utc_offset" not in tx and t.utc_offset == 0
    there = build_envelope_send_tx(
        sender_pubkey=A, sequence_number=4, expiration_time=FAR, expire_at_height=60,
        recipient_pubkey=B, amount=100, expires_at=TS + 9 * DAY, clock="seconds",
        hours=[9, 10], utc_offset=-14)
    assert there["utc_offset"] == -14 and parse_envelope_send(there).utc_offset == -14
    utc = build_envelope_send_tx(
        sender_pubkey=A, sequence_number=4, expiration_time=FAR, expire_at_height=60,
        recipient_pubkey=B, amount=100, expires_at=TS + 9 * DAY, clock="seconds",
        hours=[9, 10], utc_offset=0)
    assert "utc_offset" not in utc
    for bad in ({"utc_offset": 57, "hours": [9]}, {"utc_offset": 8, "hold": HOUR}):
        with pytest.raises(ValueError, match="utc_offset"):
            build_envelope_send_tx(
                sender_pubkey=A, sequence_number=4, expiration_time=FAR, expire_at_height=60,
                recipient_pubkey=B, amount=100, expires_at=TS + 9 * DAY, clock="seconds", **bad)
    plain = build_envelope_send_tx(
        sender_pubkey=A, sequence_number=4, expiration_time=FAR, expire_at_height=60,
        recipient_pubkey=B, amount=100, expires_at=900, caps=[10], period_blocks=5)
    assert "clock" not in plain
    with pytest.raises(ValueError, match="needs clock"):
        build_envelope_send_tx(sender_pubkey=A, sequence_number=4, expiration_time=FAR,
                               expire_at_height=60, recipient_pubkey=B, amount=100,
                               expires_at=900, hold=5)


def test_the_cli_parses_days_hours_and_times():
    from tau_testnet_cli.cli import _day_list, _hour_list, _utc_offset, _utc_time

    assert _day_list("mon-fri") == ["mon", "tue", "wed", "thu", "fri"]
    assert _day_list("sat-mon") == ["mon", "sat", "sun"]
    assert _day_list("Friday,sun") == ["fri", "sun"]
    assert _hour_list("9-17") == list(range(9, 17))
    assert _hour_list("22-2") == [0, 1, 22, 23]
    assert _hour_list("8,12-14") == [8, 12, 13]
    assert _utc_time("2026-01-01") == TS and _utc_time("2026-01-01T06:00") == TS + 6 * HOUR
    assert _utc_time(str(TS)) == TS
    assert [_utc_offset(t) for t in ("+02:00", "-03:30", "5:45", "2", "-5", "+14", "-12:00",
                                     "0", "+00:00")] == [8, -14, 23, 8, -20, 56, -48, 0, 0]
    for bad in ("+02:10", "+14:15", "-12:15", "berlin", "2:60", "", "+", "1:2:3"):
        with pytest.raises(argparse.ArgumentTypeError):
            _utc_offset(bad)
    for bad in ("funday", "mon-xyz"):
        with pytest.raises(argparse.ArgumentTypeError):
            _day_list(bad)
    for bad in ("24", "9-9", "x-5", "25-3"):
        with pytest.raises(argparse.ArgumentTypeError):
            _hour_list(bad)
    with pytest.raises(argparse.ArgumentTypeError):
        _utc_time("next week")


def test_the_cli_send_a_day_hold_and_one_clock():
    from tau_testnet_cli.cli import _PayloadError, _envelope_terms, build_parser

    parser = build_parser()
    args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount", "100",
                              "--hold", "6h", "--ends-at", "2026-01-02"])
    terms = _envelope_terms(args, tip=10, now=TS)
    assert (terms["clock"], terms["hold"], terms["expires_at"]) == \
        ("seconds", 6 * HOUR, TS + DAY)
    args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount", "9",
                              "--cap", "500", "--period", "7d", "--recurring",
                              "--not-before", "2026-12-01", "--days", "mon-fri",
                              "--hours", "9-17", "--ends-in", "52w"])
    terms = _envelope_terms(args, tip=10, now=TS)
    assert terms["caps"] == [500] and terms["period_seconds"] == 7 * DAY
    assert terms["days"] == ["mon", "tue", "wed", "thu", "fri"] and len(terms["hours"]) == 8
    assert terms["utc_offset"] is None
    args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount", "9",
                              "--days", "mon-fri", "--hours", "9-17", "--utc-offset",
                              "+05:45", "--ends-in", "52w"])
    assert _envelope_terms(args, tip=10, now=TS)["utc_offset"] == 23
    args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount", "9",
                              "--hold-blocks", "6", "--ends-in-blocks", "100"])
    terms = _envelope_terms(args, tip=10, now=TS)
    assert (terms["clock"], terms["hold"], terms["expires_at"]) == ("blocks", 6, 111)
    for argv, why in [
        (["--hold", "6h", "--ends-in-blocks", "100"], "--hold"),
        (["--days", "mon", "--ends-in-blocks", "100"], "--days"),
        (["--utc-offset", "+02:00", "--ends-in-blocks", "100"], "--utc-offset"),
        (["--utc-offset", "+02:00", "--hold", "6h", "--ends-in", "1d"], "--utc-offset says"),
        (["--hold-blocks", "6", "--ends-in", "1d"], "--hold-blocks"),
        (["--period", "1d", "--ends-in", "1d"], "need --cap"),
        (["--cap", "5", "--ends-in", "1d"], "--cap needs --period"),
    ]:
        args = parser.parse_args(["envelope", "send", "--key", "k", "--to", B, "--amount",
                                  "9", *argv])
        with pytest.raises(_PayloadError, match=why):
            _envelope_terms(args, tip=10, now=TS)
