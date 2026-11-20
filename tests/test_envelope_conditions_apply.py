"""Block-apply semantics for envelope time conditions.

Every scenario runs through the real `apply_block` with a scripted interpreter
and compares the FULL balance map, sequences and cooldown stamps against an
oracle that knows only the documented rules:

  * unlock = max(sent, not_before, sent + hold): no spend lands before it, and a
    spending limit's periods start there;
  * days and hours (seconds clock, read at the envelope's offset from UTC): a
    spend lands only in a block whose timestamp is on an allowed weekday and in
    an allowed hour;
  * no spend lands in the block that reaches the end; the rest then goes to the
    recipient.

`apply_block` raises on any supply drift (balances + every escrow), so every
block here is also a conservation check.

What the features promise, by test:
  locked until a date ............. test_not_before_on_the_time_clock
  locked for X after arrival ...... test_hold_on_the_block_clock, test_a_hold_moves_the_periods
  only on certain days ............ test_weekdays, test_hours_across_midnight
  which clock ..................... test_the_proposer_cannot_reach_a_height_early,
                                    test_a_seconds_condition_reads_the_block_timestamp
"""
import pytest

from consensus.envelope import parse_envelope_send

from tests.test_envelope_apply import (
    EnvOracle, _accepted, _events, _reason, eid_of, env_release, env_spend,
)
from tests.test_standing_apply import (
    ALICE, BOB, CAROL, FAR, HEIGHT, PROPOSER, SKS, TS, Chain, _logs, _sign,
)

_N = iter(range(10**9))
HOUR = 3600
DAY = 86400
# TS is Thursday 2026-01-01 00:00 UTC.
FRI, SAT, MON = TS + DAY, TS + 2 * DAY, TS + 4 * DAY


def cond_tx(sender=ALICE, recipient=BOB, amount=600, seq=0, *, ends, fee_limit="100",
            **fields):
    """An envelope_send with exactly the given optional fields (no caps unless given)."""
    tx = {"tx_id": f"cond-send-{next(_N)}", "tx_type": "envelope_send",
          "sender_pubkey": sender, "sequence_number": seq, "expiration_time": FAR,
          "expire_at_height": 10_000, "fee_limit": str(fee_limit),
          "recipient_pubkey": recipient, "amount": amount, "expires_at": ends}
    tx.update(fields)
    return _sign(tx, SKS[sender])


CondOracle = EnvOracle


def _bal():
    return {ALICE: 10_000, BOB: 50, CAROL: 0, PROPOSER: 0}


def _open(tx, *, height=HEIGHT, ts=TS, fee=0):
    ch, oracle = Chain(_bal(), fee=fee), CondOracle(_bal())
    result = ch.block([tx], height=height, ts=ts)
    assert _accepted(result, tx), _logs(result)
    oracle.sent(tx, fee=fee, ts=ts)
    return ch, oracle, eid_of(tx)


def _state(ch, eid):
    return ch.lm.envelopes.state_of(bytes.fromhex(eid))


# --- locks --------------------------------------------------------------------------

def test_hold_on_the_block_clock():
    ch, oracle, eid = _open(cond_tx(clock="blocks", hold=5, ends=HEIGHT + 50))
    assert _state(ch, eid).anchor == HEIGHT + 5
    early = env_spend(eid, 10, 0)
    result = ch.block([early], height=HEIGHT + 4, ts=TS + 40)
    assert _reason(result, early) == "envelope_not_spent"
    assert f"locked until {HEIGHT + 5} (blocks)" in _logs(result)
    on_time = env_spend(eid, 10, 0)
    ch.block([on_time], height=HEIGHT + 5, ts=TS + 50)
    oracle.spent(eid, BOB, CAROL, 10, ts=TS + 50)
    oracle.check(ch)


def test_no_spend_in_the_sending_block_under_a_hold():
    ch, oracle = Chain(_bal()), CondOracle(_bal())
    tx = cond_tx(clock="blocks", hold=1, ends=HEIGHT + 50)
    spend = env_spend(eid_of(tx), 10, 0)
    result = ch.block([tx, spend])
    oracle.sent(tx)
    assert not _accepted(result, spend) and "locked until" in _logs(result)
    oracle.check(ch)


def test_not_before_on_the_time_clock():
    ch, oracle, eid = _open(cond_tx(clock="seconds", not_before=TS + 10 * DAY,
                                    ends=TS + 40 * DAY))
    early = env_spend(eid, 10, 0)
    result = ch.block([early], height=HEIGHT + 1, ts=TS + 10 * DAY - 1)
    assert "locked until" in _logs(result)
    ch.block([env_spend(eid, 10, 0)], height=HEIGHT + 2, ts=TS + 10 * DAY)
    oracle.spent(eid, BOB, CAROL, 10, ts=TS + 10 * DAY)
    oracle.check(ch)


def test_a_not_before_in_the_past_does_not_lock():
    ch, oracle, eid = _open(cond_tx(clock="blocks", not_before=1, ends=HEIGHT + 9))
    assert _state(ch, eid).anchor == HEIGHT
    ch.block([env_spend(eid, 600, 0)], height=HEIGHT + 1)
    oracle.spent(eid, BOB, CAROL, 600)
    oracle.check(ch)


def test_hold_and_not_before_the_later_one_wins():
    ch, _, eid = _open(cond_tx(clock="blocks", hold=3, not_before=HEIGHT + 7,
                               ends=HEIGHT + 50))
    assert _state(ch, eid).anchor == HEIGHT + 7
    ch2, _, eid2 = _open(cond_tx(clock="blocks", hold=9, not_before=HEIGHT + 7,
                                 ends=HEIGHT + 50))
    assert _state(ch2, eid2).anchor == HEIGHT + 9


def test_a_hold_moves_the_periods():
    """500 a week from the unlock, not from the send."""
    ch, oracle, eid = _open(cond_tx(amount=3_000, caps=[500], period_seconds=7 * DAY,
                                    recurring=True, hold=2 * DAY, ends=TS + 60 * DAY))
    assert _state(ch, eid).anchor == TS + 2 * DAY
    ch.block([env_spend(eid, 500, 0)], height=HEIGHT + 1, ts=TS + 2 * DAY)
    oracle.spent(eid, BOB, CAROL, 500, ts=TS + 2 * DAY)
    # 7 days after the send but 5 after the unlock: still the first period.
    over = env_spend(eid, 1, 1)
    result = ch.block([over], height=HEIGHT + 2, ts=TS + 7 * DAY)
    assert "the cap 500 leaves 0" in _logs(result)
    ch.block([env_spend(eid, 500, 1)], height=HEIGHT + 3, ts=TS + 9 * DAY)
    oracle.spent(eid, BOB, CAROL, 500, ts=TS + 9 * DAY)
    oracle.check(ch)


# --- windows ------------------------------------------------------------------------

def test_weekdays():
    ch, oracle, eid = _open(cond_tx(clock="seconds", days=["mon", "tue", "wed", "thu", "fri"],
                                    ends=TS + 30 * DAY))
    sat = env_spend(eid, 10, 0)
    result = ch.block([sat], height=HEIGHT + 1, ts=SAT + 12 * HOUR)
    assert _reason(result, sat) == "envelope_not_spent"
    assert f"next window opens at {MON}" in _logs(result)
    ch.block([env_spend(eid, 10, 0)], height=HEIGHT + 2, ts=MON)
    oracle.spent(eid, BOB, CAROL, 10, ts=MON)
    ch.block([env_spend(eid, 10, 1)], height=HEIGHT + 3, ts=FRI + 4 * 7 * DAY - 7 * DAY)
    oracle.spent(eid, BOB, CAROL, 10, ts=FRI + 21 * DAY)
    oracle.check(ch)


def test_hours_across_midnight():
    hours = [22, 23, 0, 1]
    ch, oracle, eid = _open(cond_tx(clock="seconds", hours=sorted(hours), ends=TS + 9 * DAY))
    at_noon = env_spend(eid, 10, 0)
    result = ch.block([at_noon], height=HEIGHT + 1, ts=TS + 12 * HOUR)
    assert f"next window opens at {TS + 22 * HOUR}" in _logs(result)
    for k, (h, ts) in enumerate([(2, TS + 22 * HOUR), (3, TS + DAY + 1 * HOUR + 3599)]):
        ch.block([env_spend(eid, 10, k)], height=HEIGHT + h, ts=ts)
        oracle.spent(eid, BOB, CAROL, 10, ts=ts)
    late = env_spend(eid, 10, 2)
    result = ch.block([late], height=HEIGHT + 4, ts=TS + DAY + 2 * HOUR)
    assert not _accepted(result, late)
    oracle.check(ch)


def test_days_and_hours_together():
    ch, oracle, eid = _open(cond_tx(clock="seconds", days=["sat"], hours=[9, 10],
                                    ends=TS + 30 * DAY))
    wrong_hour = env_spend(eid, 10, 0)
    result = ch.block([wrong_hour], height=HEIGHT + 1, ts=SAT + 8 * HOUR)
    assert f"next window opens at {SAT + 9 * HOUR}" in _logs(result)
    wrong_day = env_spend(eid, 10, 0)
    result = ch.block([wrong_day], height=HEIGHT + 2, ts=MON + 9 * HOUR)
    assert f"next window opens at {SAT + 7 * DAY + 9 * HOUR}" in _logs(result)
    ch.block([env_spend(eid, 10, 0)], height=HEIGHT + 3, ts=SAT + 7 * DAY + 10 * HOUR)
    oracle.spent(eid, BOB, CAROL, 10, ts=SAT + 7 * DAY + 10 * HOUR)
    oracle.check(ch)


def test_working_hours_at_an_offset_from_utc():
    """Weekdays 9 to 17 at UTC+05:45: the block's own time, moved by the signed offset."""
    ch, oracle, eid = _open(cond_tx(clock="seconds", days=["mon", "tue", "wed", "thu", "fri"],
                                    hours=list(range(9, 17)), utc_offset=23,
                                    ends=TS + 30 * DAY))
    opens = MON + 3 * HOUR + 15 * 60             # Monday 09:00 there is 03:15 UTC
    early = env_spend(eid, 10, 0)
    result = ch.block([early], height=HEIGHT + 1, ts=opens - 1)
    assert _reason(result, early) == "envelope_not_spent"
    assert f"next window opens at {opens}" in _logs(result)
    assert "Mon 09:00 UTC+05:45" in _logs(result)
    ch.block([env_spend(eid, 10, 0)], height=HEIGHT + 2, ts=opens)
    oracle.spent(eid, BOB, CAROL, 10, ts=opens)
    closes = FRI + 7 * DAY + 11 * HOUR + 15 * 60  # Friday 17:00 there is 11:15 UTC
    ch.block([env_spend(eid, 10, 1)], height=HEIGHT + 3, ts=closes - 1)
    oracle.spent(eid, BOB, CAROL, 10, ts=closes - 1)
    late = env_spend(eid, 10, 2)
    result = ch.block([late], height=HEIGHT + 4, ts=closes)
    assert not _accepted(result, late)
    assert f"next window opens at {opens + 7 * DAY}" in _logs(result)
    oracle.check(ch)


def test_a_weekday_west_of_utc_starts_and_ends_later():
    """Thursday at UTC-05:00 runs from Thursday 05:00 UTC to Friday 05:00 UTC."""
    ch, oracle, eid = _open(cond_tx(clock="seconds", days=["thu"], utc_offset=-20,
                                    ends=TS + 30 * DAY))
    still_wednesday = env_spend(eid, 10, 0)
    result = ch.block([still_wednesday], height=HEIGHT + 1, ts=TS + 5 * HOUR - 1)
    assert not _accepted(result, still_wednesday)
    assert f"next window opens at {TS + 5 * HOUR}" in _logs(result)
    for k, ts in enumerate((TS + 5 * HOUR, FRI + 5 * HOUR - 1)):   # Friday in UTC, Thursday there
        ch.block([env_spend(eid, 10, k)], height=HEIGHT + 2 + k, ts=ts)
        oracle.spent(eid, BOB, CAROL, 10, ts=ts)
    friday_there = env_spend(eid, 10, 2)
    result = ch.block([friday_there], height=HEIGHT + 4, ts=FRI + 5 * HOUR)
    assert not _accepted(result, friday_there)
    oracle.check(ch)


def test_a_seconds_condition_reads_the_block_timestamp():
    """The block's own timestamp decides, never the node's clock."""
    ch, oracle, eid = _open(cond_tx(clock="seconds", hold=HOUR, ends=TS + DAY))
    spend = env_spend(eid, 10, 0)
    result = ch.block([spend], height=HEIGHT + 999, ts=TS + HOUR - 1)
    assert "locked until" in _logs(result)
    ch.block([env_spend(eid, 10, 0)], height=HEIGHT + 1000, ts=TS + HOUR)
    oracle.spent(eid, BOB, CAROL, 10, ts=TS + HOUR)
    oracle.check(ch)


def test_the_proposer_cannot_reach_a_height_early():
    """Whatever timestamp a block carries, a block-clock hold counts heights."""
    ch, oracle, eid = _open(cond_tx(clock="blocks", hold=10, ends=HEIGHT + 50))
    spend = env_spend(eid, 10, 0)
    result = ch.block([spend], height=HEIGHT + 9, ts=TS + 10 * DAY)
    assert "locked until" in _logs(result)
    oracle.check(ch)


# --- the end --------------------------------------------------------------------------

def test_a_day_hold_then_the_rest_is_his_at_the_end_of_the_day():
    """100 to Bob; he cannot spend it for six hours; no spend lands in the block
    that reaches the end, and what is left then is paid to him."""
    midnight = TS + DAY
    ch, oracle, eid = _open(cond_tx(amount=100, clock="seconds", hold=6 * HOUR,
                                    ends=midnight), ts=TS + 9 * HOUR)
    early = env_spend(eid, 30, 0)
    result = ch.block([early], height=HEIGHT + 1, ts=TS + 14 * HOUR)
    assert f"locked until {TS + 15 * HOUR} (seconds, Thu 2026-01-01 15:00 UTC)" in _logs(result)
    ch.block([env_spend(eid, 30, 0)], height=HEIGHT + 2, ts=TS + 15 * HOUR)
    oracle.spent(eid, BOB, CAROL, 30, ts=TS + 15 * HOUR)
    late = env_spend(eid, 10, 1)
    result = ch.block([late], height=HEIGHT + 3, ts=midnight)
    assert "reached its end" in _logs(result)
    oracle.ended(eid, BOB)
    oracle.check(ch)
    assert _events(ch) == [{"outcome": "ended", "envelope_id": eid,
                            "sender_pubkey": ALICE, "recipient_pubkey": BOB,
                            "paid_out": 70}]
    assert ch.bal[ALICE] == 10_000 - 100


def test_the_sender_may_release_a_locked_envelope():
    ch, oracle, eid = _open(cond_tx(clock="blocks", hold=20, ends=HEIGHT + 50))
    ch.block([env_release(eid, 1)], height=HEIGHT + 1)
    oracle.released(eid, ALICE, BOB)
    oracle.check(ch)


# --- refused sends ------------------------------------------------------------------

@pytest.mark.parametrize("fields, why", [
    ({"clock": "blocks"}, "at least one condition"),
    ({"clock": "blocks", "days": ["mon"]}, "need the seconds clock"),
    ({"clock": "blocks", "hours": [9]}, "need the seconds clock"),
    ({"clock": "blocks", "hold": 0}, "hold must be in"),
    ({"clock": "blocks", "hold": 50}, "it would unlock at"),
    ({"clock": "blocks", "not_before": HEIGHT + 50}, "it would unlock at"),
    ({"clock": "seconds", "days": ["sat"], "expires_at": TS + DAY}, "could never be spent"),
    ({"clock": "seconds", "hours": [23], "expires_at": TS + 20 * HOUR},
     "could never be spent"),
    ({"clock": "seconds", "days": ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]},
     "leave out at least one day"),
    ({"clock": "seconds", "hours": list(range(24))}, "leave out at least one hour"),
    ({"clock": "seconds", "hold": HOUR, "utc_offset": 8}, "utc_offset needs days or hours"),
    ({"clock": "blocks", "hold": 5, "utc_offset": 8}, "utc_offset needs days or hours"),
    ({"clock": "seconds", "hours": [9], "utc_offset": 57}, "utc_offset must be"),
    ({"clock": "seconds", "hours": [9], "utc_offset": 0}, "leave utc_offset out"),
    # Noon at UTC+05:45 opens 06:15 UTC, after this envelope has ended.
    ({"clock": "seconds", "hours": [12], "utc_offset": 23, "expires_at": TS + 6 * HOUR},
     "could never be spent"),
])
def test_an_inadmissible_conditioned_send_stays_out(fields, why):
    ch, oracle = Chain(_bal(), fee=5), CondOracle(_bal())
    ends = fields.pop("expires_at", HEIGHT + 50 if fields["clock"] == "blocks" else TS + 9 * DAY)
    tx = cond_tx(ends=ends, **fields)
    result = ch.block([tx])
    assert not _accepted(result, tx)
    assert why in _logs(result)
    oracle.check(ch)
    assert ch.lm.envelopes.is_empty()


def test_a_window_that_opens_before_the_end_is_accepted():
    ch, _, eid = _open(cond_tx(clock="seconds", hours=[23], ends=TS + 23 * HOUR + 1))
    assert ch.lm.envelopes.get(bytes.fromhex(eid)).hours == 1 << 23


# --- replay and the idle-chain wake -----------------------------------------------

def test_replay_gives_the_same_state_hashes():
    def run(replay):
        ch = Chain(_bal(), fee=2)
        a = cond_tx(amount=300, caps=[100], period_blocks=10, recurring=True, hold=3,
                    ends=HEIGHT + 40, fee_limit="2")
        b = cond_tx(seq=1, amount=50, clock="seconds", days=["fri", "sat"], hours=[9, 10],
                    ends=TS + 6 * DAY, fee_limit="2")
        c = cond_tx(seq=2, amount=20, clock="seconds", days=["sat"], hours=[14, 15],
                    utc_offset=23, ends=TS + 6 * DAY, fee_limit="2")
        ch.block([a, b, c], replay=replay)
        ea, eb, ec = eid_of(a), eid_of(b), eid_of(c)
        script = {HEIGHT + 3: [env_spend(ea, 60, 0, fee_limit="2")],
                  HEIGHT + 10: [env_spend(ea, 40, 1, fee_limit="2")],
                  # Saturday 09:00 UTC, which is 14:45 at UTC+05:45.
                  HEIGHT + 12: [env_spend(eb, 20, 2, to=BOB, fee_limit="2"),
                                env_spend(ec, 5, 3, to=BOB, fee_limit="2")]}
        for h in range(HEIGHT + 1, HEIGHT + 42):
            ts = TS + (h - HEIGHT) * 4 * HOUR + 9 * HOUR
            ch.block(script.get(h, []), height=h, ts=ts, replay=replay)
        return ch.hashes, ch.bal

    first = run(False)
    assert first == run(True)
    # Every spend landed and the rest of each reached Bob at its end; Alice paid
    # three send fees.
    assert first[1][ALICE] == 10_000 - 370 - 3 * 2


def test_the_book_wakes_an_idle_chain_for_ends():
    ch, _, eid = _open(cond_tx(clock="blocks", hold=4, ends=HEIGHT + 20))
    book = ch.lm.envelopes
    assert not book.has_due(HEIGHT + 19, TS) and book.has_due(HEIGHT + 20, TS)
    assert book.due_points() == {eid: (0, HEIGHT + 20)}


def test_a_spending_limit_envelope_keeps_its_id():
    """Without the new fields an envelope is exactly a spending-limit envelope."""
    plain = cond_tx(caps=[100], period_blocks=10, ends=HEIGHT + 100)
    explicit = cond_tx(caps=[100], period_blocks=10, ends=HEIGHT + 100, clock="blocks")
    assert parse_envelope_send(plain).envelope_id == parse_envelope_send(explicit).envelope_id
    assert not parse_envelope_send(plain).extended
