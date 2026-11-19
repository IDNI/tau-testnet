"""Block-apply semantics for standing payments, mapped to #34's acceptance cases."""
import itertools

from chain_ids import TEST_CHAIN_ID
from datetime import datetime, timezone

from consensus import periods
from consensus.standing import parse_standing_create
from tests.test_retractable_apply import (
    ALICE, BOB, CAROL, FAR, MALLORY, PROPOSER, SK_ALICE, SK_BOB, SK_CAROL,
    SK_MALLORY, Chain, _sign,
)

_SEQ = itertools.count()
KEYS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, MALLORY: SK_MALLORY}


def at(*a):
    return int(datetime(*a, tzinfo=timezone.utc).timestamp())


T0 = at(2026, 11, 20)


def month(y, m):
    return y * 12 + m - 1


def _base(tx_type, sender, seq, fee_limit):
    return {"tx_id": f"{tx_type}-{next(_SEQ)}", "tx_type": tx_type,
            "sender_pubkey": sender, "sequence_number": seq,
            "expiration_time": FAR, "expire_at_height": 1000, "chain_id": TEST_CHAIN_ID,
            "fee_limit": str(fee_limit)}


def create_tx(seq=0, **terms):
    """Rent: 1,000 to Bob on the 31st (clamped) of each month, 5-day window."""
    tx = _base("standing_payment_create", ALICE, seq, 100)
    tx.update({"recipient_pubkey": BOB, "amount": 1000,
               "period_kind": periods.PERIOD_MONTH, "period_seconds": 0,
               "start_at": at(2026, 12, 1), "due_day": 31, "due_offset_seconds": 0,
               "window_seconds": 5 * 86_400, "end_at": 0, "max_occurrences": 12})
    tx.update(terms)
    return _sign(tx, SK_ALICE)


def exec_tx(sid, period, seq, sender=CAROL, fee_limit=100):
    tx = _base("standing_payment_execute", sender, seq, fee_limit)
    tx.update({"standing_id": sid, "period": period})
    return _sign(tx, KEYS[sender])


def cancel_tx(sid, seq, sender=ALICE):
    tx = _base("standing_payment_cancel", sender, seq, 0)
    tx["standing_id"] = sid
    return _sign(tx, KEYS[sender])


def sid_of(tx):
    return parse_standing_create(tx).standing_id.hex()


def setup(**kw):
    ch = Chain({ALICE: 10_000, CAROL: 100, MALLORY: 100}, **kw)
    c = create_tx()
    ch.block([c], ts=T0)
    assert not ch.last.invalid_tx_ids
    return ch, sid_of(c)


def test_creation_reserves_no_funds():
    ch, sid = setup()
    assert ch.bal[ALICE] == 10_000
    assert ch.lm.standing_payments.get(bytes.fromhex(sid)).executions == 0


def test_executes_at_most_once_per_period_by_anyone():
    ch, sid = setup()
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31, 8))
    assert ch.bal[ALICE] == 9_000 and ch.bal[BOB] == 1_000
    # Second time in the same period: rejected.
    ch.block([exec_tx(sid, month(2026, 12), 1, sender=MALLORY)], ts=at(2027, 1, 2))
    assert ch.last.invalid_tx_ids and ch.bal[BOB] == 1_000
    # Next period, a different executor.
    ch.block([exec_tx(sid, month(2027, 1), 0, sender=MALLORY)], ts=at(2027, 1, 31))
    assert ch.bal[BOB] == 2_000
    # Last transfer time is the payer's, not the executor's.
    assert ch.lts[ALICE] == at(2027, 1, 31)


def test_before_and_after_the_window_is_rejected():
    ch, sid = setup()
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 30))
    assert ch.last.invalid_tx_ids
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2027, 1, 5))
    assert ch.last.invalid_tx_ids and ch.bal.get(BOB, 0) == 0


def test_executor_cannot_alter_terms():
    ch, sid = setup()
    forged = exec_tx(sid, month(2026, 12), 0)
    forged["amount"] = 5000  # unsigned, ignored: amount comes from stored terms
    forged["recipient_pubkey"] = CAROL
    forged = _sign(forged, SK_CAROL)
    ch.block([forged], ts=at(2026, 12, 31))
    assert ch.bal[BOB] == 1_000 and ch.bal[CAROL] == 100


def test_cancellation_prevents_every_later_execution():
    ch, sid = setup()
    ch.block([cancel_tx(sid, 1)], ts=at(2026, 12, 2))
    assert ch.lm.standing_payments.open_count() == 0
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
    assert ch.last.invalid_tx_ids and ch.bal[ALICE] == 10_000


def test_cancel_execute_race_is_decided_by_block_order():
    ch, sid = setup()
    ch.block([cancel_tx(sid, 1), exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
    assert ch.bal[ALICE] == 10_000 and len(ch.last.invalid_tx_ids) == 1

    ch2, sid2 = setup()
    ch2.block([exec_tx(sid2, month(2026, 12), 0), cancel_tx(sid2, 1)], ts=at(2026, 12, 31))
    assert ch2.bal[ALICE] == 9_000 and not ch2.last.invalid_tx_ids


def test_insufficient_funds_never_creates_debt_or_marks_done():
    ch, sid = setup()
    drain = _sign({**_base("user_tx", ALICE, 1, 100),
                   "operations": {"1": [[ALICE, MALLORY, 9_500]]}}, SK_ALICE)
    ch.block([drain], ts=at(2026, 12, 20))
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
    assert ch.last.invalid_tx_ids
    assert ch.bal[ALICE] == 500 and ch.bal.get(BOB, 0) == 0
    state = ch.lm.standing_payments.get(bytes.fromhex(sid))
    assert state.executions == 0
    # Retry inside the same window once funds return.
    topup = _sign({**_base("user_tx", MALLORY, 0, 100),
                   "operations": {"1": [[MALLORY, ALICE, 600]]}}, SK_MALLORY)
    ch.block([topup, exec_tx(sid, month(2026, 12), 0)], ts=at(2027, 1, 1))
    assert ch.bal[BOB] == 1_000


def test_current_policy_block_stops_execution():
    ch, sid = setup()
    ch.block_o5 = True  # the payer froze their wallet after creating it
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
    assert ch.last.invalid_tx_ids and ch.bal[ALICE] == 10_000


def test_executor_pays_the_fee_and_supply_is_conserved():
    ch, sid = setup(fee=3)
    supply = sum(ch.bal.values())
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
    assert ch.bal[ALICE] == 10_000 - 3 - 1_000  # creation fee (3) + the payment
    assert ch.bal[PROPOSER] == 6  # creation fee + execution fee
    assert ch.bal[CAROL] == 97 and ch.bal[BOB] == 1_000
    assert sum(ch.bal.values()) == supply


def test_replay_with_wrong_period_fails():
    ch, sid = setup()
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
    ch.block([exec_tx(sid, month(2026, 12), 1)], ts=at(2027, 1, 31))
    assert ch.last.invalid_tx_ids and ch.bal[BOB] == 1_000


def test_max_occurrences_completes_and_end_at_resolves():
    ch = Chain({ALICE: 10_000, CAROL: 100})
    c = create_tx(max_occurrences=1)
    sid = sid_of(c)
    ch.block([c], ts=T0)
    ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
    assert ch.lm.standing_payments.open_count() == 0
    assert ch.last.next_snapshot.metadata["standing_events"] == [(sid, "completed")]

    ch2 = Chain({ALICE: 10_000})
    c2 = create_tx(max_occurrences=0, end_at=at(2027, 2, 1))
    sid2 = sid_of(c2)
    ch2.block([c2], ts=T0)
    ch2.block([], ts=at(2027, 2, 1))
    assert ch2.lm.standing_payments.open_count() == 0
    assert ch2.last.next_snapshot.metadata["standing_events"] == [(sid2, "ended")]


def test_state_hash_is_deterministic():
    def run():
        ch, sid = setup()
        ch.block([exec_tx(sid, month(2026, 12), 0)], ts=at(2026, 12, 31))
        return [h[-1] for h in ch.history]
    assert run() == run()
