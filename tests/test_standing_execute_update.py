"""`standing_payment_execute` and `standing_payment_update` through the real
`apply_block` (#34).

Execute: anyone may send it; it names only the authorization; it pays the
period the block falls in and nothing else, at most once per period, never
before the first due point or after the end, never without funds or against the
payer's current policy, and a refused execute changes nothing and pays nothing.
The sweep and an execute share one book, so whichever comes first pays and the
other finds the period settled.

Update: the payer ends an authorization and starts its next version in one
transaction. The old terms are never edited; the new version has its own id,
`version` + 1 and the id it replaces.

Every block is compared against the same oracle `test_standing_apply` uses, and
`apply_block` raises on any supply drift, so every block is also a conservation
check.
"""
import itertools

import pytest

from consensus import engine as engine_mod
from consensus.engine import standing_payment_inputs
from consensus.standing import (
    MAX_OPEN_STANDING_PER_PAYER,
    OUTCOME_REPLACED,
    parse_standing_payment_create,
)
from consensus.serialization import compute_standing_resolved_acc

from tests.test_standing_apply import (
    ALICE, BOB, CAROL, CLAUSE, EVERY, FAR, HEIGHT, PROPOSER, SKS, TS,
    Chain, Oracle, _logs, _sign, cancel_tx, create_tx, sid_of, spend_tx,
)
from tests.test_standing_apply import evaluator  # noqa: F401  (fixture)

_SEQ = itertools.count()


def execute_tx(sid_hex, sender=CAROL, seq=0, *, fee_limit="100", signer_sk=None,
               mutate=None, **extra):
    tx = {
        "tx_id": f"execute-{next(_SEQ)}",
        "tx_type": "standing_payment_execute",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 10_000,
        "fee_limit": str(fee_limit),
        "standing_id": sid_hex,
    }
    tx.update(extra)
    _sign(tx, signer_sk if signer_sk is not None else SKS[sender])
    if mutate:
        mutate(tx)
    return tx


def update_tx(sid_hex, sender=ALICE, seq=1, *, recipient=BOB, amount=150,
              interval=EVERY, first_due=HEIGHT + 50, periods=3, fee_limit="100",
              signer_sk=None, mutate=None):
    tx = {
        "tx_id": f"update-{next(_SEQ)}",
        "tx_type": "standing_payment_update",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 10_000,
        "fee_limit": str(fee_limit),
        "standing_id": sid_hex,
        "recipient_pubkey": recipient,
        "amount": amount,
        "interval_blocks": interval,
        "first_due": first_due,
        "periods": periods,
    }
    _sign(tx, signer_sk if signer_sk is not None else SKS[sender])
    if mutate:
        mutate(tx)
    return tx


def new_sid(tx) -> str:
    return parse_standing_payment_create(tx).standing_id.hex()


def _rich():
    return {ALICE: 1_000, BOB: 0, CAROL: 50, PROPOSER: 0}


def _created(ch, oracle, *, fee=7, **over):
    tx = create_tx(**over)
    ch.block([tx])
    oracle.create(tx, fee=fee)
    return tx, sid_of(tx)


# --- execute: who, what, when --------------------------------------------------------

def test_anyone_may_execute_the_due_period_and_the_executor_pays_only_its_fee():
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, sid = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)

    h = HEIGHT + 5
    ch.block([execute_tx(sid)], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=7)   # the executor's fee and sequence
    oracle.check(ch)
    # One payment: the execute's. The sweep in the same block finds it settled.
    assert [(e["outcome"], e["period"], e.get("executor_pubkey")) for e in ch.events()] == \
        [("paid", 0, CAROL)]
    progress = ch.book.progress[bytes.fromhex(sid)]
    assert (progress.period, progress.paid_count, progress.last_paid_height) == (1, 1, h)
    assert ch.book.describe(bytes.fromhex(sid))["status"] == "waiting"


def test_the_payee_and_the_payer_may_execute_too():
    for executor in (BOB, ALICE):
        start = {ALICE: 1_000, BOB: 20, CAROL: 0, PROPOSER: 0}
        ch, oracle = Chain(dict(start), fee=7), Oracle(dict(start))
        _tx, sid = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)
        seq = 1 if executor == ALICE else 0
        h = HEIGHT + 5
        ch.block([execute_tx(sid, sender=executor, seq=seq)], height=h, ts=TS + h)
        oracle.pay(ALICE, BOB, 100, ts=TS + h)
        oracle.create({"sender_pubkey": executor}, fee=7)
        oracle.check(ch)


def test_an_execute_before_the_first_due_point_is_refused_and_costs_nothing():
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, sid = _created(ch, oracle, first_due=HEIGHT + 5)
    result = ch.block([execute_tx(sid)], height=HEIGHT + 4, ts=TS + 4)
    oracle.check(ch)
    assert "not due yet" in _logs(result) and ch.events() == []
    assert ch.book.progress[bytes.fromhex(sid)].period == 0


def test_a_second_execute_in_the_same_period_is_refused():
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, sid = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)
    h = HEIGHT + 5
    ch.block([], height=h, ts=TS + h)        # the sweep pays period 0
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    result = ch.block([execute_tx(sid)], height=h + 1, ts=TS + h + 1)
    oracle.check(ch)
    assert "already settled" in _logs(result)
    # And twice in one block: the second finds the first's payment.
    ch2, oracle2 = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, sid2 = _created(ch2, oracle2, fee=0, amount=100, first_due=HEIGHT + 5)
    result = ch2.block([execute_tx(sid2, seq=0), execute_tx(sid2, sender=BOB, seq=0)],
                       height=h, ts=TS + h)
    oracle2.pay(ALICE, BOB, 100, ts=TS + h)
    oracle2.create({"sender_pubkey": CAROL}, fee=0)
    oracle2.check(ch2)
    assert [e["outcome"] for e in ch2.events()] == ["paid"]
    assert "already settled" in _logs(result)


def test_a_signed_execute_pays_one_period_and_cannot_be_replayed_in_the_next():
    """An execute names the authorization, not a period. A copy of its signed bytes in
    the next period is refused by the executor's sequence number: it pays nothing and
    costs nothing, and the sweep pays that period as it always does."""
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, sid = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)
    h = HEIGHT + 5
    execute = execute_tx(sid)
    ch.block([execute], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=7)   # the executor's fee and sequence
    oracle.check(ch)

    h += EVERY
    result = ch.block([dict(execute)], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)           # by the sweep, not by the copy
    oracle.check(ch)
    assert "Invalid sequence number" in _logs(result)
    assert [(e["outcome"], e["period"], e.get("executor_pubkey")) for e in ch.events()] == \
        [("paid", 1, None)]


def test_an_execute_at_the_end_is_refused_and_the_sweep_closes_the_schedule():
    start = {ALICE: 10, BOB: 0, CAROL: 50, PROPOSER: 0}
    ch, oracle = Chain(dict(start), fee=0), Oracle(dict(start))
    _tx, sid = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5, periods=1)
    end = HEIGHT + 5 + EVERY
    result = ch.block([execute_tx(sid)], height=end, ts=TS + end)
    oracle.check(ch)
    assert "the schedule has ended" in _logs(result)
    assert ch.outcomes() == [("missed", 0), ("ended", 1)]


def test_an_execute_after_a_closed_window_pays_the_current_period_and_misses_the_old():
    start = {ALICE: 10, BOB: 0, CAROL: 500, PROPOSER: 0}
    ch, oracle = Chain(dict(start), fee=0), Oracle(dict(start))
    _tx, sid = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5, periods=3)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)                # period 0: unfunded
    assert ch.outcomes() == [("unfunded", 0)]
    h = HEIGHT + 5 + EVERY                                      # period 1 opens
    ch.block([spend_tx(CAROL, ALICE, 100, 0, fee_limit="0"), execute_tx(sid, seq=1)],
             height=h, ts=TS + h)
    oracle.spend(CAROL, ALICE, 100, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=0)
    oracle.check(ch)
    assert [(e["outcome"], e["period"], e.get("count")) for e in ch.events()] == \
        [("missed", 0, 1), ("paid", 1, None)]
    progress = ch.book.progress[bytes.fromhex(sid)]
    assert (progress.period, progress.paid_count, progress.missed_count) == (2, 1, 1)


def test_an_unfunded_execute_is_refused_and_does_not_advance_the_period():
    start = {ALICE: 60, BOB: 0, CAROL: 50, PROPOSER: 0}
    ch, oracle = Chain(dict(start), fee=7), Oracle(dict(start))
    _tx, sid = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)
    h = HEIGHT + 5
    result = ch.block([execute_tx(sid)], height=h, ts=TS + h)
    oracle.check(ch)                                   # no debt, no fee, no payment
    assert "cannot fund period 0" in _logs(result)
    assert ch.outcomes() == [("unfunded", 0)]           # the sweep's own retry
    progress = ch.book.progress[bytes.fromhex(sid)]
    assert (progress.period, progress.paid_count, progress.tries) == (0, 0, 1)


def test_money_staged_earlier_in_the_block_funds_an_execute():
    start = {ALICE: 0, BOB: 0, CAROL: 500, PROPOSER: 0}
    ch, oracle = Chain(dict(start), fee=0), Oracle(dict(start))
    _tx, sid = _created(ch, oracle, fee=0, amount=200, first_due=HEIGHT + 5)
    h = HEIGHT + 5
    ch.block([spend_tx(CAROL, ALICE, 200, 0, fee_limit="0"), execute_tx(sid, seq=1)],
             height=h, ts=TS + h)
    oracle.spend(CAROL, ALICE, 200, ts=TS + h)
    oracle.pay(ALICE, BOB, 200, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=0)
    oracle.check(ch)


def test_the_payers_current_policy_blocks_an_execute(evaluator):
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, sid = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = CLAUSE
    evaluator.set_verdict(CLAUSE, lambda inputs: 0)
    h = HEIGHT + 5
    result = ch.block([execute_tx(sid)], height=h, ts=TS + h)
    oracle.check(ch)                                   # Carol pays no fee either
    assert "policy blocks this payment" in _logs(result)
    # The sweep then judges the period itself, the same way.
    assert ch.outcomes() == [("missed", 0)]


def test_an_execute_is_judged_on_the_real_recipient_amount_and_empty_slots(evaluator):
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, sid = _created(ch, oracle, fee=0, amount=123, first_due=HEIGHT + 5)
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = CLAUSE
    h = HEIGHT + 5
    ch.block([execute_tx(sid)], height=h, ts=TS + h)
    # The execute's own check is the one call: the sweep finds the period paid.
    assert len(evaluator.verdict_calls) == 1
    body, inputs = evaluator.verdict_calls[0]
    assert body == CLAUSE
    assert inputs["i1"] == "123" and inputs["i2"] == "1000"
    assert BOB in inputs["i4"] and ALICE in inputs["i3"] and ALICE in inputs["i12"]
    assert CAROL not in str(inputs)                    # the executor is not an input
    assert inputs["i5"] == str(TS + h)
    assert all(inputs[f"i{n}"] == "0" for n in range(18, 26))
    # Exactly what the sweep would have fed for the same payment.
    sweep = standing_payment_inputs(ALICE, BOB, 123, parent_balance="1000", since_last=None,
                                    slots_active=True, timestamp=TS + h)
    assert [f"i{k}" for k in sweep] == [k for k in inputs if int(k[1:]) in sweep]


def test_the_executor_cannot_change_the_amount_or_the_recipient():
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, sid = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5)
    h = HEIGHT + 5
    # Extra fields are not signed and never read: the stored terms pay.
    ch.block([execute_tx(sid, amount=999, recipient_pubkey=CAROL)], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=0)
    oracle.check(ch)


def test_an_execute_whose_id_was_changed_after_signing_is_refused():
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _first, sid_a = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)
    second = create_tx(seq=1, amount=300, first_due=HEIGHT + 6)
    ch.block([second], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(second, fee=7)
    h = HEIGHT + 6
    ch.block([], height=HEIGHT + 5, ts=TS + HEIGHT + 5)       # the sweep pays the first
    oracle.pay(ALICE, BOB, 100, ts=TS + HEIGHT + 5)
    result = ch.block(
        [execute_tx(sid_a, mutate=lambda tx: tx.__setitem__("standing_id", sid_of(second)))],
        height=h, ts=TS + h)
    assert "signature invalid" in _logs(result)
    oracle.pay(ALICE, BOB, 300, ts=TS + h)                    # by the sweep, not by Carol
    oracle.check(ch)
    assert all("executor_pubkey" not in e for e in ch.events())


def test_a_cancel_before_an_execute_in_a_block_refuses_it_and_after_it_does_not():
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, sid = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5)
    h = HEIGHT + 5
    result = ch.block([cancel_tx(sid, seq=1), execute_tx(sid)], height=h, ts=TS + h)
    oracle.cancel(ALICE)
    oracle.check(ch)
    assert "unknown or already ended" in _logs(result)
    assert ch.outcomes() == [("cancelled", 0)]

    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, sid = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5)
    ch.block([execute_tx(sid), cancel_tx(sid, seq=1)], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=0)
    oracle.cancel(ALICE)
    oracle.check(ch)
    assert ch.outcomes() == [("paid", 0), ("cancelled", 0)]


def test_an_execute_stamps_the_payers_cooldown_clock_not_the_executors():
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, sid = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5)
    h = HEIGHT + 5
    ch.block([execute_tx(sid)], height=h, ts=TS + h)
    assert ch.lts == {ALICE: TS + h}


def test_the_block_carries_at_most_the_execute_cap(monkeypatch):
    monkeypatch.setattr(engine_mod, "MAX_STANDING_EXECUTIONS_PER_BLOCK", 1)
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    a = create_tx(seq=0, amount=100, first_due=HEIGHT + 5)
    b = create_tx(seq=1, amount=100, first_due=HEIGHT + 5)
    ch.block([a, b])
    oracle.create(a, fee=0)
    oracle.create(b, fee=0)
    h = HEIGHT + 5
    result = ch.block([execute_tx(sid_of(a), seq=0), execute_tx(sid_of(b), sender=BOB, seq=0)],
                      height=h, ts=TS + h)
    assert "most standing payment executions" in _logs(result)
    # The sweep still pays the other one in the same block.
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=0)
    oracle.check(ch)


def test_createblock_defers_executes_over_the_cap_instead_of_destroying_them(monkeypatch):
    import consensus.standing as standing
    from commands import createblock

    monkeypatch.setattr(standing, "MAX_STANDING_EXECUTIONS_PER_BLOCK", 2)
    monkeypatch.setattr(createblock.db, "unreserve_mempool_txs", lambda ids: None)
    txs = [execute_tx("aa" * 32, sender=s, seq=0) for s in (ALICE, BOB, CAROL)]
    txs.append(execute_tx("bb" * 32, sender=CAROL, seq=1))
    exe, ids = list(txs), list(range(len(txs)))
    held = createblock._defer_payout_overflow(txs, exe, ids)
    # The third execute and every later tx of its sender wait for the next block.
    assert held == [2, 3] and [t["sender_pubkey"] for t in txs] == [ALICE, BOB]


# --- update -----------------------------------------------------------------------------

def test_an_update_replaces_the_authorization_with_a_new_version():
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, old = _created(ch, oracle, amount=100, first_due=HEIGHT + 5, periods=3)
    h = HEIGHT + 5
    ch.block([], height=h, ts=TS + h)                       # period 0 paid at 100
    oracle.pay(ALICE, BOB, 100, ts=TS + h)

    up = update_tx(old, amount=150, first_due=h + 40, periods=2)
    ch.block([up], height=h + 1, ts=TS + h + 1)
    oracle.create(up, fee=7)                                # one fee, like a create
    oracle.check(ch)
    new = new_sid(up)
    assert new != old
    assert [(e["standing_id"], e["outcome"]) for e in ch.events()] == \
        [(old, "replaced"), (new, "created")]
    assert ch.events()[0]["replaced_by"] == new and ch.events()[1]["replaces"] == old
    book = ch.book
    assert not book.knows(bytes.fromhex(old)) and book.knows(bytes.fromhex(new))
    assert book.version_of(bytes.fromhex(new)) == (2, bytes.fromhex(old))
    assert book.describe(bytes.fromhex(new))["version"] == 2
    assert book.open_count_for_payer(ALICE) == 1

    # The old terms never pay again; the new ones pay their own amount.
    for hh in range(h + 2, h + 41):
        ch.block([], height=hh, ts=TS + hh)
    oracle.pay(ALICE, BOB, 150, ts=TS + h + 40)
    oracle.check(ch)
    assert ch.outcomes() == [("paid", 0)]


def test_a_second_update_makes_version_three_of_the_same_line():
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, v1 = _created(ch, oracle, fee=0, first_due=HEIGHT + 5)
    up2 = update_tx(v1, seq=1, amount=120)
    ch.block([up2], height=HEIGHT + 1, ts=TS + 1)
    v2 = new_sid(up2)
    up3 = update_tx(v2, seq=2, amount=130)
    ch.block([up3], height=HEIGHT + 2, ts=TS + 2)
    v3 = new_sid(up3)
    assert ch.book.version_of(bytes.fromhex(v3)) == (3, bytes.fromhex(v2))
    # Both replaced entries are folded into the resolved commitment, in order.
    acc = bytes(32)
    for sid in (v1, v2):
        acc = compute_standing_resolved_acc(acc, bytes.fromhex(sid), OUTCOME_REPLACED)
    assert ch.book.resolved_state() == (2, acc)


@pytest.mark.parametrize("case,why", [
    ("not_payer", "only the payer may update"),
    ("unknown", "unknown or already ended"),
    ("past_first_due", "first_due must be in the future"),
    ("self_pay", "recipient must differ"),
    ("bad_interval", "interval_blocks"),
])
def test_an_inadmissible_update_changes_nothing_and_pays_nothing(case, why):
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, old = _created(ch, oracle, first_due=HEIGHT + 5)
    root = ch.book.root()
    tx = {
        "not_payer": lambda: update_tx(old, sender=CAROL, seq=0),
        "unknown": lambda: update_tx("00" * 32),
        "past_first_due": lambda: update_tx(old, first_due=HEIGHT + 1),
        "self_pay": lambda: update_tx(old, recipient=ALICE),
        "bad_interval": lambda: update_tx(old, interval=EVERY - 1),
    }[case]()
    result = ch.block([tx], height=HEIGHT + 1, ts=TS + 1)
    oracle.check(ch)
    assert why in _logs(result)
    assert ch.book.root() == root


@pytest.mark.parametrize("field,value", [
    ("standing_id", "00" * 32), ("amount", 151), ("recipient_pubkey", CAROL),
    ("first_due", HEIGHT + 51), ("periods", 4), ("interval_blocks", EVERY + 1),
])
def test_no_term_of_an_update_can_be_changed_after_signing(field, value):
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, old = _created(ch, oracle, first_due=HEIGHT + 5)
    ch.block([update_tx(old, mutate=lambda tx: tx.__setitem__(field, value))],
             height=HEIGHT + 1, ts=TS + 1)
    oracle.check(ch)
    assert set(ch.book.terms) == {bytes.fromhex(old)}


def test_an_update_at_the_payer_cap_is_allowed_one_for_one():
    ch = Chain({ALICE: 1_000, BOB: 0, CAROL: 0, PROPOSER: 0}, fee=0)
    txs = [create_tx(seq=s, first_due=HEIGHT + 5 + s) for s in range(MAX_OPEN_STANDING_PER_PAYER)]
    ch.block(txs)
    assert ch.book.open_count_for_payer(ALICE) == MAX_OPEN_STANDING_PER_PAYER
    up = update_tx(sid_of(txs[0]), seq=MAX_OPEN_STANDING_PER_PAYER)
    ch.block([up], height=HEIGHT + 1, ts=TS + 1)
    assert ch.book.knows(bytes.fromhex(new_sid(up)))
    assert ch.book.open_count_for_payer(ALICE) == MAX_OPEN_STANDING_PER_PAYER


def test_an_execute_of_a_replaced_version_is_refused():
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, old = _created(ch, oracle, fee=0, first_due=HEIGHT + 5)
    up = update_tx(old, first_due=HEIGHT + 50)
    h = HEIGHT + 5
    result = ch.block([up, execute_tx(old)], height=h, ts=TS + h)
    oracle.create(up, fee=0)
    oracle.check(ch)
    assert "unknown or already ended" in _logs(result)


def test_an_update_mined_at_its_new_first_due_point_is_refused_and_the_old_one_pays():
    """Apply judges an update by the block it lands in, like a create."""
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, old = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5)
    up = update_tx(old, first_due=HEIGHT + 6)
    ch.block([up], height=HEIGHT + 6, ts=TS + 6)
    oracle.pay(ALICE, BOB, 100, ts=TS + 6)            # the old terms are still in force
    oracle.check(ch)
    assert ch.book.knows(bytes.fromhex(old))



def test_an_execute_before_an_update_in_the_due_block_pays_and_the_update_still_applies():
    ch, oracle = Chain(_rich(), fee=0), Oracle(_rich())
    _tx, old = _created(ch, oracle, fee=0, amount=100, first_due=HEIGHT + 5)
    up = update_tx(old, first_due=HEIGHT + 50)
    h = HEIGHT + 5
    ch.block([execute_tx(old), up], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    oracle.create({"sender_pubkey": CAROL}, fee=0)
    oracle.create(up, fee=0)
    oracle.check(ch)
    assert [(e["outcome"], e["period"]) for e in ch.events()][:1] == [("paid", 0)]
    assert not ch.book.knows(bytes.fromhex(old))
    assert ch.book.knows(bytes.fromhex(new_sid(up)))


def test_a_second_update_of_the_same_version_in_one_block_is_refused():
    """A version line never forks: the first update ends the old id."""
    ch, oracle = Chain(_rich(), fee=7), Oracle(_rich())
    _tx, old = _created(ch, oracle, first_due=HEIGHT + 5)
    first = update_tx(old, seq=1, first_due=HEIGHT + 50)
    second = update_tx(old, seq=2, amount=120, first_due=HEIGHT + 60)
    result = ch.block([first, second], height=HEIGHT + 1, ts=TS + 1)
    oracle.create(first, fee=7)
    oracle.check(ch)
    assert "unknown or already ended" in _logs(result)
    assert second["tx_id"] in result.invalid_tx_ids
    assert ch.book.knows(bytes.fromhex(new_sid(first)))
    assert not ch.book.knows(bytes.fromhex(new_sid(second)))


def test_an_execute_whose_fee_cannot_be_paid_changes_nothing_and_the_sweep_pays():
    """The payer executes holding the amount but not also the fee."""
    start = {ALICE: 107, BOB: 0, CAROL: 0, PROPOSER: 0}
    ch, oracle = Chain(dict(start), fee=7), Oracle(dict(start))
    _tx, sid = _created(ch, oracle, amount=100, first_due=HEIGHT + 5)   # 107 - 7 = 100 left
    h = HEIGHT + 5
    ex = execute_tx(sid, sender=ALICE, seq=1)
    result = ch.block([ex], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)            # by the sweep, fee-free
    oracle.check(ch)
    assert ex["tx_id"] in result.invalid_tx_ids
    assert [(e["outcome"], e["period"], e.get("executor_pubkey")) for e in ch.events()] == \
        [("paid", 0, None)]
    assert ch.book.progress[bytes.fromhex(sid)].paid_count == 1


# --- replay -----------------------------------------------------------------------------

def test_replay_and_a_fresh_apply_give_the_same_state_hashes_with_executes_and_updates(evaluator):
    def run(replay):
        ch = Chain(_rich(), fee=3)
        a = create_tx(seq=0, amount=100, first_due=HEIGHT + 5, periods=4)
        ch.block([a], replay=replay)
        h = HEIGHT + 5
        ch.block([execute_tx(sid_of(a))], height=h, ts=TS + h, replay=replay)
        up = update_tx(sid_of(a), seq=1, amount=120, first_due=h + 20)
        ch.block([up], height=h + 1, ts=TS + h + 1, replay=replay)
        ch.block([execute_tx(new_sid(up), seq=1)], height=h + 20, ts=TS + h + 20,
                 replay=replay)
        ch.block([], height=h + 21, ts=TS + h + 21, replay=replay)
        return ch.hashes, ch.bal, ch.book.root()

    assert run(False) == run(True)
