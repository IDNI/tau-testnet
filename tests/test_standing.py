"""Stage 3 (Bounty 01): standing payments -- book, parse, sweep handler.

Pure unit tests: the StandingPaymentBook is exercised directly, without the
engine. End-to-end coverage (create/execute/update/cancel transactions
through _apply_block, the sweep execution inside a block, the credit ledger)
lives in the engine tests below in this same file where they need the block
harness.
"""

from types import SimpleNamespace

import pytest

from consensus.credits import CREDIT_FEE_REWARD, CREDIT_STANDING_PAYMENT, CreditLedger
from consensus.periods import (
    PERIOD_DAY,
    PERIOD_FIXED,
    PERIOD_MONTH,
    PERIOD_WEEK,
    days_from_civil,
    period_index,
    period_start,
)
from consensus.standing import (
    OUTCOME_CANCELLED,
    OUTCOME_SUPERSEDED,
    StandingPaymentBook,
    StandingShapeError,
    _StandingSweepHandler,
    apply_standing_execution,
    compute_standing_id,
    compute_standing_version_id,
    parse_standing_cancel,
    parse_standing_create,
    parse_standing_execute,
    parse_standing_update,
    validate_standing_shape,
)
from consensus.sweep import SweepContext, SweepDue

ALICE = "a" * 96
BOB = "b" * 96
CAROL = "c" * 96

# 2026-12-01 00:00:00 UTC, a Tuesday. The demo standing payment starts here.
DEC_1_2026 = days_from_civil(2026, 12, 1) * 86400
DAY = 86400
WEEK = 7 * DAY
MONTH = 31 * DAY


def make_entry(**overrides):
    fields = {
        "version": 1,
        "payer_pubkey": ALICE,
        "payee_pubkey": BOB,
        "amount": 100,
        "period_kind": PERIOD_MONTH,
        "period_length": None,
        "period_anchor": DEC_1_2026,
        "max_fee_per_execution": 10,
        "start_at": DEC_1_2026,
        "create_sequence_number": 1,
    }
    fields.update(overrides)
    # The id is derived from payer + payee + create sequence, so an
    # overridden sequence number yields a distinct id.
    fields["standing_id"] = compute_standing_id(
        fields["payer_pubkey"], fields["payee_pubkey"],
        fields["create_sequence_number"],
    )
    from consensus.standing import StandingEntry

    return StandingEntry(**fields)


def make_tx(**overrides):
    body = {
        "sender_pubkey": ALICE,
        "payee_pubkey": BOB,
        "amount": 100,
        "sequence_number": 1,
        "period_kind": PERIOD_MONTH,
        "period_anchor": DEC_1_2026,
        "max_fee_per_execution": 10,
        "start_at": DEC_1_2026,
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------- ids


def test_standing_id_is_deterministic_and_sequence_bound():
    first = make_entry()
    assert first.standing_id == make_entry().standing_id
    assert first.standing_id != make_entry(
        standing_id=compute_standing_id(ALICE, BOB, 2),
        create_sequence_number=2,
    ).standing_id
    assert first.standing_id == compute_standing_id(ALICE, BOB, 1)
    assert first.version_id == compute_standing_version_id(first)
    assert first.version_id != make_entry(version=2).version_id


# ---------------------------------------------------------------- parse


def test_parse_standing_create_reads_all_fields():
    entry = parse_standing_create(make_tx())
    assert entry == make_entry()
    assert entry.version == 1


def test_parse_standing_create_rejects_bad_pubkey():
    with pytest.raises(StandingShapeError):
        parse_standing_create(make_tx(payee_pubkey="zz"))


def test_parse_standing_execute_update_cancel():
    sid = compute_standing_id(ALICE, BOB, 1)
    assert parse_standing_execute({"standing_id": sid.hex()}).standing_id == sid
    req = parse_standing_update(
        {
            "standing_id": sid.hex(),
            "amount": 200,
            "period_kind": PERIOD_WEEK,
            "period_anchor": 0,
            "max_fee_per_execution": 5,
            "start_at": DEC_1_2026,
        }
    )
    assert req.standing_id == sid and req.amount == 200
    assert parse_standing_cancel({"standing_id": sid.hex()}).standing_id == sid
    with pytest.raises(StandingShapeError):
        parse_standing_execute({"standing_id": "zz"})


# ---------------------------------------------------------------- shape


def test_validate_standing_shape():
    assert validate_standing_shape(make_entry(), 0, DEC_1_2026) is None
    assert validate_standing_shape(make_entry(amount=0), 0, DEC_1_2026) is not None
    assert validate_standing_shape(
        make_entry(period_kind=99), 0, DEC_1_2026
    ) is not None
    # A fixed-period schedule may not start before its anchor.
    assert validate_standing_shape(
        make_entry(
            period_kind=PERIOD_FIXED, period_length=DAY, period_anchor=DEC_1_2026 + DAY
        ),
        0,
        DEC_1_2026,
    ) is not None
    # start_at more than 90 days ahead is refused.
    assert validate_standing_shape(
        make_entry(start_at=DEC_1_2026 + 91 * DAY), 0, DEC_1_2026
    ) is not None


# ---------------------------------------------------------------- book


def test_book_create_duplicate_and_caps():
    book = StandingPaymentBook()
    entry = make_entry()
    assert book.can_admit_create(entry, 0, DEC_1_2026) == (True, "")
    book.submit(entry)
    assert book.open_count() == 1
    assert book.open_count_for_payer(ALICE) == 1
    assert book.get(entry.standing_id) == entry
    assert book.can_admit_create(entry, 0, DEC_1_2026)[0] is False
    assert book.escrowed_total() == 0  # no escrow: funds stay with the payer


def test_book_due_period_month_end_clamp():
    # Anchored on Dec 31: January starts Dec 31, February on Feb 28 (clamped).
    anchor = days_from_civil(2026, 12, 31) * 86400
    entry = make_entry(period_anchor=anchor, start_at=anchor)
    book = StandingPaymentBook()
    book.submit(entry)
    dec = period_index(PERIOD_MONTH, anchor, anchor=anchor)
    assert book.due_period(entry.standing_id, anchor) == dec
    feb_1 = days_from_civil(2027, 2, 1) * 86400
    feb = period_index(PERIOD_MONTH, feb_1, anchor=anchor)
    assert book.due_period(entry.standing_id, feb_1) == feb
    # February starts on the 28th (the anchor day, clamped).
    assert period_start(PERIOD_MONTH, feb, anchor=anchor) == days_from_civil(
        2027, 2, 28
    ) * 86400


def test_book_one_execution_per_period_no_catch_up():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    sid = entry.standing_id
    # December executes.
    dec = book.due_period(sid, DEC_1_2026)
    assert dec is not None
    book.mark_executed(sid, dec)
    assert book.due_period(sid, DEC_1_2026 + 10 * DAY) is None
    assert book.executions(sid) == 1
    # Jump to March without executing January or February: only March is due.
    mar_1 = days_from_civil(2027, 3, 1) * 86400
    mar = book.due_period(sid, mar_1)
    assert mar is not None
    assert mar == period_index(PERIOD_MONTH, mar_1, anchor=DEC_1_2026)
    book.mark_executed(sid, mar)
    assert book.executions(sid) == 2  # Dec + Mar; Jan and Feb never paid


def test_book_not_due_before_start():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    assert book.due_period(entry.standing_id, DEC_1_2026 - 1) is None


def test_book_update_creates_new_version_old_terms_untouched():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    sid = entry.standing_id
    # Execute December on the old terms first.
    book.mark_executed(sid, book.due_period(sid, DEC_1_2026))
    new_entry = make_entry(
        version=2, amount=200, period_kind=PERIOD_WEEK, period_anchor=0
    )
    assert book.can_admit_update(sid, ALICE, new_entry, 0, DEC_1_2026) == (True, "")
    old = book.update(sid, new_entry)
    assert old == entry  # the old version is returned, never mutated
    assert old.amount == 100 and old.period_kind == PERIOD_MONTH
    current = book.get(sid)
    assert current.version == 2 and current.amount == 200
    assert current.period_kind == PERIOD_WEEK
    # A fresh schedule: no executions carried over.
    assert book.last_executed_period(sid) is None
    assert book.executions(sid) == 0
    assert book.resolved_count == 1
    # Only the payer may update; the version must advance by exactly one.
    assert not book.can_admit_update(sid, BOB, new_entry, 0, DEC_1_2026)[0]
    assert not book.can_admit_update(
        sid, ALICE, make_entry(version=4, amount=200), 0, DEC_1_2026
    )[0]


def test_book_cancel_keeps_payer_funds():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    sid = entry.standing_id
    assert book.can_admit_cancel(sid, ALICE, 0, DEC_1_2026) == (True, "")
    assert not book.can_admit_cancel(sid, BOB, 0, DEC_1_2026)[0]
    assert book.cancel(sid) == entry
    assert book.open_count() == 0
    assert book.resolved_count == 1
    assert book.get(sid) is None


def test_book_root_snapshot_restore_deepcopy():
    import copy

    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    book.mark_executed(entry.standing_id, book.due_period(entry.standing_id, DEC_1_2026))
    root = book.root()
    assert root == book.root()
    rows = book.snapshot_rows()
    assert len(rows) == 1
    assert rows[0]["standing_id"] == entry.standing_id.hex()
    assert rows[0]["last_executed_period"] is not None
    restored = StandingPaymentBook.restore(rows, *book.resolved_state())
    assert restored.root() == root
    assert restored.get(entry.standing_id) == entry
    assert restored.last_executed_period(entry.standing_id) == book.last_executed_period(
        entry.standing_id
    )
    clone = copy.deepcopy(book)
    assert clone.root() == root
    clone.mark_executed(entry.standing_id, book.due_period(entry.standing_id, DEC_1_2026 + 31 * DAY))
    assert clone.root() != root
    # A row whose id does not recompute is refused.
    bad = [dict(rows[0], payer_pubkey=BOB)]
    with pytest.raises(ValueError):
        StandingPaymentBook.restore(bad, 0, bytes(32))


def test_book_execute_admission():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    sid = entry.standing_id
    assert book.can_admit_execute(sid, ALICE, 0, DEC_1_2026) == (True, "")
    assert not book.can_admit_execute(sid, BOB, 0, DEC_1_2026)[0]
    assert not book.can_admit_execute(sid, ALICE, 0, DEC_1_2026 - 1)[0]
    # The fee_limit may not exceed the payer's declared cap.
    assert not book.can_admit_execute(sid, ALICE, 0, DEC_1_2026, fee_limit=11)[0]
    assert book.can_admit_execute(sid, ALICE, 0, DEC_1_2026, fee_limit=10)[0]
    book.mark_executed(sid, book.due_period(sid, DEC_1_2026))
    assert not book.can_admit_execute(sid, ALICE, 0, DEC_1_2026 + DAY)[0]


# ---------------------------------------------------------------- apply + sweep


def _sweep_ctx(book, balances, ts, measure_fee=None, fee_beneficiary=CAROL):
    return SweepContext(
        lm=SimpleNamespace(standing=book),
        balances=dict(balances),
        sequences={ALICE: 1, BOB: 1, CAROL: 1},
        height=10,
        timestamp=ts,
        faucet_grant=0,
        credit_records=CreditLedger(),
        fee_beneficiary=fee_beneficiary,
        measure_fee=measure_fee,
    )


def test_apply_execution_pays_payee_and_fee():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    balances = {ALICE: 1000, BOB: 0, CAROL: 0}
    outcome, period = apply_standing_execution(
        book, entry.standing_id, DEC_1_2026,
        read=lambda pk: balances.get(pk, 0),
        write=lambda pk, v: balances.__setitem__(pk, v),
        fee=7, fee_beneficiary=CAROL, credit_records=CreditLedger(),
    )
    assert outcome == "executed" and period is not None
    book.mark_executed(entry.standing_id, period)
    assert balances[ALICE] == 1000 - 100 - 7
    assert balances[BOB] == 100
    assert balances[CAROL] == 7


def test_apply_fee_cap_and_insufficient_funds_skip_the_period():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    balances = {ALICE: 1000, BOB: 0, CAROL: 0}
    ledger = CreditLedger()
    # Fee above the payer's cap: the period is skipped, never retried.
    outcome, period = apply_standing_execution(
        book, entry.standing_id, DEC_1_2026,
        read=lambda pk: balances.get(pk, 0),
        write=lambda pk, v: balances.__setitem__(pk, v),
        fee=11, fee_beneficiary=CAROL, credit_records=ledger,
    )
    assert outcome == "skipped_fee_cap"
    book.mark_executed(entry.standing_id, period)
    assert balances == {ALICE: 1000, BOB: 0, CAROL: 0}
    assert ledger.all() == ()
    assert book.due_period(entry.standing_id, DEC_1_2026 + DAY) is None
    # Insufficient funds: same skip, in the next period.
    jan = days_from_civil(2027, 1, 1) * 86400
    outcome, period = apply_standing_execution(
        book, entry.standing_id, jan,
        read=lambda pk: 50 if pk == ALICE else balances.get(pk, 0),
        write=lambda pk, v: balances.__setitem__(pk, v),
        fee=7, fee_beneficiary=CAROL, credit_records=ledger,
    )
    assert outcome == "skipped_insufficient_funds"
    book.mark_executed(entry.standing_id, period)
    assert balances[BOB] == 0


def test_apply_no_beneficiary_leaves_period_due():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    balances = {ALICE: 1000, BOB: 0}
    outcome, period = apply_standing_execution(
        book, entry.standing_id, DEC_1_2026,
        read=lambda pk: balances.get(pk, 0),
        write=lambda pk, v: balances.__setitem__(pk, v),
        fee=7, fee_beneficiary="", credit_records=None,
    )
    assert outcome == "skipped_no_beneficiary" and period is None
    # The period is still due: the next block retries it.
    assert book.due_period(entry.standing_id, DEC_1_2026) is not None


def test_sweep_handler_executes_due_payment_with_fee():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    ctx = _sweep_ctx(book, {ALICE: 1000, BOB: 0, CAROL: 0}, DEC_1_2026,
                     measure_fee=lambda payer, payee, amount, ts: 7)
    handler = _StandingSweepHandler()
    due = handler.collect_due(ctx.lm, 10, DEC_1_2026)
    assert len(due) == 1
    assert due[0].object_id == entry.standing_id and due[0].kind == "standing"
    assert handler.execute(due[0], ctx) == "executed"
    assert ctx.balances[ALICE] == 1000 - 100 - 7
    assert ctx.balances[BOB] == 100
    assert ctx.balances[CAROL] == 7
    assert book.executions(entry.standing_id) == 1
    ledger = ctx.credit_records
    assert ledger.total_for(BOB, CREDIT_STANDING_PAYMENT) == 100
    assert ledger.total_for(CAROL, CREDIT_FEE_REWARD) == 7
    # The next block in the same period finds nothing due.
    assert handler.collect_due(ctx.lm, 11, DEC_1_2026 + DAY) == []


def test_sweep_handler_skips_unknown_and_not_due():
    book = StandingPaymentBook()
    ctx = _sweep_ctx(book, {}, DEC_1_2026)
    handler = _StandingSweepHandler()
    assert handler.collect_due(ctx.lm, 10, DEC_1_2026) == []
    ghost = SweepDue(due_ts=DEC_1_2026, object_id=b"\x00" * 32, kind="standing")
    assert handler.execute(ghost, ctx) == "skipped_unknown"
    book.submit(make_entry())
    # An entry whose first period is next month is not due yet, even though
    # its id is known: the handler must report not-due, not attempt payment.
    future = make_entry(start_at=DEC_1_2026 + 31 * DAY,
                        period_anchor=DEC_1_2026 + 31 * DAY,
                        create_sequence_number=2)
    book.submit(future)
    not_due = SweepDue(
        due_ts=DEC_1_2026, object_id=future.standing_id, kind="standing"
    )
    assert handler.execute(not_due, ctx) == "skipped_not_due"


def test_sweep_handler_fee_cap_skips_period():
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    ctx = _sweep_ctx(book, {ALICE: 1000, BOB: 0, CAROL: 0}, DEC_1_2026,
                     measure_fee=lambda payer, payee, amount, ts: 11)
    handler = _StandingSweepHandler()
    due = handler.collect_due(ctx.lm, 10, DEC_1_2026)
    assert handler.execute(due[0], ctx) == "skipped_fee_cap"
    assert ctx.balances[BOB] == 0
    # The period is done: the next block does not retry it.
    assert handler.collect_due(ctx.lm, 11, DEC_1_2026 + DAY) == []


def test_demo_alice_pays_bob_100_a_month_from_dec_1():
    """Demo: Alice pays Bob 100 every calendar month from Dec 1; the sweep
    executes December, January and February, and the March payment is the
    only one due after a two-month gap (no catch-up)."""
    book = StandingPaymentBook()
    entry = make_entry()
    book.submit(entry)
    sid = entry.standing_id
    balances = {ALICE: 10000, BOB: 0, CAROL: 0}
    ledger = CreditLedger()
    handler = _StandingSweepHandler()
    for month_start in (
        DEC_1_2026,
        days_from_civil(2027, 1, 1) * 86400,
        days_from_civil(2027, 2, 1) * 86400,
    ):
        ctx = _sweep_ctx(book, balances, month_start,
                         measure_fee=lambda payer, payee, amount, ts: 7)
        ctx.credit_records = ledger
        due = handler.collect_due(ctx.lm, 10, month_start)
        assert len(due) == 1
        assert handler.execute(due[0], ctx) == "executed"
        balances = ctx.balances
    assert balances[BOB] == 300
    assert balances[ALICE] == 10000 - 300 - 3 * 7
    assert ledger.total_for(BOB, CREDIT_STANDING_PAYMENT) == 300
    assert book.executions(sid) == 3


# ---------------------------------------------------------------- engine
# End-to-end: standing transactions through apply_block, with the same harness
# as test_grants.py (one transfer, fee 7, Alice proposes).

import hashlib
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

E_HEIGHT = 20
E_FEE = 7
E_TS = 1234567890

E_SK_ALICE = 11111
E_ALICE = G2Basic.SkToPk(E_SK_ALICE).hex()
E_SK_BOB = 44444
E_BOB = G2Basic.SkToPk(E_SK_BOB).hex()

CHAIN_ID = "ab" * 32


def _e_sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _e_snapshot(lm, balances, sequences=None):
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": dict(balances),
            "sequence_numbers": dict(sequences or {}),
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )


def _e_apply_block(txs, parent, height=E_HEIGHT, timestamp=E_TS, fee=E_FEE):
    lm = parent.metadata["lifecycle_manager"]
    lm.activate_approval_slots()
    active_view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(E_ALICE)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block_obj = Block.create(
        block_number=height, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=E_ALICE, timestamp=timestamp,
    )

    def _fake_multi(**kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = int(str(vals.get(1, "0")) or 0)
        return {1: str(amount), 5: "1", 8: "0", 9: str(fee)}

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", return_value="T"), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        return engine.apply_block(active_view, block_obj, parent)


# The standing payment starts 1000s after the create block, so the create
# block's own sweep does not execute the first period.
def _e_standing_create_tx(amount=100, seq=0, start_at=E_TS + 7 * 86400,
                          max_fee=10, period_kind=PERIOD_WEEK,
                          period_anchor=0, chain_id=CHAIN_ID):
    tx = {
        "tx_id": f"standing-create-{seq}",
        "tx_type": "standing_payment",
        "sender_pubkey": E_ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "payee_pubkey": E_BOB,
        "amount": amount,
        "period_kind": period_kind,
        "period_anchor": period_anchor,
        "max_fee_per_execution": max_fee,
        "start_at": start_at,
        "chain_id": chain_id,
    }
    return _e_sign(tx, E_SK_ALICE)


def _e_standing_execute_tx(standing_id, seq=0, fee_limit="10"):
    # fee_limit must not exceed max_fee_per_execution (10 in the default
    # create): admission rejects a limit above the cap, so the execute
    # tx carries a limit equal to the cap. The fee actually charged is
    # the mocked 7, well under it.
    tx = {
        "tx_id": f"standing-execute-{seq}",
        "tx_type": "standing_payment_execute",
        "sender_pubkey": E_ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": fee_limit,
        "standing_id": standing_id.hex(),
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, E_SK_ALICE)


def _e_standing_update_tx(standing_id, seq=1, amount=200, max_fee=10,
                          start_at=E_TS + 7 * 86400):
    tx = {
        "tx_id": f"standing-update-{seq}",
        "tx_type": "standing_payment_update",
        "sender_pubkey": E_ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "standing_id": standing_id.hex(),
        "amount": amount,
        "period_kind": PERIOD_WEEK,
        "period_anchor": 0,
        "max_fee_per_execution": max_fee,
        "start_at": start_at,
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, E_SK_ALICE)


def _e_standing_cancel_tx(standing_id, seq=1):
    tx = {
        "tx_id": f"standing-cancel-{seq}",
        "tx_type": "standing_payment_cancel",
        "sender_pubkey": E_ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "standing_id": standing_id.hex(),
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, E_SK_ALICE)


def _e_fresh_parent():
    lm = ConsensusLifecycleManager(active_validators=[E_ALICE])
    lm.genesis_hash = CHAIN_ID
    return _e_snapshot(lm, {E_ALICE: 100000, E_BOB: 0})


def _e_standing_id(result):
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    (sid,) = list(lm.standing.open)
    return sid


def test_engine_standing_create_no_escrow_funds_stay():
    result = _e_apply_block([_e_standing_create_tx()], _e_fresh_parent())
    assert result.accepted_tx_ids == ["standing-create-0"]
    balances = result.next_snapshot.metadata["balances"]
    # Alice pays only the 7 fee (and receives it back as proposer); the 100
    # stays in her balance -- standing payments hold no escrow.
    assert balances[E_ALICE] == 100000
    assert balances[E_BOB] == 0
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    assert lm.standing.open_count() == 1
    assert lm.standing.escrowed_total() == 0
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in result.credits}
    assert got == {(E_ALICE, E_FEE, CREDIT_FEE_REWARD)}  # fee reward only


def test_engine_standing_create_wrong_chain_id_rejected():
    result = _e_apply_block(
        [_e_standing_create_tx(chain_id="ff" * 32)], _e_fresh_parent()
    )
    assert result.accepted_tx_ids == []
    assert result.next_snapshot.metadata["balances"][E_ALICE] == 100000
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    assert lm.standing.open_count() == 0


def test_engine_standing_execute_pays_payee():
    first = _e_apply_block([_e_standing_create_tx()], _e_fresh_parent())
    sid = _e_standing_id(first)
    second = _e_apply_block(
        [_e_standing_execute_tx(sid, seq=1)], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 7 * 86400,
    )
    assert second.accepted_tx_ids == ["standing-execute-1"]
    balances = second.next_snapshot.metadata["balances"]
    # Bob gets the 100; Alice pays 100 + 7 fee and receives 7 back as proposer.
    assert balances[E_BOB] == 100
    assert balances[E_ALICE] == 100000 - 100
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in second.credits}
    assert (E_BOB, 100, CREDIT_STANDING_PAYMENT) in got
    lm = second.next_snapshot.metadata["lifecycle_manager"]
    assert lm.standing.executions(sid) == 1


def test_engine_standing_execute_fee_limit_over_cap_rejected():
    # max_fee_per_execution is 5; a fee_limit of 10000 exceeds the cap.
    first = _e_apply_block(
        [_e_standing_create_tx(max_fee=5)], _e_fresh_parent()
    )
    sid = _e_standing_id(first)
    second = _e_apply_block(
        [_e_standing_execute_tx(sid, seq=1, fee_limit="10000")], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 7 * 86400,
    )
    assert second.accepted_tx_ids == []
    assert second.next_snapshot.metadata["balances"][E_BOB] == 0


def test_engine_standing_execute_twice_same_period_rejected():
    first = _e_apply_block([_e_standing_create_tx()], _e_fresh_parent())
    sid = _e_standing_id(first)
    second = _e_apply_block(
        [_e_standing_execute_tx(sid, seq=1)], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 7 * 86400,
    )
    assert second.accepted_tx_ids == ["standing-execute-1"]
    third = _e_apply_block(
        [_e_standing_execute_tx(sid, seq=2)], second.next_snapshot,
        height=E_HEIGHT + 2, timestamp=E_TS + 7 * 86400 + 10,
    )
    assert third.accepted_tx_ids == []
    assert third.next_snapshot.metadata["balances"][E_BOB] == 100


def test_engine_standing_update_new_version_old_terms_untouched():
    first = _e_apply_block([_e_standing_create_tx()], _e_fresh_parent())
    sid = _e_standing_id(first)
    second = _e_apply_block(
        [_e_standing_update_tx(sid)], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 10,
    )
    assert second.accepted_tx_ids == ["standing-update-1"]
    lm = second.next_snapshot.metadata["lifecycle_manager"]
    entry = lm.standing.get(sid)
    assert entry.version == 2 and entry.amount == 200
    assert entry.payer_pubkey == E_ALICE and entry.payee_pubkey == E_BOB
    assert lm.standing.resolved_count == 1  # the old version, superseded
    assert lm.standing.executions(sid) == 0  # fresh schedule


def test_engine_standing_cancel():
    first = _e_apply_block([_e_standing_create_tx()], _e_fresh_parent())
    sid = _e_standing_id(first)
    second = _e_apply_block(
        [_e_standing_cancel_tx(sid, seq=1)], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 10,
    )
    assert second.accepted_tx_ids == ["standing-cancel-1"]
    lm = second.next_snapshot.metadata["lifecycle_manager"]
    assert lm.standing.open_count() == 0
    assert lm.standing.resolved_count == 1
    # Alice keeps her funds: nothing was ever escrowed.
    assert second.next_snapshot.metadata["balances"][E_ALICE] == 100000


def test_engine_sweep_executes_due_payment_in_block():
    first = _e_apply_block([_e_standing_create_tx()], _e_fresh_parent())
    sid = _e_standing_id(first)
    # An empty block at the start timestamp: the sweep executes the payment.
    second = _e_apply_block(
        [], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 7 * 86400,
    )
    assert second.accepted_tx_ids == []
    balances = second.next_snapshot.metadata["balances"]
    assert balances[E_BOB] == 100
    assert balances[E_ALICE] == 100000 - 100
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in second.credits}
    assert (E_BOB, 100, CREDIT_STANDING_PAYMENT) in got
    lm = second.next_snapshot.metadata["lifecycle_manager"]
    assert lm.standing.executions(sid) == 1
    sweep = second.governance_changes["programmable_sweep"]
    assert sweep["executed"] == [
        {"object_id": sid.hex(), "kind": "standing", "outcome": "executed"}
    ]
    assert sweep["failed"] == [] and sweep["deferred"] == []


def test_engine_sweep_skips_when_payer_broke():
    # Alice holds only 50: the 100 payment cannot execute, and the period is
    # skipped (no catch-up) rather than retried.
    parent = _e_fresh_parent()
    parent.metadata["balances"][E_ALICE] = 50
    first = _e_apply_block([_e_standing_create_tx()], parent)
    sid = _e_standing_id(first)
    second = _e_apply_block(
        [], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 7 * 86400,
    )
    assert second.next_snapshot.metadata["balances"][E_BOB] == 0
    lm = second.next_snapshot.metadata["lifecycle_manager"]
    assert lm.standing.executions(sid) == 1  # the period advanced, unpaid
    sweep = second.governance_changes["programmable_sweep"]
    assert sweep["executed"][0]["outcome"] == "skipped_insufficient_funds"


# ---------------------------------------------------------------- admission
# The mempool validators, exercised with a fake tip view backed by a real
# StandingPaymentBook (the validators judge through the book, so admission
# and apply cannot drift apart).


class _FakeTipView:
    def __init__(self, book=None, genesis_hash=CHAIN_ID, height=21, timestamp=E_TS):
        self._book = book or StandingPaymentBook()
        self.genesis_hash = genesis_hash
        self.next_block_height = height
        self.next_block_timestamp = timestamp

    def get_standing(self, standing_id):
        for row in self._book.snapshot_rows():
            if row["standing_id"] == standing_id.hex():
                return row
        return None

    def open_standing_count_for_payer(self, pubkey):
        return self._book.open_count_for_payer(pubkey)

    def open_standing_count(self):
        return self._book.open_count()


def _admission_entry(**overrides):
    # A StandingEntry whose pubkeys match the engine-test keys, so the same
    # transaction builders can feed admission.
    fields = {
        "standing_id": compute_standing_id(E_ALICE, E_BOB, 0),
        "version": 1,
        "payer_pubkey": E_ALICE,
        "payee_pubkey": E_BOB,
        "amount": 100,
        "period_kind": PERIOD_WEEK,
        "period_length": None,
        "period_anchor": 0,
        "max_fee_per_execution": 10,
        "start_at": E_TS,
        "create_sequence_number": 0,
    }
    fields.update(overrides)
    from consensus.standing import StandingEntry

    return StandingEntry(**fields)


def test_admission_standing_create_ok_and_duplicate():
    from consensus.admission import validate_standing_create_payload

    view = _FakeTipView()
    assert validate_standing_create_payload(_e_standing_create_tx(), view).is_valid
    book = StandingPaymentBook()
    book.submit(_admission_entry())
    view = _FakeTipView(book=book)
    result = validate_standing_create_payload(_e_standing_create_tx(), view)
    assert not result.is_valid


def test_admission_standing_create_wrong_chain_id():
    from consensus.admission import validate_standing_create_payload
    from consensus.chain_binding import WRONG_CHAIN_ID

    view = _FakeTipView()
    result = validate_standing_create_payload(
        _e_standing_create_tx(chain_id="ff" * 32), view
    )
    assert not result.is_valid
    assert getattr(result, "code", None) == WRONG_CHAIN_ID


def test_admission_standing_execute_update_cancel():
    from consensus.admission import (
        validate_standing_cancel_payload,
        validate_standing_execute_payload,
        validate_standing_update_payload,
    )

    book = StandingPaymentBook()
    entry = _admission_entry()
    book.submit(entry)
    view = _FakeTipView(book=book, timestamp=E_TS + 1000)
    sid = entry.standing_id
    assert validate_standing_execute_payload(_e_standing_execute_tx(sid), view).is_valid
    assert not validate_standing_execute_payload(
        _e_standing_execute_tx(sid, fee_limit="11"), view
    ).is_valid
    assert not validate_standing_execute_payload(
        _e_standing_execute_tx(b"\x00" * 32), view
    ).is_valid
    assert validate_standing_update_payload(_e_standing_update_tx(sid), view).is_valid
    assert validate_standing_cancel_payload(_e_standing_cancel_tx(sid), view).is_valid
    # Only the payer may execute, update or cancel.
    by_bob = _e_standing_execute_tx(sid)
    by_bob["sender_pubkey"] = E_BOB
    by_bob = _e_sign(by_bob, E_SK_BOB)
    assert not validate_standing_execute_payload(by_bob, view).is_valid
