"""Tests for Stage 5 payout rules (consensus/payouts.py + wiring).

Book, parse/shape, admission and apply tests live here; engine tests (the
payout create/execute/remove branch and the clause evaluation) are in the
TestEnginePayout class below and mirror the grant/standing/route engine
harness.
"""
import pytest

from consensus.credits import CREDIT_PAYOUT_LEG, CREDIT_TRANSFER
from consensus.payouts import (
    MAX_CLAUSE_BYTES,
    MAX_OPEN_PAYOUTS_PER_PAYER,
    MAX_RECIPIENTS,
    TX_TYPE_PAYOUT_CREATE,
    TX_TYPE_PAYOUT_EXECUTE,
    TX_TYPE_PAYOUT_REMOVE,
    PayoutBook,
    PayoutEntry,
    PayoutShapeError,
    apply_payout,
    clause_outputs_for,
    compute_payout_id,
    first_period,
    parse_payout_create,
    parse_payout_execute,
    parse_payout_remove,
    validate_payout_shape,
)

ALICE = "aa" * 48
BOB = "bb" * 48
CAROL = "cc" * 48
DAVE = "dd" * 48
CHAIN_ID = "ab" * 32

T0 = 1_700_000_000  # a fixed "now" for shape/admission tests
# Valid payout-clause shape: ternary over the i1 (payer balance) guard;
# see docs/programmable_payments.md Stage 5. Bare decimals and
# comma-separated assignments do not parse, and a constant-only clause
# cannot be stepped (it reads no input stream).
CLAUSE = (
    "always ((i1[t]:bv[24] > { #x000000 }:bv[24])"
    " ? (o1[t]:bv[24] = { 300 }:bv[24] && o2[t]:bv[24] = { 700 }:bv[24])"
    " : (o1[t]:bv[24] = { 0 }:bv[24] && o2[t]:bv[24] = { 0 }:bv[24]))."
)


def make_payout(**overrides):
    fields = {
        "payer_pubkey": ALICE,
        "recipients": [BOB, CAROL],
        "clause": CLAUSE,
        "max_per_execution": 1000,
        "max_per_period": 1000,
        "period_kind": 2,  # PERIOD_WEEK
        "period_length": None,
        "period_anchor": 0,
        "start_at": T0,
        "expires_at": T0 + 30 * 86400,
        "locked_until": None,
        "sequence_number": 0,
    }
    fields.update(overrides)
    # The id is derived from payer + ordered recipients + sequence, so
    # an overridden sequence number yields a distinct id.
    fields["payout_id"] = compute_payout_id(
        fields["payer_pubkey"], fields["recipients"],
        fields["sequence_number"],
    )
    return PayoutEntry(**fields)


def make_tx(**overrides):
    tx = {
        "tx_type": TX_TYPE_PAYOUT_CREATE,
        "sender_pubkey": ALICE,
        "recipients": [BOB, CAROL],
        "clause": CLAUSE,
        "max_per_execution": 1000,
        "max_per_period": 1000,
        "period_kind": 2,
        "period_length": None,
        "period_anchor": 0,
        "start_at": T0,
        "expires_at": T0 + 30 * 86400,
        "locked_until": None,
        "sequence_number": 0,
        "chain_id": CHAIN_ID,
    }
    tx.update(overrides)
    return tx


# --------------------------------------------------------------------------
# Parse + shape
# --------------------------------------------------------------------------
class TestParseAndShape:
    def test_parse_payout_create_roundtrip(self):
        entry = parse_payout_create(make_tx())
        assert entry.payer_pubkey == ALICE
        assert entry.recipients == (BOB, CAROL)
        assert entry.clause.startswith("always")
        assert entry.max_per_execution == 1000
        assert entry.max_per_period == 1000
        assert entry.payout_id == compute_payout_id(ALICE, [BOB, CAROL], 0)

    def test_parse_payout_create_rejects_bad_pubkey(self):
        with pytest.raises(PayoutShapeError):
            parse_payout_create(make_tx(sender_pubkey="zz"))
        with pytest.raises(PayoutShapeError):
            parse_payout_create(make_tx(recipients=["zz", CAROL]))

    def test_parse_payout_create_rejects_bad_recipients(self):
        with pytest.raises(PayoutShapeError):
            parse_payout_create(make_tx(recipients=[]))
        with pytest.raises(PayoutShapeError):
            parse_payout_create(make_tx(recipients=[BOB] * (MAX_RECIPIENTS + 1)))

    def test_shape_rejects_bad_caps_and_recipients(self):
        # Distinctness, payer-in-recipients and the caps are semantic
        # shape checks (validate_payout_shape), not structural parse.
        assert validate_payout_shape(make_payout(recipients=[BOB, BOB]), 0, T0) is not None
        assert validate_payout_shape(make_payout(recipients=[ALICE, CAROL]), 0, T0) is not None
        assert validate_payout_shape(make_payout(max_per_execution=0), 0, T0) is not None
        assert validate_payout_shape(make_payout(max_per_period=0), 0, T0) is not None
        # One execution cannot exceed the period cap.
        assert (
            validate_payout_shape(
                make_payout(max_per_execution=2000, max_per_period=1000), 0, T0
            )
            is not None
        )

    def test_parse_payout_create_rejects_bad_clause(self):
        with pytest.raises(PayoutShapeError):
            parse_payout_create(make_tx(clause=""))
        with pytest.raises(PayoutShapeError):
            parse_payout_create(make_tx(clause="x" * (MAX_CLAUSE_BYTES + 1)))
        with pytest.raises(PayoutShapeError):
            parse_payout_create(make_tx(clause=123))

    def test_parse_payout_execute_and_remove(self):
        payout_id = compute_payout_id(ALICE, [BOB, CAROL], 0)
        req = parse_payout_execute(
            {"tx_type": TX_TYPE_PAYOUT_EXECUTE, "sender_pubkey": ALICE,
             "payout_id": payout_id.hex(), "chain_id": CHAIN_ID}
        )
        assert req.payout_id == payout_id
        req = parse_payout_remove(
            {"tx_type": TX_TYPE_PAYOUT_REMOVE, "sender_pubkey": ALICE,
             "payout_id": payout_id.hex(), "chain_id": CHAIN_ID}
        )
        assert req.payout_id == payout_id
        with pytest.raises(PayoutShapeError):
            parse_payout_execute(
                {"tx_type": TX_TYPE_PAYOUT_EXECUTE, "sender_pubkey": ALICE,
                 "payout_id": "zz", "chain_id": CHAIN_ID}
            )

    def test_shape_rejects_expired_and_bad_lock(self):
        assert validate_payout_shape(make_payout(expires_at=T0 - 1), 0, T0) is not None
        # start_at must precede expires_at.
        assert (
            validate_payout_shape(
                make_payout(start_at=T0 + 100, expires_at=T0 + 50), 0, T0
            )
            is not None
        )
        # locked_until must be future and within the window.
        assert (
            validate_payout_shape(make_payout(locked_until=T0 - 1), 0, T0)
            is not None
        )
        assert (
            validate_payout_shape(
                make_payout(locked_until=T0 + 31 * 86400), 0, T0
            )
            is not None
        )
        assert validate_payout_shape(make_payout(locked_until=T0 + 1000), 0, T0) is None

    def test_shape_rejects_fixed_period_without_length(self):
        assert (
            validate_payout_shape(
                make_payout(period_kind=0, period_length=None), 0, T0
            )
            is not None
        )
        assert (
            validate_payout_shape(
                make_payout(period_kind=0, period_length=86400), 0, T0
            )
            is None
        )

    def test_shape_rejects_start_too_far_ahead(self):
        # start_at more than 90 days ahead is not a schedule, it is a typo.
        assert (
            validate_payout_shape(make_payout(start_at=T0 + 91 * 86400), 0, T0)
            is not None
        )

    def test_payout_id_is_deterministic(self):
        a = compute_payout_id(ALICE, [BOB, CAROL], 0)
        b = compute_payout_id(ALICE, [BOB, CAROL], 0)
        assert a == b
        assert compute_payout_id(ALICE, [BOB, CAROL], 1) != a
        # Recipient order matters: the clause maps o1 to the first.
        assert compute_payout_id(ALICE, [CAROL, BOB], 0) != a


# --------------------------------------------------------------------------
# Book
# --------------------------------------------------------------------------
class TestPayoutBook:
    def test_submit_get_remove(self):
        book = PayoutBook()
        assert book.is_empty()
        entry = make_payout()
        book.submit(entry)
        assert not book.is_empty()
        assert book.open_count() == 1
        assert book.get(entry.payout_id).payer_pubkey == ALICE
        book.remove(entry.payout_id)
        assert book.is_empty()
        assert book.get(entry.payout_id) is None
        assert book.resolved_state()[0] == 1  # removed folds into resolved

    def test_due_period(self):
        # Regression: due_period used to call current_period with 4 args
        # (it takes 2) — a TypeError no test exercised.
        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        assert book.due_period(entry.payout_id, T0) == first_period(entry)
        assert book.due_period(b"00" * 32, T0) is None
        future = make_payout(start_at=T0 + 10 * 86400, sequence_number=1)
        book.submit(future)
        assert book.due_period(future.payout_id, T0) is None

    def test_submit_duplicate_rejected(self):
        book = PayoutBook()
        book.submit(make_payout())
        with pytest.raises(ValueError):
            book.submit(make_payout())

    def test_can_admit_create_payer_full(self):
        book = PayoutBook()
        for seq in range(MAX_OPEN_PAYOUTS_PER_PAYER):
            book.submit(make_payout(sequence_number=seq))
        ok, reason = book.can_admit_create(make_payout(sequence_number=99), 0, T0)
        assert not ok and "payer" in reason.lower()

    def test_can_admit_execute_not_due(self):
        book = PayoutBook()
        entry = make_payout(start_at=T0 + 100000)
        book.submit(entry)
        ok, reason = book.can_admit_execute(entry.payout_id, ALICE, 0, T0)
        assert not ok and "not started" in reason.lower()

    def test_can_admit_execute_wrong_sender(self):
        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        ok, _ = book.can_admit_execute(entry.payout_id, BOB, 0, T0)
        assert not ok

    def test_can_admit_remove_locked(self):
        book = PayoutBook()
        entry = make_payout(locked_until=T0 + 10000)
        book.submit(entry)
        ok, reason = book.can_admit_remove(entry.payout_id, ALICE, 0, T0)
        assert not ok and "locked" in reason.lower()
        # After the lock expires the payer may remove it.
        ok, _ = book.can_admit_remove(entry.payout_id, ALICE, 0, T0 + 20000)
        assert ok

    def test_can_admit_remove_by_non_payer(self):
        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        ok, _ = book.can_admit_remove(entry.payout_id, BOB, 0, T0)
        assert not ok

    def test_escrowed_total_always_zero(self):
        # A payout rule holds no funds: the payer pays at execution time.
        book = PayoutBook()
        book.submit(make_payout())
        assert book.escrowed_total() == 0

    def test_snapshot_restore_roundtrip(self):
        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        book.mark_executed(entry.payout_id, 100, 1000)
        rows, count, acc = book.snapshot_rows(), *book.resolved_state()
        restored = PayoutBook.restore(rows, count, acc)
        # The restore roundtrips the runtime (period, amount paid and
        # execution count), not just the immutable rule terms: the
        # snapshot rows are identical, and the paid total is intact.
        assert restored.snapshot_rows() == rows
        assert restored.paid_in_period(entry.payout_id, 100) == 1000
        assert restored.root() == book.root()

    def test_restore_from_db_rows_json_recipients(self):
        # Regression (found by the checktx_estimate payout_execute case):
        # rows read back from payouts_v1 carry recipients as a JSON
        # string (the column is TEXT); restore() must parse it, not
        # iterate its characters ("[" is not a pubkey).
        import json

        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        book.mark_executed(entry.payout_id, 100, 1000)
        rows, count, acc = book.snapshot_rows(), *book.resolved_state()
        db_rows = [dict(r) for r in rows]
        db_rows[0]["recipients"] = json.dumps(db_rows[0]["recipients"])
        restored = PayoutBook.restore(db_rows, count, acc)
        assert restored.snapshot_rows() == rows
        assert restored.paid_in_period(entry.payout_id, 100) == 1000
        assert restored.root() == book.root()

    def test_restore_rejects_bad_id(self):
        book = PayoutBook()
        book.submit(make_payout())
        rows = book.snapshot_rows()
        rows[0]["payout_id"] = "00" * 32
        with pytest.raises(ValueError):
            PayoutBook.restore(rows, 0, bytes(32))


# --------------------------------------------------------------------------
# apply_payout
# --------------------------------------------------------------------------
class _Recorder:
    def __init__(self):
        self.records = []

    def record(self, recipient_pubkey, amount, credit_class, tx_id):
        self.records.append((recipient_pubkey, amount, credit_class, tx_id))


def _run_apply(entry, ts, amounts, balances, fee=0, fee_beneficiary="",
               credit_records=None):
    book = PayoutBook()
    book.submit(entry)
    read = lambda addr: balances.get(addr, 0)

    def write(addr, value):
        balances[addr] = value

    outcome, period = apply_payout(
        book, entry.payout_id, ts, amounts,
        read=read, write=write, fee=fee, fee_beneficiary=fee_beneficiary,
        credit_records=credit_records,
    )
    return outcome, period, book


class TestApplyPayout:
    def test_apply_executes_all_legs_atomically(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        rec = _Recorder()
        outcome, period, book = _run_apply(
            make_payout(), T0, [300, 700], balances, credit_records=rec
        )
        assert outcome == "executed"
        assert balances[ALICE] == 9000
        assert balances[BOB] == 300
        assert balances[CAROL] == 700
        assert any(
            r == BOB and a == 300 and c == CREDIT_PAYOUT_LEG
            for (r, a, c, t) in rec.records
        )
        assert any(
            r == CAROL and a == 700 and c == CREDIT_PAYOUT_LEG
            for (r, a, c, t) in rec.records
        )

    def test_apply_skips_zero_legs(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        rec = _Recorder()
        outcome, _, _ = _run_apply(
            make_payout(), T0, [0, 500], balances, credit_records=rec
        )
        assert outcome == "executed"
        assert balances[BOB] == 0
        assert balances[CAROL] == 500
        # A zero leg is not a credit record.
        assert not any(r == BOB for (r, a, c, t) in rec.records)
        assert any(r == CAROL and a == 500 for (r, a, c, t) in rec.records)

    def test_apply_all_zero_is_skipped_zero(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(make_payout(), T0, [0, 0], balances)
        assert outcome == "skipped_zero"
        assert balances == {ALICE: 10000, BOB: 0, CAROL: 0}

    def test_apply_rejects_negative_output(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(make_payout(), T0, [100, -5], balances)
        assert outcome == "skipped_bad_outputs"
        assert balances == {ALICE: 10000, BOB: 0, CAROL: 0}

    def test_apply_rejects_non_integer_output(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(make_payout(), T0, [100, "x"], balances)
        assert outcome == "skipped_bad_outputs"
        assert balances == {ALICE: 10000, BOB: 0, CAROL: 0}

    def test_apply_rejects_wrong_output_count(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(make_payout(), T0, [100], balances)
        assert outcome == "skipped_bad_outputs"
        assert balances == {ALICE: 10000, BOB: 0, CAROL: 0}

    def test_apply_exec_cap(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(
            make_payout(max_per_execution=500), T0, [300, 700], balances
        )
        assert outcome == "skipped_exec_cap"
        assert balances == {ALICE: 10000, BOB: 0, CAROL: 0}

    def test_apply_period_cap(self):
        # Two executions in the same period: the second exceeds the cap.
        entry = make_payout(max_per_execution=1000, max_per_period=1200)
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        book = PayoutBook()
        book.submit(entry)
        read = lambda addr: balances.get(addr, 0)

        def write(addr, value):
            balances[addr] = value

        outcome, period = apply_payout(
            book, entry.payout_id, T0, [600, 400],
            read=read, write=write, fee=0, fee_beneficiary="",
        )
        assert outcome == "executed"
        book.mark_executed(entry.payout_id, period, 1000)
        # Same period (same ISO week): 1000 already paid, 1200 cap leaves 200.
        outcome, _ = apply_payout(
            book, entry.payout_id, T0 + 100, [300, 0],
            read=read, write=write, fee=0, fee_beneficiary="",
        )
        assert outcome == "skipped_period_cap"
        assert balances[ALICE] == 9000  # only the first execution landed

    def test_apply_insufficient_funds(self):
        balances = {ALICE: 500, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(make_payout(), T0, [300, 700], balances)
        assert outcome == "skipped_insufficient_funds"
        assert balances == {ALICE: 500, BOB: 0, CAROL: 0}

    def test_apply_fee(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(
            make_payout(), T0, [300, 700], balances,
            fee=7, fee_beneficiary=DAVE,
        )
        assert outcome == "executed"
        assert balances[ALICE] == 10000 - 1000 - 7
        assert balances[DAVE] == 7

    def test_apply_no_beneficiary_blocks_fee(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(
            make_payout(), T0, [300, 700], balances, fee=7, fee_beneficiary=""
        )
        assert outcome == "skipped_no_beneficiary"
        assert balances == {ALICE: 10000, BOB: 0, CAROL: 0}

    def test_apply_not_due(self):
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        outcome, _, _ = _run_apply(
            make_payout(start_at=T0 + 100000), T0, [300, 700], balances
        )
        assert outcome == "skipped_not_due"

    def test_apply_unknown(self):
        book = PayoutBook()
        balances = {ALICE: 10000}
        outcome, _ = apply_payout(
            book, bytes(32), T0, [300, 700],
            read=lambda a: balances.get(a, 0),
            write=lambda a, v: balances.__setitem__(a, v),
        )
        assert outcome == "skipped_unknown"

    def test_apply_one_execution_per_period(self):
        entry = make_payout()
        balances = {ALICE: 10000, BOB: 0, CAROL: 0}
        book = PayoutBook()
        book.submit(entry)
        read = lambda addr: balances.get(addr, 0)

        def write(addr, value):
            balances[addr] = value

        outcome, period = apply_payout(
            book, entry.payout_id, T0, [300, 700],
            read=read, write=write, fee=0, fee_beneficiary="",
        )
        assert outcome == "executed"
        book.mark_executed(entry.payout_id, period, 1000)
        # Same period again: already executed, no second payment.
        outcome, _ = apply_payout(
            book, entry.payout_id, T0 + 100, [300, 700],
            read=read, write=write, fee=0, fee_beneficiary="",
        )
        assert outcome == "already_executed"
        assert balances[ALICE] == 9000

    def test_apply_payer_equals_recipient_nets_to_zero(self):
        # The payer is also a recipient: debit first, then credit, so the
        # payer's leg nets to the gross debit minus its own leg.
        entry = make_payout(recipients=[ALICE, CAROL])
        balances = {ALICE: 10000, CAROL: 0}
        outcome, _, _ = _run_apply(entry, T0, [400, 600], balances)
        assert outcome == "executed"
        # Alice pays 1000, gets 400 back as a recipient: 9400.
        assert balances[ALICE] == 9400
        assert balances[CAROL] == 600


# --------------------------------------------------------------------------
# Admission
# --------------------------------------------------------------------------
class _FakeTipView:
    """Minimal TipAdmissionView stand-in (mirrors test_standing.py)."""

    def __init__(self, book=None, timestamp=T0, height=20):
        self._book = book or PayoutBook()
        self.next_block_timestamp = timestamp
        self.next_block_height = height
        self.genesis_hash = CHAIN_ID

    def get_payout(self, payout_id):
        for row in self._book.snapshot_rows():
            if row["payout_id"] == payout_id.hex():
                return row
        return None

    def open_payout_count_for_payer(self, payer_pubkey):
        return sum(
            1 for row in self._book.snapshot_rows()
            if row["payer_pubkey"] == payer_pubkey
        )

    def open_payout_count(self):
        return self._book.open_count()


class TestAdmission:
    def test_create_accepted(self):
        from consensus.admission import validate_payout_create_payload

        view = _FakeTipView()
        result = validate_payout_create_payload(make_tx(), view)
        assert result.is_valid

    def test_create_wrong_chain_rejected(self):
        from consensus.admission import validate_payout_create_payload

        view = _FakeTipView()
        result = validate_payout_create_payload(
            make_tx(chain_id="ff" * 32), view
        )
        assert not result.is_valid

    def test_create_duplicate_rejected(self):
        from consensus.admission import validate_payout_create_payload

        book = PayoutBook()
        book.submit(make_payout())
        view = _FakeTipView(book=book)
        result = validate_payout_create_payload(make_tx(), view)
        assert not result.is_valid

    def test_execute_accepted_and_unknown_rejected(self):
        from consensus.admission import validate_payout_execute_payload

        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        view = _FakeTipView(book=book)
        tx = {
            "tx_type": TX_TYPE_PAYOUT_EXECUTE,
            "sender_pubkey": ALICE,
            "payout_id": entry.payout_id.hex(),
            "chain_id": CHAIN_ID,
        }
        assert validate_payout_execute_payload(tx, view).is_valid
        empty = _FakeTipView()
        assert not validate_payout_execute_payload(tx, empty).is_valid

    def test_execute_wrong_sender_rejected(self):
        from consensus.admission import validate_payout_execute_payload

        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        view = _FakeTipView(book=book)
        tx = {
            "tx_type": TX_TYPE_PAYOUT_EXECUTE,
            "sender_pubkey": BOB,
            "payout_id": entry.payout_id.hex(),
            "chain_id": CHAIN_ID,
        }
        assert not validate_payout_execute_payload(tx, view).is_valid

    def test_remove_accepted_and_locked_rejected(self):
        from consensus.admission import validate_payout_remove_payload

        book = PayoutBook()
        entry = make_payout()
        book.submit(entry)
        view = _FakeTipView(book=book)
        tx = {
            "tx_type": TX_TYPE_PAYOUT_REMOVE,
            "sender_pubkey": ALICE,
            "payout_id": entry.payout_id.hex(),
            "chain_id": CHAIN_ID,
        }
        assert validate_payout_remove_payload(tx, view).is_valid
        locked = PayoutBook()
        locked.submit(make_payout(locked_until=T0 + 10000))
        locked_view = _FakeTipView(book=locked)
        assert not validate_payout_remove_payload(tx, locked_view).is_valid


# --------------------------------------------------------------------------
# Pool isolation (native test: the payout pool is its own worker)
# --------------------------------------------------------------------------
def test_payout_pool_is_isolated():
    """The payout pool is its own singleton, distinct from apply/admission."""
    import tau_policy

    try:
        a = tau_policy.get_policy_evaluator("apply")
        assert a is tau_policy.get_policy_evaluator("apply")
        b = tau_policy.get_policy_evaluator("admission")
        assert b is not a
        p = tau_policy.get_policy_evaluator("payout")
        assert p is tau_policy.get_policy_evaluator("payout")
        assert p is not a
        assert p is not b
        with pytest.raises(ValueError):
            tau_policy.get_policy_evaluator("other")
    finally:
        tau_policy.close_policy_evaluators()
    assert tau_policy.get_policy_evaluator("apply") is not a
    tau_policy.close_policy_evaluators()


# --------------------------------------------------------------------------
# Demo
# --------------------------------------------------------------------------
def test_demo_alice_pays_bob_and_carol_by_clause():
    """Alice splits 1,000 to Bob and Carol by clause: o1=300, o2=700."""
    book = PayoutBook()
    book.submit(make_payout())
    balances = {ALICE: 10000, BOB: 0, CAROL: 0}
    outcome, period = apply_payout(
        book, make_payout().payout_id, T0, [300, 700],
        read=lambda a: balances.get(a, 0),
        write=lambda a, v: balances.__setitem__(a, v),
    )
    assert outcome == "executed"
    assert balances == {ALICE: 9000, BOB: 300, CAROL: 700}


# --------------------------------------------------------------------------
# Engine tests (payout create/execute/remove branch).
# Harness mirrors tests/test_standing.py exactly (BLS keys, TauStateSnapshot,
# ActiveConsensusView, mocked Tau fee = 7).
# --------------------------------------------------------------------------
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
E_SK_CAROL = 77777
E_CAROL = G2Basic.SkToPk(E_SK_CAROL).hex()


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


def _e_fresh_parent():
    lm = ConsensusLifecycleManager(active_validators=[E_ALICE])
    lm.genesis_hash = CHAIN_ID
    return _e_snapshot(lm, {E_ALICE: 100000, E_BOB: 10000, E_CAROL: 10000})


def _e_payout_id():
    return compute_payout_id(E_ALICE, [E_BOB, E_CAROL], 0)


def _e_payout_create_tx(seq=0, sender=E_ALICE, sk=E_SK_ALICE,
                        start_at=E_TS, locked_until=None):
    tx = {
        "tx_id": f"payout-create-{seq}",
        "tx_type": TX_TYPE_PAYOUT_CREATE,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "recipients": [E_BOB, E_CAROL],
        "clause": CLAUSE,
        "max_per_execution": 1000,
        "max_per_period": 1000,
        "period_kind": 2,
        "period_length": None,
        "period_anchor": 0,
        "start_at": start_at,
        "expires_at": E_TS + 30 * 86400,
        "locked_until": locked_until,
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, sk)


def _e_payout_execute_tx(seq=1, sender=E_ALICE, sk=E_SK_ALICE):
    tx = {
        "tx_id": f"payout-execute-{seq}",
        "tx_type": TX_TYPE_PAYOUT_EXECUTE,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "payout_id": _e_payout_id().hex(),
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, sk)


def _e_payout_remove_tx(seq=1, sender=E_ALICE, sk=E_SK_ALICE):
    tx = {
        "tx_id": f"payout-remove-{seq}",
        "tx_type": TX_TYPE_PAYOUT_REMOVE,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "payout_id": _e_payout_id().hex(),
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, sk)


class TestEnginePayout:
    def test_payout_create_lands(self):
        result = _e_apply_block([_e_payout_create_tx()], _e_fresh_parent())
        assert result.accepted_tx_ids == ["payout-create-0"]
        lm = result.next_snapshot.metadata["lifecycle_manager"]
        entry = lm.payouts.get(_e_payout_id())
        assert entry is not None
        assert entry.recipients == (E_BOB, E_CAROL)
        assert entry.max_per_execution == 1000

    def test_payout_execute_pays_by_clause(self):
        first = _e_apply_block([_e_payout_create_tx()], _e_fresh_parent())
        # Alice is proposer and payer: create fee 7 is charged and returned.
        assert first.next_snapshot.metadata["balances"][E_ALICE] == 100000
        with patch(
            "consensus.engine.clause_outputs_for",
            return_value={"o1": 300, "o2": 700},
        ):
            second = _e_apply_block(
                [_e_payout_execute_tx(seq=1)], first.next_snapshot,
                height=E_HEIGHT + 1, timestamp=E_TS + 10,
            )
        assert second.accepted_tx_ids == ["payout-execute-1"]
        balances = second.next_snapshot.metadata["balances"]
        # Alice pays 1000 and the 7 fee, and gets the 7 back as proposer.
        assert balances[E_ALICE] == 99000
        assert balances[E_BOB] == 10300
        assert balances[E_CAROL] == 10700
        got = {(r.recipient_pubkey, r.amount, r.credit_class)
               for r in second.credits}
        assert (E_BOB, 300, CREDIT_PAYOUT_LEG) in got
        assert (E_CAROL, 700, CREDIT_PAYOUT_LEG) in got

    def test_payout_execute_clause_unavailable_pays_nothing(self):
        first = _e_apply_block([_e_payout_create_tx()], _e_fresh_parent())
        with patch(
            "consensus.engine.clause_outputs_for", return_value=None
        ):
            second = _e_apply_block(
                [_e_payout_execute_tx(seq=1)], first.next_snapshot,
                height=E_HEIGHT + 1, timestamp=E_TS + 10,
            )
        # The tx is skipped (fail-closed), not applied.
        assert second.accepted_tx_ids == []
        balances = second.next_snapshot.metadata["balances"]
        assert balances[E_ALICE] == 100000
        assert balances[E_BOB] == 10000
        assert balances[E_CAROL] == 10000

    def test_payout_execute_bad_outputs_pays_nothing(self):
        first = _e_apply_block([_e_payout_create_tx()], _e_fresh_parent())
        with patch(
            "consensus.engine.clause_outputs_for",
            return_value={"o1": 300, "o2": -5},
        ):
            second = _e_apply_block(
                [_e_payout_execute_tx(seq=1)], first.next_snapshot,
                height=E_HEIGHT + 1, timestamp=E_TS + 10,
            )
        assert second.accepted_tx_ids == []
        balances = second.next_snapshot.metadata["balances"]
        assert balances[E_ALICE] == 100000
        assert balances[E_BOB] == 10000
        assert balances[E_CAROL] == 10000

    def test_payout_execute_twice_in_one_period_pays_once(self):
        first = _e_apply_block([_e_payout_create_tx()], _e_fresh_parent())
        with patch(
            "consensus.engine.clause_outputs_for",
            return_value={"o1": 300, "o2": 700},
        ):
            second = _e_apply_block(
                [_e_payout_execute_tx(seq=1)], first.next_snapshot,
                height=E_HEIGHT + 1, timestamp=E_TS + 10,
            )
            third = _e_apply_block(
                [_e_payout_execute_tx(seq=2)], second.next_snapshot,
                height=E_HEIGHT + 2, timestamp=E_TS + 20,
            )
        assert second.accepted_tx_ids == ["payout-execute-1"]
        assert third.accepted_tx_ids == []
        balances = third.next_snapshot.metadata["balances"]
        assert balances[E_ALICE] == 99000
        assert balances[E_BOB] == 10300

    def test_payout_remove_stops_execution(self):
        first = _e_apply_block([_e_payout_create_tx()], _e_fresh_parent())
        second = _e_apply_block(
            [_e_payout_remove_tx(seq=1)], first.next_snapshot,
            height=E_HEIGHT + 1, timestamp=E_TS + 10,
        )
        assert second.accepted_tx_ids == ["payout-remove-1"]
        lm = second.next_snapshot.metadata["lifecycle_manager"]
        assert lm.payouts.get(_e_payout_id()) is None
        with patch(
            "consensus.engine.clause_outputs_for",
            return_value={"o1": 300, "o2": 700},
        ):
            third = _e_apply_block(
                [_e_payout_execute_tx(seq=2)], second.next_snapshot,
                height=E_HEIGHT + 2, timestamp=E_TS + 20,
            )
        assert third.accepted_tx_ids == []

    def test_payout_remove_locked_rejected(self):
        first = _e_apply_block(
            [_e_payout_create_tx(locked_until=E_TS + 10000)], _e_fresh_parent()
        )
        second = _e_apply_block(
            [_e_payout_remove_tx(seq=1)], first.next_snapshot,
            height=E_HEIGHT + 1, timestamp=E_TS + 10,
        )
        assert second.accepted_tx_ids == []
        lm = second.next_snapshot.metadata["lifecycle_manager"]
        assert lm.payouts.get(_e_payout_id()) is not None
