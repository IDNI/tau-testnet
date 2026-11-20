"""Stage 2 (Bounty 01): conditional grants -- book, parse, sweep handler.

Pure unit tests: the GrantBook is exercised directly, without the engine.
End-to-end coverage (create/draw/cancel transactions through _apply_block,
the sweep refund inside a block, the credit ledger) lives in
test_programmable_credits.py-style engine tests below in this same file
where they need the block harness.
"""

from types import SimpleNamespace

import pytest

from consensus.credits import CREDIT_FEE_REWARD, CREDIT_GRANT_DRAW, CREDIT_GRANT_REFUND, CreditLedger
from consensus.grants import (
    ALL_HOURS_MASK,
    ALL_WEEKDAYS_MASK,
    MAX_GRANT_DURATION_SECONDS,
    GrantBook,
    GrantEntry,
    GrantShapeError,
    _GrantSweepHandler,
    compute_grant_id,
    parse_grant_cancel,
    parse_grant_create,
    parse_grant_draw,
    validate_grant_shape,
)
from consensus.periods import (
    PERIOD_FIXED,
    PERIOD_MONTH,
    PERIOD_WEEK,
    days_from_civil,
    hour_of_day,
    period_index,
    weekday,
)
from consensus.sweep import SweepContext, SweepDue

ALICE = "a" * 96
BOB = "b" * 96
CAROL = "c" * 96

# 2026-12-01 00:00:00 UTC, a Tuesday. The demo grant starts here.
DEC_1_2026 = days_from_civil(2026, 12, 1) * 86400
DAY = 86400
WEEK = 7 * DAY


def make_entry(**overrides):
    fields = {
        "granter_pubkey": ALICE,
        "grantee_pubkey": BOB,
        "refund_to": ALICE,
        "amount": 5000,
        "sequence_number": 1,
        "period_kind": PERIOD_WEEK,
        "period_length": None,
        "period_anchor": 0,
        "spend_cap": 500,
        "per_payment_cap": 500,
        "weekday_mask": ALL_WEEKDAYS_MASK,
        "hour_mask": ALL_HOURS_MASK,
        "start_at": DEC_1_2026,
        "expires_at": DEC_1_2026 + 28 * DAY,
    }
    fields.update(overrides)
    return GrantEntry(**fields)


def make_tx(**overrides):
    body = {
        "sender_pubkey": ALICE,
        "grantee_pubkey": BOB,
        "refund_to": ALICE,
        "amount": 5000,
        "sequence_number": 1,
        "period_kind": PERIOD_WEEK,
        "period_anchor": 0,
        "spend_cap": 500,
        "per_payment_cap": 500,
        "start_at": DEC_1_2026,
        "expires_at": DEC_1_2026 + 28 * DAY,
    }
    body.update(overrides)
    return body


# ---------------------------------------------------------------- ids


def test_grant_id_is_deterministic_and_sequence_bound():
    first = make_entry()
    assert first.grant_id == make_entry().grant_id
    assert first.grant_id != make_entry(sequence_number=2).grant_id
    assert first.grant_id != make_entry(amount=5001).grant_id
    assert first.grant_id == compute_grant_id(
        ALICE, BOB, ALICE, 5000, 1, PERIOD_WEEK, None, 0, 500, 500,
        ALL_WEEKDAYS_MASK, ALL_HOURS_MASK, DEC_1_2026, DEC_1_2026 + 28 * DAY,
    )


# ---------------------------------------------------------------- parse


def test_parse_grant_create_reads_all_fields():
    entry = parse_grant_create(make_tx())
    assert entry == make_entry()
    assert entry.grant_id == make_entry().grant_id


def test_parse_grant_create_defaults_masks_to_all():
    body = make_tx()
    del body["spend_cap"]  # required field: must raise
    with pytest.raises(GrantShapeError):
        parse_grant_create(body)
    body = make_tx()
    entry = parse_grant_create(body)
    assert entry.weekday_mask == ALL_WEEKDAYS_MASK
    assert entry.hour_mask == ALL_HOURS_MASK


def test_parse_rejects_malformed_fields():
    with pytest.raises(GrantShapeError):
        parse_grant_create(make_tx(grantee_pubkey="not-a-pubkey"))
    # amount=0 is a well-formed u64: parse accepts it, validate rejects it.
    assert parse_grant_create(make_tx(amount=0)).amount == 0
    assert validate_grant_shape(parse_grant_create(make_tx(amount=0)), 0, DEC_1_2026) is not None
    with pytest.raises(GrantShapeError):
        parse_grant_create(make_tx(amount=-5))
    with pytest.raises(GrantShapeError):
        parse_grant_create(make_tx(sequence_number="1"))
    with pytest.raises(GrantShapeError):
        parse_grant_draw({"grant_id": "zz", "amount": 10})
    # A zero draw amount is a well-formed u64: parse accepts it, the book
    # rejects it at admission.
    assert parse_grant_draw({"grant_id": "a" * 64, "amount": 0}).amount == 0
    with pytest.raises(GrantShapeError):
        parse_grant_cancel({"grant_id": "a" * 63})


def test_parse_grant_draw_and_cancel():
    gid = make_entry().grant_id.hex()
    assert parse_grant_draw({"grant_id": gid, "amount": 250}).amount == 250
    assert parse_grant_cancel({"grant_id": gid}).grant_id == make_entry().grant_id


# ---------------------------------------------------------------- shape


def test_validate_grant_shape_accepts_the_demo():
    assert validate_grant_shape(make_entry(), 0, DEC_1_2026) is None


def test_validate_grant_shape_rejects_bad_terms():
    base = DEC_1_2026
    assert validate_grant_shape(make_entry(amount=0), 0, base) is not None
    assert validate_grant_shape(make_entry(spend_cap=5001), 0, base) is not None
    assert validate_grant_shape(make_entry(spend_cap=0), 0, base) is not None
    assert validate_grant_shape(make_entry(per_payment_cap=501), 0, base) is not None
    assert validate_grant_shape(make_entry(per_payment_cap=0), 0, base) is not None
    assert validate_grant_shape(make_entry(weekday_mask=0), 0, base) is not None
    assert validate_grant_shape(make_entry(weekday_mask=128), 0, base) is not None
    assert validate_grant_shape(make_entry(hour_mask=0), 0, base) is not None
    assert validate_grant_shape(make_entry(hour_mask=1 << 24), 0, base) is not None
    assert validate_grant_shape(
        make_entry(start_at=base + 10, expires_at=base + 10), 0, base
    ) is not None
    assert validate_grant_shape(
        make_entry(expires_at=base), 0, base
    ) is not None  # already expired
    assert validate_grant_shape(
        make_entry(expires_at=base + MAX_GRANT_DURATION_SECONDS + 1),
        0, base,
    ) is not None  # longer than 90 days
    assert validate_grant_shape(
        make_entry(period_kind=PERIOD_FIXED, period_length=None), 0, base
    ) is not None
    assert validate_grant_shape(
        make_entry(period_kind=PERIOD_MONTH, period_length=7), 0, base
    ) is not None
    assert validate_grant_shape(make_entry(period_kind=99), 0, base) is not None


# ---------------------------------------------------------------- book


def test_submit_draw_cancel_flow():
    book = GrantBook()
    entry = make_entry()
    ok, _ = book.can_admit_create(entry, 0, DEC_1_2026)
    assert ok
    book.submit(entry)
    assert book.open_count() == 1
    assert book.escrowed_total() == 5000
    assert book.open_count_for_granter(ALICE) == 1

    gid = entry.grant_id
    ok, reason = book.can_admit_draw(gid, BOB, 500, 0, DEC_1_2026)
    assert ok, reason
    assert book.draw(gid, 500, DEC_1_2026) is False  # not exhausted
    assert book.drawn_total(gid) == 500
    assert book.remaining_for(gid) == 4500
    assert book.escrowed_total() == 4500

    _, refunded = book.cancel(gid)
    assert refunded == 4500
    assert book.open_count() == 0
    assert book.escrowed_total() == 0
    assert book.resolved_count == 1


def test_draw_exhausts_the_grant():
    book = GrantBook()
    entry = make_entry(amount=1000, spend_cap=1000, per_payment_cap=1000)
    book.submit(entry)
    gid = entry.grant_id
    assert book.draw(gid, 1000, DEC_1_2026) is True
    assert book.open_count() == 0
    assert book.escrowed_total() == 0
    assert book.get(gid) is None


def test_draw_enforces_period_cap_and_rolls_to_next_period():
    book = GrantBook()
    entry = make_entry(amount=5000, spend_cap=500, per_payment_cap=500)
    book.submit(entry)
    gid = entry.grant_id
    # Week 1: 500 is the cap.
    assert book.can_admit_draw(gid, BOB, 500, 0, DEC_1_2026)[0]
    book.draw(gid, 500, DEC_1_2026)
    assert not book.can_admit_draw(gid, BOB, 1, 0, DEC_1_2026 + DAY)[0]
    # Week 2: the cap resets, the same 500 is drawable again.
    assert book.can_admit_draw(gid, BOB, 500, 0, DEC_1_2026 + WEEK)[0]
    book.draw(gid, 500, DEC_1_2026 + WEEK)
    assert book.drawn_total(gid) == 1000
    assert book.drawn_in_period(gid, DEC_1_2026 + WEEK) == 500
    assert book.drawn_in_period(gid, DEC_1_2026) == 0


def test_draw_enforces_per_payment_cap():
    book = GrantBook()
    book.submit(make_entry())
    gid = make_entry().grant_id
    assert not book.can_admit_draw(gid, BOB, 501, 0, DEC_1_2026)[0]
    assert book.can_admit_draw(gid, BOB, 500, 0, DEC_1_2026)[0]


def test_draw_enforces_time_windows_and_masks():
    book = GrantBook()
    ts = DEC_1_2026
    w = weekday(ts)
    h = hour_of_day(ts)
    assert h < 23  # the +1h step below must stay in the same day
    entry = make_entry(
        weekday_mask=1 << w,
        hour_mask=1 << h,
        start_at=ts,
        expires_at=ts + 28 * DAY,
    )
    book.submit(entry)
    gid = entry.grant_id
    assert book.can_admit_draw(gid, BOB, 100, 0, ts)[0]
    assert not book.can_admit_draw(gid, BOB, 100, 0, ts + DAY)[0]  # wrong weekday
    assert not book.can_admit_draw(gid, BOB, 100, 0, ts + 3600)[0]  # wrong hour
    assert not book.can_admit_draw(gid, BOB, 100, 0, ts - 1)[0]  # not started
    assert not book.can_admit_draw(gid, BOB, 100, 0, ts + 28 * DAY)[0]  # expired


def test_draw_rejects_wrong_drawer_and_unknown_grant():
    book = GrantBook()
    book.submit(make_entry())
    gid = make_entry().grant_id
    assert not book.can_admit_draw(gid, CAROL, 100, 0, DEC_1_2026)[0]
    assert not book.can_admit_draw(b"\x00" * 32, BOB, 100, 0, DEC_1_2026)[0]
    assert not book.can_admit_cancel(gid, BOB, 0, DEC_1_2026)[0]
    assert book.can_admit_cancel(gid, ALICE, 0, DEC_1_2026)[0]


def test_pending_draws_count_toward_caps_in_one_block():
    book = GrantBook()
    book.submit(make_entry())
    gid = make_entry().grant_id
    # One draw of 500 is staged in this block; a second 500 would exceed
    # the 500/week cap, and a second 1 would exceed the remaining amount
    # only when combined with the staged draw.
    assert book.can_admit_draw(gid, BOB, 500, 0, DEC_1_2026, pending_drawn=500)[0] is False
    assert book.can_admit_draw(gid, BOB, 1, 0, DEC_1_2026, pending_drawn=500)[0] is False
    assert book.can_admit_draw(gid, BOB, 500, 0, DEC_1_2026, pending_drawn=0)[0]


def test_duplicate_create_and_per_granter_cap():
    book = GrantBook()
    entry = make_entry()
    book.submit(entry)
    assert not book.can_admit_create(entry, 0, DEC_1_2026)[0]  # duplicate id
    for seq in range(2, 17):
        ok, reason = book.can_admit_create(make_entry(sequence_number=seq), 0, DEC_1_2026)
        assert ok, reason
        book.submit(make_entry(sequence_number=seq))
    assert book.open_count_for_granter(ALICE) == 16
    assert not book.can_admit_create(make_entry(sequence_number=17), 0, DEC_1_2026)[0]


def test_refund_due_expires_only_matured_grants():
    book = GrantBook()
    early = make_entry(sequence_number=1, expires_at=DEC_1_2026 + 7 * DAY)
    late = make_entry(sequence_number=2, expires_at=DEC_1_2026 + 28 * DAY)
    book.submit(early)
    book.submit(late)
    due = book.refund_due(0, DEC_1_2026 + 7 * DAY)
    assert len(due) == 1
    assert due[0][0] == early and due[0][1] == 5000
    assert book.open_count() == 1
    assert book.get(late.grant_id) is not None
    assert book.escrowed_total() == 5000


def test_root_is_deterministic_and_changes_on_mutation():
    def build():
        book = GrantBook()
        book.submit(make_entry())
        book.draw(make_entry().grant_id, 500, DEC_1_2026)
        return book

    first = build()
    second = build()
    assert first.root() == second.root()
    first.cancel(make_entry().grant_id)
    assert first.root() != second.root()
    # A fresh book that cancels the same way reaches the same root.
    third = build()
    third.cancel(make_entry().grant_id)
    assert first.root() == third.root()


def test_snapshot_restore_roundtrip():
    book = GrantBook()
    book.submit(make_entry())
    book.draw(make_entry().grant_id, 500, DEC_1_2026)
    other = make_entry(sequence_number=2, amount=2000, spend_cap=2000,
                       per_payment_cap=2000)
    book.submit(other)
    restored = GrantBook.restore(
        book.snapshot_rows(), book.resolved_count, book.resolved_acc
    )
    assert restored.root() == book.root()
    assert restored.escrowed_total() == book.escrowed_total()
    assert restored.drawn_total(make_entry().grant_id) == 500
    assert restored.remaining_for(make_entry().grant_id) == 4500


def test_restore_refuses_a_tampered_row():
    book = GrantBook()
    book.submit(make_entry())
    rows = book.snapshot_rows()
    rows[0]["amount"] = 5001  # the id no longer recomputes
    with pytest.raises(ValueError):
        GrantBook.restore(rows, 0, bytes(32))


def test_deepcopy_is_independent():
    import copy

    book = GrantBook()
    book.submit(make_entry())
    clone = copy.deepcopy(book)
    clone.draw(make_entry().grant_id, 500, DEC_1_2026)
    assert book.drawn_total(make_entry().grant_id) == 0
    assert book.root() != clone.root()


def test_demo_alice_bob_5000_500_per_week_from_dec_1():
    """The Stage 2 demo: Alice grants Bob 5,000, 500/week from Dec 1,
    refund at deadline."""
    book = GrantBook()
    entry = make_entry()
    book.submit(entry)
    gid = entry.grant_id
    # Week 1 (Dec 1): Bob draws his 500.
    assert book.can_admit_draw(gid, BOB, 500, 0, DEC_1_2026)[0]
    book.draw(gid, 500, DEC_1_2026)
    # He cannot draw again that week, nor before Dec 1.
    assert not book.can_admit_draw(gid, BOB, 1, 0, DEC_1_2026 + 3 * DAY)[0]
    assert not book.can_admit_draw(gid, BOB, 1, 0, DEC_1_2026 - 1)[0]
    # Weeks 2-4: 500 each.
    for week in (1, 2, 3):
        ts = DEC_1_2026 + week * WEEK
        assert book.can_admit_draw(gid, BOB, 500, 0, ts)[0]
        book.draw(gid, 500, ts)
    assert book.drawn_total(gid) == 2000
    # Deadline Dec 29: the un-drawn 3,000 is refunded to Alice.
    due = book.refund_due(0, DEC_1_2026 + 28 * DAY)
    assert due == [(entry, 3000)]
    assert book.escrowed_total() == 0
    assert book.resolved_count == 1


# ---------------------------------------------------------------- sweep


def test_sweep_handler_refunds_expired_grant():
    book = GrantBook()
    entry = make_entry()
    book.submit(entry)
    book.draw(entry.grant_id, 500, DEC_1_2026)
    balances = {ALICE: 1000, BOB: 0}
    sequences = {ALICE: 1, BOB: 1}
    ledger = CreditLedger()
    ctx = SweepContext(
        lm=SimpleNamespace(grants=book),
        balances=balances,
        sequences=sequences,
        height=10,
        timestamp=DEC_1_2026 + 28 * DAY,
        faucet_grant=0,
        credit_records=ledger,
    )
    handler = _GrantSweepHandler()
    due = handler.collect_due(ctx.lm, 10, DEC_1_2026 + 28 * DAY)
    assert len(due) == 1
    assert due[0].object_id == entry.grant_id and due[0].kind == "grant"
    assert handler.execute(due[0], ctx) == "refunded"
    assert balances[ALICE] == 1000 + 4500  # the un-drawn remainder
    assert book.open_count() == 0
    assert book.escrowed_total() == 0
    assert len(ledger.all()) == 1
    assert ledger.total_for(ALICE, CREDIT_GRANT_REFUND) == 4500
    assert ledger.all()[0].credit_class == CREDIT_GRANT_REFUND


def test_sweep_handler_skips_unknown_and_not_due():
    book = GrantBook()
    ctx = SweepContext(
        lm=SimpleNamespace(grants=book),
        balances={},
        sequences={},
        height=10,
        timestamp=DEC_1_2026,
        faucet_grant=0,
        credit_records=None,
    )
    handler = _GrantSweepHandler()
    assert handler.collect_due(ctx.lm, 10, DEC_1_2026) == []
    ghost = SweepDue(due_ts=DEC_1_2026, object_id=b"\x00" * 32, kind="grant")
    assert handler.execute(ghost, ctx) == "skipped_unknown"
    book.submit(make_entry())
    not_due = SweepDue(
        due_ts=DEC_1_2026 + 28 * DAY,
        object_id=make_entry().grant_id,
        kind="grant",
    )
    assert handler.execute(not_due, ctx) == "skipped_not_due"


# ---------------------------------------------------------------- engine
# End-to-end: grant transactions through apply_block, with the same harness
# as test_programmable_credits.py (one transfer, fee 7, Alice proposes).

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


def _e_grant_create_tx(amount=5000, seq=0, expires_at=E_TS + 100,
                       chain_id=CHAIN_ID, start_at=E_TS):
    tx = {
        "tx_id": f"grant-create-{seq}",
        "tx_type": "grant_create",
        "sender_pubkey": E_ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "grantee_pubkey": E_BOB,
        "refund_to": E_ALICE,
        "amount": amount,
        "period_kind": PERIOD_WEEK,
        "period_anchor": 0,
        "spend_cap": 500,
        "per_payment_cap": 500,
        "start_at": start_at,
        "expires_at": expires_at,
        "chain_id": chain_id,
    }
    return _e_sign(tx, E_SK_ALICE)


def _e_grant_draw_tx(grant_id, amount=500, seq=0):
    tx = {
        "tx_id": f"grant-draw-{seq}-{amount}",
        "tx_type": "grant_draw",
        "sender_pubkey": E_BOB,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "grant_id": grant_id.hex(),
        "amount": amount,
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, E_SK_BOB)


def _e_grant_cancel_tx(grant_id, seq=1):
    tx = {
        "tx_id": f"grant-cancel-{seq}",
        "tx_type": "grant_cancel",
        "sender_pubkey": E_ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 1000,
        "fee_limit": "10000",
        "grant_id": grant_id.hex(),
        "chain_id": CHAIN_ID,
    }
    return _e_sign(tx, E_SK_ALICE)


def _e_fresh_parent():
    lm = ConsensusLifecycleManager(active_validators=[E_ALICE])
    lm.genesis_hash = CHAIN_ID
    return _e_snapshot(lm, {E_ALICE: 100000, E_BOB: 0})


def _e_grant_id(result):
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    (gid,) = list(lm.grants.open)
    return gid


def test_engine_grant_create_escrows_funds():
    result = _e_apply_block([_e_grant_create_tx()], _e_fresh_parent())
    assert result.accepted_tx_ids == ["grant-create-0"]
    balances = result.next_snapshot.metadata["balances"]
    # Alice pays 5,000 into escrow + 7 fee, and receives 7 back as proposer.
    assert balances[E_ALICE] == 100000 - 5000
    assert balances[E_BOB] == 0  # escrowed: no credit lands on Bob
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    assert lm.grants.open_count() == 1
    assert lm.grants.escrowed_total() == 5000
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in result.credits}
    assert got == {(E_ALICE, E_FEE, CREDIT_FEE_REWARD)}  # fee reward only


def test_engine_grant_create_wrong_chain_id_rejected():
    result = _e_apply_block(
        [_e_grant_create_tx(chain_id="ff" * 32)], _e_fresh_parent()
    )
    assert result.accepted_tx_ids == []
    balances = result.next_snapshot.metadata["balances"]
    assert balances[E_ALICE] == 100000
    lm = result.next_snapshot.metadata["lifecycle_manager"]
    assert lm.grants.open_count() == 0


def test_engine_grant_create_without_chain_id_rejected():
    tx = _e_grant_create_tx()
    del tx["chain_id"]
    tx = _e_sign(tx, E_SK_ALICE)
    result = _e_apply_block([tx], _e_fresh_parent())
    assert result.accepted_tx_ids == []


def test_engine_grant_draw_pays_grantee():
    first = _e_apply_block([_e_grant_create_tx()], _e_fresh_parent())
    gid = _e_grant_id(first)
    second = _e_apply_block(
        [_e_grant_draw_tx(gid)], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 10,
    )
    assert second.accepted_tx_ids == ["grant-draw-0-500"]
    balances = second.next_snapshot.metadata["balances"]
    assert balances[E_BOB] == 500
    assert balances[E_ALICE] == 100000 - 5000
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in second.credits}
    assert (E_BOB, 500, CREDIT_GRANT_DRAW) in got
    lm = second.next_snapshot.metadata["lifecycle_manager"]
    assert lm.grants.drawn_total(gid) == 500
    assert lm.grants.escrowed_total() == 4500


def test_engine_grant_draw_over_cap_rejected():
    first = _e_apply_block([_e_grant_create_tx()], _e_fresh_parent())
    gid = _e_grant_id(first)
    second = _e_apply_block(
        [_e_grant_draw_tx(gid, amount=501)], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 10,
    )
    assert second.accepted_tx_ids == []
    assert second.next_snapshot.metadata["balances"][E_BOB] == 0


def test_engine_grant_cancel_refunds_remainder():
    first = _e_apply_block([_e_grant_create_tx()], _e_fresh_parent())
    gid = _e_grant_id(first)
    second = _e_apply_block(
        [_e_grant_draw_tx(gid)], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 10,
    )
    third = _e_apply_block(
        [_e_grant_cancel_tx(gid, seq=1)], second.next_snapshot,
        height=E_HEIGHT + 2, timestamp=E_TS + 20,
    )
    assert third.accepted_tx_ids == ["grant-cancel-1"]
    balances = third.next_snapshot.metadata["balances"]
    assert balances[E_ALICE] == 100000 - 5000 + 4500
    assert balances[E_BOB] == 500
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in third.credits}
    assert (E_ALICE, 4500, CREDIT_GRANT_REFUND) in got
    lm = third.next_snapshot.metadata["lifecycle_manager"]
    assert lm.grants.open_count() == 0
    assert lm.grants.escrowed_total() == 0


def test_engine_sweep_refunds_expired_grant_in_block():
    first = _e_apply_block([_e_grant_create_tx()], _e_fresh_parent())
    gid = _e_grant_id(first)
    # An empty block at the expiry timestamp: the sweep refunds the grant.
    second = _e_apply_block(
        [], first.next_snapshot,
        height=E_HEIGHT + 1, timestamp=E_TS + 100,
    )
    assert second.accepted_tx_ids == []
    balances = second.next_snapshot.metadata["balances"]
    assert balances[E_ALICE] == 100000  # the full 5,000 is back
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in second.credits}
    assert (E_ALICE, 5000, CREDIT_GRANT_REFUND) in got
    lm = second.next_snapshot.metadata["lifecycle_manager"]
    assert lm.grants.open_count() == 0
    assert lm.grants.escrowed_total() == 0
    sweep = second.governance_changes["programmable_sweep"]
    assert sweep["executed"] == [
        {"object_id": gid.hex(), "kind": "grant", "outcome": "refunded"}
    ]
    assert sweep["failed"] == [] and sweep["deferred"] == []


# ---------------------------------------------------------------- admission
# The mempool validators, exercised with a fake tip view backed by a real
# GrantBook (the validators judge through the book, so admission and apply
# cannot drift apart).


class _FakeTipView:
    def __init__(self, book=None, genesis_hash=CHAIN_ID, height=21, timestamp=E_TS):
        self._book = book or GrantBook()
        self.genesis_hash = genesis_hash
        self.next_block_height = height
        self.next_block_timestamp = timestamp

    def get_grant(self, grant_id):
        for row in self._book.snapshot_rows():
            if row["grant_id"] == grant_id.hex():
                return row
        return None

    def open_grant_count_for_granter(self, pubkey):
        return self._book.open_count_for_granter(pubkey)

    def open_grant_count(self):
        return self._book.open_count()


def _admission_entry(**overrides):
    # A GrantEntry whose pubkeys match the engine-test keys, so the same
    # transaction builders can feed admission.
    fields = {
        "granter_pubkey": E_ALICE,
        "grantee_pubkey": E_BOB,
        "refund_to": E_ALICE,
        "amount": 5000,
        "sequence_number": 0,
        "period_kind": PERIOD_WEEK,
        "period_length": None,
        "period_anchor": 0,
        "spend_cap": 500,
        "per_payment_cap": 500,
        "weekday_mask": ALL_WEEKDAYS_MASK,
        "hour_mask": ALL_HOURS_MASK,
        "start_at": E_TS,
        "expires_at": E_TS + 100,
    }
    fields.update(overrides)
    return GrantEntry(**fields)


def test_admission_grant_create_ok_and_duplicate():
    from consensus.admission import validate_grant_create_payload

    view = _FakeTipView()
    assert validate_grant_create_payload(_e_grant_create_tx(), view).is_valid
    book = GrantBook()
    book.submit(_admission_entry())
    view = _FakeTipView(book=book)
    result = validate_grant_create_payload(_e_grant_create_tx(), view)
    assert not result.is_valid


def test_admission_grant_create_wrong_chain_id():
    from consensus.admission import validate_grant_create_payload
    from consensus.chain_binding import WRONG_CHAIN_ID

    view = _FakeTipView()
    result = validate_grant_create_payload(
        _e_grant_create_tx(chain_id="ff" * 32), view
    )
    assert not result.is_valid
    assert getattr(result, "code", None) == WRONG_CHAIN_ID


def test_admission_grant_draw_and_cancel():
    from consensus.admission import (
        validate_grant_cancel_payload,
        validate_grant_draw_payload,
    )

    book = GrantBook()
    entry = _admission_entry()
    book.submit(entry)
    view = _FakeTipView(book=book)
    gid = entry.grant_id
    assert validate_grant_draw_payload(_e_grant_draw_tx(gid), view).is_valid
    assert not validate_grant_draw_payload(
        _e_grant_draw_tx(gid, amount=501), view
    ).is_valid
    assert not validate_grant_draw_payload(
        _e_grant_draw_tx(b"\x00" * 32), view
    ).is_valid
    assert validate_grant_cancel_payload(_e_grant_cancel_tx(gid), view).is_valid
    # Only the granter may cancel: a cancel signed by Bob fails.
    cancel_by_bob = _e_grant_cancel_tx(gid)
    cancel_by_bob["sender_pubkey"] = E_BOB
    cancel_by_bob = _e_sign(cancel_by_bob, E_SK_BOB)
    assert not validate_grant_cancel_payload(cancel_by_bob, view).is_valid
