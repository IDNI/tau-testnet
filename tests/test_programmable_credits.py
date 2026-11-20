"""Tests for consensus.credits and the Stage 1 engine wiring (Bounty 01).

Classification is unit-tested; the engine wiring is tested end to end through
`apply_block` with the same harness as test_apply_block_outcome_key.py: one
transfer lands a CREDIT_TRANSFER on the recipient and a CREDIT_FEE_REWARD on
the fee beneficiary, the sweep summary is empty (no handlers in Stage 1),
and a matured retractable release lands a CREDIT_RETRACTABLE_RELEASE.
"""
import hashlib
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from block import Block
from consensus.credits import (
    CREDIT_FAUCET,
    CREDIT_FEE_REWARD,
    CREDIT_GENESIS,
    CREDIT_GRANT_DRAW,
    CREDIT_PAYOUT_LEG,
    CREDIT_REFUND,
    CREDIT_RETRACTABLE_RELEASE,
    CREDIT_ROUTE_OUTPUT,
    CREDIT_STANDING_PAYMENT,
    CREDIT_TRANSFER,
    CreditClassError,
    CreditLedger,
    CreditRecord,
    credit_class_name,
    is_routable_credit,
)
from consensus.engine import ActiveConsensusView, TauConsensusEngine, _release_due_retractables
from consensus.governance import ConsensusLifecycleManager
from consensus.retractable import KIND_HEIGHT, RetractableEntry
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
FEE = 7

SK_ALICE = 11111
ALICE = G2Basic.SkToPk(SK_ALICE).hex()
SK_BOB = 44444
BOB = G2Basic.SkToPk(SK_BOB).hex()

PUBKEY = "ab" * 48  # 96 lowercase hex characters


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


# -- classification ----------------------------------------------------------


def test_routable_classes_are_exactly_transfer_and_standing_payment():
    assert is_routable_credit(CREDIT_TRANSFER)
    assert is_routable_credit(CREDIT_STANDING_PAYMENT)
    for cls in (
        CREDIT_FAUCET,
        CREDIT_GENESIS,
        CREDIT_FEE_REWARD,
        CREDIT_REFUND,
        CREDIT_ROUTE_OUTPUT,
        CREDIT_GRANT_DRAW,
        CREDIT_PAYOUT_LEG,
        CREDIT_RETRACTABLE_RELEASE,
    ):
        assert not is_routable_credit(cls)
    # Fail closed: an unknown class is never routable.
    assert not is_routable_credit(999)


def test_class_names_cover_every_class():
    for cls in range(11):
        assert credit_class_name(cls)
    assert credit_class_name(CREDIT_TRANSFER) == "transfer"
    assert credit_class_name(CREDIT_STANDING_PAYMENT) == "standing_payment"
    with pytest.raises(CreditClassError):
        credit_class_name(999)


def test_credit_record_validation():
    rec = CreditRecord(PUBKEY, 5, CREDIT_TRANSFER, "tx-1")
    assert rec.routable
    assert not CreditRecord(PUBKEY, 5, CREDIT_FAUCET, "tx-1").routable
    with pytest.raises(CreditClassError):
        CreditRecord(PUBKEY, 5, 999, "tx-1")
    with pytest.raises(CreditClassError):
        CreditRecord(PUBKEY, 0, CREDIT_TRANSFER, "tx-1")
    with pytest.raises(CreditClassError):
        CreditRecord(PUBKEY, -1, CREDIT_TRANSFER, "tx-1")
    with pytest.raises(CreditClassError):
        CreditRecord("zz" * 48, 5, CREDIT_TRANSFER, "tx-1")
    with pytest.raises(CreditClassError):
        CreditRecord(PUBKEY, 5, CREDIT_TRANSFER, "")


def test_ledger_totals_and_routable_filter():
    ledger = CreditLedger()
    ledger.record(PUBKEY, 5, CREDIT_TRANSFER, "tx-1")
    ledger.record(PUBKEY, 3, CREDIT_FAUCET, "tx-2")
    ledger.record("cd" * 48, 9, CREDIT_STANDING_PAYMENT, "tx-3")
    assert len(ledger) == 3
    assert ledger.total_for(PUBKEY) == 8
    assert ledger.total_for(PUBKEY, CREDIT_TRANSFER) == 5
    assert ledger.total_for("cd" * 48) == 9
    assert [r.amount for r in ledger.routable_for(PUBKEY)] == [5]
    assert [r.amount for r in ledger.routable_for("cd" * 48)] == [9]
    assert ledger.routable_for("ee" * 48) == ()


# -- engine wiring -----------------------------------------------------------


def _transfer_tx(tx_id="xfer-1", amount=500):
    tx = {
        "tx_id": tx_id,
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "fee_limit": "10000",
        "operations": {"1": [[ALICE, BOB, str(amount)]]},
    }
    return _sign(tx, SK_ALICE)


def _apply_block(txs, fee=FEE):
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.activate_approval_slots()
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: 100000, BOB: 0},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    active_view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(ALICE)],
        mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
    )
    block_obj = Block.create(
        block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=ALICE, timestamp=1234567890,
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
        return engine.apply_block(active_view, block_obj, parent_snapshot)


def test_transfer_lands_transfer_and_fee_reward_credits():
    result = _apply_block([_transfer_tx()])
    assert result.accepted_tx_ids == ["xfer-1"]
    balances = result.next_snapshot.metadata["balances"]
    # Alice pays 500 + 7 fee and receives 7 as fee beneficiary (she proposes).
    assert balances[ALICE] == 100000 - 500
    assert balances[BOB] == 500
    got = {(r.recipient_pubkey, r.amount, r.credit_class) for r in result.credits}
    assert got == {
        (BOB, 500, CREDIT_TRANSFER),
        (ALICE, FEE, CREDIT_FEE_REWARD),
    }
    # The transfer credit is routable; the fee reward is not.
    by_recipient = {r.recipient_pubkey: r for r in result.credits}
    assert by_recipient[BOB].routable
    assert not by_recipient[ALICE].routable
    # No sweep handlers in Stage 1: the sweep summary is empty.
    assert result.governance_changes["programmable_sweep"] == {
        "executed": [],
        "failed": [],
        "deferred": [],
    }


def test_empty_block_lands_no_credits():
    result = _apply_block([])
    assert result.credits == ()
    assert result.accepted_tx_ids == []


def test_retractable_release_lands_a_release_credit():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.activate_approval_slots()
    book = lm.retractable_transfers
    entry = RetractableEntry(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=100,
        sequence_number=0, kind=KIND_HEIGHT, release_at=10,
    )
    book.submit(entry)
    balances = {ALICE: 100000, BOB: 0}
    ledger = CreditLedger()
    released = _release_due_retractables(
        lm, balances, {}, height=10, timestamp=1234567890, credit_records=ledger
    )
    assert released == [entry.retractable_id.hex()]
    assert balances[BOB] == 100
    assert len(ledger) == 1
    (record,) = ledger.all()
    assert record.recipient_pubkey == BOB
    assert record.amount == 100
    assert record.credit_class == CREDIT_RETRACTABLE_RELEASE
    assert not record.routable
