"""Receipt lookup in apply_block must match the key apply() uses for storage.

apply() keys receipts with tx.get('tx_id') or str(index), so a transaction
without a tx_id field keeps its outcome reason, logs and invalid_tx_ids entry.
"""
import copy
import hashlib
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.approvals import ApprovalRequest
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
EXPIRE = 500
TIER_1 = 1000

SK_ALICE = 11111
ALICE = G2Basic.SkToPk(SK_ALICE).hex()
SK_AUTH = 22222
AUTH = G2Basic.SkToPk(SK_AUTH).hex()
SK_SCAN = 33333
SCAN = G2Basic.SkToPk(SK_SCAN).hex()
SK_BOB = 44444
BOB = G2Basic.SkToPk(SK_BOB).hex()


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _request():
    return ApprovalRequest(
        sender_pubkey=ALICE, recipient_pubkey=BOB, amount=5000,
        sequence_number=0, expire_at_height=EXPIRE,
        approvers={18: AUTH, 19: SCAN}, custom_inputs={},
    )


def _request_tx(req, tx_id="req-dup", fee_limit=100):
    tx = {
        "tx_id": tx_id,
        "tx_type": "approval_request",
        "sender_pubkey": req.sender_pubkey,
        "sequence_number": req.sequence_number,
        "expiration_time": 9999999999,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": req.recipient_pubkey,
        "amount": req.amount,
        "expire_at_height": req.expire_at_height,
        "approvers": {str(k): v for k, v in req.approvers.items()},
        "custom_inputs": {},
    }
    return _sign(tx, SK_ALICE)


def _request_tx_without_tx_id(req, fee_limit=3):
    """A signed approval request with no tx_id field (synthetic / replay path)."""
    tx = {
        "tx_type": "approval_request",
        "sender_pubkey": req.sender_pubkey,
        "sequence_number": req.sequence_number,
        "expiration_time": 9999999999,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": req.recipient_pubkey,
        "amount": req.amount,
        "expire_at_height": req.expire_at_height,
        "approvers": {str(k): v for k, v in req.approvers.items()},
        "custom_inputs": {},
    }
    return _sign(tx, SK_ALICE)


def _apply(txs, fee=7):
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.activate_approval_slots()
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: 100000, AUTH: 10, SCAN: 10, BOB: 0},
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
        slot18 = str(vals.get(18, "0"))
        blocked = amount > TIER_1 and AUTH not in slot18
        out = {1: str(amount), 8: "0", 9: str(fee)}
        out[5] = "0" if blocked else "1"
        return out

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", return_value="T"), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("chain_state.get_application_rules_state", return_value=""), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        return engine.apply_block(active_view, block_obj, parent_snapshot)


def test_rejected_outcome_without_tx_id_field_uses_receipt_fallback_key():
    """Hard-reject receipts keyed by str(index) must surface on the outcome."""
    result = _apply([_request_tx_without_tx_id(_request())])
    receipt_key = "0"
    (outcome,) = [o for o in result.outcomes if o.status == "invalid"]
    assert outcome.tx_id == receipt_key
    assert outcome.reason == "fee_limit_exceeded"
    assert "Fee 7 exceeds fee_limit 3" in (outcome.receipt_logs or [])
    assert None not in result.invalid_tx_ids
    assert result.invalid_tx_ids == [receipt_key]


def test_null_tx_id_falls_back_to_index_key():
    tx = _request_tx_without_tx_id(_request())
    tx["tx_id"] = None
    result = _apply([tx])
    assert None not in result.invalid_tx_ids
    assert result.invalid_tx_ids == ["0"]
    (outcome,) = [o for o in result.outcomes if o.status == "invalid"]
    assert outcome.tx_id == "0"


def test_content_equal_rejected_duplicate_with_tx_id():
    req = _request()
    first = _request_tx(req, tx_id="dup-x")
    second = copy.deepcopy(first)
    assert first is not second and first == second
    result = _apply([first, second])
    assert len(result.outcomes) == 2
    assert result.outcomes[0].status == "applied"
    assert result.outcomes[1].status == "invalid"
    assert result.invalid_tx_ids == ["dup-x"]


def test_content_equal_rejected_duplicate_without_tx_id():
    req = _request()
    first = _request_tx_without_tx_id(req, fee_limit=100)
    second = copy.deepcopy(first)
    assert first is not second and first == second
    result = _apply([first, second])
    assert len(result.outcomes) == 2
    assert result.outcomes[0].status == "applied"
    assert result.outcomes[1].status == "invalid"
    assert result.invalid_tx_ids == ["1"]
