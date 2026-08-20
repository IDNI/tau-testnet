"""Per-block rule-transaction budget (consensus-enforced).

Applying a rule regenerates and recompiles a composite. That cost climbs
steeply with specification complexity, so an unbounded count lets a proposer
author a block that every validator times out on -- COMM_TIMEOUT, then a
watchdog kill. The budget is therefore block validity, not local policy.

It counts ONLY the rule-sharing transaction types. Legacy operations["0"]
user_tx rules are excluded on purpose: existing chains may already contain
blocks carrying many of them, and counting those would break replay of history.
"""
import pytest
from unittest.mock import patch

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import (
    DEFAULT_MAX_RULE_TXS_PER_BLOCK,
    ConsensusLifecycleManager,
    validate_max_rule_txs_per_block,
)

A = "aa" * 48
RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


def _view(budget=None, omit=False):
    meta = {"poa": True, "eligibility_mode": "validator_set"}
    if not omit:
        meta["max_rule_txs_per_block"] = (
            DEFAULT_MAX_RULE_TXS_PER_BLOCK if budget is None else budget
        )
    return ActiveConsensusView(
        target_height=10,
        consensus_rules="always ( o6[t]:bv[16] = i10[t]:bv[16] ).",
        active_validators=[bytes.fromhex(A)],
        mechanism_specific_metadata=meta,
    )


def _block(txs):
    blk = Block.create(
        block_number=10,
        previous_hash="00" * 32,
        transactions=txs,
        proposer_pubkey=A,
        timestamp=1234567890,
    )
    blk.consensus_proof = {"scheme": "bls_header_sig", "signature": "ab" * 48}
    return blk


def _offer_tx(i):
    return {
        "tx_id": f"offer-{i}",
        "tx_type": "rule_offer",
        "sender_pubkey": A,
        "recipient_pubkey": "bb" * 48,
        "rule_text": RULE,
        "expire_at_height": 500,
    }


def _legacy_rule_tx(i):
    return {
        "tx_id": f"legacy-{i}",
        "tx_type": "user_tx",
        "sender_pubkey": A,
        "operations": {"0": RULE},
    }


def _verify(block, view):
    engine = TauConsensusEngine()
    # Stub the Tau o6/o7 evaluation so only the budget check is under test.
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau_multi", return_value={6: "1", 7: "1"}), \
         patch("tau_manager.communicate_with_tau", return_value="1"), \
         patch.object(TauConsensusEngine, "_view_eligibility_mode", staticmethod(lambda v: "validator_set")), \
         patch("consensus.engine.normalize_validator_set", return_value={A}):
        ready.is_set.return_value = True
        return engine.verify_block_header(view, block, {"proof_ok": True})


def test_block_within_budget_verifies():
    assert _verify(_block([_offer_tx(i) for i in range(3)]), _view(budget=3)) is True


def test_block_over_budget_is_invalid():
    assert _verify(_block([_offer_tx(i) for i in range(4)]), _view(budget=3)) is False


def test_default_budget_applies_when_the_view_omits_it():
    """An older view without the field must still be bounded by the default,
    not left unbounded."""
    over = [_offer_tx(i) for i in range(DEFAULT_MAX_RULE_TXS_PER_BLOCK + 1)]
    assert _verify(_block(over), _view(omit=True)) is False
    within = [_offer_tx(i) for i in range(DEFAULT_MAX_RULE_TXS_PER_BLOCK)]
    assert _verify(_block(within), _view(omit=True)) is True


def test_malformed_budget_skips_the_check_rather_than_failing_closed():
    """A junk value must not invalidate every block on the chain."""
    assert _verify(_block([_offer_tx(i) for i in range(50)]), _view(budget="lots")) is True
    assert _verify(_block([_offer_tx(i) for i in range(50)]), _view(budget=0)) is True


def test_legacy_operation_zero_rules_are_not_counted():
    """Counting them would invalidate historical blocks on replay."""
    many = [_legacy_rule_tx(i) for i in range(50)]
    assert _verify(_block(many), _view(budget=1)) is True


def test_accepts_and_rejects_count_toward_the_budget():
    accepts = [
        {"tx_id": f"a-{i}", "tx_type": "rule_offer_accept", "sender_pubkey": A,
         "offer_id": "ab" * 32, "rule_text": RULE}
        for i in range(2)
    ]
    rejects = [
        {"tx_id": f"r-{i}", "tx_type": "rule_offer_reject", "sender_pubkey": A,
         "offer_id": "cd" * 32}
        for i in range(2)
    ]
    assert _verify(_block(accepts + rejects), _view(budget=4)) is True
    assert _verify(_block(accepts + rejects), _view(budget=3)) is False


def test_empty_block_verifies():
    assert _verify(_block([]), _view(budget=1)) is True


# --- governance plumbing ----------------------------------------------------

def test_budget_travels_on_the_derived_view():
    """Proposer and verifier must read one authority, so derive_active_consensus
    has to publish the lifecycle manager's value onto the view."""
    from consensus.state import TauStateSnapshot

    lm = ConsensusLifecycleManager(active_validators=[A])
    lm.max_rule_txs_per_block = 5
    parent = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"",
        metadata={
            "balances": {}, "sequence_numbers": {}, "lifecycle_manager": lm,
            "consensus_rules_state": "always ( o6[t]:bv[16] = i10[t]:bv[16] ).",
            "active_consensus_id": "",
        },
    )
    engine = TauConsensusEngine()
    view = engine.derive_active_consensus(parent, 11)
    assert view.mechanism_specific_metadata["max_rule_txs_per_block"] == 5


def test_governance_patch_changes_the_budget():
    lm = ConsensusLifecycleManager(active_validators=[A])
    assert lm.max_rule_txs_per_block == DEFAULT_MAX_RULE_TXS_PER_BLOCK
    baseline_hash = lm.consensus_meta_hash()

    lm.apply_host_contract_patch({"max_rule_txs_per_block": 2})
    assert lm.max_rule_txs_per_block == 2
    # Non-default values ARE bound, so nodes cannot disagree about the ceiling.
    assert lm.consensus_meta_hash() != baseline_hash


def test_governance_patch_rejects_out_of_range_budgets():
    lm = ConsensusLifecycleManager(active_validators=[A])
    for bad in (0, -1, 2000, "8", True, None):
        with pytest.raises(ValueError, match="max_rule_txs_per_block"):
            lm.apply_host_contract_patch({"max_rule_txs_per_block": bad})
    assert lm.max_rule_txs_per_block == DEFAULT_MAX_RULE_TXS_PER_BLOCK


@pytest.mark.parametrize("value,ok", [
    (1, True), (8, True), (1024, True),
    (0, False), (-1, False), (1025, False), (True, False), ("8", False),
])
def test_budget_validation(value, ok):
    assert (validate_max_rule_txs_per_block(value) is None) is ok
