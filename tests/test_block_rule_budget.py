"""Per-block rule-transaction budget (consensus-enforced).

Applying a rule builds an engine unit. That cost climbs steeply with
the unit's complexity, so an unbounded count lets a proposer
author a block that every validator times out on -- COMM_TIMEOUT, then a
watchdog kill. The budget is therefore block validity, not local policy.

It counts the rule-sharing transaction types and every user_tx carrying an
operations["0"] rule: an o5 rule builds a clause, any other rule rebuilds the
shared spec.
"""
import json
from unittest.mock import MagicMock

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
OTHER_STREAM_RULE = "always ( o13[t]:bv[24] = { #x000000 }:bv[24] )."


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


def _rule_tx(i, rule):
    return {
        "tx_id": f"rule-{i}",
        "tx_type": "user_tx",
        "sender_pubkey": A,
        "operations": {"0": rule},
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


def test_operation_zero_rules_on_other_streams_count_toward_the_budget():
    many = [_rule_tx(i, OTHER_STREAM_RULE) for i in range(4)]
    assert _verify(_block(many), _view(budget=4)) is True
    assert _verify(_block(many), _view(budget=3)) is False


def test_whitespace_only_rule_does_not_count():
    blanks = [_rule_tx(i, "   ") for i in range(5)]
    assert _verify(_block(blanks), _view(budget=1)) is True


def test_operation_zero_o5_rules_count_toward_the_budget():
    rules = [_rule_tx(i, RULE) for i in range(4)]
    assert _verify(_block(rules), _view(budget=4)) is True
    assert _verify(_block(rules), _view(budget=3)) is False


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


# --- the proposer's selection follows the same predicate -------------------

def _user_tx_with(rule_text, seq=0):
    return {
        "tx_type": "user_tx", "sender_pubkey": A, "sequence_number": seq,
        "expiration_time": 9999999999, "expire_at_height": 5000,
        "fee_limit": "10", "operations": {"0": rule_text},
    }


@pytest.mark.parametrize("tx", [
    _user_tx_with(RULE),
    _user_tx_with(OTHER_STREAM_RULE),
    _user_tx_with("   "),
    {"tx_type": "user_tx", "operations": {"1": [[A, A, 1]]}},
])
def test_user_tx_costs_a_slot_exactly_when_it_rides_the_slow_lane(tx):
    from consensus.lanes import LANE_SLOW, classify_lane

    assert TauConsensusEngine._counts_against_rule_budget(tx) is (
        classify_lane(tx) == LANE_SLOW
    )


def test_createblock_never_selects_more_rule_txs_than_the_ceiling(temp_database):
    import db
    from commands import createblock

    ceiling = 3
    for i in range(12):
        sender = format(i, "096x")
        db.add_mempool_tx(
            json.dumps(_user_tx_with(
                f"always ( o{12 + i}[t]:bv[24] = i1[t]:bv[24] ).")
                | {"sender_pubkey": sender}),
            f"rule-{i}", 1000 + i, fee_limit=10, estimated_fee=0,
        )
    for i in range(2):
        sender = format(500 + i, "096x")
        db.add_mempool_tx(
            json.dumps({
                "tx_type": "user_tx", "sender_pubkey": sender, "sequence_number": 0,
                "expiration_time": 9999999999, "expire_at_height": 5000,
                "fee_limit": "10", "operations": {"1": [[sender, A, 1]]},
            }),
            f"coin-{i}", 2000 + i, fee_limit=10, estimated_fee=0,
        )

    selected = []
    real_reserve = db.reserve_mempool_txs

    def reserve(**kwargs):
        rows = real_reserve(**kwargs)
        selected.extend(rows)
        return rows

    lm = MagicMock()
    lm.active_validators = set()
    lm.effective_eligibility_mode.return_value = "validator_set"
    lm.max_rule_txs_per_block = ceiling
    tau = MagicMock()
    tau.tau_ready.wait.return_value = False
    with patch.object(createblock, "tau_manager", tau), \
         patch.object(createblock.chain_state, "_lifecycle_manager", lm), \
         patch.object(createblock.config, "MINER_PRIVKEY", "1" * 64), \
         patch.object(createblock.config, "BLOCK_MAX_RULE_TXS", 8), \
         patch.object(createblock.db, "reserve_mempool_txs", side_effect=reserve), \
         patch.object(createblock.db, "unreserve_mempool_txs"), \
         patch.object(createblock.db, "get_canonical_head_block",
                      return_value={"block_hash": "0" * 64,
                                    "header": {"block_number": 0}}), \
         patch.object(TauConsensusEngine, "query_eligibility", return_value=True):
        createblock.create_block_from_mempool()

    txs = [json.loads(row["payload"]) for row in selected]
    costly = [tx for tx in txs if TauConsensusEngine._counts_against_rule_budget(tx)]
    assert len(costly) == ceiling
    assert len(txs) == ceiling + 2
