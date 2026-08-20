"""Block-apply semantics for the rule-sharing transaction types.

Design constraints these tests encode:

- Bounds and cap breaches are SOFT no-ops with a receipt log, matching the
  governance activation-delay handling, so block validity is a deterministic
  function of the block alone and replay never diverges.
- An accept re-emits the WHOLE composite for the target stream. Appending
  individually guarded units cannot work: an unconstrained output stream
  materializes with an arbitrary witness, and two total-form rules on one
  stream either fail to conjoin or supersede each other (see
  tests/test_rule_scoping_native.py). A second acceptance must therefore leave
  the first acceptor's policy in force -- that is the regression the composite
  design exists to prevent.
- Only a Tau failure on the composed rule hard-rejects, because that means the
  text could not have entered the specification at all.
"""
import itertools

import pytest
from unittest.mock import patch

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import (
    MAX_OFFER_WINDOW_BLOCKS,
    STATUS_ACCEPTED,
    STATUS_REJECTED,
    RuleOffer,
    clause_body_v1,
)
from consensus.state import TauStateSnapshot

A = "aa" * 48   # offerer
B = "bb" * 48   # recipient / acceptor
C = "cc" * 48   # second acceptor
BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
ALLOW_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
TARGET = 5
HEIGHT = 20
EXPIRE = 500


def _offer(offerer=A, recipient=B, text=BLOCK_RULE, expire=EXPIRE):
    return RuleOffer(offerer_pubkey=offerer, recipient_pubkey=recipient,
                     rule_text=text, expire_at_height=expire)


# `tx_id` mirrors what commands/createblock.py:309 injects before execution
# (the transaction hash). apply_block looks receipts up by it with no fallback,
# so a synthetic block without it loses every receipt log.
_TX_SEQ = itertools.count()


def offer_tx(offer, sender=None):
    return {
        "tx_id": f"offer-{next(_TX_SEQ)}",
        "tx_type": "rule_offer",
        "sender_pubkey": sender or offer.offerer_pubkey,
        "sequence_number": 0,
        "recipient_pubkey": offer.recipient_pubkey,
        "rule_text": offer.rule_text,
        "expire_at_height": offer.expire_at_height,
        "fee_limit": "0",
    }


def decision_tx(offer, *, accept, sender=None, rule_text=None):
    tx = {
        "tx_id": f"decision-{next(_TX_SEQ)}",
        "tx_type": "rule_offer_accept" if accept else "rule_offer_reject",
        "sender_pubkey": sender or offer.recipient_pubkey,
        "sequence_number": 0,
        "offer_id": offer.offer_id_hex,
        "fee_limit": "0",
    }
    if accept:
        tx["rule_text"] = rule_text if rule_text is not None else offer.rule_text
    return tx


def _apply(txs, lm=None, height=HEIGHT, tau_output="T"):
    """Apply a block of transactions and return (result, lifecycle_manager, calls)."""
    lm = lm or ConsensusLifecycleManager(active_validators=[A])
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {A: 1000, B: 1000, C: 1000},
            "sequence_numbers": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
            "active_consensus_id": "",
        },
    )
    active_view = ActiveConsensusView(
        target_height=height,
        consensus_rules=parent_snapshot.metadata["consensus_rules_state"],
        active_validators=[bytes.fromhex(A)],
        mechanism_specific_metadata={"poa": True},
    )
    block_obj = Block.create(
        block_number=height,
        previous_hash="00" * 32,
        transactions=txs,
        proposer_pubkey=A,
        timestamp=1234567890,
    )

    calls = []

    def _fake(**kwargs):
        calls.append(kwargs)
        return tau_output

    def _fake_multi(**kwargs):
        # The fee-query step for a transfer-less tx reads o8/o9. These types are
        # fee-bearing, so without this the tx is rejected on the fee step and
        # nothing downstream is exercised.
        calls.append(kwargs)
        return {8: "0", 9: "0"}

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", side_effect=_fake), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        result = engine.apply_block(active_view, block_obj, parent_snapshot)

    post_lm = result.next_snapshot.metadata["lifecycle_manager"]
    return result, post_lm, calls


def _logs(result):
    joined = []
    for outcome in result.outcomes:
        joined.extend(outcome.receipt_logs or [])
    return " | ".join(str(x) for x in joined)


# --- offers -----------------------------------------------------------------

def test_offer_is_recorded():
    offer = _offer()
    result, lm, _ = _apply([offer_tx(offer)])

    assert lm.rule_offers.get_offer(offer.offer_id) is not None
    assert "Offer submitted" in _logs(result)
    entry = lm.rule_offers.get_offer(offer.offer_id)
    assert entry.offerer_pubkey == A and entry.recipient_pubkey == B


def test_offer_beyond_its_window_is_a_soft_no_op():
    """The block stays valid; the offer simply is not recorded."""
    offer = _offer(expire=HEIGHT)   # expires at the inclusion height
    result, lm, _ = _apply([offer_tx(offer)])

    assert lm.rule_offers.get_offer(offer.offer_id) is None
    assert "Offer ignored" in _logs(result)
    assert result.next_snapshot is not None


def test_offer_too_far_ahead_is_a_soft_no_op():
    offer = _offer(expire=HEIGHT + MAX_OFFER_WINDOW_BLOCKS + 1)
    result, lm, _ = _apply([offer_tx(offer)])
    assert lm.rule_offers.get_offer(offer.offer_id) is None
    assert "Offer ignored" in _logs(result)


def test_offer_with_a_bad_shape_is_a_soft_no_op():
    offer = _offer(text="always ( o9[t]:bv[24] = { #x000001 }:bv[24] ).")
    result, lm, _ = _apply([offer_tx(offer)])
    assert lm.rule_offers.get_offer(offer.offer_id) is None
    assert "Offer ignored" in _logs(result)


def test_offer_from_a_different_sender_is_rejected():
    """Only reachable via a nested payload: the parser otherwise derives the
    offerer FROM the envelope sender, so the two cannot disagree."""
    offer = _offer()
    tx = {
        "tx_id": "offer-nested",
        "tx_type": "rule_offer",
        "sender_pubkey": None,
        "sequence_number": 0,
        "fee_limit": "0",
        "payload": {
            "sender_pubkey": C,
            "recipient_pubkey": B,
            "rule_text": BLOCK_RULE,
            "expire_at_height": EXPIRE,
        },
    }
    result, lm, _ = _apply([tx])
    assert lm.rule_offers.get_offer(offer.offer_id) is None
    assert "not the sender" in _logs(result)


def test_duplicate_offer_in_the_same_block_is_ignored_once():
    offer = _offer()
    result, lm, _ = _apply([offer_tx(offer), offer_tx(offer)])
    assert lm.rule_offers.get_offer(offer.offer_id) is not None
    logs = _logs(result)
    assert "Offer submitted" in logs
    assert "ignored" in logs


# --- accept -----------------------------------------------------------------

def test_accept_registers_the_clause_and_applies_the_composite():
    offer = _offer()
    result, lm, calls = _apply([offer_tx(offer), decision_tx(offer, accept=True)])

    assert lm.rule_offers.clause_for(B, TARGET) == clause_body_v1(BLOCK_RULE)
    assert lm.rule_offers.terminal_status[offer.offer_id] == STATUS_ACCEPTED

    rule_calls = [c for c in calls if c.get("rule_text")]
    composites = [c for c in rule_calls if "i12" in c["rule_text"]]
    assert len(composites) == 1, [c["rule_text"] for c in rule_calls]
    composite = composites[0]
    assert composite["target_output_stream_index"] == 0
    # Fed to the interpreter but NOT accumulated: save_effective_tau_spec only
    # dedups exact units, so appending would leave every earlier composite in
    # place. The clause registry is the source of truth and chain_state's
    # restore plan rebuilds the composite from it.
    assert composite["apply_rules_update"] is False
    assert B in composite["rule_text"]
    assert "composite applied" in _logs(result)


def test_accept_by_a_non_recipient_is_a_soft_no_op():
    offer = _offer()
    result, lm, _ = _apply([offer_tx(offer), decision_tx(offer, accept=True, sender=C)])
    assert lm.rule_offers.clause_for(C, TARGET) is None
    assert lm.rule_offers.get_offer(offer.offer_id) is not None   # still open
    assert "not the sender" in _logs(result) or "ignored" in _logs(result)


def test_accept_of_an_unknown_offer_is_a_soft_no_op():
    offer = _offer()
    result, lm, _ = _apply([decision_tx(offer, accept=True)])
    assert lm.rule_offers.clause_for(B, TARGET) is None
    assert "ignored" in _logs(result)


def test_accept_with_mismatched_text_is_a_soft_no_op():
    offer = _offer()
    result, lm, _ = _apply([
        offer_tx(offer),
        decision_tx(offer, accept=True, rule_text=ALLOW_RULE),
    ])
    assert lm.rule_offers.clause_for(B, TARGET) is None
    assert lm.rule_offers.get_offer(offer.offer_id) is not None
    assert "ignored" in _logs(result)


def test_second_acceptor_does_not_disable_the_first():
    """The core regression the composite design prevents."""
    first = _offer(recipient=B, expire=EXPIRE)
    second = _offer(recipient=C, expire=EXPIRE + 1)
    result, lm, calls = _apply([
        offer_tx(first), decision_tx(first, accept=True),
        offer_tx(second), decision_tx(second, accept=True),
    ])

    assert lm.rule_offers.clause_for(B, TARGET) is not None, "first acceptor's clause lost"
    assert lm.rule_offers.clause_for(C, TARGET) is not None

    composites = [c["rule_text"] for c in calls if c.get("rule_text") and "i12" in c["rule_text"]]
    assert len(composites) == 2
    # The final composite must carry BOTH acceptors.
    assert B in composites[-1] and C in composites[-1]
    # ...and it is one unit, not an accumulation.
    assert composites[-1].count("always") == 1


def test_accepting_again_replaces_the_acceptors_own_clause():
    first = _offer(text=BLOCK_RULE, expire=EXPIRE)
    second = _offer(text=ALLOW_RULE, expire=EXPIRE + 1)
    _, lm, calls = _apply([
        offer_tx(first), decision_tx(first, accept=True),
        offer_tx(second), decision_tx(second, accept=True),
    ])

    assert lm.rule_offers.clause_for(B, TARGET) == clause_body_v1(ALLOW_RULE)
    assert len(lm.rule_offers.clauses_for_stream(TARGET)) == 1


def test_tau_error_on_the_composite_hard_rejects():
    offer = _offer()
    result, lm, _ = _apply(
        [offer_tx(offer), decision_tx(offer, accept=True)],
        tau_output="(Error) Syntax Error",
    )
    logs = _logs(result)
    assert "composite rule rejected" in logs
    # The transaction is excluded from the block rather than silently accepted.
    assert result.invalid_tx_ids or "Error" in logs


# --- reject -----------------------------------------------------------------

def test_reject_resolves_without_touching_the_spec():
    offer = _offer()
    result, lm, calls = _apply([offer_tx(offer), decision_tx(offer, accept=False)])

    assert lm.rule_offers.terminal_status[offer.offer_id] == STATUS_REJECTED
    assert offer.offer_id in lm.rule_offers.resolved
    assert lm.rule_offers.clause_for(B, TARGET) is None
    # No composite is emitted for a rejection.
    assert not [c for c in calls if c.get("rule_text") and "i12" in c["rule_text"]]


def test_reject_by_a_non_recipient_is_a_soft_no_op():
    offer = _offer()
    result, lm, _ = _apply([offer_tx(offer), decision_tx(offer, accept=False, sender=C)])
    assert lm.rule_offers.get_offer(offer.offer_id) is not None
    assert offer.offer_id not in lm.rule_offers.resolved


# --- fees -------------------------------------------------------------------

@pytest.mark.parametrize("tx_type", ["rule_offer", "rule_offer_accept", "rule_offer_reject"])
def test_rule_sharing_types_are_fee_bearing(tx_type):
    """Governance types are fee-exempt so validators never need funds to
    govern; rule sharing must NOT inherit that, or rule spam is free."""
    from consensus.engine import FEE_BEARING_TX_TYPES
    assert tx_type in FEE_BEARING_TX_TYPES


def test_governance_types_remain_fee_exempt():
    from consensus.engine import FEE_BEARING_TX_TYPES
    assert "consensus_rule_update" not in FEE_BEARING_TX_TYPES
    assert "consensus_rule_vote" not in FEE_BEARING_TX_TYPES


# --- state hash -------------------------------------------------------------

def test_state_hash_moves_only_when_the_book_changes():
    offer = _offer()
    baseline, base_lm, _ = _apply([])
    with_offer, offer_lm, _ = _apply([offer_tx(offer)])

    assert base_lm.rule_offers.is_empty()
    assert not offer_lm.rule_offers.is_empty()
    assert baseline.next_snapshot.state_hash != with_offer.next_snapshot.state_hash


def test_soft_no_op_offer_leaves_the_offer_book_out_of_the_hash():
    """A breach must not perturb rule-sharing consensus state.

    The block's overall state hash still moves, because including any accepted
    transaction increments its sender's sequence number and that feeds
    accounts_hash. What must not move is the consensus_meta contribution: with
    the book still empty, the meta hash has to equal the pre-feature preimage.
    """
    baseline, base_lm, _ = _apply([])
    ignored, lm, _ = _apply([offer_tx(_offer(expire=HEIGHT))])

    assert lm.rule_offers.is_empty()
    assert lm.consensus_meta_hash() == base_lm.consensus_meta_hash()
