"""The no-regenesis guarantee for rule sharing.

Rule-offer state is bound into the block state hash through
`consensus_meta.mechanism_specific_metadata`. Adding a key there
unconditionally would change the state hash of every existing chain, including
genesis, forcing a coordinated reset.

Instead the keys are emitted ONLY when the offer book is non-empty, matching
the gate `eligibility_mode` already uses (see
ConsensusLifecycleManager.consensus_meta_hash and scripts/gen_genesis.py).
While no offer has ever been made, the preimage is byte-identical to what a
pre-feature binary produced.

If any of these tests fails, shipping the change forks every live chain.
"""
import pytest

from consensus.governance import (
    DEFAULT_ELIGIBILITY_MODE,
    DEFAULT_MAX_RULE_TXS_PER_BLOCK,
    DEFAULT_QUORUM_POLICY,
    ConsensusLifecycleManager,
    validate_max_rule_txs_per_block,
)
from consensus.rule_offers import RuleOffer, RuleOfferDecision, normalize_offer_rule_text
from consensus.state import compute_consensus_meta_hash

A = "aa" * 48
B = "bb" * 48
CLAUSE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."


def _legacy_meta_hash(lm):
    """The preimage a binary without rule sharing would have produced."""
    vote_records = [
        (uid, voter) for uid, voters in lm.votes.items() for voter in voters
    ]
    mech = {"vote_quorum": lm.effective_quorum_policy()}
    if lm.effective_eligibility_mode() != DEFAULT_ELIGIBILITY_MODE:
        mech["eligibility_mode"] = lm.effective_eligibility_mode()
    return compute_consensus_meta_hash(
        host_contract={},
        active_validators=list(lm.active_validators),
        pending_updates=list(lm.pending_updates),
        vote_records=vote_records,
        activation_schedule=lm.scheduled_updates,
        checkpoint_references=[],
        mechanism_specific_metadata=mech,
    )


def _offer(recipient=B, expire=1000, text=CLAUSE):
    return RuleOffer(
        offerer_pubkey=A,
        recipient_pubkey=recipient,
        rule_text=text,
        expire_at_height=expire,
    )


@pytest.mark.parametrize("eligibility_mode", ["", DEFAULT_ELIGIBILITY_MODE, "tau_validator_set"])
@pytest.mark.parametrize("validators", [[], [A], [A, B]])
def test_empty_book_preserves_legacy_meta_hash(eligibility_mode, validators):
    """Across quorum/eligibility/validator combinations, an untouched book
    contributes nothing to the hash."""
    lm = ConsensusLifecycleManager(active_validators=validators)
    lm.eligibility_mode = eligibility_mode
    assert lm.rule_offers.is_empty()
    assert lm.consensus_meta_hash() == _legacy_meta_hash(lm), (
        "an empty offer book changed the meta hash; every existing chain "
        "would fork on upgrade"
    )


def test_default_block_budget_is_not_bound():
    """The budget only enters the preimage once governance changes it."""
    lm = ConsensusLifecycleManager(active_validators=[A])
    assert lm.max_rule_txs_per_block == DEFAULT_MAX_RULE_TXS_PER_BLOCK
    baseline = lm.consensus_meta_hash()

    lm.max_rule_txs_per_block = DEFAULT_MAX_RULE_TXS_PER_BLOCK
    assert lm.consensus_meta_hash() == baseline

    lm.max_rule_txs_per_block = DEFAULT_MAX_RULE_TXS_PER_BLOCK + 1
    assert lm.consensus_meta_hash() != baseline


def test_first_offer_changes_the_meta_hash():
    """The flip side of the gate: once an offer exists it MUST be bound, so a
    node running the old binary diverges loudly instead of silently."""
    lm = ConsensusLifecycleManager(active_validators=[A])
    baseline = lm.consensus_meta_hash()

    assert lm.rule_offers.submit_offer(_offer())
    assert not lm.rule_offers.is_empty()
    assert lm.consensus_meta_hash() != baseline
    assert lm.consensus_meta_hash() != _legacy_meta_hash(lm)


def test_resolution_is_bound_but_status_is_not():
    """Accept and reject both move the id into `resolved`, which is hashed; the
    distinguishing status is node-local, so it must NOT change the hash."""
    body, target = normalize_offer_rule_text(CLAUSE)

    def resolved_hash(accept):
        lm = ConsensusLifecycleManager(active_validators=[A])
        offer = _offer()
        lm.rule_offers.submit_offer(offer)
        decision = RuleOfferDecision(
            offer_id=offer.offer_id,
            actor_pubkey=B,
            accept=accept,
            rule_text=CLAUSE if accept else None,
        )
        ok, reason = lm.rule_offers.can_admit_decision(decision)
        assert ok, reason
        lm.rule_offers.submit_decision(decision)
        return lm.consensus_meta_hash(), lm

    accepted_hash, accepted_lm = resolved_hash(True)
    rejected_hash, rejected_lm = resolved_hash(False)

    # An accept registers a clause, which IS bound, so the two must differ.
    assert accepted_lm.rule_offers.clause_for(B, target) == body
    assert rejected_lm.rule_offers.clause_for(B, target) is None
    assert accepted_hash != rejected_hash

    # Two rejects of the same offer agree regardless of node-local bookkeeping.
    again, _ = resolved_hash(False)
    assert again == rejected_hash


def test_resolved_set_is_never_pruned_back_to_empty():
    """`is_empty()` is the hash-compat gate. If resolving the last offer made
    it True again, the hash would silently revert to the legacy preimage."""
    lm = ConsensusLifecycleManager(active_validators=[A])
    offer = _offer()
    lm.rule_offers.submit_offer(offer)
    lm.rule_offers.submit_decision(
        RuleOfferDecision(offer_id=offer.offer_id, actor_pubkey=B, accept=False)
    )
    assert not lm.rule_offers.offered
    assert lm.rule_offers.resolved
    assert not lm.rule_offers.is_empty()
    assert lm.consensus_meta_hash() != _legacy_meta_hash(lm)


def test_expiry_resolves_and_binds():
    lm = ConsensusLifecycleManager(active_validators=[A])
    offer = _offer(expire=10)
    lm.rule_offers.submit_offer(offer)
    before = lm.consensus_meta_hash()

    lm.process_height_transitions(9)
    assert offer.offer_id in lm.rule_offers.offered
    assert lm.consensus_meta_hash() == before

    lm.process_height_transitions(10)
    assert offer.offer_id not in lm.rule_offers.offered
    assert offer.offer_id in lm.rule_offers.resolved
    assert lm.consensus_meta_hash() != before


def test_offer_book_root_is_order_independent():
    """Insertion order must not affect the hash."""
    offers = [
        _offer(recipient=B, expire=100 + i, text=CLAUSE) for i in range(4)
    ]

    def root_for(sequence):
        lm = ConsensusLifecycleManager(active_validators=[A])
        for offer in sequence:
            lm.rule_offers.submit_offer(offer)
        return lm.rule_offers.offers_root()

    assert root_for(offers) == root_for(list(reversed(offers)))


def test_clause_registry_root_is_order_independent():
    body, target = normalize_offer_rule_text(CLAUSE)
    other = "o5[t]:bv[24] = { #x000001 }:bv[24]"

    def root_for(items):
        lm = ConsensusLifecycleManager()
        for key, value in items:
            lm.rule_offers.accepted_clauses[key] = value
        return lm.rule_offers.clauses_root()

    forward = [((A, target), body), ((B, target), other)]
    assert root_for(forward) == root_for(list(reversed(forward)))
    # Different bodies must produce different roots.
    assert root_for(forward) != root_for([((A, target), other), ((B, target), body)])


@pytest.mark.parametrize("value,ok", [
    (1, True), (8, True), (1024, True),
    (0, False), (-1, False), (1025, False),
    (True, False), ("8", False), (None, False), (1.0, False),
])
def test_block_budget_validation(value, ok):
    assert (validate_max_rule_txs_per_block(value) is None) is ok
