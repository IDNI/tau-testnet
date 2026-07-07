"""Phase 9C — scheduled-update payloads survive a restart (Finding 2).

Before this fix, `consensus_updates_v2` stored payloads only for PENDING
updates. A node restarting in the window between an update being
approved-and-scheduled and its activation height reloaded the scheduled
`(height, uid)` entry but NOT the payload, so `process_height_transitions(H)`
found `uid not in update_payloads` and silently skipped applying the
revision/patch — forking from peers that activated it.

Also covers Phase 9D: the full lifecycle-manager field set (active_validators,
quorum_policy, eligibility_mode, pending/scheduled) round-trips through
`commit_state_to_db`. (All three production commit sites —
process_new_block:~620, commit_state_to_db:~1467, reorg:~1790 — now build the
persisted payload list via the same `_persistable_update_payloads` helper and
pass the same active_validators/quorum_policy/eligibility_mode triple; verified
by static audit.)
"""
import chain_state
from consensus.governance import (
    ConsensusLifecycleManager,
    ConsensusRuleUpdate,
    ConsensusRuleVote,
)

VALIDATORS = ["a" * 96, "b" * 96, "c" * 96]  # majority threshold = 2
REV = "always ( o6[t]:bv[16] = i10[t]:bv[16] )."
PATCH = {"eligibility_mode": "stake"}
ACTIVATE_AT = 50


def _schedule_update(lm):
    """Submit an update + reach quorum so it moves pending -> scheduled."""
    update = ConsensusRuleUpdate([REV], ACTIVATE_AT, host_contract_patch=PATCH)
    assert lm.submit_update(update)
    assert lm.submit_vote(ConsensusRuleVote(update.update_id, True), VALIDATORS[0])
    assert lm.submit_vote(ConsensusRuleVote(update.update_id, True), VALIDATORS[1])
    # Now scheduled, not pending.
    assert update.update_id not in lm.pending_updates
    assert any(uid == update.update_id for _, uid in lm.scheduled_updates)
    return update


def _seed_state(lm):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances["acct"] = 1
    chain_state._sequence_numbers["acct"] = 0
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""  # genesis default; keep meta-hash stable across reload
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm


def test_scheduled_payload_persists_and_reloads(temp_database):
    lm = ConsensusLifecycleManager(active_validators=VALIDATORS)
    _seed_state(lm)
    update = _schedule_update(lm)

    chain_state.commit_state_to_db("head-hash", 20)
    # Clobber: simulate a restart with a fresh manager.
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])

    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager

    # Scheduled entry restored...
    assert any(uid == update.update_id for _, uid in reloaded.scheduled_updates)
    # ...and, crucially, its PAYLOAD is restored (the fix).
    assert update.update_id in reloaded.update_payloads, (
        "scheduled update payload was NOT restored — activation would silently no-op"
    )
    restored = reloaded.update_payloads[update.update_id]
    assert restored.rule_revisions == [REV]
    assert restored.host_contract_patch == PATCH
    # Meta-hash integrity: a scheduled uid must NOT leak into the pending set.
    assert update.update_id not in reloaded.pending_updates


def test_scheduled_update_activates_after_reload(temp_database):
    """The end-to-end point of the fix: a node that restarts while an update is
    scheduled still activates it (applies the host_contract_patch) at H."""
    lm = ConsensusLifecycleManager(active_validators=VALIDATORS)
    _seed_state(lm)
    update = _schedule_update(lm)

    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager
    assert reloaded.eligibility_mode != "stake"  # not yet active

    newly_active = reloaded.process_height_transitions(ACTIVATE_AT)

    assert [u.update_id for u in newly_active] == [update.update_id]
    # The scheduled patch actually applied post-restart.
    assert reloaded.eligibility_mode == "stake"


def test_scheduled_payload_persistence_preserves_meta_hash(temp_database):
    """Persisting scheduled payloads is node-local durability only — the
    consensus meta hash (and thus the state hash) must be byte-identical before
    commit and after reload."""
    lm = ConsensusLifecycleManager(active_validators=VALIDATORS)
    _seed_state(lm)
    _schedule_update(lm)
    meta_before = lm.consensus_meta_hash()

    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True

    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta_before


def test_full_lifecycle_field_set_roundtrips(temp_database):
    """Phase 9D: the governance-mutable triple + scheduled state all survive a
    commit_state_to_db -> reload cycle together."""
    lm = ConsensusLifecycleManager(active_validators=VALIDATORS)
    _seed_state(lm)
    lm.quorum_policy = "count:2"
    lm.eligibility_mode = "stake"
    lm.recompute_approval_threshold()
    update = _schedule_update(lm)

    chain_state.commit_state_to_db("head-hash", 21)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    r = chain_state._lifecycle_manager

    assert r.active_validators == set(VALIDATORS)
    assert r.quorum_policy == "count:2"
    assert r.eligibility_mode == "stake"
    assert r.approval_threshold == 2  # min(2, 3)
    assert any(uid == update.update_id for _, uid in r.scheduled_updates)
    assert update.update_id in r.update_payloads
