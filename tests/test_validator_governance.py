import config
import chain_state
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot


def test_tick_governance_does_not_clobber_active_validators(monkeypatch):
    chain_validator = "a" * 96
    local_validator = "b" * 96
    monkeypatch.setattr(config, "MINER_PUBKEYS", [local_validator], raising=False)
    monkeypatch.setattr(config, "MINER_PUBKEY", local_validator, raising=False)
    monkeypatch.setattr(
        chain_state,
        "_lifecycle_manager",
        ConsensusLifecycleManager(active_validators=[chain_validator]),
    )

    chain_state.tick_governance(1)

    assert chain_state._lifecycle_manager.active_validators == {chain_validator}


def test_engine_derives_active_validators_from_lifecycle_snapshot(monkeypatch):
    chain_validator = "c" * 96
    local_validator = "d" * 96
    monkeypatch.setattr(config, "MINER_PUBKEYS", [local_validator], raising=False)
    snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always.",
        metadata={
            "lifecycle_manager": ConsensusLifecycleManager(active_validators=[chain_validator]),
        },
    )

    view = TauConsensusEngine().derive_active_consensus(snapshot, 10)

    assert view.active_validators == [bytes.fromhex(chain_validator)]


def test_active_validators_persist_and_reload(temp_database):
    validators = ["a" * 96, "b" * 96]
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances["account"] = 1
    chain_state._sequence_numbers["account"] = 0
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = "active"
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=validators)

    chain_state.commit_state_to_db("head-hash", 7)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["c" * 96])

    assert chain_state.load_state_from_db() is True
    assert chain_state._lifecycle_manager.active_validators == set(validators)
    assert chain_state._lifecycle_manager.approval_threshold == 2


def test_below_quorum_votes_persist_and_reload(temp_database):
    from consensus.governance import ConsensusRuleUpdate, ConsensusRuleVote

    validators = ["a" * 96, "b" * 96, "c" * 96]  # threshold 2
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm = ConsensusLifecycleManager(active_validators=validators)
    chain_state._lifecycle_manager = lm

    update = ConsensusRuleUpdate(["always ( o6[t]:bv[16] = { 0 }:bv[16] )."], 50)
    assert lm.submit_update(update)
    assert lm.submit_vote(ConsensusRuleVote(update.update_id, True), validators[0])
    assert update.update_id in lm.pending_updates  # 1 of 2: still pending

    chain_state.commit_state_to_db("head-hash", 9)
    chain_state._lifecycle_manager = ConsensusLifecycleManager()

    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager
    assert update.update_id in reloaded.pending_updates
    votes = reloaded.votes.get(update.update_id, set())
    assert len(votes) == 1
    # Reloaded voters are hex strings.
    assert validators[0] in {v if isinstance(v, str) else v.hex() for v in votes}
