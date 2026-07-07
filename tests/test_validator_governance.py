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


def test_derive_active_consensus_reads_consensus_rules_from_metadata_not_tau_bytes():
    """Regression: consensus_rules must come from the snapshot's
    consensus_rules_state metadata, NOT tau_bytes (the application accumulation).

    Mislabeling tau_bytes as consensus_rules made every non-governance block write
    the application spec into _consensus_rules_state; on restart the restore fed
    that multi-statement blob via i0 and the engine rejected it
    ("(Error) Unexpected 'a'"), so o6/o7 were undefined and synced blocks failed.
    """
    APP_BLOB = (
        "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1) "
        "always ( o2[t]:bv[24] = i1[t]:bv[24] )."
    )
    CONS = "always ( o6[t]:bv[64] = i10[t]:bv[64] && o7[t]:bv[64] = { 1 }:bv[64] )."
    snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=APP_BLOB.encode("utf-8"),
        metadata={
            "lifecycle_manager": ConsensusLifecycleManager(active_validators=["a" * 96]),
            "consensus_rules_state": CONS,
        },
    )

    view = TauConsensusEngine().derive_active_consensus(snapshot, 5)

    assert view.consensus_rules == CONS
    assert "u[t]" not in view.consensus_rules  # application spec must not leak in
    # Absent metadata -> empty (never the application tau_bytes).
    bare = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=APP_BLOB.encode("utf-8"),
        metadata={"lifecycle_manager": ConsensusLifecycleManager(active_validators=["a" * 96])},
    )
    assert TauConsensusEngine().derive_active_consensus(bare, 5).consensus_rules == ""


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


def test_quorum_policy_persists_and_reloads(temp_database):
    # Issue #18: a governance-activated quorum policy survives a reload rather
    # than reverting to the genesis value.
    validators = ["a" * 96, "b" * 96, "c" * 96]  # n=3
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm = ConsensusLifecycleManager(active_validators=validators)
    lm.quorum_policy = "count:2"
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm

    chain_state.commit_state_to_db("head-hash", 11)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])

    assert chain_state.load_state_from_db() is True
    reloaded = chain_state._lifecycle_manager
    assert reloaded.quorum_policy == "count:2"
    assert reloaded.approval_threshold == 2  # min(2, 3)


def test_legacy_db_without_quorum_key_falls_back_to_genesis(temp_database, monkeypatch):
    # A DB written before quorum was persisted has no 'quorum_policy' row; the
    # loader must fall back to the genesis-pinned value.
    import db
    validators = ["a" * 96, "b" * 96, "c" * 96]
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=validators)
    chain_state.commit_state_to_db("head-hash", 3)

    # Simulate a legacy DB: drop the persisted quorum row.
    with db._db_lock:
        db._db_conn.execute("DELETE FROM chain_state WHERE key = 'quorum_policy'")
        db._db_conn.commit()

    monkeypatch.setattr(chain_state, "_genesis_vote_quorum", "majority")
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    assert chain_state._lifecycle_manager.quorum_policy == "majority"


def test_eligibility_mode_persists_and_reloads(temp_database):
    # A governance-activated eligibility mode survives a reload rather than
    # reverting to the genesis value (mirrors quorum_policy).
    validators = ["a" * 96, "b" * 96, "c" * 96]
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm = ConsensusLifecycleManager(active_validators=validators)
    lm.eligibility_mode = "stake"
    chain_state._lifecycle_manager = lm

    chain_state.commit_state_to_db("head-hash", 11)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])

    assert chain_state.load_state_from_db() is True
    assert chain_state._lifecycle_manager.eligibility_mode == "stake"


def test_legacy_db_without_eligibility_mode_falls_back_to_genesis(temp_database, monkeypatch):
    # A DB written before eligibility_mode was persisted has no
    # 'eligibility_mode' row; the loader must fall back to the genesis value.
    import db
    validators = ["a" * 96, "b" * 96, "c" * 96]
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=validators)
    chain_state.commit_state_to_db("head-hash", 3)

    # Simulate a legacy DB: drop the persisted eligibility_mode row.
    with db._db_lock:
        db._db_conn.execute("DELETE FROM chain_state WHERE key = 'eligibility_mode'")
        db._db_conn.commit()

    monkeypatch.setattr(chain_state, "_genesis_eligibility_mode", "stake")
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    assert chain_state._lifecycle_manager.eligibility_mode == "stake"
