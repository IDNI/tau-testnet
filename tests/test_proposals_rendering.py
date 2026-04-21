import pytest
import json
from dataclasses import dataclass

from consensus.governance import ConsensusRuleUpdate, ConsensusLifecycleManager

class MockChainState:
    def __init__(self):
        self._balance_lock = self.DummyLock()
        self._sequence_lock = self.DummyLock()
        self._rules_lock = self.DummyLock()
        
        self._active_consensus_id = None
        self._consensus_rules_state = "rules"
        self._application_rules_state = "apps"
        
        self._lifecycle_manager = ConsensusLifecycleManager(
            active_validators=[b"v1", b"v2", b"v3"]
        )

    class DummyLock:
        def __enter__(self): pass
        def __exit__(self, exc_type, exc_val, exc_tb): pass

class MockDB:
    def get_canonical_head_block(self):
        return {
            "block_hash": "abc",
            "header": {"block_number": 100}
        }

class MockContainer:
    def __init__(self):
        self.chain_state = MockChainState()
        self.db = MockDB()

from commands.getgovernance import execute as getgov_execute

def test_getgovernance_includes_approval_threshold():
    container = MockContainer()
    resp_raw = getgov_execute("getgovernance", container)
    resp = json.loads(resp_raw)
    
    assert "approval_threshold" in resp
    assert resp["approval_threshold"] == 2 # (3 // 2) + 1

def test_pending_updates_include_revisions_and_patch():
    container = MockContainer()
    
    # Add a pending update
    update = ConsensusRuleUpdate(
        rule_revisions=["rule 1", "rule 2"],
        activate_at_height=500,
        host_contract_patch={"proof_scheme": "bls_header_sig"}
    )
    container.chain_state._lifecycle_manager.submit_update(update)
    
    resp_raw = getgov_execute("getgovernance", container)
    resp = json.loads(resp_raw)
    
    assert len(resp["pending_updates"]) == 1
    pu = resp["pending_updates"][0]
    
    assert pu["update_id"] == update.update_id_hex
    assert pu["activate_at_height"] == 500
    assert pu["rule_revisions"] == ["rule 1", "rule 2"]
    assert pu["host_contract_patch"] == {"proof_scheme": "bls_header_sig"}

def test_lifecycle_status_explicit():
    container = MockContainer()
    
    update1 = ConsensusRuleUpdate(["pending rule"], 500)
    update2 = ConsensusRuleUpdate(["scheduled rule"], 500)
    
    mgr = container.chain_state._lifecycle_manager
    mgr.submit_update(update1)
    mgr.submit_update(update2)
    
    # promote update2 to scheduled
    mgr.pending_updates.remove(update2.update_id)
    mgr.scheduled_updates.append((500, update2.update_id))
    
    resp_raw = getgov_execute("getgovernance", container)
    resp = json.loads(resp_raw)
    
    assert resp["lifecycle"][update1.update_id_hex] == "pending"
    assert resp["lifecycle"][update2.update_id_hex] == "approved-and-scheduled"

def test_only_pending_in_pending_updates():
    container = MockContainer()
    
    update1 = ConsensusRuleUpdate(["pending"], 500)
    update2 = ConsensusRuleUpdate(["scheduled"], 500)
    update3 = ConsensusRuleUpdate(["archival"], 500)
    
    mgr = container.chain_state._lifecycle_manager
    mgr.submit_update(update1)
    
    mgr.update_payloads[update2.update_id] = update2
    mgr.scheduled_updates.append((500, update2.update_id))
    
    mgr.update_payloads[update3.update_id] = update3
    mgr.archival_updates.add(update3.update_id)
    
    resp_raw = getgov_execute("getgovernance", container)
    resp = json.loads(resp_raw)
    
    assert len(resp["pending_updates"]) == 1
    assert resp["pending_updates"][0]["update_id"] == update1.update_id_hex

def test_votes_only_counted_for_pending():
    container = MockContainer()
    
    update1 = ConsensusRuleUpdate(["pending"], 500)
    mgr = container.chain_state._lifecycle_manager
    mgr.submit_update(update1)
    
    from consensus.governance import ConsensusRuleVote
    v1 = ConsensusRuleVote(update1.update_id, True)
    mgr.submit_vote(v1, b"v1")
    mgr.submit_vote(v1, b"v2")
    
    resp_raw = getgov_execute("getgovernance", container)
    resp = json.loads(resp_raw)
    
    assert len(resp["votes"]) == 2
    for v in resp["votes"]:
        assert v["update_id"] == update1.update_id_hex
        assert v["voter_pubkey"] in ["7631", "7632"] # b'v1'.hex() is 7631

