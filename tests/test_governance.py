import unittest

from consensus.governance import (
    ConsensusRuleUpdate,
    ConsensusRuleVote,
    ConsensusLifecycleManager,
    parse_consensus_rule_update,
    parse_consensus_rule_vote
)

import config

class TestGovernance(unittest.TestCase):
    def setUp(self):
        self.active_validators = [bytes.fromhex(f"{i:096x}") for i in range(1, 4)] # 3 validators
        
    def test_parse_update(self):
        tx = {
            "tx_type": "consensus_rule_update",
            "payload": {
                "rule_revisions": ["always o5 = 1"],
                "activate_at_height": 100,
                "host_contract_patch": {"fee": 10}
            }
        }
        update = parse_consensus_rule_update(tx)
        self.assertIsNotNone(update)
        self.assertEqual(update.rule_revisions, ["always o5 = 1"])
        self.assertEqual(update.activate_at_height, 100)
        self.assertEqual(update.host_contract_patch, {"fee": 10})
        self.assertEqual(len(update.update_id), 32)
        
    def test_parse_vote(self):
        update = ConsensusRuleUpdate(["test"], 10)
        tx = {
            "tx_type": "consensus_rule_vote",
            "payload": {
                "update_id": update.update_id.hex(),
                "approve": True
            }
        }
        vote = parse_consensus_rule_vote(tx)
        self.assertIsNotNone(vote)
        self.assertEqual(vote.update_id, update.update_id)
        self.assertTrue(vote.approve)
        
    def test_lifecycle_promotion(self):
        manager = ConsensusLifecycleManager(active_validators=self.active_validators)
        update = ConsensusRuleUpdate(["test"], 10)
        
        # 1. Admit Update
        self.assertTrue(manager.can_admit_update(update))
        self.assertTrue(manager.submit_update(update))
        self.assertIn(update.update_id, manager.pending_updates)
        
        # 2. Votes
        vote = ConsensusRuleVote(update.update_id, True)
        
        self.assertTrue(manager.can_admit_vote(vote, self.active_validators[0]))
        self.assertTrue(manager.submit_vote(vote, self.active_validators[0]))
        self.assertIn(update.update_id, manager.pending_updates) # still pending (1/3 votes)
        
        self.assertFalse(manager.submit_vote(vote, self.active_validators[0])) # Duplicate vote drops
        
        # 2nd vote (reaches threshold 2/3)
        self.assertTrue(manager.submit_vote(vote, self.active_validators[1]))
        
        # Should be scheduled now
        self.assertNotIn(update.update_id, manager.pending_updates)
        self.assertEqual(len(manager.scheduled_updates), 1)
        self.assertEqual(manager.scheduled_updates[0], (10, update.update_id))
        
        # 3. Post-approval vote is invalid/no-op
        self.assertFalse(manager.submit_vote(vote, self.active_validators[2]))
        
        # 4. Height transition (activation)
        active = manager.process_height_transitions(10)
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].update_id, update.update_id)
        self.assertEqual(len(manager.scheduled_updates), 0)
        self.assertIn(update.update_id, manager.archival_updates)
        
    def test_lifecycle_expiry(self):
        manager = ConsensusLifecycleManager(active_validators=self.active_validators)
        update = ConsensusRuleUpdate(["test"], 10)
        manager.submit_update(update)
        
        # Misses activation
        active = manager.process_height_transitions(11)
        self.assertEqual(len(active), 0)
        self.assertNotIn(update.update_id, manager.pending_updates)
        self.assertIn(update.update_id, manager.archival_updates)

if __name__ == '__main__':
    unittest.main()
