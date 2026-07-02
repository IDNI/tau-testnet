import unittest

from consensus.governance import (
    ConsensusRuleUpdate,
    ConsensusRuleVote,
    ConsensusLifecycleManager,
    parse_consensus_rule_update,
    parse_consensus_rule_vote,
    normalize_validator_set,
)

import config

class TestGovernance(unittest.TestCase):
    def setUp(self):
        self.active_validators = [bytes.fromhex(f"{i:096x}") for i in range(1, 4)] # 3 validators
        
    def test_parse_update(self):
        tx = {
            "tx_type": "consensus_rule_update",
            "sender_pubkey": f"{1:096x}",
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
        self.assertEqual(update.proposer_pubkey, f"{1:096x}")
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

    def test_validator_delta_applies_on_activation(self):
        manager = ConsensusLifecycleManager(active_validators=self.active_validators)
        new_validator = f"{4:096x}"
        update = ConsensusRuleUpdate(
            ["test"],
            10,
            {"validator_additions": [new_validator, new_validator]},
        )
        manager.submit_update(update)
        vote = ConsensusRuleVote(update.update_id, True)
        manager.submit_vote(vote, f"{1:096x}")
        manager.submit_vote(vote, f"{2:096x}")

        active = manager.process_height_transitions(10)

        self.assertEqual(len(active), 1)
        self.assertIn(new_validator, manager.active_validators)
        self.assertEqual(manager.approval_threshold, 3)

    def test_below_quorum_does_not_activate(self):
        manager = ConsensusLifecycleManager(active_validators=self.active_validators)
        update = ConsensusRuleUpdate(["test"], 10)
        manager.submit_update(update)
        vote = ConsensusRuleVote(update.update_id, True)
        manager.submit_vote(vote, self.active_validators[0])  # 1 of threshold 2

        active = manager.process_height_transitions(10)

        self.assertEqual(active, [])
        self.assertNotIn(update.update_id, manager.pending_updates)
        self.assertIn(update.update_id, manager.archival_updates)
        self.assertEqual(manager.active_validators, {f"{i:096x}" for i in range(1, 4)})

    def test_non_validator_vote_does_not_count(self):
        manager = ConsensusLifecycleManager(active_validators=self.active_validators)
        update = ConsensusRuleUpdate(["test"], 10)
        manager.submit_update(update)
        vote = ConsensusRuleVote(update.update_id, True)

        outsider = bytes.fromhex(f"{99:096x}")
        self.assertFalse(manager.submit_vote(vote, outsider))
        self.assertEqual(len(manager.votes.get(update.update_id, set())), 0)

        # A real validator vote still counts; update stays pending at 1/2.
        self.assertTrue(manager.submit_vote(vote, self.active_validators[0]))
        self.assertIn(update.update_id, manager.pending_updates)

    def test_garbage_voter_pubkey_is_noop(self):
        manager = ConsensusLifecycleManager(active_validators=self.active_validators)
        update = ConsensusRuleUpdate(["test"], 10)
        manager.submit_update(update)
        vote = ConsensusRuleVote(update.update_id, True)
        self.assertFalse(manager.submit_vote(vote, "not-a-pubkey"))
        self.assertEqual(len(manager.votes.get(update.update_id, set())), 0)

    def test_removal_reaches_quorum_and_activates(self):
        manager = ConsensusLifecycleManager(active_validators=self.active_validators)
        removed = f"{3:096x}"
        update = ConsensusRuleUpdate(["test"], 10, {"validator_removals": [removed]})
        manager.submit_update(update)
        vote = ConsensusRuleVote(update.update_id, True)
        manager.submit_vote(vote, self.active_validators[0])
        manager.submit_vote(vote, self.active_validators[1])

        active = manager.process_height_transitions(10)

        self.assertEqual(len(active), 1)
        self.assertNotIn(removed, manager.active_validators)
        self.assertEqual(manager.approval_threshold, 2)  # recomputed for n=2

    def test_majority_quorum_policy(self):
        validators = [bytes.fromhex(f"{i:096x}") for i in range(1, 6)]  # n=5
        manager = ConsensusLifecycleManager(active_validators=validators)
        manager.quorum_policy = "majority"
        self.assertEqual(manager.recompute_approval_threshold(), 3)
        manager.quorum_policy = "supermajority"
        self.assertEqual(manager.recompute_approval_threshold(), 4)

    def test_validator_delta_rejects_empty_validator_set(self):
        only_validator = f"{1:096x}"
        manager = ConsensusLifecycleManager(active_validators=[only_validator])
        update = ConsensusRuleUpdate(
            ["test"],
            10,
            {"validator_removals": [only_validator]},
        )
        manager.submit_update(update)
        vote = ConsensusRuleVote(update.update_id, True)
        manager.submit_vote(vote, only_validator)

        with self.assertRaises(ValueError):
            manager.process_height_transitions(10)


class TestQuorumGrammar(unittest.TestCase):
    """Issue #18: quorum policy grammar and threshold derivation."""

    def test_validate_quorum_policy(self):
        from consensus.governance import validate_quorum_policy
        for good in ("majority", "supermajority", "count:1", "count:10", "count:999999999"):
            self.assertIsNone(validate_quorum_policy(good), good)
        for bad in ("count:0", "count:010", "count:+5", "count: 5", "count:", "10",
                    "", "COUNT:5", "count:1000000000", 5, None, True, ["count:5"]):
            self.assertIsNotNone(validate_quorum_policy(bad), repr(bad))

    def test_quorum_count(self):
        from consensus.governance import quorum_count
        self.assertEqual(quorum_count("count:7"), 7)
        self.assertIsNone(quorum_count("majority"))
        self.assertIsNone(quorum_count("count:0"))
        self.assertIsNone(quorum_count(7))

    def test_count_threshold_and_clamp(self):
        validators = [bytes.fromhex(f"{i:096x}") for i in range(1, 6)]  # n=5
        manager = ConsensusLifecycleManager(active_validators=validators)
        manager.quorum_policy = "count:3"
        self.assertEqual(manager.recompute_approval_threshold(), 3)
        manager.quorum_policy = "count:1"
        self.assertEqual(manager.recompute_approval_threshold(), 1)
        # count exceeding the set clamps down to unanimity (never freezes gov).
        manager.quorum_policy = "count:10"
        self.assertEqual(manager.recompute_approval_threshold(), 5)

    def test_count_clamp_releases_when_set_grows(self):
        validators = [bytes.fromhex(f"{i:096x}") for i in range(1, 4)]  # n=3
        manager = ConsensusLifecycleManager(active_validators=validators)
        manager.quorum_policy = "count:10"
        self.assertEqual(manager.recompute_approval_threshold(), 3)  # clamped
        # Grow the set to 10; the stored policy string is untouched, so the full
        # count is now reachable.
        manager.active_validators = normalize_validator_set(
            [bytes.fromhex(f"{i:096x}") for i in range(1, 11)]
        )
        self.assertEqual(manager.recompute_approval_threshold(), 10)


class TestQuorumGovernance(unittest.TestCase):
    """Issue #18: quorum policy changed through an activated host_contract_patch."""

    def setUp(self):
        self.v3 = [bytes.fromhex(f"{i:096x}") for i in range(1, 4)]  # n=3

    def _pass(self, manager, update, voters):
        manager.submit_update(update)
        vote = ConsensusRuleVote(update.update_id, True)
        for v in voters:
            manager.submit_vote(vote, v)

    def test_activation_changes_quorum_and_next_proposal_threshold(self):
        manager = ConsensusLifecycleManager(active_validators=self.v3)
        self.assertEqual(manager.approval_threshold, 2)  # supermajority of 3

        # Proposal raising the bar to a fixed 3 votes; 2 votes pass under the
        # OLD threshold, so it schedules and activates at height 10.
        up = ConsensusRuleUpdate(["r"], 10, {"vote_quorum": "count:3"})
        self._pass(manager, up, self.v3[:2])
        active = manager.process_height_transitions(10)
        self.assertEqual(len(active), 1)
        self.assertEqual(manager.quorum_policy, "count:3")
        self.assertEqual(manager.approval_threshold, 3)

        # A subsequent proposal now needs all 3 votes.
        up2 = ConsensusRuleUpdate(["r2"], 20)
        manager.submit_update(up2)
        v2 = ConsensusRuleVote(up2.update_id, True)
        manager.submit_vote(v2, self.v3[0])
        manager.submit_vote(v2, self.v3[1])
        self.assertIn(up2.update_id, manager.pending_updates)  # 2/3, still pending
        manager.submit_vote(v2, self.v3[2])
        self.assertNotIn(up2.update_id, manager.pending_updates)  # 3/3, scheduled

    def test_combined_validator_and_quorum_patch(self):
        manager = ConsensusLifecycleManager(active_validators=self.v3)
        new_v = f"{4:096x}"
        up = ConsensusRuleUpdate(
            ["r"], 10,
            {"validator_additions": [new_v], "vote_quorum": "count:4"},
        )
        self._pass(manager, up, self.v3[:2])
        manager.process_height_transitions(10)
        # Post-delta set is 4 validators; count:4 is reachable -> threshold 4.
        self.assertIn(new_v, manager.active_validators)
        self.assertEqual(manager.quorum_policy, "count:4")
        self.assertEqual(manager.approval_threshold, 4)

    def test_pending_proposal_not_auto_promoted_at_activation(self):
        validators = [bytes.fromhex(f"{i:096x}") for i in range(1, 6)]  # n=5
        manager = ConsensusLifecycleManager(active_validators=validators)
        self.assertEqual(manager.approval_threshold, 4)  # supermajority of 5

        # A quorum-LOWERING proposal (to majority=3), scheduled to activate at 10.
        lower = ConsensusRuleUpdate(["r"], 10, {"vote_quorum": "majority"})
        self._pass(manager, lower, validators[:4])  # 4 votes meet old threshold

        # A plain proposal sitting at 3 votes: below the old threshold 4.
        pend = ConsensusRuleUpdate(["r2"], 50)
        manager.submit_update(pend)
        vote = ConsensusRuleVote(pend.update_id, True)
        for v in validators[:3]:
            manager.submit_vote(vote, v)
        self.assertIn(pend.update_id, manager.pending_updates)

        # Activate the lowering patch: threshold drops to 3, which `pend` already
        # meets — but it is NOT auto-promoted at the activation boundary.
        manager.process_height_transitions(10)
        self.assertEqual(manager.approval_threshold, 3)
        self.assertIn(pend.update_id, manager.pending_updates)

        # It promotes only when the next vote arrives.
        manager.submit_vote(vote, validators[3])
        self.assertNotIn(pend.update_id, manager.pending_updates)

    def test_meta_hash_changes_with_quorum_policy(self):
        manager = ConsensusLifecycleManager(active_validators=self.v3)
        h_before = manager.consensus_meta_hash()
        manager.apply_host_contract_patch({"vote_quorum": "count:3"})
        h_after = manager.consensus_meta_hash()
        self.assertNotEqual(h_before, h_after)

    def test_apply_patch_rejects_malformed_quorum(self):
        manager = ConsensusLifecycleManager(active_validators=self.v3)
        with self.assertRaises(ValueError):
            manager.apply_host_contract_patch({"vote_quorum": "count:0"})


if __name__ == '__main__':
    unittest.main()
