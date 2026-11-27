"""The shared-rule counters across a reorg, a restart and a full rebuild.

Mock engine, replayed without Tau (see test_reorg_deep_chain.py): what is under
test is that every route to a head reaches the same limits and counters.
"""
import chain_state
import db
from bls_keys import pubkey_hex, sign_payload
from test_reorg_deep_chain import quiet
from test_retractable_reorg import RetractableReorgTestCase

SK = 7373
SENDER = pubkey_hex(SK)


def rule_tx(seq, stream):
    return sign_payload({
        "tx_type": "user_tx", "sender_pubkey": SENDER, "sequence_number": seq,
        "expiration_time": 9999999999, "expire_at_height": 5000, "fee_limit": "0",
        "operations": {"0": f"always ( o{stream}[t]:bv[24] = i1[t]:bv[24] )."},
    }, SK)


def usage():
    lm = chain_state._lifecycle_manager
    return (lm.shared_rule_count, lm.shared_rule_nodes)


def stored():
    return tuple(
        db.get_chain_state_value(key, "")
        for key in ("shared_rule_count", "shared_rule_nodes", "shared_rule_limits")
    )


class TestSharedRuleCountersAcrossReorgs(RetractableReorgTestCase):
    def build(self):
        common = self.blocks(self.genesis_hash, [(1, [rule_tx(0, 12)])])
        fork_a = self.blocks(common[-1], [
            (2, [rule_tx(1, 13), rule_tx(2, 12)]), (3, []),
        ])
        fork_b = self.blocks(common[-1], [(2, []), (3, []), (4, [])])
        return common, fork_a, fork_b

    def test_a_branch_counts_every_occurrence_and_persists_them(self):
        common, fork_a, _ = self.build()
        self.adopt(common + fork_a)
        self.assertEqual(usage(), (3, 9))
        self.assertEqual(stored()[:2], ("3", "9"))

    def test_the_winner_restores_the_fork_point_counters(self):
        common, fork_a, fork_b = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        self.assertEqual(usage(), (1, 3))
        self.assertEqual(stored()[:2], ("1", "3"))

    def test_restart_equals_a_node_that_followed_the_winner(self):
        common, fork_a, fork_b = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        after = (usage(), stored(), self.state()["meta"])

        self.restart()
        self.assertEqual((usage(), stored(), self.state()["meta"]), after)

        self.fresh_node()
        self.adopt(common + fork_b)
        self.assertEqual((usage(), stored(), self.state()["meta"]), after)

    def test_a_full_rebuild_reaches_the_counters_the_head_was_built_with(self):
        common, fork_a, _ = self.build()
        self.adopt(common + fork_a)
        before = (usage(), stored(), self.state()["meta"])

        with quiet():
            chain_state.rebuild_state_from_blockchain()

        self.assertEqual((usage(), stored(), self.state()["meta"]), before)
