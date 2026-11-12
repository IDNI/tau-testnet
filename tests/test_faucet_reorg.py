"""The faucet grants across a reorg and a restart.

A grant is a consequence of the canonical blocks. A grant on a branch that
loses must disappear, and the winner must get its own grants again.
"""
import chain_state
from bls_keys import pubkey_hex
from test_reorg_deep_chain import FUNDED_ACCOUNT, _tx
from test_retractable_reorg import RetractableReorgTestCase

GRANT = 100000
AMOUNT = 40
ON_LOSER = pubkey_hex(0x1111)
ON_WINNER = pubkey_hex(0x2222)


def pay(to):
    return _tx(FUNDED_ACCOUNT, 0, [[FUNDED_ACCOUNT, to, str(AMOUNT)]])


class TestFaucetGrantsAfterAReorg(RetractableReorgTestCase):
    def setUp(self):
        super().setUp()
        self.addCleanup(self.set_faucet, chain_state._genesis_faucet_amount)
        self.set_faucet()

    @staticmethod
    def set_faucet(amount=GRANT):
        chain_state._genesis_faucet_amount = amount
        chain_state._lifecycle_manager.faucet_amount = amount

    def fresh_node(self):
        super().fresh_node()
        self.set_faucet()

    def build(self):
        common = self.blocks(self.genesis_hash, [(1, [])])
        fork_a = self.blocks(common[-1], [(2, [pay(ON_LOSER)]), (3, [])])
        fork_b = self.blocks(common[-1], [(2, [pay(ON_WINNER)]), (3, []), (4, [])])
        return common, fork_a, fork_b

    def test_the_winner_derives_its_own_grants(self):
        common, fork_a, fork_b = self.build()
        self.adopt(common + fork_a)
        before = self.state()
        self.assertEqual(before["balances"][ON_LOSER], GRANT + AMOUNT)
        self.assertNotIn(ON_WINNER, before["balances"])

        self.reorg_to(fork_b)

        after = self.state()
        self.assertEqual(after["balances"][ON_WINNER], GRANT + AMOUNT)
        self.assertNotIn(ON_LOSER, chain_state._balances)
        self.assertNotIn(ON_LOSER, chain_state._sequence_numbers)
        self.assertEqual(chain_state.get_balance(ON_LOSER), GRANT)
        self.assertEqual(after["balances"][FUNDED_ACCOUNT],
                         chain_state.GENESIS_BALANCE - AMOUNT)

    def test_restart_equals_a_node_that_followed_the_winner(self):
        common, fork_a, fork_b = self.build()
        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        after = self.state()

        self.restart()
        self.assertEqual(self.state(), after)

        self.fresh_node()
        self.adopt(common + fork_b)
        self.assertEqual(self.state(), after)
