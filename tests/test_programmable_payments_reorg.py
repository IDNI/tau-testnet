"""Programmable payments across reorgs and restarts.

A grant, a draw, a receive route and the credits it splits are consequences of
which blocks are canonical. These tests put them on a branch that then loses
(or wins) and require the result to equal what a node that only ever followed
the winner holds: balances, sequences, every book root and the meta hash, in
memory, after a restart, and on a fresh node replaying the winner.

Same harness and mock engine as tests/test_retractable_reorg.py.
"""
from bls_keys import pubkey_hex, sign_payload
from chain_ids import TEST_CHAIN_ID
from consensus.grants import parse_grant_create
from test_reorg_deep_chain import ADDR2, BASE_TS
from test_retractable_reorg import FUNDED, SENDER, RetractableReorgTestCase, funding

SK_GRANTEE = 5151
GRANTEE = pubkey_hex(SK_GRANTEE)
SK_PAYER = 4242  # SENDER in the shared harness


def _env(tx_type, sender, seq, **fields):
    tx = {"tx_type": tx_type, "sender_pubkey": sender, "sequence_number": seq,
          "expiration_time": 9_999_999_999, "expire_at_height": 40, "fee_limit": "0",
          "chain_id": TEST_CHAIN_ID}
    tx.update(fields)
    return tx


def grant_create(seq=0):
    return sign_payload(_env("grant_create", SENDER, seq, grantee_pubkey=GRANTEE, amount=300,
                             start_at=0, expires_at=BASE_TS + 100_000, spend_cap=0,
                             cap_period_kind=2, cap_period_seconds=0, per_payment_cap=0,
                             weekday_mask=0x7F, hour_mask=0xFFFFFF, revocable=False,
                             refund_to_pubkey=SENDER), SK_PAYER)


def grant_draw(gid, amount, seq=0):
    return sign_payload(_env("grant_draw", GRANTEE, seq, grant_id=gid,
                             recipient_pubkey=ADDR2, amount=amount), SK_GRANTEE)


def route_set(seq):
    return sign_payload(_env("receive_route_set", SENDER, seq, destination_pubkey=GRANTEE,
                             bps=5000, min_incoming=0, activate_at=0, expires_at=0,
                             locked_until=0), SK_PAYER)


class ProgrammableReorgTestCase(RetractableReorgTestCase):
    @staticmethod
    def state():
        import chain_state

        lm = chain_state._lifecycle_manager
        return {
            "balances": {k: v for k, v in chain_state._balances.items() if v},
            "sequences": {k: v for k, v in chain_state._sequence_numbers.items() if v},
            "grants": lm.grants.root(),
            "grant_escrow": lm.grants.escrow_total(),
            "routes": lm.receive_routes.root(),
            "standing": lm.standing_payments.root(),
            "payouts": lm.payout_rules.root(),
            "meta": lm.consensus_meta_hash(),
        }

    def check_equals_follower_of(self, common, winner):
        after = self.state()
        self.restart()
        self.assertEqual(self.state(), after, "restart must reproduce the state")
        self.fresh_node()
        self.adopt(common + winner)
        self.assertEqual(self.state(), after, "a fresh node replaying the winner must agree")
        return after


class TestGrantOnADiscardedBranch(ProgrammableReorgTestCase):
    def test_grant_and_draw_vanish_and_the_payer_is_whole(self):
        common = self.blocks(self.genesis_hash, [(1, [funding()])])
        create = grant_create()
        gid = parse_grant_create(create).grant_id.hex()
        fork_a = self.blocks(common[-1], [(2, [create]), (3, [grant_draw(gid, 120)])])
        fork_b = self.blocks(common[-1], [(2, []), (3, []), (4, [])])

        self.adopt(common + fork_a)
        before = self.state()
        self.assertEqual(before["grant_escrow"], 180)
        self.assertEqual(before["balances"][ADDR2], 120)
        self.assertEqual(before["balances"][SENDER], FUNDED - 300)

        self.reorg_to(fork_b)
        after = self.check_equals_follower_of(common, fork_b)
        self.assertEqual(after["grant_escrow"], 0)
        self.assertEqual(after["balances"][SENDER], FUNDED)
        self.assertNotIn(ADDR2, after["balances"])


class TestGrantOnTheWinningBranch(ProgrammableReorgTestCase):
    def test_the_winner_keeps_its_grant_state(self):
        common = self.blocks(self.genesis_hash, [(1, [funding()])])
        create = grant_create()
        gid = parse_grant_create(create).grant_id.hex()
        fork_a = self.blocks(common[-1], [(2, [])])
        fork_b = self.blocks(common[-1], [(2, [create]), (3, [grant_draw(gid, 50)])])

        self.adopt(common + fork_a)
        self.reorg_to(fork_b)
        after = self.check_equals_follower_of(common, fork_b)
        self.assertEqual(after["grant_escrow"], 250)
        self.assertEqual(after["balances"][ADDR2], 50)


class TestRouteOnADiscardedBranch(ProgrammableReorgTestCase):
    def test_a_discarded_route_splits_nothing_on_the_winner(self):
        from test_reorg_deep_chain import FUNDED_ACCOUNT, _tx

        common = self.blocks(self.genesis_hash, [(1, [funding()])])
        credit = _tx(FUNDED_ACCOUNT, 1, [[FUNDED_ACCOUNT, SENDER, "100"]])
        fork_a = self.blocks(common[-1], [(2, [route_set(0)]), (3, [credit])])
        fork_b = self.blocks(common[-1], [(2, []), (3, [credit]), (4, [])])

        self.adopt(common + fork_a)
        self.assertEqual(self.state()["balances"][GRANTEE], 50)

        self.reorg_to(fork_b)
        after = self.check_equals_follower_of(common, fork_b)
        self.assertNotIn(GRANTEE, after["balances"])
        self.assertEqual(after["balances"][SENDER], FUNDED + 100)
