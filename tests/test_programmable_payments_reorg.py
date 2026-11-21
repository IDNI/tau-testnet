"""Reorg tests for Bounty 01 programmable payments (Step 3).

Mirrors #128's tests/test_programmable_payments_reorg.py in intent, not
code: a grant+draw, a receive route, a standing payment and a payout
execute each live on the losing branch and on the winning branch. After
the reorg only the winner's effects remain, and balances + all four book
roots + meta hash are identical after restart and after a fresh-node
replay of the winning chain.

Real chain throughout: signed txs sealed into real blocks via
DeepChainTestCase.extend/adopt (ingest_block + maybe_update_canonical_head),
no mocks of the engine, books or chain. The only test double is the
"payout" pool clause evaluator (MockPolicyEvaluator), because the clause
step needs the compiled tau module, which is not built on this machine.

Branch txs are built with EXPLICIT sequence numbers (both branches reuse
seq 0 for their first tx from an account): the rebuild replays the winner
from genesis, so each branch's txs must be valid against the genesis
state, not against the loser's. Grant/payout ids are computed offline
with the books' own pure compute_*_id functions, so the winning branch
can be built whole before it is adopted; the losing branch's id is also
checked against the live book after adoption, which pins the computation.
"""
import os
import sys
import tempfile
import unittest

import config
import db
import chain_state
from chain_state import GENESIS_BALANCE
from bls_keys import (
    SK_ALICE, SK_BOB, SK_CAROL, pubkey_hex, sign_payload, signed_block,
)
from consensus import sender_policy
from consensus.grants import compute_grant_id
from consensus.payouts import compute_payout_id
from consensus.periods import (
    ALL_HOURS_MASK, ALL_WEEKDAYS_MASK, PERIOD_DAY, PERIOD_WEEK,
)
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import clause_body_v1
from consensus.standing import compute_standing_id
from test_reorg_deep_chain import (
    BASE_TS, FUNDED_ACCOUNT, DeepChainTestCase, quiet,
)
from test_grants_native import NativeChainCase, _fresh

ALICE = FUNDED_ACCOUNT
DAY = 86400
FAR_FUTURE = 9999999999
CLAUSE = (
    "always ((i1[t]:bv[24] > { #x000000 }:bv[24])"
    " ? (o1[t]:bv[24] = { 300 }:bv[24] && o2[t]:bv[24] = { 700 }:bv[24])"
    " : (o1[t]:bv[24] = { 0 }:bv[24] && o2[t]:bv[24] = { 0 }:bv[24]))."
)


class TestProgrammablePaymentsReorg(NativeChainCase):
    def setUp(self):
        super().setUp()
        # Program the payout-pool clause evaluator: the clause pays 300 to
        # the first recipient and 700 to the second. Restored in tearDown.
        self._payout_mock = MockPolicyEvaluator(pool="payout")
        self._payout_mock.set_outputs(clause_body_v1(CLAUSE), {"o1": 300, "o2": 700})
        sender_policy.set_evaluator("payout", self._payout_mock)

    def tearDown(self):
        sender_policy.set_evaluator("payout", None)
        super().tearDown()

    # -- tx builders (shapes copied from the *_native test files) --------

    def _grant_create_tx(self, granter_sk, grantee, amount=5000, seq=0,
                         start_at=BASE_TS, expires_at=BASE_TS + 28 * DAY,
                         spend_cap=500, per_payment_cap=500):
        granter = pubkey_hex(granter_sk)
        tx = {
            "tx_id": self._tx_id("grant-create"),
            "tx_type": "grant_create",
            "sender_pubkey": granter,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "grantee_pubkey": grantee,
            "refund_to": granter,
            "amount": amount,
            "period_kind": PERIOD_WEEK,
            "period_anchor": 0,
            "spend_cap": spend_cap,
            "per_payment_cap": per_payment_cap,
            "start_at": start_at,
            "expires_at": expires_at,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, granter_sk)

    def _grant_draw_tx(self, grantee_sk, grant_id, amount, seq=0):
        grantee = pubkey_hex(grantee_sk)
        tx = {
            "tx_id": self._tx_id("grant-draw"),
            "tx_type": "grant_draw",
            "sender_pubkey": grantee,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "grant_id": grant_id.hex(),
            "amount": amount,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, grantee_sk)

    def _route_set_tx(self, account_sk, destination, bps=2500, seq=0,
                      min_incoming=0, activate_at=BASE_TS,
                      expires_at=BASE_TS + 30 * DAY, locked_until=None):
        account = pubkey_hex(account_sk)
        tx = {
            "tx_id": self._tx_id("route-set"),
            "tx_type": "route_set",
            "sender_pubkey": account,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "destination_pubkey": destination,
            "bps": bps,
            "min_incoming": min_incoming,
            "activate_at": activate_at,
            "expires_at": expires_at,
            "locked_until": locked_until,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, account_sk)

    def _standing_create_tx(self, payer_sk, payee, amount=100, seq=0,
                            period_kind=PERIOD_DAY, start_at=BASE_TS,
                            max_fee=10):
        payer = pubkey_hex(payer_sk)
        tx = {
            "tx_id": self._tx_id("standing-create"),
            "tx_type": "standing_payment",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "payee_pubkey": payee,
            "amount": amount,
            "period_kind": period_kind,
            "period_anchor": 0,
            "max_fee_per_execution": max_fee,
            "start_at": start_at,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _payout_create_tx(self, payer_sk, recipients, seq=0,
                          clause=CLAUSE, max_per_execution=1000,
                          max_per_period=1000, start_at=BASE_TS,
                          locked_until=None):
        payer = pubkey_hex(payer_sk)
        tx = {
            "tx_id": self._tx_id("payout-create"),
            "tx_type": "payout_create",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "recipients": list(recipients),
            "clause": clause,
            "max_per_execution": max_per_execution,
            "max_per_period": max_per_period,
            "period_kind": PERIOD_WEEK,
            "period_length": None,
            "period_anchor": 0,
            "start_at": start_at,
            "expires_at": start_at + 30 * DAY,
            "locked_until": locked_until,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _payout_execute_tx(self, payer_sk, payout_id, seq=0):
        payer = pubkey_hex(payer_sk)
        tx = {
            "tx_id": self._tx_id("payout-execute"),
            "tx_type": "payout_execute",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "payout_id": payout_id.hex(),
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _transfer(self, sender_sk, recipient, amount, seq):
        sender = pubkey_hex(sender_sk)
        tx = {
            "tx_id": self._tx_id("transfer"),
            "tx_type": "user_tx",
            "sender_pubkey": sender,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "0",
            "operations": {"1": [[sender, recipient, str(amount)]]},
        }
        return sign_payload(tx, sender_sk)

    # -- digest helpers ----------------------------------------------------

    def _roots(self):
        lm = self._lm()
        return {
            "grants": lm.grants.root(),
            "standing": lm.standing.root(),
            "routes": lm.routes.root(),
            "payouts": lm.payouts.root(),
        }

    def _digest(self, *addrs):
        return {
            "balances": self._balances(*addrs),
            "roots": self._roots(),
            "meta": self._lm().consensus_meta_hash(),
        }

    def _assert_matches_restart_and_follower(self, winning_blocks, *addrs):
        """Node, restarted node and fresh replay of the winner all agree."""
        node = self._digest(*addrs)
        self._restart()
        self.assertEqual(self._digest(*addrs), node)
        self._blocks = list(winning_blocks)
        follower = self._fresh_replay_digest(addrs, self._roots)
        self.assertEqual(follower, node)

    # -- tests ---------------------------------------------------------------

    def test_grant_draw_on_losing_branch_is_dropped(self):
        """A grant created+drawn only on the losing fork leaves no trace."""
        grantee_lose = _fresh(4242)
        grantee_win = _fresh(4343)
        prefix = self.extend(self.genesis_hash, 0, 2)
        lose_gid = compute_grant_id(
            ALICE, grantee_lose, ALICE, 5000, 0, PERIOD_WEEK, None, 0,
            500, 500, ALL_WEEKDAYS_MASK, ALL_HOURS_MASK,
            BASE_TS, BASE_TS + 28 * DAY)
        losing = self.extend(prefix[-1].block_hash, 2, 3, proposer=SK_BOB, txs={
            3: [self._grant_create_tx(SK_ALICE, grantee_lose, seq=0)],
            4: [self._grant_draw_tx(4242, lose_gid, 500, seq=0)],
        })
        self.adopt(prefix + losing)
        # The offline id matches the live book: the computation is exact.
        self.assertIn(lose_gid, self._lm().grants.open)
        self.assertEqual(
            self._balances(ALICE, grantee_lose),
            {ALICE: 5000, grantee_lose: 500})

        win_gid = compute_grant_id(
            ALICE, grantee_win, ALICE, 5000, 0, PERIOD_WEEK, None, 0,
            500, 500, ALL_WEEKDAYS_MASK, ALL_HOURS_MASK,
            BASE_TS, BASE_TS + 28 * DAY)
        winning = self.extend(prefix[-1].block_hash, 2, 5, proposer=SK_CAROL, txs={
            3: [self._grant_create_tx(SK_ALICE, grantee_win, seq=0)],
            4: [self._grant_draw_tx(4343, win_gid, 500, seq=0)],
        })
        self.adopt(winning)
        self.assertNotIn(lose_gid, self._lm().grants.open)
        self.assertIn(win_gid, self._lm().grants.open)
        self.assertEqual(self._lm().grants.open_count(), 1)
        self.assertEqual(
            self._balances(ALICE, grantee_lose, grantee_win),
            {ALICE: 5000, grantee_lose: 0, grantee_win: 500})
        self._assert_matches_restart_and_follower(
            prefix + winning, ALICE, grantee_lose, grantee_win)

    def test_route_on_losing_branch_is_dropped(self):
        """A route set + split only on the losing fork leaves no trace."""
        account = _fresh(4242)
        dest_lose = _fresh(4343)
        dest_win = _fresh(4444)
        prefix = self.extend(self.genesis_hash, 0, 2)
        losing = self.extend(prefix[-1].block_hash, 2, 3, proposer=SK_BOB, txs={
            3: [self._route_set_tx(4242, dest_lose, bps=2500, seq=0)],
            4: [self._transfer(SK_ALICE, account, 1000, 0)],
        })
        self.adopt(prefix + losing)
        self.assertEqual(
            self._balances(ALICE, account, dest_lose),
            {ALICE: 9000, account: 750, dest_lose: 250})

        winning = self.extend(prefix[-1].block_hash, 2, 5, proposer=SK_CAROL, txs={
            3: [self._route_set_tx(4242, dest_win, bps=5000, seq=0)],
            4: [self._transfer(SK_ALICE, account, 1000, 0)],
        })
        self.adopt(winning)
        route = self._lm().routes.get(account)
        self.assertIsNotNone(route)
        self.assertEqual(route.destination_pubkey, dest_win)
        self.assertEqual(route.bps, 5000)
        self.assertEqual(
            self._balances(ALICE, account, dest_lose, dest_win),
            {ALICE: 9000, account: 500, dest_lose: 0, dest_win: 500})
        self._assert_matches_restart_and_follower(
            prefix + winning, ALICE, account, dest_lose, dest_win)

    def test_standing_on_losing_branch_is_dropped(self):
        """A standing payment created only on the losing fork leaves no trace."""
        payee_lose = _fresh(4242)
        payee_win = _fresh(4343)
        prefix = self.extend(self.genesis_hash, 0, 2)
        losing = self.extend(prefix[-1].block_hash, 2, 3, proposer=SK_BOB, txs={
            3: [self._standing_create_tx(SK_ALICE, payee_lose, amount=100, seq=0)],
        })
        self.adopt(prefix + losing)
        self.assertEqual(self._lm().standing.open_count(), 1)
        self.assertEqual(
            self._balances(ALICE, payee_lose), {ALICE: 9900, payee_lose: 100})

        winning = self.extend(prefix[-1].block_hash, 2, 5, proposer=SK_CAROL, txs={
            3: [self._standing_create_tx(SK_ALICE, payee_win, amount=100, seq=0)],
        })
        self.adopt(winning)
        self.assertEqual(self._lm().standing.open_count(), 1)
        entry = self._lm().standing.get(
            compute_standing_id(ALICE, payee_win, 0))
        self.assertIsNotNone(entry)
        self.assertEqual(entry.payee_pubkey, payee_win)
        self.assertEqual(
            self._balances(ALICE, payee_lose, payee_win),
            {ALICE: 9900, payee_lose: 0, payee_win: 100})
        self._assert_matches_restart_and_follower(
            prefix + winning, ALICE, payee_lose, payee_win)

    def test_payout_execute_on_losing_branch_is_dropped(self):
        """A payout created+executed only on the losing fork leaves no trace."""
        r1, r2 = _fresh(4242), _fresh(4343)
        r3, r4 = _fresh(4444), _fresh(4545)
        prefix = self.extend(self.genesis_hash, 0, 2)
        lose_pid = compute_payout_id(ALICE, (r1, r2), 0)
        losing = self.extend(prefix[-1].block_hash, 2, 3, proposer=SK_BOB, txs={
            3: [self._payout_create_tx(SK_ALICE, [r1, r2], seq=0)],
            4: [self._payout_execute_tx(SK_ALICE, lose_pid, seq=1)],
        })
        self.adopt(prefix + losing)
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 9000, r1: 300, r2: 700})

        win_pid = compute_payout_id(ALICE, (r3, r4), 0)
        winning = self.extend(prefix[-1].block_hash, 2, 5, proposer=SK_CAROL, txs={
            3: [self._payout_create_tx(SK_ALICE, [r3, r4], seq=0)],
            4: [self._payout_execute_tx(SK_ALICE, win_pid, seq=1)],
        })
        self.adopt(winning)
        self.assertNotIn(lose_pid, self._lm().payouts.open)
        self.assertIn(win_pid, self._lm().payouts.open)
        self.assertEqual(self._lm().payouts.open_count(), 1)
        self.assertEqual(
            self._balances(ALICE, r1, r2, r3, r4),
            {ALICE: 9000, r1: 0, r2: 0, r3: 300, r4: 700})
        self._assert_matches_restart_and_follower(
            prefix + winning, ALICE, r1, r2, r3, r4)


if __name__ == "__main__":
    unittest.main()
