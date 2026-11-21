"""Stage 5 (Bounty 01): payout rules through the REAL in-process chain.

Native tests for the payout book: signed payout_create / payout_execute /
payout_remove transactions are sealed into real blocks and driven through
``chain_state.ingest_block`` + ``maybe_update_canonical_head`` -- the same
path a live node takes -- instead of the ``_apply_block`` harness the mock
tests (test_payouts.py) use. Balances, the payout book root, the period
caps and the consensus meta hash are asserted at every step, and the last
test proves the paid-in-period totals survive a restart and a fresh replay
(the regression fixed by patch_stage5fix3).

One test double, and only one: the Tau-language clause step. A payout
clause is evaluated by the policy evaluator, which is a subprocess worker
around the compiled tau module -- and the module is not built on this
machine (see the ``test_*_native.py`` skip in the rest of the suite). The
engine, the books, the chain, the persistence and the real
``clause_outputs_for`` call are all exercised; only the evaluator behind it
is the repo's own ``MockPolicyEvaluator`` (pool ``"payout"``), programmed
with the clause outputs, exactly as the sender-policy pools are mocked in
``tests/conftest.py``. The fail-closed paths (clause unavailable, zero
outputs) are tested through the real engine too.

Requires ``data/genesis.json`` (generated genesis, faucet 0 -- see README);
the harness is ``DeepChainTestCase`` from test_reorg_deep_chain.py.
"""
import os
import sys
import tempfile
import unittest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
tests_dir = os.path.dirname(__file__)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

import config
import db
import chain_state
from chain_state import GENESIS_BALANCE
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_payload, signed_block
from consensus import sender_policy
from consensus.periods import PERIOD_WEEK, period_index
from consensus.policy_mock import MockPolicyEvaluator
from test_reorg_deep_chain import (
    BASE_TS,
    FUNDED_ACCOUNT,
    DeepChainTestCase,
    quiet,
)
from test_grants_native import NativeChainCase, _fresh

ALICE = FUNDED_ACCOUNT
DAY = 86400
FAR_FUTURE = 9999999999
CLAUSE = "always (o1[t] = 300, o2[t] = 700)."


class TestPayoutsNative(NativeChainCase):
    def setUp(self):
        super().setUp()
        # Program the payout-pool clause evaluator: the clause pays 300 to
        # the first recipient and 700 to the second. Restored in tearDown.
        self._payout_mock = MockPolicyEvaluator(pool="payout")
        self._payout_mock.set_outputs(CLAUSE, {"o1": 300, "o2": 700})
        sender_policy.set_evaluator("payout", self._payout_mock)

    def tearDown(self):
        sender_policy.set_evaluator("payout", None)
        super().tearDown()

    def _payout_create_tx(self, payer_sk, recipients, seq=None,
                          clause=CLAUSE, max_per_execution=1000,
                          max_per_period=1000, start_at=BASE_TS,
                          locked_until=None, chain_id=None):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
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
            "chain_id": self.genesis_hash if chain_id is None else chain_id,
        }
        return sign_payload(tx, payer_sk)

    def _payout_execute_tx(self, payer_sk, payout_id, seq=None):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
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

    def _payout_remove_tx(self, payer_sk, payout_id, seq=None):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
        tx = {
            "tx_id": self._tx_id("payout-remove"),
            "tx_type": "payout_remove",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "payout_id": payout_id.hex(),
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _open_payout_id(self):
        (pid,) = list(self._lm().payouts.open)
        return pid

    def test_create_execute_remove_through_real_blocks(self):
        """Create, clause execute (300/700), cap blocks a repeat, remove."""
        r1, r2 = _fresh(4242), _fresh(4343)
        create = self._payout_create_tx(SK_ALICE, [r1, r2])
        self._mine({1: [create]})
        lm = self._lm()
        pid = self._open_payout_id()
        entry = lm.payouts.get(pid)
        self.assertEqual(entry.recipients, (r1, r2))
        # A payout rule holds no escrow: the payer keeps the funds.
        self.assertEqual(self._balances(ALICE, r1, r2), {ALICE: 10000, r1: 0, r2: 0})
        root_after_create = lm.payouts.root()

        execute = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({2: [execute]})
        lm = self._lm()
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 9000, r1: 300, r2: 700})
        # The period cap is spent: paid_in_period for the current week is
        # 1000. (due_period still names the current week -- it is the cap,
        # not due_period, that blocks a repeat execution.)
        current = period_index(PERIOD_WEEK, BASE_TS + 2, anchor=0, length=None)
        self.assertEqual(lm.payouts.paid_in_period(pid, current), 1000)
        self.assertEqual(lm.payouts.due_period(pid, BASE_TS + 2), current)
        self.assertNotEqual(lm.payouts.root(), root_after_create)

        # A second execute in the same period is skipped: the period cap
        # (1000) is fully spent, and balances do not move.
        again = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({3: [again]})
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 9000, r1: 300, r2: 700})

        # The capped second execute is rejected, so it does not consume
        # Alice's sequence: the remove still uses sequence 2, not 3.
        remove = self._payout_remove_tx(SK_ALICE, pid, seq=2)
        self._mine({4: [remove]})
        self.assertEqual(self._lm().payouts.open_count(), 0)

    def test_execute_with_unavailable_clause_pays_nothing(self):
        """A clause the evaluator refuses fails closed: nothing is paid."""
        r1, r2 = _fresh(4242), _fresh(4343)
        create = self._payout_create_tx(SK_ALICE, [r1, r2])
        self._mine({1: [create]})
        pid = self._open_payout_id()
        self._payout_mock.fail_step(CLAUSE)
        execute = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({2: [execute]})
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 10000, r1: 0, r2: 0})
        self.assertIsNotNone(self._lm().payouts.get(pid))

    def test_execute_with_zero_outputs_skipped(self):
        """A clause that outputs nothing pays nothing (skipped_zero)."""
        r1, r2 = _fresh(4242), _fresh(4343)
        self._payout_mock.set_outputs(CLAUSE, {})
        create = self._payout_create_tx(SK_ALICE, [r1, r2])
        self._mine({1: [create]})
        pid = self._open_payout_id()
        execute = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({2: [execute]})
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 10000, r1: 0, r2: 0})
        self.assertIsNotNone(self._lm().payouts.get(pid))

    def test_wrong_chain_id_rejected_on_real_chain(self):
        r1, r2 = _fresh(4242), _fresh(4343)
        create = self._payout_create_tx(
            SK_ALICE, [r1, r2], chain_id="ab" * 32)
        self._mine({1: [create]})
        self.assertEqual(self._lm().payouts.open_count(), 0)
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 10000, r1: 0, r2: 0})

    def test_survives_restart_and_fresh_replay(self):
        """Paid-in-period totals survive a restart and a fresh replay.

        This is the fixup-3 regression on the real chain: the payouts table
        must carry period_index + paid_in_period, or the period cap resets
        to 0 on every restart and a second execute would double-pay.
        """
        r1, r2 = _fresh(4242), _fresh(4343)
        create = self._payout_create_tx(SK_ALICE, [r1, r2])
        self._mine({1: [create]})
        pid = self._open_payout_id()
        execute = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({2: [execute]})
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 9000, r1: 300, r2: 700})

        def roots():
            lm = self._lm()
            return {"payouts": lm.payouts.root()}

        before = {
            "balances": self._balances(ALICE, r1, r2),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self._restart()
        after_restart = {
            "balances": self._balances(ALICE, r1, r2),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self.assertEqual(after_restart, before)
        # After the restart the cap is still spent: a repeat execute pays 0.
        again = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({3: [again]})
        self.assertEqual(
            self._balances(ALICE, r1, r2), {ALICE: 9000, r1: 300, r2: 700})
        replayed = self._fresh_replay_digest((ALICE, r1, r2), roots)
        self.assertEqual(replayed["balances"], self._balances(ALICE, r1, r2))
        self.assertEqual(replayed["roots"], roots())
        self.assertEqual(replayed["meta"], self._lm().consensus_meta_hash())


if __name__ == "__main__":
    unittest.main()
