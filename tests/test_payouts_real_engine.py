"""Stage 5 (Bounty 01): payout rules against the REAL Tau engine.

The mock-based native tests (test_payouts_native.py) program the payout-pool
evaluator with scripted outputs, so a clause that cannot build, cannot step,
or returns the wrong outputs on the real engine is invisible to them -- the
e2e run proved exactly that blind spot (the demo clause never evaluated
live). These tests close it: the payout pool is the PRODUCTION evaluator
(``tau_policy.get_policy_evaluator("payout")``, the same cached pool a live
node uses), installed via ``sender_policy.set_evaluator`` so the
TAU_FORCE_TEST mock the suite installs for the other pools is bypassed
for ``"payout"`` only. No mock of any kind is used in this file.

Two realistic rules, the way a royalty split and an escrow release would
actually be written:

* Royalty split -- three recipients, 100/200/300 whenever the payer is
  funded (``i1 > 0``), else 0. Proves the worker returns ALL clause
  outputs (``o1..o3``), not just the first.
* Escrow release -- one recipient, 1000 only once the block timestamp
  passes a release time (``i5`` guard), else 0. An execute before the
  release pays nothing (``skipped_zero``, sequence not consumed); the
  same sequence re-executed after the release pays in full.

Plus the fail-closed case the mock could never catch: a constant-only
clause (no input stream) builds but the engine refuses to step it, so
``clause_outputs_for`` returns None and the execute pays nothing while
the rule survives.

Skipped when the native tau module is not available, like
test_tau_policy_native.py. Requires ``data/genesis.json``; the harness is
``DeepChainTestCase`` from test_reorg_deep_chain.py via ``NativeChainCase``.
"""
import os
import sys
import unittest

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)
tests_dir = os.path.dirname(__file__)
if tests_dir not in sys.path:
    sys.path.insert(0, tests_dir)

import tau_policy
from bls_keys import SK_ALICE, pubkey_hex, sign_payload
from consensus import sender_policy
from consensus.periods import PERIOD_WEEK, period_index
from test_reorg_deep_chain import BASE_TS, FUNDED_ACCOUNT
from test_grants_native import NativeChainCase, _fresh

ALICE = FUNDED_ACCOUNT
DAY = 86400
FAR_FUTURE = 9999999999

# Royalty split: 100/200/300 while the payer holds anything, else 0.
# The i1 guard is what makes the clause steppable at all -- a clause that
# reads no input stream is refused by the engine (see the constant-only
# test below). The guard caps at 2**24 - 1, fine for every balance here;
# a payer holding more would need a wider guard (e.g. an i5 timestamp).
ROYALTY_CLAUSE = (
    "always ((i1[t]:bv[24] > { #x000000 }:bv[24])"
    " ? (o1[t]:bv[24] = { 100 }:bv[24] && o2[t]:bv[24] = { 200 }:bv[24]"
    " && o3[t]:bv[24] = { 300 }:bv[24])"
    " : (o1[t]:bv[24] = { 0 }:bv[24] && o2[t]:bv[24] = { 0 }:bv[24]"
    " && o3[t]:bv[24] = { 0 }:bv[24]))."
)
# Escrow release: 1000 once the block timestamp passes BASE_TS + 5, else 0.
RELEASE_TS = BASE_TS + 5
ESCROW_CLAUSE = (
    "always ((i5[t]:bv[32] > { #x%08x }:bv[32])"
    " ? (o1[t]:bv[24] = { 1000 }:bv[24])"
    " : (o1[t]:bv[24] = { 0 }:bv[24]))."
) % RELEASE_TS
# Constant-only: builds, but the engine refuses to step a clause that
# reads no input stream, so every execute fails closed.
CONSTANT_CLAUSE = "always (o1[t]:bv[24] = { 300 }:bv[24])."


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built")


class TestPayoutsRealEngine(NativeChainCase):
    def setUp(self):
        super().setUp()
        # The production payout-pool evaluator; restored in tearDown.
        sender_policy.set_evaluator(
            "payout", tau_policy.get_policy_evaluator("payout"))

    def tearDown(self):
        sender_policy.set_evaluator("payout", None)
        super().tearDown()

    def _payout_create_tx(self, payer_sk, recipients, seq=None,
                          clause=ROYALTY_CLAUSE, max_per_execution=600,
                          max_per_period=600, start_at=BASE_TS):
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
            "locked_until": None,
            "chain_id": self.genesis_hash,
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

    def test_royalty_split_on_real_engine(self):
        """Three-way split: the real engine returns all three outputs."""
        r1, r2, r3 = _fresh(4242), _fresh(4343), _fresh(4444)
        create = self._payout_create_tx(SK_ALICE, [r1, r2, r3])
        self._mine({1: [create]})
        pid = self._open_payout_id()

        execute = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({2: [execute]})
        # Every leg landed: if the worker returned only o1, r2/r3 would be 0.
        self.assertEqual(
            self._balances(ALICE, r1, r2, r3),
            {ALICE: 9400, r1: 100, r2: 200, r3: 300})
        current = period_index(PERIOD_WEEK, BASE_TS + 2, anchor=0, length=None)
        self.assertEqual(self._lm().payouts.paid_in_period(pid, current), 600)

        # The period cap (600) is fully spent: a repeat pays nothing.
        again = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({3: [again]})
        self.assertEqual(
            self._balances(ALICE, r1, r2, r3),
            {ALICE: 9400, r1: 100, r2: 200, r3: 300})

        # The capped second execute is rejected, so it does not consume
        # Alice's sequence: the remove still uses sequence 2, not 3.
        remove = self._payout_remove_tx(SK_ALICE, pid, seq=2)
        self._mine({4: [remove]})
        self.assertEqual(self._lm().payouts.open_count(), 0)

    def test_escrow_release_on_real_engine(self):
        """Time-gated release: 0 before the release time, 1000 after it."""
        r1 = _fresh(4242)
        create = self._payout_create_tx(
            SK_ALICE, [r1], clause=ESCROW_CLAUSE,
            max_per_execution=1000, max_per_period=1000)
        self._mine({1: [create]})
        pid = self._open_payout_id()

        # Block 2 (ts BASE_TS + 2) is before the release: the clause
        # outputs 0, the execute is skipped and pays nothing.
        early = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({2: [early]})
        self.assertEqual(
            self._balances(ALICE, r1), {ALICE: 10000, r1: 0})
        self.assertIsNotNone(self._lm().payouts.get(pid))

        # The skipped execute did not consume Alice's sequence: the same
        # sequence 1 re-executes at block 6 (ts BASE_TS + 6, past the
        # release) and pays the full 1000.
        release = self._payout_execute_tx(SK_ALICE, pid, seq=1)
        self._mine({6: [release]}, count=4)
        self.assertEqual(
            self._balances(ALICE, r1), {ALICE: 9000, r1: 1000})
        current = period_index(PERIOD_WEEK, BASE_TS + 6, anchor=0, length=None)
        self.assertEqual(self._lm().payouts.paid_in_period(pid, current), 1000)

    def test_constant_only_clause_fails_closed_on_real_engine(self):
        """A clause that reads no input cannot be stepped: pays nothing."""
        r1 = _fresh(4242)
        create = self._payout_create_tx(
            SK_ALICE, [r1], clause=CONSTANT_CLAUSE,
            max_per_execution=1000, max_per_period=1000)
        self._mine({1: [create]})
        pid = self._open_payout_id()

        execute = self._payout_execute_tx(SK_ALICE, pid)
        self._mine({2: [execute]})
        self.assertEqual(
            self._balances(ALICE, r1), {ALICE: 10000, r1: 0})
        # Fail-closed, not removed: the rule survives a bad clause.
        self.assertIsNotNone(self._lm().payouts.get(pid))


if __name__ == "__main__":
    unittest.main()
