"""Stage 3 (Bounty 01): standing payments through the REAL in-process chain.

Native tests for the standing book: signed standing_payment /
standing_payment_execute / standing_payment_update / standing_payment_cancel
transactions are sealed into real blocks and driven through
``chain_state.ingest_block`` + ``maybe_update_canonical_head`` -- the same
path a live node takes -- instead of the ``_apply_block`` harness the mock
tests (test_standing.py) use. The post-transaction sweep (design 1.3,
trigger #1) is exercised for real: a due period is paid by the sweep with
no execute transaction in the block.

No mocks of the engine, the books or the chain are used. The tests do not
need the compiled tau module: standing payments are Tau-free, and the sweep
fee step is 0 while Tau is not ready, so every balance delta is exact.

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
from consensus.periods import PERIOD_DAY, PERIOD_WEEK
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


class TestStandingNative(NativeChainCase):
    def _standing_create_tx(self, payer_sk, payee, amount=100, seq=None,
                            period_kind=PERIOD_DAY, start_at=BASE_TS,
                            max_fee=10, chain_id=None):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
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
            "chain_id": self.genesis_hash if chain_id is None else chain_id,
        }
        return sign_payload(tx, payer_sk)

    def _standing_execute_tx(self, payer_sk, standing_id, seq=None, fee_limit="10"):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
        tx = {
            "tx_id": self._tx_id("standing-execute"),
            "tx_type": "standing_payment_execute",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": fee_limit,
            "standing_id": standing_id.hex(),
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _standing_update_tx(self, payer_sk, standing_id, amount, seq=None,
                            period_kind=PERIOD_DAY, start_at=BASE_TS,
                            max_fee=10):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
        tx = {
            "tx_id": self._tx_id("standing-update"),
            "tx_type": "standing_payment_update",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "standing_id": standing_id.hex(),
            "amount": amount,
            "period_kind": period_kind,
            "period_anchor": 0,
            "max_fee_per_execution": max_fee,
            "start_at": start_at,
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _standing_cancel_tx(self, payer_sk, standing_id, seq=None):
        payer = pubkey_hex(payer_sk)
        if seq is None:
            seq = self._next_seq(payer)
        tx = {
            "tx_id": self._tx_id("standing-cancel"),
            "tx_type": "standing_payment_cancel",
            "sender_pubkey": payer,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "standing_id": standing_id.hex(),
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, payer_sk)

    def _open_standing_id(self):
        (sid,) = list(self._lm().standing.open)
        return sid

    def test_sweep_executes_due_period_once(self):
        """The sweep pays a due period with no execute tx; no double-pay."""
        payee = _fresh(4343)
        create = self._standing_create_tx(SK_ALICE, payee, amount=100)
        # Block 1 (ts BASE_TS+1): the create lands and the sweep in the same
        # block already executes period 1 (start_at == BASE_TS, due now).
        self._mine({1: [create]})
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9900, payee: 100})
        # Block 2, same day: the period is already executed -- nothing more.
        self._mine(count=1)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9900, payee: 100})
        # Block 3, next day (jumped timestamp): the sweep pays period 2.
        self._mine(count=1, start_ts=BASE_TS + DAY + 1)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9800, payee: 200})

    def test_explicit_execute_fallback(self):
        """An explicit execute tx pays a period the sweep has not yet paid.

        The transaction loop runs before the sweep in a block, so an execute
        tx sealed into the day-2 block pays period 2 before the sweep sees
        it -- and the sweep then finds nothing due (no double-pay).
        """
        payee = _fresh(4343)
        create = self._standing_create_tx(SK_ALICE, payee, amount=100)
        self._mine({1: [create]})
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9900, payee: 100})
        sid = self._open_standing_id()
        execute = self._standing_execute_tx(SK_ALICE, sid)
        self._mine({2: [execute]}, start_ts=BASE_TS + DAY + 1)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9800, payee: 200})
        # Next block, same day: neither sweep nor a second execute pays again.
        self._mine(count=1, start_ts=BASE_TS + DAY + 2)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9800, payee: 200})
        again = self._standing_execute_tx(SK_ALICE, sid)
        self._mine({4: [again]}, start_ts=BASE_TS + DAY + 3)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9800, payee: 200})

    def test_update_restarts_schedule_at_new_amount(self):
        """standing_payment_update: new version, fresh schedule, new amount.

        The update resolves the old version as superseded and starts the new
        one with a fresh execution schedule, so the sweep re-executes the
        current period at the new amount, then pays the next period once.
        """
        payee = _fresh(4343)
        create = self._standing_create_tx(SK_ALICE, payee, amount=100)
        self._mine({1: [create]})
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9900, payee: 100})
        sid = self._open_standing_id()
        update = self._standing_update_tx(SK_ALICE, sid, amount=200)
        # Block 2 (same day): update lands, sweep re-pays period 1 at 200.
        self._mine({2: [update]})
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9700, payee: 300})
        entry = self._lm().standing.get(sid)
        self.assertEqual(entry.amount, 200)
        self.assertEqual(entry.version, 2)
        # Block 3, next day: sweep pays period 2 at the new amount, once.
        self._mine(count=1, start_ts=BASE_TS + DAY + 1)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9500, payee: 500})

    def test_cancel_stops_future_payments(self):
        """Cancel after period 1: the next day's sweep pays nothing."""
        payee = _fresh(4343)
        create = self._standing_create_tx(SK_ALICE, payee, amount=100)
        self._mine({1: [create]})
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9900, payee: 100})
        sid = self._open_standing_id()
        cancel = self._standing_cancel_tx(SK_ALICE, sid)
        self._mine({2: [cancel]})
        self.assertEqual(self._lm().standing.open_count(), 0)
        self._mine(count=1, start_ts=BASE_TS + DAY + 1)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9900, payee: 100})

    def test_wrong_chain_id_rejected_on_real_chain(self):
        payee = _fresh(4343)
        create = self._standing_create_tx(
            SK_ALICE, payee, chain_id="ab" * 32)
        self._mine({1: [create]})
        self.assertEqual(self._lm().standing.open_count(), 0)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 10000, payee: 0})

    def test_survives_restart_and_fresh_replay(self):
        """Book root + meta hash are identical after restart and fresh replay."""
        payee = _fresh(4343)
        create = self._standing_create_tx(SK_ALICE, payee, amount=100)
        self._mine({1: [create]})
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9900, payee: 100})

        def roots():
            lm = self._lm()
            return {"standing": lm.standing.root()}

        before = {
            "balances": self._balances(ALICE, payee),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self._restart()
        after_restart = {
            "balances": self._balances(ALICE, payee),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self.assertEqual(after_restart, before)
        # The executed period survives the restart: the next day pays once.
        self._mine(count=1, start_ts=BASE_TS + DAY + 1)
        self.assertEqual(self._balances(ALICE, payee), {ALICE: 9800, payee: 200})
        replayed = self._fresh_replay_digest((ALICE, payee), roots)
        self.assertEqual(
            replayed["balances"], self._balances(ALICE, payee))
        self.assertEqual(replayed["roots"], roots())
        self.assertEqual(replayed["meta"], self._lm().consensus_meta_hash())


if __name__ == "__main__":
    unittest.main()
