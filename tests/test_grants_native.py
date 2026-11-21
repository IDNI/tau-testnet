"""Stage 2 (Bounty 01): conditional grants through the REAL in-process chain.

These are the native tests for the grant book: signed grant_create /
grant_draw / grant_cancel transactions are sealed into real blocks and driven
through ``chain_state.ingest_block`` + ``maybe_update_canonical_head`` --
the same path a live node takes -- instead of the ``_apply_block`` harness
the mock tests (test_grants.py) use. Balances, the grant book root and the
consensus meta hash are asserted at every step, and the last test proves the
state survives a restart and a fresh replay of the same blocks.

No mocks of the engine, the books or the chain are used. The tests do not
need the compiled tau module: grants are Tau-free (admission screens +
book logic only), and the fee step is 0 while Tau is not ready, so every
balance delta is exact.

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
from consensus.periods import PERIOD_WEEK
from test_reorg_deep_chain import (
    BASE_TS,
    FUNDED_ACCOUNT,
    DeepChainTestCase,
    quiet,
)

ALICE = FUNDED_ACCOUNT
DAY = 86400
FAR_FUTURE = 9999999999


def _fresh(n):
    return pubkey_hex(n)


class NativeChainCase(DeepChainTestCase):
    """DeepChainTestCase + block mining, restart and fresh-replay helpers."""

    def setUp(self):
        super().setUp()
        self._seq = {}
        self._tx_n = 0
        self._tip_hash = self.genesis_hash
        self._tip_number = 0
        self._blocks = []
        self._extra_dbs = []

    def tearDown(self):
        for path in self._extra_dbs:
            if os.path.exists(path):
                os.remove(path)
        super().tearDown()

    def _next_seq(self, sender):
        n = self._seq.get(sender, 0)
        self._seq[sender] = n + 1
        return n

    def _tx_id(self, kind):
        self._tx_n += 1
        return f"native-{kind}-{self._tx_n}"

    def _mine(self, txs=None, count=1, proposer=SK_ALICE, ts_step=1, start_ts=None):
        """Seal `count` blocks on the tip; `txs` maps absolute height -> [tx]."""
        txs = txs or {}
        blocks = []
        prev = self._tip_hash
        for i in range(1, count + 1):
            n = self._tip_number + i
            ts = (start_ts + (i - 1) * ts_step) if start_ts is not None else BASE_TS + n
            blk = signed_block(
                proposer, block_number=n, previous_hash=prev,
                transactions=txs.get(n, []), timestamp=ts,
            )
            blocks.append(blk)
            prev = blk.block_hash
        self.ingest(blocks)
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), blocks[-1].block_hash)
        self._tip_hash = blocks[-1].block_hash
        self._tip_number = blocks[-1].header.block_number
        self._blocks.extend(blocks)
        return blocks

    def _lm(self):
        # Adoption may swap the lifecycle manager: always re-read it.
        return chain_state._lifecycle_manager

    def _balances(self, *addrs):
        return {a: chain_state.get_balance(a) for a in addrs}

    def _restart(self):
        path = config.STRING_DB_PATH
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(path)
        db.init_db()
        self.assertTrue(chain_state.load_state_from_db())

    def _fresh_replay_digest(self, addrs, roots_fn):
        """A follower node: fresh DB, genesis, replay of the same blocks."""
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        fd, path = tempfile.mkstemp(suffix=".sqlite")
        os.close(fd)
        self._extra_dbs.append(path)
        orig_path = config.STRING_DB_PATH
        config.set_database_path(path)
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        chain_state._last_transfer_ts.clear()
        db._db_conn = None
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        chain_state._genesis_accounts_state = {FUNDED_ACCOUNT: GENESIS_BALANCE}
        chain_state._balances[FUNDED_ACCOUNT] = GENESIS_BALANCE
        for blk in self._blocks:
            self.assertEqual(chain_state.ingest_block(blk).status, "added")
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        digest = {
            "balances": self._balances(*addrs),
            "roots": roots_fn(),
            "meta": self._lm().consensus_meta_hash(),
        }
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(orig_path)
        db.init_db()
        self.assertTrue(chain_state.load_state_from_db())
        return digest


class TestGrantsNative(NativeChainCase):
    def _grant_create_tx(self, granter_sk, grantee, amount=5000, seq=None,
                         start_at=BASE_TS, expires_at=BASE_TS + 28 * DAY,
                         spend_cap=500, per_payment_cap=500,
                         chain_id=None):
        granter = pubkey_hex(granter_sk)
        if seq is None:
            seq = self._next_seq(granter)
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
            "chain_id": self.genesis_hash if chain_id is None else chain_id,
        }
        return sign_payload(tx, granter_sk)

    def _grant_draw_tx(self, grantee_sk, grant_id, amount, seq=None):
        grantee = pubkey_hex(grantee_sk)
        if seq is None:
            seq = self._next_seq(grantee)
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

    def _grant_cancel_tx(self, granter_sk, grant_id, seq=None):
        granter = pubkey_hex(granter_sk)
        if seq is None:
            seq = self._next_seq(granter)
        tx = {
            "tx_id": self._tx_id("grant-cancel"),
            "tx_type": "grant_cancel",
            "sender_pubkey": granter,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "grant_id": grant_id.hex(),
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, granter_sk)

    def _open_grant_id(self):
        (gid,) = list(self._lm().grants.open)
        return gid

    def test_create_draw_cancel_through_real_blocks(self):
        """Create escrows, draw pays the grantee, cancel refunds the rest."""
        grantee = _fresh(4242)
        create = self._grant_create_tx(SK_ALICE, grantee)
        self._mine({1: [create]})
        lm = self._lm()
        gid = self._open_grant_id()
        self.assertEqual(self._balances(ALICE, grantee), {ALICE: 5000, grantee: 0})
        self.assertEqual(lm.grants.escrowed_total(), 5000)
        self.assertEqual(lm.grants.remaining_for(gid), 5000)
        root_after_create = lm.grants.root()
        meta_after_create = lm.consensus_meta_hash()

        draw = self._grant_draw_tx(4242, gid, 500)
        self._mine({2: [draw]})
        lm = self._lm()
        self.assertEqual(self._balances(ALICE, grantee), {ALICE: 5000, grantee: 500})
        self.assertEqual(lm.grants.drawn_total(gid), 500)
        self.assertEqual(lm.grants.remaining_for(gid), 4500)
        self.assertNotEqual(lm.grants.root(), root_after_create)
        self.assertNotEqual(lm.consensus_meta_hash(), meta_after_create)

        # Second draw in the same week breaches the 500 spend cap: rejected,
        # no balance moves, and the grantee's sequence is NOT consumed.
        over_cap = self._grant_draw_tx(4242, gid, 500)
        self._mine({3: [over_cap]})
        self.assertEqual(self._balances(ALICE, grantee), {ALICE: 5000, grantee: 500})
        self.assertEqual(chain_state._sequence_numbers.get(grantee), 1)

        cancel = self._grant_cancel_tx(SK_ALICE, gid)
        self._mine({4: [cancel]})
        lm = self._lm()
        self.assertEqual(self._balances(ALICE, grantee), {ALICE: 9500, grantee: 500})
        self.assertEqual(lm.grants.open_count(), 0)
        self.assertEqual(lm.grants.escrowed_total(), 0)

    def test_expiry_refund_via_sweep(self):
        """An un-drawn grant is expired + refunded by the block sweep."""
        grantee = _fresh(4242)
        create = self._grant_create_tx(
            SK_ALICE, grantee, expires_at=BASE_TS + 10)
        self._mine({1: [create]})
        self.assertEqual(chain_state.get_balance(ALICE), 5000)
        # Mine past expiry (block timestamps jump past expires_at).
        self._mine(count=2, start_ts=BASE_TS + 11)
        lm = self._lm()
        self.assertEqual(lm.grants.open_count(), 0)
        self.assertEqual(lm.grants.escrowed_total(), 0)
        self.assertEqual(chain_state.get_balance(ALICE), 10000)
        self.assertEqual(chain_state.get_balance(grantee), 0)

    def test_wrong_chain_id_rejected_on_real_chain(self):
        """A grant signed for another network never lands on this chain."""
        grantee = _fresh(4242)
        seq_before = chain_state._sequence_numbers.get(ALICE, 0)
        create = self._grant_create_tx(SK_ALICE, grantee, chain_id="ab" * 32)
        self._mine({1: [create]})
        lm = self._lm()
        self.assertEqual(lm.grants.open_count(), 0)
        self.assertEqual(self._balances(ALICE, grantee), {ALICE: 10000, grantee: 0})
        # Rejected transactions do not consume the sender's sequence.
        # (An unlisted sender reads as 0; block apply may seed the entry
        # at 0 without consuming it.)
        self.assertEqual(chain_state._sequence_numbers.get(ALICE, 0), seq_before)

    def test_survives_restart_and_fresh_replay(self):
        """Book root + meta hash are identical after restart and fresh replay."""
        grantee = _fresh(4242)
        create = self._grant_create_tx(SK_ALICE, grantee)
        self._mine({1: [create]})
        gid = self._open_grant_id()
        draw = self._grant_draw_tx(4242, gid, 500)
        self._mine({2: [draw]})

        def roots():
            lm = self._lm()
            return {"grants": lm.grants.root()}

        before = {
            "balances": self._balances(ALICE, grantee),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self._restart()
        after_restart = {
            "balances": self._balances(ALICE, grantee),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self.assertEqual(after_restart, before)
        self.assertEqual(self._lm().grants.drawn_total(gid), 500)
        self.assertEqual(self._lm().grants.remaining_for(gid), 4500)

        replayed = self._fresh_replay_digest((ALICE, grantee), roots)
        self.assertEqual(replayed, before)


if __name__ == "__main__":
    unittest.main()
