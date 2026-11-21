"""Stage 4 (Bounty 01): receive routes through the REAL in-process chain.

Native tests for the route book: signed route_set / route_remove
transactions are sealed into real blocks and driven through
``chain_state.ingest_block`` + ``maybe_update_canonical_head`` -- the same
path a live node takes -- instead of the ``_apply_block`` harness the mock
tests (test_routes.py) use. The split itself is exercised on ordinary
user transfers: an incoming credit to a routed account is split to the
destination in the same block, single-hop only.

No mocks of the engine, the books or the chain are used. The tests do not
need the compiled tau module: routes are Tau-free, and the fee step is 0
while Tau is not ready, so every balance delta is exact.

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


def _transfer(sender_sk, recipient, amount, seq):
    """A plain user transfer (operations {"1": ...}), signed by `sender_sk`."""
    sender = pubkey_hex(sender_sk)
    tx = {
        "tx_id": f"native-transfer-{seq}-{amount}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR_FUTURE,
        "expire_at_height": 5000,
        "fee_limit": "0",
        "operations": {"1": [[sender, recipient, str(amount)]]},
    }
    return sign_payload(tx, sender_sk)


class TestRoutesNative(NativeChainCase):
    def _route_set_tx(self, account_sk, destination, bps=2500, seq=None,
                      min_incoming=0, activate_at=BASE_TS,
                      expires_at=BASE_TS + 30 * DAY, locked_until=None,
                      chain_id=None):
        account = pubkey_hex(account_sk)
        if seq is None:
            seq = self._next_seq(account)
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
            "chain_id": self.genesis_hash if chain_id is None else chain_id,
        }
        return sign_payload(tx, account_sk)

    def _route_remove_tx(self, account_sk, seq=None):
        account = pubkey_hex(account_sk)
        if seq is None:
            seq = self._next_seq(account)
        tx = {
            "tx_id": self._tx_id("route-remove"),
            "tx_type": "route_remove",
            "sender_pubkey": account,
            "sequence_number": seq,
            "expiration_time": FAR_FUTURE,
            "expire_at_height": 5000,
            "fee_limit": "10000",
            "chain_id": self.genesis_hash,
        }
        return sign_payload(tx, account_sk)

    def test_transfer_splits_to_route(self):
        """An incoming credit to a routed account splits 2500bps to dest."""
        account = _fresh(4242)
        dest = _fresh(4343)
        self._mine({1: [self._route_set_tx(4242, dest, bps=2500)]})
        route = self._lm().routes.get(account)
        self.assertIsNotNone(route)
        self.assertEqual(route.destination_pubkey, dest)
        self.assertEqual(route.bps, 2500)
        root_after_set = self._lm().routes.root()
        meta_after_set = self._lm().consensus_meta_hash()
        accounts_after_set = chain_state.compute_accounts_hash(
            chain_state._balances, chain_state._sequence_numbers)

        # Alice pays 1000 to the routed account: 750 stays, 250 routes on.
        self._mine({2: [_transfer(SK_ALICE, account, 1000, self._next_seq(ALICE))]})
        self.assertEqual(
            self._balances(ALICE, account, dest),
            {ALICE: 9000, account: 750, dest: 250},
        )
        # The transfer moves funds but does not touch the route book itself:
        # routes root and meta hash (book roots + governance, not balances)
        # are unchanged, while the accounts hash moves with the balances.
        self.assertEqual(self._lm().routes.root(), root_after_set)
        self.assertEqual(self._lm().consensus_meta_hash(), meta_after_set)
        self.assertNotEqual(
            chain_state.compute_accounts_hash(
                chain_state._balances, chain_state._sequence_numbers),
            accounts_after_set)

    def test_min_incoming_threshold(self):
        """Credits below min_incoming are not split; at/above it, they are."""
        account = _fresh(4242)
        dest = _fresh(4343)
        self._mine({1: [self._route_set_tx(
            4242, dest, bps=5000, min_incoming=2000)]})
        self._mine({2: [_transfer(SK_ALICE, account, 1000, self._next_seq(ALICE))]})
        self.assertEqual(
            self._balances(ALICE, account, dest),
            {ALICE: 9000, account: 1000, dest: 0},
        )
        self._mine({3: [_transfer(SK_ALICE, account, 2000, self._next_seq(ALICE))]})
        self.assertEqual(
            self._balances(ALICE, account, dest),
            {ALICE: 7000, account: 2000, dest: 1000},
        )

    def test_route_is_single_hop_and_removable(self):
        """Routed funds do not split again; removing the route stops splits."""
        account = _fresh(4242)
        dest = _fresh(4343)
        onward = _fresh(4444)
        self._mine({1: [self._route_set_tx(4242, dest, bps=5000)]})
        self._mine({2: [self._route_set_tx(4343, onward, bps=5000)]})
        self._mine({3: [_transfer(SK_ALICE, account, 1000, self._next_seq(ALICE))]})
        # 500 stays, 500 routes to dest; dest's own route does NOT re-split.
        self.assertEqual(
            self._balances(ALICE, account, dest, onward),
            {ALICE: 9000, account: 500, dest: 500, onward: 0},
        )
        self._mine({4: [self._route_remove_tx(4242)]})
        self.assertIsNone(self._lm().routes.get(account))
        self._mine({5: [_transfer(SK_ALICE, account, 1000, self._next_seq(ALICE))]})
        self.assertEqual(
            self._balances(ALICE, account, dest, onward),
            {ALICE: 8000, account: 1500, dest: 500, onward: 0},
        )

    def test_wrong_chain_id_rejected_on_real_chain(self):
        account = _fresh(4242)
        dest = _fresh(4343)
        self._mine({1: [self._route_set_tx(
            4242, dest, chain_id="ab" * 32)]})
        self.assertIsNone(self._lm().routes.get(account))
        self.assertEqual(
            self._balances(ALICE, account, dest),
            {ALICE: 10000, account: 0, dest: 0},
        )

    def test_survives_restart_and_fresh_replay(self):
        """Book root + meta hash are identical after restart and fresh replay."""
        account = _fresh(4242)
        dest = _fresh(4343)
        self._mine({1: [self._route_set_tx(4242, dest, bps=2500)]})
        self._mine({2: [_transfer(SK_ALICE, account, 1000, self._next_seq(ALICE))]})
        self.assertEqual(
            self._balances(ALICE, account, dest),
            {ALICE: 9000, account: 750, dest: 250},
        )

        def roots():
            lm = self._lm()
            return {"routes": lm.routes.root()}

        before = {
            "balances": self._balances(ALICE, account, dest),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self._restart()
        after_restart = {
            "balances": self._balances(ALICE, account, dest),
            "roots": roots(),
            "meta": self._lm().consensus_meta_hash(),
        }
        self.assertEqual(after_restart, before)
        # The route still splits after the restart.
        self._mine({3: [_transfer(SK_ALICE, account, 1000, self._next_seq(ALICE))]})
        self.assertEqual(
            self._balances(ALICE, account, dest),
            {ALICE: 8000, account: 1500, dest: 500},
        )
        replayed = self._fresh_replay_digest((ALICE, account, dest), roots)
        self.assertEqual(replayed["balances"], self._balances(ALICE, account, dest))
        self.assertEqual(replayed["roots"], roots())
        self.assertEqual(replayed["meta"], self._lm().consensus_meta_hash())


if __name__ == "__main__":
    unittest.main()
