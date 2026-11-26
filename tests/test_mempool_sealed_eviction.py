"""A block that the node applies takes its transactions out of the mempool.

Every apply path is driven: the rebuild of `reorg_to`, the extension through
the commit protocol, a direct `process_new_block`, the batch that gossip and
sync hand to the network service, and a block that the node mines itself.
Each test compares the mempool keys with `compute_tx_hash` of the block
transactions.
"""
import contextlib
import json
import os
import sys
from unittest.mock import MagicMock, patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import chain_state
import db
from block import compute_tx_hash
from bls_keys import signed_block
from commands import getsequence, sendtx
from network.service import NetworkService

from test_reorg_mempool_restore import (
    ALICE, BOB, CAROL, MALLORY, PROPOSER_A, PROPOSER_B, SK_ALICE, SK_BOB,
    ReorgRestoreTestCase, _echo_multi, quiet, transfer,
)


@contextlib.contextmanager
def _tau_ready():
    mock_tau = MagicMock()
    mock_tau.tau_ready.is_set.return_value = True
    mock_tau.tau_ready.wait.return_value = True
    mock_tau.communicate_with_tau.return_value = "100"
    mock_tau.communicate_with_tau_multi.side_effect = _echo_multi
    with patch("chain_state.tau_manager", mock_tau), \
            patch("consensus.engine.tau_manager", mock_tau):
        yield


class SealedEvictionTestCase(ReorgRestoreTestCase):
    def setUp(self):
        super().setUp()
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), self.prefix.block_hash)
        self.container.chain_state = chain_state

    def queue(self, tx):
        queued = sendtx.queue_transaction(json.dumps(tx), propagate=False)
        self.assertTrue(queued["ok"], queued)
        self.assertTrue(self.in_mempool(tx))

    def next_block(self, txs):
        return self.block(2, self.head(), txs, PROPOSER_A)

    def built_block(self):
        """The block that the local producer builds from the mempool, not applied.

        A hand-made block has no valid state hash, and the extension path checks it.
        """
        built = []

        def refuse(blk):
            built.append(blk)
            return False

        with patch.object(chain_state, "process_new_block", side_effect=refuse):
            self.mine()
        self.assertEqual(len(built), 1)
        header = built[0].header
        return signed_block(PROPOSER_A, block_number=header.block_number,
                            previous_hash=header.previous_hash,
                            transactions=built[0].transactions,
                            timestamp=header.timestamp, state_hash=header.state_hash)

    def mempool_keys(self):
        return {e["tx_hash"] for e in db.get_mempool_entries()}

    def assert_sealed_gone(self, blk):
        self.assertEqual(self.head(), blk.block_hash, "the block did not become the head")
        sealed = {compute_tx_hash(tx) for tx in blk.transactions}
        left = sealed & self.mempool_keys()
        self.assertFalse(left, f"sealed transactions stay in the mempool: {sorted(left)}")

    def next_sequence(self, address):
        raw = getsequence.execute(f"getsequence {address}", self.container)
        resp = json.loads(raw)
        self.assertEqual(resp["status"], "ok", resp)
        return resp["data"]["sequence_number"]


class TestEveryApplyPathEvicts(SealedEvictionTestCase):
    def setUp(self):
        super().setUp()
        self.a0 = transfer(SK_ALICE, CAROL, 5, 0)
        self.b0 = transfer(SK_BOB, CAROL, 7, 0)
        self.queue(self.a0)
        self.queue(self.b0)
        self.blk = self.built_block()
        self.assertEqual({compute_tx_hash(tx) for tx in self.blk.transactions},
                         {compute_tx_hash(self.a0), compute_tx_hash(self.b0)})
        self.assertEqual(self.mempool_keys(),
                         {compute_tx_hash(self.a0), compute_tx_hash(self.b0)})

    def test_rebuild_path(self):
        self.ingest([self.blk])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assert_sealed_gone(self.blk)

    def test_extension_through_the_commit_protocol(self):
        self.ingest([self.blk])
        with _tau_ready(), quiet(), chain_state._chain_lock:
            self.assertTrue(chain_state._extend_through_commit_protocol(
                [self.blk.block_hash], self.blk.block_hash))
        self.assert_sealed_gone(self.blk)

    def test_direct_process_new_block(self):
        with _tau_ready(), quiet():
            self.assertTrue(chain_state.process_new_block(self.blk))
        self.assert_sealed_gone(self.blk)

    def test_gossip_and_sync_batch(self):
        with quiet():
            self.assertEqual(NetworkService._ingest_blocks([self.blk.to_dict()], "peer"), 1)
        self.assert_sealed_gone(self.blk)

    def test_block_mined_here(self):
        mined = self.mine()
        self.assertIn("block_hash", mined, mined)
        head = db.get_canonical_head()
        self.assertEqual({compute_tx_hash(self.a0), compute_tx_hash(self.b0)},
                         set(head["tx_ids"]))
        self.assertFalse(set(head["tx_ids"]) & self.mempool_keys())


class TestStaleSequenceEviction(SealedEvictionTestCase):
    def test_entry_whose_sequence_the_block_used_goes_away(self):
        # Another transaction of ALICE with the same sequence seals first.
        queued = transfer(SK_ALICE, CAROL, 5, 0)
        sealed = transfer(SK_ALICE, MALLORY, 3, 0)
        behind = transfer(SK_ALICE, CAROL, 1, 1)
        other = transfer(SK_BOB, CAROL, 2, 0)
        for tx in (queued, behind, other):
            self.queue(tx)
        blk = self.next_block([sealed])
        self.ingest([blk])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())

        self.assertEqual(chain_state.get_sequence_number(ALICE), 1)
        self.assertFalse(self.in_mempool(queued))
        self.assertEqual(self.status(queued)["status"], "evicted")
        self.assertTrue(self.in_mempool(behind))
        self.assertTrue(self.in_mempool(other))
        self.assertEqual(self.next_sequence(ALICE), 2)
        self.assertEqual(self.next_sequence(BOB), 1)


class TestForkOnlyStaleRow(SealedEvictionTestCase):
    def test_row_sealed_only_in_a_fork_block_is_evicted(self):
        forked = transfer(SK_ALICE, MALLORY, 3, 0)
        self.queue(forked)
        fork = self.block(2, self.head(), [forked], PROPOSER_B)
        won = self.block(2, self.head(), [transfer(SK_ALICE, CAROL, 5, 0)], PROPOSER_A)
        longer = self.block(3, won.block_hash, [], PROPOSER_A)
        self.ingest([fork, won, longer])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())

        self.assertEqual(self.head(), longer.block_hash)
        self.assertFalse(self.in_mempool(forked))
        self.assertEqual(self.status(forked)["status"], "evicted")


class TestSequenceDuringRebuild(SealedEvictionTestCase):
    """A `sendtx` that runs while the rebuild replays the chain from genesis."""

    def test_replay_does_not_lower_the_admission_sequence(self):
        first = transfer(SK_ALICE, CAROL, 5, 0)
        self.queue(first)
        sealed = self.next_block([first])
        self.ingest([sealed])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(chain_state.get_sequence_number(ALICE), 1)

        reused = transfer(SK_ALICE, MALLORY, 3, 0)
        during = []
        real_engine = chain_state.TauConsensusEngine

        def engine_after_probe(*args, **kwargs):
            # Probe after the replay funded ALICE, so only her sequence decides.
            if not during and chain_state._balances.get(ALICE, 0) > 0:
                during.append(sendtx.queue_transaction(json.dumps(reused), propagate=False))
            return real_engine(*args, **kwargs)

        b2 = self.block(2, self.prefix.block_hash, [], PROPOSER_B)
        b3 = self.block(3, b2.block_hash, [], PROPOSER_B)
        self.ingest([b2, b3])
        with patch.object(chain_state, "TauConsensusEngine", side_effect=engine_after_probe), \
                quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())

        self.assertEqual(self.head(), b3.block_hash)
        self.assertEqual(len(during), 1)
        self.assertFalse(during[0]["ok"], during[0])
        self.assertEqual(during[0]["code"], "INVALID_SEQUENCE")
        self.assertFalse(self.in_mempool(reused))


class TestStaleSequenceRows(SealedEvictionTestCase):
    """`db.remove_mempool_stale_sequences` on rows that admission never writes."""

    def raw_row(self, tx_hash, payload, sender):
        with db._db_lock:
            db._db_conn.execute(
                "INSERT INTO mempool (tx_hash, payload, received_at, sender_pubkey) "
                "VALUES (?, ?, 0, ?)", (tx_hash, payload, sender))
            db._db_conn.commit()

    def test_empty_sequence_map_removes_nothing(self):
        self.queue(transfer(SK_ALICE, CAROL, 5, 0))
        self.assertEqual(db.remove_mempool_stale_sequences({}), 0)
        self.assertEqual(len(self.mempool_keys()), 1)

    def test_unreadable_rows_stay_and_a_legacy_row_is_read(self):
        self.raw_row("a" * 64, "not json", ALICE)
        self.raw_row("b" * 64, "[1, 2]", ALICE)
        legacy = transfer(SK_ALICE, CAROL, 5, 0)
        self.raw_row(compute_tx_hash(legacy), json.dumps(legacy), None)

        self.assertEqual(db.remove_mempool_stale_sequences({ALICE: 1}), 1)
        self.assertEqual(self.mempool_keys(), {"a" * 64, "b" * 64})
        self.assertEqual(db.get_dropped_tx(compute_tx_hash(legacy))["reason"], "evicted")


class TestAdmissionRacesTheBlock(SealedEvictionTestCase):
    """A block that seals the transaction lands while its admission runs."""

    def admit_while_block_lands(self, tx):
        blk = self.next_block([tx])
        import consensus.admission as admission
        real = admission.validate_mempool_admission

        def admit_then_apply(*args, **kwargs):
            verdict = real(*args, **kwargs)
            self.ingest([blk])
            with quiet():
                self.assertTrue(chain_state.maybe_update_canonical_head())
            return verdict

        with patch.object(admission, "validate_mempool_admission", side_effect=admit_then_apply):
            result = sendtx.queue_transaction(json.dumps(tx), propagate=False)
        return blk, result

    def test_sealed_transaction_is_not_queued(self):
        tx = transfer(SK_ALICE, CAROL, 5, 0)
        blk, result = self.admit_while_block_lands(tx)

        self.assertTrue(result["ok"], result)
        self.assertEqual(result["status"], "confirmed")
        self.assertEqual(result["block_hash"], blk.block_hash)
        self.assertEqual(result["block_number"], 2)
        self.assert_sealed_gone(blk)
        self.assertEqual(self.status(tx)["status"], "confirmed")
        self.assertEqual(self.next_sequence(ALICE), 1)

    def test_confirmed_answer_reaches_the_envelope(self):
        tx = transfer(SK_ALICE, CAROL, 5, 0)
        blk = self.next_block([tx])
        confirmed = {"ok": True, "tx_hash": compute_tx_hash(tx), "message": "confirmed",
                     "status": "confirmed", "block_hash": blk.block_hash, "block_number": 2}
        with patch.object(sendtx, "queue_transaction", return_value=confirmed):
            raw = sendtx.execute(f"sendtx {json.dumps(tx)}", self.container)
        data = json.loads(raw)["data"]
        self.assertEqual((data["status"], data["block_hash"], data["block_number"]),
                         ("confirmed", blk.block_hash, 2))

    def test_other_transaction_with_the_same_sequence_is_refused(self):
        tx = transfer(SK_ALICE, CAROL, 5, 0)
        rival = transfer(SK_ALICE, MALLORY, 3, 0)
        blk = self.next_block([rival])
        import consensus.admission as admission
        real = admission.validate_mempool_admission

        def admit_then_apply(*args, **kwargs):
            verdict = real(*args, **kwargs)
            self.ingest([blk])
            with quiet():
                self.assertTrue(chain_state.maybe_update_canonical_head())
            return verdict

        with patch.object(admission, "validate_mempool_admission", side_effect=admit_then_apply):
            result = sendtx.queue_transaction(json.dumps(tx), propagate=False)

        self.assertFalse(result["ok"], result)
        self.assertEqual(result["code"], "INVALID_SEQUENCE")
        self.assertFalse(self.in_mempool(tx))

    def test_entry_left_by_the_race_goes_at_the_next_block(self):
        tx = transfer(SK_ALICE, CAROL, 5, 0)
        blk = self.next_block([tx])
        self.ingest([blk])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        # The row lands after the sweep of its own block.
        db.add_mempool_tx(json.dumps(tx, sort_keys=True, separators=(",", ":")),
                          compute_tx_hash(tx), 0)
        self.assertEqual(self.status(tx)["status"], "queued")

        later = self.block(3, blk.block_hash, [transfer(SK_BOB, CAROL, 1, 0)], PROPOSER_A)
        self.ingest([later])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())

        self.assertFalse(self.in_mempool(tx))
        self.assertEqual(self.status(tx)["status"], "confirmed")
        self.assertEqual(self.next_sequence(ALICE), 1)
