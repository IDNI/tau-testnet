"""Admission during a reorg: `reorg_to` replays from genesis, so the state that
admission reads passes through every lower height until the replay ends.
"""
import json
import unittest
from unittest.mock import MagicMock, patch

import chain_state
import db
from commands import checktx, sendtx
from tau_testnet_cli import tx as tx_mod
from test_reorg_mempool_restore import ALICE, CAROL, SK_ALICE, ReorgRestoreTestCase, quiet, transfer


def run_at_replay_height(height, probe, results):
    """Run `probe` when the replay published the state of block `height`."""
    real = chain_state._record_retractable_events

    def hook(block, next_snapshot):
        if block.header.block_number == height + 1 and not results:
            results.append(probe())
        return real(block, next_snapshot)

    return patch.object(chain_state, "_record_retractable_events", hook)


class TestAdmissionDuringReplay(ReorgRestoreTestCase):
    def setUp(self):
        super().setUp()
        # ALICE's next sequence is 1 at the old tip and at the new tip, and 0 at height 1.
        self.spent = transfer(SK_ALICE, CAROL, 5, 0)
        self.adopt_orphan_to_be([self.spent])
        self.next_tx = transfer(SK_ALICE, CAROL, 1, 1)

    def test_replay_does_not_give_the_verdict_of_a_lower_height(self):
        results = []
        probe = lambda: sendtx.queue_transaction(json.dumps(self.next_tx), propagate=False)
        with run_at_replay_height(1, probe, results):
            self.win_with([self.spent])

        self.assertEqual(chain_state.get_sequence_number(ALICE), 1)
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].get("code"), "REORG_IN_PROGRESS", results[0])
        self.assertFalse(self.in_mempool(self.next_tx))

    def test_checktx_is_refused_during_the_replay(self):
        results = []
        probe = lambda: json.loads(checktx.execute(f"checktx {json.dumps(self.next_tx)}", None))
        with run_at_replay_height(1, probe, results):
            self.win_with([self.spent])

        self.assertEqual(results[0]["error"]["code"], "REORG_IN_PROGRESS", results[0])

    def test_sendtx_gives_the_code_in_the_envelope(self):
        results = []
        probe = lambda: json.loads(sendtx.execute(f"sendtx {json.dumps(self.next_tx)}", None))
        with run_at_replay_height(1, probe, results):
            self.win_with([self.spent])

        self.assertEqual(results[0]["error"]["code"], "REORG_IN_PROGRESS", results[0])

    def test_admission_works_again_after_the_reorg(self):
        self.win_with([self.spent])
        result = sendtx.queue_transaction(json.dumps(self.next_tx), propagate=False)
        self.assertTrue(result["ok"], result)
        self.assertTrue(self.in_mempool(self.next_tx))

    def test_orphaned_transaction_comes_back_with_an_even_counter(self):
        start = chain_state.reorg_counter()
        real = sendtx.readmit_orphaned_transactions
        counters = []

        def recording(txs):
            counters.append(chain_state.reorg_counter())
            return real(txs)

        with patch.object(sendtx, "readmit_orphaned_transactions", recording):
            self.win_with()

        self.assertEqual(counters, [start + 2])
        self.assertTrue(self.in_mempool(self.spent))

    def test_reorg_that_starts_during_admission_stops_the_insert(self):
        with patch.object(chain_state, "reorg_counter", side_effect=[0, 2, 2]):
            result = sendtx.queue_transaction(json.dumps(self.next_tx), propagate=False)

        self.assertEqual(result.get("code"), "REORG_IN_PROGRESS", result)
        self.assertFalse(self.in_mempool(self.next_tx))

    def test_reorg_that_starts_during_admission_replaces_a_rejection(self):
        stale = transfer(SK_ALICE, CAROL, 1, 9)
        with patch.object(chain_state, "reorg_counter", side_effect=[0, 1]):
            result = sendtx.queue_transaction(json.dumps(stale), propagate=False)

        self.assertEqual(result.get("code"), "REORG_IN_PROGRESS", result)

    def test_failure_after_the_insert_keeps_its_code(self):
        counter = [0]

        def broadcast_during_a_reorg(*_args):
            counter[0] = 2
            raise RuntimeError("broadcast")

        bus = MagicMock()
        bus.get.return_value.broadcast_transaction.side_effect = broadcast_during_a_reorg
        with patch.object(chain_state, "reorg_counter", side_effect=lambda: counter[0]), \
                patch.object(sendtx, "network_bus", bus):
            result = sendtx.queue_transaction(json.dumps(self.next_tx), propagate=True)

        self.assertEqual(counter[0], 2, "the broadcast did not run")
        self.assertEqual(result.get("code"), "INTERNAL_ERROR", result)
        self.assertTrue(self.in_mempool(self.next_tx))

    def test_rejection_without_a_reorg_keeps_its_code(self):
        stale = transfer(SK_ALICE, CAROL, 1, 9)
        result = sendtx.queue_transaction(json.dumps(stale), propagate=False)
        self.assertEqual(result.get("code"), "INVALID_SEQUENCE", result)


class TestReorgCounter(ReorgRestoreTestCase):
    def setUp(self):
        super().setUp()
        self.adopt_orphan_to_be([])
        self.start = chain_state.reorg_counter()
        self.assertEqual(self.start % 2, 0)
        self.seen = []
        self.real_rebuild = chain_state._rebuild_state_from_blockchain_internal

    def fork(self):
        b2 = self.block(2, self.prefix.block_hash, [], "b" * 96)
        b3 = self.block(3, b2.block_hash, [], "b" * 96)
        self.ingest([b2, b3])
        return b3

    def rebuild_that_fails_first(self, start_block=0, path_hashes=None):
        self.seen.append(chain_state.reorg_counter())
        if len(self.seen) == 1:
            return chain_state.RebuildResult(ok=False, stopped_at_block=2, reason="test")
        return self.real_rebuild(start_block, path_hashes=path_hashes)

    def recording_rebuild(self, start_block=0, path_hashes=None):
        self.seen.append(chain_state.reorg_counter())
        return self.real_rebuild(start_block, path_hashes=path_hashes)

    def assert_window_closed(self, windows=1):
        self.assertEqual(chain_state.reorg_counter(), self.start + 2 * windows)

    def test_counter_is_odd_only_during_the_replay(self):
        tip = self.fork()
        with patch.object(chain_state, "_rebuild_state_from_blockchain_internal",
                          self.recording_rebuild), quiet():
            self.assertTrue(chain_state.reorg_to(tip.block_hash))

        self.assertEqual(self.seen, [self.start + 1])
        self.assert_window_closed()

    def test_failed_replay_stays_odd_through_the_restore_and_ends_even(self):
        tip = self.fork()
        head = self.head()
        with patch.object(chain_state, "_rebuild_state_from_blockchain_internal",
                          self.rebuild_that_fails_first), quiet():
            self.assertFalse(chain_state.reorg_to(tip.block_hash))

        self.assertEqual(self.seen, [self.start + 1, self.start + 1])
        self.assert_window_closed()
        self.assertEqual(self.head(), head)

    def test_failed_save_stays_odd_through_the_restore_and_ends_even(self):
        tip = self.fork()
        with patch.object(chain_state, "_rebuild_state_from_blockchain_internal",
                          self.recording_rebuild), \
                patch.object(db, "save_canonical_state_atomically", side_effect=OSError("disk")), \
                quiet():
            self.assertFalse(chain_state.reorg_to(tip.block_hash))

        self.assertEqual(self.seen, [self.start + 1, self.start + 1])
        self.assert_window_closed()

    def test_exception_in_the_replay_ends_even(self):
        tip = self.fork()
        with patch.object(chain_state, "_rebuild_state_from_blockchain_internal",
                          side_effect=RuntimeError("replay")), quiet():
            with self.assertRaises(RuntimeError):
                chain_state.reorg_to(tip.block_hash)

        self.assert_window_closed()

    def test_reorg_to_the_head_does_not_open_the_window(self):
        self.assertIsNone(chain_state.reorg_to(self.head()))
        self.assert_window_closed(windows=0)


class TestCliRetriesDuringAReorg(unittest.TestCase):
    REFUSED = json.dumps({"status": "error", "error": {"code": "REORG_IN_PROGRESS", "message": "wait"}})
    QUEUED = json.dumps({"status": "ok", "data": {"tx_hash": "ab"}})
    REJECTED = json.dumps({"status": "error", "error": {"code": "INVALID_SEQUENCE", "message": "no"}})

    def submit(self, answers):
        with patch.object(tx_mod.rpc_mod, "send_command", side_effect=answers) as send, \
                patch.object(tx_mod.time, "sleep") as sleep:
            response = tx_mod.submit_tx({"a": 1}, host="h", port=1)
        return response, send, sleep

    def test_refusal_is_sent_again_with_the_same_payload(self):
        response, send, sleep = self.submit([self.REFUSED, self.QUEUED])
        self.assertEqual(response, self.QUEUED)
        self.assertEqual(send.call_args_list[0], send.call_args_list[1])
        self.assertEqual(sleep.call_count, 1)

    def test_other_error_is_not_sent_again(self):
        response, send, sleep = self.submit([self.REJECTED])
        self.assertEqual(response, self.REJECTED)
        self.assertEqual(send.call_count, 1)
        sleep.assert_not_called()

    def test_plain_text_answer_is_not_sent_again(self):
        response, send, _sleep = self.submit(["ERROR: no"])
        self.assertEqual(response, "ERROR: no")
        self.assertEqual(send.call_count, 1)

    def test_retries_stop_and_give_the_last_refusal(self):
        attempts = len(tx_mod.REORG_RETRY_DELAYS) + 1
        response, send, sleep = self.submit([self.REFUSED] * attempts)
        self.assertEqual(response, self.REFUSED)
        self.assertEqual(send.call_count, attempts)
        self.assertEqual([c.args[0] for c in sleep.call_args_list], list(tx_mod.REORG_RETRY_DELAYS))
