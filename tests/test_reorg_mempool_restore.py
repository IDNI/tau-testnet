"""What `reorg_to` puts back into the mempool from an orphaned branch.

Block building never verifies signatures, so whatever the restore puts back
can be mined as it stands: a forged transaction that rode in on a losing fork
must not get past `sendtx.readmit_orphaned_transactions`.

Mock engine throughout (TAU_FORCE_TEST=1 from conftest, header verification
patched the way test_reorg_deep_chain.py does it); signatures are real BLS.
"""
import contextlib
import hashlib
import io
import json
import os
import sys
import tempfile
import time
import types
import unittest
from unittest.mock import MagicMock, patch

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import config
import db
import chain_state
import tau_manager
from py_ecc.bls import G2Basic
from block import Block, compute_tx_hash
from chain_state import GENESIS_ADDRESS
from commands import gettxstatus, sendtx
from consensus.lanes import LANE_FAST, LANE_SLOW
from consensus.tx_signing import signing_message_bytes

BASE_TS = 1_700_000_000

SK_ALICE, SK_BOB, SK_STRANGER = 11111, 22222, 55555
ALICE = G2Basic.SkToPk(SK_ALICE).hex()
BOB = G2Basic.SkToPk(SK_BOB).hex()
CAROL = G2Basic.SkToPk(33333).hex()
MALLORY = G2Basic.SkToPk(66666).hex()
FUNDING = 3000


def sign(tx, sk):
    tx["signature"] = G2Basic.Sign(sk, hashlib.sha256(signing_message_bytes(tx)).digest()).hex()
    return tx


def transfer(sk, to, amount, seq, *, signer=None, **overrides):
    """A transfer from the key `sk`'s account, signed by `signer` (default: `sk`)."""
    sender = G2Basic.SkToPk(sk).hex()
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "operations": {"1": [[sender, to, str(amount)]]},
        "fee_limit": "0",
    }
    tx.update(overrides)
    return sign(tx, signer if signer is not None else sk)


def dummy_signed(sender, seq, to, amount):
    return {
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "operations": {"1": [[sender, to, str(amount)]]},
        "fee_limit": "0",
        "signature": "dummy_signature_for_testing",
    }


@contextlib.contextmanager
def quiet():
    with contextlib.redirect_stdout(io.StringIO()):
        yield


def _echo_multi(**kw):
    vals = kw.get("input_stream_values") or {}
    return {1: str(vals.get(1, "0")), 5: "1", 8: "0", 9: "0"}


class ReorgRestoreTestCase(unittest.TestCase):
    """Block 1 funds ALICE and BOB from the genesis account (shared prefix).
    Block 2 is the one that gets orphaned; the winning branch is two blocks
    long, so the node ends up at #3 and the next block is #4."""

    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(fd)
        self.original_db_path = config.STRING_DB_PATH
        config.set_database_path(self.db_path)

        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db._db_conn = None
        db.init_db()
        db.clear_mempool()
        chain_state.load_genesis("data/genesis.json")
        chain_state._genesis_accounts_state = {GENESIS_ADDRESS: chain_state.GENESIS_BALANCE}
        chain_state._balances[GENESIS_ADDRESS] = chain_state.GENESIS_BALANCE

        self.original_auto_faucet = getattr(config, "TESTNET_AUTO_FAUCET", False)
        config.TESTNET_AUTO_FAUCET = False
        self.original_miner = config.MINER_PRIVKEY
        config.MINER_PRIVKEY = "11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09"

        self.patches = [
            patch('consensus.engine.TauConsensusEngine.verify_block_header', return_value=True),
            patch('consensus.engine.TauConsensusEngine.query_eligibility', return_value=True),
            patch.object(tau_manager.tau_ready, 'wait', return_value=False),
        ]
        for p in self.patches:
            p.start()
        self.genesis_hash = db.get_genesis_hash()
        self.container = types.SimpleNamespace(db=db)

        self.prefix = self.block(1, self.genesis_hash, [
            dummy_signed(GENESIS_ADDRESS, 0, ALICE, FUNDING),
            dummy_signed(GENESIS_ADDRESS, 1, BOB, FUNDING),
        ], "a" * 96)
        self.ingest([self.prefix])

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()
        config.MINER_PRIVKEY = self.original_miner
        config.TESTNET_AUTO_FAUCET = self.original_auto_faucet
        config.set_database_path(self.original_db_path)
        if getattr(db, '_db_conn', None) is not None:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.db_path):
            os.remove(self.db_path)

    @staticmethod
    def block(number, prev, txs, proposer):
        return Block.create(block_number=number, previous_hash=prev, transactions=txs,
                            proposer_pubkey=proposer, timestamp=BASE_TS + number)

    def ingest(self, blocks):
        for blk in blocks:
            self.assertEqual(chain_state.ingest_block(blk).status, 'added')

    def head(self):
        return db.get_canonical_head()['block_hash']

    def adopt_orphan_to_be(self, txs):
        """Make block 2, carrying `txs`, the canonical head."""
        self.orphan = self.block(2, self.prefix.block_hash, txs, "a" * 96)
        self.ingest([self.orphan])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), self.orphan.block_hash)

    def win_with(self, txs_in_b2=()):
        """Fork off block 1 with a longer branch; the node reorgs onto it."""
        b2 = self.block(2, self.prefix.block_hash, list(txs_in_b2), "b" * 96)
        b3 = self.block(3, b2.block_hash, [], "b" * 96)
        self.ingest([b2, b3])
        with quiet():
            self.assertTrue(chain_state.maybe_update_canonical_head())
        self.assertEqual(self.head(), b3.block_hash)

    def reorg(self, orphaned_txs, winning_txs=()):
        self.adopt_orphan_to_be(orphaned_txs)
        self.win_with(winning_txs)

    def mine(self):
        from commands import createblock
        mock_tau = MagicMock()
        mock_tau.tau_ready.is_set.return_value = True
        mock_tau.communicate_with_tau.return_value = "100"
        mock_tau.communicate_with_tau_multi.side_effect = _echo_multi
        # Whatever validator the genesis in use names; header proofs are patched.
        validators = sorted(chain_state._lifecycle_manager.active_validators)
        with patch("commands.createblock.tau_manager", mock_tau), \
                patch("consensus.engine.tau_manager", mock_tau), \
                patch("chain_state.tau_manager", mock_tau), \
                patch.object(config, "MINER_PUBKEY", validators[0] if validators else config.MINER_PUBKEY), \
                quiet():
            return createblock.create_block_from_mempool()

    def status(self, tx):
        raw = gettxstatus.execute(f"gettxstatus {compute_tx_hash(tx)}", self.container)
        resp = json.loads(raw)
        self.assertEqual(resp["status"], "ok", resp)
        return resp["data"]

    def in_mempool(self, tx):
        return db.get_mempool_entry(compute_tx_hash(tx)) is not None

    def row(self, tx):
        with db._db_lock:
            return db._db_conn.execute(
                "SELECT fee_limit, estimated_fee, lane, status FROM mempool WHERE tx_hash = ?",
                (compute_tx_hash(tx),),
            ).fetchone()


class TestOrphanedTransactionsAreReadmitted(ReorgRestoreTestCase):
    def test_forged_transaction_is_not_restored_or_mined(self):
        # ALICE's account, a stranger's signature.
        forged = transfer(SK_ALICE, MALLORY, 500, 0, signer=SK_STRANGER)
        self.reorg([forged])
        self.assertEqual(chain_state.get_balance(MALLORY), 0, "the reorg rolled the forgery back")

        self.assertFalse(self.in_mempool(forged), "a forged transaction came back through the reorg")
        status = self.status(forged)
        self.assertEqual(status["status"], "rejected")
        self.assertEqual(status["reason"], "INVALID_SIGNATURE")

        head_before = self.head()
        mined = self.mine()
        self.assertNotIn("block_hash", mined, mined)
        self.assertEqual(self.head(), head_before)
        self.assertEqual(chain_state.get_balance(MALLORY), 0)

    def test_genuine_transaction_is_restored_and_mined(self):
        genuine = transfer(SK_ALICE, CAROL, 5, 0)
        self.reorg([genuine])
        self.assertEqual(chain_state.get_balance(CAROL), 0)

        self.assertTrue(self.in_mempool(genuine))
        self.assertEqual(self.status(genuine)["status"], "queued")
        mined = self.mine()
        self.assertIn("block_hash", mined, mined)
        self.assertIn(compute_tx_hash(genuine), db.get_canonical_head()["tx_ids"])
        self.assertEqual(chain_state.get_balance(CAROL), 5)

    def test_transaction_that_is_also_on_the_winning_branch_is_not_restored(self):
        shared = transfer(SK_ALICE, CAROL, 5, 0)
        self.reorg([shared], winning_txs=[shared])
        self.assertEqual(chain_state.get_balance(CAROL), 5)
        self.assertFalse(self.in_mempool(shared))
        self.assertIsNone(db.get_dropped_tx(compute_tx_hash(shared)))
        self.assertEqual(self.status(shared)["status"], "confirmed")

    def test_sequence_the_winning_branch_used_is_stale(self):
        lost = transfer(SK_ALICE, CAROL, 5, 0)
        won = transfer(SK_ALICE, MALLORY, 7, 0)
        self.reorg([lost], winning_txs=[won])
        self.assertEqual(chain_state.get_sequence_number(ALICE), 1)

        self.assertFalse(self.in_mempool(lost))
        status = self.status(lost)
        self.assertEqual((status["status"], status["reason"]), ("rejected", "INVALID_SEQUENCE"))

    def test_orphaned_run_is_kept_behind_a_transaction_already_pending(self):
        t0, t1 = transfer(SK_ALICE, CAROL, 1, 0), transfer(SK_ALICE, CAROL, 2, 1)
        t2 = transfer(SK_ALICE, CAROL, 3, 2)
        self.adopt_orphan_to_be([t0, t1])
        # Admitted against the old chain, where ALICE's next sequence is 2.
        queued = sendtx.queue_transaction(json.dumps(t2), propagate=False)
        self.assertTrue(queued["ok"], queued)
        self.win_with()

        for tx in (t0, t1, t2):
            self.assertTrue(self.in_mempool(tx), f"seq {tx['sequence_number']} was dropped")
        mined = self.mine()
        self.assertIn("block_hash", mined, mined)
        self.assertEqual([tx["sequence_number"] for tx in db.get_canonical_head()["transactions"]],
                         [0, 1, 2])
        self.assertEqual(chain_state.get_balance(CAROL), 6)

    def test_forgery_in_front_of_a_genuine_transaction_takes_it_down_too(self):
        forged = transfer(SK_ALICE, MALLORY, 500, 0, signer=SK_STRANGER)
        behind = transfer(SK_ALICE, CAROL, 5, 1)
        self.reorg([forged, behind])

        self.assertFalse(self.in_mempool(forged))
        self.assertFalse(self.in_mempool(behind))
        self.assertEqual(self.status(forged)["reason"], "INVALID_SIGNATURE")
        status = self.status(behind)
        self.assertEqual((status["status"], status["reason"]), ("rejected", "INVALID_SEQUENCE"))

    def test_transaction_past_its_height_deadline_is_dropped(self):
        # Valid while block 2 is the tip's child; dead once the next block is 4.
        late = transfer(SK_ALICE, CAROL, 5, 0, expire_at_height=4)
        self.adopt_orphan_to_be([late])
        self.assertEqual(chain_state.get_balance(CAROL), 5)
        self.win_with()

        self.assertFalse(self.in_mempool(late))
        status = self.status(late)
        self.assertEqual((status["status"], status["reason"]), ("expired", "TX_EXPIRED"))

    def test_transaction_past_its_wall_clock_deadline_is_dropped(self):
        # After the old block's timestamp, before now.
        stale = transfer(SK_ALICE, CAROL, 5, 0, expiration_time=1_750_000_000)
        self.reorg([stale])

        self.assertFalse(self.in_mempool(stale))
        status = self.status(stale)
        self.assertEqual((status["status"], status["reason"]), ("expired", "TX_EXPIRED"))

    def test_full_mempool_stops_the_restore_and_evicts_nothing(self):
        resident = dummy_signed("d" * 96, 0, CAROL, 1)
        resident_hash = compute_tx_hash(resident)
        a0, a1 = transfer(SK_ALICE, CAROL, 1, 0), transfer(SK_ALICE, CAROL, 2, 1)
        b0 = transfer(SK_BOB, CAROL, 3, 0)
        self.adopt_orphan_to_be([a0, a1, b0])
        db.add_mempool_tx(json.dumps(resident), resident_hash, int(time.time() * 1000))
        with patch.object(config, "MAX_MEMPOOL_TXS", 2):
            self.win_with()

        self.assertIsNotNone(db.get_mempool_entry(resident_hash), "restore evicted a resident row")
        self.assertTrue(self.in_mempool(a0))
        self.assertEqual(db.count_mempool_txs(), 2)
        for tx in (a1, b0):
            self.assertFalse(self.in_mempool(tx))
            status = self.status(tx)
            self.assertEqual((status["status"], status["reason"]), ("evicted", "MEMPOOL_FULL"))

    def test_only_the_first_few_orphaned_transactions_are_verified(self):
        txs = [transfer(SK_ALICE, CAROL, 1, seq) for seq in range(4)]
        self.adopt_orphan_to_be(txs)
        with patch.object(config, "REORG_RESTORE_MAX_VERIFY", 2), \
                patch.object(sendtx, "verify_tx_signature",
                             wraps=sendtx.verify_tx_signature) as verify:
            self.win_with()

        self.assertEqual(verify.call_count, 2)
        self.assertTrue(self.in_mempool(txs[0]) and self.in_mempool(txs[1]))
        for tx in txs[2:]:
            self.assertFalse(self.in_mempool(tx))
            status = self.status(tx)
            self.assertEqual((status["status"], status["reason"]), ("evicted", "RESTORE_LIMIT"))


class TestReadmitDirectly(ReorgRestoreTestCase):
    """The function `reorg_to` calls, with no fork around it."""

    def test_restored_rows_keep_their_fee_limit_and_lane(self):
        plain = transfer(SK_ALICE, CAROL, 1, 0, fee_limit="7")
        rule = transfer(SK_ALICE, CAROL, 1, 1, fee_limit="3")
        rule["operations"]["0"] = "always (o30[t]:bv[24] = i31[t]:bv[24])."
        sign(rule, SK_ALICE)

        result = sendtx.readmit_orphaned_transactions([plain, rule])

        self.assertEqual(result["dropped"], {})
        self.assertEqual(result["restored"], [compute_tx_hash(plain), compute_tx_hash(rule)])
        plain_row, rule_row = self.row(plain), self.row(rule)
        self.assertEqual((plain_row[0], plain_row[1], plain_row[2]), (7, 0, LANE_FAST))
        self.assertEqual((rule_row[0], rule_row[1], rule_row[2]), (3, 0, LANE_SLOW))

    def test_slow_lane_quota_is_honoured_without_evicting(self):
        resident_rule = transfer(SK_BOB, CAROL, 1, 0)
        resident_rule["operations"]["0"] = "always (o30[t]:bv[24] = i31[t]:bv[24])."
        sign(resident_rule, SK_BOB)
        db.add_mempool_tx(json.dumps(resident_rule), compute_tx_hash(resident_rule),
                          int(time.time() * 1000), lane=LANE_SLOW)
        rule = transfer(SK_ALICE, CAROL, 1, 0)
        rule["operations"]["0"] = "always (o32[t]:bv[24] = i33[t]:bv[24])."
        sign(rule, SK_ALICE)
        plain = transfer(SK_BOB, CAROL, 1, 1)

        # 10 slots leave the slow lane a quota of one, which the resident rule holds.
        with patch.object(config, "MAX_MEMPOOL_TXS", 10):
            result = sendtx.readmit_orphaned_transactions([rule, plain])

        self.assertEqual(result["dropped"], {compute_tx_hash(rule): "MEMPOOL_FULL"})
        self.assertEqual(result["restored"], [compute_tx_hash(plain)])
        self.assertTrue(self.in_mempool(resident_rule))
        self.assertFalse(self.in_mempool(rule))

    def test_non_transactions_are_skipped_and_nothing_raises(self):
        genuine = transfer(SK_ALICE, CAROL, 1, 0)
        result = sendtx.readmit_orphaned_transactions(
            ["a" * 64, None, {"sender_pubkey": 5}, {}, genuine])
        self.assertEqual(result["restored"], [compute_tx_hash(genuine)])
        self.assertEqual(len(result["dropped"]), 2)
        self.assertTrue(self.in_mempool(genuine))

    def test_restore_never_compiles_a_rule(self):
        """A consensus_rule_update is admitted with its staging compile skipped:
        the compile runs in a subprocess for up to the admission budget, under
        the chain lock."""
        update = {
            "tx_type": "consensus_rule_update",
            "sender_pubkey": ALICE,
            "sequence_number": 0,
            "expiration_time": 9999999999,
            "expire_at_height": 5000,
            "fee_limit": "0",
            "rule_revisions": ["always ( o6[t]:bv[16] = { 0 }:bv[16] )."],
            "activate_at_height": 1000,
        }
        sign(update, SK_ALICE)
        import tau_native
        import consensus.admission as admission
        with patch("consensus.admission._open_governance_admission", return_value=True), \
                patch.object(tau_manager.tau_ready, "is_set", return_value=True), \
                patch.object(tau_native, "compile_revisions_isolated_subprocess",
                             return_value=None) as compile_, \
                patch.object(admission, "validate_mempool_admission",
                             wraps=admission.validate_mempool_admission) as validate:
            result = sendtx.readmit_orphaned_transactions([update])

        self.assertEqual(result["dropped"], {})
        self.assertEqual(result["restored"], [compute_tx_hash(update)])
        compile_.assert_not_called()
        self.assertTrue(validate.called)
        self.assertTrue(all(c.kwargs.get("compile_rules") is False for c in validate.call_args_list))
        self.assertEqual(self.row(update)[2], LANE_SLOW)


class TestAdmissionCompileSwitch(unittest.TestCase):
    def _admission(self, **kwargs):
        from consensus.admission import validate_mempool_admission, TipAdmissionView
        view = MagicMock(spec=TipAdmissionView)
        view.active_validators = {"a" * 96}
        view.next_block_height = 50
        view.current_consensus_rules = "o6\no7\n"
        view.host_contract = {}
        view.get_update_lifecycle_state.return_value = None
        tx = {
            "tx_type": "consensus_rule_update",
            "expire_at_height": 5000,
            "sender_pubkey": "a" * 96,
            "rule_revisions": ["always ( o6[t]:bv[16] = { 0 }:bv[16] )."],
            "activate_at_height": 100,
        }
        return validate_mempool_admission(tx, view, **kwargs)

    def test_compile_rules_false_skips_the_isolated_compile(self):
        import tau_native
        with patch.object(tau_manager.tau_ready, "is_set", return_value=True), \
                patch.object(tau_native, "compile_revisions_isolated_subprocess",
                             return_value=None) as compile_:
            self.assertTrue(self._admission(compile_rules=False).is_valid)
        compile_.assert_not_called()

    def test_default_still_compiles(self):
        import tau_native
        with patch.object(tau_manager.tau_ready, "is_set", return_value=True), \
                patch.object(tau_native, "compile_revisions_isolated_subprocess",
                             return_value=None) as compile_:
            self.assertTrue(self._admission().is_valid)
        compile_.assert_called_once()


if __name__ == '__main__':
    unittest.main()
