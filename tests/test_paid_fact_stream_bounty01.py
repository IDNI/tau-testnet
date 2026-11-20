"""Bounty 01, issue #34 (W5): the paid-for-period fact as a Tau input stream.

gmikeyg's W5 ask is a "paid for this period" fact **other rules can
read**. The fact existed in the standing book (paid_for_period) but no
rule-evaluation path could see it — no stream index, never fed. This
suite pins the fix: the node feeds i17
(tau_defs.STANDING_PAID_STREAM_INDEX) on every transfer evaluation —
"1" when the sender has at least one standing authorization whose
period containing the block timestamp is recorded paid, else "0" —
byte-identically at admission (commands/sendtx.py) and at apply
(consensus/engine.py), with the stream reserved so a sender operation
can never override the node's value.

Covered: the book projection itself (paid / unpaid / none / other
period / other payer / monthly calendar math / supersession and
cancellation leaving history intact / agreement with the
period_index_at + paid_for_period lookup), the apply-side feed read
off the real input maps, a membership-style clause judged on the
stream at engine level (scripted evaluator — the real-Tau form is
tests/test_paid_fact_native.py), and admission parity (the sendtx
overlay feeds the identical value; operations["17"] is refused).
"""
import hashlib
import itertools
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import tau_defs
from block import Block
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.policy_mock import MockPolicyEvaluator
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import clause_body_v1
from consensus.standing_payments import (
    SCHEDULE_DAILY,
    SCHEDULE_MONTHLY,
    SCHEDULE_WEEKLY,
    StandingPaymentBook,
    StandingPaymentEntry,
    period_index_at,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

DAY = 86400
WEEK = 7 * DAY
STREAM = tau_defs.STANDING_PAID_STREAM_INDEX


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


ANCHOR = _ts(2026, 12, 1, 12)   # weekly schedules anchor here
JAN31 = _ts(2026, 1, 31, 12)    # monthly day-31 schedules anchor here

ALICE = "a" * 96
BOB = "b" * 96
CAROL = "c" * 96


def _entry(payer=ALICE, recipient=BOB, amount=500, kind=SCHEDULE_WEEKLY,
           day=0, anchor=ANCHOR, window=2 * DAY, final=0, max_occ=12,
           max_total=0, fee_limit=0, policy_ref=0, catch_up=False,
           version=1):
    return StandingPaymentEntry(
        payer, recipient, amount, kind, day, anchor, window, final,
        max_occ, max_total, fee_limit, policy_ref, catch_up, version,
    )


def _book_with(entry, now):
    book = StandingPaymentBook()
    book.create(entry, now)
    return book


# --- the book projection -------------------------------------------------------


class TestPaidFactProjection(unittest.TestCase):

    def test_no_authorizations_means_unpaid(self):
        book = StandingPaymentBook()
        self.assertFalse(book.has_paid_period_containing(ALICE, ANCHOR))

    def test_created_but_unpaid_means_unpaid(self):
        book = _book_with(_entry(), ANCHOR)
        self.assertFalse(book.has_paid_period_containing(ALICE, ANCHOR))

    def test_paid_period_reads_paid_only_inside_that_period(self):
        entry = _entry()
        book = _book_with(entry, ANCHOR)
        self.assertTrue(book.execute(entry.auth_id, ANCHOR, 10_000).executed)
        self.assertTrue(book.has_paid_period_containing(ALICE, ANCHOR))
        self.assertTrue(book.has_paid_period_containing(ALICE, ANCHOR + WEEK - 1))
        # The NEXT period is a different period, and it is unpaid.
        self.assertFalse(book.has_paid_period_containing(ALICE, ANCHOR + WEEK))
        # Before the first period there is nothing to be paid for.
        self.assertFalse(book.has_paid_period_containing(ALICE, ANCHOR - 1))

    def test_another_payers_fact_does_not_count(self):
        entry = _entry()
        book = _book_with(entry, ANCHOR)
        self.assertTrue(book.execute(entry.auth_id, ANCHOR, 10_000).executed)
        self.assertFalse(book.has_paid_period_containing(CAROL, ANCHOR))

    def test_monthly_period_math_with_clamped_short_month(self):
        entry = _entry(kind=SCHEDULE_MONTHLY, day=31, anchor=JAN31,
                       window=5 * DAY)
        book = _book_with(entry, JAN31)
        self.assertTrue(book.execute(entry.auth_id, JAN31, 10_000).executed)
        # Period 0 runs from Jan 31 to the clamped Feb 28 due date.
        from consensus.standing_payments import due_ts
        feb28 = due_ts(entry, 1)
        self.assertTrue(book.has_paid_period_containing(ALICE, feb28 - 1))
        self.assertFalse(book.has_paid_period_containing(ALICE, feb28))

    def test_superseded_versions_fact_still_counts(self):
        v1 = _entry(amount=500, version=1)
        book = _book_with(v1, ANCHOR)
        self.assertTrue(book.execute(v1.auth_id, ANCHOR, 10_000).executed)
        v2 = _entry(amount=700, version=2)
        book.create(v2, ANCHOR)
        self.assertIsNone(book.get(v1.auth_id))  # superseded, entry gone
        # ...but its paid fact is history and still answers for period 0.
        self.assertTrue(book.has_paid_period_containing(ALICE, ANCHOR + 3600))

    def test_cancelled_authorizations_fact_still_counts(self):
        entry = _entry()
        book = _book_with(entry, ANCHOR)
        self.assertTrue(book.execute(entry.auth_id, ANCHOR, 10_000).executed)
        book.cancel(entry.auth_id, ANCHOR + 60)
        self.assertTrue(book.has_paid_period_containing(ALICE, ANCHOR + 3600))

    def test_projection_agrees_with_period_index_lookup(self):
        entry = _entry()
        book = _book_with(entry, ANCHOR)
        self.assertTrue(book.execute(entry.auth_id, ANCHOR, 10_000).executed)
        for ts in range(ANCHOR - DAY, ANCHOR + 3 * WEEK, 3600 * 7):
            expected = (
                book.paid_for_period(entry.auth_id, period_index_at(entry, ts))
                is not None
            )
            self.assertEqual(
                book.has_paid_period_containing(ALICE, ts), expected, f"ts={ts}")


# --- the apply-side feed + a membership clause at engine level -----------------

HEIGHT = 20
TS = 1_800_000_000
FEE = 7
AMOUNT = 250


def _key(seed):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, VALIDATOR = _key(11111)     # proposer / sole validator
SK_PAYER, PAYER = _key(22222)
SK_RECIPIENT, RECIPIENT = _key(33333)
SK_EXECUTOR, EXECUTOR = _key(55555)
SK_DEST, DEST = _key(66666)

_TX_SEQ = itertools.count()


def _sign(tx, sk):
    tx["signature"] = G2Basic.Sign(
        sk, hashlib.sha256(signing_message_bytes(tx)).digest()
    ).hex()
    return tx


def _lm():
    lm = ConsensusLifecycleManager(active_validators=[VALIDATOR])
    lm.activate_approval_slots()
    return lm


class _Chain:
    """The slice-4 engine harness, with the Tau step inputs captured."""

    def __init__(self, balances, lm=None, ts=TS):
        self.balances = dict(balances)
        self.sequences = {}
        self.lm = lm if lm is not None else _lm()
        self.ts = ts
        self.height = HEIGHT
        self.captured = []

    def apply(self, txs, fee=FEE):
        self.captured = []
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.balances),
                "sequence_numbers": dict(self.sequences),
                "last_transfer_ts": {},
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(VALIDATOR)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash="00" * 32,
            transactions=txs, proposer_pubkey=VALIDATOR, timestamp=self.ts,
        )

        def _fake_multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            self.captured.append(dict(vals))
            amount = int(str(vals.get(1, "0")) or 0)
            return {1: str(amount), 8: "0", 9: str(fee), 5: "1"}

        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, block, parent)
        md = result.next_snapshot.metadata
        self.balances = md["balances"]
        self.sequences = md["sequence_numbers"]
        self.lm = md["lifecycle_manager"]
        self.height += 1
        return result

    def transfer_steps(self, from_addr, to_addr, amount):
        """Captured per-transfer input maps for one (from, to, amount)."""
        return [
            vals for vals in self.captured
            if vals.get(3) == "{ #x" + from_addr + " }:bv[384]"
            and vals.get(4) == "{ #x" + to_addr + " }:bv[384]"
            and vals.get(1) == str(amount)
        ]


def _create_tx(seq, **kw):
    return _sign({
        "tx_id": f"w5-create-{next(_TX_SEQ)}",
        "tx_type": "create_standing_payment",
        "sender_pubkey": PAYER,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_recipient_pubkey": RECIPIENT,
        "standing_amount": AMOUNT,
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": TS - 100,
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": kw.get("max_total", 100000),
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
    }, SK_PAYER)


def _execute_tx(auth_id, seq):
    return _sign({
        "tx_id": f"w5-exec-{next(_TX_SEQ)}",
        "tx_type": "execute_standing_payment",
        "sender_pubkey": EXECUTOR,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "standing_auth_id": auth_id.hex(),
    }, SK_EXECUTOR)


def _transfer_tx(seq, amount=10):
    return _sign({
        "tx_id": f"w5-tr-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": PAYER,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"1": [[PAYER, DEST, str(amount)]]},
    }, SK_PAYER)


def _auth_id(create_tx):
    from consensus.standing_payments import parse_create_standing_payment
    return parse_create_standing_payment(create_tx).auth_id


def _funded_chain():
    return _Chain({VALIDATOR: 0, PAYER: 100000, RECIPIENT: 1000,
                   EXECUTOR: 1000, DEST: 0})


MEMBERSHIP_RULE = (
    "always ( ((i17[t]:bv[64] = { 1 }:bv[64]) || "
    "(i4[t]:bv[384] = { #x" + RECIPIENT + " }:bv[384])) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
)
MEMBERSHIP_BODY = clause_body_v1(MEMBERSHIP_RULE)


def _membership_decide(inputs):
    """The mock reading of MEMBERSHIP_RULE: allow when the standing-paid
    stream is 1, or when the transfer IS the standing settlement (its
    recipient is the authorization's recipient — the dues collector is
    the one payee an unpaid member may still pay). Clause inputs arrive
    bare: a pubkey value keeps its `#x` prefix."""
    if str(inputs.get("i17", "0")).strip() == "1":
        return "1"
    if str(inputs.get("i4", "")).strip().lower() == "#x" + RECIPIENT.lower():
        return "1"
    return "0"


class TestPaidFactAtApply(unittest.TestCase):

    def test_transfer_step_feeds_zero_before_and_one_after_settlement(self):
        chain = _funded_chain()
        create = _create_tx(seq=0)
        result = chain.apply([create])
        self.assertIn(create["tx_id"], result.accepted_tx_ids)
        auth_id = _auth_id(create)

        before = _transfer_tx(seq=chain.sequences.get(PAYER, 0))
        result = chain.apply([before])
        self.assertIn(before["tx_id"], result.accepted_tx_ids)
        steps = chain.transfer_steps(PAYER, DEST, 10)
        self.assertTrue(steps, "the transfer step was not captured")
        self.assertTrue(all(s[STREAM] == "0" for s in steps), steps)

        result = chain.apply([_execute_tx(auth_id, seq=chain.sequences.get(EXECUTOR, 0))])
        self.assertEqual(chain.balances[RECIPIENT], 1000 + AMOUNT)

        after = _transfer_tx(seq=chain.sequences.get(PAYER, 0))
        result = chain.apply([after])
        self.assertIn(after["tx_id"], result.accepted_tx_ids)
        steps = chain.transfer_steps(PAYER, DEST, 10)
        self.assertTrue(steps, "the transfer step was not captured")
        self.assertTrue(all(s[STREAM] == "1" for s in steps), steps)

    def test_membership_clause_refuses_before_and_settles_after(self):
        chain = _funded_chain()
        create = _create_tx(seq=0)
        result = chain.apply([create])
        self.assertIn(create["tx_id"], result.accepted_tx_ids)
        auth_id = _auth_id(create)

        evaluator = MockPolicyEvaluator(pool="apply")
        evaluator.set_verdict(MEMBERSHIP_BODY, _membership_decide)
        sender_policy.set_evaluator("apply", evaluator)
        try:
            chain.lm.rule_offers.accepted_clauses[
                (PAYER, tau_defs.USER_POLICY_STREAM_INDEX)] = MEMBERSHIP_BODY

            refused = _transfer_tx(seq=chain.sequences.get(PAYER, 0))
            result = chain.apply([refused])
            self.assertNotIn(refused["tx_id"], result.accepted_tx_ids)
            self.assertEqual(chain.balances[DEST], 0)

            # The settlement itself passes the clause through its
            # recipient exception, and writes the fact.
            result = chain.apply(
                [_execute_tx(auth_id, seq=chain.sequences.get(EXECUTOR, 0))])
            self.assertEqual(chain.balances[RECIPIENT], 1000 + AMOUNT)

            settled = _transfer_tx(seq=chain.sequences.get(PAYER, 0))
            result = chain.apply([settled])
            self.assertIn(settled["tx_id"], result.accepted_tx_ids)
            self.assertEqual(chain.balances[DEST], 10)
        finally:
            sender_policy.set_evaluator("apply", None)


# --- admission parity ------------------------------------------------------------

class TestPaidFactAtAdmission(unittest.TestCase):
    """The sendtx overlay feeds the identical value (the unification
    pattern of tests/test_custom_inputs.py), and operations["17"] is
    refused as reserved."""

    def setUp(self):
        import importlib
        import config
        import db
        import chain_state
        from commands import sendtx
        importlib.reload(sendtx)
        self._sendtx = sendtx
        self._config = config
        self._db = db
        self._chain_state = chain_state
        from py_ecc.bls import G2Basic as bls
        self._bls = bls
        self._sk = bls.KeyGen(b"w5_sender")
        self._sender = bls.SkToPk(self._sk).hex()
        self._dest = bls.SkToPk(bls.KeyGen(b"w5_dest")).hex()

        self._tmpdir = tempfile.mkdtemp()
        self.test_db = os.path.join(self._tmpdir, "test_w5_admission_db.sqlite")
        self._orig_db_path = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()
        chain_state._balances[self._sender] = 100000

        from commands.sendtx import _get_signing_message_bytes

        def _sign(tx_dict):
            msg_hash = hashlib.sha256(_get_signing_message_bytes(tx_dict)).digest()
            tx_dict["signature"] = bls.Sign(self._sk, msg_hash).hex()
            return json.dumps(tx_dict)
        self._sign = _sign

        patch("commands.sendtx.validate_bls_pubkey", return_value=None).start()
        patch("tau_native.compile_revisions_isolated_subprocess",
              return_value=None).start()
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
        import tau_manager
        patch.object(tau_manager, "tau_test_mode", False).start()
        self.addCleanup(patch.stopall)
        self.addCleanup(self._restore)

    def _restore(self):
        if self._db._db_conn:
            self._db._db_conn.close()
            self._db._db_conn = None
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        self._config.set_database_path(self._orig_db_path)

    def _tx(self, custom=None):
        ops = {"1": [[self._sender, self._dest, "10"]]}
        if custom:
            ops.update(custom)
        return self._sign({
            "tx_type": "user_tx",
            "sender_pubkey": self._sender,
            "sequence_number": self._chain_state.get_sequence_number(self._sender),
            "expiration_time": 9999999999,
            "expire_at_height": 5000,
            "operations": ops,
            "fee_limit": "0",
        })

    def _capture_overlay(self, tx_blob):
        captured = []

        def mock_multi(input_stream_values=None, **kwargs):
            captured.append(dict(input_stream_values or {}))
            return {1: tau_defs.TAU_VALUE_ONE}
        patch("tau_manager.communicate_with_tau", return_value="x1001").start()
        patch("tau_manager.communicate_with_tau_multi",
              side_effect=mock_multi).start()
        patch("tau_manager.tau_ready").start().is_set.return_value = True
        result = self._sendtx.queue_transaction(tx_blob, propagate=False)
        return result, captured

    def _install_paid_fact(self):
        now = int(time.time())
        entry = StandingPaymentEntry(
            payer_pubkey=self._sender, recipient_pubkey=self._dest,
            amount=250, schedule_kind=SCHEDULE_DAILY, signed_day=0,
            anchor_ts=now - 100, window_seconds=3600, final_ts=0,
            max_occurrences=0, max_total=100000, fee_limit=0,
            policy_version_ref=0, allow_catch_up=False, version=1,
        )
        book = self._chain_state._lifecycle_manager.standing_payments
        book.create(entry, now)
        self.assertTrue(book.execute(entry.auth_id, now, 10 ** 9).executed)
        return entry

    def test_overlay_feeds_zero_without_a_fact(self):
        result, captured = self._capture_overlay(self._tx())
        self.assertTrue(result["ok"], f"queue failed: {result}")
        self.assertTrue(captured, "no admission Tau step captured")
        self.assertEqual(captured[0].get(STREAM), "0", captured[0])

    def test_overlay_feeds_one_with_a_paid_fact(self):
        self._install_paid_fact()
        result, captured = self._capture_overlay(self._tx())
        self.assertTrue(result["ok"], f"queue failed: {result}")
        self.assertTrue(captured, "no admission Tau step captured")
        self.assertEqual(captured[0].get(STREAM), "1", captured[0])

    def test_stream_17_as_a_custom_input_is_refused(self):
        result, _ = self._capture_overlay(self._tx(custom={"17": "1"}))
        self.assertFalse(result["ok"], result)
        self.assertIn("reserved", result.get("message", "").lower())


if __name__ == "__main__":
    unittest.main()
