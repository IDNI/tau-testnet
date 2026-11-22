"""Bounty 01, issue #63 (G4): the Tau-form payout rule on the native engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the proof steps a REAL Tau clause through the real policy-evaluation
path, which needs the native bindings the mock job does not have. The
skip is environment-driven, exactly as the other Bounty 01 native suites.

The scenario is the maintainer's official grant example (issue #34's
named case 5, restated for #63's form) expressed as a Tau payout rule —
the strongest form of gmikeyg's W2: the payout policy is not a declared
program the node interprets, it is the owner's own Tau clause, and the
node only builds its inputs, reads its outputs, checks them against the
declared set and caps, and applies the legs.

- A grant account (the rule owner) holds exactly 5,000, stocked by the
  funder. The declared recipient set is {Bob, the funder}; the declared
  caps are 3,500 per execution and 5,000 per period; the book period is
  the grant's four-week accounting window.
- The clause carries the grant's own terms as configuration: anchored
  three weeks in the past (a Dec-1-shaped schedule whose wall-clock
  blocks land in its third week — the anchoring is stated here plainly
  because a native block carries the wall-clock timestamp; the first two
  weeks' branches are the same release arithmetic, carried but not
  landed on), it releases 500 per week cumulatively — computed from the
  block timestamp at i5 minus what the rule already paid at i26 — and
  pays Bob the draw; at the schedule's deadline (anchor + 3 weeks, ~60
  seconds after the test starts) its time condition selects the refund
  leg instead: everything unpaid goes back to the funder.
- A third party submits every execution (anyone may execute — W2). Bob
  draws 500 in each of three settlements (the release schedule is
  cumulative, so the three draws land against the third week's full
  1,500 release; a fourth draw is refused — the release is exhausted).
  After the deadline the third party executes once more, with base 1 —
  the refund amount comes from the clause's state inputs, not from
  anything the submitter supplies — and the funder receives exactly
  3,500. The grant account ends at 0.

A second test pins cap enforcement at engine level: a clause naming a
600 leg under a declared 500 per-execution cap settles nothing — refused
at admission, and refused again at inclusion with admission bypassed.
Assertions are deltas around the measured blocks, so faucet grants at
account creation cannot pollute them.

A further test pins the periods_from anchor on the real engine: a rule
installed now whose periods count from two weeks in the past settles
its execution against anchored period 2 — the book's period total
lands under index 2, not under the install grid's period 0. Its
clause deliberately READS an input stream (i1, the base amount): a
clause that reads no input stream cannot be stepped by the policy
worker at all (the worker's build probe names the case — "clause
cannot be evaluated: it reads no input stream" — and a step attempt
is refused the same way). The constant clauses of the cap and
duplicate tests above never exposed this: every assertion of theirs
is negative, so a step refusal and a book refusal look identical to
them. A positive settlement test has no such cover, so its clause
must be a reading clause, like the grant example's.

A final test pins install-day independence for the grant shape itself
(the FIX-1A proof): the SAME signed grant — the same clause text, the
same caps, periods_from set to the schedule's anchor — installed at two
different block times (its recorded install anchors two weeks and a day,
resp. four days, after the anchor) counts its weeks from the anchor,
not from either install: period_index_at agrees on the two entries at
every probed timestamp and provably differs from what either install
anchor would give, and the money path is identical for both installs —
three 500 draws, a refused fourth, and exactly 3,500 back to the funder
after the deadline, with every settlement recorded under the anchored
grid's period 0.
"""
import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

try:
    import tau_native
    tau_native.load_tau_module()
    _NATIVE_TAU = True
except Exception:
    _NATIVE_TAU = False

import config
import chain_state
import db
import tau_manager
from errors import TauEngineCrash
from bls_keys import SK_ALICE, SK_BOB, SK_CAROL, SK_MALLORY, pubkey_hex, sign_payload
from commands import sendtx, createblock
from consensus.payout_rules import (
    FORM_TAU_RULE,
    PayoutRuleEntry,
    period_index_at,
)

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

FUNDER = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
EXECUTOR = pubkey_hex(SK_CAROL)
OWNER = pubkey_hex(SK_MALLORY)  # the grant account holding the 5,000
OWNER2 = pubkey_hex(0xDA7E)  # a second grant account, stocked the same

WEEK = 604_800
DAY = 86_400
TOTAL = 5000
WEEKLY = 500


def _grant_clause(anchor, bob_idx, funder_idx):
    """The grant's terms as a Tau clause body (sender_policy wraps it).

    Every branch assigns all three leg outputs (o30 count, o31 candidate
    index, o32 amount), so the outputs are fully determined on every
    path. Draws: cumulative release 500/week from the anchor, minus what
    i26 says the rule already paid, capped by the submitted base at i1.
    At/after the deadline: the unpaid remainder to the funder.
    """
    a1 = anchor + WEEK
    a2 = anchor + 2 * WEEK
    deadline = anchor + 3 * WEEK

    def no_legs():
        return ("((o30[t]:bv[64] = { 0 }:bv[64]) "
                "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
                "&& (o32[t]:bv[64] = { 0 }:bv[64]))")

    def one_leg(idx, amount_expr):
        return (f"((o30[t]:bv[64] = {{ 1 }}:bv[64]) "
                f"&& (o31[t]:bv[64] = {{ {idx} }}:bv[64]) "
                f"&& (o32[t]:bv[64] = {amount_expr}))")

    def draw(release):
        return (
            f"((i26[t]:bv[64] < {{ {release} }}:bv[64]) "
            f"? ((i1[t]:bv[64] <= ({{ {release} }}:bv[64] - i26[t]:bv[64])) "
            f"? {one_leg(bob_idx, 'i1[t]:bv[64]')} "
            f": {one_leg(bob_idx, f'({{ {release} }}:bv[64] - i26[t]:bv[64])')}) "
            f": {no_legs()})"
        )

    refund = (
        f"((i26[t]:bv[64] < {{ {TOTAL} }}:bv[64]) "
        f"? {one_leg(funder_idx, f'({{ {TOTAL} }}:bv[64] - i26[t]:bv[64])')} "
        f": {no_legs()})"
    )
    return (
        f"((i5[t]:bv[64] < {{ {deadline} }}:bv[64]) "
        f"? ((i5[t]:bv[64] < {{ {a1} }}:bv[64]) "
        f"? {draw(WEEKLY)} "
        f": ((i5[t]:bv[64] < {{ {a2} }}:bv[64]) "
        f"? {draw(2 * WEEKLY)} "
        f": {draw(3 * WEEKLY)})) "
        f": {refund})"
    )


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestPayoutTauRuleNativeE2E(unittest.TestCase):
    """Full pipeline with a live Tau interpreter (the fee-native pattern)."""

    def setUp(self):
        try:
            iface = tau_native.TauInterface(GENESIS_TAU)
        except TauEngineCrash:
            self.skipTest(
                "native interpreter unavailable in this process (polluted by an "
                "earlier in-process interpreter); run this file on its own"
            )
        self._tmpdir = tempfile.mkdtemp()
        self.test_db = os.path.join(self._tmpdir, "test_payout_tau_native_db.sqlite")
        self.original_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if not config.MINER_PRIVKEY:
            # The CI job's config profile leaves MINER_PRIVKEY unset; the
            # job preamble generates the miner identity into data_local/,
            # so load it with config's own loaders (after set_database_path,
            # whose re-sync would wipe it otherwise) and skip only when the
            # identity genuinely does not exist.
            _priv = config._load_miner_privkey_from_path(
                os.path.join(config.DATA_LOCAL_DIR, "test_miner.key"))
            _pub = config._load_miner_pubkey_from_path(
                os.path.join(config.DATA_LOCAL_DIR, "test_miner.pub"))
            if not _priv or not _pub:
                self.skipTest(
                    "data_local/test_miner.key absent; local miner identity required "
                    "for real PoA mining (see config.DATA_LOCAL_DIR)"
                )
            config.MINER_PRIVKEY = _priv
            config.MINER_PUBKEY = _pub
        if db._db_conn:
            db._db_conn.close()
        db._db_conn = None

        chain_state._balances.clear()
        chain_state._sequence_numbers.clear()
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()

        chain_state._balances[OWNER] = TOTAL  # stocked by the funder
        chain_state._balances[EXECUTOR] = 1000
        chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
        chain_state._lifecycle_manager.recompute_approval_threshold()

        tau_manager.tau_direct_interface = iface
        tau_manager.tau_ready.set()
        self._seed_rule(open(TRANSFER_RULE_PATH).read(), "transfer-rule")
        self._seed_rule(
            chain_state._preprocess_tau_spec_text(
                json.load(open("data/genesis.json"))["consensus_rules"]
            ),
            "genesis-consensus",
        )
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}).start()
        patch("commands.createblock._BLS_AVAILABLE", True).start()
        patch("block.bls_signing_available", return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.verify_block_header", return_value=True).start()
        patch("consensus.engine.TauConsensusEngine.query_eligibility", return_value=True).start()

    def tearDown(self):
        patch.stopall()
        tau_manager.tau_ready.clear()
        tau_manager.tau_direct_interface = None
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        config.set_database_path(self.original_db)

    def _seed_rule(self, rule_text, label):
        out = tau_manager.communicate_with_tau(
            rule_text=rule_text,
            target_output_stream_index=0,
            apply_rules_update=False,
            source=f"seed-{label}",
        )
        self.assertNotIn("error", str(out).lower(), f"seeding {label} failed: {out}")

    def _mine(self):
        out = createblock.create_block_from_mempool()
        self.assertNotIn("error", out, out)
        return out

    def _force_queue(self, blob):
        """Put a signed tx in the mempool WITHOUT admission, to ask what
        inclusion does with it on its own (the isolation-suite pattern)."""
        payload = json.loads(blob)
        tx_hash, raw = sendtx._compute_transaction_message_id(payload)
        db.add_mempool_tx(raw, tx_hash, int(time.time() * 1000))
        return tx_hash

    def _included(self, tx_hash):
        head = db.get_canonical_head_block() or {}
        return tx_hash in (head.get("tx_ids") or [])

    def _execute_tx(self, rule_id, settlement_id, base):
        return json.dumps(sign_payload({
            "sender_pubkey": EXECUTOR,
            "tx_type": "execute_payout_rule",
            "sequence_number": chain_state.get_sequence_number(EXECUTOR),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "payout_rule_id": rule_id.hex(),
            "payout_settlement_id": settlement_id,
            "payout_base_amount": base,
            "fee_limit": "50",
        }, SK_CAROL))

    def _balances(self):
        return {pk: chain_state._balances.get(pk, 0)
                for pk in (OWNER, OWNER2, BOB, FUNDER, EXECUTOR)}

    def test_grant_example_as_a_tau_payout_rule(self):
        start = int(time.time())
        anchor = start - 3 * WEEK + 60
        deadline = anchor + 3 * WEEK
        recipients = tuple(sorted([BOB, FUNDER]))
        entry = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=recipients, legs=(),
            max_per_execution=3500, max_per_period=TOTAL,
            period_seconds=4 * WEEK, period_anchor_ts=anchor, version=1,
            form=FORM_TAU_RULE,
            clause_text=_grant_clause(
                anchor, recipients.index(BOB), recipients.index(FUNDER)),
        )
        chain_state._lifecycle_manager.payout_rules.install(entry, start)
        book = chain_state._lifecycle_manager.payout_rules
        self.assertEqual(book.get(OWNER).form, FORM_TAU_RULE)

        # Three draws of 500, submitted by a third party (anyone may
        # execute): each settles exactly 500 to Bob from the grant
        # account, against the third week's cumulative 1,500 release.
        for k, sid in enumerate(("11" * 32, "22" * 32, "33" * 32)):
            before = self._balances()
            res = sendtx.queue_transaction(
                self._execute_tx(entry.rule_id, sid, WEEKLY), propagate=False)
            self.assertTrue(res["ok"], f"draw {k + 1} rejected: {res}")
            self._mine()
            after = self._balances()
            self.assertEqual(after[BOB] - before[BOB], WEEKLY)
            self.assertEqual(after[OWNER] - before[OWNER], -WEEKLY)
            self.assertLess(after[EXECUTOR], before[EXECUTOR])  # the fee

        # A fourth draw is refused at admission: the release is exhausted
        # (1,500 paid of the 1,500 released), so the clause computes no
        # payment and nothing settles.
        before = self._balances()
        res = sendtx.queue_transaction(
            self._execute_tx(entry.rule_id, "44" * 32, WEEKLY),
            propagate=False)
        self.assertFalse(res["ok"], f"fourth draw admitted: {res}")
        self.assertEqual(self._balances(), before)

        # Past the deadline, the clause's time condition selects the
        # refund leg: a third party executes with base 1 and the funder
        # receives the unpaid remainder — exactly 3,500.
        while time.time() < deadline + 2:
            time.sleep(1)
        before = self._balances()
        res = sendtx.queue_transaction(
            self._execute_tx(entry.rule_id, "55" * 32, 1), propagate=False)
        self.assertTrue(res["ok"], f"refund execution rejected: {res}")
        self._mine()
        after = self._balances()
        self.assertEqual(after[FUNDER] - before[FUNDER], 3500)
        self.assertEqual(after[OWNER] - before[OWNER], -3500)
        self.assertEqual(after[OWNER], 0)
        self.assertEqual(after[BOB], 1500)

        # Re-read the book from the canonical manager: block apply forks
        # the lifecycle manager, so the pre-block object is not the state
        # the settlements landed in.
        book = chain_state._lifecycle_manager.payout_rules
        self.assertEqual(book.period_total(entry.rule_id, 0), TOTAL)
        record = book.settlement(entry.rule_id, bytes.fromhex("55" * 32))
        self.assertIsNotNone(record)
        self.assertEqual(record.total, 3500)

    def test_clause_leg_above_per_execution_cap_settles_nothing(self):
        now = int(time.time())
        clause = (
            "((o30[t]:bv[64] = { 1 }:bv[64]) "
            "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
            "&& (o32[t]:bv[64] = { 600 }:bv[64]))"
        )
        entry = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(BOB,), legs=(),
            max_per_execution=500, max_per_period=0,
            period_seconds=WEEK, period_anchor_ts=now - 100, version=1,
            form=FORM_TAU_RULE, clause_text=clause,
        )
        chain_state._lifecycle_manager.payout_rules.install(entry, now)

        blob = self._execute_tx(entry.rule_id, "66" * 32, 1)
        before = self._balances()
        res = sendtx.queue_transaction(blob, propagate=False)
        self.assertFalse(res["ok"], f"over-cap execution admitted: {res}")
        # Inclusion on its own refuses it too, with admission bypassed.
        forced = self._force_queue(blob)
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion settled a leg above the declared cap")
        after = self._balances()
        self.assertEqual(after[BOB] - before[BOB], 0)
        self.assertEqual(after[OWNER] - before[OWNER], 0)
        book = chain_state._lifecycle_manager.payout_rules
        self.assertFalse(book.is_settled(entry.rule_id, bytes.fromhex("66" * 32)))

    def test_clause_duplicate_candidate_index_settles_nothing(self):
        # A candidate named twice is malformed output, not two legs: the
        # whole execution settles nothing — refused at admission, and
        # refused again at inclusion with admission bypassed. The total
        # (150) is under the declared 500 per-execution cap, so only the
        # duplicate rule can refuse this execution.
        now = int(time.time())
        clause = (
            "((o30[t]:bv[64] = { 2 }:bv[64]) "
            "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
            "&& (o32[t]:bv[64] = { 100 }:bv[64]) "
            "&& (o33[t]:bv[64] = { 0 }:bv[64]) "
            "&& (o34[t]:bv[64] = { 50 }:bv[64]))"
        )
        entry = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(BOB,), legs=(),
            max_per_execution=500, max_per_period=0,
            period_seconds=WEEK, period_anchor_ts=now - 100, version=1,
            form=FORM_TAU_RULE, clause_text=clause,
        )
        chain_state._lifecycle_manager.payout_rules.install(entry, now)

        blob = self._execute_tx(entry.rule_id, "77" * 32, 1)
        before = self._balances()
        res = sendtx.queue_transaction(blob, propagate=False)
        self.assertFalse(res["ok"], f"duplicate-index execution admitted: {res}")
        # Inclusion on its own refuses it too, with admission bypassed.
        forced = self._force_queue(blob)
        self._mine()
        self.assertFalse(self._included(forced),
                         "inclusion settled a duplicate candidate index")
        after = self._balances()
        self.assertEqual(after[BOB] - before[BOB], 0)
        self.assertEqual(after[OWNER] - before[OWNER], 0)
        book = chain_state._lifecycle_manager.payout_rules
        self.assertFalse(book.is_settled(entry.rule_id, bytes.fromhex("77" * 32)))

    def test_anchored_grid_counts_the_settlement_in_period_2(self):
        # periods_from two weeks in the past: the wall-clock execution
        # lands in anchored period 2, while the install-anchored grid
        # would call it period 0. The clause pays a fixed 100 to Bob
        # whenever the submitted base is positive (always true of a
        # valid execution — and the read of i1 is what makes the
        # clause steppable at all; see the module docstring); the
        # settlement must be counted against anchored period 2 —
        # period_total(rule_id, 2) is 100 and period 0 stays empty.
        now = int(time.time())
        clause = (
            "((i1[t]:bv[64] < { 1 }:bv[64]) "
            "? ((o30[t]:bv[64] = { 0 }:bv[64]) "
            "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
            "&& (o32[t]:bv[64] = { 0 }:bv[64])) "
            ": ((o30[t]:bv[64] = { 1 }:bv[64]) "
            "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
            "&& (o32[t]:bv[64] = { 100 }:bv[64])))"
        )
        entry = PayoutRuleEntry(
            owner_pubkey=OWNER, recipients=(BOB,), legs=(),
            max_per_execution=500, max_per_period=500,
            period_seconds=WEEK, period_anchor_ts=now - 100, version=1,
            form=FORM_TAU_RULE, clause_text=clause,
            periods_from_ts=now - 2 * WEEK,
        )
        chain_state._lifecycle_manager.payout_rules.install(entry, now)

        before = self._balances()
        res = sendtx.queue_transaction(
            self._execute_tx(entry.rule_id, "88" * 32, 1), propagate=False)
        self.assertTrue(res["ok"], f"anchored execution rejected: {res}")
        self._mine()
        after = self._balances()
        self.assertEqual(after[BOB] - before[BOB], 100)
        self.assertEqual(after[OWNER] - before[OWNER], -100)
        book = chain_state._lifecycle_manager.payout_rules
        self.assertTrue(book.is_settled(entry.rule_id, bytes.fromhex("88" * 32)))
        self.assertEqual(book.period_total(entry.rule_id, 2), 100)
        self.assertEqual(book.period_total(entry.rule_id, 0), 0)

    def test_grant_weeks_count_from_periods_from_not_from_install(self):
        # FIX-1A: the grant example installed at two different block
        # times, with periods_from set to the schedule's own anchor.
        # The two installs record different install anchors (the anchor
        # + 2 weeks + 1 day, resp. + 4 days — the moments the two
        # installs "happened"), but every period answer counts from the
        # signed periods_from anchor, so the week boundaries and the
        # whole money path are identical for both.
        start = int(time.time())
        anchor = start - 3 * WEEK + 150
        deadline = anchor + 3 * WEEK
        recipients = tuple(sorted([BOB, FUNDER]))
        clause = _grant_clause(
            anchor, recipients.index(BOB), recipients.index(FUNDER))
        installs = (
            (OWNER, anchor + 2 * WEEK + DAY, ("a1", "a2", "a3", "a4", "a5")),
            (OWNER2, anchor + 2 * WEEK + 4 * DAY, ("b1", "b2", "b3", "b4", "b5")),
        )
        chain_state._balances[OWNER2] = TOTAL
        chain_state._balances[EXECUTOR] = 100_000
        book = chain_state._lifecycle_manager.payout_rules
        entries = []
        for owner, install_ts, _sids in installs:
            entry = PayoutRuleEntry(
                owner_pubkey=owner, recipients=recipients, legs=(),
                max_per_execution=3500, max_per_period=TOTAL,
                period_seconds=4 * WEEK, period_anchor_ts=install_ts,
                version=1, form=FORM_TAU_RULE, clause_text=clause,
                periods_from_ts=anchor,
            )
            book.install(entry, install_ts)
            entries.append(entry)

        # Identical week boundaries: at every probed timestamp the two
        # entries name the same period — the one the anchor gives — and
        # at the anchor's own 4-week boundary the anchored index (1)
        # provably differs from what either install anchor would give
        # (0): the grid follows periods_from, not the install day.
        for ts in (anchor - 1, anchor, anchor + WEEK, anchor + 2 * WEEK,
                   anchor + 3 * WEEK, anchor + 4 * WEEK - 1,
                   anchor + 4 * WEEK, anchor + 5 * WEEK, anchor + 8 * WEEK):
            expected = -1 if ts < anchor else (ts - anchor) // (4 * WEEK)
            for entry in entries:
                self.assertEqual(period_index_at(entry, ts), expected,
                                 f"ts={ts} owner={entry.owner_pubkey[:8]}")
        for entry in entries:
            twin = PayoutRuleEntry(
                owner_pubkey=entry.owner_pubkey, recipients=recipients,
                legs=(), max_per_execution=3500, max_per_period=TOTAL,
                period_seconds=4 * WEEK,
                period_anchor_ts=entry.period_anchor_ts, version=1,
                form=FORM_TAU_RULE, clause_text=clause,
            )
            self.assertEqual(
                period_index_at(twin, anchor + 4 * WEEK), 0,
                "install-anchored twin should still be in its period 0")

        # Identical money path: three 500 draws per install, submitted
        # by the third party, each settling exactly 500 to Bob; a
        # fourth draw per install refused (release exhausted).
        for entry, (owner, _ts, sids) in zip(entries, installs):
            for k in range(3):
                before = self._balances()
                res = sendtx.queue_transaction(
                    self._execute_tx(entry.rule_id, sids[k] * 32, WEEKLY),
                    propagate=False)
                self.assertTrue(res["ok"], f"draw {k + 1} rejected: {res}")
                self._mine()
                after = self._balances()
                self.assertEqual(after[BOB] - before[BOB], WEEKLY)
                self.assertEqual(after[owner] - before[owner], -WEEKLY)
            before = self._balances()
            res = sendtx.queue_transaction(
                self._execute_tx(entry.rule_id, sids[3] * 32, WEEKLY),
                propagate=False)
            self.assertFalse(res["ok"], f"fourth draw admitted: {res}")
            self.assertEqual(self._balances(), before)

        # Past the deadline, the refund leg pays the unpaid remainder —
        # exactly 3,500 — back to the funder, for both installs.
        while time.time() < deadline + 2:
            time.sleep(1)
        for entry, (owner, _ts, sids) in zip(entries, installs):
            before = self._balances()
            res = sendtx.queue_transaction(
                self._execute_tx(entry.rule_id, sids[4] * 32, 1),
                propagate=False)
            self.assertTrue(res["ok"], f"refund rejected: {res}")
            self._mine()
            after = self._balances()
            self.assertEqual(after[FUNDER] - before[FUNDER], 3500)
            self.assertEqual(after[owner], 0)

        # Identical book accounting: every settlement of both grants —
        # 1,500 of draws plus the 3,500 refund — is recorded under the
        # anchored grid's period 0, the four-week window from the
        # anchor, on both installs.
        book = chain_state._lifecycle_manager.payout_rules
        for entry in entries:
            self.assertEqual(book.period_total(entry.rule_id, 0), TOTAL)
        self.assertEqual(self._balances()[BOB], 2 * 1500)


if __name__ == "__main__":
    unittest.main()
