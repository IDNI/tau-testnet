"""Bounty 03, issues #47 + #76 — FIX B03-1: the recipient-controls native
suite expanded to every named case, on the native tau-lang engine.

tests/test_recipient_controls_native.py proves four cases on the real
engine. This file is its expansion, on a successor branch of PR #140: the
same boot harness and the same clause bodies, widened until every case the
two issues name has a native counterpart with the real PolicyEvaluator
making the verdict —

  #47: allow-list admission + apply (listed / unlisted / no fee), the
       neutral default (no clause; a clause that never reads the hold),
       batch atomicity, one rule judged in its own direction only,
       the self-transfer exemption;
  #76: the 600-second cap at its exact boundary (pre-flight) and in real
       parks on both sides of it, cap 0 in both units, the block cap,
       cross-unit refusal (a height park is never measured in seconds),
       per-branch caps, retract never gated, release never re-checked,
       replay determinism (proven cross-node in the two-node file —
       see the NOTE in TestNeutralAndExemptionsNative for why no
       from-0 rebuild test lives in this harness);
  plus the surfaces around them: the CLI-composed clauses installed
  verbatim, the deploy screens (unit-blind, wrong width, pre-activation),
  the gate inert before activation, and registry tampering (the admission
  source altered — the apply seam still refuses, nothing settles).

Exact cap boundaries are pinned through the node's own pre-flight
(getrecipientpolicy takes the hold as an explicit argument, so 600 vs 601
is deterministic there); real parks use the same safe margins the
four-case suite uses (540 s in, 700 s out; height parks keep two blocks
of slack against the height the park is applied at).

Kept in its own file so the real-Tau CI job can register exactly this
file beside the four-case suite; the skip is environment-driven exactly
as there — the bindings are present in the real-Tau job's image and the
skip lifts. Everywhere else it skips.
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
from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, pubkey_hex, sign_payload
from commands import createblock, getrecipientpolicy, sendtx
from consensus.retractable import parse_retractable_transfer
from tau_testnet_cli import tx as cli_tx
from tau_testnet_cli.cli import (
    compose_allowlist_clause,
    compose_combined_clause,
    compose_max_hold_clause,
)

GENESIS_TAU = os.path.join(project_root, "genesis.tau")
TRANSFER_RULE_PATH = os.path.join(project_root, "rules", "04_handle_valid_transfer.tau")

SENDER = pubkey_hex(SK_ALICE)
RECIPIENT = pubkey_hex(SK_BOB)
STRANGER = pubkey_hex(SK_MALLORY)

# The four-case suite's canonical bodies, unchanged.
ALLOWLIST_BODY = (
    "(i16[t]:bv[64] = { #x0000 }:bv[64] || "
    "i3[t]:bv[384] = { #x" + SENDER + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
)

CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0258 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

# The same allow-list admitting both known payers.
ALLOWLIST_TWO_BODY = (
    "(i16[t]:bv[64] = { #x0000 }:bv[64] || "
    "i3[t]:bv[384] = { #x" + SENDER + " }:bv[384] || "
    "i3[t]:bv[384] = { #x" + STRANGER + " }:bv[384]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
)

# Per-branch caps: each unit capped alone, the other branch uncapped.
SECONDS_ONLY_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0258 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

BLOCKS_ONLY_BODY = (
    "((i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

# Admits only the owner's own outgoing branch; every inbound context —
# final payment or park — is refused. Inbound-capable (it reads i16).
BLOCK_INBOUND_BODY = (
    "(i16[t]:bv[64] = { #x0000 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000000 }:bv[24])"
)

# A constant verdict that reads neither i16 nor i17: not inbound-capable,
# so the gate must never consult it (the mock suite's BLOCKALL_BODY).
NOT_INBOUND_BODY = "(o5[t]:bv[24] = { #x000000 }:bv[24])"

# Deploy-screen rules (full "always ( ... )." texts, as a wallet submits).
CAP_RULE = "always ( %s )." % CAP_BODY
BLIND_RULE = (
    "always ( (i17[t]:bv[64] > { #x0258 }:bv[64]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
WRONG_WIDTH_RULE = (
    "always ( (i17[t]:bv[32] > { #x0258 }:bv[32]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)


class _RecipientNativeHarness:
    """The four-case suite's boot, verbatim in pattern: a real
    TauInterface, a throwaway database, genesis loaded, the miner
    identity installed where createblock reads it, and — unless the
    class opts out — recipient controls activated through the manager's
    own one-way switch."""

    ACTIVATE = True

    def setUp(self):
        try:
            iface = tau_native.TauInterface(GENESIS_TAU)
        except TauEngineCrash:
            self.skipTest(
                "native interpreter unavailable in this process (polluted by an "
                "earlier in-process interpreter); run this file on its own"
            )
        self._tmpdir = tempfile.mkdtemp()
        self.test_db = os.path.join(self._tmpdir, "test_recipient_expand_db.sqlite")
        self.original_db = config.STRING_DB_PATH
        config.set_database_path(self.test_db)
        if not config.MINER_PRIVKEY:
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

        chain_state._balances[SENDER] = 100000
        chain_state._balances[STRANGER] = 100000
        chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY.lower()}
        chain_state._lifecycle_manager.recompute_approval_threshold()
        if self.ACTIVATE:
            chain_state._lifecycle_manager.activate_recipient_policy()

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

    # --- helpers (the four-case suite's, plus park/deploy variants) ----

    def _seed_rule(self, rule_text, label):
        out = tau_manager.communicate_with_tau(
            rule_text=rule_text,
            target_output_stream_index=0,
            apply_rules_update=False,
            source=f"seed-{label}",
        )
        self.assertNotIn("error", str(out).lower(), f"seeding {label} failed: {out}")

    def _install_clause(self, recipient, body):
        lm = chain_state._lifecycle_manager
        lm.rule_offers.accepted_clauses[(recipient.lower(), 5)] = body
        with db._db_lock:
            db._insert_clause_rows([{
                "acceptor_pubkey": recipient.lower(),
                "target_stream": 5,
                "clause_body": body,
            }])
            db._db_conn.commit()

    def _head(self):
        head = db.get_canonical_head_block()
        return int(head["header"]["block_number"]) if head else 0

    def _escrow_total(self):
        # Re-fetched per read: a block commit replaces the book object.
        return chain_state._lifecycle_manager.retractable_transfers.escrow_total()

    def _queue_transfer(self, sender, to, amount, sk):
        tx = json.dumps(sign_payload({
            "sender_pubkey": sender,
            "sequence_number": chain_state.get_sequence_number(sender),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[sender, to, str(amount)]]},
            "fee_limit": "50",
        }, sk))
        return sendtx.queue_transaction(tx, propagate=False)

    def _transfer(self, sender, to, amount, sk):
        res = self._queue_transfer(sender, to, amount, sk)
        self.assertTrue(res["ok"], f"transfer rejected: {res}")
        block_res = createblock.create_block_from_mempool()
        self.assertEqual(len(block_res.get("transactions", [])), 1, block_res)
        return block_res

    def _park(self, sender, to, amount, sk, **release):
        return self._park_full(sender, to, amount, sk, **release)[0]

    def _park_full(self, sender, to, amount, sk, expire_blocks=50,
                   seq_offset=0, **release):
        payload = cli_tx.build_retractable_transfer_tx(
            sender_pubkey=sender,
            sequence_number=(chain_state.get_sequence_number(sender)
                             + seq_offset),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=self._head() + expire_blocks,
            recipient_pubkey=to, amount=amount, fee_limit="1000", **release)
        res = sendtx.queue_transaction(
            json.dumps(sign_payload(payload, sk)), propagate=False)
        return res, payload

    def _mine(self, expected_txs=None):
        block_res = createblock.create_block_from_mempool()
        if expected_txs is not None:
            self.assertEqual(
                len(block_res.get("transactions", [])), expected_txs, block_res)
        return block_res

    def _seal_empty(self, n=1):
        for _ in range(n):
            res = createblock.create_block_from_mempool(allow_empty=True)
            self.assertIn("block_hash", res, res)

    def _preflight(self, hold, unit, sender=SENDER, recipient=RECIPIENT,
                   amount=100):
        pre = json.loads(getrecipientpolicy.execute(
            f"getrecipientpolicy {recipient} {sender} {amount} {hold} {unit}",
            None))
        self.assertEqual(pre["status"], "ok", pre)
        return pre["data"]["evaluation"]

    def _deploy_rule(self, sender, rule_text, sk):
        tx = json.dumps(sign_payload({
            "sender_pubkey": sender,
            "sequence_number": chain_state.get_sequence_number(sender),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"0": rule_text},
            "fee_limit": "50",
        }, sk))
        return sendtx.queue_transaction(tx, propagate=False)

    def _warm(self):
        """One plain transfer so the tip's timestamp sits near the wall
        clock and the recipient exists before measurements."""
        self._transfer(SENDER, RECIPIENT, 1, SK_ALICE)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestPreflightCapBoundariesNative(_RecipientNativeHarness,
                                       unittest.TestCase):
    """#76.2/#76.5 at the exact boundary, through the node's own
    pre-flight: the hold is an explicit argument, so cap and cap+1 are
    deterministic — the same evaluation admission and apply perform."""

    def setUp(self):
        super().setUp()
        self._install_clause(RECIPIENT, CAP_BODY)
        self._warm()

    # -- seconds branch (cap 600) --

    def test_preflight_seconds_hold_zero_admitted(self):
        ev = self._preflight(0, "seconds")
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_seconds_hold_one_admitted(self):
        ev = self._preflight(1, "seconds")
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_seconds_hold_599_admitted(self):
        ev = self._preflight(599, "seconds")
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_seconds_hold_600_at_cap_admitted(self):
        ev = self._preflight(600, "seconds")
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_seconds_hold_601_refused_with_cap_600(self):
        ev = self._preflight(601, "seconds")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_seconds"], 600, ev)
        self.assertEqual(ev["cap_kind"], "threshold", ev)

    def test_preflight_seconds_hold_3600_refused_with_cap_600(self):
        ev = self._preflight(3600, "seconds")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_seconds"], 600, ev)

    def test_preflight_seconds_hold_day_refused_with_cap_600(self):
        ev = self._preflight(86400, "seconds")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_seconds"], 600, ev)

    # -- blocks branch (cap 100) --

    def test_preflight_blocks_hold_zero_admitted(self):
        ev = self._preflight(0, "blocks")
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_blocks_hold_99_admitted(self):
        ev = self._preflight(99, "blocks")
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_blocks_hold_100_at_cap_admitted(self):
        ev = self._preflight(100, "blocks")
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_blocks_hold_101_refused_with_cap_100(self):
        ev = self._preflight(101, "blocks")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_blocks"], 100, ev)
        self.assertNotIn("max_hold_seconds", ev, ev)

    def test_preflight_blocks_hold_huge_refused_with_cap_100(self):
        ev = self._preflight(100000, "blocks")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_blocks"], 100, ev)

    # -- allow-list through the same pre-flight --

    def test_preflight_allowlist_listed_payer_admitted(self):
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        ev = self._preflight(0, "seconds", sender=SENDER)
        self.assertTrue(ev["admitted"], ev)

    def test_preflight_allowlist_unlisted_payer_refused_without_a_cap(self):
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        ev = self._preflight(0, "seconds", sender=STRANGER)
        self.assertFalse(ev["admitted"], ev)
        self.assertNotIn("max_hold_seconds", ev, ev)
        self.assertNotIn("max_hold_blocks", ev, ev)

    # -- combined clause (the CLI's own text) through the pre-flight --

    def test_preflight_combined_listed_payer_over_cap_refused(self):
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_combined_clause([SENDER], 600, 100)))
        ev = self._preflight(700, "seconds", sender=SENDER)
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_seconds"], 600, ev)

    def test_preflight_combined_listed_payer_over_block_cap_refused(self):
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_combined_clause([SENDER], 600, 100)))
        ev = self._preflight(101, "blocks", sender=SENDER)
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_blocks"], 100, ev)

    def test_preflight_combined_unlisted_payer_refused_by_the_list(self):
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_combined_clause([SENDER], 600, 100)))
        ev = self._preflight(10, "seconds", sender=STRANGER)
        self.assertFalse(ev["admitted"], ev)
        # A list refusal, not a hold refusal (the mock suite's distinction,
        # carried through the same info dict this RPC merges in).
        self.assertEqual(ev["reason"], "recipient_policy_block", ev)


def _clause_body_of(composed_text: str) -> str:
    """The CLI composers print full rules ("always ( <body> )."); the
    registry stores clause bodies. Strip the wrapper the same way the
    node's own clause plumbing does when a rule lands."""
    text = composed_text.strip()
    assert text.startswith("always ( ") and text.endswith(" )."), text
    return text[len("always ( "):-len(" ).")]


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestNativeParksExpanded(_RecipientNativeHarness, unittest.TestCase):
    """#76 in real parks on the real engine: escrow deltas and admission
    refusals carrying the verified cap, in each unit."""

    def setUp(self):
        super().setUp()
        self._install_clause(RECIPIENT, CAP_BODY)
        self._warm()

    def test_time_park_inside_the_cap_escrows_the_full_amount(self):
        escrow_before = self._escrow_total()
        recip_before = chain_state._balances.get(RECIPIENT, 0)
        res = self._park(SENDER, RECIPIENT, 250, SK_ALICE,
                         release_at_time=int(time.time()) + 540)
        self.assertTrue(res["ok"], f"in-cap park refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 250)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0), recip_before)

    def test_time_park_over_the_cap_refused_with_the_verified_cap(self):
        escrow_before = self._escrow_total()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 700)
        self.assertFalse(res["ok"], f"over-cap park admitted: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        self.assertEqual(
            res["details"]["recipient_policy"]["max_hold_seconds"], 600, res)
        self.assertEqual(db.get_mempool_txs(), [])
        self.assertEqual(self._escrow_total(), escrow_before)

    def test_height_park_inside_the_cap_escrows(self):
        escrow_before = self._escrow_total()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_height=self._head() + 100)
        self.assertTrue(res["ok"], f"in-cap height park refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)

    def test_height_park_over_the_cap_refused_with_the_block_cap(self):
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_height=self._head() + 102)
        self.assertFalse(res["ok"], f"over-cap height park admitted: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        policy = res["details"]["recipient_policy"]
        self.assertEqual(policy["max_hold_blocks"], 100, res)
        self.assertNotIn("max_hold_seconds", policy, res)

    def test_cross_unit_giant_height_park_refused_as_blocks(self):
        """The failure mode of acknowledging a height park in seconds: a
        height park far beyond the cap (but inside the generic
        10,000-block params horizon, so the gate is what refuses it) is
        refused AS a block park, carrying the block cap and no seconds
        figure at all."""
        res = self._park_full(
            SENDER, RECIPIENT, 100, SK_ALICE, expire_blocks=9000,
            release_at_height=self._head() + 5000)[0]
        self.assertFalse(res["ok"], f"giant height park admitted: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        policy = res["details"]["recipient_policy"]
        self.assertEqual(policy["max_hold_blocks"], 100, res)
        self.assertNotIn("max_hold_seconds", policy, res)

    def test_two_parks_settle_in_one_block(self):
        escrow_before = self._escrow_total()
        r1 = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                        release_at_time=int(time.time()) + 540)
        # Admission counts the still-queued first park, so the second
        # park must carry the next sequence number already.
        r2 = self._park_full(SENDER, RECIPIENT, 50, SK_ALICE, seq_offset=1,
                             release_at_time=int(time.time()) + 540)[0]
        self.assertTrue(r1["ok"], r1)
        self.assertTrue(r2["ok"], r2)
        self._mine(expected_txs=2)
        self.assertEqual(self._escrow_total() - escrow_before, 150)

    def test_park_from_an_unlisted_payer_is_a_list_refusal_not_a_cap(self):
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        res = self._park(STRANGER, RECIPIENT, 100, SK_MALLORY,
                         release_at_time=int(time.time()) + 60)
        self.assertFalse(res["ok"], f"unlisted park admitted: {res}")
        self.assertNotIn("RECIPIENT_MAX_HOLD", str(res))
        self.assertIn("recipient", str(res).lower())

    # -- cap 0, both units (the CLI's composed body) --

    def _install_zero_cap(self):
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_max_hold_clause(0, 0)))

    def test_zero_cap_still_admits_a_plain_transfer(self):
        self._install_zero_cap()
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(SENDER, RECIPIENT, 42, SK_ALICE)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - before, 42)

    def test_zero_cap_refuses_a_one_second_park(self):
        self._install_zero_cap()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 30)
        self.assertFalse(res["ok"], f"park admitted under cap 0: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        self.assertEqual(
            res["details"]["recipient_policy"]["max_hold_seconds"], 0, res)

    def test_zero_cap_refuses_a_one_block_park(self):
        self._install_zero_cap()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_height=self._head() + 3)
        self.assertFalse(res["ok"], f"park admitted under cap 0: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        self.assertEqual(
            res["details"]["recipient_policy"]["max_hold_blocks"], 0, res)

    # -- per-branch caps --

    def test_seconds_only_clause_leaves_height_parks_uncapped(self):
        self._install_clause(RECIPIENT, SECONDS_ONLY_BODY)
        escrow_before = self._escrow_total()
        res = self._park_full(SENDER, RECIPIENT, 100, SK_ALICE,
                              expire_blocks=600,
                              release_at_height=self._head() + 500)[0]
        self.assertTrue(res["ok"], f"height park refused by a seconds-only cap: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)

    def test_blocks_only_clause_leaves_time_parks_uncapped(self):
        self._install_clause(RECIPIENT, BLOCKS_ONLY_BODY)
        escrow_before = self._escrow_total()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 3600)
        self.assertTrue(res["ok"], f"time park refused by a blocks-only cap: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestAllowlistExpandedNative(_RecipientNativeHarness, unittest.TestCase):
    """#47.1 widened: more payers, the CLI's own clause texts installed
    verbatim, and batch atomicity at the real admission path."""

    def setUp(self):
        super().setUp()
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        self._warm()

    def test_two_sender_allowlist_admits_the_second_listed_payer(self):
        self._install_clause(RECIPIENT, ALLOWLIST_TWO_BODY)
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(STRANGER, RECIPIENT, 77, SK_MALLORY)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - before, 77)

    def test_cli_allowlist_clause_behaves_like_the_handwritten_body(self):
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_allowlist_clause([SENDER])))
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(SENDER, RECIPIENT, 101, SK_ALICE)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - before, 101)
        res = self._queue_transfer(STRANGER, RECIPIENT, 100, SK_MALLORY)
        self.assertFalse(res["ok"], f"unlisted payer admitted: {res}")
        self.assertIn("recipient", str(res).lower())

    def test_cli_max_hold_clause_caps_both_units(self):
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_max_hold_clause(600, 100)))
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 700)
        self.assertFalse(res["ok"], f"over-cap park admitted: {res}")
        self.assertEqual(
            res["details"]["recipient_policy"]["max_hold_seconds"], 600, res)
        escrow_before = self._escrow_total()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_height=self._head() + 100)
        self.assertTrue(res["ok"], f"in-cap height park refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)

    def test_cli_combined_clause_gates_list_and_cap_together(self):
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_combined_clause([SENDER], 600, 100)))
        # Unlisted payer: refused even with a tiny hold.
        res = self._queue_transfer(STRANGER, RECIPIENT, 100, SK_MALLORY)
        self.assertFalse(res["ok"], f"unlisted payer admitted: {res}")
        # Listed payer, over-cap park: refused with the cap.
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 700)
        self.assertFalse(res["ok"], f"over-cap park admitted: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        # Listed payer, in-cap park: settles into escrow.
        escrow_before = self._escrow_total()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 540)
        self.assertTrue(res["ok"], f"in-cap park refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)

    def test_batch_with_one_refused_leg_is_refused_whole(self):
        """#47.3 at admission: a two-leg payment whose second leg pays
        the gated recipient from an unlisted payer is refused as one
        transaction — nothing queues, nothing moves."""
        bal_sender = chain_state._balances.get(SENDER, 0)
        bal_stranger = chain_state._balances.get(STRANGER, 0)
        bal_recip = chain_state._balances.get(RECIPIENT, 0)
        tx = json.dumps(sign_payload({
            "sender_pubkey": STRANGER,
            "sequence_number": chain_state.get_sequence_number(STRANGER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[STRANGER, SENDER, "100"],
                                 [STRANGER, RECIPIENT, "100"]]},
            "fee_limit": "50",
        }, SK_MALLORY))
        res = sendtx.queue_transaction(tx, propagate=False)
        self.assertFalse(res["ok"], f"mixed batch admitted: {res}")
        self.assertEqual(db.get_mempool_txs(), [])
        self._seal_empty(1)
        self.assertEqual(chain_state._balances.get(SENDER, 0), bal_sender)
        self.assertEqual(chain_state._balances.get(STRANGER, 0), bal_stranger)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0), bal_recip)

    def test_batch_of_admitted_legs_settles_both_in_one_block(self):
        bal_recip = chain_state._balances.get(RECIPIENT, 0)
        bal_stranger = chain_state._balances.get(STRANGER, 0)
        tx = json.dumps(sign_payload({
            "sender_pubkey": SENDER,
            "sequence_number": chain_state.get_sequence_number(SENDER),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": {"1": [[SENDER, RECIPIENT, "40"],
                                 [SENDER, STRANGER, "60"]]},
            "fee_limit": "50",
        }, SK_ALICE))
        res = sendtx.queue_transaction(tx, propagate=False)
        self.assertTrue(res["ok"], f"clean batch refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - bal_recip, 40)
        self.assertEqual(
            chain_state._balances.get(STRANGER, 0) - bal_stranger, 60)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestNeutralAndExemptionsNative(_RecipientNativeHarness,
                                     unittest.TestCase):
    """#47.2/#47.4/#76.3/#76.4 on the real engine: the neutral default,
    direction, self-transfers, retracts, releases, replay."""

    def test_no_clause_means_the_neutral_default_for_transfers(self):
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(STRANGER, RECIPIENT, 55, SK_MALLORY)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - before, 55)

    def test_no_clause_means_no_cap_for_parks(self):
        escrow_before = self._escrow_total()
        res = self._park(STRANGER, RECIPIENT, 100, SK_MALLORY,
                         release_at_time=int(time.time()) + 3600)
        self.assertTrue(res["ok"], f"uncapped park refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)

    def test_clause_that_never_reads_the_hold_is_never_consulted(self):
        """The constant-block body would refuse everything if the gate
        consulted it; it reads neither i16 nor i17, so it is not
        inbound-capable and payments settle exactly as before."""
        self._install_clause(RECIPIENT, NOT_INBOUND_BODY)
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(SENDER, RECIPIENT, 66, SK_ALICE)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - before, 66)

    def test_clause_on_another_account_does_not_gate_this_recipient(self):
        self._install_clause(STRANGER, ALLOWLIST_BODY)
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(STRANGER, RECIPIENT, 25, SK_MALLORY)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - before, 25)

    def test_recipients_own_outgoing_payment_is_not_judged_by_her_clause(self):
        """#47.4: the recipient's allow-list governs payments TO her;
        her own outgoing payment is judged by the other side (no
        clause) and settles."""
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        self._transfer(SENDER, RECIPIENT, 100, SK_ALICE)
        before = chain_state._balances.get(STRANGER, 0)
        self._transfer(RECIPIENT, STRANGER, 33, SK_BOB)
        self.assertEqual(chain_state._balances.get(STRANGER, 0) - before, 33)

    def test_self_transfer_is_never_a_recipient_refusal(self):
        """The engine refuses self-transfers on its own, before any
        policy pass: even with a block-all-inbound clause on the sender's
        own account, the outcome is never a recipient-policy refusal
        and nothing moves."""
        self._install_clause(SENDER, BLOCK_INBOUND_BODY)
        bal_before = chain_state._balances.get(SENDER, 0)
        seq_before = chain_state.get_sequence_number(SENDER)
        res = self._queue_transfer(SENDER, SENDER, 10, SK_ALICE)
        if res["ok"]:
            block_res = createblock.create_block_from_mempool(allow_empty=True)
            self.assertEqual(len(block_res.get("transactions", [])), 0,
                             block_res)
        else:
            self.assertNotIn("recipient_policy", str(res).lower(), res)
            self.assertNotIn("RECIPIENT_MAX_HOLD", str(res), res)
        self.assertEqual(chain_state._balances.get(SENDER, 0), bal_before)
        self.assertEqual(chain_state.get_sequence_number(SENDER), seq_before)

    def test_retract_is_never_gated_by_a_tightened_clause(self):
        """#76.4: park under the cap, tighten the recipient's clause to
        block-all-inbound, and the sender's retract still refunds in
        full — measured as deltas around the retract block."""
        self._install_clause(RECIPIENT, CAP_BODY)
        self._warm()
        res, payload = self._park_full(
            SENDER, RECIPIENT, 100, SK_ALICE,
            release_at_height=self._head() + 10)
        self.assertTrue(res["ok"], f"park refused: {res}")
        self._mine(expected_txs=1)
        rid = parse_retractable_transfer(payload).retractable_id.hex()
        self._install_clause(RECIPIENT, BLOCK_INBOUND_BODY)
        sender_before = chain_state._balances.get(SENDER, 0)
        escrow_before = self._escrow_total()
        retract = cli_tx.build_retract_transfer_tx(
            sender_pubkey=SENDER,
            sequence_number=chain_state.get_sequence_number(SENDER),
            expiration_time=int(time.time()) + 3600,
            expire_at_height=self._head() + 50,
            retractable_id=rid, fee_limit="0")
        res = sendtx.queue_transaction(
            json.dumps(sign_payload(retract, SK_ALICE)), propagate=False)
        self.assertTrue(res["ok"], f"retract refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(
            chain_state._balances.get(SENDER, 0) - sender_before, 100)
        self.assertEqual(self._escrow_total(), escrow_before - 100)

    def test_release_is_never_rechecked_by_a_tightened_clause(self):
        """A park admitted under the 600-second cap pays out at maturity
        even after the recipient tightens to cap 0 — the gate judges
        parks, not releases."""
        self._install_clause(RECIPIENT, CAP_BODY)
        self._warm()
        release_height = self._head() + 5
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_height=release_height)
        self.assertTrue(res["ok"], f"park refused: {res}")
        self._mine(expected_txs=1)
        self._install_clause(
            RECIPIENT, _clause_body_of(compose_max_hold_clause(0, 0)))
        recip_before = chain_state._balances.get(RECIPIENT, 0)
        escrow_before = self._escrow_total()
        while self._head() <= release_height:
            self._seal_empty(1)
        self.assertEqual(
            chain_state._balances.get(RECIPIENT, 0) - recip_before, 100)
        self.assertEqual(self._escrow_total(), escrow_before - 100)

    # NOTE — no from-0 rebuild test in this file, deliberately: this
    # harness funds SENDER/STRANGER by direct in-memory balance writes
    # after genesis (see setUp), so the stored chain's first block is
    # mined over state a from-0 rebuild can never reproduce (verified
    # in fork CI: rebuild stops at block 1 with a state-hash mismatch
    # even for a plain pre-clause funding transfer). From-0 rebuild
    # determinism needs a genesis-funded subprocess harness — the
    # pattern of tests/test_replay_determinism_native.py, which runs
    # in the same CI. The gate's replay determinism IS covered in this
    # package by the two-node activation+replay test in
    # tests/test_recipient_controls_twonode_native.py: a follower
    # replays the whole block stream (governance activation included)
    # and reaches byte-identical checkpoints.


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestDeployScreensNative(_RecipientNativeHarness, unittest.TestCase):
    """#47.5/#76.6 at the real admission path: the deploy screens that
    keep a bad inbound clause from ever being registered."""

    def setUp(self):
        super().setUp()
        # The deployer needs a balance for her own rule transaction.
        self._transfer(SENDER, RECIPIENT, 1000, SK_ALICE)

    def test_unit_blind_hold_rule_is_refused_at_deploy(self):
        res = self._deploy_rule(RECIPIENT, BLIND_RULE, SK_BOB)
        self.assertFalse(res["ok"], f"unit-blind rule admitted: {res}")
        self.assertIn("unit-blind", str(res).lower(), res)

    def test_wrong_width_hold_rule_is_refused_at_deploy(self):
        res = self._deploy_rule(RECIPIENT, WRONG_WIDTH_RULE, SK_BOB)
        self.assertFalse(res["ok"], f"bv[32] hold rule admitted: {res}")

    def test_inbound_clause_deploys_clean_once_active(self):
        res = self._deploy_rule(RECIPIENT, CAP_RULE, SK_BOB)
        self.assertTrue(res["ok"], f"valid inbound clause refused: {res}")

    def test_cli_composed_rule_text_deploys_clean(self):
        res = self._deploy_rule(
            RECIPIENT, compose_combined_clause([SENDER], 600, 100), SK_BOB)
        self.assertTrue(res["ok"], f"CLI-composed rule refused: {res}")


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestPreActivationNative(_RecipientNativeHarness, unittest.TestCase):
    """The gate before activation: inert for payments, closed for
    deploys — then open once the one-way switch lands."""

    ACTIVATE = False

    def setUp(self):
        super().setUp()
        # The deployer needs a balance for her own rule transaction.
        self._transfer(SENDER, RECIPIENT, 1000, SK_ALICE)

    def test_gate_is_inert_for_transfers_before_activation(self):
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        before = chain_state._balances.get(RECIPIENT, 0)
        self._transfer(STRANGER, RECIPIENT, 44, SK_MALLORY)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0) - before, 44)

    def test_gate_is_inert_for_parks_before_activation(self):
        self._install_clause(RECIPIENT, CAP_BODY)
        self._warm()
        escrow_before = self._escrow_total()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 3600)
        self.assertTrue(res["ok"], f"park gated before activation: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)

    def test_inbound_clause_deploy_is_refused_before_activation(self):
        res = self._deploy_rule(RECIPIENT, CAP_RULE, SK_BOB)
        self.assertFalse(res["ok"], f"inbound clause deployed pre-activation: {res}")
        self.assertIn("RECIPIENT_POLICY_INACTIVE", str(res), res)

    def test_the_same_deploy_is_admitted_after_activation(self):
        res = self._deploy_rule(RECIPIENT, CAP_RULE, SK_BOB)
        self.assertFalse(res["ok"], res)
        chain_state._lifecycle_manager.activate_recipient_policy()
        res = self._deploy_rule(RECIPIENT, CAP_RULE, SK_BOB)
        self.assertTrue(res["ok"], f"deploy refused after activation: {res}")


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestRegistryTamperNative(_RecipientNativeHarness, unittest.TestCase):
    """Tamper evidence, in the shape this chain's surfaces allow: the
    persisted registry is what admission reads, the lifecycle manager's
    accepted clauses are what apply reads. Altering the registry row
    after install must not be able to force a settlement the real
    clause refuses — and the divergence is visible, not silent."""

    def _tamper_registry(self, recipient, body):
        with db._db_lock:
            db._db_conn.execute(
                "UPDATE rule_clauses_v1 SET clause_body = ? "
                "WHERE acceptor_pubkey = ? AND target_stream = 5",
                (body, recipient.lower()))
            db._db_conn.commit()

    def test_tampered_registry_cannot_force_a_settlement(self):
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        self._warm()
        # The registry now claims STRANGER is listed; the accepted
        # clause (the apply seam's source) still lists only SENDER.
        self._tamper_registry(
            RECIPIENT,
            _clause_body_of(compose_allowlist_clause([STRANGER])))
        bal_stranger = chain_state._balances.get(STRANGER, 0)
        bal_recip = chain_state._balances.get(RECIPIENT, 0)
        seq_stranger = chain_state.get_sequence_number(STRANGER)
        res = self._queue_transfer(STRANGER, RECIPIENT, 100, SK_MALLORY)
        self.assertTrue(
            res["ok"], f"admission did not follow the tampered registry: {res}")
        block_res = createblock.create_block_from_mempool(allow_empty=True)
        self.assertEqual(len(block_res.get("transactions", [])), 0, block_res)
        self.assertEqual(chain_state._balances.get(STRANGER, 0), bal_stranger)
        self.assertEqual(chain_state._balances.get(RECIPIENT, 0), bal_recip)
        self.assertEqual(chain_state.get_sequence_number(STRANGER), seq_stranger)

    def test_tampered_registry_refusal_is_admission_only(self):
        """The other direction: a registry row tightened to refuse the
        listed payer refuses at admission — the divergence shows up as
        a refusal to fix, never as a settlement to unwind."""
        self._install_clause(RECIPIENT, ALLOWLIST_BODY)
        self._warm()
        self._tamper_registry(
            RECIPIENT,
            _clause_body_of(compose_allowlist_clause([RECIPIENT])))
        res = self._queue_transfer(SENDER, RECIPIENT, 100, SK_ALICE)
        self.assertFalse(res["ok"], f"tampered registry not read: {res}")
        self.assertIn("recipient", str(res).lower())
        self.assertEqual(db.get_mempool_txs(), [])


# --- B03FIX2: hold-cap semantics a competitor refined, pinned natively ---
#
# PR #166 (AduAkorful) spent four commits on the exactness of hold-cap
# reporting: a seconds cap must refuse a height park however large the
# literal, a cap must stay exact when the clause also names a time lock,
# a cap may be named only from change points the judged payment itself
# fixes, and a forged stream key must never reach the clause. Our design
# reaches the same semantics by different machinery (the hold is judged
# in its native unit behind an i16 context tag; caps are verified as a
# single threshold across the branch's change points) — these tests pin
# each semantic BY NAME on the real engine.

# Seconds cap of one year (31,536,000 — past the 90-day release window)
# and a blocks cap of 0.
PAST_WINDOW_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x1E13380 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0000 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

# CAP_BODY with a bv[64] time-lock literal (i5) conjoined in the seconds
# branch: the hold cap must still be named exactly.
TIMELOCK_CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > { #x0258 }:bv[64] && "
    "i5[t]:bv[64] > { #x0064 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

# Admits 0..101 and 5000..6000 seconds, refuses between and above.
HOLED_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] <= { #x0065 }:bv[64]) || "
    "(i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] >= { #x1388 }:bv[64] && "
    "i17[t]:bv[64] <= { #x1770 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24])"
)

# The seconds branch caps the hold at the payment amount (i1) — a change
# point this payment itself fixes, with no literal anywhere.
STREAM_CAP_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > i1[t]:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)

# The seconds branch caps the hold at i9, a stream this payment's input
# map does not carry: the change point is not this payment's to name.
UNFIXED_STREAM_BODY = (
    "((i16[t]:bv[64] = { #x0002 }:bv[64] && i17[t]:bv[64] > i9[t]:bv[64]) || "
    "(i16[t]:bv[64] = { #x0003 }:bv[64] && i17[t]:bv[64] > { #x0064 }:bv[64])) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
)


class TestGetgovernanceScheduledPatch(unittest.TestCase):
    """The getgovernance deadlock class, found by this parity test: for
    a scheduled update carrying an activation flag patch, the advisory
    precheck audits the tip's effective spec texts, whose chain_state
    getters take _rules_lock — while getgovernance already held that
    (non-re-entrant) lock, plus the balance and sequence locks. The
    read hung forever exactly during a flag-activation window. The fix
    defers the prechecks until after the state locks are released.
    Pure Python: runs in every job, not only the native one."""

    def test_getgovernance_answers_with_a_scheduled_flag_patch(self):
        import threading
        import types

        from commands import getgovernance
        from consensus.governance import (
            ConsensusLifecycleManager,
            ConsensusRuleUpdate,
        )

        lm = ConsensusLifecycleManager(active_validators=["aa" * 48])
        # Both activation flags take the precheck through the collision
        # audit over the tip's effective spec texts — the read that used
        # to re-take the rules lock. One scheduled update per flag.
        updates = []
        for height, key in ((12, "recipient_policy_active"),
                            (13, "approval_slots_active")):
            update = ConsensusRuleUpdate(
                rule_revisions=[], activate_at_height=height,
                host_contract_patch={key: True})
            lm.scheduled_updates.append((height, update.update_id))
            lm.update_payloads[update.update_id] = update
            updates.append(update)

        class _DB:
            def get_canonical_head_block(self):
                return {"block_hash": "ab" * 32,
                        "header": {"block_number": 7}}

            def get_mempool_txs(self):
                return []

        stub_chain_state = types.SimpleNamespace(
            _balance_lock=chain_state._balance_lock,
            _sequence_lock=chain_state._sequence_lock,
            _rules_lock=chain_state._rules_lock,
            _lifecycle_manager=lm,
            _active_consensus_id=None,
            _consensus_rules_state="",
            _application_rules_state="",
        )
        container = types.SimpleNamespace(
            chain_state=stub_chain_state, db=_DB())
        out = {}

        def run():
            out["resp"] = getgovernance.execute("getgovernance", container)

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        thread.join(5)
        self.assertFalse(
            thread.is_alive(),
            "getgovernance stalled on a scheduled flag patch")
        resp = json.loads(out["resp"])
        self.assertEqual(resp["status"], "ok", resp)
        scheduled = resp["data"]["scheduled_updates"]
        self.assertEqual(len(scheduled), 2, resp)
        by_patch = {
            next(iter(e["host_contract_patch"])): e for e in scheduled
        }
        for key in ("recipient_policy_active", "approval_slots_active"):
            self.assertEqual(by_patch[key]["precheck"], "ok", resp)
            self.assertEqual(
                by_patch[key]["host_contract_patch"], {key: True}, resp)


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestHoldCapChangePointsNative(_RecipientNativeHarness,
                                    unittest.TestCase):
    """B03FIX2 on the real engine: cross-unit caps, time-lock neighbours,
    change-point cap naming, and forged stream keys."""

    # -- a seconds cap, however large, never speaks for blocks --

    def test_seconds_cap_past_the_release_window_still_refuses_a_height_park(self):
        self._install_clause(RECIPIENT, PAST_WINDOW_BODY)
        self._warm()
        ev = self._preflight(3, "blocks")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_blocks"], 0, ev)
        self.assertNotIn("max_hold_seconds", ev, ev)
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_height=self._head() + 3)
        self.assertFalse(res["ok"], f"height park admitted: {res}")
        self.assertIn("RECIPIENT_MAX_HOLD", str(res))
        policy = res["details"]["recipient_policy"]
        self.assertEqual(policy["max_hold_blocks"], 0, res)
        self.assertNotIn("max_hold_seconds", policy, res)

    def test_past_window_seconds_cap_admits_the_longest_legal_time_park(self):
        self._install_clause(RECIPIENT, PAST_WINDOW_BODY)
        self._warm()
        ev = self._preflight(7776000, "seconds")
        self.assertTrue(ev["admitted"], ev)
        escrow_before = self._escrow_total()
        res = self._park(SENDER, RECIPIENT, 100, SK_ALICE,
                         release_at_time=int(time.time()) + 7700000)
        self.assertTrue(res["ok"], f"legal time park refused: {res}")
        self._mine(expected_txs=1)
        self.assertEqual(self._escrow_total() - escrow_before, 100)

    # -- a neighbouring time-lock literal changes nothing --

    def test_hold_cap_named_exactly_when_clause_also_names_a_time_lock(self):
        self._install_clause(RECIPIENT, TIMELOCK_CAP_BODY)
        self._warm()
        ev = self._preflight(600, "seconds")
        self.assertTrue(ev["admitted"], ev)
        ev = self._preflight(601, "seconds")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_seconds"], 600, ev)
        self.assertEqual(ev["cap_kind"], "threshold", ev)

    # -- caps are named only from change points this payment fixes --

    def test_a_holed_clause_quotes_no_cap_from_its_change_points(self):
        self._install_clause(RECIPIENT, HOLED_BODY)
        self._warm()
        # The hole is real on the engine: a hold inside the upper band
        # is admitted even though a smaller one is refused.
        ev = self._preflight(5500, "seconds")
        self.assertTrue(ev["admitted"], ev)
        ev = self._preflight(200, "seconds")
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["cap_kind"], "rule", ev)
        self.assertNotIn("max_hold_seconds", ev, ev)
        self.assertNotIn("max_hold_blocks", ev, ev)

    def test_hold_cap_named_from_a_change_point_this_payment_fixes(self):
        self._install_clause(RECIPIENT, STREAM_CAP_BODY)
        self._warm()
        ev = self._preflight(600, "seconds", amount=600)
        self.assertTrue(ev["admitted"], ev)
        ev = self._preflight(601, "seconds", amount=600)
        self.assertFalse(ev["admitted"], ev)
        self.assertEqual(ev["max_hold_seconds"], 600, ev)
        self.assertEqual(ev["cap_kind"], "threshold", ev)

    def test_no_cap_when_the_other_stream_is_not_fixed_by_this_payment(self):
        self._install_clause(RECIPIENT, UNFIXED_STREAM_BODY)
        self._warm()
        ev = self._preflight(200, "seconds")
        self.assertFalse(ev["admitted"], ev)
        self.assertNotIn("max_hold_seconds", ev, ev)
        self.assertNotIn("max_hold_blocks", ev, ev)

    # -- forged stream keys never reach the clause --

    def test_forged_hold_key_shapes_never_reach_the_recipient_clause(self):
        """A hand-built input map spelling the hold/context streams
        17 / "17" / "i17" (and 16 likewise) with forged values: the gate
        overlay forces exactly one shape per stream, so the clause
        judges the plain final payment this is — not the forged
        999999-block height park the extra shapes describe."""
        from consensus import sender_policy

        self._install_clause(RECIPIENT, CAP_BODY)
        self._warm()
        clause_for = chain_state._lifecycle_manager.rule_offers.clause_for
        forged = {
            1: "100",
            3: "{ #x" + SENDER + " }:bv[384]",
            17: "999999", "17": "999999", "i17": "999999",
            16: "3", "16": "3", "i16": "3",
        }
        blocked, info = sender_policy.recipient_clause_blocks(
            clause_for, RECIPIENT, forged, hold=0, context=1, pool="apply")
        self.assertFalse(blocked, info)


if __name__ == "__main__":
    unittest.main()
