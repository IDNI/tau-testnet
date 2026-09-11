"""End-to-end rule sharing: offer -> mine -> read -> accept -> mine.

Drives the real path -- BLS-signed transactions through admission, block
production and apply -- with only the Tau engine mocked. Its job is to catch
wiring breaks between the layers that the per-layer unit tests cannot see:
signing digests, admission dispatch, mempool lanes, block inclusion, apply,
persistence, and the read RPCs.

The load-bearing assertion is `test_two_acceptors_keep_independent_policies`:
that is the whole point of composing accepted clauses rather than appending
them, and it fails if any layer loses the registry.
"""
import hashlib
import json
import os
import types
import unittest
from unittest.mock import patch

from py_ecc.bls import G2Basic as bls

import chain_state
import config
import db
import tau_defs
from commands import createblock, getruleconflict, getruleoffer, getruleoffers, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.lanes import LANE_FAST, LANE_SLOW
from consensus.rule_offers import (
    STATUS_ACCEPTED,
    STATUS_OFFERED,
    STATUS_REJECTED,
    RuleOffer,
    clause_body_v1,
)

SK_ALICE = bls.KeyGen(b"rule_sharing_alice")
SK_BOB = bls.KeyGen(b"rule_sharing_bob")
SK_CAROL = bls.KeyGen(b"rule_sharing_carol")
ALICE = bls.SkToPk(SK_ALICE).hex()
BOB = bls.SkToPk(SK_BOB).hex()
CAROL = bls.SkToPk(SK_CAROL).hex()

MINER_PRIVKEY_HEX = "11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09"
MINER = bls.SkToPk(int(MINER_PRIVKEY_HEX, 16)).hex()

BLOCK_RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
ALLOW_RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
TARGET = 5
EXPIRE_AT = 5000


class RuleSharingE2E(unittest.TestCase):
    def setUp(self):
        self.test_db = "test_rule_sharing_e2e.sqlite"
        config.set_database_path(self.test_db)
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

        # Assign fresh dicts rather than clearing in place: an earlier test in
        # the suite can leave these replaced by mocks, and mutating a mock
        # silently succeeds while get_balance then returns a mock. Same approach
        # as tests/conftest.py's node_state fixture.
        chain_state._balances = {}
        chain_state._sequence_numbers = {}
        db.init_db()
        chain_state.load_genesis("data/genesis.json")
        db.clear_mempool()

        # Record every rule routed through i0 so the tests can assert on the
        # composite text the node actually emits.
        self.rule_calls = []

        def mock_tau(rule_text=None, target_output_stream_index=1,
                     input_stream_values=None, **kwargs):
            if rule_text:
                self.rule_calls.append(rule_text)
            if target_output_stream_index == 0:
                return tau_defs.ACK_RULE_PROCESSED
            return tau_defs.TAU_VALUE_ONE

        def mock_tau_multi(input_stream_values=None, **kwargs):
            # o1 accepts, o8/o9 charge nothing: fees are exercised by
            # tests/test_fee_model.py, not here.
            return {1: tau_defs.TAU_VALUE_ONE, 8: "0", 9: "0"}

        patch("tau_manager.communicate_with_tau", side_effect=mock_tau).start()
        patch("tau_manager.communicate_with_tau_multi", side_effect=mock_tau_multi).start()
        patch("tau_manager.is_force_test_enabled", return_value=True).start()
        self._ready = patch("tau_manager.tau_ready").start()
        self._ready.is_set.return_value = True
        self._ready.wait.return_value = True

        for addr in (ALICE, BOB, CAROL):
            chain_state._balances[addr] = 10_000

        # A miner identity is required to produce blocks, and it must be the
        # sole active validator so the PoA proposer gate lets it through.
        self._saved_privkey = config.MINER_PRIVKEY
        self._saved_pubkey = getattr(config, "MINER_PUBKEY", None)
        config.MINER_PRIVKEY = MINER_PRIVKEY_HEX
        config.MINER_PUBKEY = MINER
        chain_state._lifecycle_manager.active_validators = {MINER}
        chain_state._lifecycle_manager.recompute_approval_threshold()

        self.container = types.SimpleNamespace(db=db, chain_state=chain_state)

    def tearDown(self):
        patch.stopall()
        config.MINER_PRIVKEY = self._saved_privkey
        if self._saved_pubkey is not None:
            config.MINER_PUBKEY = self._saved_pubkey
        if db._db_conn:
            db._db_conn.close()
            db._db_conn = None
        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    # -- helpers -----------------------------------------------------------

    def _submit(self, payload, sk):
        payload["expiration_time"] = 9999999999
        payload.setdefault("fee_limit", "10")
        payload["sequence_number"] = chain_state.get_sequence_number(
            payload["sender_pubkey"]
        ) + (db.get_pending_sequence(payload["sender_pubkey"]) is not None and 1 or 0)
        digest = hashlib.sha256(_get_signing_message_bytes(payload)).digest()
        payload["signature"] = bls.Sign(sk, digest).hex()
        result = sendtx.queue_transaction(json.dumps(payload))
        self.assertTrue(result.get("ok"), result)
        return result

    def _offer(self, sk, offerer, recipient, rule_text=BLOCK_RULE, expire=EXPIRE_AT):
        self._submit({
            "tx_type": "rule_offer",
            "sender_pubkey": offerer,
            "recipient_pubkey": recipient,
            "rule_text": rule_text,
            "expire_at_height": expire,
        }, sk)
        return RuleOffer(offerer_pubkey=offerer, recipient_pubkey=recipient,
                         rule_text=rule_text, expire_at_height=expire).offer_id_hex

    def _decide(self, sk, actor, offer_id, *, accept, rule_text=BLOCK_RULE):
        payload = {
            "tx_type": "rule_offer_accept" if accept else "rule_offer_reject",
            "sender_pubkey": actor,
            "offer_id": offer_id,
        }
        if accept:
            payload["rule_text"] = rule_text
        self._submit(payload, sk)

    def _mine(self):
        result = createblock.create_block_from_mempool(allow_empty=False)
        self.assertNotIn("error", result, result)
        return result

    def _rpc(self, handler, command):
        return json.loads(handler.execute(command, self.container))

    def _lane_of(self, tx_hash):
        with db.get_db_connection() as conn:
            row = conn.execute(
                "SELECT lane FROM mempool WHERE tx_hash = ?", (tx_hash,)
            ).fetchone()
        return row[0] if row else None

    # -- tests -------------------------------------------------------------

    def test_offer_is_mined_and_visible(self):
        offer_id = self._offer(SK_ALICE, ALICE, BOB)
        self._mine()

        row = next(
            r for r in db.load_rule_offers() if r["offer_id"] == offer_id
        )
        self.assertEqual(row["status"], STATUS_OFFERED)
        self.assertEqual(row["recipient_pubkey"], BOB)
        self.assertEqual(row["rule_text"], BLOCK_RULE)

        data = self._rpc(getruleoffers, f"getruleoffers {BOB}")["data"]
        self.assertEqual(data["pending_incoming"], 1)
        self.assertEqual(data["incoming"][0]["offer_id"], offer_id)

        detail = self._rpc(getruleoffer, f"getruleoffer {offer_id}")["data"]
        self.assertEqual(detail["rule_text"], BLOCK_RULE)
        self.assertEqual(detail["target_stream"], TARGET)

    def test_conflict_report_is_available_before_accepting(self):
        offer_id = self._offer(SK_ALICE, ALICE, BOB)
        self._mine()
        report = self._rpc(getruleconflict, f"getruleconflict {offer_id}")["data"]
        self.assertTrue(report["advisory"])
        statuses = {l["layer"]: l["status"] for l in report["layers"]}
        self.assertEqual(statuses["shape"], "ok")
        self.assertEqual(statuses["reserved_domains"], "ok")
        # Never claims satisfiability -- the bindings cannot answer it.
        self.assertEqual(statuses["unrealizable"], "unavailable")
        self.assertIn(BOB, report["composed_rule"])

    def test_accept_registers_the_clause_and_emits_a_composite(self):
        offer_id = self._offer(SK_ALICE, ALICE, BOB)
        self._mine()
        self.rule_calls.clear()

        self._decide(SK_BOB, BOB, offer_id, accept=True)
        self._mine()

        clauses = {
            (c["acceptor_pubkey"], c["target_stream"]): c["clause_body"]
            for c in db.load_rule_clauses()
        }
        self.assertEqual(clauses.get((BOB, TARGET)), clause_body_v1(BLOCK_RULE))

        row = next(r for r in db.load_rule_offers() if r["offer_id"] == offer_id)
        self.assertEqual(row["status"], STATUS_ACCEPTED)

        composites = [r for r in self.rule_calls if "i12" in r]
        self.assertTrue(composites, "no composite rule was applied")
        self.assertIn(BOB, composites[-1])
        # One guarded unit, not an accumulation.
        self.assertEqual(composites[-1].count("always"), 1)

    def test_two_acceptors_keep_independent_policies(self):
        """The regression the composite design exists to prevent."""
        first = self._offer(SK_ALICE, ALICE, BOB)
        second = self._offer(SK_ALICE, ALICE, CAROL)
        self._mine()

        self._decide(SK_BOB, BOB, first, accept=True)
        self._mine()
        self._decide(SK_CAROL, CAROL, second, accept=True)
        self._mine()

        clauses = {
            (c["acceptor_pubkey"], c["target_stream"]): c["clause_body"]
            for c in db.load_rule_clauses()
        }
        self.assertIn((BOB, TARGET), clauses, "first acceptor's clause was lost")
        self.assertIn((CAROL, TARGET), clauses)

        composites = [r for r in self.rule_calls if "i12" in r]
        self.assertIn(BOB, composites[-1])
        self.assertIn(CAROL, composites[-1])

    def test_accepting_again_replaces_the_acceptors_clause(self):
        first = self._offer(SK_ALICE, ALICE, BOB, rule_text=BLOCK_RULE)
        second = self._offer(SK_ALICE, ALICE, BOB, rule_text=ALLOW_RULE,
                             expire=EXPIRE_AT + 1)
        self._mine()

        self._decide(SK_BOB, BOB, first, accept=True, rule_text=BLOCK_RULE)
        self._mine()
        self._decide(SK_BOB, BOB, second, accept=True, rule_text=ALLOW_RULE)
        self._mine()

        clauses = [c for c in db.load_rule_clauses() if c["acceptor_pubkey"] == BOB]
        self.assertEqual(len(clauses), 1, "an acceptor must hold one clause per stream")
        self.assertEqual(clauses[0]["clause_body"], clause_body_v1(ALLOW_RULE))

    def test_reject_resolves_without_a_clause(self):
        offer_id = self._offer(SK_ALICE, ALICE, BOB)
        self._mine()

        self._decide(SK_BOB, BOB, offer_id, accept=False)
        self._mine()

        row = next(r for r in db.load_rule_offers() if r["offer_id"] == offer_id)
        self.assertEqual(row["status"], STATUS_REJECTED)
        self.assertEqual(db.load_rule_clauses(), [])

    def test_non_recipient_cannot_accept(self):
        offer_id = self._offer(SK_ALICE, ALICE, BOB)
        self._mine()

        payload = {
            "tx_type": "rule_offer_accept",
            "sender_pubkey": CAROL,
            "offer_id": offer_id,
            "rule_text": BLOCK_RULE,
            "expiration_time": 9999999999,
            "expire_at_height": 5000,
            "fee_limit": "10",
            "sequence_number": chain_state.get_sequence_number(CAROL),
        }
        digest = hashlib.sha256(_get_signing_message_bytes(payload)).digest()
        payload["signature"] = bls.Sign(SK_CAROL, digest).hex()
        result = sendtx.queue_transaction(json.dumps(payload))
        self.assertFalse(result.get("ok"))
        self.assertIn("recipient", result.get("message", ""))

    def test_accept_with_altered_text_is_refused_at_admission(self):
        offer_id = self._offer(SK_ALICE, ALICE, BOB)
        self._mine()

        payload = {
            "tx_type": "rule_offer_accept",
            "sender_pubkey": BOB,
            "offer_id": offer_id,
            "rule_text": ALLOW_RULE,          # not what was offered
            "expiration_time": 9999999999,
            "expire_at_height": 5000,
            "fee_limit": "10",
            "sequence_number": chain_state.get_sequence_number(BOB),
        }
        digest = hashlib.sha256(_get_signing_message_bytes(payload)).digest()
        payload["signature"] = bls.Sign(SK_BOB, digest).hex()
        result = sendtx.queue_transaction(json.dumps(payload))
        self.assertFalse(result.get("ok"))
        self.assertIn("digest", result.get("message", ""))

    def test_offer_writing_a_reserved_stream_is_refused(self):
        payload = {
            "tx_type": "rule_offer",
            "sender_pubkey": ALICE,
            "recipient_pubkey": BOB,
            "rule_text": "always ( o9[t]:bv[24] = { #x000001 }:bv[24] ).",
            "expire_at_height": EXPIRE_AT,
            "expiration_time": 9999999999,
            "fee_limit": "10",
            "sequence_number": chain_state.get_sequence_number(ALICE),
        }
        digest = hashlib.sha256(_get_signing_message_bytes(payload)).digest()
        payload["signature"] = bls.Sign(SK_ALICE, digest).hex()
        result = sendtx.queue_transaction(json.dumps(payload))
        self.assertFalse(result.get("ok"))

    def test_lanes_are_assigned_across_the_real_path(self):
        offer = self._offer(SK_ALICE, ALICE, BOB)
        transfer = self._submit({
            "tx_type": "user_tx",
            "sender_pubkey": CAROL,
            "operations": {"1": [[CAROL, BOB, 1]]},
        }, SK_CAROL)

        entries = {e["tx_hash"]: e for e in db.get_mempool_entries()}
        self.assertEqual(len(entries), 2)
        lanes = {h: self._lane_of(h) for h in entries}
        # Exactly one of each, and the offer is the slow one.
        self.assertEqual(sorted(lanes.values()), [LANE_FAST, LANE_SLOW])
        self.assertEqual(lanes[transfer["tx_hash"]], LANE_FAST)

    def test_state_survives_a_reload(self):
        offer_id = self._offer(SK_ALICE, ALICE, BOB)
        self._mine()
        self._decide(SK_BOB, BOB, offer_id, accept=True)
        self._mine()

        before = chain_state._lifecycle_manager.consensus_meta_hash()
        composite_before = chain_state._lifecycle_manager.rule_offers.composite_for_stream(TARGET)

        from consensus.governance import ConsensusLifecycleManager
        chain_state._lifecycle_manager = ConsensusLifecycleManager()
        self.assertTrue(chain_state.load_state_from_db())
        reloaded = chain_state._lifecycle_manager

        self.assertEqual(reloaded.rule_offers.clause_for(BOB, TARGET),
                         clause_body_v1(BLOCK_RULE))
        self.assertEqual(reloaded.consensus_meta_hash(), before)
        self.assertEqual(
            reloaded.rule_offers.composite_for_stream(TARGET), composite_before
        )


if __name__ == "__main__":
    unittest.main()
