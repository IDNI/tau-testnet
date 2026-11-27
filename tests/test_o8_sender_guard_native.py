"""User fee rules from different accounts coexist on the real engine.

Each account fences its own o8 rule to its own key, so a later account's rule
neither displaces an earlier one nor charges anyone else, and a rule fenced to
another account's key is refused. Run this file on its own.
"""
import json
import time
import unittest

import pytest

import chain_state
import config
import db
from bls_keys import SK_ALICE, SK_BOB, SK_MALLORY, pubkey_hex, sign_payload
from commands import createblock, sendtx
from test_fee_model_native import RECIPIENT, _NATIVE_TAU, _NativeFeeE2EBase

BASE_FEE = 10
AMOUNT = 100


@pytest.mark.skipif(not _NATIVE_TAU, reason="native tau module not available")
class TestOwnKeyFeeRules(_NativeFeeE2EBase):
    def setUp(self):
        super().setUp()
        self.keys = {
            "a": (SK_ALICE, pubkey_hex(SK_ALICE)),
            "b": (SK_BOB, pubkey_hex(SK_BOB)),
            "c": (SK_MALLORY, pubkey_hex(SK_MALLORY)),
        }
        for _, pk in self.keys.values():
            self.assertTrue(any(ch in "abcdef" for ch in pk))
            chain_state._balances[pk] = 100000

    def _rule(self, guarded_key, fee):
        return (
            f"always ( (i12[t]:bv[384] = {{ #x{guarded_key} }}:bv[384]) -> "
            f"(o8[t]:bv[24] = {{ #x{fee:06x} }}:bv[24]) )."
        )

    def _signed(self, who, operations):
        sk, pk = self.keys[who]
        return json.dumps(sign_payload({
            "sender_pubkey": pk,
            "sequence_number": chain_state.get_sequence_number(pk),
            "expiration_time": int(time.time()) + 3600,
            "expire_at_height": 5000,
            "operations": operations,
            "fee_limit": "100",
        }, sk))

    def _mine_rule(self, who, rule):
        res = sendtx.queue_transaction(self._signed(who, {"0": rule}), propagate=False)
        self.assertTrue(res["ok"], f"rule tx rejected: {res}")
        block = createblock.create_block_from_mempool()
        self.assertEqual(len(block.get("transactions", [])), 1, block)
        self._seed_rule(rule, f"mined-rule-{who}")

    def _paid(self, who):
        """What `who` pays on top of the amount for one transfer, estimated and charged."""
        pk = self.keys[who][1]
        before = chain_state.get_balance(pk)
        ops = {"1": [[pk, RECIPIENT, str(AMOUNT)]]}
        res = sendtx.queue_transaction(self._signed(who, ops), propagate=False)
        self.assertTrue(res["ok"], f"transfer rejected: {res}")
        estimated = db.get_mempool_entries()[0]["estimated_fee"]
        block = createblock.create_block_from_mempool()
        self.assertEqual(len(block.get("transactions", [])), 1, block)
        charged = before - chain_state.get_balance(pk) - AMOUNT
        self.assertEqual(estimated, charged)
        return charged

    def test_each_account_pays_only_its_own_fee_rule(self):
        pk_a, pk_b, pk_c = (self.keys[k][1] for k in "abc")
        self._mine_rule("a", self._rule(pk_a, 5))
        self._mine_rule("b", self._rule(pk_b, 7))

        self.assertEqual(self._paid("c"), BASE_FEE)
        self.assertEqual(self._paid("a"), BASE_FEE + 5)
        self.assertEqual(self._paid("b"), BASE_FEE + 7)
        self.assertEqual(self._paid("c"), BASE_FEE)

    def test_a_rule_fenced_to_another_account_is_refused(self):
        pk_c = self.keys["c"][1]
        before = db.get_mempool_entries()
        res = sendtx.queue_transaction(
            self._signed("b", {"0": self._rule(pk_c, 9)}), propagate=False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "UNSCOPED_USER_RULE")
        self.assertEqual(db.get_mempool_entries(), before)
        self.assertEqual(self._paid("c"), BASE_FEE)

    def test_a_tax_on_every_sender_is_refused(self):
        pk_b = self.keys["b"][1]
        tax = (
            f"always ( ((i12[t]:bv[384] = {{ #x{pk_b} }}:bv[384]) || "
            f"(i1[t]:bv[24] > {{ #x000000 }}:bv[24])) -> "
            f"(o8[t]:bv[24] = {{ #x000064 }}:bv[24]) )."
        )
        res = sendtx.queue_transaction(self._signed("b", {"0": tax}), propagate=False)
        self.assertFalse(res["ok"])
        self.assertEqual(res["code"], "UNSCOPED_USER_RULE")


if __name__ == "__main__":
    unittest.main()
