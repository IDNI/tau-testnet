"""Block-apply semantics for payout rules (Bounty 01, issue #63).

Runs through the real `apply_block` with a scripted evaluator,
mirroring tests/test_routes_apply.py. The named tests are the
engine-level half of the design's case -> test mapping for #63.
"""

import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.payouts import PAYOUT_STREAM_INDEX, parse_payout_install
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

FAR = 9_999_999_999


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


NOW = _ts(2026, 1, 15, 12)
JAN1 = _ts(2026, 1, 1)


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_MALLORY, MALLORY = _key(66666)
PROPOSER = "d4" * 48
_KEYS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, MALLORY: SK_MALLORY}

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def install_tx(owner=ALICE, sk=SK_ALICE, seq=0, extra=None, **kw):
    tx = {
        "tx_id": f"payout-install-{next(_TX_SEQ)}",
        "tx_type": "payout_rule_install",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "max_per_execution": kw.get("max_per_execution", 1000),
        "max_per_period": kw.get("max_per_period", 1500),
        "recipients": kw.get("recipients", [BOB, CAROL]),
        "period_kind": kw.get("period_kind", 2),
        "anchor_ts": kw.get("anchor_ts", JAN1),
    }
    tx.update(extra or {})
    return _sign(tx, sk)


def execute_tx(owner=ALICE, executor=CAROL, sk=SK_CAROL, seq=0,
               settlement_id="s1", gross=101, extra=None):
    tx = {
        "tx_id": f"payout-exec-{next(_TX_SEQ)}",
        "tx_type": "payout_execute",
        "sender_pubkey": executor,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "owner": owner,
        "settlement_id": settlement_id,
        "gross": gross,
    }
    tx.update(extra or {})
    return _sign(tx, sk)


def remove_tx(owner=ALICE, sk=SK_ALICE, seq=1, rule_id="", extra=None):
    tx = {
        "tx_id": f"payout-remove-{next(_TX_SEQ)}",
        "tx_type": "payout_rule_remove",
        "sender_pubkey": owner,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "rule_id": rule_id,
    }
    tx.update(extra or {})
    return _sign(tx, sk)


class Chain:
    def __init__(self, balances, *, fee=0):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.fee = fee
        self.legs = {}
        self.last = None

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        out = {1: str(vals.get(1, "0")), 8: "0", 9: str(self.fee), 5: "1"}
        marker = vals.get(3)
        if isinstance(marker, str) and marker.startswith("{ #x"):
            out.update(self.legs)
        return out

    def block(self, txs, height=20, ts=NOW):
        parent = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": dict(self.bal),
                "sequence_numbers": dict(self.seq),
                "last_transfer_ts": dict(self.lts),
                "lifecycle_manager": self.lm,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )
        view = ActiveConsensusView(
            target_height=height,
            consensus_rules=parent.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ALICE)],
            mechanism_specific_metadata={"poa": True},
        )
        blk = Block.create(
            block_number=height, previous_hash="00" * 32, transactions=txs,
            proposer_pubkey=PROPOSER, timestamp=ts,
        )
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=self._multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, blk, parent)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.last = result
        return result

    @property
    def book(self):
        return self.lm.payout_rules

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids

    def receipt(self, tx):
        for outcome in self.last.outcomes:
            if outcome.tx_id == tx["tx_id"]:
                return {"logs": outcome.receipt_logs, "reason": outcome.reason}
        raise KeyError(tx["tx_id"])


def _installed_chain(fee=0, **kw):
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0}, fee=fee)
    ch.lm.rule_offers.accepted_clauses[(ALICE, PAYOUT_STREAM_INDEX)] = (
        "always (o20[t] = 1)."
    )
    tx = install_tx(**kw)
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx), ch.receipt(tx)
    assert ch.book.get(ALICE) is not None
    return ch, parse_payout_install(tx)


def test_payout_all_legs_atomic_or_none():
    ch, _terms = _installed_chain()
    ch.legs = {20: "2", 21: "600", 22: "0", 23: "400", 24: "1"}
    ex = execute_tx(gross=1000)
    ch.block([ex], height=21, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[BOB] == 600
    assert ch.bal[CAROL] == 400
    assert ch.bal[ALICE] == 10_000 - 1000

    # A second execution whose legs exceed the per-execution cap
    # moves NOTHING -- no leg is paid partially.
    ch.legs = {20: "1", 21: "1001", 22: "0"}
    ex2 = execute_tx(seq=1, settlement_id="s2", gross=1001)
    ch.block([ex2], height=22, ts=NOW)
    assert not ch.accepted(ex2)
    assert ch.bal[BOB] == 600
    assert ch.bal[ALICE] == 10_000 - 1000


def test_royalty_execution_pays_once_at_apply():
    ch, _terms = _installed_chain()
    ch.legs = {20: "1", 21: "5", 22: "0"}
    ex = execute_tx(settlement_id="royalty-101", gross=101)
    ch.block([ex], height=21, ts=NOW)
    assert ch.accepted(ex), ch.receipt(ex)
    assert ch.bal[BOB] == 5
    replay = execute_tx(seq=1, settlement_id="royalty-101", gross=101)
    ch.block([replay], height=22, ts=NOW)
    assert not ch.accepted(replay)
    assert ch.bal[BOB] == 5


def test_payout_rule_removal_follows_account_rules():
    ch, terms = _installed_chain()
    # A stranger cannot remove the owner's rule.
    bad = remove_tx(sk=SK_MALLORY, seq=0, rule_id=terms.rule_id)
    bad["sender_pubkey"] = MALLORY
    bad = _sign(bad, SK_MALLORY)
    ch.block([bad], height=21, ts=NOW)
    assert not ch.accepted(bad)
    assert ch.book.get(ALICE) is not None
    # The owner can.
    good = remove_tx(seq=1, rule_id=terms.rule_id)
    ch.block([good], height=22, ts=NOW)
    assert ch.accepted(good), ch.receipt(good)
    assert ch.book.get(ALICE) is None


def test_execution_without_clause_settles_nothing():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0})
    tx = install_tx()
    ch.block([tx], height=20, ts=NOW)
    assert ch.accepted(tx)
    ch.legs = {20: "1", 21: "5", 22: "0"}
    ex = execute_tx(gross=101)
    ch.block([ex], height=21, ts=NOW)
    assert not ch.accepted(ex)
    assert ch.bal[BOB] == 0
    assert ch.bal[ALICE] == 10_000
