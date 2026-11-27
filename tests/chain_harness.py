"""Shared block-apply harness for the payout-rule tests (#63).

Every scenario runs through the real `apply_block` with a scripted interpreter
and a mock policy evaluator, and compares the FULL balance map, sequences and
cooldown stamps against an oracle that only knows the documented rules.
`apply_block` itself raises on any supply drift, so every block here is also a
conservation check.

Extracted from tests/test_standing_apply.py when standing payments were
deleted (rules-form pivot, 23 Nov 2026): the standing helpers went with that
file; what is left is the harness every payout test shares.
"""
import hashlib
import itertools
from collections import defaultdict
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from block import Block
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.network_binding import BOUND_TX_TYPES, FIELD, chain_genesis_hash
from consensus.policy_mock import MockPolicyEvaluator
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_767_225_600  # 2026-01-01T00:00:00Z
FAR = 9_999_999_999


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
PROPOSER = "d4" * 48
SKS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL}

_TX_SEQ = itertools.count()
CLAUSE = "(o5[t]:bv[24] = { #x000001 }:bv[24])"


def _sign(tx: dict, sk: int) -> dict:
    """Sign like a wallet: a type bound to a network names this one first, unless
    the test has already named another."""
    if tx.get("tx_type") in BOUND_TX_TYPES:
        tx.setdefault(FIELD, chain_genesis_hash())
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def spend_tx(sender, to, amount, seq, fee_limit="100"):
    return _sign({
        "tx_id": f"spend-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "operations": {"1": [[sender, to, amount]]},
    }, SKS[sender])


class Chain:
    """Carries state across blocks and scripts the interpreter."""

    def __init__(self, balances, *, fee=0, slots=True, faucet=0):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.lm.faucet_amount = faucet
        if slots:
            self.lm.activate_approval_slots()
        self.fee = fee
        self.calls = []
        self.hashes = []
        self.last = None

    def _multi(self, **kwargs):
        self.calls.append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        return {1: str(vals.get(1, "0")), 8: "0", 9: str(self.fee), 5: "1"}

    def block(self, txs, height=HEIGHT, ts=TS, *, replay=False, proposer=PROPOSER):
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
            proposer_pubkey=proposer, timestamp=ts,
        )
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=self._multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = TauConsensusEngine().apply_block(view, blk, parent, replay_mode=replay)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.hashes.append(result.next_snapshot.state_hash)
        self.last = result
        return result

    @property
    def payout_rules(self):
        return self.lm.payout_rules

    def events(self):
        return self.last.next_snapshot.metadata["payout_events"]


class Oracle:
    def __init__(self, balances):
        self.bal = defaultdict(int, balances)
        self.seq = defaultdict(int)
        self.lts = {}

    def create(self, tx, *, fee, proposer=PROPOSER):
        sender = tx["sender_pubkey"]
        self.bal[sender] -= fee
        self.bal[proposer] += fee
        self.seq[sender] += 1

    def cancel(self, sender):
        self.seq[sender] += 1

    def pay(self, payer, recipient, amount, *, ts):
        self.bal[payer] -= amount
        self.bal[recipient] += amount
        self.lts[payer] = ts

    def spend(self, sender, to, amount, *, fee=0, ts, proposer=PROPOSER):
        self.bal[sender] -= amount + fee
        self.bal[to] += amount
        self.bal[proposer] += fee
        self.seq[sender] += 1
        self.lts[sender] = ts

    def check(self, ch: Chain):
        assert {k: v for k, v in ch.bal.items() if v} == \
            {k: v for k, v in self.bal.items() if v}
        assert {k: v for k, v in ch.seq.items() if v} == \
            {k: v for k, v in self.seq.items() if v}
        assert ch.lts == self.lts


def _balances():
    return {ALICE: 1_000, BOB: 0, CAROL: 0, PROPOSER: 0}


def _logs(result):
    out = []
    for outcome in result.outcomes:
        out.extend(outcome.receipt_logs or [])
    return " | ".join(str(x) for x in out)


@pytest.fixture
def evaluator():
    mock = MockPolicyEvaluator(pool="apply")
    sender_policy.set_evaluator("apply", mock)
    yield mock
    sender_policy.set_evaluator("apply", None)
