"""Block-apply semantics for conditional grants (Bounty 01, #63).

Runs through the real `apply_block` with a scripted evaluator,
mirroring tests/test_payouts_apply.py. The named test is the bounty
page's worked example end to end: creation escrows the money, the
weekly cap binds draws, and the deadline sweep refunds the exact
remainder to the sender, fee-free.

Draws are decided by the sender's grant clause: the harness seeds
the canonical clause for ALICE (the grant sender throughout) and
the scripted evaluator plays the Tau engine's role for it, reading
the verdict off the draw facts the node feeds (o29) -- a test may
override `ch.verdict` to script a stricter clause's answer.
"""

import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.grants import (
    CANONICAL_GRANT_CLAUSE,
    GRANT_STREAM_INDEX,
    parse_grant_create,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

FAR = 9_999_999_999
WEEK = 604800


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


DEC1 = _ts(2025, 12, 1)
DEADLINE = DEC1 + 4 * WEEK


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def create_tx(seq=0, total=5000, cap=500, extra=None):
    tx = {
        "tx_id": f"grant-create-{next(_TX_SEQ)}",
        "tx_type": "grant_create",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "recipient_pubkey": BOB,
        "total": total,
        "cap_per_period": cap,
        "opens_at": DEC1,
        "deadline": DEADLINE,
    }
    tx.update(extra or {})
    return _sign(tx, SK_ALICE)


def draw_tx(grant_id, amount, seq=0, sk=SK_BOB, sender=BOB, extra=None):
    tx = {
        "tx_id": f"grant-draw-{next(_TX_SEQ)}",
        "tx_type": "grant_draw",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "100",
        "grant_id": grant_id,
        "amount": amount,
    }
    tx.update(extra or {})
    return _sign(tx, sk)


class Chain:
    def __init__(self, balances, *, fee=0):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.lm.rule_offers.accepted_clauses[(ALICE, GRANT_STREAM_INDEX)] = (
            CANONICAL_GRANT_CLAUSE
        )
        self.fee = fee
        self.verdict = None
        self.last = None

    def _grant_verdict(self, vals):
        """The canonical clause's verdict over the fed draw facts,
        unless the test scripted one (a stricter clause's answer)."""
        if self.verdict is not None:
            return self.verdict
        ts = int(vals.get(5, 0))
        req = int(vals.get(24, 0))
        rem = int(vals.get(25, 0))
        drawn = int(vals.get(26, 0))
        cap = int(vals.get(27, 0))
        opens = int(vals.get(28, 0))
        deadline = int(vals.get(29, 0))
        group_drawn = int(vals.get(30, 0))
        group_cap = int(vals.get(31, 0))
        ok = (opens <= ts < deadline and req <= rem
              and drawn + req <= cap
              and (group_cap == 0 or group_drawn + req <= group_cap))
        return "1" if ok else "0"

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        out = {1: str(vals.get(1, "0")), 8: "0", 9: str(self.fee), 5: "1"}
        if 24 in vals:
            out[29] = self._grant_verdict(vals)
        return out

    def block(self, txs, height=20, ts=DEC1):
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
        return self.lm.grants

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids

    def receipt(self, tx):
        for outcome in self.last.outcomes:
            if outcome.tx_id == tx["tx_id"]:
                return {"logs": outcome.receipt_logs, "reason": outcome.reason}
        raise KeyError(tx["tx_id"])


def test_grant_5000_week_cap_refund_returns_remainder():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    create = create_tx()
    ch.block([create], height=20, ts=DEC1 - 60)
    assert ch.accepted(create), ch.receipt(create)
    grant_id = parse_grant_create(create).grant_id
    # Creation escrows the full 5,000 out of the sender's balance.
    assert ch.bal[ALICE] == 5_000
    assert ch.bal[BOB] == 0

    # Draws have not opened yet.
    early = draw_tx(grant_id, 100, seq=0)
    ch.block([early], height=21, ts=DEC1 - 30)
    assert not ch.accepted(early)
    assert ch.bal[BOB] == 0

    # Week 1: the 500 cap binds.
    d1 = draw_tx(grant_id, 500, seq=0)
    ch.block([d1], height=22, ts=DEC1 + 60)
    assert ch.accepted(d1), ch.receipt(d1)
    assert ch.bal[BOB] == 500
    over = draw_tx(grant_id, 1, seq=1)
    ch.block([over], height=23, ts=DEC1 + 120)
    assert not ch.accepted(over)
    assert ch.bal[BOB] == 500

    # A stranger cannot draw.
    stranger = draw_tx(grant_id, 100, seq=0, sk=SK_CAROL, sender=CAROL)
    ch.block([stranger], height=24, ts=DEC1 + WEEK)
    assert not ch.accepted(stranger)

    # Week 2 draw, then the deadline sweep refunds the remainder.
    d2 = draw_tx(grant_id, 500, seq=1)
    ch.block([d2], height=25, ts=DEC1 + WEEK + 60)
    assert ch.accepted(d2), ch.receipt(d2)
    assert ch.bal[BOB] == 1000

    ch.block([], height=26, ts=DEADLINE)
    state = ch.book.get(grant_id)
    assert state.refunded is True
    assert state.remaining == 0
    # 5,000 - 1,000 drawn = 4,000 back to the sender, in full.
    assert ch.bal[ALICE] == 5_000 + 4_000
    assert ch.bal[BOB] == 1000


def test_grant_shared_cap_binds_across_grants():
    # Two grants in one cap group: each has its own 500/week cap,
    # and together they may draw at most 600/week.
    ch = Chain({ALICE: 20_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    group = {"cap_group": "team-budget", "cap_group_cap": 600}
    c1 = create_tx(seq=0, total=5000, cap=500, extra=group)
    ch.block([c1], height=20, ts=DEC1 - 60)
    assert ch.accepted(c1), ch.receipt(c1)
    c2 = create_tx(seq=1, total=5000, cap=500,
                   extra={**group, "recipient_pubkey": CAROL})
    ch.block([c2], height=21, ts=DEC1 - 60)
    assert ch.accepted(c2), ch.receipt(c2)
    g1 = parse_grant_create(c1).grant_id
    g2 = parse_grant_create(c2).grant_id

    d1 = draw_tx(g1, 500, seq=0)
    ch.block([d1], height=22, ts=DEC1 + 60)
    assert ch.accepted(d1), ch.receipt(d1)
    assert ch.bal[BOB] == 500

    # Carol's grant has drawn nothing and its own cap is 500, but
    # the shared budget has only 100 left this week.
    over = draw_tx(g2, 101, seq=0, sk=SK_CAROL, sender=CAROL)
    ch.block([over], height=23, ts=DEC1 + 120)
    assert not ch.accepted(over)
    assert ch.bal[CAROL] == 0
    d2 = draw_tx(g2, 100, seq=0, sk=SK_CAROL, sender=CAROL)
    ch.block([d2], height=24, ts=DEC1 + 180)
    assert ch.accepted(d2), ch.receipt(d2)
    assert ch.bal[CAROL] == 100
