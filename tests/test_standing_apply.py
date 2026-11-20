"""Block-apply semantics for standing payments (Bounty 01, issue #34).

Runs through the real `apply_block` with a scripted evaluator, mirroring
tests/test_retractable_apply.py. The named tests are the engine-level
half of the design's case -> test mapping for #34: the book-level half
lives in tests/test_standing.py.
"""

import hashlib
import itertools
from datetime import datetime, timezone
from unittest.mock import patch

from py_ecc.bls import G2Basic

from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.periods import PERIOD_MONTH, SECONDS_PER_DAY
from consensus.standing import parse_standing_create
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

FAR = 9_999_999_999


def _ts(year, month, day, hour=0):
    return int(datetime(year, month, day, hour, tzinfo=timezone.utc).timestamp())


ANCHOR = _ts(2026, 1, 31, 12)  # monthly, anchored on the 31st
BEFORE = _ts(2026, 1, 30, 12)
DUE_JAN = _ts(2026, 1, 31, 13)  # inside the January window
DUE_FEB = _ts(2026, 2, 28, 12)  # February window (clamped to the 28th)


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


def create_tx(sk=SK_ALICE, sender=ALICE, recipient=BOB, amount=1000, seq=0,
              fee_limit="100", signer_sk=None, extra=None, drop=()):
    tx = {
        "tx_id": f"standing-create-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_create",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient,
        "amount": amount,
        "period_kind": PERIOD_MONTH,
        "anchor_timestamp": ANCHOR,
        "window_start_offset": 0,
        "window_end_offset": SECONDS_PER_DAY,
        "max_occurrences": 12,
    }
    for key in drop:
        tx.pop(key, None)
    tx.update(extra or {})
    return _sign(tx, signer_sk if signer_sk is not None else sk)


def execute_tx(standing_id_hex, sk=SK_CAROL, sender=CAROL, seq=0, fee_limit="100"):
    tx = {
        "tx_id": f"standing-execute-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_execute",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "standing_id": standing_id_hex,
    }
    return _sign(tx, sk)


def cancel_tx(standing_id_hex, sk=SK_ALICE, sender=ALICE, seq=1, fee_limit="100"):
    tx = {
        "tx_id": f"standing-cancel-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_cancel",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "standing_id": standing_id_hex,
    }
    return _sign(tx, sk)


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
    }, _KEYS[sender])


class Chain:
    def __init__(self, balances, *, fee=0):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        self.fee = fee
        self.last = None

    def _multi(self, **kwargs):
        vals = kwargs.get("input_stream_values") or {}
        amount = str(vals.get(1, "0"))
        return {1: amount, 8: "0", 9: str(self.fee), 5: "1"}

    def block(self, txs, height=20, ts=BEFORE):
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
        return self.lm.standing_payments

    def accepted(self, tx):
        return tx["tx_id"] in self.last.accepted_tx_ids


def _balances():
    return {ALICE: 10_000, BOB: 0, CAROL: 100, MALLORY: 100, PROPOSER: 0}


def _created_chain(fee=0):
    ch = Chain(_balances(), fee=fee)
    tx = create_tx()
    ch.block([tx], height=20, ts=BEFORE)
    assert ch.accepted(tx)
    sid = parse_standing_create(tx).standing_id
    assert ch.book.get(sid) is not None
    return ch, sid


def test_create_then_anyone_executes_and_money_moves_once():
    ch, sid = _created_chain()
    ex = execute_tx(sid.hex())  # Carol executes; she is neither party.
    ch.block([ex], height=21, ts=DUE_JAN)
    assert ch.accepted(ex)
    assert ch.bal[ALICE] == 9_000
    assert ch.bal[BOB] == 1_000
    assert ch.book.paid_for_period(sid, 0)


def test_second_execution_in_same_period_is_rejected():
    ch, sid = _created_chain()
    ch.block([execute_tx(sid.hex())], height=21, ts=DUE_JAN)
    ex2 = execute_tx(sid.hex(), seq=1)
    ch.block([ex2], height=22, ts=DUE_JAN + 3600)
    assert not ch.accepted(ex2)
    assert ch.bal[ALICE] == 9_000
    assert ch.bal[BOB] == 1_000


def test_execution_outside_the_window_is_rejected():
    ch, sid = _created_chain()
    ex = execute_tx(sid.hex())
    ch.block([ex], height=21, ts=BEFORE)  # a day before the first window
    assert not ch.accepted(ex)
    assert ch.bal[BOB] == 0


def test_february_execution_uses_the_clamped_day():
    ch, sid = _created_chain()
    ch.block([execute_tx(sid.hex())], height=21, ts=DUE_JAN)
    ex = execute_tx(sid.hex(), seq=1)
    ch.block([ex], height=22, ts=DUE_FEB)
    assert ch.accepted(ex)
    assert ch.bal[BOB] == 2_000
    assert ch.book.paid_for_period(sid, 1)


def test_cancel_prevents_all_later_executions():
    ch, sid = _created_chain()
    cx = cancel_tx(sid.hex())
    ch.block([cx], height=21, ts=BEFORE + 3600)
    assert ch.accepted(cx)
    ex = execute_tx(sid.hex())
    ch.block([ex], height=22, ts=DUE_JAN)
    assert not ch.accepted(ex)
    assert ch.bal[BOB] == 0


def test_only_the_payer_can_cancel():
    ch, sid = _created_chain()
    cx = cancel_tx(sid.hex(), sk=SK_MALLORY, sender=MALLORY, seq=0)
    ch.block([cx], height=21, ts=BEFORE + 3600)
    assert not ch.accepted(cx)
    assert ch.book.get(sid) is not None


def test_insufficient_funds_execution_leaves_the_marker_untouched():
    ch = Chain({ALICE: 500, BOB: 0, CAROL: 5_000, MALLORY: 0, PROPOSER: 0})
    tx = create_tx()
    ch.block([tx], height=20, ts=BEFORE)
    sid = parse_standing_create(tx).standing_id
    ex = execute_tx(sid.hex())
    ch.block([ex], height=21, ts=DUE_JAN)
    assert not ch.accepted(ex)  # Alice has 500 < 1000 due
    assert not ch.book.paid_for_period(sid, 0)
    # Carol tops Alice up inside the same window; execution now succeeds.
    top = spend_tx(CAROL, ALICE, 600, seq=0)
    ch.block([top], height=22, ts=DUE_JAN + 600)
    ex2 = execute_tx(sid.hex(), seq=1)
    ch.block([ex2], height=23, ts=DUE_JAN + 1200)
    assert ch.accepted(ex2)
    assert ch.bal[BOB] == 1_000
    assert ch.book.paid_for_period(sid, 0)


def test_create_without_exactly_one_end_condition_is_rejected():
    ch = Chain(_balances())
    two = create_tx(extra={"max_total": 12_000})
    ch.block([two], height=20, ts=BEFORE)
    assert not ch.accepted(two)
    none = create_tx(drop=("max_occurrences",))
    ch.block([none], height=21, ts=BEFORE)
    assert not ch.accepted(none)
    assert ch.book.is_empty()


def test_executor_pays_the_fee_not_the_payer():
    ch, sid = _created_chain(fee=7)
    # Creation was transfer-less: its signer (Alice) paid the fee step.
    assert ch.bal[ALICE] == 10_000 - 7
    ex = execute_tx(sid.hex())
    ch.block([ex], height=21, ts=DUE_JAN)
    assert ch.accepted(ex)
    # The transfer debited the payer exactly the amount; the execution
    # fee (7) came out of the executor, Carol.
    assert ch.bal[ALICE] == 10_000 - 7 - 1_000
    assert ch.bal[BOB] == 1_000
    assert ch.bal[CAROL] == 100 - 7
