"""Block-apply semantics for standing payments (#34).

Every scenario runs through the real `apply_block` with a scripted interpreter
and a mock policy evaluator, and compares the FULL balance map, sequences,
cooldown stamps and the book against an oracle that only knows the documented
rules: one fee at creation, at most one payment per period, never without funds,
never past a cancel, the payer's current o5 clause re-checked every time.

`apply_block` itself raises on any supply drift, so every block here is also a
conservation check.
"""
import hashlib
import itertools
from collections import defaultdict
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from block import Block
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine, standing_payment_inputs
from consensus.governance import ConsensusLifecycleManager
from consensus.network_binding import BOUND_TX_TYPES, FIELD, chain_genesis_hash
from consensus.policy_mock import MockPolicyEvaluator
from consensus.standing import (
    MIN_INTERVAL_BLOCKS,
    parse_standing_payment_create,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes

HEIGHT = 20
TS = 1_767_225_600  # 2026-01-01T00:00:00Z
FAR = 9_999_999_999
EVERY = MIN_INTERVAL_BLOCKS


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


def create_tx(sender=ALICE, recipient=BOB, amount=100, seq=0, *, interval=EVERY,
              first_due=HEIGHT + 5, periods=3, kind="interval_blocks", fee_limit="100",
              signer_sk=None, mutate=None):
    tx = {
        "tx_id": f"create-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_create",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient,
        "amount": amount,
        kind: interval,
        "first_due": first_due,
        "periods": periods,
    }
    _sign(tx, signer_sk if signer_sk is not None else SKS[sender])
    if mutate:
        mutate(tx)
    return tx


def cancel_tx(sid_hex, sender=ALICE, seq=1, signer_sk=None):
    return _sign({
        "tx_id": f"cancel-{next(_TX_SEQ)}",
        "tx_type": "standing_payment_cancel",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "0",
        "standing_id": sid_hex,
    }, signer_sk if signer_sk is not None else SKS[sender])


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


def sid_of(tx) -> str:
    return parse_standing_payment_create(tx).standing_id.hex()


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
    def book(self):
        return self.lm.standing_payments

    def events(self):
        return self.last.next_snapshot.metadata["standing_events"]

    def outcomes(self):
        return [(e["outcome"], e["period"]) for e in self.events()]


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


# --- creation -------------------------------------------------------------------

def test_create_charges_one_fee_and_moves_no_money():
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    tx = create_tx()
    ch.block([tx])

    oracle.create(tx, fee=7)
    oracle.check(ch)
    assert ch.book.knows(bytes.fromhex(sid_of(tx)))
    assert ch.outcomes() == [("created", 0)]
    # Priced by the generic transfer-less fee query, not by a transfer step.
    fee_steps = [c["input_stream_values"] for c in ch.calls]
    assert len(fee_steps) == 1 and fee_steps[0][1] == "0" and fee_steps[0][4] == "0"


@pytest.mark.parametrize("over,why", [
    ({"first_due": HEIGHT}, "future"),
    ({"recipient": ALICE}, "recipient must differ"),
    ({"interval": EVERY - 1}, "interval_blocks"),
    ({"periods": 0}, "periods"),
    ({"amount": 0}, "amount"),
])
def test_an_inadmissible_create_stays_out_and_pays_nothing(over, why):
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    result = ch.block([create_tx(**over)])
    oracle.check(ch)
    assert not ch.book.terms and ch.book.is_empty()
    assert why in _logs(result)


@pytest.mark.parametrize("field,value", [
    ("amount", 101), ("recipient_pubkey", CAROL), ("first_due", HEIGHT + 6),
    ("periods", 4), ("interval_blocks", EVERY + 1),
])
def test_no_signed_term_can_be_changed_after_signing(field, value):
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    ch.block([create_tx(mutate=lambda tx: tx.__setitem__(field, value))])
    oracle.check(ch)
    assert not ch.book.terms


def test_a_create_signed_by_someone_else_is_refused():
    ch = Chain(_balances(), fee=7)
    ch.block([create_tx(signer_sk=SK_BOB)])
    assert not ch.book.terms and ch.bal[ALICE] == 1_000


@pytest.mark.parametrize("when", ["same block", "next block", "after a cancel", "after the end"])
def test_a_signed_create_is_applied_once_and_never_again(when):
    """A copy of the signed bytes is refused wherever it is replayed: the payer's
    sequence number has moved on, so the copy pays nothing and brings nothing back."""
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    tx = create_tx(periods=1)
    result = ch.block([tx, dict(tx)] if when == "same block" else [tx])
    oracle.create(tx, fee=7)
    again = HEIGHT + 1
    if when == "after a cancel":
        ch.block([cancel_tx(sid_of(tx))], height=HEIGHT + 1)
        oracle.cancel(ALICE)
        again = HEIGHT + 2
    if when == "after the end":
        ch.block([], height=HEIGHT + 5)
        oracle.pay(ALICE, BOB, 100, ts=TS)
        ch.block([], height=HEIGHT + 5 + EVERY)
        again = HEIGHT + 6 + EVERY
    if when != "same block":
        open_before = dict(ch.book.terms)
        result = ch.block([dict(tx)], height=again)
        assert ch.book.terms == open_before and ch.events() == []
    oracle.check(ch)
    assert "Invalid sequence number" in _logs(result)
    assert len(ch.book.terms) == (1 if when in ("same block", "next block") else 0)


# --- payments --------------------------------------------------------------------

def test_pays_once_per_period_until_the_schedule_ends():
    ch, oracle = Chain(_balances(), fee=7), Oracle(_balances())
    tx = create_tx(amount=100, first_due=HEIGHT + 5, periods=3)
    ch.block([tx])
    oracle.create(tx, fee=7)
    due = [HEIGHT + 5 + p * EVERY for p in range(3)]
    for h in range(HEIGHT + 1, due[-1] + EVERY + 3):
        ch.block([], height=h, ts=TS + h)
        if h in due:
            oracle.pay(ALICE, BOB, 100, ts=TS + h)
            assert ch.outcomes()[0] == ("paid", due.index(h))
        else:
            assert ch.events() == [], h
        oracle.check(ch)
    assert ch.bal[BOB] == 300 and not ch.book.terms and ch.book.resolved_count == 1


def test_an_unfunded_occurrence_never_creates_debt_and_pays_when_funded():
    ch, oracle = Chain({ALICE: 150, BOB: 0, CAROL: 500, PROPOSER: 0}), \
        Oracle({ALICE: 150, BOB: 0, CAROL: 500, PROPOSER: 0})
    tx = create_tx(amount=200, first_due=HEIGHT + 2)
    ch.block([tx])
    oracle.create(tx, fee=0)
    ch.block([], height=HEIGHT + 2, ts=TS + 2)
    assert ch.outcomes() == [("unfunded", 0)]
    oracle.check(ch)
    ch.block([], height=HEIGHT + 3, ts=TS + 3)
    assert ch.outcomes() == [("unfunded", 0)]
    # Carol tops Alice up; the retry in the next block pays, once.
    ch.block([spend_tx(CAROL, ALICE, 100, 0, fee_limit="0")], height=HEIGHT + 4, ts=TS + 4)
    oracle.spend(CAROL, ALICE, 100, ts=TS + 4)
    oracle.pay(ALICE, BOB, 200, ts=TS + 4)
    assert ch.outcomes() == [("paid", 0)]
    oracle.check(ch)
    ch.block([], height=HEIGHT + 5, ts=TS + 5)
    assert ch.events() == []
    assert ch.bal[ALICE] == 50


def test_a_payment_is_funded_by_money_that_arrives_in_the_same_block():
    ch, oracle = Chain({ALICE: 0, BOB: 0, CAROL: 500, PROPOSER: 0}), \
        Oracle({ALICE: 0, BOB: 0, CAROL: 500, PROPOSER: 0})
    tx = create_tx(amount=200, first_due=HEIGHT + 2)
    ch.block([tx])
    oracle.create(tx, fee=0)
    ch.block([spend_tx(CAROL, ALICE, 200, 0, fee_limit="0")], height=HEIGHT + 2, ts=TS + 2)
    oracle.spend(CAROL, ALICE, 200, ts=TS + 2)
    oracle.pay(ALICE, BOB, 200, ts=TS + 2)
    oracle.check(ch)


def test_the_payers_current_policy_is_rechecked_and_a_block_misses_the_period(evaluator):
    ch, oracle = Chain(_balances()), Oracle(_balances())
    tx = create_tx(amount=100, first_due=HEIGHT + 2, periods=2)
    ch.block([tx])
    oracle.create(tx, fee=0)
    # Alice freezes outgoing payments after creating the authorization.
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = CLAUSE
    evaluator.set_verdict(CLAUSE, 0)
    ch.block([], height=HEIGHT + 2, ts=TS + 2)
    assert ch.outcomes() == [("missed", 0)]
    assert ch.events()[0]["reason"] == "policy_block"
    oracle.check(ch)
    # Same period, later block: no retry after a policy block.
    calls = len(evaluator.verdict_calls)
    ch.block([], height=HEIGHT + 3, ts=TS + 3)
    assert ch.events() == [] and len(evaluator.verdict_calls) == calls
    # Unfrozen: the next period pays.
    evaluator.set_verdict(CLAUSE, None)
    h = HEIGHT + 2 + EVERY
    ch.block([], height=h, ts=TS + h)
    oracle.pay(ALICE, BOB, 100, ts=TS + h)
    assert ch.outcomes() == [("paid", 1), ("ended", 2)]
    oracle.check(ch)


def test_the_policy_sees_the_real_recipient_amount_and_empty_slots(evaluator):
    ch = Chain(_balances())
    ch.block([create_tx(amount=123, first_due=HEIGHT + 2)])
    ch.lm.rule_offers.accepted_clauses[(ALICE, 5)] = CLAUSE
    ch.block([], height=HEIGHT + 2, ts=TS + 2)
    body, inputs = evaluator.verdict_calls[-1]
    assert body == CLAUSE
    assert inputs["i1"] == "123"
    assert BOB in inputs["i4"] and ALICE in inputs["i3"] and ALICE in inputs["i12"]
    assert inputs["i2"] == str(1_000)
    assert inputs["i5"] == str(TS + 2)
    assert all(inputs[f"i{n}"] == "0" for n in range(18, 26))


def test_a_cancel_wins_over_a_payment_due_in_the_same_block():
    ch, oracle = Chain(_balances()), Oracle(_balances())
    tx = create_tx(first_due=HEIGHT + 2)
    ch.block([tx])
    oracle.create(tx, fee=0)
    ch.block([cancel_tx(sid_of(tx))], height=HEIGHT + 2, ts=TS + 2)
    oracle.cancel(ALICE)
    assert ch.outcomes() == [("cancelled", 0)]
    oracle.check(ch)
    for h in range(HEIGHT + 3, HEIGHT + 3 * EVERY):
        ch.block([], height=h, ts=TS + h)
        assert ch.events() == []
    oracle.check(ch)


def test_only_the_payer_can_cancel():
    ch, oracle = Chain(_balances()), Oracle(_balances())
    tx = create_tx(first_due=HEIGHT + 2)
    ch.block([tx])
    oracle.create(tx, fee=0)
    result = ch.block([cancel_tx(sid_of(tx), sender=BOB, seq=0)], height=HEIGHT + 1)
    assert "only the payer may cancel" in _logs(result)
    assert ch.book.knows(bytes.fromhex(sid_of(tx)))
    oracle.check(ch)


def test_a_recipient_with_no_record_gets_the_grant_and_the_payment():
    ch = Chain({ALICE: 1_000, PROPOSER: 0}, faucet=50)
    ch.block([create_tx(recipient=CAROL, amount=100, first_due=HEIGHT + 2)])
    ch.block([], height=HEIGHT + 2, ts=TS + 2)
    assert ch.bal[CAROL] == 150  # grant + payment; apply_block checked the mint


def test_a_payment_stamps_the_cooldown_clock_once():
    ch = Chain(_balances())
    ch.block([create_tx(first_due=HEIGHT + 2)])
    assert ALICE not in ch.lts
    ch.block([], height=HEIGHT + 2, ts=TS + 99)
    assert ch.lts == {ALICE: TS + 99}


def test_replay_and_a_fresh_apply_give_the_same_state_hashes(evaluator):
    def run(replay):
        ch = Chain({ALICE: 300, BOB: 0, CAROL: 500, PROPOSER: 0}, fee=3)
        txs = [create_tx(amount=100, first_due=HEIGHT + 2, periods=4)]
        ch.block(txs)
        for h in range(HEIGHT + 1, HEIGHT + 4 * EVERY + 4):
            block_txs = []
            if h == HEIGHT + EVERY + 2:
                block_txs = [spend_tx(CAROL, ALICE, 300, 0, fee_limit="3")]
            ch.block(block_txs, height=h, ts=TS + h, replay=replay)
        return ch.hashes, ch.bal

    live, replayed = run(False), run(True)
    assert live == replayed


def test_the_payment_inputs_match_the_transfer_input_order():
    values = standing_payment_inputs(ALICE, BOB, 5, parent_balance="9", since_last="7",
                                     slots_active=True, timestamp=TS)
    keys = list(values)
    assert keys[:6] == [1, 2, 16, 3, 4, 12] and keys[-1] == 5
    assert values[1] == "5" and values[2] == "9" and values[16] == "7"
