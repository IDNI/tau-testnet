"""Block-apply semantics for retractable transfers.

Every scenario runs through the real `apply_block` with a scripted evaluator and
is checked against an accounting oracle that knows nothing about the engine: it
aggregates expected balance deltas BY ADDRESS per transition (park, retract,
release, ordinary spend) and the tests compare the FULL balance map, the escrow
total, the open set, sequences and last-transfer stamps after every block.
"""
import hashlib
import itertools
from collections import defaultdict
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

import config
import consensus.retractable as retractable
from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    RetractableEntry,
    parse_retractable_transfer,
)
from consensus.state import TauStateSnapshot
from consensus.tx_signing import signing_message_bytes
from errors import BlockchainBug

HEIGHT = 20
TS = 1_700_000_000
FAR = 9_999_999_999


def _key(seed: int):
    return seed, G2Basic.SkToPk(seed).hex()


SK_ALICE, ALICE = _key(11111)
SK_BOB, BOB = _key(44444)
SK_CAROL, CAROL = _key(55555)
SK_MALLORY, MALLORY = _key(66666)
PROPOSER = "d4" * 48

_TX_SEQ = itertools.count()


@pytest.fixture(autouse=True)
def _no_faucet(monkeypatch):
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False)


def _sign(tx: dict, sk: int) -> dict:
    digest = hashlib.sha256(signing_message_bytes(tx)).digest()
    tx["signature"] = G2Basic.Sign(sk, digest).hex()
    return tx


def park_tx(sk=SK_ALICE, sender=ALICE, recipient=BOB, amount=100, seq=0, *,
            at_height=HEIGHT + 10, at_time=None, fee_limit="100",
            expire_at_height=1000, expiration_time=FAR, signer_sk=None,
            extra=None, mutate=None):
    tx = {
        "tx_id": f"park-{next(_TX_SEQ)}",
        "tx_type": "retractable_transfer",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": expiration_time,
        "expire_at_height": expire_at_height,
        "fee_limit": str(fee_limit),
        "recipient_pubkey": recipient,
        "amount": amount,
    }
    if at_time is not None:
        tx["release_at_time"] = at_time
    elif at_height is not None:
        tx["release_at_height"] = at_height
    if mutate:
        mutate(tx)
    tx.update(extra or {})
    return _sign(tx, signer_sk if signer_sk is not None else sk)


def retract_tx(rid_hex, sk=SK_ALICE, sender=ALICE, seq=1, signer_sk=None):
    tx = {
        "tx_id": f"retract-{next(_TX_SEQ)}",
        "tx_type": "retract_transfer",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": "0",
        "retractable_id": rid_hex,
    }
    return _sign(tx, signer_sk if signer_sk is not None else sk)


def spend_tx(sender, to, amount, seq, fee_limit="100"):
    return {
        "tx_id": f"spend-{next(_TX_SEQ)}",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000,
        "fee_limit": str(fee_limit),
        "operations": {"1": [[sender, to, amount]]},
    }


def rid_of(tx) -> str:
    return parse_retractable_transfer(tx).retractable_id.hex()


class Chain:
    """Carries state across blocks and scripts the evaluator."""

    def __init__(self, balances, *, fee=0, block_o5=False, slots=True):
        self.bal = dict(balances)
        self.seq = {}
        self.lts = {}
        self.lm = ConsensusLifecycleManager(active_validators=[ALICE])
        if slots:
            self.lm.activate_approval_slots()
        self.fee = fee
        self.block_o5 = block_o5
        self.calls = []
        self.history = []   # (txs, height, ts, proposer, fee, block_o5, state_hash)
        self.last = None

    def _multi(self, **kwargs):
        self.calls.append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        amount = str(vals.get(1, "0"))
        return {1: amount, 8: "0", 9: str(self.fee),
                5: "0" if self.block_o5 else "1"}

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
        engine = TauConsensusEngine()
        with patch("tau_manager.communicate_with_tau", return_value="T"), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=self._multi), \
             patch("chain_state.get_application_rules_state", return_value=""), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = engine.apply_block(view, blk, parent, replay_mode=replay)
        meta = result.next_snapshot.metadata
        self.bal = dict(meta["balances"])
        self.seq = dict(meta["sequence_numbers"])
        self.lts = dict(meta["last_transfer_ts"])
        self.lm = meta["lifecycle_manager"]
        self.history.append((txs, height, ts, proposer, self.fee, self.block_o5,
                             result.next_snapshot.state_hash))
        self.last = result
        return result

    # -- observable state ----------------------------------------------------

    @property
    def book(self):
        return self.lm.retractable_transfers

    def snapshot(self):
        nonzero = {k: v for k, v in self.bal.items() if v}
        return (nonzero, dict(self.seq), dict(self.lts), self.book.root(),
                self.book.escrow_total(), frozenset(self.book.open))


class Oracle:
    """Expected state, derived from transitions only."""

    def __init__(self, balances):
        self.bal = defaultdict(int, balances)
        self.seq = defaultdict(int)
        self.lts = {}
        self.open = {}
        self.resolved = 0

    @property
    def escrow(self):
        return sum(e.amount for e in self.open.values())

    def park(self, tx, *, fee, ts, proposer=PROPOSER):
        e = parse_retractable_transfer(tx)
        self.bal[e.sender_pubkey] -= e.amount + fee
        self.bal[proposer] += fee
        self.open[e.retractable_id.hex()] = e
        self.seq[e.sender_pubkey] += 1
        self.lts[e.sender_pubkey] = ts

    def retract(self, rid_hex, sender):
        e = self.open.pop(rid_hex)
        self.bal[sender] += e.amount
        self.seq[sender] += 1
        self.resolved += 1

    def release(self, rid_hex):
        e = self.open.pop(rid_hex)
        self.bal[e.recipient_pubkey] += e.amount
        self.resolved += 1

    def spend(self, sender, to, amount, *, fee=0, ts, proposer=PROPOSER):
        self.bal[sender] -= amount + fee
        self.bal[to] += amount
        self.bal[proposer] += fee
        self.seq[sender] += 1
        self.lts[sender] = ts

    def check(self, ch: Chain):
        assert {k: v for k, v in ch.bal.items() if v} == \
            {k: v for k, v in self.bal.items() if v}
        assert ch.book.escrow_total() == self.escrow
        assert set(ch.book.open) == {bytes.fromhex(k) for k in self.open}
        assert {k: v for k, v in ch.seq.items() if v} == \
            {k: v for k, v in self.seq.items() if v}
        assert ch.lts == self.lts
        assert ch.book.resolved_count == self.resolved


def _balances():
    return {ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0}


def _logs(result):
    out = []
    for outcome in result.outcomes:
        out.extend(outcome.receipt_logs or [])
    return " | ".join(str(x) for x in out)


# --- park ---------------------------------------------------------------------

def test_park_escrows_the_amount_and_charges_one_fee():
    ch = Chain(_balances(), fee=7)
    oracle = Oracle(_balances())
    tx = park_tx(amount=500)
    result = ch.block([tx])

    oracle.park(tx, fee=7, ts=TS)
    oracle.check(ch)
    assert ch.bal[BOB] == 0
    assert ch.bal[ALICE] == 10_000 - 500 - 7
    assert ch.book.escrow_total() == 500
    assert ch.seq[ALICE] == 1
    assert ch.lts[ALICE] == TS
    assert len(ch.calls) == 1, "the transfer-less fee query must not run as well"
    assert result.accepted_tx_ids == [tx["tx_id"]]
    assert "Retractable transfer parked" in _logs(result)


def test_park_works_with_approval_slots_inactive():
    ch = Chain(_balances(), slots=False)
    oracle = Oracle(_balances())
    tx = park_tx()
    ch.block([tx])
    oracle.park(tx, fee=0, ts=TS)
    oracle.check(ch)


def test_park_with_no_fee_model_moves_only_the_escrow():
    ch = Chain(_balances(), fee=0)
    tx = park_tx(amount=250)
    ch.block([tx])
    assert ch.bal[ALICE] == 10_000 - 250
    assert ch.bal[PROPOSER] == 0


def _untouched(ch, before):
    assert ch.snapshot() == before


def _rejected_cases():
    """(id, chain kwargs, tx factory, optional chain prep)."""
    def prep_cap(ch, monkeypatch, which):
        monkeypatch.setattr(retractable, which, 1)
        ch.block([park_tx(amount=1, seq=0, at_height=HEIGHT + 5)], height=HEIGHT - 1)
        ch.history.clear()

    def prep_dup(ch, monkeypatch):
        entry = parse_retractable_transfer(park_tx(amount=100, seq=0))
        ch.book.submit(entry)
        ch.bal[ALICE] -= entry.amount

    return [
        ("o5_block", dict(block_o5=True), lambda: park_tx(), None),
        ("insufficient_funds", {}, lambda: park_tx(amount=10_001), None),
        ("fee_limit_exceeded", dict(fee=50), lambda: park_tx(fee_limit="10"), None),
        ("insufficient_for_fee", dict(fee=5),
         lambda: park_tx(amount=10_000), None),
        ("wrong_sequence", {}, lambda: park_tx(seq=5), None),
        ("expired_time", {}, lambda: park_tx(expiration_time=TS - 1), None),
        ("expired_height", {}, lambda: park_tx(expire_at_height=HEIGHT), None),
        ("forged", {}, lambda: park_tx(signer_sk=SK_MALLORY), None),
        ("shape_both_releases", {},
         lambda: park_tx(mutate=lambda t: t.update(release_at_time=TS + 50)), None),
        ("release_not_future", {}, lambda: park_tx(at_height=HEIGHT), None),
        ("per_sender_cap", {}, lambda: park_tx(amount=2, seq=1),
         lambda ch, mp: prep_cap(ch, mp, "MAX_OPEN_RETRACTABLE_PER_SENDER")),
        ("global_cap", {}, lambda: park_tx(amount=2, seq=1),
         lambda ch, mp: prep_cap(ch, mp, "MAX_OPEN_RETRACTABLE_TOTAL")),
        ("duplicate", {}, lambda: park_tx(amount=100, seq=0), prep_dup),
    ]


@pytest.mark.parametrize(
    "name,kwargs,factory,prep", _rejected_cases(),
    ids=[c[0] for c in _rejected_cases()],
)
def test_a_rejected_park_changes_nothing(monkeypatch, name, kwargs, factory, prep):
    ch = Chain(_balances(), **kwargs)
    if prep:
        prep(ch, monkeypatch)
    before = ch.snapshot()
    tx = factory()
    result = ch.block([tx])
    assert result.invalid_tx_ids == [tx["tx_id"]], _logs(result)
    assert result.accepted_tx_ids == []
    _untouched(ch, before)


def test_a_park_signed_by_another_account_is_a_hard_reject():
    ch = Chain(_balances())
    before = ch.snapshot()
    # Carol signs a park that names Alice as the sender: forged, not merely
    # unauthorised.
    tx = park_tx(sender=ALICE, signer_sk=SK_CAROL)
    result = ch.block([tx])
    assert result.invalid_tx_ids == [tx["tx_id"]]
    _untouched(ch, before)


def test_stray_payload_and_operations_cause_no_extra_tau_work():
    ch = Chain(_balances(), fee=3)
    tx = park_tx(
        amount=300,
        extra={
            "payload": {"recipient_pubkey": CAROL, "amount": 1, "operations": {"13": ["9"]}},
            "operations": {"13": ["5"], "1": [[ALICE, CAROL, 9_000]], "0": "always (o0[t]=0)."},
        },
    )
    ch.block([tx])
    oracle = Oracle(_balances())
    oracle.park(tx, fee=3, ts=TS)
    oracle.check(ch)
    assert len(ch.calls) == 1
    inputs = ch.calls[0]["input_stream_values"]
    assert 13 not in inputs
    assert inputs[1] == "300"
    assert ch.bal[CAROL] == 0


# --- retract ------------------------------------------------------------------

def _parked(ch, oracle, *, amount=400, seq=0, **kw):
    tx = park_tx(amount=amount, seq=seq, **kw)
    ch.block([tx], height=HEIGHT, ts=TS)
    oracle.park(tx, fee=ch.fee, ts=TS)
    return tx, rid_of(tx)


def test_retract_refunds_the_sender():
    ch = Chain(_balances(), fee=4)
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle)
    lts_before = dict(ch.lts)

    result = ch.block([retract_tx(rid)], height=HEIGHT + 1, ts=TS + 10)
    oracle.retract(rid, ALICE)
    oracle.check(ch)
    assert ch.bal[ALICE] == 10_000 - 4, "the fee is never refunded"
    assert ch.lts == lts_before, "a retract is not a send"
    assert ch.book.resolved_count == 1
    assert "Retractable transfer retracted" in _logs(result)
    assert len(ch.calls) == 1, "a retract is feeless and runs no Tau step"


def test_only_the_sender_may_retract():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle)
    before = ch.snapshot()
    tx = retract_tx(rid, sk=SK_CAROL, sender=CAROL, seq=0)
    result = ch.block([tx], height=HEIGHT + 1)
    assert result.invalid_tx_ids == [tx["tx_id"]]
    _untouched(ch, before)


def test_a_second_retract_is_a_no_op():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle)
    first = retract_tx(rid, seq=1)
    second = retract_tx(rid, seq=2)
    result = ch.block([first, second], height=HEIGHT + 1)
    oracle.retract(rid, ALICE)
    oracle.check(ch)
    assert result.invalid_tx_ids == [second["tx_id"]]


def test_a_retract_in_a_later_block_after_resolution_is_a_no_op():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle)
    ch.block([retract_tx(rid, seq=1)], height=HEIGHT + 1)
    oracle.retract(rid, ALICE)
    before = ch.snapshot()
    late = retract_tx(rid, seq=2)
    result = ch.block([late], height=HEIGHT + 2)
    assert result.invalid_tx_ids == [late["tx_id"]]
    _untouched(ch, before)


def test_a_retract_at_the_release_height_loses_to_the_sweep():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle, at_height=HEIGHT + 5)
    late = retract_tx(rid, seq=1)
    result = ch.block([late], height=HEIGHT + 5)
    oracle.release(rid)
    oracle.check(ch)
    assert result.invalid_tx_ids == [late["tx_id"]]
    assert ch.bal[BOB] == 400
    assert result.governance_changes["released_retractables"] == [rid]


def test_a_retract_one_block_before_the_release_height_wins():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle, at_height=HEIGHT + 5)
    ch.block([retract_tx(rid, seq=1)], height=HEIGHT + 4)
    oracle.retract(rid, ALICE)
    oracle.check(ch)
    assert ch.bal[BOB] == 0


def test_time_kind_retract_is_judged_by_the_header_timestamp():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle, at_height=None, at_time=TS + 100)

    late = retract_tx(rid, seq=1)
    result = ch.block([late], height=HEIGHT + 1, ts=TS + 100)
    oracle.release(rid)
    oracle.check(ch)
    assert result.invalid_tx_ids == [late["tx_id"]]

    ch2 = Chain(_balances())
    oracle2 = Oracle(_balances())
    _, rid2 = _parked(ch2, oracle2, at_height=None, at_time=TS + 100)
    ch2.block([retract_tx(rid2, seq=1)], height=HEIGHT + 1, ts=TS + 99)
    oracle2.retract(rid2, ALICE)
    oracle2.check(ch2)


# --- release ------------------------------------------------------------------

def test_the_sweep_releases_at_the_first_block_at_or_after_the_height():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle, at_height=HEIGHT + 5)

    for h in (HEIGHT + 1, HEIGHT + 4):
        ch.block([], height=h)
        oracle.check(ch)
        assert ch.bal[BOB] == 0
    # The chain skips past the release height: the first block at or after it
    # releases, even though it is EMPTY.
    result = ch.block([], height=HEIGHT + 7)
    oracle.release(rid)
    oracle.check(ch)
    assert ch.bal[BOB] == 400
    assert result.governance_changes["released_retractables"] == [rid]


def test_time_kind_releases_on_an_empty_block():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle, at_height=None, at_time=TS + 60)
    ch.block([], height=HEIGHT + 1, ts=TS + 30)
    oracle.check(ch)
    ch.block([], height=HEIGHT + 2, ts=TS + 60)
    oracle.release(rid)
    oracle.check(ch)
    assert ch.bal[BOB] == 400


def test_many_entries_maturing_together_all_release():
    ch = Chain(_balances(), fee=1)
    oracle = Oracle(_balances())
    txs = [park_tx(amount=10 + i, seq=i, at_height=HEIGHT + 3,
                   recipient=BOB if i % 2 else CAROL) for i in range(6)]
    ch.block(txs, height=HEIGHT)
    for tx in txs:
        oracle.park(tx, fee=1, ts=TS)
    oracle.check(ch)

    result = ch.block([], height=HEIGHT + 3)
    for tx in txs:
        oracle.release(rid_of(tx))
    oracle.check(ch)
    assert result.governance_changes["released_retractables"] == sorted(
        rid_of(t) for t in txs
    )
    assert ch.book.escrow_total() == 0


def test_release_does_not_depend_on_the_senders_later_state():
    ch = Chain({ALICE: 1_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    oracle = Oracle({ALICE: 1_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    _, rid = _parked(ch, oracle, amount=400, at_height=HEIGHT + 5)

    drain = spend_tx(ALICE, CAROL, 600, seq=1)
    ch.block([drain], height=HEIGHT + 1)
    oracle.spend(ALICE, CAROL, 600, ts=TS)
    oracle.check(ch)
    assert ch.bal[ALICE] == 0

    ch.block_o5 = True   # the sender's policy now blocks everything
    ch.block([], height=HEIGHT + 5)
    oracle.release(rid)
    oracle.check(ch)
    assert ch.bal[BOB] == 400


# --- ordering inside a block --------------------------------------------------

def test_park_and_retract_in_the_same_block():
    ch = Chain(_balances(), fee=2)
    oracle = Oracle(_balances())
    park = park_tx(amount=700, seq=0)
    rid = rid_of(park)
    ch.block([park, retract_tx(rid, seq=1)])
    oracle.park(park, fee=2, ts=TS)
    oracle.retract(rid, ALICE)
    oracle.check(ch)
    assert ch.bal[ALICE] == 10_000 - 2


def _low_alice():
    return {ALICE: 1_000, BOB: 5_000, CAROL: 0, PROPOSER: 0}


def test_retract_then_spend_matches_an_ordinary_incoming_transfer_then_spend():
    ch = Chain(_low_alice())
    oracle = Oracle(_low_alice())
    park = park_tx(amount=900, seq=0, at_height=HEIGHT + 5)
    ch.block([park], height=HEIGHT)
    oracle.park(park, fee=0, ts=TS)
    rid = rid_of(park)
    spend = spend_tx(ALICE, CAROL, 800, seq=2)

    # Without the refund the spend cannot be covered.
    alone = Chain(_low_alice())
    alone.block([park], height=HEIGHT)
    rejected = alone.block([spend_tx(ALICE, CAROL, 800, seq=1)], height=HEIGHT + 1)
    assert rejected.accepted_tx_ids == []

    result = ch.block([retract_tx(rid, seq=1), spend], height=HEIGHT + 1)
    oracle.retract(rid, ALICE)
    oracle.spend(ALICE, CAROL, 800, ts=TS)
    oracle.check(ch)
    assert spend["tx_id"] in result.accepted_tx_ids

    baseline = Chain({**_low_alice(), ALICE: 100})
    incoming = spend_tx(BOB, ALICE, 900, seq=0)
    base_spend = spend_tx(ALICE, CAROL, 800, seq=0)
    baseline.block([incoming, base_spend], height=HEIGHT + 1)
    assert baseline.bal[ALICE] == ch.bal[ALICE]
    assert baseline.bal[CAROL] == ch.bal[CAROL]


def test_released_funds_cannot_be_spent_earlier_in_the_release_block():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _, rid = _parked(ch, oracle, amount=400, at_height=HEIGHT + 5)
    early = spend_tx(BOB, CAROL, 100, seq=0)
    result = ch.block([early], height=HEIGHT + 5)
    assert result.invalid_tx_ids == [early["tx_id"]]
    oracle.release(rid)
    oracle.check(ch)
    assert ch.bal[BOB] == 400
    assert ch.bal[CAROL] == 0


# --- conservation -------------------------------------------------------------

def test_a_release_that_skips_its_credit_breaks_conservation():
    ch = Chain(_balances())
    oracle = Oracle(_balances())
    _parked(ch, oracle, at_height=HEIGHT + 2)

    def lossy(lm, balances, height, timestamp):
        lm.retractable_transfers.release_due(int(height), int(timestamp))
        return []

    with patch("consensus.engine._release_due_retractables", lossy):
        with pytest.raises(BlockchainBug):
            ch.block([], height=HEIGHT + 2)


# --- degenerate parties -------------------------------------------------------

def test_sender_equal_to_recipient():
    ch = Chain(_balances(), fee=3)
    oracle = Oracle(_balances())
    tx = park_tx(recipient=ALICE, amount=250, at_height=HEIGHT + 2)
    ch.block([tx])
    oracle.park(tx, fee=3, ts=TS)
    oracle.check(ch)
    ch.block([], height=HEIGHT + 2)
    oracle.release(rid_of(tx))
    oracle.check(ch)
    assert ch.bal[ALICE] == 10_000 - 3


def test_fee_beneficiary_equal_to_sender():
    ch = Chain(_balances(), fee=9)
    oracle = Oracle(_balances())
    tx = park_tx(amount=100)
    ch.block([tx], proposer=ALICE)
    oracle.park(tx, fee=9, ts=TS, proposer=ALICE)
    oracle.check(ch)
    assert ch.bal[ALICE] == 10_000 - 100


# --- replay -------------------------------------------------------------------

def _replayed(ch: Chain, balances) -> Chain:
    twin = Chain(balances, fee=ch.fee)
    for txs, height, ts, proposer, fee, block_o5, state_hash in ch.history:
        twin.fee, twin.block_o5 = fee, block_o5
        twin.block(txs, height, ts, replay=True, proposer=proposer)
        assert twin.history[-1][-1] == state_hash
    return twin


def test_replay_reproduces_success_and_failure_exactly():
    ch = Chain(_balances(), fee=6)
    good = park_tx(amount=300, seq=0, at_height=HEIGHT + 4)
    second = park_tx(amount=50, seq=1, at_height=HEIGHT + 20, recipient=CAROL)
    ch.block([good, second])
    rid = rid_of(good)

    forged = park_tx(seq=2, signer_sk=SK_MALLORY)
    shape = park_tx(seq=2, mutate=lambda t: t.update(release_at_time=TS + 9))
    wrong_seq = park_tx(seq=9)
    not_future = park_tx(seq=2, at_height=HEIGHT)
    stranger = retract_tx(rid, sk=SK_CAROL, sender=CAROL, seq=0)
    ch.block([forged, shape, wrong_seq, not_future, stranger,
              retract_tx(rid_of(second), seq=2)], height=HEIGHT + 1)
    ch.block([], height=HEIGHT + 4)

    twin = _replayed(ch, _balances())
    assert twin.snapshot() == ch.snapshot()
    assert twin.book.resolved_state() == ch.book.resolved_state()


@pytest.mark.parametrize("scenario", ["unfunded", "o5_block"])
def test_replay_of_an_unfundable_park_books_nothing(scenario):
    kwargs = dict(block_o5=True) if scenario == "o5_block" else {}
    amount = 10_001 if scenario == "unfunded" else 100

    ch = Chain(_balances(), **kwargs)
    park = park_tx(amount=amount)
    before = ch.snapshot()
    ch.block([park], replay=True)

    nonzero, _, lts, root, escrow, open_ids = ch.snapshot()
    assert (nonzero, root, escrow, open_ids) == (before[0], before[3], before[4], before[5])
    assert lts == {}

    # An ordinary transfer in the same replay situation, as the reference.
    ref = Chain(_balances(), **kwargs)
    ref.block([spend_tx(ALICE, BOB, amount, seq=0)], replay=True)
    if scenario == "unfunded":
        assert {k: v for k, v in ref.bal.items() if v} == nonzero
