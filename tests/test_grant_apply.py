"""Block-apply semantics for conditional grants (programmable payments).

Runs through the real `apply_block` with the scripted evaluator from the
retractable apply tests, and checks full balance maps, escrow and the open set
after each block, including the Alice/Bob demo end to end.
"""
import itertools

from chain_ids import TEST_CHAIN_ID
from datetime import datetime, timezone

import pytest

from consensus import periods
from consensus.grants import parse_grant_create
from tests.test_retractable_apply import (
    ALICE, BOB, CAROL, FAR, MALLORY, PROPOSER, SK_ALICE, SK_BOB, SK_CAROL,
    SK_MALLORY, Chain, _sign,
)

_SEQ = itertools.count()
KEYS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, MALLORY: SK_MALLORY}


def at(*args):
    return int(datetime(*args, tzinfo=timezone.utc).timestamp())


T0 = at(2026, 11, 20)
DEC1 = at(2026, 12, 1)
DEADLINE = at(2027, 3, 1)


def _base(tx_type, sender, seq, fee_limit):
    return {
        "tx_id": f"{tx_type}-{next(_SEQ)}",
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 1000, "chain_id": TEST_CHAIN_ID,
        "fee_limit": str(fee_limit),
        "chain_id": TEST_CHAIN_ID,
    }


def create_tx(seq=0, sender=ALICE, fee_limit=100, signer=None, **terms):
    tx = _base("grant_create", sender, seq, fee_limit)
    tx.update({
        "grantee_pubkey": BOB, "amount": 5000, "start_at": DEC1,
        "expires_at": DEADLINE, "spend_cap": 500,
        "cap_period_kind": periods.PERIOD_WEEK,
    })
    tx.update(terms)
    return _sign(tx, KEYS[signer or sender])


def draw_tx(gid, amount, seq, sender=BOB, to=CAROL, fee_limit=100):
    tx = _base("grant_draw", sender, seq, fee_limit)
    tx.update({"grant_id": gid, "recipient_pubkey": to, "amount": amount})
    return _sign(tx, KEYS[sender])


def cancel_tx(gid, seq, sender=ALICE):
    tx = _base("grant_cancel", sender, seq, 0)
    tx["grant_id"] = gid
    return _sign(tx, KEYS[sender])


def gid_of(tx):
    return parse_grant_create(tx).grant_id.hex()


def receipts(ch):
    return [o.receipt_logs for o in ch.last.outcomes]


def total(ch):
    return sum(ch.bal.values()) + ch.lm.grants.escrow_total() + ch.lm.retractable_transfers.escrow_total()


def test_alice_bob_demo_end_to_end():
    ch = Chain({ALICE: 10_000, BOB: 50})
    supply = total(ch)
    c = create_tx()
    gid = gid_of(c)
    ch.block([c], ts=T0)
    assert ch.bal[ALICE] == 5_000 and ch.lm.grants.escrow_total() == 5_000
    assert ch.lm.grants.get(bytes.fromhex(gid)).remaining == 5_000

    # Before December 1: time-locked.
    ch.block([draw_tx(gid, 100, 0)], ts=at(2026, 11, 30, 12))
    assert ch.last.invalid_tx_ids and ch.bal.get(CAROL, 0) == 0

    # Week of Mon 2026-11-30: 300 + 200 fit, a further 1 does not.
    ch.block([draw_tx(gid, 300, 0), draw_tx(gid, 200, 1)], ts=at(2026, 12, 1, 10))
    assert ch.bal[CAROL] == 500
    ch.block([draw_tx(gid, 1, 2)], ts=at(2026, 12, 6, 22))
    assert ch.bal[CAROL] == 500 and ch.last.invalid_tx_ids

    # New week: the cap resets.
    ch.block([draw_tx(gid, 500, 2)], ts=at(2026, 12, 8, 9))
    assert ch.bal[CAROL] == 1_000
    assert ch.lm.grants.escrow_total() == 4_000

    # Deadline: the first block that reaches it refunds Alice with no tx.
    ch.block([], ts=DEADLINE)
    assert ch.lm.grants.open_count() == 0
    assert ch.bal[ALICE] == 9_000
    assert ch.last.next_snapshot.metadata["grant_events"] == [(gid, "expired")]
    assert total(ch) == supply


def test_only_grantee_can_draw_and_signature_binds_terms():
    ch = Chain({ALICE: 10_000, MALLORY: 50})
    c = create_tx()
    gid = gid_of(c)
    ch.block([c], ts=T0)
    ch.block([draw_tx(gid, 100, 0, sender=MALLORY, to=MALLORY)], ts=DEC1)
    assert ch.last.invalid_tx_ids and ch.bal.get(MALLORY) == 50

    tampered = create_tx(seq=1)
    tampered["spend_cap"] = 5000  # not what Alice signed
    ch.block([tampered], ts=T0 + 10)
    assert ch.last.invalid_tx_ids and ch.lm.grants.open_count() == 1


def test_insufficient_funds_creates_nothing():
    ch = Chain({ALICE: 100})
    ch.block([create_tx()], ts=T0)
    assert ch.last.invalid_tx_ids
    assert ch.bal[ALICE] == 100 and ch.lm.grants.open_count() == 0


def test_policy_block_stops_grant_creation():
    ch = Chain({ALICE: 10_000}, block_o5=True)
    ch.block([create_tx()], ts=T0)
    assert ch.last.invalid_tx_ids and ch.lm.grants.open_count() == 0
    assert ch.bal[ALICE] == 10_000


def test_fees_go_to_proposer_and_supply_is_conserved():
    ch = Chain({ALICE: 10_000, BOB: 50}, fee=3)
    supply = total(ch)
    c = create_tx()
    gid = gid_of(c)
    ch.block([c], ts=T0)
    assert ch.bal[ALICE] == 10_000 - 5_000 - 3
    ch.block([draw_tx(gid, 100, 0)], ts=DEC1)
    assert ch.bal[BOB] == 50 - 3 and ch.bal[CAROL] == 100
    assert ch.bal[PROPOSER] == 6
    assert total(ch) == supply


def test_revocable_grant_cancel_refunds_remaining():
    ch = Chain({ALICE: 10_000, BOB: 50})
    c = create_tx(revocable=True, refund_to_pubkey=CAROL)
    gid = gid_of(c)
    ch.block([c], ts=T0)
    ch.block([draw_tx(gid, 200, 0, to=BOB)], ts=DEC1)
    ch.block([cancel_tx(gid, 1)], ts=DEC1 + 60)
    assert ch.lm.grants.open_count() == 0
    assert ch.bal[CAROL] == 4_800 and ch.bal[BOB] == 250


def test_non_revocable_grant_cannot_be_cancelled():
    ch = Chain({ALICE: 10_000})
    c = create_tx()
    gid = gid_of(c)
    ch.block([c], ts=T0)
    ch.block([cancel_tx(gid, 1)], ts=T0 + 60)
    assert ch.last.invalid_tx_ids and ch.lm.grants.open_count() == 1


def test_draw_and_expiry_in_same_block_cannot_both_happen():
    ch = Chain({ALICE: 10_000, BOB: 50})
    c = create_tx()
    gid = gid_of(c)
    ch.block([c], ts=T0)
    ch.block([draw_tx(gid, 100, 0)], ts=DEADLINE)
    assert ch.last.invalid_tx_ids
    assert ch.bal[ALICE] == 10_000 and ch.bal.get(CAROL, 0) == 0


def test_state_hash_reflects_grant_state_and_is_deterministic():
    def run():
        ch = Chain({ALICE: 10_000, BOB: 50})
        c = create_tx()
        ch.block([c], ts=T0)
        ch.block([draw_tx(gid_of(c), 100, 0)], ts=DEC1)
        return [h[-1] for h in ch.history]

    a, b = run(), run()
    assert a == b and a[0] != a[1]


def test_chain_without_grants_keeps_meta_hash_unchanged():
    from consensus.governance import ConsensusLifecycleManager

    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    before = lm.consensus_meta_hash()
    lm.grants  # present but empty
    assert lm.consensus_meta_hash() == before
    lm.grants.submit(parse_grant_create(create_tx()), T0)
    assert lm.consensus_meta_hash() != before
