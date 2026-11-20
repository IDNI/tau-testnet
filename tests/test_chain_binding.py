"""Cross-network binding for standing payments (Bounty 01, issue #34).

A standing transaction signed for another network must be refused on
this one, at mempool admission and at block apply. Its signature is
valid over there, but the preimage it was made over names that
network's identity: consensus.tx_signing binds network_binding() into
the preimage of the standing types, and admission and apply share the
one verifier. Sequence numbers alone cannot give this -- two networks
that share genesis-era account state would otherwise accept each
other's transactions as replays with valid signatures.

The foreign network here is a pinned binding, standing in for a chain
whose genesis differs from ours.
"""

import json

import pytest

from commands.sendtx import _check_tx_envelope
from consensus.standing import parse_standing_create
from consensus.tx_signing import (
    network_binding,
    set_network_binding,
    signing_message_bytes,
    verify_tx_signature,
)
from test_standing_apply import (
    ALICE,
    BEFORE,
    BOB,
    DUE_JAN,
    Chain,
    _balances,
    create_tx,
    execute_tx,
)

LOCAL = "local-genesis-hash-for-this-chain"
FOREIGN = "foreign-genesis-hash-that-is-not-ours"


@pytest.fixture(autouse=True)
def _local_network():
    set_network_binding(LOCAL)
    yield
    set_network_binding(None)


def _signed_on_foreign(builder):
    """Build and sign a transaction as the foreign network would."""
    set_network_binding(FOREIGN)
    try:
        return builder()
    finally:
        set_network_binding(LOCAL)


def test_preimage_names_the_network_it_was_signed_for():
    tx = create_tx()
    tx.pop("signature")
    local_bytes = signing_message_bytes(tx)
    assert json.loads(local_bytes)["network_id"] == LOCAL
    set_network_binding(FOREIGN)
    try:
        foreign_bytes = signing_message_bytes(tx)
    finally:
        set_network_binding(LOCAL)
    assert json.loads(foreign_bytes)["network_id"] == FOREIGN
    assert local_bytes != foreign_bytes


def test_preexisting_types_keep_their_unbound_preimage():
    # user_tx predates network binding; its frozen preimage must not
    # gain a network_id, or every existing signature breaks.
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "expiration_time": 9_999_999_999,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, 1]]},
    }
    decoded = json.loads(signing_message_bytes(tx))
    assert "network_id" not in decoded


def test_foreign_signed_create_fails_verification_here():
    foreign = _signed_on_foreign(create_tx)
    ok, _reason = verify_tx_signature(foreign)
    assert not ok
    local = create_tx()
    ok, _reason = verify_tx_signature(local)
    assert ok


def test_cross_network_create_is_refused_at_admission():
    foreign = _signed_on_foreign(create_tx)
    err = _check_tx_envelope(foreign)
    assert err is not None
    assert "INVALID_SIGNATURE" in json.dumps(err)
    local = create_tx()
    assert _check_tx_envelope(local) is None


def test_cross_network_create_is_refused_at_apply():
    ch = Chain(_balances())
    foreign = _signed_on_foreign(create_tx)
    ch.block([foreign], height=20, ts=BEFORE)
    assert not ch.accepted(foreign)
    assert ch.book.is_empty()
    local = create_tx()
    ch.block([local], height=21, ts=BEFORE)
    assert ch.accepted(local)
    assert ch.book.get(parse_standing_create(local).standing_id) is not None


def test_cross_network_execute_is_refused_at_apply():
    ch = Chain(_balances())
    create = create_tx()
    ch.block([create], height=20, ts=BEFORE)
    assert ch.accepted(create)
    sid = parse_standing_create(create).standing_id
    foreign_exec = _signed_on_foreign(lambda: execute_tx(sid.hex()))
    ch.block([foreign_exec], height=21, ts=DUE_JAN)
    assert not ch.accepted(foreign_exec)
    assert not ch.book.paid_for_period(sid, 0)
    assert ch.bal[BOB] == 0
    local_exec = execute_tx(sid.hex())
    ch.block([local_exec], height=22, ts=DUE_JAN)
    assert ch.accepted(local_exec)
    assert ch.book.paid_for_period(sid, 0)


def test_the_binding_resolves_to_one_stable_local_value():
    # With no pin, the binding resolves to this chain's identity: the
    # genesis hash when a chain is loaded, else the configured network
    # id. Either way it is one stable value for the process, and it is
    # never the foreign network's.
    set_network_binding(None)
    try:
        assert network_binding() == network_binding()
        assert network_binding() != FOREIGN
    finally:
        set_network_binding(LOCAL)
