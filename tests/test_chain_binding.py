"""Cross-network binding for payout rules and grants (Bounty 01, #63).

A payout or grant transaction signed for another network must be
refused on this one, at mempool admission and at block apply. Its
signature is valid over there, but the preimage it was made over
names that network's identity: consensus.tx_signing binds
network_binding() into the preimage of the payout and grant types,
and admission and apply share the one verifier. Sequence numbers
alone cannot give this -- two networks that share genesis-era account
state would otherwise accept each other's transactions as replays
with valid signatures.

The foreign network here is a pinned binding, standing in for a chain
whose genesis differs from ours.
"""

import json

import pytest

from commands.sendtx import _check_tx_envelope
from consensus.grants import parse_grant_create
from consensus.tx_signing import (
    network_binding,
    set_network_binding,
    signing_message_bytes,
    verify_tx_signature,
)
from test_grants_apply import DEC1
from test_grants_apply import Chain as GrantChain
from test_grants_apply import create_tx as grant_create_tx
from test_grants_apply import draw_tx as grant_draw_tx
from test_payouts_apply import ALICE, BOB, CAROL, MALLORY, NOW, PROPOSER
from test_payouts_apply import Chain as PayoutChain
from test_payouts_apply import _installed_chain, execute_tx, install_tx

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
    for builder in (install_tx, grant_create_tx):
        tx = builder()
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


def test_foreign_signed_install_fails_verification_here():
    foreign = _signed_on_foreign(install_tx)
    ok, _reason = verify_tx_signature(foreign)
    assert not ok
    local = install_tx()
    ok, _reason = verify_tx_signature(local)
    assert ok


def test_cross_network_install_is_refused_at_admission():
    foreign = _signed_on_foreign(install_tx)
    err = _check_tx_envelope(foreign)
    assert err is not None
    assert "INVALID_SIGNATURE" in json.dumps(err)
    local = install_tx()
    assert _check_tx_envelope(local) is None


def test_cross_network_payout_install_is_refused_at_apply():
    ch, _terms = _installed_chain()
    assert ch.book.get(ALICE) is not None
    foreign_chain = PayoutChain(
        {ALICE: 10_000, BOB: 0, CAROL: 0, MALLORY: 0, PROPOSER: 0}
    )
    foreign = _signed_on_foreign(install_tx)
    foreign_chain.block([foreign], height=20, ts=NOW)
    assert not foreign_chain.accepted(foreign)
    assert foreign_chain.book.get(ALICE) is None


def test_cross_network_payout_execute_is_refused_at_apply():
    ch, _terms = _installed_chain()
    ch.legs = {20: "1", 21: "5", 22: "0"}
    foreign_exec = _signed_on_foreign(
        lambda: execute_tx(settlement_id="royalty-101", gross=101)
    )
    ch.block([foreign_exec], height=21, ts=NOW)
    assert not ch.accepted(foreign_exec)
    assert ch.bal[BOB] == 0
    local_exec = execute_tx(settlement_id="royalty-101", gross=101)
    ch.block([local_exec], height=22, ts=NOW)
    assert ch.accepted(local_exec)
    assert ch.bal[BOB] == 5


def test_cross_network_grant_create_is_refused_at_apply():
    ch = GrantChain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    foreign = _signed_on_foreign(grant_create_tx)
    ch.block([foreign], height=20, ts=DEC1 - 60)
    assert not ch.accepted(foreign)
    assert ch.bal[ALICE] == 10_000  # nothing escrowed
    local = grant_create_tx()
    ch.block([local], height=21, ts=DEC1 - 60)
    assert ch.accepted(local)
    assert ch.bal[ALICE] == 5_000  # the full 5,000 escrowed on creation


def test_cross_network_grant_draw_is_refused_at_apply():
    ch = GrantChain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    create = grant_create_tx()
    ch.block([create], height=20, ts=DEC1 - 60)
    assert ch.accepted(create)
    grant_id = parse_grant_create(create).grant_id
    foreign_draw = _signed_on_foreign(lambda: grant_draw_tx(grant_id, 500, seq=0))
    ch.block([foreign_draw], height=21, ts=DEC1 + 60)
    assert not ch.accepted(foreign_draw)
    assert ch.bal[BOB] == 0
    local_draw = grant_draw_tx(grant_id, 500, seq=0)
    ch.block([local_draw], height=22, ts=DEC1 + 60)
    assert ch.accepted(local_draw)
    assert ch.bal[BOB] == 500


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
