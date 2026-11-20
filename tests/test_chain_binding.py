"""Cross-network binding for receive routes (Bounty 01, issue #35).

A route transaction signed for another network must be refused on
this one, at mempool admission and at block apply. Its signature is
valid over there, but the preimage it was made over names that
network's identity: consensus.tx_signing binds network_binding() into
the preimage of the route types, and admission and apply share the
one verifier. Sequence numbers alone cannot give this -- two networks
that share genesis-era account state would otherwise accept each
other's transactions as replays with valid signatures.

The foreign network here is a pinned binding, standing in for a chain
whose genesis differs from ours.
"""

import json

import pytest

from commands.sendtx import _check_tx_envelope
from consensus.routes import parse_route_install
from consensus.tx_signing import (
    network_binding,
    set_network_binding,
    signing_message_bytes,
    verify_tx_signature,
)
from test_routes_apply import (
    ALICE,
    BOB,
    NOW,
    Chain,
    _balances,
    _routed_chain,
    install_tx,
    remove_tx,
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
    tx = install_tx()
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


def test_cross_network_install_is_refused_at_apply():
    ch = Chain(_balances())
    foreign = _signed_on_foreign(install_tx)
    ch.block([foreign], height=20, ts=NOW)
    assert not ch.accepted(foreign)
    assert ch.book.get(BOB) is None
    local = install_tx()
    ch.block([local], height=21, ts=NOW)
    assert ch.accepted(local)
    assert ch.book.get(BOB) is not None


def test_cross_network_remove_is_refused_at_apply():
    ch, terms = _routed_chain()
    rid = terms.route_id.hex()
    foreign_remove = _signed_on_foreign(lambda: remove_tx(rid, seq=1))
    ch.block([foreign_remove], height=21, ts=NOW)
    assert not ch.accepted(foreign_remove)
    assert ch.book.get(BOB) is not None
    local_remove = remove_tx(rid, seq=1)
    ch.block([local_remove], height=22, ts=NOW)
    assert ch.accepted(local_remove)
    assert ch.book.get(BOB) is None


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
