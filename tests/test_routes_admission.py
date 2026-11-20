"""Admission screens for receive routes (Bounty 01, issue #35).

The validators run against a stub tip view: the book states that
matter (no route / unlocked route / locked route) are rows in the
facade's shape, exactly what TipAdmissionView.get_route returns.
"""

import hashlib

from py_ecc.bls import G2Basic

from consensus.admission import (
    validate_route_install_payload,
    validate_route_remove_payload,
)
from consensus.routes import RouteTerms, unlock_message_bytes

SK_OWNER = 11111
SK_DEST = 55555
OWNER = G2Basic.SkToPk(SK_OWNER).hex()
DEST = G2Basic.SkToPk(44444).hex()
DEST_PK = G2Basic.SkToPk(SK_DEST).hex()
NOW = 1_700_000_000


class View:
    def __init__(self, row=None, count=0):
        self._row = row
        self._count = count
        self.next_block_timestamp = NOW
        self.next_block_height = 100

    def get_route(self, owner):
        return self._row if self._row and self._row["owner_pubkey"] == owner else None

    def route_count(self):
        return self._count


def install_tx(**over):
    tx = {
        "tx_type": "receive_route_install",
        "sender_pubkey": OWNER,
        "destination_pubkey": DEST,
        "bps": 2000,
        "min_incoming": 0,
        "activation_timestamp": 0,
        "expiry_timestamp": 0,
        "locked": False,
        "sequence_number": 0,
    }
    tx.update(over)
    return tx


def row_for(terms, **over):
    row = {
        "route_id": terms.route_id.hex(),
        "owner_pubkey": terms.owner,
        "destination_pubkey": terms.destination,
        "bps": terms.bps,
        "min_incoming": terms.min_incoming,
        "activation_timestamp": terms.activation_ts,
        "expiry_timestamp": terms.expiry_ts,
        "locked": terms.locked,
        "sequence_number": terms.sequence_number,
    }
    row.update(over)
    return row


def test_install_admitted_on_empty_book():
    result = validate_route_install_payload(install_tx(), View())
    assert result.is_valid, result


def test_install_rejects_self_route_and_full_share():
    assert not validate_route_install_payload(
        install_tx(destination_pubkey=OWNER), View()).is_valid
    assert not validate_route_install_payload(install_tx(bps=10_000), View()).is_valid


def test_install_rejects_locked_without_expiry():
    assert not validate_route_install_payload(install_tx(locked=True), View()).is_valid


def _locked_terms():
    return RouteTerms(owner=OWNER, destination=DEST_PK, bps=2000,
                      locked=True, expiry_ts=NOW + 1000)


def _unlock(terms, sk=SK_DEST):
    digest = hashlib.sha256(unlock_message_bytes(terms)).digest()
    return G2Basic.Sign(sk, digest).hex()


def test_replace_locked_route_needs_destination_signature():
    terms = _locked_terms()
    view = View(row=row_for(terms))
    assert not validate_route_install_payload(install_tx(), view).is_valid
    signed = install_tx(destination_signature=_unlock(terms))
    assert validate_route_install_payload(signed, view).is_valid


def test_remove_locked_route_needs_destination_signature():
    terms = _locked_terms()
    view = View(row=row_for(terms))
    tx = {"tx_type": "receive_route_remove", "sender_pubkey": OWNER,
          "route_id": terms.route_id.hex()}
    assert not validate_route_remove_payload(tx, view).is_valid
    tx["destination_signature"] = _unlock(terms)
    assert validate_route_remove_payload(tx, view).is_valid


def test_remove_unknown_route_rejected():
    tx = {"tx_type": "receive_route_remove", "sender_pubkey": OWNER,
          "route_id": "ab" * 32}
    assert not validate_route_remove_payload(tx, View()).is_valid


def test_remove_after_expiry_needs_no_signature():
    terms = RouteTerms(owner=OWNER, destination=DEST, bps=2000,
                       locked=True, expiry_ts=NOW - 5)
    view = View(row=row_for(terms))
    tx = {"tx_type": "receive_route_remove", "sender_pubkey": OWNER,
          "route_id": terms.route_id.hex()}
    assert validate_route_remove_payload(tx, view).is_valid
