"""Book-level tests for consensus/routes.py (Bounty 01, issue #35).

Engine-level tests (the seam split, fees, receipts) live with the
engine wiring; here a RouteBook stands on its own: terms validation,
the split arithmetic, the lock rules and the root/restore discipline.
"""

import pytest

from consensus import routes as routes_mod
from consensus.routes import (
    MAX_BPS,
    RouteBook,
    RouteShapeError,
    RouteTerms,
    parse_route_install,
    parse_route_remove,
    validate_route_shape,
    verify_route_unlock,
)

OWNER = "aa" * 48
DEST = "bb" * 48
OTHER = "cc" * 48
NOW = 1_700_000_000


def terms(**over):
    base = dict(owner=OWNER, destination=DEST, bps=2000)
    base.update(over)
    return RouteTerms(**base)


# -- split arithmetic -----------------------------------------------------

def test_route_101_at_20pct_gives_20_and_81_one_fee_split_math():
    # Book half of gmikeyg's named case: the share of the gross is 20,
    # so the recipient keeps 81. (The one-fee half is an engine test.)
    route = terms(bps=2000)
    assert route.split(101) == 20
    assert 101 - route.split(101) == 81


def test_split_rounds_down_and_never_up():
    route = terms(bps=5000)
    assert route.split(3) == 1  # 1.5 floors to 1
    assert route.split(1) == 0  # 0.5 floors to 0: no diversion


def test_split_respects_minimum_incoming():
    route = terms(bps=2000, min_incoming=100)
    assert route.split(99) == 0
    assert route.split(100) == 20


# -- shape validation -----------------------------------------------------

def test_self_route_rejected():
    assert validate_route_shape(terms(destination=OWNER), NOW) is not None


def test_bps_bounds_reject_zero_and_full_or_more():
    assert validate_route_shape(terms(bps=0), NOW) is not None
    assert validate_route_shape(terms(bps=10_000), NOW) is not None
    assert validate_route_shape(terms(bps=MAX_BPS), NOW) is None
    assert validate_route_shape(terms(bps=1), NOW) is None


def test_locked_route_requires_expiry():
    assert validate_route_shape(terms(locked=True), NOW) is not None
    assert validate_route_shape(
        terms(locked=True, expiry_ts=NOW + 1000), NOW
    ) is None


def test_expiry_must_be_future_and_after_activation():
    assert validate_route_shape(terms(expiry_ts=NOW - 1), NOW) is not None
    assert validate_route_shape(
        terms(activation_ts=NOW + 100, expiry_ts=NOW + 100), NOW
    ) is not None
    assert validate_route_shape(
        terms(activation_ts=NOW + 100, expiry_ts=NOW + 200), NOW
    ) is None


# -- activity + lock windows ------------------------------------------------

def test_route_activity_window():
    route = terms(activation_ts=NOW + 10, expiry_ts=NOW + 20)
    assert not route.is_active(NOW + 9)
    assert route.is_active(NOW + 10)
    assert route.is_active(NOW + 19)
    assert not route.is_active(NOW + 20)


def test_removal_locked_only_while_lock_runs():
    route = terms(locked=True, expiry_ts=NOW + 100)
    assert route.removal_locked(NOW) is True
    assert route.removal_locked(NOW + 99) is True
    assert route.removal_locked(NOW + 100) is False
    assert terms().removal_locked(NOW) is False


def test_verify_route_unlock_uses_destination_key(monkeypatch):
    route = terms(locked=True, expiry_ts=NOW + 100)
    seen = {}

    def fake_verify(pk, msg, sig):
        seen["pk"] = pk
        return sig == b"\x01" * 96

    monkeypatch.setattr(routes_mod.bls, "verify", fake_verify)
    assert verify_route_unlock(route, (b"\x01" * 96).hex()) is True
    assert seen["pk"] == bytes.fromhex(DEST)
    assert verify_route_unlock(route, (b"\x02" * 96).hex()) is False
    assert verify_route_unlock(route, "not-hex") is False
    assert verify_route_unlock(route, None) is False


# -- the book ---------------------------------------------------------------

def test_book_install_replace_remove_and_root():
    book = RouteBook()
    assert book.is_empty()
    empty_root = book.root()
    book.install(terms())
    assert book.get(OWNER).bps == 2000
    assert book.root() != empty_root
    first_root = book.root()
    book.install(terms(bps=3000, sequence_number=1))  # replacement
    assert book.get(OWNER).bps == 3000
    assert book.count() == 1
    assert book.remove(OWNER).bps == 3000
    assert book.is_empty()
    assert book.root() == empty_root  # configuration root: removal restores it
    assert first_root != empty_root


def test_book_active_route_respects_window():
    book = RouteBook()
    book.install(terms(activation_ts=NOW + 50))
    assert book.active_route(OWNER, NOW) is None
    assert book.active_route(OWNER, NOW + 50) is not None
    assert book.active_route(OTHER, NOW + 50) is None


def test_snapshot_restore_round_trip():
    book = RouteBook()
    book.install(terms())
    book.install(terms(owner=OTHER, destination=DEST, bps=500, locked=True,
                       expiry_ts=NOW + 5000, sequence_number=3))
    rows = book.snapshot_rows()
    restored = RouteBook.restore(rows)
    assert restored.root() == book.root()
    assert restored.get(OTHER).locked is True


def test_restore_refuses_id_mismatch():
    book = RouteBook()
    book.install(terms())
    rows = book.snapshot_rows()
    rows[0]["bps"] = 3000  # terms no longer recompute to the stored id
    with pytest.raises(ValueError):
        RouteBook.restore(rows)


# -- parsing ------------------------------------------------------------------

def test_parse_install_defaults_and_locked_flag():
    tx = {
        "sender_pubkey": OWNER,
        "destination_pubkey": DEST,
        "bps": 2000,
        "sequence_number": 7,
    }
    parsed = parse_route_install(tx)
    assert parsed.min_incoming == 0 and parsed.locked is False
    assert parsed.sequence_number == 7
    with pytest.raises(RouteShapeError):
        parse_route_install(dict(tx, locked="yes"))
    with pytest.raises(RouteShapeError):
        parse_route_install(dict(tx, bps=-1))
    with pytest.raises(RouteShapeError):
        parse_route_install(dict(tx, destination_pubkey="zz"))


def test_parse_remove_requires_route_id():
    tx = {"sender_pubkey": OWNER, "route_id": "ab" * 32}
    removal = parse_route_remove(tx)
    assert removal.route_id == bytes.fromhex("ab" * 32)
    assert removal.destination_signature is None
    with pytest.raises(RouteShapeError):
        parse_route_remove({"sender_pubkey": OWNER})
