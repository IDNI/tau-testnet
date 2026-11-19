"""Grants outside block apply: persistence, admission, RPC, CLI and signing."""
import json
import time
import types

import pytest

from chain_ids import TEST_CHAIN_ID

import chain_state
import db
from commands import getgrants
from consensus import periods
from consensus.admission import validate_grant_payload
from consensus.facade import TipAdmissionView
from consensus.grants import GrantBook, GrantDraw, load_grant_book, parse_grant_create
from consensus.tx_signing import signing_message_bytes
from tau_testnet_cli import cli, tx as tx_mod
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
SHOP = "c0" * 48


def _terms(now, **over):
    tx = {"sender_pubkey": ALICE, "grantee_pubkey": BOB, "amount": 1000,
          "sequence_number": 0, "expires_at": now + 86_400, "spend_cap": 100,
          "cap_period_kind": periods.PERIOD_DAY}
    tx.update(over)
    return parse_grant_create(tx)


def _commit(book):
    lm = types.SimpleNamespace(grants=book)
    db.set_chain_state_value("grants_v1", json.dumps(chain_state._grants_state(lm)))


# --- persistence ----------------------------------------------------------------


def test_db_roundtrip_preserves_root(temp_database):
    now = int(time.time())
    book = GrantBook()
    gid = book.submit(_terms(now), now)
    book.draw(GrantDraw(BOB, gid, SHOP, 40), now)
    book.submit(_terms(now, sequence_number=1, revocable=True), now)
    _commit(book)
    loaded = load_grant_book(db.load_grants_state())
    assert loaded.root() == book.root()
    assert loaded.get(gid).spent_in_period == 40


def test_empty_db_reads_as_empty_book(temp_database):
    assert load_grant_book(db.load_grants_state()).root() == GrantBook().root()


def test_tampered_row_refuses_to_load(temp_database):
    now = int(time.time())
    book = GrantBook()
    book.submit(_terms(now), now)
    _commit(book)
    state = db.load_grants_state()
    state["rows"][0]["spend_cap"] = 1000  # loosen a signed limit
    db.set_chain_state_value("grants_v1", json.dumps(state))
    lm = types.SimpleNamespace()
    with pytest.raises(chain_state.DatabaseError):
        chain_state._restore_grants(lm)


def test_canonical_state_save_writes_the_grant_book(temp_database):
    now = int(time.time())
    book = GrantBook()
    book.submit(_terms(now), now)
    lm = types.SimpleNamespace(grants=book)
    db.save_canonical_state_atomically(
        "00" * 32, 1, {}, {}, "", "", "", [], [], [], [],
        grants=chain_state._grants_state(lm),
    )
    assert load_grant_book(db.load_grants_state()).root() == book.root()
    assert db.has_due_grants(now + 86_400) and not db.has_due_grants(now)


# --- admission and RPC ------------------------------------------------------------


def test_admission_uses_the_committed_book(temp_database):
    now = int(time.time())
    book = GrantBook()
    gid = book.submit(_terms(now, start_at=0), now)
    _commit(book)
    view = TipAdmissionView()
    ok = validate_grant_payload({"chain_id": TEST_CHAIN_ID, "tx_type": "grant_draw", "sender_pubkey": BOB,
                                 "grant_id": gid.hex(), "recipient_pubkey": ALICE,
                                 "amount": 100}, view)
    assert ok.is_valid, ok.error
    over_cap = validate_grant_payload({"chain_id": TEST_CHAIN_ID, "tx_type": "grant_draw", "sender_pubkey": BOB,
                                       "grant_id": gid.hex(), "recipient_pubkey": ALICE,
                                       "amount": 101}, view)
    assert not over_cap.is_valid and "spending cap" in over_cap.error
    wrong_signer = validate_grant_payload({"chain_id": TEST_CHAIN_ID, "tx_type": "grant_draw", "sender_pubkey": ALICE,
                                           "grant_id": gid.hex(), "recipient_pubkey": ALICE,
                                           "amount": 1}, view)
    assert not wrong_signer.is_valid


def test_admission_rejects_bad_create(temp_database):
    view = TipAdmissionView()
    res = validate_grant_payload({"chain_id": TEST_CHAIN_ID, "tx_type": "grant_create", "sender_pubkey": ALICE,
                                  "grantee_pubkey": BOB, "amount": 10,
                                  "sequence_number": 0, "expires_at": 1}, view)
    assert not res.is_valid and "future" in res.error


def test_getgrants_reports_drawable_now(temp_database):
    now = int(time.time())
    book = GrantBook()
    gid = book.submit(_terms(now), now)
    book.draw(GrantDraw(BOB, gid, SHOP, 30), now)
    _commit(book)
    out = json.loads(getgrants.execute(f"getgrants {BOB} in", None))
    assert out["status"] == "ok"
    (g,) = out["data"]["grants"]
    assert g["grant_id"] == gid.hex() and g["remaining"] == 970
    assert g["drawable_now"] in (70, 100)  # 100 if the UTC day rolled over
    assert json.loads(getgrants.execute(f"getgrants {SHOP}", None))["data"]["grants"] == []
    assert json.loads(getgrants.execute("getgrants nope", None))["status"] == "error"


# --- signing --------------------------------------------------------------------


def test_every_grant_term_is_signed():
    base = tx_mod.build_grant_create_tx(chain_id=TEST_CHAIN_ID, 
        sender_pubkey=ALICE, sequence_number=0, expiration_time=10,
        expire_at_height=5, grantee_pubkey=BOB, amount=10, expires_at=100,
    )
    ref = signing_message_bytes(base)
    for field, value in [("grantee_pubkey", SHOP), ("refund_to_pubkey", SHOP),
                         ("amount", 11), ("start_at", 1), ("expires_at", 101),
                         ("spend_cap", 1), ("cap_period_kind", 1),
                         ("cap_period_seconds", 3600), ("per_payment_cap", 1),
                         ("weekday_mask", 1), ("hour_mask", 1), ("revocable", True)]:
        changed = dict(base, **{field: value})
        assert signing_message_bytes(changed) != ref, field

    draw = tx_mod.build_grant_draw_tx(chain_id=TEST_CHAIN_ID, sender_pubkey=BOB, sequence_number=0,
                                      expiration_time=10, expire_at_height=5,
                                      grant_id="ab" * 32, recipient_pubkey=SHOP, amount=5)
    ref = signing_message_bytes(draw)
    for field, value in [("grant_id", "cd" * 32), ("recipient_pubkey", ALICE), ("amount", 6)]:
        assert signing_message_bytes(dict(draw, **{field: value})) != ref, field


# --- CLI ------------------------------------------------------------------------


def test_cli_parsers():
    assert cli._parse_days("mon-fri") == 0b0011111
    assert cli._parse_days("sat,sun") == 0b1100000
    assert cli._parse_hours("9-17") == sum(1 << h for h in range(9, 18))
    assert cli._parse_hours("8,20") == (1 << 8) | (1 << 20)
    assert cli._parse_when("2026-12-01") == 1_796_083_200
    assert cli._parse_when("1796083200") == 1_796_083_200
    import argparse
    for bad in ("funday", "mon-xyz"):
        with pytest.raises(argparse.ArgumentTypeError):
            cli._parse_days(bad)
    with pytest.raises(argparse.ArgumentTypeError):
        cli._parse_hours("20-25")


def test_cli_grant_create_parses_the_demo():
    args = cli.build_parser().parse_args([
        "grant", "create", "--key", "alice", "--to", BOB, "--amount", "5000",
        "--start", "2026-12-01", "--cap", "500", "--cap-period", "week",
        "--expires", "2027-03-01", "--days", "mon-fri", "--hours", "9-17",
    ])
    assert args.func is cli.cmd_grant_create
    assert args.start == 1_796_083_200 and args.cap == 500
    assert args.days == 0b0011111


def test_builder_output_parses_to_the_same_terms():
    tx = tx_mod.build_grant_create_tx(chain_id=TEST_CHAIN_ID, 
        sender_pubkey=ALICE, sequence_number=3, expiration_time=10,
        expire_at_height=5, grantee_pubkey=BOB, amount=5000,
        start_at=1_796_083_200, expires_at=1_772_323_200, spend_cap=500,
    )
    t = parse_grant_create(tx)
    assert t.refund_to_pubkey == ALICE and t.cap_period_kind == periods.PERIOD_WEEK
    assert t.spend_cap == 500 and t.sequence_number == 3
