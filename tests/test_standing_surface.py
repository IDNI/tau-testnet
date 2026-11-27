"""Standing payments outside block apply: persistence, admission, RPC, signing, CLI."""
import json
import time
import types

import pytest

from chain_ids import TEST_CHAIN_ID

import chain_state
import db
from commands import getstandingpayments
from consensus import periods
from consensus.admission import validate_standing_payload
from consensus.facade import TipAdmissionView
from consensus.standing import (
    StandingBook, StandingExecute, load_standing_book, parse_standing_create,
)
from consensus.tx_signing import signing_message_bytes
from tau_testnet_cli import cli, tx as tx_mod
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
OTHER = "c0" * 48


def _daily(now, **over):
    tx = {"sender_pubkey": ALICE, "recipient_pubkey": BOB, "amount": 50,
          "sequence_number": 0, "period_kind": periods.PERIOD_DAY,
          "start_at": now - (now % 86_400), "window_seconds": 86_400,
          "max_occurrences": 5}
    tx.update(over)
    return parse_standing_create(tx)


def _commit(book):
    lm = types.SimpleNamespace(standing_payments=book)
    db.set_chain_state_value("standing_v1", json.dumps(chain_state._standing_state(lm)))


def test_db_roundtrip_and_tamper(temp_database):
    now = int(time.time())
    book = StandingBook()
    t = _daily(now)
    sid = book.submit(t)
    book.record_execution(StandingExecute(OTHER, sid, t.period_of(now)), now)
    _commit(book)
    assert load_standing_book(db.load_standing_state()).root() == book.root()
    state = db.load_standing_state()
    state["rows"][0]["recipient_pubkey"] = OTHER
    db.set_chain_state_value("standing_v1", json.dumps(state))
    with pytest.raises(chain_state.DatabaseError):
        chain_state._restore_standing(types.SimpleNamespace())


def test_canonical_save_writes_standing(temp_database):
    now = int(time.time())
    book = StandingBook()
    book.submit(_daily(now))
    db.save_canonical_state_atomically(
        "00" * 32, 1, {}, {}, "", "", "", [], [], [], [],
        standing=chain_state._standing_state(types.SimpleNamespace(standing_payments=book)),
    )
    assert load_standing_book(db.load_standing_state()).root() == book.root()


def test_admission_execute_due_and_not_due(temp_database):
    now = int(time.time())
    book = StandingBook()
    t = _daily(now)
    sid = book.submit(t)
    _commit(book)
    view = TipAdmissionView()
    period = t.period_of(view.next_block_timestamp)
    ok = validate_standing_payload({"chain_id": TEST_CHAIN_ID, "tx_type": "standing_payment_execute",
                                    "sender_pubkey": OTHER, "standing_id": sid.hex(),
                                    "period": period}, view)
    assert ok.is_valid, ok.error
    bad = validate_standing_payload({"chain_id": TEST_CHAIN_ID, "tx_type": "standing_payment_execute",
                                     "sender_pubkey": OTHER, "standing_id": sid.hex(),
                                     "period": period + 1}, view)
    assert not bad.is_valid and bad.code == "STANDING_NOT_DUE"


def test_admission_requires_an_end(temp_database):
    res = validate_standing_payload({"chain_id": TEST_CHAIN_ID, 
        "tx_type": "standing_payment_create", "sender_pubkey": ALICE,
        "recipient_pubkey": BOB, "amount": 5, "sequence_number": 0,
        "period_kind": periods.PERIOD_DAY, "start_at": int(time.time()),
        "window_seconds": 3600}, TipAdmissionView())
    assert not res.is_valid and "end is required" in res.error


def test_rpc_reports_due_and_paid(temp_database):
    now = int(time.time())
    book = StandingBook()
    t = _daily(now)
    sid = book.submit(t)
    _commit(book)
    out = json.loads(getstandingpayments.execute(f"getstandingpayments {BOB} in", None))
    (row,) = out["data"]["standing_payments"]
    assert row["standing_id"] == sid.hex()
    assert row["due_period"] is not None and row["paid_this_period"] is False
    out = json.loads(getstandingpayments.execute(f"getstandingpayments {OTHER}", None))
    assert out["data"]["standing_payments"] == []
    book.record_execution(StandingExecute(OTHER, sid, row["due_period"]), out["data"]["as_of"])
    _commit(book)
    out = json.loads(getstandingpayments.execute(f"getstandingpayments {ALICE} out", None))
    (row,) = out["data"]["standing_payments"]
    assert row["paid_this_period"] is True and row["due_period"] is None
    # #34: the capability endpoint states the canonical schedule semantics.
    sem = out["data"]["semantics"]
    assert sem["month_missing_due_day"] == "last calendar day of the month"
    assert sem["missed_period"] == "skipped; no catch-up"
    assert sem["executions_per_period"] == 1 and sem["end_condition_required"] is True
    assert sem["executor"] == "anyone" and sem["chain_bound"] is True


def test_every_schedule_term_is_signed():
    base = tx_mod.build_standing_create_tx(chain_id=TEST_CHAIN_ID, 
        sender_pubkey=ALICE, sequence_number=0, expiration_time=10, expire_at_height=5,
        recipient_pubkey=BOB, amount=10, period_kind=3, start_at=1, window_seconds=3600,
        due_day=31, max_occurrences=3)
    ref = signing_message_bytes(base)
    for k, v in [("recipient_pubkey", OTHER), ("amount", 11), ("period_kind", 2),
                 ("period_seconds", 7200), ("start_at", 2), ("due_day", 30),
                 ("due_offset_seconds", 60), ("window_seconds", 7200), ("end_at", 99),
                 ("max_occurrences", 4)]:
        assert signing_message_bytes(dict(base, **{k: v})) != ref, k
    ex = tx_mod.build_standing_execute_tx(chain_id=TEST_CHAIN_ID, sender_pubkey=OTHER, sequence_number=0,
                                          expiration_time=1, expire_at_height=1,
                                          standing_id="ab" * 32, period=7)
    assert signing_message_bytes(dict(ex, period=8)) != signing_message_bytes(ex)


def test_cli_parses_monthly_rent():
    args = cli.build_parser().parse_args([
        "standing", "create", "--key", "alice", "--to", BOB, "--amount", "1000",
        "--every", "month", "--day", "31", "--window", "432000",
        "--start", "2026-12-01", "--times", "12",
    ])
    assert args.func is cli.cmd_standing_create and args.day == 31 and args.times == 12
    args = cli.build_parser().parse_args(["standing", "execute", "--key", "bob", "ab" * 32])
    assert args.func is cli.cmd_standing_execute and args.period is None
