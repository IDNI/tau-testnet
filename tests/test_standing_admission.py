"""Mempool admission for standing payments (Bounty 01, issue #34).

Pure validators against a mocked tip view, mirroring
tests/test_retractable_admission.py. Admission and block apply share
the parsers and the shape check, so they cannot disagree on shape.
"""

from unittest.mock import MagicMock

import pytest

from bls_keys import pubkey_hex
from consensus.admission import (
    TipAdmissionView,
    validate_standing_cancel_payload,
    validate_standing_create_payload,
    validate_standing_execute_payload,
)
from consensus.periods import PERIOD_MONTH, SECONDS_PER_DAY
from consensus.standing import StandingBook, StandingTerms, END_MAX_OCCURRENCES

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
C = pubkey_hex(0x3C)
TIP_TS = 1767220800  # 2026-01-01T00:00:00Z
ANCHOR = 1769817600  # 2026-01-31T12:00:00Z


@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = 50
    view.next_block_timestamp = TIP_TS
    view.get_standing.return_value = None
    view.open_standing_count_for_payer.return_value = 0
    view.open_standing_count.return_value = 0
    return view


def create_tx(**overrides):
    tx = {
        "tx_type": "standing_payment_create",
        "sender_pubkey": A,
        "recipient_pubkey": B,
        "amount": 1000,
        "sequence_number": 1,
        "period_kind": PERIOD_MONTH,
        "anchor_timestamp": ANCHOR,
        "window_start_offset": 0,
        "window_end_offset": SECONDS_PER_DAY,
        "max_occurrences": 12,
    }
    tx.update(overrides)
    return tx


def _terms():
    return StandingTerms(
        payer=A, recipient=B, amount=1000, kind=PERIOD_MONTH,
        anchor_ts=ANCHOR, window_start_offset=0,
        window_end_offset=SECONDS_PER_DAY,
        end_kind=END_MAX_OCCURRENCES, end_value=12, sequence_number=1,
    )


def _row(**overrides):
    book = StandingBook()
    terms = _terms()
    book.create(terms, 10**12)
    row = book.snapshot_rows()[0]
    row.update(overrides)
    return row


def test_create_admitted(tip_view):
    result = validate_standing_create_payload(create_tx(), tip_view)
    assert result.is_valid
    assert result.data["standing_id"] == _terms().standing_id.hex()


def test_create_duplicate_rejected(tip_view):
    tip_view.get_standing.return_value = _row()
    result = validate_standing_create_payload(create_tx(), tip_view)
    assert not result.is_valid and result.code == "DUPLICATE_STANDING"


def test_create_two_end_conditions_rejected(tip_view):
    result = validate_standing_create_payload(create_tx(max_total=12000), tip_view)
    assert not result.is_valid


def test_execute_unknown_rejected(tip_view):
    tx = {"tx_type": "standing_payment_execute", "sender_pubkey": C,
          "standing_id": "00" * 32}
    result = validate_standing_execute_payload(tx, tip_view)
    assert not result.is_valid and result.code == "UNKNOWN_STANDING"


def test_execute_not_due_rejected(tip_view):
    row = _row()
    tip_view.get_standing.return_value = row
    tip_view.next_block_timestamp = TIP_TS  # weeks before the first window
    tx = {"tx_type": "standing_payment_execute", "sender_pubkey": C,
          "standing_id": row["standing_id"]}
    result = validate_standing_execute_payload(tx, tip_view)
    assert not result.is_valid and result.code == "STANDING_NOT_DUE"


def test_execute_due_admitted(tip_view):
    row = _row()
    tip_view.get_standing.return_value = row
    tip_view.next_block_timestamp = ANCHOR + 3600  # inside the window
    tx = {"tx_type": "standing_payment_execute", "sender_pubkey": C,
          "standing_id": row["standing_id"]}
    result = validate_standing_execute_payload(tx, tip_view)
    assert result.is_valid


def test_cancel_only_by_payer(tip_view):
    row = _row()
    tip_view.get_standing.return_value = row
    tx = {"tx_type": "standing_payment_cancel", "sender_pubkey": C,
          "standing_id": row["standing_id"]}
    result = validate_standing_cancel_payload(tx, tip_view)
    assert not result.is_valid and result.code == "NOT_STANDING_PAYER"
    tx["sender_pubkey"] = A
    result = validate_standing_cancel_payload(tx, tip_view)
    assert result.is_valid
