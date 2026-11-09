"""Admission judges time against its best guess of the next block's timestamp.

The genesis block has timestamp 0, and the tip lags the next block between any
two blocks. The guess is the later of the tip timestamp and the clock.
"""
from unittest.mock import MagicMock, patch

import pytest

from commands import sendtx
from consensus.admission import (
    TipAdmissionView,
    validate_retract_transfer_payload,
    validate_retractable_transfer_payload,
)
from consensus.retractable import KIND_TIME, MAX_RELEASE_WINDOW_SECONDS

A = "1a" * 48
B = "2b" * 48
NOW = 1_800_000_000


def _clock_at(ts):
    return patch("consensus.facade.time", MagicMock(time=MagicMock(return_value=ts)))


def _head_at(ts):
    head = {"header": {"block_number": 0, "timestamp": ts}}
    return patch("consensus.facade.db.get_canonical_head_block", return_value=head)


def _tip_view(tip_timestamp, row=None):
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = 1
    view.tip_timestamp = tip_timestamp
    view.next_block_timestamp = TipAdmissionView.next_block_timestamp.fget(view)
    view.get_retractable.return_value = row
    view.open_retractable_count_for_sender.return_value = 0
    view.open_retractable_count.return_value = 0
    return view


def _timed_park(release_at_time):
    return {
        "tx_type": "retractable_transfer",
        "sender_pubkey": A,
        "sequence_number": 0,
        "expiration_time": NOW + 60,
        "expire_at_height": 20,
        "fee_limit": "10",
        "recipient_pubkey": B,
        "amount": 100,
        "release_at_time": release_at_time,
    }


def _admit(tx, tip_timestamp):
    with _clock_at(NOW):
        return validate_retractable_transfer_payload(tx, _tip_view(tip_timestamp))


def test_a_time_park_right_after_genesis_is_admitted():
    result = _admit(_timed_park(NOW + 180), tip_timestamp=0)
    assert result.is_valid is True, result.error


def test_a_time_park_too_far_ahead_is_still_refused_after_genesis():
    result = _admit(_timed_park(NOW + MAX_RELEASE_WINDOW_SECONDS + 1), tip_timestamp=0)
    assert result.is_valid is False
    assert "seconds ahead" in result.error


def test_a_time_park_already_due_by_the_clock_is_refused():
    tx = _timed_park(NOW - 1)
    tx["expiration_time"] = NOW - 2
    result = _admit(tx, tip_timestamp=NOW - 600)
    assert result.is_valid is False
    assert "must be in the future" in result.error


@pytest.mark.parametrize("tip_ahead", [0, 30])
def test_a_tip_ahead_of_the_clock_still_bounds_the_window(tip_ahead):
    tip = NOW + tip_ahead
    assert _admit(_timed_park(tip + MAX_RELEASE_WINDOW_SECONDS), tip).is_valid is True
    assert _admit(_timed_park(tip + MAX_RELEASE_WINDOW_SECONDS + 1), tip).is_valid is False


def _retract_verdict(release_at, tip_timestamp):
    row = {
        "retractable_id": "ab" * 32,
        "sender_pubkey": A,
        "recipient_pubkey": B,
        "amount": 100,
        "sequence_number": 0,
        "release_kind": KIND_TIME,
        "release_at": release_at,
    }
    tx = {
        "tx_type": "retract_transfer",
        "sender_pubkey": A,
        "sequence_number": 1,
        "expiration_time": NOW + 60,
        "expire_at_height": 20,
        "fee_limit": "0",
        "retractable_id": "ab" * 32,
    }
    with _clock_at(NOW):
        return validate_retract_transfer_payload(tx, _tip_view(tip_timestamp, row))


def test_a_retract_after_release_by_the_clock_is_refused_on_an_older_tip():
    result = _retract_verdict(release_at=NOW - 10, tip_timestamp=NOW - 600)
    assert (result.is_valid, result.code) == (False, "RETRACT_TOO_LATE")


def test_a_retract_before_release_by_the_clock_is_admitted():
    result = _retract_verdict(release_at=NOW + 10, tip_timestamp=NOW - 600)
    assert result.is_valid is True, result.error


def test_a_retract_after_release_by_a_tip_ahead_of_the_clock_is_refused():
    result = _retract_verdict(release_at=NOW + 10, tip_timestamp=NOW + 20)
    assert (result.is_valid, result.code) == (False, "RETRACT_TOO_LATE")


@pytest.mark.parametrize("tip_timestamp,expected", [
    (0, NOW),
    (NOW - 600, NOW),
    (NOW + 30, NOW + 30),
])
def test_the_next_block_timestamp_is_the_later_of_tip_and_clock(tip_timestamp, expected):
    with _clock_at(NOW), _head_at(tip_timestamp):
        assert TipAdmissionView().next_block_timestamp == expected


def test_no_head_falls_back_to_the_clock():
    with _clock_at(NOW), patch("consensus.facade.db.get_canonical_head_block",
                               return_value=None):
        assert TipAdmissionView().next_block_timestamp == NOW


@pytest.mark.parametrize("tip_timestamp", [0, NOW - 600, NOW + 30])
def test_i5_at_admission_is_the_next_block_timestamp(tip_timestamp):
    with _clock_at(NOW), _head_at(tip_timestamp):
        assert sendtx._admission_timestamp() == TipAdmissionView().next_block_timestamp
        assert sendtx._admission_timestamp() == max(tip_timestamp, NOW)
