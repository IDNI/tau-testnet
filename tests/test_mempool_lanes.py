"""Fast/slow transaction lanes: selection, quotas, eviction, block budget.

Rule-bearing transactions cost orders of magnitude more to apply than coin
transfers (applying a rule recompiles a composite; a transfer is one cheap
step), and both used to share a single ordering key. A burst of rule work
therefore delayed every queued transfer behind it.

Fee priority cannot express the split: a rule emits its own o8 user fee, so
`estimated_fee` is self-declared and a rule transaction can price itself to the
front of the queue. Quotas are the only sound mechanism, which is what these
tests pin.
"""
import json

import pytest

import config
import db
from consensus.lanes import (
    LANE_FAST,
    LANE_SLOW,
    classify_lane,
    classify_lane_payload,
    is_rule_bearing,
)

A = "aa" * 48
B = "bb" * 48
RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
FUTURE = 9999999999


def _payload(tx_type="user_tx", sender=A, seq=0, operations=None, **extra):
    tx = {
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FUTURE,
        "expire_at_height": 5000,
        "fee_limit": "10",
    }
    if operations is not None:
        tx["operations"] = operations
    tx.update(extra)
    return json.dumps(tx)


def _coin(sender=A, seq=0):
    return _payload(operations={"1": [[sender, B, 1]]}, sender=sender, seq=seq)


def _rule(sender=A, seq=0):
    return _payload(operations={"0": RULE}, sender=sender, seq=seq)


def _add(payload, tx_hash, received_at, estimated_fee=0, lane=None):
    db.add_mempool_tx(payload, tx_hash, received_at,
                      fee_limit=10, estimated_fee=estimated_fee, lane=lane)


# --- classification ---------------------------------------------------------

@pytest.mark.parametrize("tx,expected", [
    ({"tx_type": "user_tx", "operations": {"1": [["a", "b", 1]]}}, LANE_FAST),
    ({"tx_type": "user_tx", "operations": {"0": RULE}}, LANE_SLOW),
    # A mixed tx cannot be split -- the signature covers the whole payload --
    # so it goes slow, where the rule half belongs.
    ({"tx_type": "user_tx", "operations": {"0": RULE, "1": [["a", "b", 1]]}}, LANE_SLOW),
    # Whitespace-only rule op must NOT demote a pure transfer.
    ({"tx_type": "user_tx", "operations": {"0": "   ", "1": []}}, LANE_FAST),
    ({"tx_type": "user_tx", "operations": {"0": ""}}, LANE_FAST),
    ({"tx_type": "user_tx", "operations": {"0": 5}}, LANE_FAST),
    ({"tx_type": "rule_offer"}, LANE_SLOW),
    ({"tx_type": "rule_offer_accept"}, LANE_SLOW),
    # A rejection resolves a set membership and compiles nothing.
    ({"tx_type": "rule_offer_reject"}, LANE_FAST),
    ({"tx_type": "consensus_rule_update"}, LANE_SLOW),
    ({"tx_type": "consensus_rule_vote"}, LANE_FAST),
    ({}, LANE_FAST),
    ({"tx_type": "user_tx"}, LANE_FAST),
    ({"tx_type": "user_tx", "operations": "not a dict"}, LANE_FAST),
    (None, LANE_FAST),
    ("garbage", LANE_FAST),
])
def test_classify_lane(tx, expected):
    assert classify_lane(tx) == expected
    if isinstance(tx, dict):
        assert is_rule_bearing(tx) == (expected == LANE_SLOW)


def test_classify_lane_payload_tolerates_junk():
    assert classify_lane_payload(_rule()) == LANE_SLOW
    assert classify_lane_payload(_coin()) == LANE_FAST
    # Historical rows carried a "json:" prefix.
    assert classify_lane_payload("json:" + _rule()) == LANE_SLOW
    # Unparseable rows must not be able to claim slow-lane quota.
    assert classify_lane_payload("not json") == LANE_FAST
    assert classify_lane_payload(None) == LANE_FAST


# --- persistence ------------------------------------------------------------

def test_lane_is_persisted_and_derived_when_not_passed(temp_database):
    _add(_coin(), "coin-1", 1000)
    _add(_rule(), "rule-1", 1001)
    with db.get_db_connection() as conn:
        rows = dict(conn.execute("SELECT tx_hash, lane FROM mempool").fetchall())
    assert rows["coin-1"] == LANE_FAST
    assert rows["rule-1"] == LANE_SLOW


def test_sender_pubkey_is_persisted(temp_database):
    _add(_coin(sender=B), "coin-1", 1000)
    with db.get_db_connection() as conn:
        row = conn.execute(
            "SELECT sender_pubkey FROM mempool WHERE tx_hash = 'coin-1'").fetchone()
    assert row[0] == B


def test_backfill_fills_lane_for_preexisting_rows(temp_database):
    """DEFAULT 0 alone would misfile every existing rule tx into the fast lane,
    letting it keep competing with transfers for the same slots."""
    _add(_rule(), "rule-1", 1000)
    with db.get_db_connection() as conn:
        conn.execute("UPDATE mempool SET lane = 0, sender_pubkey = NULL")
        db._backfill_mempool_lanes(conn)
        row = conn.execute(
            "SELECT lane, sender_pubkey FROM mempool WHERE tx_hash = 'rule-1'").fetchone()
    assert row[0] == LANE_SLOW
    assert row[1] == A


def test_init_db_is_idempotent_with_lane_columns(temp_database):
    _add(_coin(), "coin-1", 1000)
    db.init_db()
    db.init_db()
    assert db.count_mempool_txs() == 1


# --- selection --------------------------------------------------------------

def test_fast_lane_is_selected_first(temp_database):
    _add(_rule(sender=B), "rule-1", 1000)
    _add(_coin(sender=A), "coin-1", 1001)
    rows = db.reserve_mempool_txs(limit=10)
    hashes = [r["tx_hash"] for r in rows]
    assert hashes == ["coin-1", "rule-1"]


def test_slow_quota_is_respected(temp_database):
    for i in range(5):
        _add(_rule(sender=format(i, "096x")), f"rule-{i}", 1000 + i)
    for i in range(3):
        _add(_coin(sender=format(100 + i, "096x")), f"coin-{i}", 2000 + i)

    rows = db.reserve_mempool_txs(limit=10, slow_limit=2)
    hashes = [r["tx_hash"] for r in rows]
    assert sum(1 for h in hashes if h.startswith("rule-")) == 2
    assert sum(1 for h in hashes if h.startswith("coin-")) == 3
    # Fast lane first.
    assert hashes[:3] == ["coin-0", "coin-1", "coin-2"]


def test_a_high_fee_rule_cannot_starve_transfers(temp_database):
    """The head-of-line case. A rule emits its own o8 fee, so it can declare a
    huge estimate; the quota must still hold it back."""
    _add(_rule(sender=B), "rule-rich", 500, estimated_fee=10 ** 9)
    for i in range(3):
        _add(_coin(sender=format(i, "096x")), f"coin-{i}", 1000 + i, estimated_fee=1)

    rows = db.reserve_mempool_txs(limit=10, slow_limit=1)
    hashes = [r["tx_hash"] for r in rows]
    assert hashes[:3] == ["coin-0", "coin-1", "coin-2"]
    assert hashes[3] == "rule-rich"


def test_slow_limit_zero_excludes_the_slow_lane(temp_database):
    _add(_rule(sender=B), "rule-1", 1000)
    _add(_coin(sender=A), "coin-1", 1001)
    hashes = [r["tx_hash"] for r in db.reserve_mempool_txs(limit=10, slow_limit=0)]
    assert hashes == ["coin-1"]


def test_slow_limit_none_keeps_pre_lane_behaviour(temp_database):
    for i in range(3):
        _add(_rule(sender=format(i, "096x")), f"rule-{i}", 1000 + i)
    hashes = [r["tx_hash"] for r in db.reserve_mempool_txs(limit=10)]
    assert len(hashes) == 3


def test_total_limit_is_still_respected(temp_database):
    for i in range(4):
        _add(_coin(sender=format(i, "096x")), f"coin-{i}", 1000 + i)
    for i in range(4):
        _add(_rule(sender=format(100 + i, "096x")), f"rule-{i}", 2000 + i)
    rows = db.reserve_mempool_txs(limit=5, slow_limit=4)
    assert len(rows) == 5
    # The fast lane fills first, so only one slow row fits.
    hashes = [r["tx_hash"] for r in rows]
    assert sum(1 for h in hashes if h.startswith("coin-")) == 4
    assert sum(1 for h in hashes if h.startswith("rule-")) == 1


def test_within_lane_order_is_unchanged(temp_database):
    """Fee priority, then arrival, then id -- the documented key."""
    _add(_coin(sender=format(1, "096x")), "coin-low", 1000, estimated_fee=1)
    _add(_coin(sender=format(2, "096x")), "coin-high", 2000, estimated_fee=99)
    _add(_coin(sender=format(3, "096x")), "coin-mid", 1500, estimated_fee=50)
    hashes = [r["tx_hash"] for r in db.reserve_mempool_txs(limit=10)]
    assert hashes == ["coin-high", "coin-mid", "coin-low"]


def test_reserved_rows_are_not_reselected(temp_database):
    _add(_coin(), "coin-1", 1000)
    assert len(db.reserve_mempool_txs(limit=10)) == 1
    assert db.reserve_mempool_txs(limit=10) == []


# --- eviction ---------------------------------------------------------------

def test_slow_lane_eviction_spares_the_fast_lane(temp_database, monkeypatch):
    """A rule flood must evict its own rows, not queued fee-paying transfers."""
    monkeypatch.setattr(config, "MAX_MEMPOOL_TXS", 20, raising=False)
    monkeypatch.setattr(config, "MEMPOOL_RULE_LANE_MAX_FRACTION", 0.1, raising=False)
    assert db._slow_lane_cap(20) == 2

    for i in range(3):
        _add(_coin(sender=format(i, "096x")), f"coin-{i}", 1000 + i)
    for i in range(2):
        _add(_rule(sender=format(100 + i, "096x")), f"rule-{i}", 2000 + i)
    # This one pushes the slow lane over its quota.
    _add(_rule(sender=format(200, "096x")), "rule-new", 3000)

    with db.get_db_connection() as conn:
        remaining = {r[0] for r in conn.execute("SELECT tx_hash FROM mempool").fetchall()}

    # Every transfer survived.
    assert {"coin-0", "coin-1", "coin-2"} <= remaining
    # The oldest slow-lane row was the victim.
    assert "rule-0" not in remaining
    assert "rule-new" in remaining


def test_eviction_is_recorded_for_gettxstatus(temp_database, monkeypatch):
    monkeypatch.setattr(config, "MAX_MEMPOOL_TXS", 20, raising=False)
    monkeypatch.setattr(config, "MEMPOOL_RULE_LANE_MAX_FRACTION", 0.1, raising=False)
    for i in range(2):
        _add(_rule(sender=format(i, "096x")), f"rule-{i}", 1000 + i)
    _add(_rule(sender=format(9, "096x")), "rule-new", 3000)

    dropped = db.get_dropped_tx("rule-0")
    assert dropped is not None and dropped["reason"] == "evicted"


def test_global_cap_still_evicts_when_lanes_are_within_quota(temp_database, monkeypatch):
    monkeypatch.setattr(config, "MAX_MEMPOOL_TXS", 3, raising=False)
    for i in range(3):
        _add(_coin(sender=format(i, "096x")), f"coin-{i}", 1000 + i)
    _add(_coin(sender=format(9, "096x")), "coin-new", 4000)

    with db.get_db_connection() as conn:
        remaining = {r[0] for r in conn.execute("SELECT tx_hash FROM mempool").fetchall()}
    assert "coin-0" not in remaining      # oldest-first, as before
    assert "coin-new" in remaining


# --- sequence helpers -------------------------------------------------------

def test_pending_sequence_uses_the_indexed_column(temp_database):
    _add(_coin(sender=A, seq=3), "a-3", 1000)
    _add(_coin(sender=A, seq=7), "a-7", 1001)
    _add(_coin(sender=B, seq=99), "b-99", 1002)
    assert db.get_pending_sequence(A) == 7
    assert db.get_min_pending_sequence(A) == 3
    assert db.get_pending_sequence(B) == 99
    assert db.get_pending_sequence("cc" * 48) is None
    assert db.get_min_pending_sequence("cc" * 48) is None


def test_pending_sequence_covers_rows_without_the_column(temp_database):
    """An upgraded database whose backfill could not run must still answer
    correctly, or a sender's next sequence number would be miscomputed."""
    _add(_coin(sender=A, seq=5), "a-5", 1000)
    with db.get_db_connection() as conn:
        conn.execute("UPDATE mempool SET sender_pubkey = NULL")
    assert db.get_pending_sequence(A) == 5
    assert db.get_min_pending_sequence(A) == 5


def test_pending_sequence_counts_reserved_rows(temp_database):
    """A reserved tx still owns its sequence number."""
    _add(_coin(sender=A, seq=4), "a-4", 1000)
    db.reserve_mempool_txs(limit=10)
    assert db.get_pending_sequence(A) == 4
