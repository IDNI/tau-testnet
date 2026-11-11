"""Consensus number rule: block and transaction JSON hold only integers in -2**63..2**64-1."""

from __future__ import annotations

import json
import math
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import block as block_mod
import chain_state
import db
from block import Block
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot

PROPOSER = "a" * 96
PREV = "b" * 64
BASE_TS = 1_700_000_000
PROOF = "c" * 192

INT_MIN = -(2**63)
INT_MAX = 2**64 - 1

# (id, Python value, JSON literal)
BAD_NUMBERS = [
    ("float", 1.5, "1.5"),
    ("float_exponent", 1e5, "1e5"),
    ("float_integral", 7.0, "7.0"),
    ("nan", float("nan"), "NaN"),
    ("infinity", float("inf"), "Infinity"),
    ("minus_infinity", float("-inf"), "-Infinity"),
    ("int_above", INT_MAX + 1, str(INT_MAX + 1)),
    ("int_below", INT_MIN - 1, str(INT_MIN - 1)),
]
BAD_IDS = [row[0] for row in BAD_NUMBERS]


def _tx(**extra):
    tx = {
        "tx_type": "user_tx",
        "sender_pubkey": PROPOSER,
        "sequence_number": 0,
        "operations": {},
    }
    tx.update(extra)
    return tx


# Places in a block body; each returns a transaction that holds `value`.
BODY_PLACES = {
    "tx_field": lambda v: _tx(sequence_number=v),
    "extra_tx_key": lambda v: _tx(memo=v),
    "operations_non_digit_key": lambda v: _tx(operations={"meta": {"k": [1, v]}}),
    "operations_custom_stream": lambda v: _tx(operations={"2": [v]}),
}


def _block(txs, *, number=1, previous_hash=PREV, timestamp=BASE_TS) -> Block:
    return Block.create(
        number, previous_hash, txs, PROPOSER, timestamp=timestamp, consensus_proof=PROOF,
    )


def _wire_text_with_header_literal(literal: str) -> str:
    """A signed-shape block JSON text whose header timestamp is `literal`."""
    text = json.dumps(_block([_tx()]).to_dict())
    old = '"timestamp": %d' % BASE_TS
    assert old in text
    return text.replace(old, '"timestamp": %s' % literal)


def _wire_text_with_body_literal(literal: str) -> str:
    """A block JSON text whose first transaction has `memo` set to `literal`.

    The block is built from the parsed value, so its hashes match the body.
    """
    return json.dumps(_block([_tx(memo=json.loads(literal))]).to_dict())


def _parent_snapshot() -> TauStateSnapshot:
    return TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"",
        metadata={"balances": {}, "sequence_numbers": {}, "lifecycle_manager": MagicMock()},
    )


# --- The strict parse and the number check -----------------------------------


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_strict_parse_refuses_non_finite_literals(literal):
    from consensus.json_numbers import loads_strict

    with pytest.raises(ValueError):
        loads_strict('{"a": [1, %s]}' % literal)


def test_strict_parse_keeps_valid_json():
    from consensus.json_numbers import loads_strict

    text = '{"a": [%d, %d, 0, -1, "x", true, null]}' % (INT_MIN, INT_MAX)
    assert loads_strict(text) == json.loads(text)


@pytest.mark.parametrize("name,value,literal", BAD_NUMBERS, ids=BAD_IDS)
def test_number_error_names_each_bad_number(name, value, literal):
    from consensus.json_numbers import number_error

    reason = number_error({"x": [{"y": value}]})
    assert reason and "$.x[0].y" in reason


@pytest.mark.parametrize("value", [INT_MIN, INT_MAX, 0, -1, True, False, None, "1.5"])
def test_number_error_accepts_valid_values(value):
    from consensus.json_numbers import number_error

    assert number_error({"x": [value]}) is None


# --- Blocks ------------------------------------------------------------------


@pytest.mark.parametrize("literal", ["1700000000.0", "1.7e9", "NaN", "Infinity", str(INT_MAX + 1)])
def test_from_dict_refuses_bad_number_in_header(literal):
    payload = json.loads(_wire_text_with_header_literal(literal))
    with pytest.raises(ValueError, match="number at"):
        Block.from_dict(payload)


@pytest.mark.parametrize("name,value,literal", BAD_NUMBERS, ids=BAD_IDS)
def test_from_dict_refuses_bad_number_in_body(name, value, literal):
    payload = json.loads(_wire_text_with_body_literal(literal))
    with pytest.raises(ValueError, match="number at"):
        Block.from_dict(payload)


@pytest.mark.parametrize("place", sorted(BODY_PLACES))
@pytest.mark.parametrize("name,value,literal", BAD_NUMBERS, ids=BAD_IDS)
def test_apply_refuses_bad_number_in_body(place, name, value, literal):
    from errors import BlockNumberInvalid

    blk = _block([BODY_PLACES[place](value)])
    with pytest.raises(BlockNumberInvalid):
        TauConsensusEngine().apply_block(MagicMock(), blk, _parent_snapshot())


def test_apply_refuses_float_in_header():
    from errors import BlockNumberInvalid

    blk = _block([_tx()])
    blk.header.timestamp = float(BASE_TS)
    with pytest.raises(BlockNumberInvalid):
        TauConsensusEngine().apply_block(MagicMock(), blk, _parent_snapshot())


@pytest.mark.parametrize("value", [INT_MIN, INT_MAX, -1])
def test_block_with_edge_integers_is_valid(value):
    blk = _block([_tx(memo=value, operations={"2": [value], "meta": value})])
    assert block_mod.block_number_reason(blk) is None
    again = Block.from_dict(json.loads(json.dumps(blk.to_dict())))
    assert again.transactions == blk.transactions


def test_process_new_block_refuses_bad_number(node_state):
    blk = _block([_tx(memo=1.5)], previous_hash=db.get_genesis_hash())
    with patch.object(chain_state.logger, "error") as log_error:
        assert chain_state.process_new_block(blk) is False
    assert db.get_block_by_hash(blk.block_hash) is None
    assert any("number at" in str(call.args) for call in log_error.call_args_list)


def test_ingest_block_refuses_bad_number(node_state):
    blk = _block([_tx(memo=INT_MAX + 1)], previous_hash=db.get_genesis_hash())
    result = chain_state.ingest_block(blk)
    assert result.status == "invalid"
    assert "number at" in result.message
    assert db.get_block_by_hash(blk.block_hash) is None


def test_rebuild_stops_on_bad_number():
    blk = _block([_tx(memo=float("inf"))])
    with patch("db.get_canonical_blocks_at_or_after_height", return_value=[blk.to_dict()]):
        result = chain_state.rebuild_state_from_blockchain(start_block=1)
    assert not result.ok
    assert "number at" in result.reason


def test_sync_ingest_skips_block_with_bad_number(node_state):
    from network.service import NetworkService

    blk = _block([_tx(memo=-(2**63) - 1)], previous_hash=db.get_genesis_hash())
    assert NetworkService._ingest_blocks([blk.to_dict()], "peer-under-test") == 0
    assert db.get_block_by_hash(blk.block_hash) is None


def test_db_block_read_refuses_non_finite_literal(node_state):
    blk = _block([_tx(memo="__NUMBER__")], previous_hash=db.get_genesis_hash())
    text = json.dumps(blk.to_dict()).replace('"__NUMBER__"', "NaN")
    with pytest.raises(ValueError):
        db.parse_block_json(text)


FIXTURES = os.path.join(os.path.dirname(__file__), "fixtures", "block_byte_size_vectors.json")


def test_fixture_vectors_hold_only_valid_integers():
    with open(FIXTURES, encoding="utf-8") as f:
        doc = json.load(f)
    for row in doc["vectors"]:
        payload = json.loads(row["block_json"])
        assert block_mod.block_number_reason(payload) is None, row["id"]
        assert block_mod.block_storage_json_bytes(Block.from_dict(payload)) == row["byte_count"], row["id"]


def test_fixture_invalid_number_literals_make_a_block_invalid():
    with open(FIXTURES, encoding="utf-8") as f:
        literals = json.load(f)["invalid_number_literals"]
    assert literals
    for literal in literals:
        text = _wire_text_with_body_literal(literal)
        with pytest.raises(ValueError, match="number at"):
            Block.from_dict(json.loads(text))
        try:
            stored = db.parse_block_json(text)
        except ValueError:
            continue
        assert block_mod.block_number_reason(stored), literal


# --- Admission ---------------------------------------------------------------


@pytest.mark.parametrize("literal", ["NaN", "Infinity", "-Infinity"])
def test_admission_refuses_non_finite_literal_at_parse(literal):
    from commands import sendtx

    blob = json.dumps(_tx(memo="__NUMBER__")).replace('"__NUMBER__"', literal)
    result = sendtx.queue_transaction(blob, propagate=False)
    assert result["ok"] is False
    assert result["code"] == "PARSE_ERROR"


@pytest.mark.parametrize("place", sorted(BODY_PLACES))
@pytest.mark.parametrize("name,value,literal", BAD_NUMBERS, ids=BAD_IDS)
def test_admission_refuses_bad_number(place, name, value, literal):
    from commands import sendtx

    # json.dumps writes a non-finite float as NaN or Infinity, which fails at the parse.
    if not (isinstance(value, float) and not math.isfinite(value)):
        blob = json.dumps(BODY_PLACES[place](value))
        result = sendtx.queue_transaction(blob, propagate=False)
        assert result["ok"] is False
        assert result["code"] == "INVALID_PARAMS"
        assert "number at" in result["message"]
    # The envelope check also covers payloads that arrive as dicts (readmission).
    verdict = sendtx._check_tx_envelope(BODY_PLACES[place](value))
    assert verdict is not None and verdict["code"] == "INVALID_PARAMS"
    assert "number at" in verdict["message"]


@pytest.mark.parametrize("value", [INT_MIN, INT_MAX, -1])
def test_admission_number_check_passes_edge_integers(value):
    from commands import sendtx

    verdict = sendtx._check_tx_envelope(_tx(memo=value, operations={"2": [value]}))
    # The envelope still fails later (no signature), but not on the number rule.
    assert verdict is not None
    assert "number at" not in verdict["message"]


# --- Producer ----------------------------------------------------------------


def test_producer_never_takes_bad_number_tx(node_state, monkeypatch):
    from commands import createblock
    from test_block_production_serialization import _forced_apply_result, _mining_allowed

    good = _tx(sender_pubkey=f"{1:096x}")
    bad = _tx(sender_pubkey=f"{2:096x}", memo=1.5)
    good_hash = block_mod.compute_tx_hash(good)
    bad_hash = block_mod.compute_tx_hash(bad)
    db.add_mempool_tx(json.dumps(good), good_hash, 1)
    db.add_mempool_tx(json.dumps(bad), bad_hash, 2)

    built = []
    monkeypatch.setattr(chain_state, "process_new_block", lambda blk: built.append(blk) or True)
    monkeypatch.setattr(TauConsensusEngine, "apply_block", _forced_apply_result([good_hash]))
    with _mining_allowed():
        createblock.create_block_from_mempool()

    assert len(built) == 1
    assert built[0].tx_ids == [good_hash]
    assert db.get_mempool_entry(bad_hash) is None
