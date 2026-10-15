"""RPC surface for retractable transfers and the status/account extensions."""
import json
import time
import types

import pytest

import block as block_module
import chain_state
import db
from commands import (
    getaccountstate,
    getretractable,
    getretractableid,
    getretractables,
    gettxstatus,
)
from consensus.retractable import KIND_HEIGHT, KIND_TIME, RetractableEntry

SENDER = "a" * 96
RECIPIENT = "b" * 96
OTHER = "c" * 96
HEIGHT_ENTRY = RetractableEntry(SENDER, RECIPIENT, 40, 3, KIND_HEIGHT, 900)
TIME_ENTRY = RetractableEntry(SENDER, OTHER, 7, 4, KIND_TIME, 1_900_000_000)


@pytest.fixture()
def container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def call(module, line, container):
    return json.loads(module.execute(line, container))


def insert(entry):
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT INTO retractable_transfers_v1 (retractable_id, sender_pubkey, "
            "recipient_pubkey, amount, sequence_number, release_kind, release_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.retractable_id.hex(), entry.sender_pubkey, entry.recipient_pubkey,
             entry.amount, entry.sequence_number, entry.kind, entry.release_at),
        )


def remove(entry):
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "DELETE FROM retractable_transfers_v1 WHERE retractable_id = ?",
            (entry.retractable_id.hex(),),
        )


def park_tx(entry, **extra):
    tx = {
        "tx_type": "retractable_transfer", "sender_pubkey": entry.sender_pubkey,
        "sequence_number": entry.sequence_number, "expiration_time": 9999999999,
        "expire_at_height": 5000, "fee_limit": "0",
        "recipient_pubkey": entry.recipient_pubkey, "amount": entry.amount,
        "signature": "00" * 48,
    }
    tx["release_at_height" if entry.kind == KIND_HEIGHT else "release_at_time"] = entry.release_at
    tx.update(extra)
    return tx


def retract_tx(rid, seq=9):
    return {
        "tx_type": "retract_transfer", "sender_pubkey": SENDER, "sequence_number": seq,
        "expiration_time": 9999999999, "expire_at_height": 5000, "fee_limit": "0",
        "retractable_id": rid, "signature": "00" * 48,
    }


def queue(tx, tx_hash, **kwargs):
    db.add_mempool_tx(json.dumps(tx), tx_hash, int(time.time() * 1000), **kwargs)


def canonical_chain(*txs_per_block):
    """Genesis plus one block per entry; returns the non-genesis blocks."""
    parent = block_module.Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey=SENDER, timestamp=1_700_000_000)
    db.add_block(parent)
    blocks = []
    for n, txs in enumerate(txs_per_block, start=1):
        blk = block_module.Block.create(
            block_number=n, previous_hash=parent.block_hash, transactions=txs,
            proposer_pubkey=SENDER, timestamp=1_700_000_000 + n)
        db.add_block(blk)
        blocks.append(blk)
        parent = blk
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_hash', ?)",
            (parent.block_hash,))
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_number', ?)",
            (str(len(txs_per_block)),))
    return blocks


# --- getretractable -----------------------------------------------------------


def test_getretractable_open_entry(temp_database, container):
    insert(HEIGHT_ENTRY)
    resp = call(getretractable, f"getretractable {HEIGHT_ENTRY.retractable_id.hex()}", container)
    assert resp["status"] == "ok"
    assert resp["data"] == {
        "retractable_id": HEIGHT_ENTRY.retractable_id.hex(),
        "sender_pubkey": SENDER, "recipient_pubkey": RECIPIENT, "amount": 40,
        "sequence_number": 3, "status": "open", "release_at_height": 900,
    }


def test_getretractable_time_kind_reports_release_time(temp_database, container):
    insert(TIME_ENTRY)
    data = call(getretractable, f"getretractable {TIME_ENTRY.retractable_id.hex()}", container)["data"]
    assert data["release_at_time"] == 1_900_000_000
    assert "release_at_height" not in data


@pytest.mark.parametrize("outcome", ["released", "retracted"])
def test_getretractable_resolved_from_canonical_events(temp_database, container, outcome):
    parked, closing = canonical_chain([], [])
    rid = HEIGHT_ENTRY.retractable_id.hex()
    db.record_retractable_events(parked.block_hash, 1, [(rid, "parked")])
    db.record_retractable_events(closing.block_hash, 2, [(rid, outcome)])
    resp = call(getretractable, f"getretractable {rid}", container)
    assert resp["status"] == "ok"
    assert resp["data"] == {
        "retractable_id": rid, "status": outcome, "resolved_at_height": 2,
    }


def test_park_and_retract_in_one_block_resolve_as_retracted(temp_database, container):
    park = park_tx(HEIGHT_ENTRY)
    rid = HEIGHT_ENTRY.retractable_id.hex()
    (blk,) = canonical_chain([park, retract_tx(rid)])
    db.record_retractable_events(blk.block_hash, 1, [(rid, "parked"), (rid, "retracted")])

    resolved = call(getretractable, f"getretractable {rid}", container)
    assert resolved["data"]["status"] == "retracted"
    assert resolved["data"]["resolved_at_height"] == 1
    status = call(gettxstatus, f"gettxstatus {blk.tx_ids[0]}", container)["data"]
    assert status["retractable"] == {"id": rid, "status": "retracted"}


def test_getretractable_ignores_events_from_a_fork(temp_database, container):
    canonical_chain([])
    rid = HEIGHT_ENTRY.retractable_id.hex()
    db.record_retractable_events("ff" * 32, 1, [(rid, "released")])
    resp = call(getretractable, f"getretractable {rid}", container)
    assert resp["status"] == "error"
    assert resp["error"]["code"] == "RETRACTABLE_UNKNOWN"


def test_getretractable_unknown_and_malformed(temp_database, container):
    unknown = call(getretractable, f"getretractable {'ab' * 32}", container)
    assert unknown["error"]["code"] == "RETRACTABLE_UNKNOWN"
    assert call(getretractable, "getretractable nope", container)["error"]["code"] == "INVALID_PARAMS"
    assert call(getretractable, "getretractable", container)["error"]["code"] == "INVALID_PARAMS"


# --- getretractables ----------------------------------------------------------


def test_getretractables_roles(temp_database, container):
    insert(HEIGHT_ENTRY)
    insert(TIME_ENTRY)

    def ids(address, role):
        resp = call(getretractables, f"getretractables {address} {role}", container)
        assert resp["status"] == "ok", resp
        return {e["retractable_id"] for e in resp["data"]["retractables"]}

    both = {HEIGHT_ENTRY.retractable_id.hex(), TIME_ENTRY.retractable_id.hex()}
    assert ids(SENDER, "out") == both
    assert ids(SENDER, "in") == set()
    assert ids(RECIPIENT, "in") == {HEIGHT_ENTRY.retractable_id.hex()}
    assert ids(OTHER, "all") == {TIME_ENTRY.retractable_id.hex()}
    assert ids(SENDER, "all") == both


def test_getretractables_defaults_to_all_and_lists_mempool(temp_database, container):
    insert(HEIGHT_ENTRY)
    queue(park_tx(TIME_ENTRY), "11" * 32)
    queue(retract_tx(HEIGHT_ENTRY.retractable_id.hex()), "22" * 32)
    queue({"tx_type": "user_tx", "sender_pubkey": SENDER, "operations": {"1": []}}, "33" * 32)

    data = call(getretractables, f"getretractables {SENDER}", container)["data"]

    assert data["role"] == "all"
    assert len(data["retractables"]) == 1
    pending = {p["tx_type"]: p for p in data["mempool"]}
    assert set(pending) == {"retractable_transfer", "retract_transfer"}
    assert pending["retractable_transfer"]["retractable_id"] == TIME_ENTRY.retractable_id.hex()
    assert pending["retractable_transfer"]["release_at_time"] == 1_900_000_000
    assert pending["retract_transfer"]["retractable_id"] == HEIGHT_ENTRY.retractable_id.hex()


def test_getretractables_mempool_shows_incoming_park_to_recipient(temp_database, container):
    queue(park_tx(TIME_ENTRY), "11" * 32)
    data = call(getretractables, f"getretractables {OTHER} in", container)["data"]
    assert data["retractables"] == []
    assert [p["tx_type"] for p in data["mempool"]] == ["retractable_transfer"]


def test_getretractables_parameter_errors(temp_database, container):
    assert call(getretractables, "getretractables", container)["error"]["code"] == "INVALID_PARAMS"
    assert call(getretractables, "getretractables xyz", container)["error"]["code"] == "INVALID_PARAMS"
    bad_role = call(getretractables, f"getretractables {SENDER} sideways", container)
    assert bad_role["error"]["code"] == "INVALID_PARAMS"


# --- getretractableid ---------------------------------------------------------


def payload(**over):
    base = {"sender_pubkey": SENDER, "recipient_pubkey": RECIPIENT, "amount": 40,
            "sequence_number": 3, "release_at_height": 900}
    base.update(over)
    return base


def test_getretractableid_matches_the_entry_id(temp_database, container):
    resp = call(getretractableid, f"getretractableid {json.dumps(payload())}", container)
    assert resp["status"] == "ok"
    assert resp["data"]["retractable_id"] == HEIGHT_ENTRY.retractable_id.hex()
    assert resp["data"]["input_echo"]["release_at_height"] == 900


def test_getretractableid_accepts_quoted_json_and_uppercase_keys(temp_database, container):
    body = payload(sender_pubkey=SENDER.upper(), recipient_pubkey=RECIPIENT.upper())
    resp = call(getretractableid, f"getretractableid '{json.dumps(body)}'", container)
    assert resp["data"]["retractable_id"] == HEIGHT_ENTRY.retractable_id.hex()


def test_getretractableid_time_kind_differs_from_height_kind(temp_database, container):
    body = payload(release_at_height=None, release_at_time=900)
    time_id = call(getretractableid, f"getretractableid {json.dumps(body)}", container)["data"]["retractable_id"]
    assert time_id != HEIGHT_ENTRY.retractable_id.hex()


def test_getretractableid_reports_shape_problems_without_raising(temp_database, container):
    resp = call(getretractableid, f"getretractableid {json.dumps(payload(amount=0))}", container)
    assert resp["status"] == "ok"
    assert "retractable_id" in resp["data"]
    assert "amount" in resp["data"]["shape_error"]

    past = call(getretractableid, f"getretractableid {json.dumps(payload(release_at_height=0))}", container)
    assert "future" in past["data"]["shape_error"]


@pytest.mark.parametrize("body", [
    payload(release_at_time=5),
    payload(release_at_height=None),
    payload(sender_pubkey="zz"),
    payload(amount="x"),
])
def test_getretractableid_rejects_unusable_input(temp_database, container, body):
    resp = call(getretractableid, f"getretractableid {json.dumps(body)}", container)
    assert resp["status"] == "error"
    assert resp["error"]["code"] == "INVALID_PARAMS"


def test_getretractableid_json_errors(temp_database, container):
    assert call(getretractableid, "getretractableid {", container)["error"]["code"] == "PARSE_ERROR"
    assert call(getretractableid, "getretractableid", container)["error"]["code"] == "INVALID_PARAMS"
    assert call(getretractableid, "getretractableid [1]", container)["error"]["code"] == "INVALID_PARAMS"


# --- gettxstatus --------------------------------------------------------------


def test_gettxstatus_confirmed_park_reports_open(temp_database, container):
    park = park_tx(HEIGHT_ENTRY)
    (blk,) = canonical_chain([park])
    insert(HEIGHT_ENTRY)

    data = call(gettxstatus, f"gettxstatus {blk.tx_ids[0]}", container)["data"]

    assert data["status"] == "confirmed"
    assert data["retractable"] == {"id": HEIGHT_ENTRY.retractable_id.hex(), "status": "open"}


def test_gettxstatus_confirmed_park_reports_how_it_ended(temp_database, container):
    park = park_tx(HEIGHT_ENTRY)
    parked, closing = canonical_chain([park], [])
    rid = HEIGHT_ENTRY.retractable_id.hex()
    db.record_retractable_events(closing.block_hash, 2, [(rid, "released")])

    data = call(gettxstatus, f"gettxstatus {parked.tx_ids[0]}", container)["data"]

    assert data["retractable"] == {"id": rid, "status": "released"}


def test_gettxstatus_park_that_never_landed_in_the_book(temp_database, container):
    (blk,) = canonical_chain([park_tx(HEIGHT_ENTRY)])
    data = call(gettxstatus, f"gettxstatus {blk.tx_ids[0]}", container)["data"]
    assert data["retractable"]["status"] == "not_recorded"


def test_gettxstatus_confirmed_retract_names_its_target(temp_database, container):
    rid = HEIGHT_ENTRY.retractable_id.hex()
    (blk,) = canonical_chain([retract_tx(rid)])
    data = call(gettxstatus, f"gettxstatus {blk.tx_ids[0]}", container)["data"]
    assert data["retracts"] == rid
    assert "retractable" not in data


def test_gettxstatus_ordinary_tx_has_no_retractable_fields(temp_database, container):
    tx = {"tx_id": "t", "operations": {"1": [[SENDER, RECIPIENT, "1"]]}}
    (blk,) = canonical_chain([tx])
    data = call(gettxstatus, f"gettxstatus {blk.tx_ids[0]}", container)["data"]
    assert data["status"] == "confirmed"
    assert "retractable" not in data and "retracts" not in data


# --- getaccountstate ----------------------------------------------------------


def test_getaccountstate_reports_escrow_both_ways(temp_database, container):
    insert(HEIGHT_ENTRY)
    insert(TIME_ENTRY)
    chain_state._balances[SENDER] = 500
    chain_state._balances[RECIPIENT] = 5

    sender = call(getaccountstate, f"getaccountstate {SENDER}", container)["data"]
    recipient = call(getaccountstate, f"getaccountstate {RECIPIENT}", container)["data"]
    stranger = call(getaccountstate, f"getaccountstate {'d' * 96}", container)["data"]

    assert (sender["escrowed_out"], sender["escrowed_in"]) == ("47", "0")
    assert (recipient["escrowed_out"], recipient["escrowed_in"]) == ("0", "40")
    assert (stranger["escrowed_out"], stranger["escrowed_in"]) == ("0", "0")
    assert sender["chain_balance"] == "500"


def test_queued_park_is_pending_outgoing_for_the_sender_only(temp_database, container):
    chain_state._balances[SENDER] = 500
    queue(park_tx(HEIGHT_ENTRY), "44" * 32, estimated_fee=2)

    sender = call(getaccountstate, f"getaccountstate {SENDER}", container)["data"]
    recipient = call(getaccountstate, f"getaccountstate {RECIPIENT}", container)["data"]

    assert sender["pending_outgoing"] == "40"
    assert sender["pending_fees"] == "2"
    assert sender["available_balance"] == "458"
    assert sender["pending_txs"][0]["direction"] == "outgoing"
    assert sender["pending_txs"][0]["tx_type"] == "retractable_transfer"
    assert recipient["pending_incoming"] == "0"
    assert recipient["pending_txs"] == []


def test_mempool_helper_counts_a_queued_park(temp_database):
    queue(park_tx(HEIGHT_ENTRY), "55" * 32)
    (row,) = db.get_mempool_txs_for_address(SENDER)
    assert row["amount_out"] == 40 and row["amount_in"] == 0
    assert db.get_mempool_txs_for_address(RECIPIENT) == []
