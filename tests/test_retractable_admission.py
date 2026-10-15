"""Mempool admission for retractable transfers.

Three layers: the pure validators against a mocked tip view, `queue_transaction`
end to end with scripted Tau outputs, and a shared corpus judged by BOTH the
admission validator and block apply, which must accept and reject the same
inputs or the chain splits.

`MagicMock(spec=TipAdmissionView)` returns a truthy Mock for any attribute left
unset, so every accessor the validators read is set explicitly below.
"""
import json
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

import chain_state
import config
import db
import tau_defs
import consensus.retractable as retractable
from consensus.admission import (
    TipAdmissionView,
    validate_mempool_admission,
    validate_retract_transfer_payload,
    validate_retractable_transfer_payload,
)
from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    MAX_RELEASE_WINDOW_BLOCKS,
    MAX_RELEASE_WINDOW_SECONDS,
    RetractableEntry,
    parse_retractable_transfer,
)

A = "1a" * 48
B = "2b" * 48
C = "3c" * 48
NEXT_HEIGHT = 50
TIP_TS = 1_700_000_000
FAR = 9_999_999_999


@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = TIP_TS
    view.get_retractable.return_value = None
    view.open_retractable_count_for_sender.return_value = 0
    view.open_retractable_count.return_value = 0
    return view


def park(**over):
    tx = {
        "tx_type": "retractable_transfer",
        "sender_pubkey": A,
        "sequence_number": 1,
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "10",
        "recipient_pubkey": B,
        "amount": 100,
        "release_at_height": NEXT_HEIGHT + 30,
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def timed_park(**over):
    over.setdefault("release_at_time", TIP_TS + 600)
    over.setdefault("expiration_time", TIP_TS + 100)
    return park(release_at_height=None, **over)


def entry_of(tx):
    return parse_retractable_transfer(tx)


def retract(rid, sender=A, **over):
    tx = {
        "tx_type": "retract_transfer",
        "sender_pubkey": sender,
        "sequence_number": 2,
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 20,
        "fee_limit": "0",
        "retractable_id": rid,
    }
    tx.update(over)
    return tx


def row_for(entry: RetractableEntry):
    return {
        "retractable_id": entry.retractable_id.hex(),
        "sender_pubkey": entry.sender_pubkey,
        "recipient_pubkey": entry.recipient_pubkey,
        "amount": entry.amount,
        "sequence_number": entry.sequence_number,
        "release_kind": entry.kind,
        "release_at": entry.release_at,
    }


# --- park validator ----------------------------------------------------------

def test_a_well_formed_height_park_is_admitted(tip_view):
    tx = park()
    result = validate_mempool_admission(tx, tip_view)
    assert result.is_valid is True, result.error
    assert result.data == {
        "retractable_id": entry_of(tx).retractable_id.hex(),
        "amount": 100,
        "recipient_pubkey": B,
        "release_kind": KIND_HEIGHT,
        "release_at": NEXT_HEIGHT + 30,
    }


def test_a_well_formed_time_park_is_admitted(tip_view):
    result = validate_mempool_admission(timed_park(), tip_view)
    assert result.is_valid is True, result.error
    assert result.data["release_kind"] == KIND_TIME


@pytest.mark.parametrize("over,fragment", [
    ({"amount": 0}, "amount must be in"),
    ({"amount": tau_defs.MAX_TRANSFER_VALUE + 1}, "amount must be in"),
    ({"release_at_height": NEXT_HEIGHT, "expire_at_height": NEXT_HEIGHT + 1}, "in the future"),
    ({"release_at_height": NEXT_HEIGHT + MAX_RELEASE_WINDOW_BLOCKS + 1,
      "expire_at_height": NEXT_HEIGHT + 20}, "blocks ahead"),
    ({"release_at_time": TIP_TS + 100}, "exactly one"),
    ({"release_at_height": None}, "exactly one"),
    ({"recipient_pubkey": B.upper()}, "recipient_pubkey"),
    ({"recipient_pubkey": "zz"}, "recipient_pubkey"),
    ({"amount": "100"}, "amount"),
    ({"amount": True}, "amount"),
])
def test_park_shape_errors_are_surfaced(tip_view, over, fragment):
    result = validate_mempool_admission(park(**over), tip_view)
    assert result.is_valid is False
    assert fragment in result.error


def test_time_park_window_errors(tip_view):
    past = validate_mempool_admission(timed_park(release_at_time=TIP_TS), tip_view)
    far = validate_mempool_admission(
        timed_park(release_at_time=TIP_TS + MAX_RELEASE_WINDOW_SECONDS + 1), tip_view)
    assert "in the future" in past.error
    assert "seconds ahead" in far.error


def test_park_sender_must_match_the_envelope_signer(tip_view):
    tx = park()
    tx["sender_pubkey"] = A.upper()
    result = validate_retractable_transfer_payload(tx, tip_view)
    assert result.is_valid is False


def test_a_duplicate_park_is_refused(tip_view):
    tx = park()
    tip_view.get_retractable.return_value = row_for(entry_of(tx))
    result = validate_mempool_admission(tx, tip_view)
    assert result.is_valid is False
    assert result.code == "DUPLICATE_RETRACTABLE"
    tip_view.get_retractable.assert_called_once_with(entry_of(tx).retractable_id)


def test_the_per_sender_cap_is_enforced(tip_view):
    tip_view.open_retractable_count_for_sender.return_value = (
        retractable.MAX_OPEN_RETRACTABLE_PER_SENDER)
    result = validate_mempool_admission(park(), tip_view)
    assert (result.is_valid, result.code) == (False, "TOO_MANY_RETRACTABLES")
    tip_view.open_retractable_count_for_sender.assert_called_once_with(A)


def test_just_under_the_per_sender_cap_is_admitted(tip_view):
    tip_view.open_retractable_count_for_sender.return_value = (
        retractable.MAX_OPEN_RETRACTABLE_PER_SENDER - 1)
    assert validate_mempool_admission(park(), tip_view).is_valid is True


def test_the_global_cap_is_enforced(tip_view):
    tip_view.open_retractable_count.return_value = retractable.MAX_OPEN_RETRACTABLE_TOTAL
    result = validate_mempool_admission(park(), tip_view)
    assert (result.is_valid, result.code) == (False, "RETRACTABLE_BOOK_FULL")


def test_height_deadline_may_equal_but_not_exceed_release(tip_view):
    release = NEXT_HEIGHT + 30
    ok = validate_mempool_admission(park(expire_at_height=release), tip_view)
    late = validate_mempool_admission(park(expire_at_height=release + 1), tip_view)
    assert ok.is_valid is True, ok.error
    assert (late.is_valid, late.code) == (False, "DEADLINE_AFTER_RELEASE")


def test_time_deadline_must_be_strictly_before_release(tip_view):
    release = TIP_TS + 600
    ok = validate_mempool_admission(timed_park(expiration_time=release - 1), tip_view)
    at = validate_mempool_admission(timed_park(expiration_time=release), tip_view)
    assert ok.is_valid is True, ok.error
    assert (at.is_valid, at.code) == (False, "DEADLINE_AFTER_RELEASE")


def test_height_kind_ignores_the_wall_clock_deadline(tip_view):
    tx = park(expiration_time=1)
    assert validate_retractable_transfer_payload(tx, tip_view).is_valid is True


# --- retract validator -------------------------------------------------------

def _open(tip_view, tx=None, **over):
    entry = entry_of(tx or park(**over))
    tip_view.get_retractable.return_value = row_for(entry)
    return entry.retractable_id.hex()


def test_the_sender_may_retract_an_open_entry(tip_view):
    rid = _open(tip_view)
    result = validate_mempool_admission(retract(rid), tip_view)
    assert result.is_valid is True, result.error
    assert result.data == {"retractable_id": rid}


def test_an_unknown_id_is_refused(tip_view):
    result = validate_mempool_admission(retract("ab" * 32), tip_view)
    assert (result.is_valid, result.code) == (False, "UNKNOWN_RETRACTABLE")


def test_a_non_sender_is_refused(tip_view):
    rid = _open(tip_view)
    result = validate_mempool_admission(retract(rid, sender=C), tip_view)
    assert (result.is_valid, result.code) == (False, "NOT_RETRACTABLE_SENDER")


def test_a_height_retract_at_or_after_release_is_too_late(tip_view):
    rid = _open(tip_view, release_at_height=NEXT_HEIGHT, expire_at_height=NEXT_HEIGHT)
    result = validate_retract_transfer_payload(retract(rid), tip_view)
    assert (result.is_valid, result.code) == (False, "RETRACT_TOO_LATE")


def test_a_height_retract_in_the_last_block_before_release_is_admitted(tip_view):
    rid = _open(tip_view, release_at_height=NEXT_HEIGHT + 1)
    assert validate_retract_transfer_payload(retract(rid), tip_view).is_valid is True


def test_a_time_retract_at_or_after_release_is_too_late(tip_view):
    rid = _open(tip_view, tx=timed_park(release_at_time=TIP_TS))
    result = validate_retract_transfer_payload(retract(rid), tip_view)
    assert (result.is_valid, result.code) == (False, "RETRACT_TOO_LATE")


def test_a_time_retract_before_release_is_admitted(tip_view):
    rid = _open(tip_view, tx=timed_park())
    assert validate_retract_transfer_payload(retract(rid), tip_view).is_valid is True


@pytest.mark.parametrize("rid", ["", "AB" * 32, "ab" * 31, 5, None])
def test_a_malformed_retractable_id_is_refused(tip_view, rid):
    result = validate_retract_transfer_payload(retract(rid), tip_view)
    assert result.is_valid is False
    assert "Malformed retract_transfer" in result.error


# --- queue_transaction flows -------------------------------------------------

SENDER = "a" * 96
RECIPIENT = "c" * 96


@pytest.fixture
def node(temp_database, monkeypatch):
    """A real database, a mocked signature check, and a scriptable Tau."""
    from commands import sendtx

    script = {"fee": 0, "custom": 0, "block_o5": False, "calls": []}

    def multi(**kwargs):
        script["calls"].append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        return {
            1: str(vals.get(1, "0")),
            5: "0" if script["block_o5"] else "1",
            8: str(script["custom"]),
            9: str(script["fee"]),
        }

    patches = [
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau", return_value="x1001"),
        patch("tau_manager.communicate_with_tau_multi", side_effect=multi),
        patch("commands.sendtx.G2Basic"),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch("commands.sendtx._validate_bls12_381_pubkey", return_value=(True, None)),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
    ]
    mocks = [p.start() for p in patches]
    mocks[0].is_set.return_value = True
    mocks[3].Verify.return_value = True
    monkeypatch.setattr(config, "TESTNET_AUTO_FAUCET", False)
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    height = patch.object(TipAdmissionView, "next_block_height",
                          new_callable=PropertyMock, return_value=NEXT_HEIGHT)
    ts = patch.object(TipAdmissionView, "tip_timestamp",
                      new_callable=PropertyMock, return_value=TIP_TS)
    height.start()
    ts.start()
    yield sendtx, script
    for p in reversed(patches + [height, ts]):
        p.stop()


def _park_payload(**over):
    over.setdefault("fee_limit", "100")
    return park(sender_pubkey=SENDER, recipient_pubkey=RECIPIENT,
                signature="00" * 48, **over)


def _queue(sendtx, payload, **kw):
    return sendtx.queue_transaction(json.dumps(payload), propagate=False, **kw)


def _mempool_hashes():
    with db._db_lock:
        return [r[0] for r in db._db_conn.execute("SELECT tx_hash FROM mempool")]


def test_a_park_is_queued_with_its_estimated_fee(node):
    sendtx, script = node
    script["fee"], script["custom"] = 30, 5
    result = _queue(sendtx, _park_payload())
    assert result["ok"], result
    with db._db_lock:
        row = db._db_conn.execute(
            "SELECT estimated_fee, fee_limit FROM mempool").fetchone()
    assert tuple(row) == (35, 100)
    assert len(script["calls"]) == 1, "one transfer step, no extra fee query"
    inputs = script["calls"][0]["input_stream_values"]
    assert inputs[1] == "100"
    assert inputs[3].endswith("}:bv[384]") and SENDER in inputs[3]
    assert RECIPIENT in inputs[4]


def test_the_park_fee_limit_is_checked_against_the_estimate(node):
    sendtx, script = node
    script["fee"] = 50
    result = _queue(sendtx, _park_payload(fee_limit="10"))
    assert result["ok"] is False
    assert result["code"] == "FEE_LIMIT_TOO_LOW"
    assert result["details"]["required_fee"] == 50
    assert _mempool_hashes() == []


def test_a_park_the_balance_cannot_cover_is_refused(node, monkeypatch):
    sendtx, script = node
    script["fee"] = 5
    monkeypatch.setitem(chain_state._balances, SENDER, 103)
    result = _queue(sendtx, _park_payload(fee_limit="10"))
    assert result["ok"] is False
    assert result["code"] in {"INSUFFICIENT_FUNDS", "TX_INVALID"}
    assert _mempool_hashes() == []


def test_a_park_blocked_by_the_senders_o5_policy_is_refused(node):
    sendtx, script = node
    script["block_o5"] = True
    result = _queue(sendtx, _park_payload())
    assert result["ok"] is False
    assert result["code"] == "TX_REJECTED"
    assert "policy" in result["message"]
    assert _mempool_hashes() == []


def test_a_park_dry_run_reports_the_fee_and_queues_nothing(node):
    sendtx, script = node
    script["fee"] = 8
    result = _queue(sendtx, _park_payload(), dry_run=True)
    assert result["ok"] and result["admissible"]
    assert result["tx_type"] == "retractable_transfer"
    assert result["estimated_fee"] == "8"
    assert _mempool_hashes() == []


def test_a_park_dry_run_without_tau_has_no_estimate(node):
    sendtx, script = node
    result = _queue(sendtx, _park_payload(), dry_run=True, skip_tau_eval=True)
    assert result["ok"] and "estimated_fee" not in result
    assert script["calls"] == []


def test_a_park_with_stray_operations_is_judged_only_by_its_fields(node):
    sendtx, script = node
    payload = _park_payload(operations={"1": [[SENDER, "d" * 96, 999_999]], "13": "5"})
    result = _queue(sendtx, payload)
    assert result["ok"], result
    inputs = script["calls"][0]["input_stream_values"]
    assert inputs[1] == "100" and 13 not in inputs


def _seed_open_entry(tx):
    entry = entry_of(tx)
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT INTO retractable_transfers_v1 (retractable_id, sender_pubkey, "
            "recipient_pubkey, amount, sequence_number, release_kind, release_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (entry.retractable_id.hex(), entry.sender_pubkey, entry.recipient_pubkey,
             entry.amount, entry.sequence_number, entry.kind, entry.release_at))
    return entry.retractable_id.hex()


def _retract_payload(rid, **over):
    return retract(rid, sender=SENDER, signature="00" * 48, **over)


def test_a_retract_is_queued_without_a_tau_step(node):
    sendtx, script = node
    rid = _seed_open_entry(_park_payload())
    result = _queue(sendtx, _retract_payload(rid, sequence_number=1))
    assert result["ok"], result
    assert script["calls"] == []
    with db._db_lock:
        row = db._db_conn.execute("SELECT estimated_fee, lane FROM mempool").fetchone()
    assert tuple(row) == (0, 0)


def test_a_second_pending_retract_for_the_same_entry_is_refused(node):
    sendtx, script = node
    rid = _seed_open_entry(_park_payload())
    first = _queue(sendtx, _retract_payload(rid, sequence_number=1))
    assert first["ok"], first
    second = _queue(sendtx, _retract_payload(rid, sequence_number=2, expiration_time=FAR - 1))
    assert second["ok"] is False
    assert second["code"] == "DUPLICATE_RETRACT"
    assert second["details"]["pending_tx_hash"] == first["tx_hash"]
    assert _mempool_hashes() == [first["tx_hash"]]


def test_a_retract_for_another_entry_is_not_a_duplicate(node):
    sendtx, script = node
    rid_a = _seed_open_entry(_park_payload())
    rid_b = _seed_open_entry(_park_payload(amount=200))
    assert _queue(sendtx, _retract_payload(rid_a, sequence_number=1))["ok"]
    assert _queue(sendtx, _retract_payload(rid_b, sequence_number=2))["ok"]


def test_the_dedupe_does_not_block_the_admission_validator(node):
    """Readmission and checktx share validate_mempool_admission; they must not
    see the mempool, or a queued retract would refuse its own readmission."""
    sendtx, _ = node
    rid = _seed_open_entry(_park_payload())
    assert _queue(sendtx, _retract_payload(rid, sequence_number=1))["ok"]
    result = validate_mempool_admission(_retract_payload(rid), TipAdmissionView())
    assert result.is_valid is True, result.error


def test_a_retract_dry_run_does_not_touch_the_mempool(node):
    sendtx, _ = node
    rid = _seed_open_entry(_park_payload())
    result = _queue(sendtx, _retract_payload(rid, sequence_number=1), dry_run=True)
    assert result["ok"] and result["admissible"]
    assert _mempool_hashes() == []


def test_a_retract_of_an_unknown_entry_is_refused(node):
    sendtx, _ = node
    result = _queue(sendtx, _retract_payload("ab" * 32, sequence_number=1))
    assert (result["ok"], result["code"]) == (False, "UNKNOWN_RETRACTABLE")


# --- the facade reads what the commit wrote ---------------------------------

def test_facade_accessors_read_the_persisted_rows(temp_database):
    view = TipAdmissionView()
    assert view.open_retractable_count() == 0
    assert view.get_retractable(b"\x01" * 32) is None
    assert view.escrowed_out(A) == view.escrowed_in(B) == 0

    first, second = park(), park(sequence_number=2, amount=40, recipient_pubkey=C)
    rid = _seed_open_entry(first)
    _seed_open_entry(second)
    row = view.get_retractable(bytes.fromhex(rid))
    assert row["amount"] == 100 and row["sender_pubkey"] == A
    assert view.open_retractable_count() == 2
    assert view.open_retractable_count_for_sender(A) == 2
    assert view.open_retractable_count_for_sender(B) == 0
    assert view.escrowed_out(A) == 140
    assert view.escrowed_in(B) == 100 and view.escrowed_in(C) == 40


def test_facade_defaults_when_the_tables_are_absent(temp_database):
    with db._db_lock, db._db_conn:
        db._db_conn.execute("DROP TABLE retractable_transfers_v1")
    view = TipAdmissionView()
    assert view.get_retractable(b"\x01" * 32) is None
    assert view.open_retractable_count() == 0
    assert view.open_retractable_count_for_sender(A) == 0
    assert view.escrowed_out(A) == 0 and view.escrowed_in(A) == 0


# --- admission and apply agree ----------------------------------------------

def _apply_park(**kw):
    """test_retractable_apply.park_tx with deadlines that satisfy the advisory
    coupling, so only the rules shared with apply decide the verdict."""
    from test_retractable_apply import HEIGHT, TS, park_tx

    kw.setdefault("expire_at_height", HEIGHT + 5)
    kw.setdefault("expiration_time", TS + 100)
    return park_tx(**kw)


def _agreement_corpus():
    from test_retractable_apply import ALICE, BOB, HEIGHT, TS
    park_tx = _apply_park

    cases = {
        "valid_height": park_tx(),
        "valid_time": park_tx(at_height=None, at_time=TS + 600),
        "amount_zero": park_tx(amount=0),
        "amount_too_big": park_tx(amount=tau_defs.MAX_TRANSFER_VALUE + 1),
        "height_not_future": park_tx(at_height=HEIGHT),
        "height_past": park_tx(at_height=HEIGHT - 3),
        "height_too_far": park_tx(at_height=HEIGHT + MAX_RELEASE_WINDOW_BLOCKS + 1),
        "height_at_limit": park_tx(at_height=HEIGHT + MAX_RELEASE_WINDOW_BLOCKS),
        "time_not_future": park_tx(at_height=None, at_time=TS),
        "time_too_far": park_tx(at_height=None, at_time=TS + MAX_RELEASE_WINDOW_SECONDS + 1),
        "time_at_limit": park_tx(at_height=None, at_time=TS + MAX_RELEASE_WINDOW_SECONDS),
        "both_release_points": park_tx(mutate=lambda t: t.update(release_at_time=TS + 9)),
        "neither_release_point": park_tx(at_height=None),
        "negative_amount": park_tx(amount=-5),
        "self_transfer": park_tx(recipient=ALICE),
    }
    return cases, (ALICE, BOB, HEIGHT, TS)


def _admission_verdict(tx, sender_height, ts, *, existing=None, sender_open=0, total_open=0):
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = sender_height
    view.tip_timestamp = ts
    view.get_retractable.return_value = existing
    view.open_retractable_count_for_sender.return_value = sender_open
    view.open_retractable_count.return_value = total_open
    admitted = validate_retractable_transfer_payload(tx, view)
    return admitted.is_valid


def test_admission_and_apply_agree_on_the_shared_corpus():
    from test_retractable_apply import Chain, _balances

    cases, (_, _, height, ts) = _agreement_corpus()
    for name, tx in cases.items():
        chain = Chain(_balances())
        applied = chain.block([tx], height=height, ts=ts)
        parked = tx["tx_id"] in applied.accepted_tx_ids and bool(chain.book.open)
        admitted = _admission_verdict(tx, height, ts)
        assert admitted == parked, (
            f"{name}: admission={admitted} apply={parked}; the two layers must "
            "accept and reject the same park")
    assert any(_admission_verdict(tx, height, ts) for tx in cases.values())
    assert not all(_admission_verdict(tx, height, ts) for tx in cases.values())


def test_admission_and_apply_agree_on_duplicates_and_caps(monkeypatch):
    from test_retractable_apply import ALICE, Chain, HEIGHT, TS, _balances, rid_of
    park_tx = _apply_park

    # Duplicate: the same entry already open.
    chain = Chain(_balances())
    first = park_tx(amount=50, seq=0)
    chain.block([first], height=HEIGHT, ts=TS)
    again = park_tx(amount=50, seq=0)
    result = chain.block([again], height=HEIGHT + 1, ts=TS + 5)
    existing = row_for(parse_retractable_transfer(first))
    assert again["tx_id"] not in result.accepted_tx_ids
    assert _admission_verdict(again, HEIGHT + 1, TS + 5, existing=existing) is False

    # Per-sender cap, with both layers reading the same limit.
    import consensus.admission as admission

    monkeypatch.setattr(retractable, "MAX_OPEN_RETRACTABLE_PER_SENDER", 1)
    monkeypatch.setattr(admission, "MAX_OPEN_RETRACTABLE_PER_SENDER", 1)
    chain = Chain(_balances())
    chain.block([park_tx(amount=1, seq=0)], height=HEIGHT, ts=TS)
    over = park_tx(amount=2, seq=1)
    result = chain.block([over], height=HEIGHT + 1, ts=TS + 5)
    assert over["tx_id"] not in result.accepted_tx_ids
    assert _admission_verdict(over, HEIGHT + 1, TS + 5, sender_open=1) is False
    assert _admission_verdict(over, HEIGHT + 1, TS + 5, sender_open=0) is True

    # Global cap.
    monkeypatch.setattr(retractable, "MAX_OPEN_RETRACTABLE_TOTAL", 1)
    monkeypatch.setattr(admission, "MAX_OPEN_RETRACTABLE_TOTAL", 1)
    monkeypatch.setattr(retractable, "MAX_OPEN_RETRACTABLE_PER_SENDER", 16)
    monkeypatch.setattr(admission, "MAX_OPEN_RETRACTABLE_PER_SENDER", 16)
    chain = Chain(_balances())
    chain.block([park_tx(amount=1, seq=0)], height=HEIGHT, ts=TS)
    over = park_tx(amount=2, seq=1)
    result = chain.block([over], height=HEIGHT + 1, ts=TS + 5)
    assert over["tx_id"] not in result.accepted_tx_ids
    assert _admission_verdict(over, HEIGHT + 1, TS + 5, total_open=1) is False


def test_admission_and_apply_agree_on_retract_timing():
    from test_retractable_apply import ALICE, Chain, HEIGHT, TS, _balances, retract_tx, rid_of
    park_tx = _apply_park

    chain = Chain(_balances())
    parked = park_tx(amount=70, seq=0, at_height=HEIGHT + 3)
    chain.block([parked], height=HEIGHT, ts=TS)
    rid = rid_of(parked)
    row = row_for(parse_retractable_transfer(parked))

    for height in (HEIGHT + 1, HEIGHT + 2, HEIGHT + 3, HEIGHT + 4):
        probe = Chain(_balances())
        probe.block([parked], height=HEIGHT, ts=TS)
        tx = retract_tx(rid, seq=1)
        applied = probe.block([tx], height=height, ts=TS + 30)
        retracted = tx["tx_id"] in applied.accepted_tx_ids and not probe.book.open

        view = MagicMock(spec=TipAdmissionView)
        view.next_block_height = height
        view.tip_timestamp = TS
        view.get_retractable.return_value = row
        admitted = validate_retract_transfer_payload(tx, view).is_valid
        assert admitted == retracted, f"height {height}: admission={admitted} apply={retracted}"


# --- registration parity -----------------------------------------------------

def test_both_types_are_known_to_sendtx():
    from commands import sendtx
    assert {"retractable_transfer", "retract_transfer"} <= sendtx.KNOWN_TX_TYPES


def test_only_the_park_bears_a_fee_and_the_two_sets_agree():
    from commands import sendtx
    from consensus import engine
    assert sendtx.FEE_BEARING_TX_TYPES == engine.FEE_BEARING_TX_TYPES
    assert "retractable_transfer" in sendtx.FEE_BEARING_TX_TYPES
    assert "retract_transfer" not in sendtx.FEE_BEARING_TX_TYPES


def test_lanes_route_the_two_types():
    from consensus.lanes import (
        LANE_FAST, TAU_EVALUATING_TX_TYPES, classify_lane)
    assert "retractable_transfer" in TAU_EVALUATING_TX_TYPES
    assert "retract_transfer" not in TAU_EVALUATING_TX_TYPES
    assert classify_lane({"tx_type": "retractable_transfer"}) == LANE_FAST
    assert classify_lane({"tx_type": "retract_transfer"}) == LANE_FAST
