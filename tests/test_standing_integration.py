"""Standing payments outside block apply: admission, signing, the meta hash,
persistence, RPC, gossip and the idle-chain wake.

The admission tests end with a shared corpus judged by BOTH the admission
validator and the book apply consults: they must accept and reject the same
authorizations, or a proposer and the mempool disagree about what can land.
"""
import json
import types
from unittest.mock import MagicMock

import pytest

import chain_state
import db
from commands import getstandingpayment, getstandingpayments, gettxstatus
from consensus.admission import (
    TipAdmissionView,
    validate_mempool_admission,
    validate_standing_payment_cancel_payload,
    validate_standing_payment_create_payload,
    validate_standing_payment_execute_payload,
    validate_standing_payment_update_payload,
)
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.lanes import LANE_FAST, TAU_EVALUATING_TX_TYPES, classify_lane
from consensus.network_binding import chain_genesis_hash
from consensus.standing import (
    ATTEMPT_NO_FUNDS,
    ATTEMPT_PAID,
    MIN_INTERVAL_BLOCKS,
    StandingBook,
    parse_standing_payment_create,
)
from consensus.tx_checks import apply_tx_error
from consensus.tx_signing import signing_message_bytes
from errors import DatabaseError
from network.service import _SNAPSHOT_TX_TYPES, NetworkService

from bls_keys import pubkey_hex

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
C = pubkey_hex(0x3C)
NEXT_HEIGHT = 50
TIP_TS = 1_767_225_600
FAR = 9_999_999_999
KEY = "standing_payments_root"


def create(**over):
    tx = {
        "tx_type": "standing_payment_create",
        "genesis_hash": chain_genesis_hash(),
        "sender_pubkey": A,
        "sequence_number": 1,
        "expiration_time": FAR,
        "expire_at_height": NEXT_HEIGHT + 5,
        "fee_limit": "10",
        "recipient_pubkey": B,
        "amount": 100,
        "interval_blocks": MIN_INTERVAL_BLOCKS,
        "first_due": NEXT_HEIGHT + 10,
        "periods": 12,
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def monthly_create(**over):
    over.setdefault("interval_blocks", None)
    over.setdefault("interval_months", 1)
    over.setdefault("first_due", TIP_TS + 86_400)
    over.setdefault("expiration_time", TIP_TS + 600)
    return create(**over)


def cancel(sid_hex, signer=A):
    return {
        "tx_type": "standing_payment_cancel", "genesis_hash": chain_genesis_hash(),
        "sender_pubkey": signer, "sequence_number": 2,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "0",
        "standing_id": sid_hex,
    }


@pytest.fixture
def book():
    return StandingBook()


@pytest.fixture
def tip_view(book):
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = TIP_TS
    view.next_block_timestamp = TIP_TS
    view.standing_book.return_value = book
    return view


# --- admission ------------------------------------------------------------------

def test_a_valid_create_is_admitted_with_its_id_and_end(tip_view):
    tx = create()
    result = validate_standing_payment_create_payload(tx, tip_view)
    assert result.is_valid, result.error
    terms = parse_standing_payment_create(tx)
    assert result.data["standing_id"] == terms.standing_id.hex()
    assert result.data["end"] == NEXT_HEIGHT + 10 + 12 * MIN_INTERVAL_BLOCKS
    assert result.data["schedule"] == "blocks"


@pytest.mark.parametrize("over,code", [
    ({"interval_blocks": 5}, "INVALID_SCHEDULE"),
    ({"first_due": NEXT_HEIGHT}, "INVALID_SCHEDULE"),
    ({"recipient_pubkey": A}, "INVALID_SCHEDULE"),
    ({"expire_at_height": NEXT_HEIGHT + 11}, "DEADLINE_AFTER_FIRST_DUE"),
    ({"recipient_pubkey": "ab" * 48}, "TX_REJECTED"),   # not a curve point
    ({"interval_seconds": 3_600}, "TX_REJECTED"),        # two intervals
])
def test_admission_refusals_carry_a_code(tip_view, over, code):
    result = validate_standing_payment_create_payload(create(**over), tip_view)
    assert not result.is_valid and result.code == code, result.error


def test_a_time_schedule_must_be_mined_before_its_first_due_time(tip_view):
    ok = validate_standing_payment_create_payload(monthly_create(), tip_view)
    assert ok.is_valid, ok.error
    late = validate_standing_payment_create_payload(
        monthly_create(expiration_time=TIP_TS + 86_400), tip_view)
    assert late.code == "DEADLINE_AFTER_FIRST_DUE"


def test_duplicates_and_limits(tip_view, book):
    tx = create()
    book.create(parse_standing_payment_create(tx))
    assert validate_standing_payment_create_payload(tx, tip_view).code == \
        "DUPLICATE_STANDING_PAYMENT"
    for seq in range(2, 17):
        book.create(parse_standing_payment_create(create(sequence_number=seq)))
    assert validate_standing_payment_create_payload(
        create(sequence_number=99), tip_view).code == "TOO_MANY_STANDING_PAYMENTS"


def test_cancel_admission(tip_view, book):
    sid = book.create(parse_standing_payment_create(create())).hex()
    assert validate_standing_payment_cancel_payload(cancel(sid), tip_view).is_valid
    assert validate_standing_payment_cancel_payload(cancel(sid, signer=B), tip_view).code == \
        "NOT_STANDING_PAYER"
    assert validate_standing_payment_cancel_payload(cancel("00" * 32), tip_view).code == \
        "UNKNOWN_STANDING_PAYMENT"


def test_the_dispatcher_routes_both_types(tip_view):
    assert validate_mempool_admission(create(), tip_view).is_valid
    assert validate_mempool_admission(cancel("00" * 32), tip_view).code == \
        "UNKNOWN_STANDING_PAYMENT"


CORPUS = [
    create(),
    create(amount=0),
    create(periods=0),
    create(periods=1_201),
    create(interval_blocks=MIN_INTERVAL_BLOCKS - 1),
    create(first_due=NEXT_HEIGHT),
    create(first_due=NEXT_HEIGHT + 100_001),
    create(recipient_pubkey=A),
    monthly_create(),
    monthly_create(interval_months=13),
    monthly_create(first_due=TIP_TS),
    monthly_create(periods=1_200, interval_months=12),
]


@pytest.mark.parametrize("tx", CORPUS)
def test_admission_and_apply_agree_on_every_create(tip_view, tx):
    admitted = validate_standing_payment_create_payload(tx, tip_view)
    terms = parse_standing_payment_create(tx)
    applied, _reason = StandingBook().can_admit_create(terms, NEXT_HEIGHT, TIP_TS)
    assert admitted.is_valid == applied, (admitted.error, _reason)


# --- signing and shared checks -----------------------------------------------------

@pytest.mark.parametrize("field,value", [
    ("recipient_pubkey", C), ("amount", 101), ("interval_blocks", 129),
    ("first_due", NEXT_HEIGHT + 11), ("periods", 13), ("interval_seconds", 3_600),
    ("interval_months", 1), ("fee_limit", "11"), ("expire_at_height", NEXT_HEIGHT + 6),
])
def test_every_term_is_in_the_signed_bytes(field, value):
    base = signing_message_bytes(create())
    assert signing_message_bytes(create(**{field: value})) != base


def test_the_cancel_id_is_signed():
    assert signing_message_bytes(cancel("00" * 32)) != signing_message_bytes(cancel("11" * 32))


def test_apply_refuses_a_recipient_that_is_not_a_key():
    reason, _detail = apply_tx_error(create(recipient_pubkey="ab" * 48))
    assert reason == "invalid_recipient_key"
    assert apply_tx_error(create()) is None


def test_lanes_and_tau_needs():
    assert classify_lane(create()) == LANE_FAST
    assert classify_lane(cancel("00" * 32)) == LANE_FAST
    assert "standing_payment_create" in TAU_EVALUATING_TX_TYPES
    assert "standing_payment_cancel" not in TAU_EVALUATING_TX_TYPES


def test_engine_and_admission_agree_on_who_pays_a_fee():
    from commands import sendtx
    from consensus import engine

    assert engine.FEE_BEARING_TX_TYPES == sendtx.FEE_BEARING_TX_TYPES
    assert "standing_payment_create" in sendtx.FEE_BEARING_TX_TYPES
    assert "standing_payment_cancel" not in sendtx.FEE_BEARING_TX_TYPES
    assert {"standing_payment_create", "standing_payment_cancel"} <= sendtx.KNOWN_TX_TYPES


# --- the meta hash ------------------------------------------------------------------

def test_an_unused_book_leaves_the_meta_hash_as_it_was():
    lm = ConsensusLifecycleManager()
    assert KEY not in build_mechanism_metadata("supermajority")
    before = lm.consensus_meta_hash()
    lm.standing_payments = StandingBook()
    assert lm.consensus_meta_hash() == before


def test_the_book_is_bound_once_used_and_stays_bound():
    lm = ConsensusLifecycleManager()
    empty = lm.consensus_meta_hash()
    sid = lm.standing_payments.create(parse_standing_payment_create(create()))
    opened = lm.consensus_meta_hash()
    assert opened != empty
    lm.standing_payments.cancel(sid)
    closed = lm.consensus_meta_hash()
    assert closed not in (empty, opened)


def test_progress_alone_moves_the_meta_hash():
    lm = ConsensusLifecycleManager()
    lm.standing_payments.create(parse_standing_payment_create(create()))
    before = lm.consensus_meta_hash()
    lm.standing_payments.sweep(NEXT_HEIGHT + 10, TIP_TS, lambda t: ATTEMPT_NO_FUNDS)
    assert lm.consensus_meta_hash() != before


# --- persistence --------------------------------------------------------------------

def _seed():
    lm = ConsensusLifecycleManager(active_validators=[A])
    # Run on the loaded genesis, as the restarted node will: other modules may
    # leave a genesis faucet grant or slot flag set, and a restart reads both.
    lm.faucet_amount = chain_state._genesis_faucet_amount
    if chain_state._genesis_approval_slots_active:
        lm.activate_approval_slots()
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 500, B: 7})
    chain_state._sequence_numbers.update({A: 3})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    book = lm.standing_payments
    first = book.create(parse_standing_payment_create(create(sequence_number=1)))
    book.create(parse_standing_payment_create(create(sequence_number=2)))
    book.create(parse_standing_payment_create(monthly_create(sequence_number=3)))
    book.sweep(NEXT_HEIGHT + 10, TIP_TS, lambda t: ATTEMPT_NO_FUNDS, cap=1)
    book.cancel(first)
    return lm


def _reload():
    chain_state.commit_state_to_db("head-hash", 60)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_book_round_trips_with_its_queue_and_history(temp_database):
    lm = _seed()
    meta = lm.consensus_meta_hash()
    book = lm.standing_payments
    reloaded = _reload().standing_payments
    assert reloaded.rows() == book.rows()
    assert reloaded.resolved_state() == book.resolved_state()
    assert reloaded._queue == book._queue and reloaded._fresh == book._fresh
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


@pytest.mark.usefixtures("isolated_chain_state")
@pytest.mark.parametrize("column,value", [
    ("amount", 101), ("first_due", 61), ("period", 3), ("tries", 1),
])
def test_a_tampered_row_refuses_to_load(temp_database, column, value):
    _seed()
    chain_state.commit_state_to_db("head-hash", 60)
    with db._db_conn as conn:
        conn.execute(f"UPDATE standing_payments_v1 SET {column} = ? WHERE queued_at = 0",
                     (value,))
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="standing"):
        chain_state.load_state_from_db()


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_wake_hint_reads_the_persisted_book(temp_database):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    lm.standing_payments.create(parse_standing_payment_create(create()))
    chain_state.commit_state_to_db("head-hash", 40)
    assert not db.has_due_standing_payments(NEXT_HEIGHT + 9, TIP_TS)
    assert db.has_due_standing_payments(NEXT_HEIGHT + 10, TIP_TS)
    lm.standing_payments.sweep(NEXT_HEIGHT + 10, TIP_TS, lambda t: ATTEMPT_NO_FUNDS)
    chain_state.commit_state_to_db("head-hash-2", 41)
    assert not db.has_due_standing_payments(NEXT_HEIGHT + 11, TIP_TS)  # a retry sleeps


# --- RPC ------------------------------------------------------------------------------

@pytest.fixture
def container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def call(module, line, container):
    return json.loads(module.execute(line, container))


@pytest.mark.usefixtures("isolated_chain_state")
def test_getstandingpayments_lists_by_role_with_semantics(temp_database, container):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    out_sid = lm.standing_payments.create(parse_standing_payment_create(create()))
    in_sid = lm.standing_payments.create(parse_standing_payment_create(
        create(sender_pubkey=C, recipient_pubkey=A)))
    every = call(getstandingpayments, f"getstandingpayments {A}", container)["data"]
    assert {r["standing_id"] for r in every["payments"]} == {out_sid.hex(), in_sid.hex()}
    outs = call(getstandingpayments, f"getstandingpayments {A} out", container)["data"]
    assert [r["standing_id"] for r in outs["payments"]] == [out_sid.hex()]
    row = outs["payments"][0]
    assert row["status"] == "waiting" and row["period_due"] == NEXT_HEIGHT + 10
    sem = every["semantics"]
    assert sem["schedules"]["months"]["missing_day"] == "last day of the month"
    assert sem["limits"]["actions_per_block"] == 32 and sem["reserved_funds"] == "none"


@pytest.mark.usefixtures("isolated_chain_state")
def test_getstandingpayment_open_then_ended(temp_database, container, monkeypatch):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    sid = lm.standing_payments.create(parse_standing_payment_create(create(periods=1)))
    resp = call(getstandingpayment, f"getstandingpayment {sid.hex()}", container)
    assert resp["data"]["status"] == "waiting" and resp["data"]["history"] == []

    events = lm.standing_payments.sweep(NEXT_HEIGHT + 10, TIP_TS, lambda t: ATTEMPT_PAID)
    assert [e["outcome"] for e in events] == ["paid", "ended"]
    db.record_standing_events("blk", NEXT_HEIGHT + 10, events)
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (h == "blk", 1))
    ended = call(getstandingpayment, f"getstandingpayment {sid.hex()}", container)["data"]
    assert ended["status"] == "ended" and ended["resolved_at_height"] == NEXT_HEIGHT + 10
    assert [e["outcome"] for e in ended["history"]] == ["ended", "paid"]
    assert ended["history"][1]["amount"] == 100

    # A fork that is not canonical leaves no trace.
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (False, 0))
    unknown = call(getstandingpayment, f"getstandingpayment {sid.hex()}", container)
    assert unknown["error"]["code"] == "STANDING_PAYMENT_UNKNOWN"


def test_bad_rpc_arguments(container):
    assert call(getstandingpayments, "getstandingpayments", container)["error"]["code"] == \
        "INVALID_PARAMS"
    assert call(getstandingpayments, f"getstandingpayments {A} sideways", container)["error"][
        "code"] == "INVALID_PARAMS"
    assert call(getstandingpayment, "getstandingpayment xyz", container)["error"]["code"] == \
        "INVALID_PARAMS"


# --- gossip ---------------------------------------------------------------------------

def test_gossip_routes_and_snapshots_both_types():
    assert NetworkService.topic_for_tx_type("standing_payment_create") == "tau/standing/1.0.0"
    assert NetworkService.topic_for_tx_type("standing_payment_cancel") == "tau/standing/1.0.0"
    assert {"standing_payment_create", "standing_payment_cancel"} <= _SNAPSHOT_TX_TYPES


# --- gettxstatus ----------------------------------------------------------------------

@pytest.mark.usefixtures("isolated_chain_state")
def test_gettxstatus_names_the_authorization_and_its_state(temp_database):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    tx = create()
    sid = lm.standing_payments.create(parse_standing_payment_create(tx)).hex()
    assert gettxstatus._standing_fields(tx) == {"standing": {"id": sid, "status": "waiting"}}
    assert gettxstatus._standing_fields(cancel(sid)) == {"cancels": sid}
    lm.standing_payments.cancel(bytes.fromhex(sid))
    assert gettxstatus._standing_fields(tx)["standing"]["status"] == "not_recorded"



# --- execute and update: admission, parity, wiring ----------------------------------

def execute(sid_hex, signer=C, **over):
    tx = {
        "tx_type": "standing_payment_execute", "genesis_hash": chain_genesis_hash(),
        "sender_pubkey": signer, "sequence_number": 0,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
        "standing_id": sid_hex,
    }
    tx.update(over)
    return tx


def update(sid_hex, **over):
    tx = create(sequence_number=2, amount=150, standing_id=sid_hex)
    tx["tx_type"] = "standing_payment_update"
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


@pytest.fixture
def funded(monkeypatch, tip_view):
    """The tip as admission reads it: balances, and no clause unless a test sets one."""
    balances = {A: 1_000, B: 0, C: 5}
    monkeypatch.setattr(chain_state, "get_balance", lambda who: balances.get(who, 0))
    tip_view.clause_for.return_value = None
    tip_view.approval_slots_active = True
    return balances


def _due_book(book, **over):
    """An entry whose first period opens at the next block."""
    return book.create(parse_standing_payment_create(create(first_due=NEXT_HEIGHT, **over)))


def test_execute_admission_reports_the_period_it_would_pay(tip_view, book, funded):
    sid = _due_book(book)
    result = validate_standing_payment_execute_payload(execute(sid.hex()), tip_view)
    assert result.is_valid, result.error
    assert result.data == {"standing_id": sid.hex(), "period": 0, "amount": 100,
                           "payer_pubkey": A, "recipient_pubkey": B}


def test_execute_admission_refusals_carry_a_code(tip_view, book, funded):
    early = book.create(parse_standing_payment_create(create()))
    due = _due_book(book, sequence_number=7)
    assert validate_standing_payment_execute_payload(execute(early.hex()), tip_view).code == \
        "STANDING_PAYMENT_NOT_DUE"
    assert validate_standing_payment_execute_payload(execute("00" * 32), tip_view).code == \
        "UNKNOWN_STANDING_PAYMENT"
    funded[A] = 99
    assert validate_standing_payment_execute_payload(execute(due.hex()), tip_view).code == \
        "STANDING_PAYMENT_UNFUNDED"
    funded[A] = 1_000
    book.execute(due, NEXT_HEIGHT, TIP_TS, C)
    assert validate_standing_payment_execute_payload(execute(due.hex()), tip_view).code == \
        "STANDING_PAYMENT_NOT_DUE"
    bad = execute(due.hex(), sender_pubkey=A)
    assert not validate_standing_payment_execute_payload(
        {**bad, "standing_id": "XY"}, tip_view).is_valid


def test_execute_admission_runs_the_payers_clause(tip_view, book, funded, monkeypatch):
    from consensus import sender_policy

    sid = _due_book(book)
    tip_view.clause_for.side_effect = lambda who, idx: "clause" if (who, idx) == (A, 5) else None
    seen = []

    def blocks(body, values, *, pool, timeout=None):
        seen.append((body, dict(values), pool))
        return True, "0"

    monkeypatch.setattr(sender_policy, "clause_blocks", blocks)
    result = validate_standing_payment_execute_payload(execute(sid.hex()), tip_view)
    assert result.code == "STANDING_PAYMENT_BLOCKED"
    body, values, pool = seen[0]
    assert (body, pool) == ("clause", "admission")
    assert values[1] == "100" and B in values[4] and A in values[3] and values[5] == str(TIP_TS)


def test_update_admission(tip_view, book):
    old = book.create(parse_standing_payment_create(create()))
    result = validate_standing_payment_update_payload(update(old.hex()), tip_view)
    assert result.is_valid, result.error
    new_terms = parse_standing_payment_create(update(old.hex()))
    assert result.data["standing_id"] == new_terms.standing_id.hex()
    assert result.data["replaces"] == old.hex() and result.data["version"] == 2
    codes = {
        "unknown": update("00" * 32),
        "not_payer": update(old.hex(), sender_pubkey=C),
        "schedule": update(old.hex(), first_due=NEXT_HEIGHT),
        "deadline": update(old.hex(), expire_at_height=NEXT_HEIGHT + 11),
        "key": update(old.hex(), recipient_pubkey="ab" * 48),
    }
    got = {k: validate_standing_payment_update_payload(tx, tip_view).code
           for k, tx in codes.items()}
    assert got == {"unknown": "UNKNOWN_STANDING_PAYMENT", "not_payer": "NOT_STANDING_PAYER",
                   "schedule": "INVALID_SCHEDULE", "deadline": "DEADLINE_AFTER_FIRST_DUE",
                   "key": "TX_REJECTED"}


def test_the_dispatcher_routes_execute_and_update(tip_view, funded):
    assert validate_mempool_admission(execute("00" * 32), tip_view).code == \
        "UNKNOWN_STANDING_PAYMENT"
    assert validate_mempool_admission(update("00" * 32), tip_view).code == \
        "UNKNOWN_STANDING_PAYMENT"


UPDATE_CORPUS = [
    {},
    {"amount": 0},
    {"periods": 0},
    {"interval_blocks": MIN_INTERVAL_BLOCKS - 1},
    {"first_due": NEXT_HEIGHT},
    {"first_due": NEXT_HEIGHT + 100_001},
    {"recipient_pubkey": A},
    {"sender_pubkey": C},
    {"standing_id": "00" * 32},
    {"sequence_number": 1, "amount": 100},     # the very terms it replaces
]


@pytest.mark.parametrize("over", UPDATE_CORPUS)
def test_admission_and_apply_agree_on_every_update(tip_view, book, over):
    old = book.create(parse_standing_payment_create(create()))
    tx = update(old.hex(), **over)
    admitted = validate_standing_payment_update_payload(tx, tip_view)
    from consensus.standing import parse_standing_payment_update
    sid, terms = parse_standing_payment_update(tx)
    applied, why = book.can_admit_update(sid, tx["sender_pubkey"], terms, NEXT_HEIGHT, TIP_TS)
    assert admitted.is_valid == applied, (admitted.error, why)


@pytest.mark.parametrize("height_offset,settled", [
    (-1, False), (0, False), (MIN_INTERVAL_BLOCKS - 1, False), (0, True),
    (MIN_INTERVAL_BLOCKS, False), (12 * MIN_INTERVAL_BLOCKS, False),
])
def test_admission_and_apply_agree_on_when_an_execute_may_pay(
        tip_view, book, funded, height_offset, settled):
    sid = book.create(parse_standing_payment_create(create()))   # first due NEXT_HEIGHT + 10
    height = NEXT_HEIGHT + 10 + height_offset
    if settled:
        book.execute(sid, height, TIP_TS, C)
    tip_view.next_block_height = height
    admitted = validate_standing_payment_execute_payload(execute(sid.hex()), tip_view)
    period, why = book.payable_period(sid, height, TIP_TS)
    assert admitted.is_valid == (period >= 0), (admitted.error, why)


def test_execute_signs_only_its_id_and_update_signs_the_id_and_every_term():
    base = signing_message_bytes(execute("00" * 32))
    assert signing_message_bytes(execute("11" * 32)) != base
    # Unsigned extras change nothing: an executor cannot name an amount.
    assert signing_message_bytes(execute("00" * 32, amount=5, recipient_pubkey=B)) == base
    up = signing_message_bytes(update("00" * 32))
    for field, value in (("standing_id", "11" * 32), ("amount", 151), ("recipient_pubkey", C),
                         ("first_due", NEXT_HEIGHT + 11), ("periods", 13),
                         ("interval_blocks", 129), ("interval_months", 1)):
        assert signing_message_bytes(update("00" * 32, **{field: value})) != up, field


def test_execute_and_update_lanes_fees_and_checks():
    from commands import sendtx
    from consensus import engine

    assert classify_lane(execute("00" * 32)) == LANE_FAST
    assert classify_lane(update("00" * 32)) == LANE_FAST
    assert {"standing_payment_execute", "standing_payment_update"} <= TAU_EVALUATING_TX_TYPES
    assert {"standing_payment_execute", "standing_payment_update"} <= sendtx.FEE_BEARING_TX_TYPES
    assert engine.FEE_BEARING_TX_TYPES == sendtx.FEE_BEARING_TX_TYPES
    assert {"standing_payment_execute", "standing_payment_update"} <= sendtx.KNOWN_TX_TYPES
    reason, _detail = apply_tx_error(update("00" * 32, recipient_pubkey="ab" * 48))
    assert reason == "invalid_recipient_key"


def test_gossip_routes_and_snapshots_all_four_types():
    for tx_type in ("standing_payment_create", "standing_payment_cancel",
                    "standing_payment_update", "standing_payment_execute"):
        assert NetworkService.topic_for_tx_type(tx_type) == "tau/standing/1.0.0"
        assert tx_type in _SNAPSHOT_TX_TYPES


@pytest.mark.usefixtures("isolated_chain_state")
def test_a_replaced_version_round_trips_and_tampering_its_lineage_refuses_to_load(temp_database):
    lm = _seed()
    book = lm.standing_payments
    old = next(sid for sid in sorted(book.terms) if book.progress[sid].queued_at == 0)
    new, _ = book.update(old, parse_standing_payment_create(create(sequence_number=9)))
    meta = lm.consensus_meta_hash()
    reloaded = _reload().standing_payments
    assert reloaded.rows() == book.rows() and reloaded.version_of(new) == (2, old)
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta
    with db._db_conn as conn:
        conn.execute("UPDATE standing_payments_v1 SET version = 3 WHERE standing_id = ?",
                     (new.hex(),))
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    # Version 3 with a valid predecessor still loads, but no longer hashes the same.
    assert chain_state.load_state_from_db() is True
    assert chain_state._lifecycle_manager.consensus_meta_hash() != meta
    with db._db_conn as conn:
        conn.execute("UPDATE standing_payments_v1 SET replaces = '' WHERE standing_id = ?",
                     (new.hex(),))
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="standing"):
        chain_state.load_state_from_db()


@pytest.mark.usefixtures("isolated_chain_state")
def test_getstandingpayment_follows_a_replaced_version(temp_database, container, monkeypatch):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    old = lm.standing_payments.create(parse_standing_payment_create(create()))
    new, events = lm.standing_payments.update(
        old, parse_standing_payment_create(create(sequence_number=2, amount=150)))
    db.record_standing_events("blk", NEXT_HEIGHT, events)
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (True, 1))
    gone = call(getstandingpayment, f"getstandingpayment {old.hex()}", container)["data"]
    assert gone["status"] == "replaced" and gone["replaced_by"] == new.hex()
    now = call(getstandingpayment, f"getstandingpayment {new.hex()}", container)["data"]
    assert now["version"] == 2 and now["replaces"] == old.hex()
    assert [e["outcome"] for e in now["history"]] == ["created"]
    sem = call(getstandingpayments, f"getstandingpayments {A}", container)["data"]["semantics"]
    assert set(sem["tx_types"]) == {"standing_payment_create", "standing_payment_cancel",
                                    "standing_payment_update", "standing_payment_execute"}
    assert sem["limits"]["executes_per_block"] == 32 and "anyone" in sem["paid_by"]


@pytest.mark.usefixtures("isolated_chain_state")
def test_gettxstatus_for_execute_and_update(temp_database, monkeypatch):
    lm = ConsensusLifecycleManager(active_validators=[A])
    chain_state._lifecycle_manager = lm
    old = lm.standing_payments.create(parse_standing_payment_create(create(first_due=NEXT_HEIGHT)))
    paid = lm.standing_payments.execute(old, NEXT_HEIGHT, TIP_TS, C)
    db.record_standing_events("blk", NEXT_HEIGHT, paid)
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (True, 1))
    assert gettxstatus._standing_fields(execute(old.hex()), "blk") == {
        "executes": old.hex(), "standing_payment": {"period": 0, "amount": 100}}
    assert gettxstatus._standing_fields(execute(old.hex()), "other") == {"executes": old.hex()}
    up = update(old.hex())
    new, _ = lm.standing_payments.update(old, parse_standing_payment_create(up))
    assert gettxstatus._standing_fields(up) == {
        "standing": {"id": new.hex(), "status": "waiting", "replaces": old.hex()}}
