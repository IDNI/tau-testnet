"""Receive routes (issue #35) outside block apply: admission, persistence,
history and the RPC surface.

Admission judges a route change with the same `ReceiveRouteBook` methods block
apply uses, against the persisted book, so the two cannot disagree about what
is installable. The book is bound into the meta hash, so a reload must rebuild
it exactly; the routing history is node-local and filtered to the canonical
chain like the retractable history.
"""
import json
import types
from unittest.mock import MagicMock, patch

import pytest

import chain_state
import db
import tau_defs
from bls_keys import pubkey_hex
from commands import checktx, getaccountstate, getreceiveroute, gettxstatus, sendtx
from consensus.admission import (
    TipAdmissionView,
    validate_mempool_admission,
    validate_receive_route_clear_payload,
    validate_receive_route_set_payload,
    validate_rule_change_request_payload,
)
from consensus.approvals import parse_rule_change_request
from consensus.governance import ConsensusLifecycleManager
from consensus.receive_routes import (
    MAX_LOCK_SECONDS,
    ReceiveRoute,
    ReceiveRouteBook,
    capability,
    parse_route_set,
    parse_route_spec,
    route_spec_text,
)
from errors import DatabaseError

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
C = pubkey_hex(0x3C)
NEXT_HEIGHT = 50
TS = 1_700_000_000
FAR = 9_999_999_999


# --- admission -------------------------------------------------------------------

@pytest.fixture
def tip_view():
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = TS
    view.next_block_timestamp = TS
    view.clause_for.return_value = None
    view.receive_routes_active = True
    view.book = ReceiveRouteBook()
    view.receive_route_book.side_effect = lambda: view.book
    return view


def set_tx(**over):
    tx = {
        "tx_type": "receive_route_set", "sender_pubkey": A, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 20, "fee_limit": "10",
        "destination_pubkey": B, "route_bps": 2000,
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def clear_tx(signer=A, owner=A, **over):
    tx = {
        "tx_type": "receive_route_clear", "sender_pubkey": signer, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 20, "fee_limit": "10",
        "route_owner_pubkey": owner,
    }
    tx.update(over)
    return tx


def test_admission_accepts_a_route_and_reports_what_it_replaces(tip_view):
    result = validate_receive_route_set_payload(set_tx(), tip_view)
    assert result.is_valid
    assert result.data["receive_route"]["bps"] == 2000
    assert result.data["replaces"] is None
    tip_view.book.install(ReceiveRoute(A, C, 100))
    result = validate_receive_route_set_payload(set_tx(), tip_view)
    assert result.data["replaces"]["destination_pubkey"] == C


@pytest.mark.parametrize("over,code", [
    (dict(destination_pubkey=A), "INVALID_RECEIVE_ROUTE"),
    (dict(route_bps=0), "INVALID_RECEIVE_ROUTE"),
    (dict(route_bps=9001), "INVALID_RECEIVE_ROUTE"),
    (dict(route_bps="2000"), "INVALID_RECEIVE_ROUTE"),
    (dict(destination_pubkey="AB" * 48), "INVALID_RECEIVE_ROUTE"),
    (dict(locked=True), "INVALID_RECEIVE_ROUTE"),
    (dict(locked=True, expires_at_time=TS + MAX_LOCK_SECONDS + 1), "INVALID_RECEIVE_ROUTE"),
    (dict(expires_at_time=TS), "INVALID_RECEIVE_ROUTE"),
    (dict(active_from_time=TS + 100, expires_at_time=TS + 100), "INVALID_RECEIVE_ROUTE"),
])
def test_admission_refuses_bad_routes(tip_view, over, code):
    result = validate_receive_route_set_payload(set_tx(**over), tip_view)
    assert not result.is_valid and result.code == code


def test_admission_refuses_every_route_change_until_activation(tip_view):
    tip_view.receive_routes_active = False
    for result in (validate_receive_route_set_payload(set_tx(), tip_view),
                   validate_receive_route_clear_payload(clear_tx(), tip_view)):
        assert not result.is_valid and result.code == "FEATURE_INACTIVE"
    tip_view.get_rule_change_request.return_value = None
    tip_view.open_requests_for_sender.return_value = 0
    parked = validate_rule_change_request_payload(
        request_tx(tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE, route_spec_text(B, 2000)),
        tip_view)
    assert parked.code == "INVALID_RULE_CHANGE_REQUEST" and "not active" in parked.error


def test_the_activation_patch_is_screened_at_admission():
    from consensus.admission import _check_host_contract_patch

    assert _check_host_contract_patch({"receive_routes_active": True}) is None
    assert "receive_routes_active" in _check_host_contract_patch({"receive_routes_active": False})


def test_admission_refuses_to_replace_or_clear_a_locked_route(tip_view):
    tip_view.book.install(ReceiveRoute(A, B, 100, locked=True, expires_at=TS + 10))
    assert validate_receive_route_set_payload(set_tx(destination_pubkey=C), tip_view).code \
        == "RECEIVE_ROUTE_LOCKED"
    assert validate_receive_route_clear_payload(clear_tx(), tip_view).code \
        == "RECEIVE_ROUTE_LOCKED"
    released = validate_receive_route_clear_payload(clear_tx(signer=B), tip_view)
    assert released.is_valid and released.data["cleared_by"] == "destination"
    assert validate_receive_route_clear_payload(clear_tx(signer=C), tip_view).code \
        == "NOT_ROUTE_OWNER"


def test_admission_refuses_to_clear_a_missing_route(tip_view):
    assert validate_receive_route_clear_payload(clear_tx(), tip_view).code \
        == "UNKNOWN_RECEIVE_ROUTE"


def test_admission_consults_the_rule_change_guard(tip_view):
    tip_view.clause_for.side_effect = (
        lambda who, idx: "guard" if idx == tau_defs.RULE_CHANGE_GUARD_INDEX else None
    )
    with patch("consensus.sender_policy.clause_blocks", return_value=(True, "0")):
        assert validate_receive_route_set_payload(set_tx(), tip_view).code \
            == "RULE_CHANGE_NEEDS_APPROVAL"
        tip_view.book.install(ReceiveRoute(A, B, 100))
        assert validate_receive_route_clear_payload(clear_tx(), tip_view).code \
            == "RULE_CHANGE_NEEDS_APPROVAL"
        # The destination releasing its share is not the owner's change.
        assert validate_receive_route_clear_payload(clear_tx(signer=B), tip_view).is_valid


def test_dispatch_routes_both_types_and_requires_a_height_deadline(tip_view):
    assert validate_mempool_admission(set_tx(), tip_view).is_valid
    no_deadline = set_tx()
    del no_deadline["expire_at_height"]
    assert validate_mempool_admission(no_deadline, tip_view).code == "INVALID_PARAMS"


def test_checktx_preview_shows_the_split_a_transfer_would_make(tip_view):
    tip_view.book.install(ReceiveRoute(B, C, 2500))
    preview = sendtx._receive_routing_preview(
        tip_view, "user_tx", [(A, B, 401), (A, C, 5)], {}
    )
    (split,) = preview["splits"]
    assert (split["gross"], split["net"], split["routed"]) == (401, 301, 100)
    assert split["transfer_index"] == 0 and split["routing_fee"] == 0
    assert "floor" in preview["rounding"]
    assert sendtx._receive_routing_preview(tip_view, "user_tx", [(A, C, 5)], {}) is None


def test_an_explicit_null_lock_parses_like_an_absent_one(tip_view):
    tx = set_tx()
    tx["locked"] = None
    assert parse_route_set(tx).locked is False
    assert validate_receive_route_set_payload(tx, tip_view).is_valid


def test_there_is_no_book_wide_cap(tip_view):
    for i in range(20_000):
        key = f"{i:096x}"
        tip_view.book.routes[key] = ReceiveRoute(key, B, 100)
    assert validate_receive_route_set_payload(set_tx(), tip_view).is_valid
    assert "max_routes_total" not in capability()


def test_an_unreadable_book_fails_admission_closed(tip_view):
    tip_view.receive_route_book.side_effect = RuntimeError("database is locked")
    for result in (validate_receive_route_set_payload(set_tx(), tip_view),
                   validate_receive_route_clear_payload(clear_tx(), tip_view)):
        assert not result.is_valid and result.code == "RECEIVE_ROUTE_STATE_UNAVAILABLE"


# --- guarded changes parked as rule_change_request kinds 6 and 7 -----------------

def request_tx(kind, rule_text="", sender=A, **over):
    tx = {
        "tx_type": "rule_change_request", "sender_pubkey": sender, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 2000, "fee_limit": "10",
        "kind": kind, "approvers": {},
    }
    if rule_text:
        tx["rule_text"] = rule_text
    tx.update(over)
    return tx


@pytest.fixture
def request_view(tip_view):
    tip_view.get_rule_change_request.return_value = None
    tip_view.open_requests_for_sender.return_value = 0
    return tip_view


def test_a_route_change_can_be_parked_for_the_guard(request_view):
    set_kind = tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE
    clear_kind = tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE
    parked = validate_rule_change_request_payload(
        request_tx(set_kind, route_spec_text(B, 2000)), request_view)
    assert parked.is_valid, parked.error
    # Nothing to clear yet; then there is.
    assert validate_rule_change_request_payload(
        request_tx(clear_kind), request_view).code == "INVALID_RULE_CHANGE_REQUEST"
    request_view.book.install(ReceiveRoute(A, B, 100))
    assert validate_rule_change_request_payload(request_tx(clear_kind), request_view).is_valid
    # A lock refuses both, exactly as it refuses the direct transactions.
    request_view.book.install(ReceiveRoute(A, B, 100, locked=True, expires_at=TS + 10))
    for tx in (request_tx(set_kind, route_spec_text(C, 2000)), request_tx(clear_kind)):
        result = validate_rule_change_request_payload(tx, request_view)
        assert not result.is_valid and "locked" in result.error


@pytest.mark.parametrize("text", [
    "receive_route_v1 bps=2000",                                   # no destination
    f"receive_route_v1 destination={B}",                           # no bps
    f"receive_route_v1 destination={B} bps=02000",                 # not canonical
    f"receive_route_v1 destination={B} bps=2000 version=1",        # version is the seq
    f"receive_route_v1 destination={B} bps=2000 bps=2000",         # duplicate field
    f"receive_route_v1 destination={B} bps=2000 colour=red",       # unknown field
    f"receive_route_v1 destination={B} bps=2000 locked=yes",
    f"route destination={B} bps=2000",                             # wrong tag
    f"receive_route_v1 destination={A} bps=2000",                  # self-route
    f"receive_route_v1 destination={B} bps=9001",                  # over the cap
])
def test_a_bad_route_spec_is_refused(request_view, text):
    tx = request_tx(tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE, text)
    result = validate_rule_change_request_payload(tx, request_view)
    assert not result.is_valid and result.code == "INVALID_RULE_CHANGE_REQUEST"


def test_the_request_body_binds_the_route_and_its_version():
    set_kind = tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE
    spec = route_spec_text(B, 2000, expires_at_time=TS + 5, locked=True)
    request = parse_rule_change_request(request_tx(set_kind, spec, sequence_number=7))
    assert parse_route_spec(request.body, A) == ReceiveRoute(A, B, 2000, 0, 0, TS + 5, True, 7)
    other = parse_rule_change_request(
        request_tx(set_kind, route_spec_text(B, 2001), sequence_number=7))
    assert other.request_id != request.request_id


def test_the_mempool_view_names_parked_route_requests():
    set_kind = tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE
    clear_kind = tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE
    assert getreceiveroute._names(request_tx(set_kind, route_spec_text(B, 2000))) == {A, B}
    assert getreceiveroute._names(request_tx(clear_kind)) == {A}
    assert getreceiveroute._names(request_tx(1, "always o5[t] = 1.")) == set()


def test_the_mempool_prefilter_reads_only_route_changes(temp_database):
    rows = [
        ("h1", json.dumps(set_tx())),
        ("h2", json.dumps({"tx_type": "user_tx", "sender_pubkey": A})),
        ("h3", json.dumps(request_tx(tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE))),
    ]
    with db._db_lock, db._db_conn:
        for tx_hash, payload in rows:
            db._db_conn.execute(
                "INSERT INTO mempool (tx_hash, payload, received_at) VALUES (?, ?, ?)",
                (tx_hash, payload, 1),
            )
    assert len(db.get_mempool_receive_route_payloads()) == 2


def test_the_tip_view_does_not_read_a_corrupt_book_as_empty(temp_database):
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT INTO receive_routes_v1 (owner_pubkey, destination_pubkey, bps, min_amount, "
            "active_from, expires_at, locked, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (A, A, 2000, 0, 0, 0, 0, 0),
        )
    with pytest.raises(ValueError):
        TipAdmissionView().receive_route_book()


# --- persistence -----------------------------------------------------------------

pytestmark_chain = pytest.mark.usefixtures("isolated_chain_state")


def _seed(lm):
    # A reload takes the faucet from the genesis global, which other test
    # modules leave set; pin it to this manager's value.
    lm.faucet_amount = chain_state._genesis_faucet_amount or 0
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 500})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    return lm


def _reload():
    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


@pytestmark_chain
def test_routes_round_trip_through_a_restart_with_the_same_meta_hash(temp_database):
    lm = _seed(ConsensusLifecycleManager(active_validators=[A]))
    lm.activate_receive_routes()
    lm.receive_routes.install(ReceiveRoute(A, B, 2000, 5, 0, TS + 9, True, 3, TS - 7))
    lm.receive_routes.install(ReceiveRoute(C, A, 1, 0, TS, 0, False, 0))
    meta = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.receive_routes.routes == lm.receive_routes.routes
    assert reloaded.receive_routes_active is True
    assert reloaded.consensus_meta_hash() == meta


@pytestmark_chain
def test_clearing_every_route_empties_the_table(temp_database):
    lm = _seed(ConsensusLifecycleManager(active_validators=[A]))
    lm.receive_routes.install(ReceiveRoute(A, B, 2000))
    chain_state.commit_state_to_db("h1", 1)
    lm.receive_routes.clear(A)
    meta = lm.consensus_meta_hash()
    reloaded = _reload()
    assert reloaded.receive_routes.is_empty()
    assert reloaded.consensus_meta_hash() == meta
    assert db.load_receive_routes() == []


@pytestmark_chain
@pytest.mark.parametrize("row", [
    (A, A, 2000, 0, 0, 0, 0, 0),          # routes to itself
    (A, B, 0, 0, 0, 0, 0, 0),             # bps out of range
    (A, B, 10_000, 0, 0, 0, 0, 0),        # over the cap
    (A, B, 2000, 0, 0, 0, 1, 0),          # locked with no expiry
    ("not-a-key", B, 2000, 0, 0, 0, 0, 0),
])
def test_a_corrupt_stored_route_refuses_to_load(temp_database, row):
    _seed(ConsensusLifecycleManager(active_validators=[A]))
    chain_state.commit_state_to_db("head-hash", 20)
    with db._db_lock, db._db_conn:
        db._db_conn.execute(
            "INSERT INTO receive_routes_v1 (owner_pubkey, destination_pubkey, bps, min_amount, "
            "active_from, expires_at, locked, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", row
        )
    with pytest.raises(DatabaseError, match="corrupt receive route state"):
        chain_state.load_state_from_db()


# --- history -----------------------------------------------------------------------

def _block_row(conn, block_hash, number, previous):
    conn.execute(
        "INSERT INTO blocks (block_hash, block_number, previous_hash, timestamp, block_data) "
        "VALUES (?, ?, ?, ?, ?)",
        (block_hash, number, previous, TS + number, "{}"),
    )


def _fork():
    conn = db._db_conn
    with conn:
        _block_row(conn, "g0", 0, "")
        _block_row(conn, "a1", 1, "g0")
        _block_row(conn, "b1", 1, "g0")


def _head(block_hash, number):
    db.set_chain_state_value("canonical_head_hash", block_hash)
    db.set_chain_state_value("canonical_head_number", str(number))


def _split(gross, routed, tx_hash):
    return {
        "kind": "split", "tx_index": 0, "tx_hash": tx_hash, "source": "transfer",
        "recipient_pubkey": A, "destination_pubkey": B, "gross": gross,
        "net": gross - routed, "routed": routed, "bps": 2000, "route_version": 1,
        "credit_class": "transfer", "fee_charged": 3, "routing_fee": 0,
    }


def test_history_is_filtered_to_the_canonical_chain(temp_database):
    _fork()
    db.record_receive_route_events("a1", 1, [_split(100, 20, "t" * 64)])
    db.record_receive_route_events("b1", 1, [_split(50, 10, "u" * 64)])
    db.record_receive_route_events("a1", 1, [_split(100, 20, "t" * 64)])  # idempotent
    _head("a1", 1)
    (event,) = db.get_canonical_receive_route_events(A)
    assert event["gross"] == 100 and event["block_hash"] == "a1"
    assert db.get_canonical_receive_route_events(B) == [event]
    _head("b1", 1)
    assert [e["gross"] for e in db.get_canonical_receive_route_events(A)] == [50]
    assert db.get_canonical_receive_route_events(C) == []


def test_history_pages_past_non_canonical_rows(temp_database):
    _fork()
    db.record_receive_route_events("b1", 1, [_split(50, 10, "u" * 64) for _ in range(80)])
    db.record_receive_route_events("a1", 1, [_split(100, 20, "t" * 64) for _ in range(5)])
    _head("a1", 1)
    events = db.get_canonical_receive_route_events(A, limit=5)
    assert [e["block_hash"] for e in events] == ["a1"] * 5


def test_chain_state_records_block_events_with_their_tx_hash(temp_database):
    block = types.SimpleNamespace(
        block_hash="a1", tx_ids=["t" * 64],
        header=types.SimpleNamespace(block_number=1),
    )
    snapshot = types.SimpleNamespace(metadata={"receive_route_events": [
        dict(_split(10, 2, None), tx_index=0),
        {"kind": "cleared", "tx_index": None, "cleared_by": "expiry",
         "owner_pubkey": A, "destination_pubkey": B},
    ]})
    chain_state._record_receive_route_events(block, snapshot)
    stored = db.get_receive_route_events_for_tx("t" * 64, "a1")
    assert [e["kind"] for e in stored] == ["split"]
    assert stored[0]["routed"] == 2


# --- RPC -----------------------------------------------------------------------------

@pytest.fixture()
def container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def call(module, line, container):
    return json.loads(module.execute(line, container))


def test_capability_reports_support_classes_rounding_and_fees(temp_database, container):
    out = call(getreceiveroute, "getreceiveroute capability", container)
    caps = out["data"]["capability"] if "data" in out else out["result"]["capability"]
    assert caps == capability()
    assert caps["supported"] is True
    assert caps["credit_classes_routed"] == ["transfer", "claimed_payment"]
    assert "faucet_grant" in caps["credit_classes_excluded"]
    assert caps["rounding"] == "floor" and caps["routing_fee"] == 0
    assert caps["max_bps"] < caps["bps_denominator"]


def _data(out):
    return out.get("data", out.get("result"))


def test_getreceiveroute_shows_route_inbound_routes_and_history(temp_database, container):
    db.save_canonical_state_atomically(
        "head", 0, {}, {}, "", "", "", [], [], [], [],
        receive_routes=[
            {"owner_pubkey": A, "destination_pubkey": B, "bps": 2000, "min_amount": 0,
             "active_from": 0, "expires_at": 0, "locked": False, "version": 4},
            {"owner_pubkey": C, "destination_pubkey": A, "bps": 100, "min_amount": 0,
             "active_from": 0, "expires_at": 0, "locked": False, "version": 0},
        ],
    )
    _fork()
    db.record_receive_route_events("a1", 1, [_split(100, 20, "t" * 64)])
    _head("a1", 1)
    data = _data(call(getreceiveroute, f"getreceiveroute {A}", container))
    assert data["route"]["destination_pubkey"] == B and data["route"]["status"] == "active"
    assert [r["owner_pubkey"] for r in data["routes_to_this_address"]] == [C]
    assert data["history"][0]["routed"] == 20
    assert data["capability"]["supported"] is True
    nobody = _data(call(getreceiveroute, f"getreceiveroute {'e' * 96}", container))
    assert nobody["route"] is None


def test_getreceiveroute_rejects_bad_params(temp_database, container):
    for line in ("getreceiveroute", "getreceiveroute xyz", f"getreceiveroute {A} 0"):
        out = call(getreceiveroute, line, container)
        assert out.get("ok") is False or out.get("status") == "error" or "error" in out


def test_gettxstatus_lists_the_splits_of_a_confirmed_transaction(temp_database):
    db.record_receive_route_events("blk", 3, [
        _split(100, 20, "t" * 64),
        {"kind": "installed", "tx_hash": "v" * 64, "owner_pubkey": A,
         "destination_pubkey": B, "bps": 2000},
    ])
    fields = gettxstatus._receive_route_fields(db, "t" * 64, "blk")
    assert fields["receive_routes"][0]["net"] == 80
    assert "receive_route_change" not in fields
    change = gettxstatus._receive_route_fields(db, "v" * 64, "blk")
    assert change["receive_route_change"]["kind"] == "installed"


# --- sendtx end to end ---------------------------------------------------------------

from unittest.mock import PropertyMock  # noqa: E402

from bls_keys import SK_ALICE, SK_BOB, sign_payload  # noqa: E402

SENDER = pubkey_hex(SK_ALICE)
OWNER = pubkey_hex(SK_BOB)


@pytest.fixture
def node(temp_database, monkeypatch):
    script = {"fee": 0, "calls": []}

    def multi(**kwargs):
        script["calls"].append(kwargs)
        vals = kwargs.get("input_stream_values") or {}
        return {1: str(vals.get(1, "0")), 5: "1", 8: "0", 9: str(script["fee"])}

    patches = [
        patch("tau_manager.tau_ready"),
        patch("tau_manager.communicate_with_tau", return_value="x1001"),
        patch("tau_manager.communicate_with_tau_multi", side_effect=multi),
        patch("commands.sendtx.chain_state.get_sequence_number", return_value=1),
        patch.dict("os.environ", {"TAU_FORCE_TEST": "0"}),
        patch.object(TipAdmissionView, "next_block_height",
                     new_callable=PropertyMock, return_value=NEXT_HEIGHT),
        patch.object(TipAdmissionView, "tip_timestamp",
                     new_callable=PropertyMock, return_value=TS),
        patch.object(TipAdmissionView, "next_block_timestamp",
                     new_callable=PropertyMock, return_value=TS),
        patch.object(TipAdmissionView, "receive_routes_active",
                     new_callable=PropertyMock, return_value=True),
    ]
    mocks = [p.start() for p in patches]
    mocks[0].is_set.return_value = True
    monkeypatch.setitem(chain_state._balances, SENDER, 1_000_000)
    monkeypatch.setitem(chain_state._balances, OWNER, 1_000)
    yield script
    for p in reversed(patches):
        p.stop()


def _queue(payload, **kw):
    return sendtx.queue_transaction(json.dumps(payload), propagate=False, **kw)


def _install_rows(*routes):
    db.save_canonical_state_atomically(
        "head", 0, {}, {}, "", "", "", [], [], [], [],
        receive_routes=ReceiveRouteBook.restore(
            [r.as_row() for r in routes]
        ).snapshot_rows(),
    )


def test_a_route_install_is_queued_with_its_fee(node):
    node["fee"] = 4
    payload = sign_payload(set_tx(sender_pubkey=OWNER, destination_pubkey=SENDER), SK_BOB)
    result = _queue(payload)
    assert result["ok"], result
    with db._db_lock:
        row = db._db_conn.execute("SELECT estimated_fee FROM mempool").fetchone()
    assert row[0] == 4


def test_a_route_install_dry_run_echoes_the_change(node):
    payload = sign_payload(set_tx(sender_pubkey=OWNER, destination_pubkey=SENDER), SK_BOB)
    result = _queue(payload, dry_run=True, skip_tau_eval=True)
    assert result["ok"], result
    change = result["receive_routing"]["change"]
    assert change["receive_route"]["destination_pubkey"] == SENDER
    assert result["receive_routing"]["capability"]["rounding"] == "floor"


def test_a_self_route_is_refused_at_sendtx(node):
    payload = sign_payload(set_tx(sender_pubkey=OWNER, destination_pubkey=OWNER), SK_BOB)
    result = _queue(payload)
    assert result["ok"] is False and result["code"] == "INVALID_RECEIVE_ROUTE"


def test_checktx_on_a_transfer_previews_the_recipients_route(node, container):
    _install_rows(ReceiveRoute(OWNER, C, 2000))
    tx = sign_payload({
        "tx_type": "user_tx", "sender_pubkey": SENDER, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 20, "fee_limit": "10",
        "operations": {"1": [[SENDER, OWNER, "101"]]},
    }, SK_ALICE)
    out = json.loads(checktx.execute("checktx " + json.dumps(tx), container))
    data = _data(out)
    (split,) = data["receive_routing"]["splits"]
    assert (split["gross"], split["net"], split["routed"]) == (101, 81, 20)
    assert split["destination_pubkey"] == C


def test_getaccountstate_shows_the_route(node, container):
    _install_rows(ReceiveRoute(OWNER, C, 2000, locked=True, expires_at=TS + 50))
    data = _data(json.loads(getaccountstate.execute(f"getaccountstate {OWNER}", container)))
    assert data["receive_route"]["locked"] is True
    assert data["receive_route"]["status"] == "active"


def test_a_table_from_an_earlier_build_gains_the_install_time_column(tmp_path):
    import sqlite3

    import config

    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE receive_routes_v1 (owner_pubkey TEXT PRIMARY KEY, "
        "destination_pubkey TEXT NOT NULL, bps INTEGER NOT NULL, "
        "min_amount INTEGER NOT NULL DEFAULT 0, active_from INTEGER NOT NULL DEFAULT 0, "
        "expires_at INTEGER NOT NULL DEFAULT 0, locked INTEGER NOT NULL DEFAULT 0, "
        "version INTEGER NOT NULL DEFAULT 0)"
    )
    conn.execute("INSERT INTO receive_routes_v1 VALUES (?, ?, 2000, 0, 0, 0, 0, 1)", (A, B))
    conn.commit()
    conn.close()

    original = config.STRING_DB_PATH
    if db._db_conn is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(str(path))
    try:
        db.init_db()
        assert db.load_receive_routes() == [(A, B, 2000, 0, 0, 0, False, 1, 0)]
    finally:
        if db._db_conn is not None:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(original)
