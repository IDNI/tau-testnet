"""Receive routes outside block apply: admission, signing, the meta hash,
persistence, RPC (the capability report and history), the pre-send preview,
gossip, the command line and the book's own invariants.

The admission tests end with a corpus judged by BOTH the admission validator and
the book apply consults: they must accept and reject the same routes, or a
proposer and the mempool disagree about what can land.
"""
import json
import types
from fractions import Fraction
from unittest.mock import MagicMock

import pytest

import chain_state
import db
import tau_defs
from commands import checktx, getreceiveroute, gettxstatus, sendtx
from consensus.admission import (
    TipAdmissionView,
    validate_mempool_admission,
    validate_receive_route_release_payload,
    validate_receive_route_remove_payload,
    validate_receive_route_set_payload,
)
from consensus.governance import ConsensusLifecycleManager, build_mechanism_metadata
from consensus.lanes import LANE_FAST, TAU_EVALUATING_TX_TYPES, classify_lane
from consensus.receive_route import (
    MAX_RECEIVE_ROUTES_TOTAL,
    MAX_SHARE_BPS,
    ROUTED_CLASSES,
    ReceiveRouteBook,
    RouteShapeError,
    RouteTerms,
    parse_receive_route_release,
    parse_receive_route_set,
    parse_route_spec,
    preview_credits,
    route_spec_text,
    strengthens,
)
from consensus.network_binding import chain_genesis_hash
from consensus.tx_checks import apply_tx_error
from consensus.tx_signing import signing_message_bytes
from errors import DatabaseError
from network.service import _SNAPSHOT_TX_TYPES, NetworkService

from bls_keys import pubkey_hex

A = pubkey_hex(0x1A)
B = pubkey_hex(0x2B)
C = pubkey_hex(0x3C)
NEXT_HEIGHT = 50
TS = 1_767_225_600
FAR = 9_999_999_999
KEY = "receive_routes_root"


def route_set(**over):
    tx = {
        "tx_type": "receive_route_set", "sender_pubkey": A, "sequence_number": 1,
        "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "10",
        "destination_pubkey": B, "share_bps": 2000, "genesis_hash": chain_genesis_hash(),
    }
    tx.update(over)
    return {k: v for k, v in tx.items() if v is not None}


def remove(signer=A):
    return {"tx_type": "receive_route_remove", "sender_pubkey": signer, "sequence_number": 2,
            "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "0",
            "genesis_hash": chain_genesis_hash()}


def release(route_id, signer=B, owner=A):
    return {"tx_type": "receive_route_release", "sender_pubkey": signer, "sequence_number": 0,
            "expiration_time": FAR, "expire_at_height": NEXT_HEIGHT + 5, "fee_limit": "0",
            "owner_pubkey": owner, "route_id": route_id, "genesis_hash": chain_genesis_hash()}


@pytest.fixture
def book():
    return ReceiveRouteBook()


@pytest.fixture
def tip_view(book):
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = NEXT_HEIGHT
    view.tip_timestamp = TS
    view.next_block_timestamp = TS
    view.route_book.return_value = book
    view.clause_for.return_value = None
    return view


def _installed(book, **over):
    terms = parse_receive_route_set(route_set(**over))
    book.install(terms)
    return terms


# --- the split itself ----------------------------------------------------------------

@pytest.mark.parametrize("bps", [1, 333, 2000, 5000, 8999, MAX_SHARE_BPS])
def test_the_split_is_the_floor_of_the_exact_share(bps):
    terms = RouteTerms(A, 0, B, bps)
    for gross in list(range(0, 400)) + [10**6 + 7, tau_defs.MAX_TRANSFER_VALUE]:
        routed = terms.share_of(gross)
        assert routed == int(Fraction(gross * bps, 10_000)) if gross > 0 else routed == 0
        assert 0 <= routed < max(gross, 1) or gross == 0
        assert gross - routed >= (gross + 9) // 10   # the owner keeps at least a tenth


def test_the_issue_example():
    assert RouteTerms(A, 0, B, 2000).share_of(101) == 20


def test_the_minimum_is_inclusive():
    terms = RouteTerms(A, 0, B, 5000, min_amount=10)
    assert (terms.share_of(9), terms.share_of(10)) == (0, 5)


@pytest.mark.parametrize("start, end, ts, active", [
    (0, 0, TS, True), (TS, 0, TS, True), (TS + 1, 0, TS, False),
    (0, TS + 1, TS, True), (0, TS, TS, False), (TS - 5, TS + 5, TS + 4, True),
])
def test_the_active_window_is_half_open(start, end, ts, active):
    terms = RouteTerms(A, 0, B, 100, active_from=start, expires_at=end)
    assert terms.is_active(ts) is active
    book = ReceiveRouteBook()
    book.install(terms)
    assert (book.split(A, 1000, ts)[1] == 10) is active


# --- parsing, specs and ids ----------------------------------------------------------

@pytest.mark.parametrize("over, why", [
    ({"destination_pubkey": "xyz"}, "destination_pubkey"),
    ({"share_bps": None}, "share_bps"),
    ({"share_bps": "20"}, "share_bps"),
    ({"share_bps": -1}, "share_bps"),
    ({"min_amount": -1}, "min_amount"),
    ({"active_from": 1.5}, "active_from"),
    ({"expires_at": 2**64}, "expires_at"),
    ({"locked": 1}, "locked"),
])
def test_malformed_routes(over, why):
    with pytest.raises(RouteShapeError, match=why):
        parse_receive_route_set(route_set(**over))


def test_every_term_changes_the_route_id():
    base = parse_receive_route_set(route_set()).route_id
    for over in ({"sequence_number": 2}, {"destination_pubkey": C}, {"share_bps": 2001},
                 {"min_amount": 1}, {"active_from": 1}, {"expires_at": TS + 9},
                 {"locked": True, "expires_at": TS + 9}, {"sender_pubkey": C}):
        assert parse_receive_route_set(route_set(**over)).route_id != base, over


def test_spec_text_round_trips_and_must_be_canonical():
    terms = parse_receive_route_set(route_set(min_amount=5, locked=True, expires_at=TS + 9))
    text = route_spec_text(route_set(min_amount=5, locked=True, expires_at=TS + 9))
    assert parse_route_spec(text, A, 1) == terms
    stored = route_spec_text(json.loads(text), 1)
    assert parse_route_spec(stored, A) == terms
    with pytest.raises(RouteShapeError, match="exactly one sequence"):
        parse_route_spec(stored, A, 1)
    with pytest.raises(RouteShapeError, match="canonical"):
        parse_route_spec(text.replace(":", ": "), A, 1)
    assert "locked" not in route_spec_text(route_set(locked=False))


def test_a_release_names_owner_and_route():
    signer, owner, rid = parse_receive_route_release(release("ab" * 32))
    assert (signer, owner, rid) == (B, A, bytes.fromhex("ab" * 32))
    with pytest.raises(RouteShapeError, match="route_id"):
        parse_receive_route_release(release("AB" * 32))


# --- admission -------------------------------------------------------------------------

def test_a_valid_route_is_admitted_with_its_id(tip_view):
    result = validate_receive_route_set_payload(route_set(), tip_view)
    assert result.is_valid, result.error
    assert result.data["route_id"] == parse_receive_route_set(route_set()).route_id.hex()
    assert result.data["example"] == {"gross": 101, "routed": 20, "net": 81}


@pytest.mark.parametrize("over, code", [
    ({"destination_pubkey": A}, "INVALID_RECEIVE_ROUTE"),
    ({"destination_pubkey": "ab" * 48}, "INVALID_RECEIVE_ROUTE"),
    ({"share_bps": 9001}, "INVALID_RECEIVE_ROUTE"),
    ({"share_bps": 10001}, "INVALID_RECEIVE_ROUTE"),
    ({"locked": True}, "INVALID_RECEIVE_ROUTE"),
])
def test_route_refusals_carry_a_code(tip_view, over, code):
    assert validate_receive_route_set_payload(route_set(**over), tip_view).code == code


def test_a_guard_refuses_a_direct_change(tip_view):
    from consensus import sender_policy
    from consensus.policy_mock import MockPolicyEvaluator

    guard = "(o5[t]:bv[24] = { #x000000 }:bv[24])"
    tip_view.clause_for.side_effect = lambda who, idx: (
        guard if idx == tau_defs.RULE_CHANGE_GUARD_INDEX else None)
    mock = MockPolicyEvaluator(pool="admission")
    mock.set_verdict(guard, 0)
    sender_policy.set_evaluator("admission", mock)
    try:
        assert validate_receive_route_set_payload(route_set(), tip_view).code == \
            "RULE_CHANGE_NEEDS_APPROVAL"
        assert mock.verdict_calls[0][1]["i1"] == str(tau_defs.RULE_CHANGE_KIND_SET_ROUTE)
        _installed(tip_view.route_book())
        assert validate_receive_route_remove_payload(remove(), tip_view).code == \
            "RULE_CHANGE_NEEDS_APPROVAL"
        assert mock.verdict_calls[-1][1]["i1"] == str(tau_defs.RULE_CHANGE_KIND_REMOVE_ROUTE)
        terms = tip_view.route_book().get(A)
        assert validate_receive_route_release_payload(
            release(terms.route_id.hex()), tip_view).is_valid
    finally:
        sender_policy.set_evaluator("admission", None)


def test_loop_full_locked_and_duplicate(tip_view, book, monkeypatch):
    book.install(RouteTerms(B, 0, A, 100))
    assert validate_receive_route_set_payload(route_set(), tip_view).code == \
        "INVALID_RECEIVE_ROUTE"
    book.remove(B)
    terms = _installed(book, locked=True, expires_at=TS + 100)
    assert validate_receive_route_set_payload(
        route_set(sequence_number=2), tip_view).code == "RECEIVE_ROUTE_LOCKED"
    assert book.can_admit_set(terms, TS)[1] == "this route is already installed"
    assert validate_receive_route_remove_payload(remove(), tip_view).code == \
        "RECEIVE_ROUTE_LOCKED"
    book.release(A)
    import consensus.receive_route as rr
    monkeypatch.setattr(rr, "MAX_RECEIVE_ROUTES_TOTAL", 0)
    assert validate_receive_route_set_payload(route_set(), tip_view).code == \
        "RECEIVE_ROUTE_BOOK_FULL"


def test_remove_and_release_admission(tip_view, book):
    assert validate_receive_route_remove_payload(remove(), tip_view).code == "NO_RECEIVE_ROUTE"
    terms = _installed(book)
    assert validate_receive_route_remove_payload(remove(), tip_view).is_valid
    assert validate_receive_route_release_payload(
        release("00" * 32), tip_view).code == "STALE_ROUTE_ID"
    assert validate_receive_route_release_payload(
        release(terms.route_id.hex(), signer=C), tip_view).code == "NOT_ROUTE_DESTINATION"
    assert validate_receive_route_release_payload(
        release(terms.route_id.hex()), tip_view).is_valid


def test_the_dispatcher_routes_all_three_types(tip_view, book):
    assert validate_mempool_admission(route_set(), tip_view).is_valid
    terms = _installed(book)
    assert validate_mempool_admission(remove(), tip_view).is_valid
    assert validate_mempool_admission(release(terms.route_id.hex()), tip_view).is_valid


CORPUS = [
    route_set(),
    route_set(destination_pubkey=A),
    route_set(share_bps=0), route_set(share_bps=1), route_set(share_bps=9000),
    route_set(share_bps=9001),
    route_set(min_amount=tau_defs.MAX_TRANSFER_VALUE),
    route_set(min_amount=tau_defs.MAX_TRANSFER_VALUE + 1),
    route_set(active_from=TS + 31_622_400), route_set(active_from=TS + 31_622_401),
    route_set(expires_at=TS), route_set(expires_at=TS + 1),
    route_set(expires_at=TS + 4 * 31_622_400), route_set(expires_at=TS + 4 * 31_622_400 + 1),
    route_set(active_from=TS + 10, expires_at=TS + 10),
    route_set(locked=True), route_set(locked=True, expires_at=TS + 31_622_400),
    route_set(locked=True, expires_at=TS + 31_622_401),
]


@pytest.mark.parametrize("tx", CORPUS)
def test_admission_and_apply_agree_on_every_route(tip_view, tx):
    admitted = validate_receive_route_set_payload(tx, tip_view)
    applied, reason = ReceiveRouteBook().can_admit_set(parse_receive_route_set(tx), TS)
    assert admitted.is_valid == applied, (admitted.error, reason)


# --- signing and shared checks ---------------------------------------------------------

@pytest.mark.parametrize("field, value", [
    ("destination_pubkey", C), ("share_bps", 2001), ("min_amount", 1), ("active_from", 1),
    ("expires_at", 7), ("locked", True), ("locked", False), ("fee_limit", "11"),
])
def test_every_term_of_a_route_is_signed(field, value):
    assert signing_message_bytes(route_set(**{field: value})) != signing_message_bytes(route_set())


@pytest.mark.parametrize("field, value", [("owner_pubkey", C), ("route_id", "11" * 32)])
def test_every_part_of_a_release_is_signed(field, value):
    base = release("00" * 32)
    assert signing_message_bytes({**base, field: value}) != signing_message_bytes(base)


def test_apply_refuses_keys_that_are_not_keys():
    assert apply_tx_error(route_set(destination_pubkey="ab" * 48))[0] == "invalid_recipient_key"
    assert apply_tx_error(release("00" * 32, owner="ab" * 48))[0] == "invalid_recipient_key"
    assert apply_tx_error(route_set()) is None and apply_tx_error(release("00" * 32)) is None


def test_lanes_tau_needs_and_fees():
    from consensus import engine

    for tx in (route_set(), remove(), release("00" * 32)):
        assert classify_lane(tx) == LANE_FAST
    assert "receive_route_set" in TAU_EVALUATING_TX_TYPES
    assert not {"receive_route_remove", "receive_route_release"} & TAU_EVALUATING_TX_TYPES
    assert engine.FEE_BEARING_TX_TYPES == sendtx.FEE_BEARING_TX_TYPES
    assert "receive_route_set" in sendtx.FEE_BEARING_TX_TYPES
    assert not {"receive_route_remove", "receive_route_release"} & sendtx.FEE_BEARING_TX_TYPES
    assert {"receive_route_set", "receive_route_remove",
            "receive_route_release"} <= sendtx.KNOWN_TX_TYPES


# --- the book and the meta hash ---------------------------------------------------------

def test_an_unused_book_leaves_the_meta_hash_as_it_was():
    lm = ConsensusLifecycleManager()
    assert KEY not in build_mechanism_metadata("supermajority")
    before = lm.consensus_meta_hash()
    lm.receive_routes = ReceiveRouteBook()
    assert lm.consensus_meta_hash() == before


def test_the_book_is_bound_once_used_and_stays_bound():
    lm = ConsensusLifecycleManager()
    empty = lm.consensus_meta_hash()
    _installed(lm.receive_routes)
    opened = lm.consensus_meta_hash()
    lm.receive_routes.remove(A)
    removed = lm.consensus_meta_hash()
    assert len({empty, opened, removed}) == 3


def test_a_copy_does_not_leak_into_its_original(book):
    import copy

    _installed(book, expires_at=TS + 9)
    clone = copy.deepcopy(book)
    clone.remove(A)
    assert book.get(A) is not None and book._expiry and not clone._expiry
    assert book.root() != clone.root()


def test_expiry_removes_in_order_and_only_routes_with_an_end(book):
    _installed(book, expires_at=TS + 9)
    _installed(book, sender_pubkey=C, expires_at=TS + 5)
    _installed(book, sender_pubkey=B, destination_pubkey=C)
    assert not book.has_expiring(TS + 4)
    gone = book.expire(TS + 9)
    assert [t.owner_pubkey for t in gone] == [C, A]
    assert book.get(B) is not None and not book._expiry


@pytest.mark.parametrize("change, ok", [
    ({}, True), ({"share_bps": 2500}, True), ({"expires_at": TS + 200}, True),
    ({"min_amount": 0}, True), ({"active_from": 0}, True),
    ({"share_bps": 1999}, False), ({"destination_pubkey": C}, False),
    ({"expires_at": TS + 99}, False), ({"locked": False}, False),
    ({"min_amount": 6}, False), ({"active_from": TS + 51}, False),
])
def test_what_strengthens_a_locked_route(change, ok):
    fields = dict(sender_pubkey=A, sequence_number=0, destination_pubkey=B, share_bps=2000,
                  min_amount=5, active_from=TS + 50, expires_at=TS + 100, locked=True)
    old = parse_receive_route_set(route_set(**fields))
    new = parse_receive_route_set(route_set(**{**fields, "sequence_number": 1, **change}))
    assert strengthens(old, new, TS) is ok


# --- persistence --------------------------------------------------------------------------

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
    book = lm.receive_routes
    _installed(book, min_amount=3, active_from=TS - 5, expires_at=TS + 600, locked=True)
    _installed(book, sender_pubkey=C, destination_pubkey=B, share_bps=50)
    _installed(book, sender_pubkey=B, destination_pubkey=C)
    book.remove(B)
    return lm


def _reload():
    chain_state.commit_state_to_db("head-hash", 60)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


@pytest.mark.usefixtures("isolated_chain_state")
def test_the_book_round_trips(temp_database):
    """Acceptance 7, the restore half: a node that restarts holds the same routes
    and the same commitment."""
    lm = _seed()
    meta = lm.consensus_meta_hash()
    book = lm.receive_routes
    reloaded = _reload().receive_routes
    assert reloaded.store_rows() == book.store_rows()
    assert reloaded.resolved_state() == book.resolved_state()
    assert reloaded._expiry == book._expiry
    assert chain_state._lifecycle_manager.consensus_meta_hash() == meta


@pytest.mark.usefixtures("isolated_chain_state")
@pytest.mark.parametrize("column, value", [
    ("share_bps", 2001), ("expires_at", TS + 601), ("locked", 0),
    ("destination_pubkey", A),
])
def test_a_tampered_row_refuses_to_load(temp_database, column, value):
    _seed()
    chain_state.commit_state_to_db("head-hash", 60)
    with db._db_conn as conn:
        conn.execute(f"UPDATE receive_routes_v1 SET {column} = ? WHERE owner_pubkey = ?",
                     (value, A))
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="receive route"):
        chain_state.load_state_from_db()


def test_restore_refuses_impossible_terms():
    good = RouteTerms(A, 0, B, 100)
    row = (good.route_id, A, 0, B, 100, 0, 0, 0, False)
    assert ReceiveRouteBook.restore([row], 0, bytes(32)).get(A) == good
    with pytest.raises(ValueError, match="two stored"):
        ReceiveRouteBook.restore([row, row], 0, bytes(32))
    for bad in (RouteTerms(A, 0, A, 100), RouteTerms(A, 0, B, 9001),
                RouteTerms(A, 0, B, 100, locked=True)):
        with pytest.raises(ValueError, match="impossible"):
            ReceiveRouteBook.restore([(bad.route_id, A, 0, bad.destination_pubkey,
                                       bad.share_bps, 0, 0, 0, bad.locked)], 0, bytes(32))


# --- RPC: the capability report, history, tx status ---------------------------------------

@pytest.fixture
def container():
    return types.SimpleNamespace(db=db, chain_state=chain_state)


def call(module, line, container):
    return json.loads(module.execute(line, container))


def test_the_capability_report():
    """Acceptance 8: support, credit classes, rounding and fee semantics."""
    sem = getreceiveroute.semantics()
    assert sem["supported"] is True and sem["version"] == 1
    assert sem["routed_credit_classes"] == list(ROUTED_CLASSES)
    assert set(sem["unrouted_credit_classes"]) == {
        "retract_refund", "faucet_grant", "fee", "routed_share"}
    assert sem["rounding"].startswith("routed = floor(gross * share_bps / 10000)")
    assert "no fee of its own" in sem["fees"]
    assert sem["share_bps_max"] == MAX_SHARE_BPS
    assert sem["limits"]["routes_total"] == MAX_RECEIVE_ROUTES_TOTAL
    assert sem["fee_by_tx_type"]["receive_route_remove"] == "fee-free"


@pytest.mark.usefixtures("isolated_chain_state")
def test_getreceiveroute_shows_routes_both_ways_and_history(temp_database, container,
                                                            monkeypatch):
    """Acceptance 6: gross, net and routed are in the history, both ways."""
    lm = ConsensusLifecycleManager(active_validators=[A])
    terms = _installed(lm.receive_routes)
    monkeypatch.setattr(getreceiveroute, "_tip", lambda: ("head", lm.receive_routes))
    rid = terms.route_id.hex()
    db.record_route_events("blk", NEXT_HEIGHT, [
        {"outcome": "installed", "owner_pubkey": A, "destination_pubkey": B,
         "route_id": rid, "tx_id": "t1"},
        {"outcome": "routed", "owner_pubkey": A, "destination_pubkey": B, "route_id": rid,
         "credit_class": "transfer", "gross": 101, "routed": 20, "net": 81,
         "payer_pubkey": C, "tx_id": "t2"},
    ])
    db.record_route_events("blk2", NEXT_HEIGHT + 1, [
        {"outcome": "removed", "owner_pubkey": A, "destination_pubkey": B,
         "route_id": rid, "tx_id": "t3"}])
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (h == "blk", 1))
    data = call(getreceiveroute, f"getreceiveroute {A}", container)["data"]
    assert data["installed"] is True
    assert data["route"]["share_percent"] == 20.0 and data["route"]["status"] == "active"
    assert [e["outcome"] for e in data["history"]] == ["routed", "installed"]
    assert {k: data["history"][0][k] for k in ("gross", "routed", "net")} == \
        {"gross": 101, "routed": 20, "net": 81}
    into_b = call(getreceiveroute, f"getreceiveroute {B}", container)["data"]
    assert into_b["installed"] is False
    assert [r["owner_pubkey"] for r in into_b["routes_in"]] == [A]
    assert [e["outcome"] for e in into_b["history_in"]] == ["routed", "installed"]


def test_bad_rpc_arguments(container):
    assert call(getreceiveroute, "getreceiveroute", container)["error"]["code"] == \
        "INVALID_PARAMS"
    assert call(getreceiveroute, "getreceiveroute xyz", container)["error"]["code"] == \
        "INVALID_PARAMS"


@pytest.mark.usefixtures("isolated_chain_state")
def test_gettxstatus_shows_the_split_and_the_route_change(temp_database, monkeypatch):
    rid = "ab" * 32
    db.record_route_events("blk", 9, [
        {"outcome": "installed", "owner_pubkey": A, "destination_pubkey": B,
         "route_id": rid, "tx_id": "h1"},
        {"outcome": "routed", "owner_pubkey": A, "destination_pubkey": B, "route_id": rid,
         "credit_class": "transfer", "gross": 50, "routed": 10, "net": 40,
         "payer_pubkey": C, "tx_id": "h2"},
        {"outcome": "routed", "owner_pubkey": A, "destination_pubkey": B, "route_id": rid,
         "credit_class": "transfer", "gross": 5, "routed": 1, "net": 4,
         "payer_pubkey": C, "tx_id": "h2"},
    ])
    db.record_route_events("blk2", 10, [
        {"outcome": "released", "owner_pubkey": A, "destination_pubkey": B,
         "route_id": rid, "tx_id": "h3"}])
    monkeypatch.setattr(db, "get_canonical_confirmation", lambda h, n: (True, 1))
    paid = gettxstatus._route_fields(db, "h2", "blk")["receive_routes"]
    assert [(e["gross"], e["routed"], e["net"]) for e in paid] == [(50, 10, 40), (5, 1, 4)]
    assert gettxstatus._route_fields(db, "h1", "blk")["receive_routes"][0]["status"] == \
        "released"
    assert gettxstatus._route_fields(db, "zz", "blk") == {}


def test_history_events_keep_their_payment_source():
    block = types.SimpleNamespace(tx_ids=["h0", "h1"])
    event = {"outcome": "routed", "tx_id": "1", "gross": 3}
    assert chain_state._with_tx_hash(block, event)["tx_id"] == "h1"
    released = {"outcome": "routed", "retractable_id": "ff" * 32}
    assert "tx_id" not in chain_state._with_tx_hash(block, released)


# --- the preview a payer sees before sending ------------------------------------------------

def test_the_preview_splits_what_a_transaction_would_pay():
    book = ReceiveRouteBook()
    book.install(RouteTerms(B, 0, C, 2000))
    pay = {"tx_type": "user_tx", "operations": {"1": [[A, B, "101"], [A, C, 7]]}}
    assert preview_credits(pay, book, TS) == [{
        "recipient_pubkey": B, "credit_class": "transfer", "gross": 101, "routed": 20,
        "net": 81, "destination_pubkey": C, "route_id": book.get(B).route_id.hex(),
        "route_status": "active"}]
    later = preview_credits({"tx_type": "retractable_transfer", "recipient_pubkey": B,
                             "amount": 50}, book, TS)
    assert later[0]["lands_later"] is True and later[0]["routed"] == 10
    assert preview_credits({"tx_type": "user_tx", "operations": {"1": [[A, C, 9]]}},
                           book, TS) == []
    book.install(RouteTerms(B, 1, C, 2000, active_from=TS + 9))
    scheduled = preview_credits(pay, book, TS)
    assert scheduled[0]["routed"] == 0 and scheduled[0]["route_status"] == "scheduled"


def test_sendtx_and_checktx_hand_the_preview_back(monkeypatch):
    preview = [{"recipient_pubkey": B, "gross": 101, "routed": 20, "net": 81}]
    monkeypatch.setattr(sendtx, "queue_transaction",
                        lambda *a, **k: {"ok": True, "tx_hash": "h", "tx_type": "user_tx",
                                         "receive_routes": preview})
    sent = json.loads(sendtx.execute("sendtx {}", None))
    assert sent["data"]["receive_routes"] == preview
    checked = json.loads(checktx.execute("checktx {}", None))
    assert checked["data"]["receive_routes"] == preview


# --- gossip and the command line ------------------------------------------------------------

def test_gossip_routes_and_snapshots_all_three_types():
    for t in ("receive_route_set", "receive_route_remove", "receive_route_release"):
        assert NetworkService.topic_for_tx_type(t) == "tau/routes/1.0.0"
        assert t in _SNAPSHOT_TX_TYPES


def test_the_cli_builders_make_what_the_node_parses():
    from tau_testnet_cli import tx as tx_mod

    built = tx_mod.build_receive_route_set_tx(
        sender_pubkey=A, sequence_number=1, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, destination_pubkey=B.upper(), share_bps=2000,
        expires_at=TS + 100, locked=True)
    terms = parse_receive_route_set(built)
    assert (terms.destination_pubkey, terms.locked, terms.min_amount) == (B, True, 0)
    assert "min_amount" not in built and "active_from" not in built
    with pytest.raises(ValueError, match="locked route needs an end"):
        tx_mod.build_receive_route_set_tx(
            sender_pubkey=A, sequence_number=1, expiration_time=FAR,
            expire_at_height=NEXT_HEIGHT + 5, destination_pubkey=B, share_bps=1, locked=True)
    rel = tx_mod.build_receive_route_release_tx(
        sender_pubkey=B, sequence_number=0, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, owner_pubkey=A, route_id=terms.route_id.hex())
    assert parse_receive_route_release(rel)[1:] == (A, terms.route_id)
    req = tx_mod.build_rule_change_request_tx(
        sender_pubkey=A, sequence_number=4, expiration_time=FAR,
        expire_at_height=NEXT_HEIGHT + 5, kind=8, rule_text=route_spec_text(built))
    assert json.loads(req["rule_text"]) == {"destination_pubkey": B, "expires_at": TS + 100,
                                            "locked": True, "share_bps": 2000}
    with pytest.raises(ValueError, match="no rule text"):
        tx_mod.build_rule_change_request_tx(
            sender_pubkey=A, sequence_number=4, expiration_time=FAR,
            expire_at_height=NEXT_HEIGHT + 5, kind=9, rule_text="x")


def test_the_cli_parses_the_route_commands():
    from tau_testnet_cli.cli import _share_bps, build_parser

    parser = build_parser()
    args = parser.parse_args(["route", "set", "--key", "k", "--to", B, "--share", "12.5",
                              "--ends-in", "3600", "--locked", "--request",
                              "--approver", f"18={C}"])
    assert _share_bps(args) == 1250 and args.locked and args.request
    args = parser.parse_args(["route", "set", "--key", "k", "--to", B, "--share-bps", "7"])
    assert _share_bps(args) == 7
    args = parser.parse_args(["route", "set", "--key", "k", "--to", B, "--share", "0.001"])
    with pytest.raises(Exception, match="two decimals"):
        _share_bps(args)
    assert parser.parse_args(["route", "release", "--key", "k", "--owner", A]).owner == A
    assert parser.parse_args(["route", "show", A]).address == A
    assert parser.parse_args(["route", "remove", "--key", "k"]).request is False


def test_route_remove_without_fee_sends_fee_limit_0_and_asks_for_no_estimate(monkeypatch):
    """A fee-exempt type gets no estimate from the node, so the CLI must not ask
    for one (it used to fail with "give the fee limit with --fee")."""
    from tau_testnet_cli import cli
    from tau_testnet_cli import tx as tx_mod

    def no_estimate(*_a, **_k):
        raise RuntimeError("no estimated_fee for a fee-exempt type")

    sent = []
    monkeypatch.setattr(tx_mod, "get_sequence_tip_and_network",
                        lambda *_a, **_k: (3, 100, chain_genesis_hash()))
    monkeypatch.setattr(tx_mod, "estimate_fee", no_estimate)
    monkeypatch.setattr(tx_mod, "submit_tx", lambda payload, **_k: sent.append(payload)
                        or '{"status": "ok", "data": {"tx_hash": "ab"}}')
    args = cli.build_parser().parse_args(["route", "remove", "--privkey", "1"])
    assert args.func(args) == cli.EXIT_OK
    assert [(t["tx_type"], t["fee_limit"]) for t in sent] == [("receive_route_remove", "0")]
    assert sent[0]["genesis_hash"] == chain_genesis_hash()
