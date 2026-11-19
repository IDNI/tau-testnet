"""Receive routes (#35): book rules, block apply, persistence, RPC and CLI."""
import itertools

from chain_ids import TEST_CHAIN_ID
import json
import types
from datetime import datetime, timezone

import pytest

import chain_state
import db
from commands import getreceiveroute
from consensus import periods
from consensus.grants import parse_grant_create
from consensus.routes import RouteBook, RouteRemove, load_route_book, parse_route_set
from consensus.standing import parse_standing_create
from consensus.tx_signing import signing_message_bytes
from tau_testnet_cli import cli, tx as tx_mod
from tests.test_retractable_apply import (
    ALICE, BOB, CAROL, FAR, MALLORY, PROPOSER, SK_ALICE, SK_BOB, SK_CAROL,
    SK_MALLORY, Chain, _sign,
)

_SEQ = itertools.count()
KEYS = {ALICE: SK_ALICE, BOB: SK_BOB, CAROL: SK_CAROL, MALLORY: SK_MALLORY}


def at(*a):
    return int(datetime(*a, tzinfo=timezone.utc).timestamp())


T0 = at(2026, 11, 20)


def _base(tx_type, sender, seq, fee_limit=100):
    return {"tx_id": f"{tx_type}-{next(_SEQ)}", "tx_type": tx_type,
            "sender_pubkey": sender, "sequence_number": seq,
            "expiration_time": FAR, "expire_at_height": 1000, "chain_id": TEST_CHAIN_ID, "fee_limit": str(fee_limit)}


def route_tx(owner, dest, bps, seq=0, **over):
    tx = _base("receive_route_set", owner, seq)
    tx.update({"destination_pubkey": dest, "bps": bps, "min_incoming": 0,
               "activate_at": 0, "expires_at": 0, "locked_until": 0})
    tx.update(over)
    return _sign(tx, KEYS[owner])


def remove_tx(owner, seq):
    return _sign(_base("receive_route_remove", owner, seq, 0), KEYS[owner])


def send_tx(sender, to, amount, seq):
    return _sign({**_base("user_tx", sender, seq),
                  "operations": {"1": [[sender, to, amount]]}}, KEYS[sender])


# --- block apply -------------------------------------------------------------------


def test_twenty_percent_route_with_floor_rounding():
    ch = Chain({ALICE: 1_000, BOB: 10})
    ch.block([route_tx(BOB, CAROL, 2000)], ts=T0)
    ch.block([send_tx(ALICE, BOB, 101, 0)], ts=T0 + 10)
    assert ch.bal[BOB] == 10 + 81 and ch.bal[CAROL] == 20
    receipt = ch.last.outcomes[0].receipt_logs
    assert any("Receive route: 20 of 101" in log for log in receipt)


def test_sender_cannot_bypass_and_wallet_need_not_be_online():
    ch = Chain({ALICE: 1_000, MALLORY: 1_000, BOB: 10})
    ch.block([route_tx(BOB, CAROL, 5000)], ts=T0)
    ch.block([send_tx(ALICE, BOB, 100, 0), send_tx(MALLORY, BOB, 100, 0)], ts=T0 + 10)
    assert ch.bal[CAROL] == 100 and ch.bal[BOB] == 110


def test_routing_is_single_hop_no_loops():
    ch = Chain({ALICE: 1_000, BOB: 10, CAROL: 10})
    ch.block([route_tx(BOB, CAROL, 5000), route_tx(CAROL, BOB, 5000)], ts=T0)
    ch.block([send_tx(ALICE, BOB, 100, 0)], ts=T0 + 10)
    assert ch.bal[BOB] == 60 and ch.bal[CAROL] == 60
    assert sum(ch.bal.values()) == 1_020


def test_routed_credits_from_standing_payments_and_grant_draws():
    ch = Chain({ALICE: 10_000, BOB: 100, MALLORY: 100})
    ch.block([route_tx(BOB, CAROL, 1000)], ts=T0)
    sp = _sign({**_base("standing_payment_create", ALICE, 0),
                "recipient_pubkey": BOB, "amount": 1000,
                "period_kind": periods.PERIOD_DAY, "period_seconds": 0,
                "start_at": T0, "due_day": 0, "due_offset_seconds": 0,
                "window_seconds": 86_400, "end_at": 0, "max_occurrences": 3}, SK_ALICE)
    sid = parse_standing_create(sp).standing_id.hex()
    ch.block([sp], ts=T0 + 5)
    ex = _sign({**_base("standing_payment_execute", MALLORY, 0),
                "standing_id": sid, "period": T0 // 86_400 + 1}, SK_MALLORY)
    ch.block([ex], ts=T0 + 86_400 + 5)
    assert ch.bal[CAROL] == 100 and ch.bal[BOB] == 100 + 900


def test_excluded_credit_classes_are_not_routed():
    ch = Chain({ALICE: 10_000, BOB: 100})
    ch.block([route_tx(ALICE, CAROL, 5000, seq=0)], ts=T0)
    # Grant refund to Alice at expiry is not routed.
    g = _sign({**_base("grant_create", ALICE, 1), "grantee_pubkey": BOB, "amount": 1000,
               "expires_at": T0 + 3600}, SK_ALICE)
    ch.block([g], ts=T0 + 10)
    ch.block([], ts=T0 + 3600)
    assert ch.bal[ALICE] == 10_000 and ch.bal.get(CAROL, 0) == 0


def test_min_incoming_activation_and_expiry():
    ch = Chain({ALICE: 10_000, BOB: 10})
    ch.block([route_tx(BOB, CAROL, 5000, min_incoming=100,
                       activate_at=T0 + 100, expires_at=T0 + 200)], ts=T0)
    ch.block([send_tx(ALICE, BOB, 500, 0)], ts=T0 + 50)   # not yet active
    ch.block([send_tx(ALICE, BOB, 50, 1)], ts=T0 + 150)   # below min
    ch.block([send_tx(ALICE, BOB, 100, 2)], ts=T0 + 150)  # routed
    ch.block([send_tx(ALICE, BOB, 100, 3)], ts=T0 + 200)  # expired
    assert ch.bal[CAROL] == 50
    assert ch.lm.receive_routes.get(BOB) is None  # swept


def test_locked_route_cannot_be_removed_or_replaced():
    ch = Chain({BOB: 10})
    ch.block([route_tx(BOB, CAROL, 1000, locked_until=T0 + 1000, expires_at=T0 + 5000)], ts=T0)
    ch.block([remove_tx(BOB, 1)], ts=T0 + 10)
    assert ch.last.invalid_tx_ids
    ch.block([route_tx(BOB, MALLORY, 1000, seq=1)], ts=T0 + 20)
    assert ch.last.invalid_tx_ids and ch.lm.receive_routes.get(BOB).destination_pubkey == CAROL
    ch.block([remove_tx(BOB, 1)], ts=T0 + 1000)
    assert ch.lm.receive_routes.get(BOB) is None


@pytest.mark.parametrize("over,needle", [
    ({"destination_pubkey": BOB}, "self-route"),
    ({"bps": 0}, "bps"), ({"bps": 9001}, "bps"),
    ({"locked_until": T0 + 10}, "needs an expiry"),
    ({"locked_until": T0 + 100, "expires_at": T0 + 50}, "locked_until"),
])
def test_invalid_routes_rejected(over, needle):
    tx = {"sender_pubkey": BOB, "destination_pubkey": CAROL, "bps": 2000, "sequence_number": 0}
    tx.update(over)
    ok, reason = RouteBook().can_admit_set(parse_route_set(tx), T0)
    assert not ok and needle in reason


def test_meta_hash_unchanged_until_first_route():
    from consensus.governance import ConsensusLifecycleManager

    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    before = lm.consensus_meta_hash()
    lm.receive_routes.install(parse_route_set(
        {"sender_pubkey": BOB, "destination_pubkey": CAROL, "bps": 1, "sequence_number": 0}))
    assert lm.consensus_meta_hash() != before


# --- persistence, RPC, signing, CLI -------------------------------------------------


def test_persistence_roundtrip_and_tamper(temp_database):
    book = RouteBook()
    book.install(parse_route_set({"sender_pubkey": BOB, "destination_pubkey": CAROL,
                                  "bps": 2000, "sequence_number": 3}))
    lm = types.SimpleNamespace(receive_routes=book)
    db.save_canonical_state_atomically("00" * 32, 1, {}, {}, "", "", "", [], [], [], [],
                                       routes=chain_state._routes_state(lm))
    assert load_route_book(db.load_routes_state()).root() == book.root()
    state = db.load_routes_state()
    state["routes"][0]["bps"] = 10_000
    db.set_chain_state_value("routes_v1", json.dumps(state))
    with pytest.raises(chain_state.DatabaseError):
        chain_state._restore_routes(types.SimpleNamespace())


def test_rpc_reports_route_and_semantics(temp_database):
    book = RouteBook()
    book.install(parse_route_set({"sender_pubkey": BOB, "destination_pubkey": CAROL,
                                  "bps": 2000, "sequence_number": 0}))
    db.set_chain_state_value("routes_v1", json.dumps(book.snapshot()))
    out = json.loads(getreceiveroute.execute(f"getreceiveroute {BOB}", None))
    assert out["data"]["route"]["bps"] == 2000 and out["data"]["route"]["active"]
    assert "floor" in out["data"]["semantics"]["rounding"]
    assert json.loads(getreceiveroute.execute(f"getreceiveroute {ALICE}", None))["data"]["route"] is None


def test_route_terms_are_signed_and_cli_parses():
    base = tx_mod.build_route_set_tx(chain_id=TEST_CHAIN_ID, sender_pubkey=BOB, sequence_number=0, expiration_time=1,
                                     expire_at_height=1, destination_pubkey=CAROL, bps=2000)
    ref = signing_message_bytes(base)
    for k, v in [("destination_pubkey", ALICE), ("bps", 2001), ("min_incoming", 1),
                 ("activate_at", 1), ("expires_at", 9), ("locked_until", 5)]:
        assert signing_message_bytes(dict(base, **{k: v})) != ref, k
    args = cli.build_parser().parse_args(["route", "set", "--key", "bob", "--to", CAROL,
                                          "--share", "12.5"])
    assert args.share == 1250 and args.func is cli.cmd_route_set
