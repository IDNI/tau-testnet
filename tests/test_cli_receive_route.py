"""Tests for `tau-testnet route ...` (issue #35), on the canned-response harness."""
from __future__ import annotations

import json

import pytest

import tau_defs
from consensus.approvals import parse_rule_change_request
from consensus.receive_routes import parse_route_clear, parse_route_set, parse_route_spec
from consensus.tx_signing import verify_tx_signature
from tau_testnet_cli import tx as tx_mod
from test_cli_retractable import TIP, _ok, _run_cli, _send, _sent_payload, alice  # noqa: F401

OTHER = "bb" * 48
THIRD = "cc" * 48


def test_route_set_signs_a_route_with_percent_and_options(alice):
    rc, out, err, recorded = _send([
        "route", "set", "--key", "alice", "--to", OTHER, "--percent", "12.5",
        "--min-amount", "10", "--expires-at-time", "1900000000", "--locked",
    ])
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert verify_tx_signature(payload) == (True, "")
    route = parse_route_set(payload)
    assert (route.owner_pubkey, route.destination_pubkey) == (alice, OTHER)
    assert (route.bps, route.min_amount, route.expires_at, route.locked) == \
        (1250, 10, 1_900_000_000, True)
    assert payload["fee_limit"] == "13"


def test_route_clear_defaults_to_your_own_route(alice):
    rc, out, err, recorded = _send(["route", "clear", "--key", "alice", "--fee", "5"])
    assert rc == 0, err
    request = parse_route_clear(_sent_payload(recorded))
    assert request.signer_pubkey == request.owner_pubkey == alice


def test_route_clear_as_destination_names_the_owner(alice):
    rc, out, err, recorded = _send(
        ["route", "clear", "--key", "alice", "--owner", OTHER, "--fee", "5"])
    assert rc == 0, err
    assert parse_route_clear(_sent_payload(recorded)).owner_pubkey == OTHER


def test_route_show_queries_the_node(alice):
    recorded = []
    rc, out, err = _run_cli(["route", "show", "--key", "alice"],
                            send_responses=[_ok({"route": None})], recorded=recorded)
    assert rc == 0, err
    assert recorded == [f"getreceiveroute {alice} 50"]
    recorded.clear()
    _run_cli(["route", "show", "--capability"],
             send_responses=[_ok({"capability": {}})], recorded=recorded)
    assert recorded == ["getreceiveroute capability"]


@pytest.mark.parametrize("kwargs,match", [
    (dict(route_bps=0), "route_bps"),
    (dict(route_bps=9001), "route_bps"),
    (dict(locked=True), "locked route needs an expiry"),
    (dict(destination_pubkey="aa" * 48), "must not be the receiving account"),
])
def test_the_builder_refuses_what_admission_would(kwargs, match):
    base = dict(sender_pubkey="aa" * 48, sequence_number=0, expiration_time=1,
                expire_at_height=10, destination_pubkey=OTHER, route_bps=2000)
    base.update(kwargs)
    with pytest.raises(ValueError, match=match):
        tx_mod.build_receive_route_set_tx(**base)


def test_percent_with_three_decimals_is_refused(alice):
    with pytest.raises(SystemExit) as exc:
        _run_cli(["route", "set", "--key", "alice", "--to", OTHER, "--percent", "12.345"])
    assert exc.value.code == 2


def test_percent_that_is_not_finite_is_refused(alice):
    for bad in ("inf", "nan"):
        with pytest.raises(SystemExit) as exc:
            _run_cli(["route", "set", "--key", "alice", "--to", OTHER, "--percent", bad])
        assert exc.value.code == 2


def test_route_set_request_parks_a_kind_6_rule_change_request(alice):
    rc, out, err, recorded = _send([
        "route", "set", "--key", "alice", "--to", OTHER, "--percent", "20",
        "--min-amount", "10", "--request", "--approver", f"18={THIRD}", "--fee", "5",
    ])
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert verify_tx_signature(payload) == (True, "")
    assert (payload["tx_type"], payload["kind"]) == (
        "rule_change_request", tau_defs.RULE_CHANGE_KIND_SET_RECEIVE_ROUTE)
    assert payload["approvers"] == {"18": THIRD}
    request = parse_rule_change_request(payload)
    route = parse_route_spec(request.body, alice)
    assert (route.destination_pubkey, route.bps, route.min_amount, route.version) == \
        (OTHER, 2000, 10, payload["sequence_number"])
    # Defaults past the time escape so the request can release without votes.
    assert payload["expire_at_height"] > TIP + 1 + tau_defs.RULE_CHANGE_DELAY_BLOCKS


def test_route_clear_request_parks_a_kind_7_rule_change_request(alice):
    rc, out, err, recorded = _send(["route", "clear", "--key", "alice", "--request", "--fee", "5"])
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert payload["kind"] == tau_defs.RULE_CHANGE_KIND_CLEAR_RECEIVE_ROUTE
    assert "rule_text" not in payload


@pytest.mark.parametrize("argv", [
    ["route", "set", "--key", "alice", "--to", OTHER, "--percent", "20",
     "--approver", f"18={THIRD}"],
    ["route", "clear", "--key", "alice", "--owner", OTHER, "--request"],
])
def test_request_flags_are_refused_where_they_do_not_apply(alice, argv):
    rc, out, err = _run_cli(argv, send_responses=[], recorded=[])
    assert rc != 0
    assert "--request" in err
