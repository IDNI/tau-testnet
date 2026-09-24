"""Tests for `tau-testnet rule ...` -- the user-facing rule sharing surface.

Uses the canned-response harness from tests/test_cli_governance.py so the
assertions are on the exact wire strings and payload schemas the node will see.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

from tau_testnet_cli import cli, keys as keys_mod, tx as tx_mod

RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
OFFER_ID = "ab" * 32
OTHER = "bb" * 48


# A canned getsequence answer carries tip_height, as a node's does: without it
# the CLI takes the node for one too old to report the tip, asks getblocks as
# well, and that extra call takes the response queued for sendtx.
def _run_cli(argv, *, send_responses=None, recorded=None):
    responses = list(send_responses or [])

    def fake_send(command, host, port, *, timeout=10.0, max_bytes=None):
        if recorded is not None:
            recorded.append(command)
        if not responses:
            raise AssertionError(f"no canned response for command: {command!r}")
        return responses.pop(0)

    out, err = io.StringIO(), io.StringIO()
    with patch("tau_testnet_cli.rpc.send_command", side_effect=fake_send), \
         redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


@pytest.fixture
def alice(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())
    return record["public_key_hex"]


def _ok(data):
    return json.dumps({"status": "ok", "command": "x", "data": data})


def _sent_payload(recorded):
    """The JSON payload from a recorded `sendtx '<json>'` command."""
    sendtx = next(c for c in recorded if c.startswith("sendtx "))
    blob = sendtx[len("sendtx "):].strip()
    if blob.startswith("'") and blob.endswith("'"):
        blob = blob[1:-1]
    return json.loads(blob)


# --- read-only commands -----------------------------------------------------

def test_rule_list_calls_getruleoffers():
    recorded = []
    rc, _, _ = _run_cli(
        ["rule", "list", OTHER], send_responses=[_ok({})], recorded=recorded
    )
    assert rc == 0
    assert recorded == [f"getruleoffers {OTHER} all"]


def test_rule_list_role_filter():
    recorded = []
    _run_cli(
        ["rule", "list", OTHER, "--role", "in"],
        send_responses=[_ok({})], recorded=recorded,
    )
    assert recorded == [f"getruleoffers {OTHER} in"]


def test_rule_list_defaults_to_the_key_owner(alice):
    recorded = []
    rc, _, _ = _run_cli(
        ["rule", "list", "--key", "alice"], send_responses=[_ok({})], recorded=recorded
    )
    assert rc == 0
    assert recorded == [f"getruleoffers {alice} all"]


def test_rule_show_and_check():
    recorded = []
    _run_cli(["rule", "show", OFFER_ID], send_responses=[_ok({})], recorded=recorded)
    assert recorded == [f"getruleoffer {OFFER_ID}"]

    recorded = []
    _run_cli(["rule", "check", OFFER_ID], send_responses=[_ok({})], recorded=recorded)
    assert recorded == [f"getruleconflict {OFFER_ID}"]


def test_rule_offer_id_sends_json_payload():
    recorded = []
    rc, _, _ = _run_cli(
        ["rule", "offer-id", "--rule", RULE, "--from-pubkey", "aa" * 48,
         "--to", OTHER, "--expire-at-height", "500"],
        send_responses=[_ok({"offer_id": OFFER_ID})], recorded=recorded,
    )
    assert rc == 0
    assert recorded[0].startswith("getofferid ")
    payload = json.loads(recorded[0][len("getofferid "):].strip("'"))
    assert payload["rule_text"] == RULE
    assert payload["expire_at_height"] == 500


# --- offer ------------------------------------------------------------------

def test_rule_offer_builds_the_payload(alice, tmp_path):
    rule_file = tmp_path / "policy.tau"
    rule_file.write_text(RULE, encoding="utf-8")

    recorded = []
    rc, _, err = _run_cli(
        ["rule", "offer", "--key", "alice", "--to", OTHER,
         "--rule-file", str(rule_file), "--expire-at-height", "500"],
        send_responses=[
            _ok({"sequence_number": 3, "tip_height": 9}),  # getsequence
            _ok({"tx_hash": "deadbeef"}),                  # sendtx
        ],
        recorded=recorded,
    )
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "rule_offer"
    assert payload["sender_pubkey"] == alice
    assert payload["recipient_pubkey"] == OTHER
    assert payload["rule_text"] == RULE
    assert payload["expire_at_height"] == 500
    assert payload["sequence_number"] == 3
    assert payload["signature"]


def test_rule_offer_resolves_expire_in_against_the_tip(alice):
    recorded = []
    rc, _, err = _run_cli(
        ["rule", "offer", "--key", "alice", "--to", OTHER, "--rule", RULE,
         "--expire-in", "50"],
        send_responses=[
            _ok({"blocks": [{"header": {"block_number": 9}}]}),  # getblocks
            _ok({"sequence_number": 0, "tip_height": 9}),
            _ok({"tx_hash": "deadbeef"}),
        ],
        recorded=recorded,
    )
    assert rc == 0, err
    # tip 9 -> next height 10 -> +50
    assert _sent_payload(recorded)["expire_at_height"] == 60


def test_rule_offer_rejects_self_offer(alice):
    rc, _, err = _run_cli(
        ["rule", "offer", "--key", "alice", "--to", alice, "--rule", RULE,
         "--expire-at-height", "500"],
        send_responses=[_ok({"sequence_number": 0, "tip_height": 9})],
    )
    assert rc == cli.EXIT_LOCAL
    assert "differ" in err


def test_rule_offer_requires_a_rule_source(alice):
    """argparse enforces the mutually-exclusive required group, so this exits
    with the usage code before any RPC is attempted."""
    with pytest.raises(SystemExit) as exc:
        _run_cli(
            ["rule", "offer", "--key", "alice", "--to", OTHER, "--expire-at-height", "5"],
            send_responses=[],
        )
    assert exc.value.code == 2


# --- reject -----------------------------------------------------------------

def test_rule_reject_builds_the_payload(alice):
    recorded = []
    rc, _, err = _run_cli(
        ["rule", "reject", "--key", "alice", OFFER_ID],
        send_responses=[_ok({"sequence_number": 1, "tip_height": 9}),
                        _ok({"tx_hash": "x"})],
        recorded=recorded,
    )
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "rule_offer_reject"
    assert payload["offer_id"] == OFFER_ID
    # A rejection compiles nothing, so it carries no rule text.
    assert "rule_text" not in payload


# --- accept -----------------------------------------------------------------

def _accept_responses(verdict, rule_text=RULE):
    return [
        _ok({"offer_id": OFFER_ID, "rule_text": rule_text}),   # getruleoffer
        _ok({"verdict": verdict, "layers": []}),               # getruleconflict
        _ok({"sequence_number": 2, "tip_height": 9}),          # getsequence
        _ok({"tx_hash": "x"}),                                 # sendtx
    ]


def test_rule_accept_uses_the_offered_text_verbatim(alice):
    """The accept must repeat the offered bytes: the node recomputes the offer
    digest from them, so the CLI fetches rather than retypes."""
    recorded = []
    rc, out, err = _run_cli(
        ["rule", "accept", "--key", "alice", OFFER_ID],
        send_responses=_accept_responses("clean"),
        recorded=recorded,
    )
    assert rc == 0, err
    assert recorded[0] == f"getruleoffer {OFFER_ID}"
    assert recorded[1] == f"getruleconflict {OFFER_ID}"
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "rule_offer_accept"
    assert payload["offer_id"] == OFFER_ID
    assert payload["rule_text"] == RULE
    assert "conflict check: clean" in out


@pytest.mark.parametrize("verdict", ["warn", "conflict"])
def test_rule_accept_refuses_without_yes_on_a_bad_verdict(alice, verdict):
    recorded = []
    rc, out, err = _run_cli(
        ["rule", "accept", "--key", "alice", OFFER_ID],
        send_responses=_accept_responses(verdict)[:2],
        recorded=recorded,
    )
    assert rc == cli.EXIT_APP_ERROR
    assert verdict in err
    assert not any(c.startswith("sendtx") for c in recorded)


@pytest.mark.parametrize("verdict", ["warn", "conflict"])
def test_rule_accept_proceeds_with_yes(alice, verdict):
    recorded = []
    rc, _, err = _run_cli(
        ["rule", "accept", "--key", "alice", OFFER_ID, "--yes"],
        send_responses=_accept_responses(verdict),
        recorded=recorded,
    )
    assert rc == 0, err
    assert _sent_payload(recorded)["tx_type"] == "rule_offer_accept"


def test_rule_accept_fails_when_the_node_lost_the_text(alice):
    """Offer text is node-local; a node that dropped it cannot build an accept."""
    rc, _, err = _run_cli(
        ["rule", "accept", "--key", "alice", OFFER_ID],
        send_responses=[_ok({"offer_id": OFFER_ID, "rule_text": ""})],
    )
    assert rc == cli.EXIT_APP_ERROR
    assert "node-local" in err


def test_rule_accept_reports_conflict_layers(alice):
    recorded = []
    rc, out, _ = _run_cli(
        ["rule", "accept", "--key", "alice", OFFER_ID, "--yes"],
        send_responses=[
            _ok({"offer_id": OFFER_ID, "rule_text": RULE}),
            _ok({"verdict": "warn", "layers": [
                {"layer": "registry_collision", "status": "warn",
                 "detail": "accepting REPLACES it"},
            ]}),
            _ok({"sequence_number": 0, "tip_height": 9}),
            _ok({"tx_hash": "x"}),
        ],
        recorded=recorded,
    )
    assert rc == 0
    assert "registry_collision: warn" in out
    assert "REPLACES" in out
