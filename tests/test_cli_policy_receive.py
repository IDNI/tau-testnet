"""Tests for `tau-testnet policy receive ...` (issues #47/#76).

Two halves, mirroring the command's own split:

- Composition (allow-list / max-hold / combined) is offline pure text.
  The tests hold the printed clauses to the node's own standards: they
  must be byte-identical to the canonical bodies the recipient-controls
  suite pins where the shapes overlap, pass the deploy width screen,
  be inbound-capable, never be unit-blind, and have their caps read back
  exactly by the node's branch-aware cap extractor.
- Inspection (status / show) is a thin formatted read over the node's
  getgovernance / getrecipientpolicy commands, exercised here against
  canned RPC responses in the house pattern of test_cli_policy.py.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

import tau_defs
from consensus import sender_policy
from consensus.approvals import screen_recipient_stream_widths
from tau_testnet_cli import cli

ALICE = "aa" * 48
BOB = "bb" * 48
CAROL = "cc" * 48


def _ok(data):
    return json.dumps({"status": "ok", "command": "x", "data": data})


def _err(message, code="FEATURE_INACTIVE"):
    return json.dumps({"status": "error", "command": "x",
                       "error": message, "code": code})


def _run(argv, responses=None, recorded=None):
    responses = list(responses or [])

    def fake_send(command, host, port, *, timeout=10.0, max_bytes=None):
        if recorded is not None:
            recorded.append(command)
        if not responses:
            raise AssertionError(f"no canned response for {command!r}")
        return responses.pop(0)

    out, err = io.StringIO(), io.StringIO()
    with patch("tau_testnet_cli.rpc.send_command", side_effect=fake_send), \
            redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def _offline(argv):
    """Composition commands must never touch the network."""
    def boom(command, host, port, *, timeout=10.0, max_bytes=None):
        raise AssertionError(f"unexpected RPC for a composition command: {command!r}")

    out, err = io.StringIO(), io.StringIO()
    with patch("tau_testnet_cli.rpc.send_command", side_effect=boom), \
            redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def _first_line(text):
    return text.splitlines()[0]


# --- composition: allow-list -------------------------------------------------

def test_allowlist_single_sender_matches_the_canonical_body():
    rc, out, err = _offline(["policy", "receive", "allow-list", ALICE])
    assert rc == 0, err
    expected = (
        "always ( (i16[t]:bv[64] = { #x0000 }:bv[64] || "
        "i3[t]:bv[384] = { #x" + ALICE + " }:bv[384]) "
        "? (o5[t]:bv[24] = { #x000001 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000000 }:bv[24]) )."
    )
    assert _first_line(out) == expected


def test_allowlist_multiple_senders_all_listed_once():
    rc, out, err = _offline(["policy", "receive", "allow-list", ALICE, BOB])
    assert rc == 0, err
    clause = _first_line(out)
    assert clause.count("{ #x" + ALICE + " }:bv[384]") == 1
    assert clause.count("{ #x" + BOB + " }:bv[384]") == 1


def test_allowlist_rejects_a_malformed_pubkey():
    rc, out, err = _offline(["policy", "receive", "allow-list", "xyz"])
    assert rc == cli.EXIT_LOCAL
    assert "96-hex" in err


# --- composition: max-hold ----------------------------------------------------

def test_max_hold_both_caps_matches_the_canonical_body():
    rc, out, err = _offline(
        ["policy", "receive", "max-hold", "--seconds", "600",
         "--blocks", "100"])
    assert rc == 0, err
    cap_body = (
        "((i16[t]:bv[64] = { #x0002 }:bv[64] && "
        "i17[t]:bv[64] > { #x0258 }:bv[64]) || "
        "(i16[t]:bv[64] = { #x0003 }:bv[64] && "
        "i17[t]:bv[64] > { #x0064 }:bv[64])) "
        "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
        ": (o5[t]:bv[24] = { #x000001 }:bv[24])"
    )
    assert _first_line(out) == "always ( %s )." % cap_body


def test_max_hold_single_unit_variants():
    rc, out, err = _offline(["policy", "receive", "max-hold",
                             "--seconds", "0"])
    assert rc == 0, err
    clause = _first_line(out)
    assert "{ #x0002 }" in clause and "{ #x0003 }" not in clause
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_TIME_PARK) == 0
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_HEIGHT_PARK) is None

    rc, out, err = _offline(["policy", "receive", "max-hold",
                             "--blocks", "10"])
    assert rc == 0, err
    clause = _first_line(out)
    assert "{ #x0003 }" in clause and "{ #x0002 }" not in clause
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_HEIGHT_PARK) == 10


def test_max_hold_needs_at_least_one_cap():
    rc, out, err = _offline(["policy", "receive", "max-hold"])
    assert rc == cli.EXIT_LOCAL
    assert "--seconds" in err


def test_max_hold_rejects_a_negative_cap():
    rc, out, err = _offline(["policy", "receive", "max-hold",
                             "--seconds", "-5"])
    assert rc == cli.EXIT_LOCAL
    assert "0 or more" in err


# --- composition: combined -----------------------------------------------------

def test_combined_caps_round_trip_through_the_extractor():
    rc, out, err = _offline(
        ["policy", "receive", "combined", "--allow", ALICE,
         "--allow", BOB, "--seconds", "600", "--blocks", "100"])
    assert rc == 0, err
    clause = _first_line(out)
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_TIME_PARK) == 600
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_HEIGHT_PARK) == 100


def test_combined_without_a_cap_leaves_that_unit_uncapped():
    rc, out, err = _offline(
        ["policy", "receive", "combined", "--allow", ALICE,
         "--seconds", "60"])
    assert rc == 0, err
    clause = _first_line(out)
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_TIME_PARK) == 60
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_HEIGHT_PARK) is None


def test_combined_requires_an_allowed_sender():
    with pytest.raises(SystemExit) as excinfo:
        _offline(["policy", "receive", "combined", "--seconds", "60"])
    assert excinfo.value.code == cli.EXIT_USAGE  # argparse: --allow required


# --- composition: every printed clause passes the node's deploy screens -------

@pytest.mark.parametrize("argv", [
    ["policy", "receive", "allow-list", ALICE],
    ["policy", "receive", "allow-list", ALICE, BOB, CAROL],
    ["policy", "receive", "max-hold", "--seconds", "600", "--blocks", "100"],
    ["policy", "receive", "max-hold", "--seconds", "3600"],
    ["policy", "receive", "max-hold", "--blocks", "0"],
    ["policy", "receive", "combined", "--allow", ALICE,
     "--seconds", "600", "--blocks", "100"],
    ["policy", "receive", "combined", "--allow", ALICE, "--allow", BOB],
])
def test_composed_clauses_pass_the_deploy_screens(argv):
    rc, out, err = _offline(argv)
    assert rc == 0, err
    clause = _first_line(out)
    # The bv-width screen: every i17/i16 mention typed bv[64].
    assert screen_recipient_stream_widths(clause) is None
    # Inbound-capable: the clause reads the recipient streams at all.
    assert sender_policy.clause_is_inbound_capable(clause)
    # Never unit-blind: a clause reading the hold always reads the context.
    assert not sender_policy.clause_reads_hold_without_context(clause)


def test_composed_caps_are_read_back_exactly():
    rc, out, err = _offline(
        ["policy", "receive", "max-hold", "--seconds", "86400",
         "--blocks", "144"])
    assert rc == 0, err
    clause = _first_line(out)
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_TIME_PARK) == 86400
    assert sender_policy.extract_candidate_cap(
        clause, tau_defs.CONTEXT_INCOMING_HEIGHT_PARK) == 144


# --- inspection: status --------------------------------------------------------

_GOVERNANCE_ACTIVE = _ok({
    "recipient_policy_active": True,
    "capabilities": {
        "recipient_controls": {
            "active": True,
            "hold_stream": 17,
            "context_stream": 16,
            "hold_stream_width": 64,
            "context_stream_width": 64,
            "contexts": {"outgoing": 0, "incoming_final": 1,
                         "incoming_time_park": 2, "incoming_height_park": 3},
            "preflight_command": "getrecipientpolicy",
        },
    },
})

_GOVERNANCE_INACTIVE = _ok({
    "recipient_policy_active": False,
    "capabilities": {
        "recipient_controls": {
            "active": False,
            "hold_stream": 17,
            "context_stream": 16,
            "hold_stream_width": 64,
            "context_stream_width": 64,
            "preflight_command": "getrecipientpolicy",
        },
    },
})


def test_status_reports_active_with_the_reserved_streams():
    recorded = []
    rc, out, err = _run(["policy", "receive", "status"],
                        [_GOVERNANCE_ACTIVE], recorded)
    assert rc == 0, err
    assert recorded == ["getgovernance"]
    assert "ACTIVE" in out
    assert "i17" in out and "i16" in out


def test_status_reports_inactive_with_the_activation_path():
    rc, out, err = _run(["policy", "receive", "status"],
                        [_GOVERNANCE_INACTIVE])
    assert rc == 0, err
    assert "inactive" in out
    assert "recipient_policy_active=true" in out


def test_status_tolerates_a_node_without_the_feature():
    rc, out, err = _run(["policy", "receive", "status"],
                        [_ok({"validators": []})])
    assert rc == 0, err
    assert "not reported by this node" in out


def test_status_json_passes_the_envelope_through():
    rc, out, err = _run(["--json", "policy", "receive", "status"],
                        [_GOVERNANCE_ACTIVE])
    assert rc == 0, err
    payload = json.loads(out)
    assert payload["data"]["recipient_policy_active"] is True


# --- inspection: show -----------------------------------------------------------

_SHOW_PLAIN = _ok({
    "address": ALICE,
    "has_clause": True,
    "inbound_capable": True,
    "neutral_default": False,
})

_SHOW_EVAL = _ok({
    "address": ALICE,
    "has_clause": True,
    "inbound_capable": True,
    "neutral_default": False,
    "evaluation": {
        "sender": BOB,
        "amount": 50,
        "hold": 700,
        "unit": "seconds",
        "admitted": False,
        "max_hold_seconds": 600,
        "cap_kind": "verified",
    },
})


def test_show_reports_the_recipient_state():
    recorded = []
    rc, out, err = _run(["policy", "receive", "show", ALICE],
                        [_SHOW_PLAIN], recorded)
    assert rc == 0, err
    assert recorded == [f"getrecipientpolicy {ALICE}"]
    assert "inbound-capable:   True" in out
    assert "neutral default:   False" in out


def test_show_preflight_prints_the_verdict_and_verified_cap():
    recorded = []
    rc, out, err = _run(
        ["policy", "receive", "show", ALICE, "--sender", BOB,
         "--amount", "50", "--hold", "700", "--unit", "seconds"],
        [_SHOW_EVAL], recorded)
    assert rc == 0, err
    assert recorded == [f"getrecipientpolicy {ALICE} {BOB} 50 700 seconds"]
    assert "REFUSED" in out
    assert "verified cap (seconds): 600" in out


def test_show_preflight_needs_all_four_flags():
    rc, out, err = _run(["policy", "receive", "show", ALICE,
                         "--sender", BOB], [])
    assert rc == cli.EXIT_LOCAL
    assert "--sender, --amount, --hold" in err


def test_show_surfaces_a_feature_inactive_node_error():
    rc, out, err = _run(["policy", "receive", "show", ALICE],
                        [_err("Recipient controls are not active on "
                              "this chain.")])
    assert rc == cli.EXIT_APP_ERROR
    assert "not active" in out


def test_show_rejects_a_malformed_address_locally():
    rc, out, err = _run(["policy", "receive", "show", "nope"], [])
    assert rc == cli.EXIT_LOCAL
    assert "96-hex" in err
