"""Tests for `tau-testnet payout set/update --request` — the kind-8 wiring.

The new CLI paths build a placeholder payout tx, render its canonical spec
with `payout_spec_text`, and file it as a rule-change request through
`_submit_rule_change`. These tests pin the exact request the node sees: an
update files kind 8 with the replaced rule's id as offer_id, a set files
kind 6 with no offer_id, and both carry the canonical spec as rule_text.

Uses the canned-response harness from tests/test_cli_policy.py so the
assertions are on the exact wire strings and payload schemas the node sees.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

import tau_defs
from consensus.approvals import parse_rule_change_request
from consensus.payout import (
    KIND_SECONDS,
    parse_payout_spec,
    payout_rule_body,
    payout_spec_text,
)
from consensus.tx_signing import verify_tx_signature
from tau_testnet_cli import cli, keys as keys_mod

RULE = "always ( o30[t]:bv[24] = i40[t]:bv[24] )."
BOB = "bb" * 48
RULE_ID = "cd" * 32
TIP = 7
# Fixed clock so the spec's expires_at is deterministic: with
# --period-seconds the rule's clock is unix time, so expires_at is
# _now() + --ends-in.
FIXED_NOW = 1_800_000_000


def _ok(data):
    return json.dumps({"status": "ok", "command": "x", "data": data})


def _run(argv, responses=None, recorded=None):
    responses = list(responses or [])

    def fake_send(command, host, port, *, timeout=10.0, max_bytes=None):
        if recorded is not None:
            recorded.append(command)
        if command.startswith("checktx estimate "):
            return _ok({"estimated_fee": "13"})
        if not responses:
            raise AssertionError(f"no canned response for {command!r}")
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
    monkeypatch.setattr(cli, "_now", lambda: FIXED_NOW)
    return json.loads((tmp_path / "alice.json").read_text())["public_key_hex"]


def _sent(recorded):
    sendtx = next(c for c in recorded if c.startswith("sendtx "))
    blob = sendtx[len("sendtx "):].strip()
    if blob.startswith("'") and blob.endswith("'"):
        blob = blob[1:-1]
    return json.loads(blob)


SEQ = _ok({"sequence_number": 4, "tip_height": TIP})
SENT = _ok({"tx_hash": "deadbeef"})

# The spec the --request paths must carry: same fields the command line
# names, canonicalised by payout_spec_text, without a sequence number.
EXPECTED_SPEC = payout_spec_text({
    "rule_text": RULE,
    "slots": [BOB],
    "cap_per_execution": 500,
    "cap_per_period": 2000,
    "period_seconds": 1000,
    "expires_at": FIXED_NOW + 100000,
})

SET_ARGV = [
    "payout", "set", "--key", "alice", "--body", RULE,
    "--slot", BOB, "--cap-per-execution", "500", "--cap-per-period", "2000",
    "--period-seconds", "1000", "--ends-in", "100000",
    "--request", "--expire-in", "2000",
]

UPDATE_ARGV = [
    "payout", "update", "--key", "alice", "--rule-id", RULE_ID,
    "--body", RULE,
    "--slot", BOB, "--cap-per-execution", "500", "--cap-per-period", "2000",
    "--period-seconds", "1000", "--ends-in", "100000",
    "--request", "--expire-in", "2000",
]


def test_payout_update_request_is_kind_8_with_rule_id_as_offer_id(alice):
    recorded = []
    rc, out, err = _run(UPDATE_ARGV, [SEQ, SENT], recorded)
    assert rc == 0, err
    tx = _sent(recorded)
    assert tx["tx_type"] == "rule_change_request"
    assert tx["kind"] == tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT == 8
    assert tx["offer_id"] == RULE_ID
    assert tx["rule_text"] == EXPECTED_SPEC
    assert tx["expire_at_height"] == TIP + 1 + 2 * tau_defs.RULE_CHANGE_DELAY_BLOCKS
    assert verify_tx_signature(tx)[0]
    assert f"request id: {parse_rule_change_request(tx).request_id.hex()}" in out
    # The spec parses back to exactly the terms the command line named.
    terms = parse_payout_spec(tx["rule_text"], alice, tx["sequence_number"])
    assert terms.body == payout_rule_body(RULE)
    assert list(terms.slots) == [BOB]
    assert terms.cap_per_execution == 500
    assert terms.cap_per_period == 2000
    assert terms.kind == KIND_SECONDS
    assert terms.period == 1000
    assert terms.expires_at == FIXED_NOW + 100000


def test_payout_set_request_is_kind_6_with_no_offer_id(alice):
    recorded = []
    rc, out, err = _run(SET_ARGV, [SEQ, SENT], recorded)
    assert rc == 0, err
    tx = _sent(recorded)
    assert tx["tx_type"] == "rule_change_request"
    assert tx["kind"] == tau_defs.RULE_CHANGE_KIND_SET_PAYOUT == 6
    assert tx.get("offer_id", "") == ""
    assert tx["rule_text"] == EXPECTED_SPEC
    assert tx["expire_at_height"] == TIP + 1 + 2 * tau_defs.RULE_CHANGE_DELAY_BLOCKS
    assert verify_tx_signature(tx)[0]
    assert f"request id: {parse_rule_change_request(tx).request_id.hex()}" in out
    terms = parse_payout_spec(tx["rule_text"], alice, tx["sequence_number"])
    assert terms.body == payout_rule_body(RULE)
    assert list(terms.slots) == [BOB]
    assert terms.cap_per_execution == 500
    assert terms.cap_per_period == 2000
    assert terms.kind == KIND_SECONDS
    assert terms.period == 1000
    assert terms.expires_at == FIXED_NOW + 100000
