"""Tests for `tau-testnet policy ...` and rule-change rows in `approval ...`."""
from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

import tau_defs
from consensus.approvals import parse_rule_change_request
from consensus.tx_signing import verify_tx_signature
from tau_testnet_cli import cli, keys as keys_mod

POLICY = "always ( o5[t]:bv[24] = { #x000003 }:bv[24] )."
GUARD = (
    "always ( (i18[t]:bv[384] = { #x" + "ab" * 48 + " }:bv[384]) ? "
    "o5[t]:bv[24] = { #x000001 }:bv[24] : o5[t]:bv[24] = { #x000000 }:bv[24] )."
)
OFFER_ID = "ab" * 32
REQ_ID = "cd" * 32
APPROVER = "bb" * 48
TIP = 7


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
    return json.loads((tmp_path / "alice.json").read_text())["public_key_hex"]


def _sent(recorded):
    sendtx = next(c for c in recorded if c.startswith("sendtx "))
    blob = sendtx[len("sendtx "):].strip()
    if blob.startswith("'") and blob.endswith("'"):
        blob = blob[1:-1]
    return json.loads(blob)


SEQ = _ok({"sequence_number": 4, "tip_height": TIP})
SENT = _ok({"tx_hash": "deadbeef"})


def test_guard_set_builds_a_kind_4_request_and_prints_its_id(alice):
    recorded = []
    rc, out, err = _run(
        ["policy", "guard", "set", "--key", "alice", "--body", GUARD,
         "--approver", f"18={APPROVER}"],
        [SEQ, SENT], recorded,
    )
    assert rc == 0, err
    tx = _sent(recorded)
    assert tx["tx_type"] == "rule_change_request"
    assert tx["kind"] == 4
    assert tx["rule_text"] == GUARD
    assert tx["approvers"] == {"18": APPROVER}
    assert tx["expire_at_height"] == TIP + 1 + 2 * tau_defs.RULE_CHANGE_DELAY_BLOCKS
    assert verify_tx_signature(tx)[0]
    assert f"request id: {parse_rule_change_request(tx).request_id.hex()}" in out


def test_guard_set_reads_the_body_from_a_file(alice, tmp_path):
    path = tmp_path / "guard.tau"
    path.write_text(GUARD, encoding="utf-8")
    recorded = []
    rc, _, err = _run(
        ["policy", "guard", "set", "--key", "alice", "--file", str(path)],
        [SEQ, SENT], recorded,
    )
    assert rc == 0, err
    assert _sent(recorded)["rule_text"] == GUARD


def test_guard_revoke_is_kind_5_with_no_text(alice):
    recorded = []
    rc, _, err = _run(
        ["policy", "guard", "revoke", "--key", "alice"], [SEQ, SENT], recorded
    )
    assert rc == 0, err
    tx = _sent(recorded)
    assert tx["kind"] == 5
    assert "rule_text" not in tx


@pytest.mark.parametrize("argv,kind", [
    (["--kind", "set", "--body", POLICY], 1),
    (["--kind", "revoke"], 2),
])
def test_change_request_kinds(alice, argv, kind):
    recorded = []
    rc, _, err = _run(
        ["policy", "change", "request", "--key", "alice", *argv],
        [SEQ, SENT], recorded,
    )
    assert rc == 0, err
    assert _sent(recorded)["kind"] == kind


def test_change_request_accept_fetches_the_offer_text(alice):
    recorded = []
    rc, _, err = _run(
        ["policy", "change", "request", "--key", "alice", "--kind", "accept",
         "--offer-id", OFFER_ID],
        [_ok({"rule_text": POLICY}), SEQ, SENT], recorded,
    )
    assert rc == 0, err
    assert recorded[0] == f"getruleoffer {OFFER_ID}"
    tx = _sent(recorded)
    assert tx["kind"] == 3
    assert tx["rule_text"] == POLICY
    assert tx["offer_id"] == OFFER_ID


def test_change_request_revoke_refuses_a_body(alice):
    rc, _, err = _run(
        ["policy", "change", "request", "--key", "alice", "--kind", "revoke",
         "--body", POLICY],
        [],
    )
    assert rc != 0
    assert "no body" in err


def test_a_short_expiry_warns_about_the_time_escape(alice):
    rc, _, err = _run(
        ["policy", "change", "request", "--key", "alice", "--kind", "revoke",
         "--expire-in", str(tau_defs.RULE_CHANGE_DELAY_BLOCKS)],
        [SEQ, SENT],
    )
    assert rc == 0
    assert "before the" in err and "time escape" in err


def test_the_default_expiry_does_not_warn(alice):
    _, _, err = _run(
        ["policy", "change", "request", "--key", "alice", "--kind", "revoke"],
        [SEQ, SENT],
    )
    assert "warning" not in err


def test_an_expiry_past_the_window_is_refused_locally(alice):
    rc, _, err = _run(
        ["policy", "change", "request", "--key", "alice", "--kind", "revoke",
         "--expire-in", "10001"],
        [SEQ],
    )
    assert rc != 0
    assert "10000" in err


def test_dry_run_signs_and_prints_but_sends_nothing(alice):
    recorded = []
    rc, out, err = _run(
        ["policy", "guard", "revoke", "--key", "alice", "--dry-run"],
        [SEQ], recorded,
    )
    assert rc == 0, err
    assert not any(c.startswith("sendtx") for c in recorded)
    assert json.loads(out)["signature"]


def test_preview_asks_the_node_and_prints_a_summary(alice):
    recorded = []
    rc, out, err = _run(
        ["policy", "guard", "revoke", "--key", "alice", "--preview",
         "--approver", f"18={APPROVER}"],
        [_ok({
            "request_type": "rule_change", "kind_name": "revoke_guard",
            "has_guard": True, "executes_immediately": False, "satisfiable": True,
            "required_approvers": {"18": APPROVER},
            "allowing_subsets": [[18]], "screen": {"ok": True, "error": None},
            "escape_delay_blocks": 1000, "available": True,
        })],
        recorded,
    )
    assert rc == 0, err
    assert recorded[0].startswith("getapprovalpreview ")
    draft = json.loads(recorded[0][len("getapprovalpreview "):])
    assert draft["request_type"] == "rule_change"
    assert draft["kind"] == 5
    assert draft["approvers"] == {"18": APPROVER}
    assert not any(c.startswith("sendtx") for c in recorded)
    assert f"i18: {APPROVER}" in out
    assert "1000 blocks" in out


def test_preview_reports_immediate_execution(alice):
    rc, out, _ = _run(
        ["policy", "guard", "revoke", "--key", "alice", "--preview"],
        [_ok({"kind_name": "revoke_guard", "has_guard": False,
              "executes_immediately": True, "available": True,
              "escape_delay_blocks": 1000})],
    )
    assert rc == 0
    assert "executes in the block" in out


def test_guard_show_reads_getruleoffers(alice):
    recorded = []
    rc, out, _ = _run(
        ["policy", "guard", "show", APPROVER],
        [_ok({"rule_change_guard": GUARD})], recorded,
    )
    assert rc == 0
    assert recorded == [f"getruleoffers {APPROVER} all"]
    assert GUARD in out


def test_guard_show_without_a_guard(alice):
    rc, out, _ = _run(
        ["policy", "guard", "show", APPROVER], [_ok({"rule_change_guard": None})]
    )
    assert rc == 0
    assert "no rule-change guard" in out


def test_cancel_builds_a_feeless_cancel(alice):
    recorded = []
    rc, _, err = _run(
        ["policy", "change", "cancel", "--key", "alice", "--request-id", REQ_ID],
        [SEQ, SENT], recorded,
    )
    assert rc == 0, err
    assert not any(c.startswith("checktx estimate") for c in recorded)
    tx = _sent(recorded)
    assert tx["tx_type"] == "rule_change_cancel"
    assert tx["request_id"] == REQ_ID
    assert tx["fee_limit"] == "0"
    assert verify_tx_signature(tx)[0]


def test_cancel_has_no_fee_flag():
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(
            ["policy", "change", "cancel", "--key", "k", "--request-id", REQ_ID,
             "--fee", "5"]
        )
    assert exc.value.code == 2


# --- approval list / show -----------------------------------------------------

def _rc_row(body=POLICY):
    return {
        "request_type": "rule_change", "request_id": REQ_ID, "kind": 1,
        "kind_name": "set_policy", "sender_pubkey": "aa" * 48, "body": body,
        "body_hash": "ee" * 32, "offer_id": "", "status": "open", "ready": False,
        "created_height": 10, "escape_height": 1010, "expire_at_height": 2010,
        "approvers": {"18": {"pubkey": APPROVER, "state": "awaiting"}},
    }


def test_approval_show_renders_a_rule_change_row():
    rc, out, _ = _run(["approval", "show", REQ_ID], [_ok(_rc_row())])
    assert rc == 0
    assert "set_policy" in out and POLICY in out
    assert "time escape at height 1010" in out
    assert f"i18: {APPROVER} [awaiting]" in out


def test_a_long_body_shows_its_hash_and_length():
    body = "x" * 800
    _, out, _ = _run(["approval", "show", REQ_ID], [_ok(_rc_row(body))])
    assert "800 chars" in out and "ee" * 32 in out
    assert body not in out


def test_approval_list_renders_rule_change_rows_and_keeps_transfers_raw():
    transfer = {"request_type": "transfer", "request_id": "11" * 32, "amount": 5}
    rc, out, _ = _run(
        ["approval", "list", APPROVER],
        [_ok({"incoming": [_rc_row(), transfer], "outgoing": []})],
    )
    assert rc == 0
    assert "rule change " + REQ_ID in out
    assert '"amount": 5' in out


def test_approval_list_without_rule_changes_is_the_raw_response():
    raw = _ok({"incoming": [{"request_type": "transfer", "amount": 5}], "outgoing": []})
    _, out, _ = _run(["approval", "list", APPROVER], [raw])
    assert out.strip() == raw


def test_approve_on_a_rule_change_id_builds_a_plain_vote(alice):
    recorded = []
    rc, _, err = _run(
        ["approval", "approve", "--key", "alice", REQ_ID], [SEQ, SENT], recorded
    )
    assert rc == 0, err
    tx = _sent(recorded)
    assert tx["tx_type"] == "transfer_vote"
    assert tx["request_id"] == REQ_ID
    assert tx["approve"] is True


# --- policy show (issue #42) ---------------------------------------------------

ACCOUNT_RULES = {
    "address": APPROVER, "block_number": 41, "block_hash": "ee" * 32,
    "rule_clauses_root": "11" * 32,
    "clauses": [{"stream": 5, "name": "o5", "body": "(o5[t]:bv[24] = { #x000000 }:bv[24])",
                 "sha256": "22" * 32, "since": {"block_number": 40, "tx_hash": "33" * 32}}],
    "rule_change_guard": None,
    "application_rules": [],
    "open_rule_changes": [{"request_id": REQ_ID, "kind": "set_policy", "body_sha256": "44" * 32,
                           "offer_id": None, "approvers": {"18": APPROVER}, "voted": {},
                           "declined": [], "ready": False, "created_height": 39,
                           "expire_at_height": 2039}],
    "awaiting_my_vote": [], "pending_offers": 1, "mempool": [],
    "history": [{"block_number": 40, "kind": "clause", "action": "registered", "stream": 5,
                 "tx_hash": "33" * 32, "sha256": "22" * 32},
                {"block_number": 38, "kind": "rule_change_request",
                 "action": "release_failed", "request_id": "55" * 32,
                 "detail": "no policy to revoke"}],
}


def test_policy_show_reads_getaccountrules_and_explains_it(alice):
    recorded = []
    rc, out, err = _run(["policy", "show", APPROVER], [_ok(ACCOUNT_RULES)], recorded)
    assert rc == 0, err
    assert recorded == [f"getaccountrules {APPROVER}"]
    assert "o5 clause: sha256 " + "22" * 32 in out
    assert "set at block 40 by tx 333333333333..." in out
    assert "rule-change guard: none" in out
    assert "open rule-change requests: 1" in out
    assert "votes 0/1  waiting  expires at 2039" in out
    assert "block 38  rule_change_request release_failed" in out
    assert "(no policy to revoke)" in out


def test_policy_show_defaults_to_the_key_and_passes_json_through(alice):
    recorded = []
    rc, out, _ = _run(["--json", "policy", "show", "--key", "alice"],
                      [_ok(ACCOUNT_RULES)], recorded)
    assert rc == 0
    assert recorded == [f"getaccountrules {alice}"]
    assert json.loads(out)["data"]["clauses"][0]["sha256"] == "22" * 32
