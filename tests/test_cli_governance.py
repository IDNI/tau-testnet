"""Tests for `tau-testnet gov ...` flow.

Schemas pinned by tests/test_gov_integration.py:54-107 (flat top-level
fields, not nested under a `payload:` key).
"""

from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from tau_testnet_cli import cli, keys as keys_mod, tx as tx_mod


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


def test_gov_list_calls_getgovernance():
    recorded = []
    rc, out, _ = _run_cli(
        ["gov", "list"],
        send_responses=['{"head_number": 7}'],
        recorded=recorded,
    )
    assert rc == 0
    assert recorded == ["getgovernance"]


def test_gov_update_id_from_file_calls_getupdateid(tmp_path):
    update_file = tmp_path / "update.json"
    update_obj = {
        "rule_revisions": ["always."],
        "activate_at_height": 100,
    }
    update_file.write_text(json.dumps(update_obj), encoding="utf-8")

    recorded = []
    rc, _, _ = _run_cli(
        ["gov", "update-id", "--file", str(update_file)],
        send_responses=['{"status":"ok","update_id":"' + "a" * 96 + '"}'],
        recorded=recorded,
    )
    assert rc == 0
    assert recorded[0].startswith("getupdateid ")
    sent_json = json.loads(recorded[0].split(" ", 1)[1])
    assert sent_json == update_obj


def test_gov_update_id_inline():
    recorded = []
    rc, _, _ = _run_cli(
        [
            "gov",
            "update-id",
            "--inline",
            json.dumps({"rule_revisions": ["a"], "activate_at_height": 1}),
        ],
        send_responses=['{"status":"ok","update_id":"' + "b" * 96 + '"}'],
        recorded=recorded,
    )
    assert rc == 0
    assert recorded[0].startswith("getupdateid ")


def test_gov_propose_builds_consensus_rule_update_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())
    pk_hex = record["public_key_hex"]

    update_file = tmp_path / "update.json"
    update_file.write_text(
        json.dumps(
            {
                "rule_revisions": ["always."],
                "activate_at_height": 100,
                "host_contract_patch": {
                    "proof_scheme": "bls_header_sig",
                    "fork_choice_scheme": "height_then_hash",
                    "input_contract_version": 1,
                },
            }
        ),
        encoding="utf-8",
    )

    recorded = []
    rc, _, err = _run_cli(
        [
            "gov",
            "propose",
            "--key",
            "alice",
            "--file",
            str(update_file),
        ],
        send_responses=[
            '{"status":"ok","command":"getsequence","data":{"address":"x","sequence_number":0}}',
            '{"status":"ok","command":"sendtx","data":{"message":"Transaction queued.","tx_hash":"ok"}}',
        ],
        recorded=recorded,
    )
    assert rc == 0, err
    assert recorded[0] == f"getsequence {pk_hex}"
    blob = recorded[1][len("sendtx '") : -1]
    payload = json.loads(blob)

    # Schema pinned by tests/test_gov_integration.py — flat at top level.
    assert payload["tx_type"] == "consensus_rule_update"
    assert payload["sender_pubkey"] == pk_hex
    assert payload["sequence_number"] == 0
    assert payload["rule_revisions"] == ["always."]
    assert payload["activate_at_height"] == 100
    assert payload["host_contract_patch"]["proof_scheme"] == "bls_header_sig"
    assert payload["fee_limit"] == "0"
    assert "expiration_time" in payload
    assert len(payload["signature"]) == 192
    # Must NOT be nested.
    assert "payload" not in payload


def test_gov_propose_omits_host_contract_patch_when_null(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)

    update_file = tmp_path / "update.json"
    update_file.write_text(
        json.dumps(
            {
                "rule_revisions": ["always."],
                "activate_at_height": 99,
                "host_contract_patch": None,
            }
        ),
        encoding="utf-8",
    )

    recorded = []
    rc, _, _ = _run_cli(
        ["gov", "propose", "--key", "alice", "--file", str(update_file)],
        send_responses=[
            '{"status":"ok","command":"getsequence","data":{"address":"x","sequence_number":0}}',
            '{"status":"ok","command":"sendtx","data":{"message":"Transaction queued.","tx_hash":"ok"}}',
        ],
        recorded=recorded,
    )
    assert rc == 0
    blob = recorded[1][len("sendtx '") : -1]
    payload = json.loads(blob)
    # When the source `host_contract_patch` is null/absent, it must not appear
    # in the signed payload — `_get_signing_message_bytes` only includes it
    # when present.
    assert "host_contract_patch" not in payload


def test_gov_vote_builds_consensus_rule_vote_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())
    pk_hex = record["public_key_hex"]

    recorded = []
    rc, _, _ = _run_cli(
        ["gov", "vote", "--key", "alice", "--update-id", "a" * 64],
        send_responses=[
            '{"status":"ok","command":"getsequence","data":{"address":"x","sequence_number":3}}',
            '{"status":"ok","command":"sendtx","data":{"message":"Transaction queued.","tx_hash":"ok"}}',
        ],
        recorded=recorded,
    )
    assert rc == 0
    blob = recorded[1][len("sendtx '") : -1]
    payload = json.loads(blob)

    assert payload["tx_type"] == "consensus_rule_vote"
    assert payload["sender_pubkey"] == pk_hex
    assert payload["sequence_number"] == 3
    assert payload["update_id"] == "a" * 64
    assert payload["approve"] is True
    assert payload["fee_limit"] == "0"
    assert len(payload["signature"]) == 192
    # Schema is FLAT — must NOT be nested under `payload:`.
    assert "payload" not in payload


def test_gov_vote_signature_uses_canonical_signer():
    """gov vote signature must equal _get_signing_message_bytes -> sha256 -> Sign."""
    import hashlib

    from py_ecc.bls import G2Basic

    from commands.sendtx import _get_signing_message_bytes

    # Use a hex string that contains a letter so wallet._parse_privkey
    # routes to its hex branch (otherwise it treats all-digits as decimal).
    sk_hex = "0x" + ("1" * 63) + "a"
    sk_int = int(sk_hex, 16)
    pk_hex = G2Basic.SkToPk(sk_int).hex()

    payload = tx_mod.build_consensus_rule_vote_tx(
        sender_pubkey=pk_hex,
        sequence_number=0,
        expiration_time=1234,
        update_id="b" * 64,
        approve=True,
        fee_limit="0",
    )
    msg = _get_signing_message_bytes(payload)
    expected = G2Basic.Sign(sk_int, hashlib.sha256(msg).digest()).hex()
    tx_mod.sign_tx(payload, sk_hex)
    assert payload["signature"] == expected


def test_gov_propose_invalid_input_exits_4(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    bad = tmp_path / "bad.json"
    bad.write_text("not valid json", encoding="utf-8")
    rc, _, err = _run_cli(
        ["gov", "propose", "--key", "alice", "--file", str(bad)],
        send_responses=[],
    )
    assert rc == 4
    assert "json" in err.lower()
