"""Tests for tau_testnet_cli.tx and `tau-testnet tx ...` CLI flow."""

from __future__ import annotations

import hashlib
import io
import json
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic

from commands.sendtx import _get_signing_message_bytes
from tau_testnet_cli import cli, keys as keys_mod, tx as tx_mod


# --------------------------------------------------------------------------- #
# Library-level (tx.py)
# --------------------------------------------------------------------------- #


def _make_keypair():
    kp = keys_mod.generate_keypair()
    return kp["private_key_hex"], kp["public_key_hex"]


def test_build_user_tx_includes_required_fields():
    sk_hex, pk = _make_keypair()
    payload = tx_mod.build_user_tx(
        sender_pubkey=pk,
        sequence_number=5,
        expiration_time=1234567890,
        operations={"1": [[pk, "ab" * 48, "10"]]},
    )
    assert payload["tx_type"] == "user_tx"
    assert payload["sender_pubkey"] == pk
    assert payload["sequence_number"] == 5
    assert payload["expiration_time"] == 1234567890
    assert payload["fee_limit"] == "0"
    assert payload["operations"]["1"][0][2] == "10"


def test_build_user_tx_rejects_empty_operations():
    sk_hex, pk = _make_keypair()
    with pytest.raises(ValueError, match="at least one operation"):
        tx_mod.build_user_tx(
            sender_pubkey=pk,
            sequence_number=0,
            expiration_time=0,
            operations={},
        )


def test_validate_transfer_amount_rejects_negative_and_too_large():
    with pytest.raises(ValueError):
        tx_mod.validate_transfer_amount(-1)
    with pytest.raises(ValueError):
        tx_mod.validate_transfer_amount(1 << 64)
    tx_mod.validate_transfer_amount(0)
    tx_mod.validate_transfer_amount((1 << 64) - 1)


def test_parse_transfer_flag_ok_and_invalid():
    addr, amt = tx_mod.parse_transfer_flag("0xabc:42")
    assert addr == "0xabc"
    assert amt == 42
    with pytest.raises(ValueError):
        tx_mod.parse_transfer_flag("not-a-valid-format")
    with pytest.raises(ValueError):
        tx_mod.parse_transfer_flag(":42")
    with pytest.raises(ValueError):
        tx_mod.parse_transfer_flag("0xabc:notanumber")


def test_sign_tx_matches_canonical_chain():
    """sign_tx must equal _get_signing_message_bytes -> sha256 -> G2Basic.Sign."""
    sk_hex, pk = _make_keypair()
    payload = tx_mod.build_user_tx(
        sender_pubkey=pk,
        sequence_number=0,
        expiration_time=999,
        operations={"1": [[pk, pk, "1"]]},
    )

    expected_msg = _get_signing_message_bytes(payload)
    expected_hash = hashlib.sha256(expected_msg).digest()

    signed = tx_mod.sign_tx(dict(payload), sk_hex)
    sk_int = int.from_bytes(bytes.fromhex(sk_hex), "big")
    expected_sig = G2Basic.Sign(sk_int, expected_hash).hex()

    assert signed["signature"] == expected_sig


def test_assemble_operations_supports_to_amount_and_transfer():
    sk_hex, pk = _make_keypair()
    other = "ab" * 48
    third = "cd" * 48
    ops = tx_mod.assemble_operations(
        sender_pubkey=pk,
        to=other,
        amount=10,
        transfers=[f"{third}:5"],
    )
    assert "1" in ops
    transfers = ops["1"]
    assert len(transfers) == 2
    assert transfers[0] == [pk, other, "10"]
    assert transfers[1] == [pk, third, "5"]


def test_assemble_operations_to_without_amount_raises():
    sk_hex, pk = _make_keypair()
    with pytest.raises(ValueError):
        tx_mod.assemble_operations(sender_pubkey=pk, to="ab" * 48, amount=None)


def test_assemble_operations_rejects_negative_amount():
    sk_hex, pk = _make_keypair()
    with pytest.raises(ValueError):
        tx_mod.assemble_operations(
            sender_pubkey=pk, to="ab" * 48, amount=-1
        )


def test_assemble_operations_rule_file(tmp_path):
    sk_hex, pk = _make_keypair()
    rule_file = tmp_path / "rule.tau"
    rule_file.write_text("always.\n", encoding="utf-8")
    ops = tx_mod.assemble_operations(sender_pubkey=pk, rule_file=rule_file)
    assert ops["0"] == "always."


def test_assemble_operations_json_overrides(tmp_path):
    sk_hex, pk = _make_keypair()
    ops_file = tmp_path / "ops.json"
    ops_file.write_text(json.dumps({"7": "raw"}), encoding="utf-8")
    ops = tx_mod.assemble_operations(
        sender_pubkey=pk, operations_json=ops_file
    )
    assert ops == {"7": "raw"}


# --------------------------------------------------------------------------- #
# CLI-level (`tau-testnet tx ...`)
# --------------------------------------------------------------------------- #


def _run_cli(argv, *, send_responses=None, recorded=None):
    """Invoke cli.main with rpc.send_command stubbed.

    ``send_responses`` is a list of canned responses (in order); each call to
    ``rpc.send_command`` pops one. ``recorded`` (if given) is a list that will
    receive the ``command`` argument of each call.
    """
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


def test_tx_send_builds_signed_payload(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())
    sk_hex = record["private_key_hex"]
    pk_hex = record["public_key_hex"]
    recipient = "ab" * 48

    recorded = []
    rc, out, err = _run_cli(
        [
            "--json",
            "tx",
            "send",
            "--key",
            "alice",
            "--to",
            recipient,
            "--amount",
            "10",
        ],
        send_responses=["SEQUENCE: 5", "SUCCESS: deadbeef"],
        recorded=recorded,
    )
    assert rc == 0, err
    assert recorded[0] == f"getsequence {pk_hex}"
    assert recorded[1].startswith("sendtx '")

    blob = recorded[1][len("sendtx '") : -1]
    payload = json.loads(blob)
    assert payload["tx_type"] == "user_tx"
    assert payload["sender_pubkey"] == pk_hex
    assert payload["sequence_number"] == 5
    assert payload["operations"]["1"] == [[pk_hex, recipient, "10"]]
    assert len(payload["signature"]) == 192

    parsed = json.loads(out)
    assert parsed["sequence_number"] == 5
    # The submitted echo must include the signature.
    assert "signature" in parsed["submitted"]


def test_tx_send_negative_amount_exits_4():
    rc, _, err = _run_cli(
        [
            "tx",
            "send",
            "--privkey",
            "1" * 64,
            "--to",
            "ab" * 48,
            "--amount",
            "-1",
        ],
        send_responses=[],
    )
    assert rc == 4
    assert "transfer amount" in err.lower() or "amount" in err.lower()


def test_tx_send_no_operations_exits_4():
    """No --to/--amount/--transfer/--rule-file/--operations-json → no operations."""
    rc, _, err = _run_cli(
        ["tx", "send", "--privkey", "1" * 64],
        send_responses=["SEQUENCE: 0"],
    )
    assert rc == 4
    assert "operation" in err.lower()


def test_tx_send_error_response_exits_1(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    rc, _, _ = _run_cli(
        [
            "tx",
            "send",
            "--key",
            "alice",
            "--to",
            "ab" * 48,
            "--amount",
            "1",
        ],
        send_responses=["SEQUENCE: 0", "ERROR: insufficient funds"],
    )
    assert rc == 1


def test_tx_raw_sign_then_raw_submit_round_trip(tmp_path):
    sk_hex, pk = _make_keypair()
    unsigned = {
        "tx_type": "user_tx",
        "sender_pubkey": pk,
        "sequence_number": 0,
        "expiration_time": 1,
        "operations": {"1": [[pk, pk, "1"]]},
        "fee_limit": "0",
    }
    payload_path = tmp_path / "unsigned.json"
    payload_path.write_text(json.dumps(unsigned), encoding="utf-8")

    rc, out, _ = _run_cli(
        ["--json", "tx", "raw-sign", "--privkey", sk_hex, "--payload", str(payload_path)],
        send_responses=[],
    )
    assert rc == 0
    signed = json.loads(out)
    assert "signature" in signed

    signed_path = tmp_path / "signed.json"
    signed_path.write_text(json.dumps(signed), encoding="utf-8")

    recorded = []
    rc, _, _ = _run_cli(
        ["tx", "raw-submit", "--file", str(signed_path)],
        send_responses=["SUCCESS: deadbeef"],
        recorded=recorded,
    )
    assert rc == 0
    assert recorded[0].startswith("sendtx '")


def test_tx_send_multiple_transfers_combine(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())
    pk_hex = record["public_key_hex"]
    a = "ab" * 48
    b = "cd" * 48

    recorded = []
    rc, _, _ = _run_cli(
        [
            "tx",
            "send",
            "--key",
            "alice",
            "--transfer",
            f"{a}:1",
            "--transfer",
            f"{b}:2",
        ],
        send_responses=["SEQUENCE: 0", "SUCCESS: ok"],
        recorded=recorded,
    )
    assert rc == 0
    blob = recorded[1][len("sendtx '") : -1]
    payload = json.loads(blob)
    assert payload["operations"]["1"] == [
        [pk_hex, a, "1"],
        [pk_hex, b, "2"],
    ]
