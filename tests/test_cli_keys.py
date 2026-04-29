"""Tests for tau_testnet_cli.keys and `tau-testnet keys ...` CLI flow."""

from __future__ import annotations

import io
import json
import os
import sys
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import pytest

from tau_testnet_cli import cli, keys as keys_mod


# --------------------------------------------------------------------------- #
# Library-level (keys.py)
# --------------------------------------------------------------------------- #


def test_generate_keypair_shape():
    kp = keys_mod.generate_keypair()
    assert set(kp) >= {"private_key_hex", "public_key_hex", "private_key_int"}
    assert len(kp["private_key_hex"]) == 64
    assert len(kp["public_key_hex"]) == 96
    int(kp["private_key_hex"], 16)
    int(kp["public_key_hex"], 16)


def test_parse_private_key_hex_and_decimal():
    kp = keys_mod.generate_keypair()
    sk_hex = kp["private_key_hex"]
    raw_hex = keys_mod.parse_private_key(sk_hex)
    raw_dec = keys_mod.parse_private_key(str(int(sk_hex, 16)))
    assert raw_hex == raw_dec
    assert len(raw_hex) == 32


def test_public_key_from_private_matches_keypair():
    kp = keys_mod.generate_keypair()
    derived = keys_mod.public_key_from_private(kp["private_key_hex"])
    assert derived == kp["public_key_hex"]


def test_save_key_writes_json_and_chmod_0600(tmp_path):
    path = keys_mod.save_key("alice", tmp_path)
    assert path.exists()
    record = json.loads(path.read_text(encoding="utf-8"))
    assert record["version"] == 1
    assert record["name"] == "alice"
    assert "private_key_hex" in record
    assert "public_key_hex" in record
    if os.name == "posix":
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600, f"expected 0600, got 0o{mode:03o}"


def test_save_key_with_privkey_imports_existing():
    """`save --privkey <hex>` must derive the matching pubkey."""
    import tempfile

    kp = keys_mod.generate_keypair()
    sk_hex = kp["private_key_hex"]

    with tempfile.TemporaryDirectory() as td:
        path = keys_mod.save_key("imported", Path(td), privkey=sk_hex)
        record = json.loads(path.read_text(encoding="utf-8"))
        assert record["private_key_hex"] == sk_hex
        assert record["public_key_hex"] == kp["public_key_hex"]


def test_save_key_refuses_overwrite_by_default(tmp_path):
    keys_mod.save_key("bob", tmp_path)
    with pytest.raises(FileExistsError):
        keys_mod.save_key("bob", tmp_path)


def test_save_key_rejects_path_traversal(tmp_path):
    with pytest.raises(ValueError):
        keys_mod.save_key("../escape", tmp_path)
    with pytest.raises(ValueError):
        keys_mod.save_key("a/b", tmp_path)


def test_list_keys_returns_public_only(tmp_path):
    keys_mod.save_key("alice", tmp_path)
    keys_mod.save_key("bob", tmp_path)
    listing = keys_mod.list_keys(tmp_path)
    assert {entry["name"] for entry in listing} == {"alice", "bob"}
    for entry in listing:
        assert "private_key_hex" not in entry
        assert entry["public_key_hex"] is not None


def test_load_key_round_trips(tmp_path):
    keys_mod.save_key("carol", tmp_path)
    record = keys_mod.load_key("carol", tmp_path)
    assert record["name"] == "carol"
    assert "private_key_hex" in record


def test_delete_key_removes_file(tmp_path):
    keys_mod.save_key("dan", tmp_path)
    path = keys_mod.delete_key("dan", tmp_path)
    assert not path.exists()


def test_delete_key_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        keys_mod.delete_key("ghost", tmp_path)


# --------------------------------------------------------------------------- #
# CLI-level (`cli.main(["keys", ...])`)
# --------------------------------------------------------------------------- #


def _run_cli(argv, *, stdin_isatty=False):
    out, err = io.StringIO(), io.StringIO()
    with patch.object(sys.stdin, "isatty", return_value=stdin_isatty), redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_keys_new_json_payload_shape():
    rc, out, _ = _run_cli(["keys", "new", "--json"])
    assert rc == 0
    payload = json.loads(out)
    assert set(payload) == {"private_key_hex", "public_key_hex"}
    assert len(payload["private_key_hex"]) == 64
    assert len(payload["public_key_hex"]) == 96


def test_keys_new_human_format():
    rc, out, _ = _run_cli(["keys", "new"])
    assert rc == 0
    assert "Private Key" in out
    assert "Public Key" in out


def test_keys_save_creates_file_and_does_not_print_private(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    rc, out, err = _run_cli(["keys", "save", "--name", "alice"])
    assert rc == 0
    record = json.loads((tmp_path / "alice.json").read_text())
    private_hex = record["private_key_hex"]
    assert private_hex not in out
    assert private_hex not in err
    assert record["public_key_hex"] in out


def test_keys_save_with_privkey_imports_and_does_not_echo(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    kp = keys_mod.generate_keypair()
    sk_hex = kp["private_key_hex"]

    rc, out, err = _run_cli(
        ["keys", "save", "--name", "imp", "--privkey", sk_hex]
    )
    assert rc == 0
    record = json.loads((tmp_path / "imp.json").read_text())
    assert record["private_key_hex"] == sk_hex
    assert record["public_key_hex"] == kp["public_key_hex"]
    # Imported private key must not be echoed back to the user.
    assert sk_hex not in out
    assert sk_hex not in err


def test_keys_list_does_not_reveal_private(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())
    private_hex = record["private_key_hex"]

    rc, out_human, _ = _run_cli(["keys", "list"])
    assert rc == 0
    assert private_hex not in out_human

    rc, out_json, _ = _run_cli(["keys", "list", "--json"])
    assert rc == 0
    assert private_hex not in out_json
    listing = json.loads(out_json)
    assert listing and "private_key_hex" not in listing[0]


def test_keys_show_default_hides_private(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())
    private_hex = record["private_key_hex"]

    rc, out, _ = _run_cli(["keys", "show", "alice"])
    assert rc == 0
    assert private_hex not in out
    assert record["public_key_hex"] in out


def test_keys_show_private_reveals(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("alice", tmp_path)
    record = json.loads((tmp_path / "alice.json").read_text())

    rc, out, _ = _run_cli(["keys", "show", "alice", "--private"])
    assert rc == 0
    assert record["private_key_hex"] in out


def test_keys_delete_yes_bypasses_prompt(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("victim", tmp_path)
    rc, _, _ = _run_cli(["keys", "delete", "victim", "--yes"])
    assert rc == 0
    assert not (tmp_path / "victim.json").exists()


def test_keys_delete_non_tty_without_yes_exits_4(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    keys_mod.save_key("survivor", tmp_path)
    rc, _, err = _run_cli(["keys", "delete", "survivor"], stdin_isatty=False)
    assert rc == 4
    assert "non-interactive" in err.lower() or "--yes" in err
    assert (tmp_path / "survivor.json").exists()


def test_keys_save_existing_returns_exit_4(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    rc, _, _ = _run_cli(["keys", "save", "--name", "alice"])
    assert rc == 0
    rc, _, err = _run_cli(["keys", "save", "--name", "alice"])
    assert rc == 4
    assert "already exists" in err.lower()


def test_keys_show_missing_returns_exit_4(tmp_path, monkeypatch):
    monkeypatch.setattr(keys_mod, "KEY_DIR_DEFAULT", tmp_path)
    rc, _, err = _run_cli(["keys", "show", "ghost"])
    assert rc == 4
    assert "not found" in err.lower()
