"""Tests for `tau-testnet retractable ...`, on the canned-response harness."""
from __future__ import annotations

import io
import json
import time
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

from consensus.retractable import (
    KIND_HEIGHT,
    KIND_TIME,
    parse_retract_transfer,
    parse_retractable_transfer,
)
from consensus.tx_signing import verify_tx_signature
from tau_testnet_cli import cli, keys as keys_mod, tx as tx_mod

RID = "ab" * 32
OTHER = "bb" * 48
TIP = 7


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
    return json.loads((tmp_path / "alice.json").read_text())["public_key_hex"]


def _ok(data):
    return json.dumps({"status": "ok", "command": "x", "data": data})


def _sent_payload(recorded):
    sendtx = next(c for c in recorded if c.startswith("sendtx "))
    blob = sendtx[len("sendtx "):].strip()
    if blob.startswith("'") and blob.endswith("'"):
        blob = blob[1:-1]
    return json.loads(blob)


def _send(argv, tip=TIP, seq=3):
    recorded = []
    rc, out, err = _run_cli(
        argv,
        send_responses=[_ok({"sequence_number": seq, "tip_height": tip}), _ok({"tx_hash": "de"})],
        recorded=recorded,
    )
    return rc, out, err, recorded


# --- parser -------------------------------------------------------------------


@pytest.mark.parametrize("argv", [
    ["retractable", "send", "--key", "k", "--to", OTHER, "--amount", "5", "--release-in", "3"],
    ["retractable", "send", "--key", "k", "--to", OTHER, "--amount", "5", "--release-at-height", "90"],
    ["retractable", "send", "--privkey", "0x1", "--to", OTHER, "--amount", "5", "--release-at-time", "1790000000"],
    ["retractable", "send", "--key", "k", "--to", OTHER, "--amount", "5", "--release-after", "60"],
    ["retractable", "retract", "--key", "k", RID],
    ["retractable", "list", "--key", "k", "--role", "out"],
    ["retractable", "list", "--address", OTHER],
    ["retractable", "show", RID],
    ["retractable", "id", "--from-pubkey", OTHER, "--to", OTHER, "--amount", "5",
     "--sequence", "1", "--release-at-height", "9"],
    ["retractable", "id", "--from-pubkey", OTHER, "--to", OTHER, "--amount", "5",
     "--sequence", "1", "--release-at-time", "9"],
])
def test_every_subcommand_parses(argv):
    args = cli.build_parser().parse_args(argv)
    assert callable(args.func)


@pytest.mark.parametrize("argv", [
    ["retractable", "send", "--key", "k", "--to", OTHER, "--amount", "5"],
    ["retractable", "send", "--key", "k", "--to", OTHER, "--amount", "5",
     "--release-in", "3", "--release-after", "60"],
    ["retractable", "send", "--key", "k", "--to", OTHER, "--amount", "5", "--release-in", "0"],
    ["retractable", "send", "--to", OTHER, "--amount", "5", "--release-in", "3"],
    ["retractable", "id", "--from-pubkey", OTHER, "--to", OTHER, "--amount", "5", "--sequence", "1"],
    ["retractable"],
])
def test_bad_invocations_are_usage_errors(argv):
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(argv)
    assert exc.value.code == 2


# --- builders -----------------------------------------------------------------


def _signed(payload, privkey=0x1234):
    tx_mod.sign_tx(payload, privkey)
    return payload


def test_park_builder_signs_and_parses_height_kind():
    from py_ecc.bls import G2Basic

    sender = G2Basic.SkToPk(0x1234).hex()
    tx = tx_mod.build_retractable_transfer_tx(
        sender_pubkey=sender, sequence_number=2, expiration_time=2_000_000_000,
        expire_at_height=50, recipient_pubkey=OTHER.upper(), amount=9,
        release_at_height=80,
    )
    _signed(tx)

    ok, reason = verify_tx_signature(tx)
    assert ok, reason
    entry = parse_retractable_transfer(tx)
    assert (entry.kind, entry.release_at, entry.amount) == (KIND_HEIGHT, 80, 9)
    assert entry.recipient_pubkey == OTHER


def test_park_builder_signs_and_parses_time_kind():
    from py_ecc.bls import G2Basic

    sender = G2Basic.SkToPk(0x1234).hex()
    tx = _signed(tx_mod.build_retractable_transfer_tx(
        sender_pubkey=sender, sequence_number=0, expiration_time=1_000,
        expire_at_height=50, recipient_pubkey=OTHER, amount=1,
        release_at_time=2_000_000_000,
    ))
    assert verify_tx_signature(tx)[0]
    assert parse_retractable_transfer(tx).kind == KIND_TIME
    assert "release_at_height" not in tx


def test_signature_covers_the_release_point():
    from py_ecc.bls import G2Basic

    sender = G2Basic.SkToPk(0x1234).hex()
    tx = _signed(tx_mod.build_retractable_transfer_tx(
        sender_pubkey=sender, sequence_number=0, expiration_time=1_000,
        expire_at_height=50, recipient_pubkey=OTHER, amount=1, release_at_height=80,
    ))
    tx["release_at_height"] = 81
    assert not verify_tx_signature(tx)[0]


def test_retract_builder_signs_and_parses():
    from py_ecc.bls import G2Basic

    sender = G2Basic.SkToPk(0x1234).hex()
    tx = _signed(tx_mod.build_retract_transfer_tx(
        sender_pubkey=sender, sequence_number=4, expiration_time=2_000_000_000,
        expire_at_height=50, retractable_id=RID.upper(),
    ))
    assert verify_tx_signature(tx)[0]
    request = parse_retract_transfer(tx)
    assert request.retractable_id.hex() == RID
    assert tx["fee_limit"] == "0"


def test_height_clamp_never_leaves_the_deadline_after_release():
    tx = tx_mod.build_retractable_transfer_tx(
        sender_pubkey="a" * 96, sequence_number=0, expiration_time=10**10,
        expire_at_height=1000, recipient_pubkey=OTHER, amount=1, release_at_height=80,
    )
    assert tx["expire_at_height"] == 80
    assert tx["expiration_time"] == 10**10

    earlier = tx_mod.build_retractable_transfer_tx(
        sender_pubkey="a" * 96, sequence_number=0, expiration_time=10**10,
        expire_at_height=60, recipient_pubkey=OTHER, amount=1, release_at_height=80,
    )
    assert earlier["expire_at_height"] == 60


def test_time_clamp_keeps_the_deadline_strictly_before_release():
    tx = tx_mod.build_retractable_transfer_tx(
        sender_pubkey="a" * 96, sequence_number=0, expiration_time=5_000,
        expire_at_height=1000, recipient_pubkey=OTHER, amount=1, release_at_time=4_000,
    )
    assert tx["expiration_time"] == 3_999
    assert tx["expire_at_height"] == 1000

    sooner = tx_mod.build_retractable_transfer_tx(
        sender_pubkey="a" * 96, sequence_number=0, expiration_time=3_000,
        expire_at_height=1000, recipient_pubkey=OTHER, amount=1, release_at_time=4_000,
    )
    assert sooner["expiration_time"] == 3_000


@pytest.mark.parametrize("kwargs", [
    {},
    {"release_at_height": 5, "release_at_time": 5},
    {"release_at_height": 0},
    {"release_at_time": 0},
    {"release_at_height": True},
])
def test_park_builder_needs_exactly_one_valid_release(kwargs):
    with pytest.raises(ValueError):
        tx_mod.build_retractable_transfer_tx(
            sender_pubkey="a" * 96, sequence_number=0, expiration_time=10,
            expire_at_height=10, recipient_pubkey=OTHER, amount=1, **kwargs,
        )


def test_park_builder_validates_recipient_and_amount():
    base = dict(sender_pubkey="a" * 96, sequence_number=0, expiration_time=10,
                expire_at_height=10, release_at_height=5)
    with pytest.raises(ValueError):
        tx_mod.build_retractable_transfer_tx(recipient_pubkey="short", amount=1, **base)
    with pytest.raises(ValueError):
        tx_mod.build_retractable_transfer_tx(recipient_pubkey=OTHER, amount=0, **base)


def test_retract_builder_validates_id():
    with pytest.raises(ValueError):
        tx_mod.build_retract_transfer_tx(
            sender_pubkey="a" * 96, sequence_number=0, expiration_time=10,
            expire_at_height=10, retractable_id="abc",
        )


# --- send flows ---------------------------------------------------------------


def test_send_release_in_counts_from_the_next_height(alice):
    rc, out, err, recorded = _send(
        ["retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "12",
         "--release-in", "5"])
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "retractable_transfer"
    # tip 7 -> next 8 -> +5
    assert payload["release_at_height"] == 13
    assert payload["expire_at_height"] == 13
    assert payload["sequence_number"] == 3
    assert payload["amount"] == 12
    assert verify_tx_signature(payload)[0]
    assert not any(str(c).startswith("getblocks") for c in recorded)
    assert f"retractable id: {parse_retractable_transfer(payload).retractable_id.hex()}" in out


def test_send_at_height_with_room_keeps_a_shorter_expiry(alice):
    rc, _, err, recorded = _send(
        ["retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "1",
         "--release-at-height", "500", "--expire-in", "10"])
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert payload["release_at_height"] == 500
    assert payload["expire_at_height"] == TIP + 1 + 10


@pytest.mark.parametrize("height", [TIP, TIP + 1])
def test_send_refuses_a_release_at_or_before_the_next_block(alice, height):
    recorded = []
    rc, _, err = _run_cli(
        ["retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "1",
         "--release-at-height", str(height)],
        send_responses=[_ok({"sequence_number": 0, "tip_height": TIP})], recorded=recorded,
    )
    assert rc == cli.EXIT_LOCAL
    assert "release height" in err
    assert not any(c.startswith("sendtx") for c in recorded)


def test_send_at_time_clamps_the_envelope_expiry(alice):
    release = int(time.time()) + 100
    rc, _, err, recorded = _send(
        ["retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "1",
         "--release-at-time", str(release), "--expiry", "600"])
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert payload["release_at_time"] == release
    assert payload["expiration_time"] == release - 1
    assert "release_at_height" not in payload


def test_send_release_after_is_relative_to_now(alice):
    before = int(time.time())
    rc, _, err, recorded = _send(
        ["retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "1",
         "--release-after", "3600"])
    after = int(time.time())
    assert rc == 0, err
    release = _sent_payload(recorded)["release_at_time"]
    assert before + 3600 <= release <= after + 3600


def test_send_refuses_a_release_time_in_the_past(alice):
    recorded = []
    rc, _, err = _run_cli(
        ["retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "1",
         "--release-at-time", "5"],
        send_responses=[_ok({"sequence_number": 0, "tip_height": TIP})], recorded=recorded,
    )
    assert rc == cli.EXIT_LOCAL
    assert "past" in err
    assert not any(c.startswith("sendtx") for c in recorded)


def test_send_failure_prints_no_id(alice):
    recorded = []
    rc, out, _ = _run_cli(
        ["retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "1",
         "--release-in", "3"],
        send_responses=[
            _ok({"sequence_number": 0, "tip_height": TIP}),
            json.dumps({"status": "error", "command": "sendtx",
                        "error": {"code": "TX_REJECTED", "message": "no"}}),
        ],
        recorded=recorded,
    )
    assert rc == cli.EXIT_APP_ERROR
    assert "retractable id" not in out


def test_send_json_mode_keeps_stdout_machine_readable(alice):
    rc, out, err, _ = _send(
        ["--json", "retractable", "send", "--key", "alice", "--to", OTHER, "--amount", "1",
         "--release-in", "3"])
    assert rc == 0, err
    assert json.loads(out)["submitted"]["tx_type"] == "retractable_transfer"
    assert "retractable id:" in err


# --- retract / reads ----------------------------------------------------------


def test_retract_builds_a_signed_feeless_tx(alice):
    rc, _, err, recorded = _send(["retractable", "retract", "--key", "alice", RID])
    assert rc == 0, err
    payload = _sent_payload(recorded)
    assert payload["tx_type"] == "retract_transfer"
    assert payload["retractable_id"] == RID
    assert payload["sender_pubkey"] == alice
    assert payload["fee_limit"] == "0"
    assert verify_tx_signature(payload)[0]


def test_list_queries_getretractables_for_the_key_owner(alice):
    recorded = []
    rc, _, _ = _run_cli(["retractable", "list", "--key", "alice"],
                        send_responses=[_ok({})], recorded=recorded)
    assert rc == 0
    assert recorded == [f"getretractables {alice} all"]


def test_list_with_address_and_role():
    recorded = []
    _run_cli(["retractable", "list", "--address", OTHER, "--role", "in"],
             send_responses=[_ok({})], recorded=recorded)
    assert recorded == [f"getretractables {OTHER} in"]


def test_show_queries_getretractable():
    recorded = []
    rc, _, _ = _run_cli(["retractable", "show", RID], send_responses=[_ok({})], recorded=recorded)
    assert rc == 0
    assert recorded == [f"getretractable {RID}"]


def test_id_is_computed_locally_and_matches_the_book():
    recorded = []
    rc, out, _ = _run_cli(
        ["retractable", "id", "--from-pubkey", "aa" * 48, "--to", OTHER, "--amount", "40",
         "--sequence", "3", "--release-at-height", "900"],
        recorded=recorded,
    )
    from consensus.retractable import RetractableEntry

    expected = RetractableEntry("aa" * 48, OTHER, 40, 3, KIND_HEIGHT, 900).retractable_id.hex()
    assert rc == 0
    assert out.strip() == expected
    assert recorded == []


def test_id_rejects_a_malformed_pubkey():
    rc, _, err = _run_cli(
        ["retractable", "id", "--from-pubkey", "nope", "--to", OTHER, "--amount", "1",
         "--sequence", "0", "--release-at-time", "9"])
    assert rc == cli.EXIT_LOCAL
    assert "96" in err
