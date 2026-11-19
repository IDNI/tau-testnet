"""Tests for `tau-testnet policy receive ...` (recipient-controls composition).

These exercise pure text composition: the helpers print an `always ( ... ).`
unit and a registration guide, touch no node and sign nothing, so they run on a
build where the consensus feature (issues #47 / #76) has not landed yet. The
hold stream indices are read from tau_defs when the core agent defines them and
fall back to the frozen literals 17/27 until then.
"""
from __future__ import annotations

import io
import json
from contextlib import redirect_stderr, redirect_stdout
from unittest.mock import patch

import pytest

import tau_defs
from tau_testnet_cli import cli, keys as keys_mod

PK_A = "aa" * 48
PK_B = "bb" * 48
PK_SHOP = "cc" * 48

ALLOW = "(o5[t]:bv[24] = { #x000001 }:bv[24])"
BLOCK = "(o5[t]:bv[24] = { #x000000 }:bv[24])"


def _run(argv, recorded=None):
    """Run the CLI offline. Any node call is a test failure: receive composes
    text only."""
    def fake_send(command, host, port, *, timeout=10.0, max_bytes=None):
        if recorded is not None:
            recorded.append(command)
        raise AssertionError(f"policy receive must not touch the node: {command!r}")

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


def _i3(pk):
    return f"(i3[t]:bv[384] = {{ #x{pk} }}:bv[384])"


# --- verdict width and values (verified against tau_defs, not guessed) -------


def test_verdict_uses_the_consensus_pinned_o5_width_and_values():
    allow, block = cli._receive_verdict()
    width = tau_defs.USER_POLICY_BV_WIDTH
    assert width == 24  # frozen: o5 is bv[24], not bv[16]
    digits = width // 4
    assert allow == (
        f"(o5[t]:bv[{width}] = "
        f"{{ #x{tau_defs.USER_POLICY_ALLOW_VALUE:0{digits}x} }}:bv[{width}])"
    )
    assert block == (
        f"(o5[t]:bv[{width}] = "
        f"{{ #x{tau_defs.USER_POLICY_BLOCK_VALUE:0{digits}x} }}:bv[{width}])"
    )
    assert tau_defs.USER_POLICY_ALLOW_VALUE == 1
    assert tau_defs.USER_POLICY_BLOCK_VALUE == 0


def test_hold_indices_prefer_tau_defs_constants_when_present():
    sec = getattr(tau_defs, "HOLD_SECONDS_STREAM_INDEX", None)
    blk = getattr(tau_defs, "HOLD_BLOCKS_STREAM_INDEX", None)
    if sec is None or blk is None:
        pytest.skip("core HOLD_*_STREAM_INDEX constants not landed yet")
    assert cli._receive_stream_indices() == (sec, blk)
    clause = cli.compose_receive_max_hold(600, 10)
    assert f"i{sec}[t]:bv[64] <= {{ 600 }}:bv[64]" in clause
    assert f"i{blk}[t]:bv[64] <= {{ 10 }}:bv[64]" in clause


def test_hold_indices_fall_back_to_the_frozen_literals():
    # Works whether or not the core constants exist: the contract is i17/i27.
    sec, blk = cli._receive_stream_indices()
    assert (sec, blk) == (
        getattr(tau_defs, "HOLD_SECONDS_STREAM_INDEX", 17),
        getattr(tau_defs, "HOLD_BLOCKS_STREAM_INDEX", 27),
    )


# --- max-hold ----------------------------------------------------------------


def test_max_hold_seconds_exact_unit():
    rc, out, err = _run(["policy", "receive", "max-hold", "--max-hold-seconds", "600"])
    assert rc == 0, err
    assert out.strip() == (
        "always ( i17[t]:bv[64] <= { 600 }:bv[64] "
        f"? {ALLOW} : {BLOCK} )."
    )


def test_max_hold_blocks_only():
    rc, out, _ = _run(["policy", "receive", "max-hold", "--max-hold-blocks", "10"])
    assert rc == 0
    assert out.strip() == (
        "always ( i27[t]:bv[64] <= { 10 }:bv[64] "
        f"? {ALLOW} : {BLOCK} )."
    )


def test_max_hold_both_streams():
    clause = cli.compose_receive_max_hold(600, 10)
    assert clause == (
        "always ( ( i17[t]:bv[64] <= { 600 }:bv[64] "
        "&& i27[t]:bv[64] <= { 10 }:bv[64] ) "
        f"? {ALLOW} : {BLOCK} )."
    )


def test_instant_only_shape_bounds_both_streams_at_zero():
    rc, out, _ = _run([
        "policy", "receive", "max-hold",
        "--max-hold-seconds", "0", "--max-hold-blocks", "0",
    ])
    assert rc == 0
    assert out.strip() == (
        "always ( ( i17[t]:bv[64] <= { 0 }:bv[64] "
        "&& i27[t]:bv[64] <= { 0 }:bv[64] ) "
        f"? {ALLOW} : {BLOCK} )."
    )


def test_seconds_cap_zero_alone_warns_about_height_parks():
    rc, out, err = _run(["policy", "receive", "max-hold", "--max-hold-seconds", "0"])
    assert rc == 0
    assert "i17[t]:bv[64] <= { 0 }:bv[64]" in out
    assert "i27" not in out
    assert "--max-hold-blocks 0" in err


def test_max_hold_requires_a_flag():
    rc, _, err = _run(["policy", "receive", "max-hold"])
    assert rc == cli.EXIT_LOCAL
    assert "--max-hold-seconds" in err


@pytest.mark.parametrize("flag", ["--max-hold-seconds", "--max-hold-blocks"])
def test_negative_cap_is_refused(flag):
    rc, _, err = _run(["policy", "receive", "max-hold", flag, "-1"])
    assert rc == cli.EXIT_LOCAL
    assert "between 0" in err


def test_cap_overflowing_bv64_is_refused():
    rc, _, err = _run([
        "policy", "receive", "max-hold", "--max-hold-seconds", str(1 << 64),
    ])
    assert rc == cli.EXIT_LOCAL


# --- allow-list --------------------------------------------------------------


def test_allow_list_single_sender_exact_unit():
    rc, out, _ = _run(["policy", "receive", "allow-list", PK_A])
    assert rc == 0
    assert out.strip() == f"always ( {_i3(PK_A)} ? {ALLOW} : {BLOCK} )."


def test_allow_list_multi_address_is_a_disjunction():
    rc, out, _ = _run(["policy", "receive", "allow-list", PK_A, PK_B])
    assert rc == 0
    assert out.strip() == (
        f"always ( ( {_i3(PK_A)} || {_i3(PK_B)} ) ? {ALLOW} : {BLOCK} )."
    )


def test_allow_list_normalizes_and_dedupes():
    clause = cli.compose_receive_allow_list(["0x" + PK_A.upper(), PK_A, PK_B])
    assert clause.count(_i3(PK_A)) == 1
    assert clause.count(_i3(PK_B)) == 1
    assert "#x" + PK_A in clause  # lowercase, no 0x inside the literal


def test_allow_list_with_key_includes_the_owner_first(alice):
    rc, out, err = _run(["policy", "receive", "allow-list", "--key", "alice", PK_A])
    assert rc == 0, err
    assert out.strip() == (
        f"always ( ( {_i3(alice)} || {_i3(PK_A)} ) ? {ALLOW} : {BLOCK} )."
    )
    assert "omits your own pubkey" not in err


def test_allow_list_without_key_warns_about_outbound(alice):
    rc, out, err = _run(["policy", "receive", "allow-list", PK_A])
    assert rc == 0
    assert alice not in out
    assert "omits your own pubkey" in err


def test_allow_list_rejects_a_bad_pubkey():
    rc, _, err = _run(["policy", "receive", "allow-list", "nothex"])
    assert rc == cli.EXIT_LOCAL
    assert "96-character hex" in err


def test_allow_list_over_the_comparison_limit_is_refused():
    keys = [f"{i:096x}" for i in range(33)]
    with pytest.raises(cli._PayloadError):
        cli.compose_receive_allow_list(keys)


def test_allow_list_empty_is_refused():
    with pytest.raises(cli._PayloadError):
        cli.compose_receive_allow_list([])


# --- combined ----------------------------------------------------------------


def test_combined_scopes_every_inbound_conjunct_by_the_owner(alice):
    rc, out, err = _run([
        "policy", "receive", "combined", "--key", "alice",
        "--send-to", PK_SHOP, "--allow-from", PK_A,
        "--max-hold-seconds", "600", "--max-hold-blocks", "10",
    ])
    assert rc == 0, err
    clause = out.strip()
    mine = _i3(alice)
    # outbound whitelist: when I send, recipient must be the shop
    assert f"( !{mine} || {_i3(PK_SHOP).replace('i3', 'i4')} )" in clause
    # inbound allow-list: me or A
    assert f"( {mine} || {_i3(PK_A)} )" in clause
    # caps scoped to incoming payments, canonical comparisons
    assert f"( {mine} || i17[t]:bv[64] <= {{ 600 }}:bv[64] )" in clause
    assert f"( {mine} || i27[t]:bv[64] <= {{ 10 }}:bv[64] )" in clause
    assert clause.startswith("always ( ") and clause.endswith(" ).")
    assert clause.count("?") == 1 and clause.count("always") == 1


def test_combined_requires_a_key():
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(
            ["policy", "receive", "combined", "--allow-from", PK_A]
        )
    assert exc.value.code == cli.EXIT_USAGE  # argparse: --key/--privkey required


def test_combined_requires_at_least_one_constraint(alice):
    rc, _, err = _run(["policy", "receive", "combined", "--key", "alice"])
    assert rc == cli.EXIT_LOCAL
    assert "at least one" in err


def test_combined_drops_the_owner_from_the_inbound_list(alice):
    clause = cli.compose_receive_combined(alice, [], [alice, PK_A], None, None)
    # owner already covered by the `mine` term; not duplicated
    assert clause.count(_i3(alice)) == 1
    assert _i3(PK_A) in clause


def test_combined_outbound_only(alice):
    clause = cli.compose_receive_combined(alice, [PK_SHOP], [], None, None)
    assert "i4[t]:bv[384]" in clause
    assert "i17" not in clause and "i27" not in clause


# --- output contract ---------------------------------------------------------


def test_clause_on_stdout_guide_on_stderr():
    rc, out, err = _run(["policy", "receive", "max-hold", "--max-hold-seconds", "600"])
    assert rc == 0
    # stdout is exactly the unit, so `> receive.tau` gives a clean file
    assert out.startswith("always ( ") and out.rstrip().endswith(" ).")
    assert out.count("\n") == 1
    assert "tau-testnet tx send" in err
    assert "policy change request" in err


def test_json_mode_emits_clause_and_registration():
    rc, out, _ = _run([
        "--json", "policy", "receive", "allow-list", PK_A, PK_B,
    ])
    assert rc == 0
    data = json.loads(out)
    assert data["clause"].startswith("always ( ")
    assert "tx send" in data["register"]["direct"]
    assert "policy change request" in data["register"]["guarded"]
    assert isinstance(data["notes"], list)


def test_receive_never_calls_the_node():
    recorded = []
    rc, _, _ = _run(["policy", "receive", "max-hold", "--max-hold-blocks", "5"], recorded)
    assert rc == 0
    assert recorded == []


# --- parser wiring -----------------------------------------------------------


@pytest.mark.parametrize("argv", [
    ["policy", "receive"],
    ["policy", "receive", "allow-list"],
    ["policy", "receive", "max-hold"],
    ["policy", "receive", "combined"],
])
def test_receive_help_exits_zero(argv):
    buf = io.StringIO()
    with redirect_stdout(buf), pytest.raises(SystemExit) as exc:
        cli.main(argv + ["--help"])
    assert exc.value.code == 0
    assert "usage:" in buf.getvalue().lower()


def test_unknown_receive_subcommand_exits_two():
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as exc:
        cli.main(["policy", "receive", "definitely-not"])
    assert exc.value.code == 2


def test_receive_is_registered_under_policy():
    args = cli.build_parser().parse_args(
        ["policy", "receive", "max-hold", "--max-hold-seconds", "600"]
    )
    assert args.policy_command == "receive"
    assert args.receive_command == "max-hold"
    assert callable(args.func)
