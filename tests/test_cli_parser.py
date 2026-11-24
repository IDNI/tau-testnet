"""Tests for the tau-testnet CLI argparse tree (Phase 1 commands)."""

from __future__ import annotations

import io
import json
import subprocess
import sys
from contextlib import redirect_stderr, redirect_stdout

import pytest

from tau_testnet_cli import cli, __version__


# --------------------------------------------------------------------------- #
# In-process --help / misuse coverage (fast)
# --------------------------------------------------------------------------- #


PHASE1_HELP_TARGETS = [
    [],
    ["version"],
    ["ping"],
    ["status"],
    ["rpc"],
    ["balance"],
    ["sequence"],
    ["history"],
    ["mempool"],
    ["blocks"],
    ["accounts"],
    ["tau-state"],
    ["governance"],
    ["update-id"],
]


@pytest.mark.parametrize("argv", PHASE1_HELP_TARGETS)
def test_help_exits_zero(argv):
    """Every subcommand --help must parse cleanly and exit 0."""
    buf = io.StringIO()
    with redirect_stdout(buf), pytest.raises(SystemExit) as excinfo:
        cli.main(argv + ["--help"])
    assert excinfo.value.code == 0
    output = buf.getvalue()
    assert "usage:" in output.lower() or "tau-testnet" in output


def test_unknown_subcommand_exit_code_2():
    err = io.StringIO()
    with redirect_stderr(err), pytest.raises(SystemExit) as excinfo:
        cli.main(["definitely-not-a-command"])
    assert excinfo.value.code == 2


def test_missing_subcommand_exit_code_2():
    err = io.StringIO()
    with redirect_stderr(err), pytest.raises(SystemExit) as excinfo:
        cli.main([])
    assert excinfo.value.code == 2


def test_balance_missing_address_exit_code_2():
    err = io.StringIO()
    with redirect_stderr(err), pytest.raises(SystemExit) as excinfo:
        cli.main(["balance"])
    assert excinfo.value.code == 2


def test_update_id_requires_input_source():
    """--file / --json are mutually exclusive AND required."""
    err = io.StringIO()
    with redirect_stderr(err), pytest.raises(SystemExit) as excinfo:
        cli.main(["update-id"])
    assert excinfo.value.code == 2


# --------------------------------------------------------------------------- #
# `version` actually executes (no network)
# --------------------------------------------------------------------------- #


def test_version_human(capsys):
    rc = cli.main(["version"])
    assert rc == 0
    out = capsys.readouterr().out.strip()
    # Either the editable-install metadata version or the package __version__.
    assert out in {__version__, "0.1.0"} or out.count(".") >= 1


def test_version_json(capsys):
    rc = cli.main(["--json", "version"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert "version" in payload


# --------------------------------------------------------------------------- #
# Subprocess sanity: `python -m tau_testnet_cli --help` works
# --------------------------------------------------------------------------- #


def test_python_dash_m_help_works():
    """`python -m tau_testnet_cli --help` must run cleanly out-of-process."""
    result = subprocess.run(
        [sys.executable, "-m", "tau_testnet_cli", "--help"],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert "tau-testnet" in result.stdout


# --------------------------------------------------------------------------- #
# --fee only where it can change something
# --------------------------------------------------------------------------- #

_PK = "ab" * 48
_ID = "cd" * 32


@pytest.mark.parametrize("argv", [
    ["approval", "approve", "--key", "k", _ID],
    ["approval", "decline", "--key", "k", _ID],
    ["retractable", "retract", "--key", "k", _ID],
    ["gov", "propose", "--key", "k", "--file", "update.json"],
    ["gov", "vote", "--key", "k", "--update-id", _ID],
])
def test_fee_exempt_commands_have_no_fee_flag(argv):
    assert callable(cli.build_parser().parse_args(argv).func)
    with redirect_stderr(io.StringIO()), pytest.raises(SystemExit) as exc:
        cli.build_parser().parse_args(argv + ["--fee", "5"])
    assert exc.value.code == 2


@pytest.mark.parametrize("argv", [
    ["tx", "send", "--key", "k", "--to", _PK, "--amount", "1"],
    ["rule", "offer", "--key", "k", "--to", _PK, "--rule", "always ( o5[t] = 1 )."],
    ["rule", "accept", "--key", "k", _ID],
    ["rule", "reject", "--key", "k", _ID],
    ["approval", "request", "--key", "k", "--to", _PK, "--amount", "1"],
    ["retractable", "send", "--key", "k", "--to", _PK, "--amount", "1",
     "--release-in", "3"],
])
def test_fee_bearing_commands_default_to_the_node_estimate(argv):
    assert cli.build_parser().parse_args(argv).fee is None
    assert cli.build_parser().parse_args(argv + ["--fee", "7"]).fee == "7"
