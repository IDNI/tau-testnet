"""Tests for `tau-testnet node run` flag semantics.

`apply_node_run_env` is the env-mapping helper invoked by `cmd_node_run`.
It is exercised in isolation here — the CLI handler also imports/runs
`server.main()`, which we never trigger from the test suite.
"""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout

import pytest

from tau_testnet_cli import cli


def _parse(argv):
    """Run argparse on `node run` argv with no main() invocation."""
    parser = cli.build_parser()
    return parser.parse_args(["node", "run", *argv])


def _apply(argv: list[str], shell_env: dict | None = None) -> dict:
    args = _parse(argv)
    env = dict(shell_env or {})
    cli.apply_node_run_env(args, env)
    return env


# --------------------------------------------------------------------------- #
# --test default behavior
# --------------------------------------------------------------------------- #


def test_test_implies_miner_and_isolated():
    env = _apply(["--test"])
    assert env["TAU_ENV"] == "test"
    assert env["TAU_FORCE_TEST"] == "1"
    assert env["TAU_MINING_ENABLED"] == "true"
    assert env["TAU_BOOTSTRAP_PEERS"] == "[]"


def test_test_with_no_miner_disables_mining():
    env = _apply(["--test", "--no-miner"])
    assert env["TAU_ENV"] == "test"
    assert env["TAU_FORCE_TEST"] == "1"
    assert env["TAU_MINING_ENABLED"] == "false"
    # isolated default still applies
    assert env["TAU_BOOTSTRAP_PEERS"] == "[]"


def test_test_with_no_isolated_drops_bootstrap_override():
    env = _apply(["--test", "--no-isolated"])
    assert env["TAU_MINING_ENABLED"] == "true"
    assert "TAU_BOOTSTRAP_PEERS" not in env


def test_test_with_no_miner_no_isolated_only_sets_env_flags():
    env = _apply(["--test", "--no-miner", "--no-isolated"])
    assert env["TAU_ENV"] == "test"
    assert env["TAU_FORCE_TEST"] == "1"
    assert env["TAU_MINING_ENABLED"] == "false"
    assert "TAU_BOOTSTRAP_PEERS" not in env


# --------------------------------------------------------------------------- #
# Without --test
# --------------------------------------------------------------------------- #


def test_no_flags_leaves_env_untouched():
    env = _apply([])
    assert env == {}


def test_explicit_miner_without_test():
    env = _apply(["--miner"])
    assert env["TAU_MINING_ENABLED"] == "true"
    assert "TAU_ENV" not in env
    assert "TAU_BOOTSTRAP_PEERS" not in env


def test_explicit_isolated_without_test():
    env = _apply(["--isolated"])
    assert env["TAU_BOOTSTRAP_PEERS"] == "[]"
    assert "TAU_MINING_ENABLED" not in env


def test_no_miner_alone_forces_off():
    env = _apply(["--no-miner"])
    assert env["TAU_MINING_ENABLED"] == "false"


def test_fresh_sets_force_fresh_start():
    env = _apply(["--fresh"])
    assert env["TAU_FORCE_FRESH_START"] == "1"


# --------------------------------------------------------------------------- #
# Shell-env interaction (setdefault semantics)
# --------------------------------------------------------------------------- #


def test_shell_env_wins_when_implicit():
    """--test implies miner=true via setdefault → shell value wins."""
    env = _apply(["--test"], shell_env={"TAU_MINING_ENABLED": "false"})
    assert env["TAU_MINING_ENABLED"] == "false"


def test_explicit_flag_overrides_shell_env():
    """Explicit --miner overrides whatever the shell exported."""
    env = _apply(["--miner"], shell_env={"TAU_MINING_ENABLED": "false"})
    assert env["TAU_MINING_ENABLED"] == "true"


def test_explicit_no_miner_overrides_shell_env():
    env = _apply(["--no-miner"], shell_env={"TAU_MINING_ENABLED": "true"})
    assert env["TAU_MINING_ENABLED"] == "false"


def test_explicit_isolated_overrides_shell_env():
    env = _apply(
        ["--isolated"],
        shell_env={"TAU_BOOTSTRAP_PEERS": '["abc"]'},
    )
    assert env["TAU_BOOTSTRAP_PEERS"] == "[]"


# --------------------------------------------------------------------------- #
# --listen normalization
# --------------------------------------------------------------------------- #


def test_listen_multiaddr_passthrough():
    env = _apply(["--listen", "/ip4/127.0.0.1/tcp/4001"])
    assert env["TAU_NETWORK_LISTEN"] == "/ip4/127.0.0.1/tcp/4001"


def test_listen_host_port_shorthand():
    env = _apply(["--listen", "127.0.0.1:4001"])
    assert env["TAU_NETWORK_LISTEN"] == "/ip4/127.0.0.1/tcp/4001"


def test_listen_zero_address_shorthand():
    env = _apply(["--listen", "0.0.0.0:4001"])
    assert env["TAU_NETWORK_LISTEN"] == "/ip4/0.0.0.0/tcp/4001"


def test_listen_invalid_format_raises():
    with pytest.raises(ValueError):
        _apply(["--listen", "no-port-here"])


def test_listen_overrides_shell_env():
    env = _apply(
        ["--listen", "127.0.0.1:4001"],
        shell_env={"TAU_NETWORK_LISTEN": "/ip4/0.0.0.0/tcp/4001"},
    )
    assert env["TAU_NETWORK_LISTEN"] == "/ip4/127.0.0.1/tcp/4001"


def test_node_run_reload_applies_listen_to_settings(monkeypatch):
    """`config` is imported before `node run`; reload must pick up --listen."""
    import os

    import config

    # Simulate CLI startup: config loaded without TAU_NETWORK_LISTEN.
    monkeypatch.delenv("TAU_NETWORK_LISTEN", raising=False)
    config.reload_settings()
    assert config.settings.network.listen == ["/ip4/0.0.0.0/tcp/0"]

    monkeypatch.setenv("TAU_NETWORK_LISTEN", "/ip4/127.0.0.1/tcp/4001")
    args = _parse(["--listen", "127.0.0.1:4001"])
    cli.apply_node_run_env(args, os.environ)
    config.reload_settings()
    assert config.settings.network.listen == ["/ip4/127.0.0.1/tcp/4001"]


def test_open_governance_sets_env_with_isolated():
    env = _apply(["--isolated", "--open-governance"])
    assert env["TAU_BOOTSTRAP_PEERS"] == "[]"
    assert env["TAU_GOVERNANCE_OPEN_ADMISSION"] == "true"


def test_open_governance_sets_env_with_test():
    env = _apply(["--test", "--open-governance"])
    assert env["TAU_GOVERNANCE_OPEN_ADMISSION"] == "true"


def test_open_governance_without_isolated_raises():
    with pytest.raises(ValueError, match="--open-governance requires"):
        _apply(["--open-governance"])


def test_open_governance_with_test_no_isolated_raises():
    with pytest.raises(ValueError, match="--open-governance requires"):
        _apply(["--test", "--no-isolated", "--open-governance"])


def test_no_open_governance_explicit_sets_false():
    env = _apply(["--isolated", "--no-open-governance"])
    assert env["TAU_GOVERNANCE_OPEN_ADMISSION"] == "false"


# --------------------------------------------------------------------------- #
# Argparse surface
# --------------------------------------------------------------------------- #


def test_node_run_help_works():
    err, out = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err), pytest.raises(SystemExit) as exc:
        cli.main(["node", "run", "--help"])
    assert exc.value.code == 0
    assert "--test" in out.getvalue()
    assert "--no-miner" in out.getvalue()
    assert "--no-isolated" in out.getvalue()
    assert "--open-governance" in out.getvalue()
    assert "--listen" in out.getvalue()
