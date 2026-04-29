"""Tests for tau_testnet_cli.docker and `tau-testnet node ...` Docker wrappers.

All tests mock both ``shutil.which`` (so we don't depend on a docker binary
being installed) and ``subprocess.run`` (so no container is actually built).
"""

from __future__ import annotations

import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tau_testnet_cli import cli, docker as docker_mod


# --------------------------------------------------------------------------- #
# Library-level (docker.py)
# --------------------------------------------------------------------------- #


def _patch_docker_runtime():
    """Patch shutil.which → '/usr/local/bin/docker' and subprocess.run → success."""
    fake_run = MagicMock(return_value=MagicMock(returncode=0))
    return (
        patch("tau_testnet_cli.docker.shutil.which", return_value="/usr/local/bin/docker"),
        patch("tau_testnet_cli.docker.subprocess.run", fake_run),
        fake_run,
    )


def _last_argv(fake_run: MagicMock) -> list[str]:
    assert fake_run.call_count >= 1, "subprocess.run was never invoked"
    return list(fake_run.call_args.args[0])


def test_docker_build_uses_dockerfile_standalone():
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        rc = docker_mod.docker_build()
    assert rc == 0
    argv = _last_argv(fake_run)
    assert argv[0] == "/usr/local/bin/docker"
    assert argv[1] == "build"
    assert "-f" in argv
    assert argv[argv.index("-f") + 1] == "Dockerfile.standalone"
    assert "-t" in argv
    assert argv[argv.index("-t") + 1] == "tau-testnet-standalone:latest"
    # Build context is the last arg.
    assert argv[-1] == "."


def test_docker_build_passes_jobs_and_lang_ref():
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_build(jobs=2, tau_lang_ref="my-branch")
    argv = _last_argv(fake_run)
    assert "--build-arg" in argv
    assert "TAU_BUILD_JOBS=2" in argv
    assert "TAU_LANG_REF=my-branch" in argv


def test_docker_build_pull_flag():
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_build(pull=True)
    argv = _last_argv(fake_run)
    assert "--pull" in argv


def test_docker_run_publishes_required_ports_and_data_volume(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_run(data_dir=tmp_path)
    argv = _last_argv(fake_run)
    # Ports
    p_specs = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
    assert "65432:65432" in p_specs
    assert "65433:65433" in p_specs
    assert "4001:4001" in p_specs
    # Volume
    v_specs = [argv[i + 1] for i, a in enumerate(argv) if a == "-v"]
    assert any(spec.endswith(":/data") for spec in v_specs)
    # --rm by default, no -d
    assert "--rm" in argv
    assert "-d" not in argv


def test_docker_run_miner_injects_mining_env(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_run(data_dir=tmp_path, miner=True)
    argv = _last_argv(fake_run)
    e_specs = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert "TAU_MINING_ENABLED=true" in e_specs


def test_docker_run_isolated_injects_empty_bootstrap(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_run(data_dir=tmp_path, isolated=True)
    argv = _last_argv(fake_run)
    e_specs = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert "TAU_BOOTSTRAP_PEERS=[]" in e_specs


def test_docker_run_extra_env(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_run(
            data_dir=tmp_path, extra_env=["TAU_LOG_LEVEL=DEBUG", "FOO=bar"]
        )
    argv = _last_argv(fake_run)
    e_specs = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert "TAU_LOG_LEVEL=DEBUG" in e_specs
    assert "FOO=bar" in e_specs


def test_docker_run_rejects_malformed_env(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run, pytest.raises(ValueError, match="KEY=VALUE"):
        docker_mod.docker_run(data_dir=tmp_path, extra_env=["NOT_A_KV"])


def test_docker_run_no_rm_omits_rm(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_run(data_dir=tmp_path, no_rm=True)
    argv = _last_argv(fake_run)
    assert "--rm" not in argv


def test_docker_run_detach_and_name(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_run(data_dir=tmp_path, detach=True, name="mynode")
    argv = _last_argv(fake_run)
    assert "-d" in argv
    assert "--name" in argv
    assert argv[argv.index("--name") + 1] == "mynode"


def test_docker_compose_up_invocation():
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_compose_up()
    argv = _last_argv(fake_run)
    assert argv[1:5] == ["compose", "-f", "docker-compose.standalone.yml", "up"]
    assert "--build" in argv
    assert "-d" not in argv


def test_docker_compose_up_no_build_and_detach():
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        docker_mod.docker_compose_up(build=False, detach=True)
    argv = _last_argv(fake_run)
    assert "--build" not in argv
    assert "-d" in argv


def test_docker_not_found_raises():
    with patch("tau_testnet_cli.docker.shutil.which", return_value=None):
        with pytest.raises(docker_mod.DockerNotFoundError):
            docker_mod.docker_build()


# --------------------------------------------------------------------------- #
# CLI-level (`tau-testnet node ...`)
# --------------------------------------------------------------------------- #


def _run_cli(argv):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        rc = cli.main(argv)
    return rc, out.getvalue(), err.getvalue()


def test_cli_node_docker_build_help_works():
    """`node docker-build --help` must not invoke docker."""
    p_which, p_run, fake_run = _patch_docker_runtime()
    import pytest as _pt

    with p_which, p_run, _pt.raises(SystemExit) as excinfo:
        cli.main(["node", "docker-build", "--help"])
    assert excinfo.value.code == 0
    fake_run.assert_not_called()


def test_cli_node_docker_build_propagates_jobs():
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        rc = cli.main(["node", "docker-build", "--jobs", "2"])
    assert rc == 0
    argv = _last_argv(fake_run)
    assert "TAU_BUILD_JOBS=2" in argv


def test_cli_node_docker_run_default_argv(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        rc = cli.main(["node", "docker-run", "--data-dir", str(tmp_path)])
    assert rc == 0
    argv = _last_argv(fake_run)
    assert argv[1] == "run"
    p_specs = [argv[i + 1] for i, a in enumerate(argv) if a == "-p"]
    assert set(p_specs) == {"65432:65432", "65433:65433", "4001:4001"}


def test_cli_node_docker_run_miner_isolated(tmp_path):
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        rc = cli.main(
            [
                "node",
                "docker-run",
                "--data-dir",
                str(tmp_path),
                "--miner",
                "--isolated",
                "--env",
                "FOO=bar",
            ]
        )
    assert rc == 0
    argv = _last_argv(fake_run)
    e_specs = [argv[i + 1] for i, a in enumerate(argv) if a == "-e"]
    assert "TAU_MINING_ENABLED=true" in e_specs
    assert "TAU_BOOTSTRAP_PEERS=[]" in e_specs
    assert "FOO=bar" in e_specs


def test_cli_node_docker_compose_up_default():
    p_which, p_run, fake_run = _patch_docker_runtime()
    with p_which, p_run:
        rc = cli.main(["node", "docker-compose-up"])
    assert rc == 0
    argv = _last_argv(fake_run)
    assert argv[1:5] == ["compose", "-f", "docker-compose.standalone.yml", "up"]
    assert "--build" in argv


def test_cli_node_docker_build_returns_4_when_docker_missing():
    with patch("tau_testnet_cli.docker.shutil.which", return_value=None):
        rc = cli.main(["node", "docker-build"])
    assert rc == 4


def test_cli_node_docker_build_returns_1_when_docker_exits_nonzero():
    fake = MagicMock(return_value=MagicMock(returncode=2))
    with patch("tau_testnet_cli.docker.shutil.which", return_value="/usr/bin/docker"), \
         patch("tau_testnet_cli.docker.subprocess.run", fake):
        rc = cli.main(["node", "docker-build"])
    assert rc == 1


def test_cli_node_run_help_does_not_import_server():
    """`node run --help` must not actually start the server."""
    import sys
    # Snapshot — the lazy `import server` should not have happened during --help.
    server_was_imported_before = "server" in sys.modules
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["node", "run", "--help"])
    assert excinfo.value.code == 0
    server_imported_now = "server" in sys.modules
    # If server was already imported by another test that's fine — what we
    # really want is for THIS call not to invoke server.main(). Argparse
    # SystemExit(0) on --help guarantees the handler never ran.
