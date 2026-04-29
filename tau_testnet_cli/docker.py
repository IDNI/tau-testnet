"""Docker / docker-compose wrappers for the Tau Testnet CLI.

Each function builds an explicit ``docker ...`` argv and passes it to
:func:`subprocess.run`. No shell strings, no ``os.system``. The wrappers
reproduce the published port set (``65432``, ``65433``, ``4001``) and the
``/data`` volume mount used by ``scripts/run_standalone_node.sh`` and
``docker-compose.standalone.yml``.

Returns the exit code of the underlying ``docker`` invocation so the CLI
can surface failures via its own non-zero exit codes.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import Iterable, Sequence

logger = logging.getLogger(__name__)


DEFAULT_IMAGE = "tau-testnet-standalone:latest"
DEFAULT_DOCKERFILE = "Dockerfile.standalone"
DEFAULT_COMPOSE_FILE = "docker-compose.standalone.yml"
PUBLISHED_PORTS: tuple[str, ...] = ("65432:65432", "65433:65433", "4001:4001")
CONTAINER_DATA_DIR = "/data"


class DockerNotFoundError(RuntimeError):
    """Raised when the ``docker`` (or ``docker compose``) binary is missing."""


def _docker_path() -> str:
    path = shutil.which("docker")
    if not path:
        raise DockerNotFoundError(
            "docker binary not found on PATH; install Docker Desktop or the docker CLI"
        )
    return path


def _run(argv: Sequence[str]) -> int:
    """Echo the command then exec it; return the child's exit code."""
    logger.debug("docker invocation: %s", " ".join(argv))
    return subprocess.run(list(argv)).returncode


def docker_build(
    *,
    image: str = DEFAULT_IMAGE,
    dockerfile: str = DEFAULT_DOCKERFILE,
    context: str = ".",
    tau_lang_ref: str | None = None,
    jobs: int | None = None,
    pull: bool = False,
    extra_build_args: Iterable[str] = (),
) -> int:
    """Build the standalone tau-testnet Docker image.

    Equivalent shell command (with all options expanded)::

        docker build -f Dockerfile.standalone -t <image> \
            --build-arg TAU_LANG_REF=<ref> \
            --build-arg TAU_BUILD_JOBS=<jobs> \
            [--pull] [<extra build args>] .
    """
    argv: list[str] = [_docker_path(), "build", "-f", dockerfile, "-t", image]
    if tau_lang_ref:
        argv += ["--build-arg", f"TAU_LANG_REF={tau_lang_ref}"]
    if jobs is not None:
        argv += ["--build-arg", f"TAU_BUILD_JOBS={int(jobs)}"]
    if pull:
        argv.append("--pull")
    argv.extend(extra_build_args)
    argv.append(context)
    return _run(argv)


def docker_run(
    *,
    image: str = DEFAULT_IMAGE,
    data_dir: Path | str,
    miner: bool = False,
    isolated: bool = False,
    extra_env: Iterable[str] = (),
    detach: bool = False,
    name: str | None = None,
    no_rm: bool = False,
    interactive: bool = False,
    extra_args: Iterable[str] = (),
) -> int:
    """Run the standalone tau-testnet container.

    Always publishes ports ``65432``, ``65433``, ``4001`` and mounts
    ``data_dir`` at ``/data``. ``--miner`` toggles ``TAU_MINING_ENABLED=true``.
    ``--isolated`` toggles ``TAU_BOOTSTRAP_PEERS=[]`` (empty bootstrap list
    so the container does not try to join the public testnet).
    """
    data_path = Path(data_dir).expanduser().resolve()
    data_path.mkdir(parents=True, exist_ok=True)

    argv: list[str] = [_docker_path(), "run"]
    if not no_rm:
        argv.append("--rm")
    if interactive:
        argv.append("-it")
    if detach:
        argv.append("-d")
    if name:
        argv += ["--name", name]
    for spec in PUBLISHED_PORTS:
        argv += ["-p", spec]
    argv += ["-v", f"{data_path}:{CONTAINER_DATA_DIR}"]

    if miner:
        argv += ["-e", "TAU_MINING_ENABLED=true"]
    if isolated:
        argv += ["-e", "TAU_BOOTSTRAP_PEERS=[]"]
    for kv in extra_env:
        if "=" not in kv:
            raise ValueError(f"--env value must be KEY=VALUE, got {kv!r}")
        argv += ["-e", kv]

    argv.append(image)
    argv.extend(extra_args)
    return _run(argv)


def docker_compose_up(
    *,
    file: str = DEFAULT_COMPOSE_FILE,
    build: bool = True,
    detach: bool = False,
) -> int:
    """Run ``docker compose -f <file> up [--build] [-d]``."""
    argv: list[str] = [_docker_path(), "compose", "-f", file, "up"]
    if build:
        argv.append("--build")
    if detach:
        argv.append("-d")
    return _run(argv)
