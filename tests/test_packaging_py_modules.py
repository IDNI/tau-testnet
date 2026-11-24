import subprocess
import tomllib
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _declared():
    data = tomllib.loads((ROOT / "pyproject.toml").read_text())
    return set(data["tool"]["setuptools"]["py-modules"])


def test_py_modules_matches_top_level_tracked_modules():
    """Wheels only ship modules listed in py-modules, so drift breaks installs."""
    try:
        out = subprocess.run(
            ["git", "ls-files", "*.py"], cwd=ROOT, capture_output=True, text=True, check=True
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("git metadata unavailable")
    tracked = {Path(f).stem for f in out.split() if "/" not in f}
    if not tracked:
        pytest.skip("no tracked files")
    declared = _declared()
    assert not (tracked - declared), f"missing from py-modules: {sorted(tracked - declared)}"
    assert not (declared - tracked), f"py-modules without a file: {sorted(declared - tracked)}"
