"""The real engine runs with the pinned profile whatever the environment says.

Each case runs in a child process: options are read once per process and the
native library segfaults on interpreter teardown, so the child hard-exits.
"""
import json
import os
import subprocess
import sys

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SENTINEL = "ENGINE_PROFILE_RESULT "

SPECS = [
    "always (o1[t]:bv[16] = i1[t]:bv[16]) && sometimes (o2[t]:bv[16] = { 5 }:bv[16]).",
    "always (o1[t]:bv[16] = i1[t]:bv[16] && sometimes (o2[t]:bv[16] = { 5 }:bv[16])).",
]


def _native_python():
    return os.environ.get("TAU_NATIVE_PYTHON") or sys.executable


def _child_env(extra=None):
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(
        [REPO_ROOT, os.path.join(REPO_ROOT, "tests"), env.get("PYTHONPATH", "")])
    env.update(extra or {})
    return env


def _native_available():
    try:
        proc = subprocess.run(
            [_native_python(), "-c",
             "import tau_native; assert tau_native.load_tau_module() is not None"],
            capture_output=True, text=True, env=_child_env(), timeout=120,
        )
        return proc.returncode == 0
    except Exception:
        return False


requires_native = pytest.mark.skipif(
    not _native_available(), reason="native tau module not importable"
)

_BODY = r'''
import json, os, sys
SENTINEL = %(sentinel)r
SPECS = %(specs)r
PROFILED = %(profiled)r

if PROFILED:
    import tau_native
    tau = tau_native.load_tau_module()
else:
    import tau

import tau_engine_profile
read = {n: tau.get_option(n).value for n in tau.option_names()}
for spec in SPECS:
    try:
        tau.get_interpreter(spec)
    except Exception:
        pass
print(SENTINEL + json.dumps({
    "options": read,
    "path": os.environ.get("PATH", ""),
    "env_left": sorted(k for k in os.environ if k in (
        "TAU_OUTPUT_PREFER", "TAU_MAX_REVISION_ALTS", "TAU_SPOT_BIN")),
}))
sys.stdout.flush()
os._exit(0)
'''


def _fake_tool(directory, marker):
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, "ltlsynt")
    with open(path, "w") as fh:
        fh.write("#!/bin/sh\necho ran >> '%s'\nexit 1\n" % marker)
    os.chmod(path, 0o755)


def _run(tmp_path, profiled):
    path_dir = str(tmp_path / "pathdir")
    spot_dir = str(tmp_path / "spotdir")
    path_marker = str(tmp_path / "path.marker")
    spot_marker = str(tmp_path / "spot.marker")
    _fake_tool(path_dir, path_marker)
    _fake_tool(spot_dir, spot_marker)
    env = _child_env({
        "PATH": path_dir + os.pathsep + os.environ.get("PATH", ""),
        "TAU_OUTPUT_PREFER": "o5=prev",
        "TAU_MAX_REVISION_ALTS": "7",
        "TAU_SPOT_BIN": spot_dir,
        "TAU_ENV": "test",
        "TAU_FORCE_TEST": "0",
    })
    code = _BODY % {"sentinel": SENTINEL, "specs": SPECS, "profiled": profiled}
    proc = subprocess.run([_native_python(), "-c", code], capture_output=True,
                          text=True, env=env, timeout=300)
    lines = [l for l in proc.stdout.splitlines() if l.startswith(SENTINEL)]
    assert lines, proc.stdout[-2000:] + proc.stderr[-2000:]
    result = json.loads(lines[-1][len(SENTINEL):])
    result["path_ran"] = os.path.exists(path_marker)
    result["spot_ran"] = os.path.exists(spot_marker)
    result["path_dir"] = path_dir
    return result


@requires_native
def test_environment_cannot_change_the_engine(tmp_path):
    import tau_engine_profile
    result = _run(tmp_path, profiled=True)
    assert result["options"] == tau_engine_profile.MANIFEST
    assert result["env_left"] == []
    assert result["path_dir"] not in result["path"].split(os.pathsep)
    assert not result["path_ran"]
    assert not result["spot_ran"]


@requires_native
def test_unpinned_engine_follows_the_environment(tmp_path):
    result = _run(tmp_path, profiled=False)
    assert result["options"]["output-prefer"] == "o5=prev"
    assert result["options"]["max-revision-alts"] == "7"
    assert result["path_ran"] or result["spot_ran"]
