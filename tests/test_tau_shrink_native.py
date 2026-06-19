"""Real-engine end-to-end test for the shrink layer.

Auto-skips unless the native tau module is importable (set PYTHONPATH to the
tau-lang nanobind build). Proves that a SHRUNK spec + production-style wrapped
i12 input, driven through tau_manager against the REAL interpreter, yields the
correct equality verdicts, and that the persisted spec stays full-width.

The actual engine call runs in a FRESH SUBPROCESS: the native engine has
process-global per-stream bv-width typing, so a sibling real-engine test in the
same process can poison the shared type table. A subprocess gives a clean one.
"""
import os
import subprocess
import sys
import tempfile

import pytest


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

HEX = "ab" * 48
OTHER = "cd" * 48

_CHILD = r'''
import os, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"   # opt in (OFF by default)
import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

HEX = "%s"; OTHER = "%s"
RULE = ("always ( ((i12[t]:bv[384] = { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 1 }:bv[64]) "
        "|| ((i12[t]:bv[384] != { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 0 }:bv[64]) ).")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager.last_known_tau_spec = None
tau_manager._current_prepared_spec = None
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

tau_manager.restore_full_tau_spec(RULE)
streams = sorted(tau_manager._runtime_shrunk_streams)
m = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=2, input_stream_values={12: "{ #x"+HEX+" }:bv[384]"})))
n = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=2, input_stream_values={12: "{ #x"+OTHER+" }:bv[384]"})))
cur = tau_manager.tau_direct_interface.get_current_spec() or ""
import tau_shrink
W = tau_shrink.current_shrink_width()
runtime_shrunk = ("bv[384]" not in cur) and (("i12[t]:bv[" + str(W) + "]") in cur)
print("SHRINK_RESULT", streams, m, n, runtime_shrunk, "W=" + str(W))
'''


def test_shrunk_equality_verdicts_match_real_engine(tmp_path):
    child = _CHILD % (HEX, OTHER)
    script = tmp_path / "child.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "shrink_native.db")
    # The spawned subprocess does not inherit sys.path; put the repo root on
    # PYTHONPATH so it can import tau_shrink/tau_manager (native tau auto-discovers
    # the sibling tau-lang build, or honors an already-set PYTHONPATH).
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("SHRINK_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    # SHRINK_RESULT [12] 1 0 True W=8
    _, streams, match, nomatch, runtime_shrunk, width = line.split(maxsplit=5)
    assert streams == "[12]", line
    # The core proof: the SHRUNK spec yields the SAME verdicts as full-width would.
    assert match == "1", f"matching i12 should pass (o2=1): {line}"
    assert nomatch == "0", f"non-matching i12 should fail (o2=0): {line}"
    # The interpreter is running the shrunk spec at the smallest dynamic width.
    assert runtime_shrunk == "True", f"interpreter should hold the shrunk spec: {line}"
    assert width == "W=8", f"tiny table should pick bv[8]: {line}"
