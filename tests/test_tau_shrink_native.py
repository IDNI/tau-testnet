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


# --- rule 02 (src==dest) with FULL pubkeys on i3/i4 via the real engine --------
_CHILD_SRC_EQ = r'''
import os, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"
import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

HEX = "%s"; OTHER = "%s"
# The actual src==dest rule, now bv[384] on i3/i4 (shrunk for eval).
RULE = ("always ( ((i3[t]:bv[384] = i4[t]:bv[384]) && o3[t] = { #x0000 }:bv[16]) "
        "|| ((i3[t]:bv[384] != i4[t]:bv[384]) && o3[t] = { #x0001 }:bv[16]) ).")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

tau_manager.restore_full_tau_spec(RULE)
streams = sorted(tau_manager._runtime_shrunk_streams)
# from == to  -> o3 = 0 (src==dest fails the check)
same = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=3,
    input_stream_values={3: "{ #x"+HEX+" }:bv[384]", 4: "{ #x"+HEX+" }:bv[384]"})))
# from != to  -> o3 = 1
diff = tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
    target_output_stream_index=3,
    input_stream_values={3: "{ #x"+HEX+" }:bv[384]", 4: "{ #x"+OTHER+" }:bv[384]"})))
print("SRC_EQ_RESULT", "/".join(str(s) for s in streams), same, diff)
'''


# --- sendtx restore must NOT desync the shrunk-stream set (regression) ----------
# Repro of the live validate-then-restore path: a rule sendtx snapshots the
# interpreter's (shrunk) spec + shrunk-stream set, validates a user rule via i0
# (mutating the interpreter), then restores. restore_full_tau_spec on the
# already-shrunk snapshot re-classifies nothing (bv[W<128]) and WIPES the set;
# passing runtime_shrunk_streams= re-pins it so a following transfer that feeds a
# wide bv[384] literal still shrinks correctly and yields the right verdict.
_CHILD_RESTORE = r'''
import os, tempfile
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"
import config; config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager

HEX = "%s"; KEY = "11" * 48
BASE = ("always ( ((i12[t]:bv[384] = { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 1 }:bv[64]) "
        "|| ((i12[t]:bv[384] != { #x"+HEX+" }:bv[384]) && o2[t]:bv[64] = { 0 }:bv[64]) ).")
USER = ("always ((i12[t]:bv[384] = { #x"+KEY+" }:bv[384] && i1[t]:bv[24] > { 5000 }:bv[24]) "
        "-> o5[t]:bv[24] = { #x000000 }:bv[24]).")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

def verdict():
    return tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
        target_output_stream_index=2, input_stream_values={12: "{ #x"+HEX+" }:bv[384]"})))

tau_manager.restore_full_tau_spec(BASE)
spec0 = tau_manager.tau_direct_interface.get_current_spec()
set0 = tau_manager.get_runtime_shrunk_streams()
tau_manager.communicate_with_tau(rule_text=USER, target_output_stream_index=0, apply_rules_update=False)

# WITHOUT the kwarg: set wipes (the bug this guards against).
tau_manager.restore_full_tau_spec(spec0)
wiped = sorted(tau_manager._runtime_shrunk_streams)

# WITH the kwarg (the fix): set re-pinned, verdict correct.
tau_manager.restore_full_tau_spec(spec0, runtime_shrunk_streams=set0)
fixed = sorted(tau_manager._runtime_shrunk_streams)
v = verdict()
print("RESTORE_RESULT", "/".join(map(str, wiped)) or "EMPTY", "/".join(map(str, fixed)), v)
'''


def test_sendtx_restore_repins_shrunk_streams_real_engine(tmp_path):
    """restore_full_tau_spec(runtime_shrunk_streams=...) keeps the shrunk-stream
    set consistent with the restored interpreter; without it the set wipes and a
    later bv[384] input mis-validates."""
    child = _CHILD_RESTORE % (HEX,)
    script = tmp_path / "child_restore.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "restore.db")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("RESTORE_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, wiped, fixed, verdict = line.split(maxsplit=3)
    assert wiped == "EMPTY", f"without the kwarg the set should wipe (proves the hazard): {line}"
    assert fixed == "12", f"with the kwarg the shrunk set must be re-pinned to [12]: {line}"
    assert verdict == "1", f"matching i12 must still verify (o2=1) after restore: {line}"


def test_src_eq_dest_rule_full_pubkeys_real_engine(tmp_path):
    """Rule 02 with bv[384] i3/i4 fed FULL pubkeys: shrink interns both, equality
    is preserved (same -> o3=0, different -> o3=1) on the real interpreter."""
    child = _CHILD_SRC_EQ % (HEX, OTHER)
    script = tmp_path / "child_srceq.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "srceq.db")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=120,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("SRC_EQ_RESULT")), None)
    assert line is not None, f"child produced no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, streams, same, diff = line.split(maxsplit=3)
    assert streams == "3/4", line          # both address streams shrunk
    assert same == "0", f"from==to must fail src!=dest (o3=0): {line}"
    assert diff == "1", f"from!=to must pass (o3=1): {line}"
