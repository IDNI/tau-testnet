"""Real-engine end-to-end test that the shrink id space is DENSE.

Shrink ids used to be drawn from the `tau_strings` autoincrement, which
`TauConsensusEngine._encode_yid` also draws from for the per-block consensus
streams i8 (proposer), i9 (previous_hash) and i11 (claims_json). previous_hash is
unique per block, so that sequence grew at least one id per block regardless of
how many addresses existed -- and the shrink width was picked from its whole-table
MAX. A node with a handful of addresses therefore drifted to bv[16] on block churn
alone, and an address first seen after ~254 blocks interned above the bv[8] usable
range and re-exec'd the process (`tau_manager._handle_width_overflow`).

This drives the REAL native interpreter and the REAL consensus stream encoder:
300 blocks' worth of `_build_consensus_input_streams` (each with a fresh
previous_hash, exactly as a live chain produces), interleaved with real transfer
evaluations, then a transfer from an address the node has never seen before --
the case that used to overflow.

Two subprocesses (the native engine's per-stream bv typing is process-global, so
each case needs a clean process):

  * `test_block_churn_keeps_the_shrink_width_and_verdicts`: the fixed behavior.
  * `test_control_pre_fix_sharing_overflows`: the same run with `db.get_shrink_id`
    routed back through `db.get_string_id` (the pre-fix sharing), which must
    overflow -- otherwise this file would pass without the fix in place.
"""
import os
import subprocess
import sys

import pytest


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")

ALLOWED = "aa" * 48
DENIED = "bb" * 48
# Interned only AFTER the churn -- pre-fix this is the id that overflowed bv[8].
LATE = "ee" * 48
BLOCKS = 300  # > 254, the bv[8] usable ceiling

# `_normalize_assignment_value` only prefixes `#x` when the value contains a hex
# LETTER, so all-digit pubkeys are read as decimals and silently never match an
# i12 guard. Every key here is hex-letter-bearing on purpose.

_CHILD = r'''
import json, os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
os.environ["TAU_SHRINK_ENABLED"] = "true"
os.environ["TAU_NO_WIDTH_REEXEC"] = "1"   # observe the overflow, never os.execv

import config
config.set_database_path(os.environ["SHRINK_DB"])
import db; db.init_db()
import tau_native, tau_manager, tau_shrink
from consensus.engine import TauConsensusEngine

ALLOWED = "%(ALLOWED)s"; DENIED = "%(DENIED)s"; LATE = "%(LATE)s"
BLOCKS = %(BLOCKS)d
PRE_FIX_SHARING = %(PRE_FIX_SHARING)s

if PRE_FIX_SHARING:
    # Reinstate the pre-fix behavior: shrink keys drawn from the tau_strings
    # sequence that the per-block consensus yids also advance.
    db.get_shrink_id = lambda key: int(db.get_string_id(key)[1:])

RULE = ("always ( ((i12[t]:bv[384] = { #x"+ALLOWED+" }:bv[384]) && o2[t]:bv[64] = { 1 }:bv[64]) "
        "|| ((i12[t]:bv[384] != { #x"+ALLOWED+" }:bv[384]) && o2[t]:bv[64] = { 0 }:bv[64]) ).")

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write("always ( o9[t]:bv[64] = { 1 }:bv[64] ).\n"); boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager.last_known_tau_spec = None
tau_manager._current_prepared_spec = None
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

# Mirror a real process start: the width is picked ONCE, here.
boot_width = tau_shrink.set_shrink_width_from_db()
tau_manager.restore_full_tau_spec(RULE)

def verdict(pubkey):
    return tau_manager.parse_tau_output(str(tau_manager.communicate_with_tau(
        target_output_stream_index=2,
        input_stream_values={12: "{ #x"+pubkey+" }:bv[384]"})))

result = {"boot_width": boot_width, "blocks": BLOCKS}
result["before"] = [verdict(ALLOWED), verdict(DENIED)]

# --- The churn: real per-block consensus stream encoding -----------------------
engine = TauConsensusEngine()
try:
    for n in range(1, BLOCKS + 1):
        engine._build_consensus_input_streams(
            proposer_pubkey=ALLOWED,
            block_number=n,
            timestamp=1700000000 + 10 * n,
            previous_hash="%%064x" %% n,      # unique per block, as on a real chain
            proof_ok=True,
            claims={},
        )
        if n %% 50 == 0:
            # Keep the engine in the loop, not just the DB: a real node evaluates
            # transfers between blocks, and every eval re-interns i12.
            result.setdefault("during", []).append([n, verdict(ALLOWED), verdict(DENIED)])
except Exception as exc:
    result["churn_error"] = type(exc).__name__ + ": " + str(exc)

# --- The case that used to overflow: an address first seen after the churn ----
try:
    result["late"] = verdict(LATE)
except Exception as exc:
    result["late_error"] = type(exc).__name__ + ": " + str(exc)

try:
    result["after"] = [verdict(ALLOWED), verdict(DENIED)]
except Exception as exc:
    result["after_error"] = type(exc).__name__ + ": " + str(exc)

result["width_after"] = tau_shrink.current_shrink_width()
with db.get_db_connection() as conn:
    result["tau_strings_max"] = conn.execute("SELECT MAX(id) FROM tau_strings").fetchone()[0]
    result["shrink_rows"] = conn.execute("SELECT COUNT(*) FROM tau_shrink_ids").fetchone()[0]
result["max_shrink_id"] = db.get_max_shrink_id()
# What each width picker would choose against this live data.
result["width_from_shrink_space"] = tau_shrink.width_for_count(result["max_shrink_id"])
result["width_from_tau_strings"] = tau_shrink.width_for_count(result["tau_strings_max"] or 0)
cur = tau_manager.tau_direct_interface.get_current_spec() or ""
result["spec_still_shrunk"] = ("bv[384]" not in cur) and (
    ("i12[t]:bv[" + str(result["width_after"]) + "]") in cur)

print("ID_SPACE_RESULT " + json.dumps(result))
sys.stdout.flush()
os._exit(0)   # native teardown segfaults; the result is already flushed.
'''


def _run(tmp_path, *, pre_fix_sharing: bool) -> dict:
    import json
    child = _CHILD % {
        "ALLOWED": ALLOWED, "DENIED": DENIED, "LATE": LATE,
        "BLOCKS": BLOCKS, "PRE_FIX_SHARING": repr(pre_fix_sharing),
    }
    script = tmp_path / "child.py"
    script.write_text(child)
    env = dict(os.environ)
    env["SHRINK_DB"] = str(tmp_path / "id_space.db")
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    env["PYTHONPATH"] = repo_root + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, env=env, timeout=600,
    )
    line = next((l for l in proc.stdout.splitlines() if l.startswith("ID_SPACE_RESULT")), None)
    assert line is not None, (
        f"child produced no result.\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-4000:]}"
    )
    return json.loads(line.split(maxsplit=1)[1])


def test_block_churn_keeps_the_shrink_width_and_verdicts(tmp_path):
    r = _run(tmp_path, pre_fix_sharing=False)

    # The churn really happened: the consensus yid sequence crossed the bv[8]
    # usable ceiling (254), so the old whole-table picker would now say bv[16].
    assert r["tau_strings_max"] > 254, r
    assert r["width_from_tau_strings"] > 8, r

    # ... while the shrink space holds only the addresses actually interned:
    # ALLOWED, DENIED, LATE. Nothing from the 300 blocks.
    assert r["max_shrink_id"] == 3, r
    assert r["shrink_rows"] == 3, r
    assert r["width_from_shrink_space"] == 8, r

    # No overflow, no re-exec, width untouched from boot to end.
    assert "churn_error" not in r, r
    assert "late_error" not in r, r
    assert "after_error" not in r, r
    assert r["boot_width"] == 8 and r["width_after"] == 8, r

    # The real engine still gives the right answers, on the shrunk spec, after
    # 300 blocks -- including for an address first interned post-churn.
    assert r["before"] == [1, 0], r
    assert r["after"] == [1, 0], r
    assert r["late"] == 0, r            # LATE != ALLOWED -> denied
    assert all(row[1:] == [1, 0] for row in r["during"]), r
    assert r["spec_still_shrunk"] is True, r


def test_control_pre_fix_sharing_overflows(tmp_path):
    """The same run with the pre-fix shared sequence MUST break -- otherwise the
    test above would pass with or without the fix."""
    r = _run(tmp_path, pre_fix_sharing=True)

    assert r["tau_strings_max"] > 254, r
    # An address first seen after the churn interns above the bv[8] range, and
    # the node can only grow the width by re-exec'ing.
    overflow = r.get("late_error", "") or r.get("churn_error", "")
    assert "ShrinkWidthOverflow" in overflow, r
