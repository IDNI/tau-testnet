"""The simulation worker must not be more permissive than the authoritative one.

A type commitment outlives the rule that created it and is INVISIBLE in the spec
text afterwards. A worker seeded from the current composed spec therefore accepts
candidates the authoritative interpreter refuses -- and a miner simulating on the
permissive one puts a transaction in a block that the authoritative re-apply then
rejects, failing the block on its state hash.

Measured before the fix: authoritative REJECTED_RULE, fresh-from-spec
ACCEPTED_CHANGED, for the same candidate.
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

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_CHILD = r'''
import os, sys, tempfile
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import config
config.set_database_path(os.environ["PROBE_DB"])
import db; db.init_db()
import tau_native, tau_manager, chain_state
from commands.createblock import _speculative_session

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(open(os.path.join(os.environ["REPO_ROOT"], "genesis.tau")).read()); boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager.tau_ready.set()

PIN20   = "always ( i20[t]:bv[8] = { 1 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] )."
REPLACE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
WIDE20  = ("always ( i20[t]:bv[384] = { #x" + "cc"*48 + " }:bv[384] -> "
           "( o5[t]:bv[24] = { #x000000 }:bv[24] ) ).")

# PIN20 types i20 narrow; REPLACE supersedes it, so i20 no longer appears in the
# spec text -- but the commitment stands.
for unit in (PIN20, REPLACE):
    tau_manager.communicate_with_tau(rule_text=unit, target_output_stream_index=0)
    chain_state.save_effective_tau_spec(unit)

sess = _speculative_session()
kind = type(sess).__name__
seeded = len(sess.log)
worker_verdict = sess.apply_rule(WIDE20)
sess.dispose()
print("EQUIV_RESULT", kind, seeded, worker_verdict.replace(" ", "_"))
sys.stdout.flush()
os._exit(0)
'''


def test_the_worker_inherits_commitments_the_spec_text_hides(tmp_path):
    script = tmp_path / "child_equiv.py"
    script.write_text(_CHILD)
    env = dict(os.environ)
    env["PROBE_DB"] = str(tmp_path / "equiv.db")
    env["REPO_ROOT"] = REPO
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True,
                          text=True, env=env, timeout=180)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("EQUIV_RESULT")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, kind, seeded, verdict = line.split()
    assert kind == "WorkerSession", line
    # seeded by REPLAYING the accepted units, not by loading the text they left
    assert int(seeded) >= 2, f"the worker was not replay-seeded: {line}"
    # the authoritative interpreter refuses this candidate; so must the worker
    assert verdict == "error:_REJECTED_RULE", (
        f"the worker is more permissive than the authoritative evaluator: {line}"
    )
