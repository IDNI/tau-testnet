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
# An ORDERING use of i20: the optimizer refuses to shrink it (equality-only), so
# preparation cannot narrow it and it reaches the engine at full width. That is
# what makes it a probe for the commitment: a session that typed i20 narrow
# refuses it, a session that never did accepts it.
WIDE20  = ("always ( i20[t]:bv[384] > { #x" + "cc"*48 + " }:bv[384] -> "
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


_CHILD_DISCRIMINATES = r'''
import os, sys
sys.path.insert(0, os.environ["REPO_ROOT"])
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import config
config.set_database_path(os.environ["PROBE_DB"])
import db; db.init_db()
import tau_session as ts

with open(os.path.join(os.environ["REPO_ROOT"], "genesis.tau")) as fh:
    ROUTER = "always ( " + fh.read().strip() + " )."
PIN20   = "always ( i20[t]:bv[384] = { #x" + "dd"*48 + " }:bv[384] -> o5[t]:bv[24] = { #x000001 }:bv[24] )."
REPLACE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
WIDE20  = "always ( i20[t]:bv[384] > { #x" + "cc"*48 + " }:bv[384] -> ( o5[t]:bv[24] = { #x000000 }:bv[24] ) )."
env = dict(os.environ)

seeded = ts.WorkerSession.spawn(ROUTER, cwd=os.environ["REPO_ROOT"], env=env,
                                trace=[{"kind": ts.RULE, "rule_text": PIN20},
                                       {"kind": ts.RULE, "rule_text": REPLACE}])
seeded_verdict = seeded.apply_rule(WIDE20)
seeded.dispose()

fresh = ts.WorkerSession.spawn(ROUTER, cwd=os.environ["REPO_ROOT"], env=env,
                               trace=[{"kind": ts.RULE, "rule_text": REPLACE}])
fresh_verdict = fresh.apply_rule(WIDE20)
fresh.dispose()
print("DISCRIMINATES", seeded_verdict.replace(" ", "_"), fresh_verdict.replace(" ", "_"))
sys.stdout.flush()
os._exit(0)
'''


def test_the_probe_distinguishes_a_seeded_worker_from_a_fresh_one(tmp_path):
    """Guard the guard. The candidate is an ORDERING use of i20, which the
    optimizer refuses to shrink, so preparation cannot narrow it away: a worker
    that replayed the superseded rule refuses it, a worker built from the
    surviving spec text alone accepts it. Without this, the equivalence test could
    pass because both sides reject everything."""
    script = tmp_path / "child_discriminate.py"
    script.write_text(_CHILD_DISCRIMINATES)
    env = dict(os.environ)
    env["PROBE_DB"] = str(tmp_path / "disc.db")
    env["REPO_ROOT"] = REPO
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True,
                          text=True, env=env, timeout=180)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("DISCRIMINATES")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    _, seeded, fresh = line.split()
    assert seeded == "error:_REJECTED_RULE", line
    assert fresh == "ok", line
