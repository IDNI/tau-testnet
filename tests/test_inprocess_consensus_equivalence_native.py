"""o6/o7 do not depend on the user rules the in-process interpreter holds.

Under worker-backed authority that interpreter only carries the consensus unit;
this pins that its header/eligibility answers equal those of an interpreter that
also replayed the builtin rules and an o5 composite. Each phase runs in its own
process: stream typing is process-global in the native engine.
"""
import json
import os
import subprocess
import sys

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(),
                                reason="native tau module not built")

PHASE = r'''
import json, os, sys
sys.path.insert(0, os.environ["REPO"])
mode, scratch = sys.argv[1], sys.argv[2]
import config
config.set_database_path(os.path.join(scratch, mode + ".db"))
config.DATA_DIR = scratch
config.COMM_DEBUG_PATH = None
import db
db._db_conn = None
db.init_db()
import chain_state, tau_manager, tau_native, tau_shrink
from consensus.engine import TauConsensusEngine
from consensus.rule_offers import compose_stream_rule

def bv24(n): return "{ #x" + format(n, "06x") + " }:bv[24]"
def bv384(h): return "{ #x" + h + " }:bv[384]"
def key(p, i): return (p + format(i, "04x")) * 16
def tier(i):
    a, s, c = key("ca", i), key("cb", i), key("cc", i)
    blocked = ("(i1[t]:bv[24] > " + bv24(1000) + " && !(i18[t]:bv[384] = " + bv384(a) + "))"
               " || (i1[t]:bv[24] > " + bv24(10000) + " && !(i19[t]:bv[384] = " + bv384(s) + "))"
               " || (i1[t]:bv[24] > " + bv24(100000) + " && !(i20[t]:bv[384] = " + bv384(c) + "))")
    return ("( (" + blocked + ") ? (o5[t]:bv[24] = " + bv24(0) + ") : (o5[t]:bv[24] = " + bv24(1) + ") )")

with open(os.path.join(os.environ["REPO"], "data", "genesis.json")) as fh:
    cons = json.load(fh)["consensus_rules"]
plan = chain_state.restore_plan_for(cons, "", lifecycle=None)
if mode == "cons":
    plan = [e for e in plan if e["label"] == "consensus_rules"]
else:
    plan.append({"label": "rule_composite_o5", "persist": False,
                 "text": compose_stream_rule(5, {key("ab", i): tier(i) for i in (1, 2, 3)})})
tau_manager._print_tau_send = lambda *a, **k: None
tau_manager.tau_direct_interface = tau_native.TauInterface(config.TAU_PROGRAM_FILE)
if getattr(config, "TAU_SHRINK_ENABLED", False):
    tau_shrink.set_shrink_width_from_db()
tau_manager.tau_test_mode = False
tau_manager.tau_process_ready.set()
chain_state.replay_tau_restore_plan(plan, source_prefix="startup")
tau_manager.tau_ready.set()
eng = TauConsensusEngine()
verdicts = {}
for proof in (True, False):
    inputs = eng._build_consensus_input_streams(
        proposer_pubkey="a1" * 48, block_number=7, timestamp=1_700_000_000,
        previous_hash="ab" * 32, proof_ok=proof, claims={}, proposer_stake=0,
        stake_mode=False, feed_proposer_pubkey=False)
    out = tau_manager.communicate_with_tau_multi(
        input_stream_values=inputs, source="consensus_verify", apply_rules_update=False)
    verdicts[int(proof)] = {k: out.get(k) for k in (6, 7)}
sys.stdout.write("VERDICTS " + json.dumps(verdicts) + "\n")
sys.stdout.flush()
'''


def _run(mode, tmp_path):
    env = dict(os.environ, REPO=REPO)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, "-c", PHASE, mode, str(tmp_path)],
                          capture_output=True, text=True, timeout=240, env=env, cwd=REPO)
    for line in proc.stdout.splitlines():
        if line.startswith("VERDICTS "):
            return json.loads(line[len("VERDICTS "):])
    pytest.fail(f"phase {mode} produced no verdicts (rc={proc.returncode}): "
                f"{proc.stderr[-800:]}")


def test_consensus_only_interpreter_answers_o6_o7_like_the_full_one(tmp_path):
    (tmp_path / "full").mkdir()
    (tmp_path / "cons").mkdir()
    full = _run("full", tmp_path / "full")
    cons = _run("cons", tmp_path / "cons")
    assert full == cons
    assert cons["1"]["6"] is not None
