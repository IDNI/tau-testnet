"""The authoritative owner against the real engine: genesis, restart, refusal.

Subprocess per case -- native stream typing is process-global, and these build
several interpreters.
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

_PRELUDE = r'''
import os, sys, json, threading
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import config
config.set_database_path(os.environ["PROBE_DB"])
import db; db.init_db()
import chain_state
chain_state.load_genesis("data/genesis.json")
import tau_authority as auth
REPO = os.environ["REPO_ROOT"]
ENV = dict(os.environ); ENV["PYTHONPATH"] = REPO + os.pathsep + ENV.get("PYTHONPATH", "")
BASELINE = "always ( " + open(os.path.join(REPO, "genesis.tau")).read().strip() + " )."

def owner():
    ready = threading.Event()
    return auth.AuthoritativeTauOwner(ready=ready, program_baseline=BASELINE), ready

def out(**kw):
    print("RESULT " + json.dumps(kw)); sys.stdout.flush(); os._exit(0)
'''


def _run(tmp_path, body, name="probe"):
    script = tmp_path / f"{name}.py"
    script.write_text(_PRELUDE + body)
    env = dict(os.environ)
    env["PROBE_DB"] = str(tmp_path / f"{name}.sqlite")
    env["REPO_ROOT"] = REPO
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True,
                          text=True, env=env, timeout=300, cwd=REPO)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("RESULT ")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout[-3000:]}\nSTDERR:\n{proc.stderr[-3000:]}"
    return json.loads(line[len("RESULT "):])


def test_a_fresh_chain_commits_its_genesis_rules_to_the_journal(tmp_path):
    r = _run(tmp_path, r'''
o, ready = owner()
s = o.initialize(cwd=REPO, env=ENV)
st = s._spec.state()
head, seq = db.committed_journal_head()
rec = db.latest_block_commit()
out(state=o.state, ready=ready.is_set(), seq=seq, record_tip=rec["tip"],
    genesis=db.get_genesis_hash(), spec_revision=st["spec_revision"],
    kinds=[e["kind"] for e in db.committed_journal_entries()],
    app_units=len([u for u in (chain_state._application_rules_state or "").split(chr(10)) if u.strip()]))
''')
    assert r["state"] == "ACTIVE" and r["ready"]
    assert r["seq"] > 0, "the genesis rules were not committed to the journal"
    assert set(r["kinds"]) == {"revision"}
    assert r["record_tip"] == r["genesis"]
    assert r["spec_revision"] == r["seq"], (
        "every genesis rule should have revised the evaluator exactly once"
    )
    # The persisted (builtin) units are accumulated exactly as the in-process
    # rules handler did -- the hashed application-rules state must not change
    # just because the evaluator moved into a worker.
    assert r["app_units"] > 0


def test_a_restart_reconstructs_the_same_evaluator_from_the_journal(tmp_path):
    r = _run(tmp_path, r'''
o, _ = owner()
first = o.initialize(cwd=REPO, env=ENV)._spec.state()
o.dispose()
o2, ready2 = owner()
second = o2.initialize(cwd=REPO, env=ENV)._spec.state()
out(first=[first["spec_revision"], first["time_point"]],
    second=[second["spec_revision"], second["time_point"]],
    state=o2.state, ready=ready2.is_set(),
    seq=db.committed_journal_head()[1],
    records=len([1 for _ in [db.latest_block_commit()] if _]))
''')
    assert r["state"] == "ACTIVE" and r["ready"]
    assert r["second"] == r["first"], (
        f"the restarted evaluator is at {r['second']}, the original was at {r['first']}"
    )


def test_the_journal_the_node_writes_is_one_the_node_can_verify(tmp_path):
    """The regression that made this cutover necessary to test end to end:
    WorkerSession recorded a revision's fingerprint without its outputs, while
    reconstruction compared with them. Every hand-built test journal passed
    `result=` explicitly and so never exercised the production recorder."""
    r = _run(tmp_path, r'''
import tau_journal as tj, tau_session as ts, tau_allocator as alloc, tau_reconstruction as tr
rule = "always ( o8[t]:bv[24] = i1[t-1]:bv[24] )."
plan = tr.plan_representation(candidate_rules=[rule])
snap = alloc.DbMappingSnapshot()
s = ts.WorkerSession.spawn(BASELINE, cwd=REPO, env=ENV, plan=plan,
                           allocation=alloc.Allocator(snap, width=plan.width))
s.journal = tj.Journal(authoritative=False)
s.apply_rule(rule, target=0)                                # production recorder
for v in ("#x000005", "#x000009"):
    s.evaluate({1: v}, multi=True)                          # production recorder
s.dispose()
try:
    r = ts.WorkerSession.reconstruct(BASELINE, journal=s.journal, plan=plan,
                                     snapshot=snap, cwd=REPO, env=ENV, verify=True)
    r.dispose(); verified = True; err = None
except Exception as exc:
    verified = False; err = repr(exc)
out(verified=verified, err=err)
''')
    assert r["verified"], f"a journal written by the node failed its own verification: {r['err']}"


def test_a_chain_the_journal_never_recorded_is_not_ready(tmp_path):
    """Blocks applied by the in-process interpreter left no journal. Their Tau
    state cannot be reconstructed from committed history, and guessing -- or
    quietly using the old restore mechanism -- is exactly the second source of
    truth this owner removes."""
    r = _run(tmp_path, r'''
db.set_chain_state_value("canonical_head_hash", "a-block-the-journal-never-saw")
o, ready = owner()
try:
    o.initialize(cwd=REPO, env=ENV); raised = None
except Exception as exc:
    raised = type(exc).__name__
out(raised=raised, state=o.state, ready=ready.is_set(), reason=o.reason)
''')
    assert r["raised"] == "AuthorityMismatch"
    assert r["state"] == "UNAVAILABLE" and not r["ready"]
    assert "Rebuild from genesis" in r["reason"]


def test_a_corrupted_committed_journal_is_not_ready(tmp_path):
    r = _run(tmp_path, r'''
o, _ = owner()
o.initialize(cwd=REPO, env=ENV); o.dispose()
with db._db_lock:
    db._db_conn.execute("UPDATE tau_journal_v1 SET rule_text = 'tampered' WHERE seq = 1")
    db._db_conn.commit()
o2, ready2 = owner()
try:
    o2.initialize(cwd=REPO, env=ENV); raised = None
except Exception as exc:
    raised = type(exc).__name__
out(raised=raised, state=o2.state, ready=ready2.is_set())
''')
    assert r["raised"] in ("AuthorityMismatch", "DivergenceError")
    assert r["state"] == "UNAVAILABLE" and not r["ready"]
