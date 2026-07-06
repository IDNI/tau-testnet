"""Phase 5 — End-to-end stake switch on the REAL native engine (unmocked).

One interpreter lives through the whole scenario: genesis consensus load ->
governance vote -> `engine.apply_block` activation (revision routed through Tau
i0) -> stake-mode `verify_block_header`. This is the unmocked twin of
tests/test_gov_integration.py::test_apply_block_routes_activation_revisions_through_i0.

A second child proves restart equivalence: a fresh interpreter seeded with ONLY
the activated revision (what `get_tau_restore_plan` replays) produces identical
verify verdicts.

Each case runs in its own subprocess (native per-stream bv-width typing is
process-global; teardown segfaults, so children os._exit after emitting JSON).
Auto-skips unless the native tau module is importable.
"""
import json
import os
import pathlib
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

_REPO = pathlib.Path(__file__).resolve().parent.parent
_DEMO = _REPO / "demo"


def _flatten(text: str) -> str:
    """Strip # comment lines and flatten to one line (i0 rule_text is fed raw --
    tau_native does NOT comment-strip an i0 value, only a spec build does)."""
    lines = [l.strip() for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]
    return " ".join(lines)


def _rendered_revision() -> str:
    tmpl = (_DEMO / "stake_consensus_revision.tau.tmpl").read_text(encoding="utf-8")
    return _flatten(tmpl.replace("__THRESHOLD__", "100000"))


GENESIS_DEMO = _flatten((_DEMO / "genesis_consensus_demo.tau").read_text(encoding="utf-8"))
REVISION = _rendered_revision()

V1, V2, V3 = "a" * 96, "b" * 96, "c" * 96
OUTSIDER = "d" * 96   # balance 200000 -> eligible in stake mode
POOR = "e" * 96       # balance 5      -> ineligible

_PREAMBLE = r'''
import json, os, sys, tempfile
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import config; config.set_database_path(os.environ["SPIKE_DB"])
import db; db.init_db()
import tau_native, tau_manager
from consensus.engine import TauConsensusEngine, ActiveConsensusView
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate, ConsensusRuleVote
from consensus.state import TauStateSnapshot
from block import Block

ROUTER = "((!(i0[t] = 0)) ? ( u[t] = i0[t] && o0[t] = 0 ) : o0[t] = 1)"
V1, V2, V3, OUTSIDER, POOR = %(V1)r, %(V2)r, %(V3)r, %(OUTSIDER)r, %(POOR)r
GENESIS_DEMO = %(GENESIS_DEMO)r
REVISION = %(REVISION)r
BALANCES = {OUTSIDER: 200000, POOR: 5, V1: 0, V2: 0, V3: 0}

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(ROUTER + "\n"); boot.close()
tau_manager.tau_direct_interface = tau_native.TauInterface(boot.name)
tau_manager.tau_test_mode = False
tau_manager.last_known_tau_spec = None
tau_manager._current_prepared_spec = None
tau_manager._runtime_shrunk_streams = frozenset()
tau_manager.tau_ready.set()

def _mk_block(height, proposer):
    b = Block.create(block_number=height, previous_hash="11" * 32,
                     transactions=[], proposer_pubkey=proposer, timestamp=1234567890)
    b.consensus_proof = {"signature": "00" * 48}
    return b

def emit(obj):
    print("E2E_RESULT " + json.dumps(obj)); sys.stdout.flush()
    os._exit(0)  # skip native teardown segfault (result already emitted)
'''


_LIVE_BODY = r'''
engine = TauConsensusEngine()
# Genesis consensus load: route the mode-guarded demo rule through i0.
tau_manager.communicate_with_tau(rule_text=GENESIS_DEMO, target_output_stream_index=0, apply_rules_update=False)

H = 5
lm = ConsensusLifecycleManager(active_validators=[V1, V2, V3])
update = ConsensusRuleUpdate(
    rule_revisions=[REVISION],
    activate_at_height=H,
    host_contract_patch={"eligibility_mode": "stake"},
)
assert lm.submit_update(update)
lm.submit_vote(ConsensusRuleVote(update_id=update.update_id, approve=True), bytes.fromhex(V1))
lm.submit_vote(ConsensusRuleVote(update_id=update.update_id, approve=True), bytes.fromhex(V2))
scheduled = any(uid == update.update_id for _, uid in lm.scheduled_updates)

parent = TauStateSnapshot(
    state_hash="0" * 64,
    tau_bytes=b"always (o0[t]=1).",
    metadata={
        "balances": dict(BALANCES),
        "sequence_numbers": {},
        "lifecycle_manager": lm,
        "consensus_rules_state": GENESIS_DEMO,
        "active_consensus_id": "",
    },
)
active_view = engine.derive_active_consensus(parent, H)
block = _mk_block(H, V1)
result = engine.apply_block(active_view, block, parent)

post_lm = result.next_snapshot.metadata["lifecycle_manager"]
twin = ConsensusLifecycleManager(active_validators=[V1, V2, V3])  # left in validator_set
next_snap = result.next_snapshot

view2 = engine.derive_active_consensus(next_snap, H + 1)
def verify(proposer):
    return engine.verify_block_header(view2, _mk_block(H + 1, proposer), {"proof_ok": True})

emit({
    "scheduled": scheduled,
    "activated": update.update_id_hex in result.governance_changes["activated_updates"],
    "mode": post_lm.effective_eligibility_mode(),
    "cons_rules_ok": next_snap.metadata["consensus_rules_state"] == REVISION,
    "hash_differs": post_lm.consensus_meta_hash() != twin.consensus_meta_hash(),
    "view2_mode": view2.mechanism_specific_metadata.get("eligibility_mode"),
    "verify_outsider": verify(OUTSIDER),
    "verify_poor": verify(POOR),
    "verify_outsider_again": verify(OUTSIDER),
})
'''


_RESTART_BODY = r'''
engine = TauConsensusEngine()
# Restart replays ONLY the activated revision into a fresh interpreter.
tau_manager.communicate_with_tau(rule_text=REVISION, target_output_stream_index=0, apply_rules_update=False)

H = 5
lm = ConsensusLifecycleManager(active_validators=[V1, V2, V3])
lm.eligibility_mode = "stake"
snap = TauStateSnapshot(
    state_hash="0" * 64,
    tau_bytes=b"always (o0[t]=1).",
    metadata={
        "balances": dict(BALANCES),
        "sequence_numbers": {},
        "lifecycle_manager": lm,
        "consensus_rules_state": REVISION,
        "active_consensus_id": "restart",
    },
)
view = engine.derive_active_consensus(snap, H + 1)
def verify(proposer):
    return engine.verify_block_header(view, _mk_block(H + 1, proposer), {"proof_ok": True})

emit({
    "view_mode": view.mechanism_specific_metadata.get("eligibility_mode"),
    "verify_outsider": verify(OUTSIDER),
    "verify_poor": verify(POOR),
    "verify_outsider_again": verify(OUTSIDER),
})
'''


def _child_src(body):
    return (_PREAMBLE % {
        "V1": V1, "V2": V2, "V3": V3, "OUTSIDER": OUTSIDER, "POOR": POOR,
        "GENESIS_DEMO": GENESIS_DEMO, "REVISION": REVISION,
    }) + "\n" + body


def _run_child(tmp_path, name, body):
    script = tmp_path / (name + ".py")
    script.write_text(_child_src(body))
    env = dict(os.environ)
    env["SPIKE_DB"] = str(tmp_path / (name + ".db"))
    env["PYTHONPATH"] = str(_REPO) + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)],
                          capture_output=True, text=True, env=env, timeout=300)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("E2E_RESULT ")), None)
    assert line is not None, (
        f"child produced no verdict (STOP: activation or wiring failure)\n"
        f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    return json.loads(line[len("E2E_RESULT "):])


def test_stake_switch_live_e2e(tmp_path):
    r = _run_child(tmp_path, "live", _LIVE_BODY)
    assert r["scheduled"] is True, r
    assert r["activated"] is True, r
    assert r["mode"] == "stake", r
    assert r["cons_rules_ok"] is True, r
    assert r["hash_differs"] is True, r
    assert r["view2_mode"] == "stake", r
    assert r["verify_outsider"] is True, f"rich outsider must verify in stake mode: {r}"
    assert r["verify_poor"] is False, f"poor proposer must be rejected: {r}"
    assert r["verify_outsider_again"] is True, f"interpreter poisoned after rejection: {r}"


def test_stake_switch_restart_equivalence(tmp_path):
    live = _run_child(tmp_path, "live_for_restart", _LIVE_BODY)
    restart = _run_child(tmp_path, "restart", _RESTART_BODY)
    assert restart["view_mode"] == "stake", restart
    triple = ("verify_outsider", "verify_poor", "verify_outsider_again")
    assert [live[k] for k in triple] == [restart[k] for k in triple], (
        f"live vs restarted verdicts differ (STOP: restart determinism broken)\n"
        f"live={ {k: live[k] for k in triple} }\nrestart={ {k: restart[k] for k in triple} }"
    )
