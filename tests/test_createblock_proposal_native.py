"""The miner simulates inside a proposal, so it writes no canonical state.

`createblock` used to write `chain_state._application_rules_state` and the db
`full_tau_spec` row for every rule-bearing transaction it simulated, and put
them back in a `finally`. That works until something escapes the block: a crash
or an unexpected raise between simulating and restoring leaves the node's
canonical rules state carrying rules from a block that was never mined.

In proposal mode the writes never happen. The staged rules state lives in the
proposal and is discarded with it.

Subprocess per case, because native stream typing is process-global.
"""
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

RULE = 'always ( o5[t]:bv[24] = { #x000000 }:bv[24] ).'

_CHILD = r'''
import os, sys, tempfile, json
os.environ["TAU_ENV"] = "test"; os.environ["TAU_FORCE_TEST"] = "0"
import config
config.set_database_path(os.environ["PROBE_DB"])
import db; db.init_db()
import tau_native, tau_manager, chain_state, tau_guard
from unittest.mock import MagicMock
from commands.createblock import _speculative_proposal
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot
from block import Block

RULE = os.environ["PROBE_RULE"]
SENDER = "a1" * 48
PROPOSER = "d4" * 48

boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
boot.write(open(os.path.join(os.environ["REPO_ROOT"], "genesis.tau")).read()); boot.close()
iface = tau_native.TauInterface(boot.name)
tau_manager.tau_direct_interface = iface
tau_manager.tau_test_mode = False
tau_manager.tau_ready.set()

rules_before = chain_state.get_application_rules_state()
spec_before = db.get_chain_state_value("full_tau_spec", "")
epoch_before = db.shrink_mapping_epoch()
time_before = iface.interpreter.time_point

tx = {"tx_id": "r1", "tx_type": "user_tx", "sender_pubkey": SENDER,
      "sequence_number": 0, "fee_limit": "10000", "operations": {"0": RULE}}

proposal = _speculative_proposal(candidate_rules=[RULE])
kind = type(proposal).__name__ if proposal is not None else "None"

lm = ConsensusLifecycleManager(active_validators=[SENDER])
parent = TauStateSnapshot(
    state_hash="0" * 64, tau_bytes=b"always ( o0[t]=1 ).",
    metadata={"balances": {SENDER: 100000}, "sequence_numbers": {},
              "last_transfer_ts": {}, "lifecycle_manager": lm,
              "active_consensus_id": ""},
)
blk = Block.create(block_number=1, previous_hash="0" * 64, transactions=[tx],
                   proposer_pubkey=PROPOSER, timestamp=1700000000)
view = ActiveConsensusView(target_height=1, consensus_rules="",
                           active_validators=[bytes.fromhex(SENDER)])

engine = TauConsensusEngine(state_store=MagicMock())
engine._state_store.commit.side_effect = lambda snap: snap

watcher = tau_guard.ProposalIsolationGuard(strict=False)
with watcher:
    result = engine.apply_block(view, blk, parent,
                                session=proposal.session, proposal=proposal)
staged = proposal.state.get("application_rules", "")
proposal.dispose()

print("CB_RESULT " + json.dumps({
    "kind": kind,
    "accepted": list(result.accepted_tx_ids),
    "staged_has_rule": RULE.strip() in staged,
    "violations": watcher.calls(),
    "rules_unchanged": chain_state.get_application_rules_state() == rules_before,
    "spec_unchanged": db.get_chain_state_value("full_tau_spec", "") == spec_before,
    "epoch_unchanged": db.shrink_mapping_epoch() == epoch_before,
    "time_unchanged": iface.interpreter.time_point == time_before,
}))
sys.stdout.flush(); os._exit(0)
'''


def _run(tmp_path):
    script = tmp_path / "child_cb.py"
    script.write_text(_CHILD)
    env = dict(os.environ)
    env["PROBE_DB"] = str(tmp_path / "cb.db")
    env["REPO_ROOT"] = REPO
    env["PROBE_RULE"] = RULE
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    proc = subprocess.run([sys.executable, str(script)], capture_output=True,
                          text=True, env=env, timeout=180)
    line = next((l for l in proc.stdout.splitlines() if l.startswith("CB_RESULT")), None)
    assert line is not None, f"no result.\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    import json
    return json.loads(line[len("CB_RESULT "):])


def test_the_miner_proposal_writes_no_canonical_state(tmp_path):
    out = _run(tmp_path)

    assert out["kind"] == "ProposalContext", (
        f"createblock did not build a proposal: {out}"
    )
    # The rule really was applied, or the assertions below are about a block
    # that did nothing.
    assert out["accepted"] == ["r1"], f"the rule transaction was not accepted: {out}"
    assert out["staged_has_rule"], (
        f"the rule was accepted but never staged in the proposal: {out}"
    )

    assert out["violations"] == [], (
        f"the miner simulation reached committed state: {out['violations']}"
    )
    assert out["rules_unchanged"], "canonical application-rules state was written"
    assert out["spec_unchanged"], "the db full_tau_spec row was written"
    assert out["epoch_unchanged"], "the committed allocator advanced"
    assert out["time_unchanged"], "the authoritative interpreter was stepped"
