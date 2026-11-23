"""getgovernance must answer while a stream-switching patch is scheduled.

The advisory precheck of a scheduled update audits the rules in force for a
patch such as approval_slots_active, which takes chain_state's rules lock.
getgovernance used to run it while holding that lock itself, so the call never
returned and the node could apply no further block until the update activated.
"""
import json
import threading
from types import SimpleNamespace
from unittest.mock import patch

import chain_state
import db
from commands import getgovernance
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate

VALIDATOR = "d" * 96


def test_getgovernance_returns_while_a_flag_patch_is_scheduled(temp_database):
    chain_state.load_genesis("data/genesis.json")
    lm = ConsensusLifecycleManager(active_validators=[VALIDATOR])
    update = ConsensusRuleUpdate(
        rule_revisions=["always ( o6[t]:bv[16] = i10[t]:bv[16] )."],
        activate_at_height=50, host_contract_patch={"approval_slots_active": True},
        proposer_pubkey=VALIDATOR)
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates.append((50, update.update_id))
    out = {}

    def call():
        with patch.object(chain_state, "_lifecycle_manager", lm):
            out["res"] = getgovernance.execute(
                "getgovernance", SimpleNamespace(chain_state=chain_state, db=db))

    t = threading.Thread(target=call, daemon=True)
    t.start()
    t.join(timeout=20)
    assert not t.is_alive(), "getgovernance hung with a flag patch scheduled"
    (entry,) = json.loads(out["res"])["data"]["scheduled_updates"]
    assert entry["precheck"]
