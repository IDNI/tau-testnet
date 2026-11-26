"""getgovernance must answer while a stream-switching patch is scheduled.

The advisory precheck audits the rules in force, and that audit takes the
rules lock. getgovernance used to run the precheck while it already held
that lock, so the call never returned. Block apply needs the same lock.
"""
import json
import threading

import chain_state
from commands.getgovernance import execute
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate

VALIDATOR = "d" * 96


class _Lock:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _DB:
    def get_canonical_head_block(self):
        return {"block_hash": "abc", "header": {"block_number": 1}}

    def get_mempool_txs(self):
        return []


def test_getgovernance_returns_while_a_flag_patch_is_scheduled():
    saved = chain_state._consensus_rules_state
    chain_state._consensus_rules_state = "i17[t]:bv[64] = 0"
    lm = ConsensusLifecycleManager(active_validators=[VALIDATOR])
    update = ConsensusRuleUpdate(
        rule_revisions=["always ( o6[t]:bv[16] = i10[t]:bv[16] )."],
        activate_at_height=50,
        host_contract_patch={"recipient_controls_active": True},
        proposer_pubkey=VALIDATOR,
    )
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates.append((50, update.update_id))

    class _Chain:
        _balance_lock = _Lock()
        _sequence_lock = _Lock()
        # The real lock. A second acquire from this thread never returns.
        _rules_lock = chain_state._rules_lock
        _active_consensus_id = None
        _consensus_rules_state = ""
        _application_rules_state = ""
        _lifecycle_manager = lm

    class _Container:
        chain_state = _Chain()
        db = _DB()

    outcome = {}

    def run():
        try:
            outcome["raw"] = execute("getgovernance", _Container())
        except Exception as exc:  # noqa: BLE001 - the assertion reports it
            outcome["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    try:
        worker.start()
        worker.join(2)
        assert not worker.is_alive(), "getgovernance held the rules lock across the audit"
        assert "error" not in outcome, outcome.get("error")
        entry = json.loads(outcome["raw"])["data"]["scheduled_updates"][0]
        assert entry["precheck"] == "fail"
        assert "consensus_rules" in entry["precheck_error"]
        assert "i17" in entry["precheck_error"]
    finally:
        chain_state._consensus_rules_state = saved
