"""`getgovernance` while a governance update is approved and scheduled.

Between approval and activation every poll runs the advisory check of the
scheduled update. For a patch that switches a stream on, that check audits the
rules in force, which takes the rules lock, so it has to run after the command
has released its own locks. Under them it never returned, and the handler kept
the balance and sequence locks with it, so the node could not apply another
block.
"""
import json
import threading
from unittest.mock import MagicMock

import pytest

import chain_state
import db
from commands import getgovernance
from consensus.governance import ConsensusLifecycleManager, ConsensusRuleUpdate

from test_approval_persistence import _seed_state

pytestmark = pytest.mark.usefixtures("isolated_chain_state")


def governance_with_a_scheduled_patch(monkeypatch, patch_body):
    """The one scheduled entry `getgovernance` reports, read on the real
    chain_state under real (test-local) locks."""
    # Fresh locks: if the call ever hangs again, it must not take the suite's
    # own locks with it.
    for name in ("_balance_lock", "_sequence_lock", "_rules_lock"):
        monkeypatch.setattr(chain_state, name, threading.Lock())

    lm = _seed_state(ConsensusLifecycleManager(active_validators=["d" * 96]))
    update = ConsensusRuleUpdate(
        rule_revisions=["consensus rules"], activate_at_height=50,
        host_contract_patch=patch_body, proposer_pubkey="d" * 96)
    lm.update_payloads[update.update_id] = update
    lm.scheduled_updates.append((50, update.update_id))

    container = MagicMock()
    container.chain_state = chain_state
    container.db = db
    answer = []
    reader = threading.Thread(
        target=lambda: answer.append(getgovernance.execute("getgovernance", container)),
        daemon=True)
    reader.start()
    reader.join(30)
    assert answer, (
        "getgovernance did not return while a flag patch was scheduled: its "
        "advisory check takes the rules lock the command already holds")
    (entry,) = json.loads(answer[0])["data"]["scheduled_updates"]
    return entry


def test_it_answers_while_an_approval_slots_patch_is_scheduled(temp_database, monkeypatch):
    entry = governance_with_a_scheduled_patch(monkeypatch, {"approval_slots_active": True})
    assert entry["host_contract_patch"] == {"approval_slots_active": True}
    assert entry["precheck"] == "ok", entry


def test_a_patch_that_audits_nothing_is_checked_as_before(temp_database, monkeypatch):
    entry = governance_with_a_scheduled_patch(monkeypatch, {"vote_quorum": "majority"})
    assert entry["precheck"] == "ok", entry


def test_the_check_still_flags_a_patch_that_will_not_activate(temp_database, monkeypatch):
    """The warning window the advisory check exists for."""
    import consensus.admission as admission

    monkeypatch.setattr(admission, "_tip_effective_spec_texts", lambda: [
        ("application_rules",
         "always ( (i18[t]:bv[24] = { #x01 }:bv[24]) -> (o13[t]:bv[24] = { #x01 }:bv[24]) )."),
    ])
    entry = governance_with_a_scheduled_patch(monkeypatch, {"approval_slots_active": True})
    assert entry["precheck"] == "fail"
    assert "cannot be activated on this chain" in entry["precheck_error"]
