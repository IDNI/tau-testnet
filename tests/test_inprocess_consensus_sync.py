"""Under worker-backed authority the in-process interpreter holds genesis.tau and
the consensus unit only; it is neither fed user revisions nor booted from the
persisted application spec."""
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import chain_state
import tau_journal
import tau_manager

PLAN = [
    {"label": "consensus_rules", "text": "C", "persist": False},
    {"label": "application_rule_1", "text": "A", "persist": False},
    {"label": "rule_composite_o5", "text": "X", "persist": False},
]


class _Owner:
    def __init__(self, enabled):
        self.enabled = enabled


@pytest.fixture
def interp(monkeypatch):
    monkeypatch.setattr(tau_manager, "tau_test_mode", False, raising=False)
    monkeypatch.setattr(tau_manager, "tau_direct_interface", object(), raising=False)
    monkeypatch.setattr(chain_state, "_inprocess_consensus_text", "C")
    monkeypatch.setattr(chain_state, "_consensus_rules_state", "C")
    monkeypatch.setattr(chain_state, "_preprocess_tau_spec_text", lambda t: t)


def _prepared():
    entry = SimpleNamespace(kind=tau_journal.REVISION, rule_text="always (o5[t]:bv[24] = i1[t]:bv[24]).")
    return SimpleNamespace(journal_delta=[entry])


def test_advisory_plan_is_the_consensus_unit_only():
    with patch.object(chain_state, "get_tau_restore_plan", return_value=PLAN) as get_plan:
        plan = chain_state.advisory_restore_plan()
    get_plan.assert_called_once_with(use_persisted_state=True)
    assert [e["label"] for e in plan] == ["consensus_rules"]


def test_advisory_plan_is_empty_without_a_consensus_unit():
    with patch.object(chain_state, "get_tau_restore_plan", return_value=PLAN[1:]):
        assert chain_state.advisory_restore_plan() == []


def test_sync_under_authority_feeds_no_revision_and_skips_unchanged_consensus(interp):
    with patch.object(chain_state.tau_authority, "owner", return_value=_Owner(True)), \
         patch.object(tau_manager, "communicate_with_tau") as comm, \
         patch.object(chain_state, "reload_consensus_interpreter_from_state") as reload:
        chain_state._sync_inprocess_consensus(_prepared())
    comm.assert_not_called()
    reload.assert_not_called()


def test_sync_under_authority_reloads_when_consensus_changed(interp, monkeypatch):
    monkeypatch.setattr(chain_state, "_consensus_rules_state", "C2")
    with patch.object(chain_state.tau_authority, "owner", return_value=_Owner(True)), \
         patch.object(tau_manager, "communicate_with_tau") as comm, \
         patch.object(chain_state, "reload_consensus_interpreter_from_state") as reload:
        chain_state._sync_inprocess_consensus(_prepared())
    comm.assert_not_called()
    reload.assert_called_once()


def test_sync_without_authority_still_feeds_revisions(interp):
    with patch.object(chain_state.tau_authority, "owner", return_value=_Owner(False)), \
         patch.object(tau_manager, "communicate_with_tau") as comm, \
         patch.object(chain_state, "reload_consensus_interpreter_from_state") as reload:
        chain_state._sync_inprocess_consensus(_prepared())
    assert comm.call_count == 1
    assert comm.call_args.kwargs["source"] == "advisory_mirror"
    reload.assert_not_called()


def test_replay_records_the_loaded_consensus_text(monkeypatch):
    monkeypatch.setattr(chain_state, "_inprocess_consensus_text", None)
    with patch.object(chain_state, "replay_tau_restore_plan", return_value=False):
        chain_state.replay_advisory_restore_plan(PLAN[:1], source_prefix="startup")
    assert chain_state._inprocess_consensus_text == "C"


def _boot_callback(monkeypatch, *, persisted_spec, plan):
    import server
    import tau_authority

    monkeypatch.setenv("TAU_FORCE_TEST", "0")
    monkeypatch.delenv("TAU_FORCE_FRESH_START", raising=False)
    monkeypatch.delenv("TAU_RESTORE_RULES_ON_STARTUP", raising=False)
    cs = MagicMock()
    cs.get_persisted_full_tau_spec.return_value = persisted_spec
    cs.advisory_restore_plan.return_value = plan
    cs.get_tau_restore_plan.return_value = PLAN
    cs.replay_advisory_restore_plan.return_value = False
    db_module = MagicMock()
    db_module.get_canonical_head_block.return_value = {"block_number": 5}
    tm = MagicMock()
    tm.is_force_test_enabled.return_value = False
    container = SimpleNamespace(settings=SimpleNamespace(env="test"), tau_manager=tm,
                                db=db_module, chain_state=cs)
    captured = {}
    tm.set_state_restore_callback.side_effect = lambda cb: captured.setdefault("cb", cb)
    with patch.object(tau_authority.AuthoritativeTauOwner, "initialize"), \
         patch("tau_admission.enable_standby"), \
         patch("threading.Thread") as thread:
        thread.return_value.start.side_effect = RuntimeError("stop here")
        with pytest.raises(RuntimeError, match="stop here"):
            server._run_server(container)
    return captured["cb"], cs, tm


def test_boot_callback_under_authority_replays_consensus_only_and_ignores_full_spec(monkeypatch):
    cb, cs, tm = _boot_callback(monkeypatch, persisted_spec="FULL SPEC", plan=PLAN[:1])
    cb()
    tm.restore_full_tau_spec.assert_not_called()
    cs.get_tau_restore_plan.assert_not_called()
    cs.replay_advisory_restore_plan.assert_called_once_with(PLAN[:1], source_prefix="startup")
    cs.replay_tau_restore_plan.assert_not_called()
