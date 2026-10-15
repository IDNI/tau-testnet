"""Governance activation must collapse the live Tau interpreter to the single
active consensus revision.

`engine.apply_block` routes each activated revision through `i0`, so a
long-running node accumulates the CONJUNCTION of every revision it ever applied,
while a freshly started node loads only the last one. Left alone, the two
disagree on o6/o7 -- a running node and a restarted node would judge the same
block differently. `chain_state.process_new_block` therefore calls
`reload_consensus_interpreter_from_state()` whenever an applied block changed
`_consensus_rules_state`.

These tests pin the helper's contract. The end-to-end activation path is covered
by the native stake-switch and replay-determinism suites.
"""
import os
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import chain_state
import config
import tau_manager


def _with_program_file(text="always (o0[t] = i0[t]).\n"):
    fd, path = tempfile.mkstemp(suffix=".tau")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
    return path


def test_reload_is_a_noop_until_tau_is_ready():
    """Before the engine is up there is no live interpreter to collapse, and
    touching the restore path would race the boot sequence."""
    was_set = tau_manager.tau_ready.is_set()
    tau_manager.tau_ready.clear()
    try:
        with patch.object(tau_manager, "restore_full_tau_spec") as restore:
            chain_state.reload_consensus_interpreter_from_state()
        restore.assert_not_called()
    finally:
        if was_set:
            tau_manager.tau_ready.set()


def test_reload_replays_the_persisted_restore_plan():
    """The reload must reproduce a restart exactly: reset to the genesis program,
    then replay the PERSISTED restore plan (single active consensus revision +
    application units + builtin rules)."""
    path = _with_program_file()
    was_set = tau_manager.tau_ready.is_set()
    tau_manager.tau_ready.set()
    original = config.TAU_PROGRAM_FILE
    config.TAU_PROGRAM_FILE = path
    plan = [{"kind": "consensus", "text": "always (o6[t]:bv[16] = i10[t]:bv[16])."}]
    try:
        with patch.object(tau_manager, "restore_full_tau_spec") as restore, \
             patch.object(chain_state, "get_tau_restore_plan", return_value=plan) as get_plan, \
             patch.object(chain_state, "replay_tau_restore_plan") as replay:
            chain_state.reload_consensus_interpreter_from_state(source_prefix="activation")

        restore.assert_called_once()
        assert restore.call_args.args[0] == "always (o0[t] = i0[t]).\n"
        get_plan.assert_called_once_with(use_persisted_state=True)
        replay.assert_called_once_with(plan, source_prefix="activation")
    finally:
        config.TAU_PROGRAM_FILE = original
        if not was_set:
            tau_manager.tau_ready.clear()
        os.remove(path)


def test_reload_failure_does_not_break_block_processing():
    """The caller is mid-`process_new_block` with the block already committed, so
    a failed reload must be logged and swallowed, not propagated."""
    path = _with_program_file()
    was_set = tau_manager.tau_ready.is_set()
    tau_manager.tau_ready.set()
    original = config.TAU_PROGRAM_FILE
    config.TAU_PROGRAM_FILE = path
    try:
        with patch.object(tau_manager, "restore_full_tau_spec", side_effect=RuntimeError("engine down")), \
             patch.object(chain_state, "replay_tau_restore_plan") as replay:
            chain_state.reload_consensus_interpreter_from_state()
        replay.assert_not_called()
    finally:
        config.TAU_PROGRAM_FILE = original
        if not was_set:
            tau_manager.tau_ready.clear()
        os.remove(path)


# --- worker-backed authority: the in-process interpreter is consensus-only ----

class _Owner:
    enabled = True


def _authority_reload(plan, *, held, consensus="C"):
    path = _with_program_file()
    was_set = tau_manager.tau_ready.is_set()
    tau_manager.tau_ready.set()
    original = (config.TAU_PROGRAM_FILE, chain_state._inprocess_consensus_text,
                chain_state._consensus_rules_state)
    config.TAU_PROGRAM_FILE = path
    chain_state._inprocess_consensus_text = held
    chain_state._consensus_rules_state = consensus
    try:
        with patch.object(chain_state.tau_authority, "owner", return_value=_Owner()), \
             patch.object(tau_manager, "restore_full_tau_spec") as restore, \
             patch.object(chain_state, "get_tau_restore_plan", return_value=plan), \
             patch.object(chain_state, "replay_tau_restore_plan") as replay, \
             patch.object(chain_state, "_preprocess_tau_spec_text", side_effect=lambda t: t):
            chain_state.reload_consensus_interpreter_from_state()
        return restore, replay
    finally:
        (config.TAU_PROGRAM_FILE, chain_state._inprocess_consensus_text,
         chain_state._consensus_rules_state) = original
        if not was_set:
            tau_manager.tau_ready.clear()
        os.remove(path)


MIXED_PLAN = [
    {"label": "consensus_rules", "text": "C", "persist": False},
    {"label": "application_rule_1", "text": "A", "persist": False},
    {"label": "builtin_rule_1", "text": "B", "persist": False},
    {"label": "rule_composite_o5", "text": "X", "persist": False},
]


def test_reload_under_authority_replays_the_consensus_unit_only():
    restore, replay = _authority_reload(MIXED_PLAN, held="old")
    restore.assert_called_once()
    replay.assert_called_once()
    assert [e["label"] for e in replay.call_args.args[0]] == ["consensus_rules"]


def test_reload_under_authority_is_idempotent_for_unchanged_consensus():
    restore, replay = _authority_reload(MIXED_PLAN, held="C")
    restore.assert_not_called()
    replay.assert_not_called()
