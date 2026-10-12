"""Consensus-owned output streams (o0-o4, o6, o7, o9) against the REAL engine.

A user rule that writes one of these streams is an unguarded unit, so on the
real engine it displaces the builtin/consensus value for EVERY sender. The
admission screen refuses such text, but a proposer can skip admission, so the
live apply path has to refuse it too:

1. CHARACTERIZATION. The hostile units really do displace the fee (o9) and the
   transfer verdict (o1) -- this pins the engine behaviour the screen guards
   against, so a change in the engine that made the screen unnecessary (or
   insufficient) shows up here.

2. LIVE APPLY. A block built directly (no admission) whose first tx carries
   the hostile rule and whose second tx is an ordinary transfer: the rule tx is
   rejected as `reserved_output_stream`, the rule never reaches the engine or
   the accumulated application rules, and the transfer is still charged the
   consensus fee.

3. REPLAY. Stored blocks are canonical, so the same block under
   `replay_mode=True` keeps the old behaviour: the rule is applied.

Each case runs in a child process: the engine types streams process-wide, and
the native library segfaults on interpreter teardown, so the child prints a
sentinel line and hard-exits.
"""
import json
import os
import subprocess
import sys

import pytest


REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SENTINEL = "RESERVED_OUTPUT_RESULT "

HOSTILE_O9 = "always ( o9[t]:bv[24] = { #x000000 }:bv[24] )."
HOSTILE_O1 = "always ( o1[t]:bv[24] = { #x000000 }:bv[24] )."
HOSTILE_O1_GUARDED = (
    "always ( ( i12[t]:bv[384] = { #x" + "cc" * 48 + " }:bv[384] ) -> "
    "( o1[t]:bv[24] = { #x000000 }:bv[24] ) )."
)

AMOUNT = 100
FEE = 10


def _native_python():
    """Interpreter for the engine children.

    Defaults to the one running pytest; TAU_NATIVE_PYTHON overrides it when the
    checkout's venv and the built `tau.cpython-3XX-*.so` disagree on ABI.
    """
    return os.environ.get("TAU_NATIVE_PYTHON") or sys.executable


def _child_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO_ROOT + os.pathsep + env.get("PYTHONPATH", "")
    env["REPO_ROOT"] = REPO_ROOT
    return env


def _native_available():
    try:
        proc = subprocess.run(
            [_native_python(), "-c",
             "import tau_native; assert tau_native.load_tau_module() is not None"],
            capture_output=True, text=True, env=_child_env(), timeout=120,
        )
        return proc.returncode == 0
    except Exception:
        return False


requires_native = pytest.mark.skipif(
    not _native_available(), reason="native tau module not importable"
)


_PREAMBLE = r'''
import json, os, sys, tempfile
os.environ["TAU_ENV"] = "test"
os.environ["TAU_FORCE_TEST"] = "0"
# Raw engine for the characterization; the apply child runs as a node does.
os.environ["TAU_SHRINK_ENABLED"] = os.environ.get("CHILD_SHRINK", "false")

SENTINEL = %(sentinel)r
A = "aa" * 48
B = "bb" * 48
PROPOSER = "dd" * 48


def emit(obj):
    print(SENTINEL + json.dumps(obj))
    sys.stdout.flush()
    os._exit(0)


with open(os.path.join(os.environ["REPO_ROOT"], "data", "genesis.json")) as fh:
    GENESIS = json.load(fh)


def boot_interface(through_manager=False):
    """Genesis application rules, then consensus rules and the builtins via i0."""
    import tau_native, chain_state
    boot = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
    boot.write(GENESIS["application_rules"].strip().rstrip(".") + "\n")
    boot.close()
    iface = tau_native.TauInterface(boot.name)

    if through_manager:
        import tau_manager

        tau_manager.tau_direct_interface = iface
        tau_manager.tau_test_mode = False
        tau_manager.last_known_tau_spec = None
        tau_manager._current_prepared_spec = None
        tau_manager._runtime_shrunk_streams = frozenset()
        tau_manager.tau_ready.set()

        def revise(text):
            return tau_manager.communicate_with_tau(
                rule_text=text, target_output_stream_index=0,
                apply_rules_update=False, source="seed",
            )

        revise(GENESIS["consensus_rules"])
    else:
        def revise(text):
            return iface.communicate_multi(rule_text=text, input_stream_values={"0": text})

        revise(tau_native.TauInterface.preprocess_spec_text(GENESIS["consensus_rules"]))
    for rule in chain_state.load_builtin_rules_from_disk():
        revise(rule)
    return iface, revise
''' % {"sentinel": SENTINEL}


_CHARACTERIZE_BODY = r'''
iface, revise = boot_interface()


def step(amount="100"):
    return iface.communicate_multi(input_stream_values={
        "1": amount, "2": "1000", "3": A, "4": B, "5": "0", "6": "5",
        "7": "1000", "8": A, "9": A, "10": "1", "11": A, "12": A,
    })


def stream(outputs, index):
    value = outputs.get(index, outputs.get(str(index)))
    return None if value is None else str(value)


before = step()
revise(os.environ["HOSTILE_RULE"])
after = step()
emit({"before": {"o1": stream(before, 1), "o9": stream(before, 9)},
      "after": {"o1": stream(after, 1), "o9": stream(after, 9)}})
'''


_APPLY_BODY = r'''
import logging
from unittest.mock import MagicMock, patch

import config
config.set_database_path(os.path.join(tempfile.mkdtemp(), "reserved.sqlite"))
import db
db.init_db()
import tau_manager
import tau_shrink
import chain_state
from block import Block
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot

tau_shrink.set_shrink_width_from_db()
iface, revise = boot_interface(through_manager=True)
# As a node wires it: an accepted rule lands in the hashed accumulation.
tau_manager.set_rules_handler(chain_state.save_effective_tau_spec)

HOSTILE = os.environ["HOSTILE_RULE"]
REPLAY = os.environ["REPLAY_MODE"] == "1"
AMOUNT = int(os.environ["AMOUNT"])

tx_rule = {"tx_id": "rule-tx", "tx_type": "user_tx", "sender_pubkey": A,
           "sequence_number": 0, "fee_limit": "1000",
           "operations": {"0": HOSTILE}}
tx_transfer = {"tx_id": "transfer-tx", "tx_type": "user_tx", "sender_pubkey": B,
               "sequence_number": 0, "fee_limit": "1000",
               "operations": {"1": [[B, A, str(AMOUNT)]]}}

lifecycle = ConsensusLifecycleManager(active_validators=[PROPOSER])
parent_app_rules = GENESIS["application_rules"]
parent = TauStateSnapshot(
    state_hash="0" * 64, tau_bytes=parent_app_rules.encode("utf-8"),
    metadata={"balances": {A: 1000, B: 1000}, "sequence_numbers": {},
              "last_transfer_ts": {}, "lifecycle_manager": lifecycle,
              "active_consensus_id": ""},
)
block = Block.create(block_number=1, previous_hash="0" * 64,
                     transactions=[tx_rule, tx_transfer],
                     proposer_pubkey=PROPOSER, timestamp=1700000000)
view = ActiveConsensusView(target_height=1,
                           consensus_rules=GENESIS["consensus_rules"],
                           active_validators=[bytes.fromhex(PROPOSER)])

engine = TauConsensusEngine(state_store=MagicMock())
engine._state_store.commit.side_effect = lambda snap: snap
with patch("consensus.engine.verify_tx_signature", return_value=(True, "")):
    result = engine.apply_block(view, block, parent, replay_mode=REPLAY)

outcomes = {o.tx_id: o for o in result.outcomes}
balances = result.next_snapshot.metadata["balances"]
next_rules = result.next_snapshot.tau_bytes.decode("utf-8")
emit({
    "accepted": sorted(result.accepted_tx_ids),
    "invalid": sorted(result.invalid_tx_ids),
    "rule_reason": outcomes["rule-tx"].reason if "rule-tx" in outcomes else None,
    "rule_logs": list(outcomes["rule-tx"].receipt_logs) if "rule-tx" in outcomes else [],
    "transfer_logs": list(outcomes["transfer-tx"].receipt_logs) if "transfer-tx" in outcomes else [],
    "rules_changed": next_rules != parent_app_rules,
    "rule_in_saved_state": chain_state._preprocess_tau_spec_text(HOSTILE)
        in (chain_state.get_application_rules_state() or ""),
    "sender_balance": balances.get(B),
    "recipient_balance": balances.get(A),
    "proposer_balance": balances.get(PROPOSER, 0),
})
'''


def _run_child(tmp_path, name, body, env_extra):
    script = tmp_path / (name + ".py")
    script.write_text(_PREAMBLE + "\n" + body)
    env = _child_env()
    env.update(env_extra)
    proc = subprocess.run(
        [_native_python(), str(script)],
        capture_output=True, text=True, env=env, cwd=REPO_ROOT, timeout=600,
    )
    for line in proc.stdout.splitlines():
        if line.startswith(SENTINEL):
            return json.loads(line[len(SENTINEL):])
    pytest.fail(
        f"child {name} produced no result (rc={proc.returncode})\n"
        f"--- stdout ---\n{proc.stdout[-3000:]}\n--- stderr ---\n{proc.stderr[-3000:]}"
    )


@requires_native
@pytest.mark.parametrize(
    "stream,rule,expect_before",
    [
        ("o9", HOSTILE_O9, FEE),
        ("o1", HOSTILE_O1, AMOUNT),
        ("o1", HOSTILE_O1_GUARDED, AMOUNT),
    ],
    ids=["o9-unguarded", "o1-unguarded", "o1-sender-guarded"],
)
def test_hostile_unit_displaces_the_builtin_value(tmp_path, stream, rule, expect_before):
    """Pins the engine behaviour the reserved-output screen guards against: a
    later unit on a consensus-owned stream wins for every sender, even when the
    unit is guarded on someone else's pubkey."""
    out = _run_child(tmp_path, "characterize", _CHARACTERIZE_BODY,
                     {"HOSTILE_RULE": rule})
    assert int(out["before"][stream]) == expect_before
    assert int(out["after"][stream]) == 0


def _apply(tmp_path, rule, replay):
    return _run_child(
        tmp_path, "apply", _APPLY_BODY,
        {"HOSTILE_RULE": rule, "REPLAY_MODE": "1" if replay else "0",
         "CHILD_SHRINK": "true", "AMOUNT": str(AMOUNT)},
    )


@requires_native
@pytest.mark.parametrize(
    "rule", [HOSTILE_O9, HOSTILE_O1], ids=["o9", "o1"],
)
def test_live_apply_rejects_the_hostile_rule_and_keeps_the_builtin_values(tmp_path, rule):
    out = _apply(tmp_path, rule, replay=False)

    assert out["invalid"] == ["rule-tx"], out
    assert out["accepted"] == ["transfer-tx"], out
    assert out["rule_reason"] == "reserved_output_stream", out
    assert not out["rules_changed"], "the rejected rule was accumulated"
    assert not out["rule_in_saved_state"], "the rejected rule was persisted"

    # The rule never reached the engine: the transfer still sees o1 = amount
    # and pays the consensus fee, which went to the proposer.
    assert f"Tau(transfer) o1: {AMOUNT}" in " ".join(out["transfer_logs"]), out
    assert out["sender_balance"] == 1000 - AMOUNT - FEE, out
    assert out["recipient_balance"] == 1000 + AMOUNT, out
    assert out["proposer_balance"] == FEE, out


@requires_native
def test_replay_applies_the_rule_a_stored_block_already_carried(tmp_path):
    """Replay never re-litigates a stored block: the screen is live-only, so the
    rule is applied and, being the later unit, zeroes the fee."""
    out = _apply(tmp_path, HOSTILE_O9, replay=True)

    assert out["rule_reason"] != "reserved_output_stream", out
    assert "rule-tx" in out["accepted"], out
    assert out["rules_changed"], out
    assert out["rule_in_saved_state"], out
    assert out["proposer_balance"] == 0, out
