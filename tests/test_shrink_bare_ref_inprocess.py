"""The in-process paths and a bare reference with no width source.

The process cannot plan again, so a bare reference to a stream that it runs
shrunk stops at the guard as a node-local conflict. Other refusals keep the
engine text.
"""
import threading
from unittest.mock import MagicMock, patch

import pytest

import tau_manager
from errors import TauSpecRejected

KEY = "a1" * 48
BARE_I13 = ("always ( i13[t] = ({ #x" + KEY + " }:bv[384])"
            " -> o13[t]:bv[24] = { #x000001 }:bv[24] ).")
ENGINE_TEXT = "Tau native step reported an error: type inference produced no tree"


class _Interface:
    """Refuses every rule with the given codes. Answers every other step."""

    def __init__(self, codes):
        self.codes = codes
        self.rules = []
        self.last_revision_receipt = None

    def communicate(self, *, rule_text=None, **_kwargs):
        if rule_text is not None:
            self.rules.append(rule_text)
            raise TauSpecRejected(ENGINE_TEXT, codes=self.codes)
        return "1"

    def get_current_spec(self):
        return ""


@pytest.fixture
def in_process(temp_database, monkeypatch):
    def _install(codes, shrunk=frozenset({13})):
        ready = threading.Event()
        ready.set()
        monkeypatch.setattr(tau_manager, "tau_ready", ready)
        monkeypatch.setattr(tau_manager, "tau_test_mode", False)
        monkeypatch.setattr(tau_manager, "tau_direct_interface", _Interface(codes))
        monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset(shrunk))
        return tau_manager.tau_direct_interface
    return _install


def _refusal(rule_text):
    with pytest.raises(TauSpecRejected) as info:
        tau_manager.communicate_with_tau(rule_text=rule_text, apply_rules_update=False)
    return info.value


def test_in_process_bare_ref_of_a_shrunk_stream_stops_at_the_guard(in_process):
    import tau_shrink

    engine = in_process(codes=(4, 15))
    with pytest.raises(tau_shrink.ShrinkTypeConflict, match="i13"):
        tau_manager.communicate_with_tau(rule_text=BARE_I13, apply_rules_update=False)
    assert engine.rules == []


def test_in_process_other_refusal_keeps_its_cause(in_process):
    in_process(codes=(13,), shrunk=frozenset())
    assert str(_refusal(BARE_I13)) == ENGINE_TEXT


def test_in_process_no_hint_when_the_stream_is_not_shrunk(in_process):
    in_process(codes=(4,), shrunk=frozenset())
    assert str(_refusal(BARE_I13)) == ENGINE_TEXT


def _apply_block(rule_text):
    from bls_keys import pubkey_hex, sign_payload
    from consensus.engine import TauConsensusEngine
    from consensus.state import TauStateSnapshot

    secret = 44444
    sender = pubkey_hex(secret)
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    tx = sign_payload({
        "tx_id": "r1",
        "tx_type": "user_tx",
        "sender_pubkey": sender,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "fee_limit": "1000",
        "operations": {"0": rule_text},
    }, secret)
    with patch("tau_manager.communicate_with_tau_multi", return_value={9: "7"}), \
         patch("chain_state.get_application_rules_state", return_value=""):
        return engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [tx], 1700000000,
            target_balances={sender: 1000},
            target_sequences={},
            proposer_pubkey="bb" * 48,
            block_height=1,
        )


def test_block_apply_bare_ref_of_a_shrunk_stream_is_node_local(in_process):
    engine = in_process(codes=(4,))
    result = _apply_block(BARE_I13)
    assert "r1" in [t.get("tx_id") for t in result.rejected_transactions]
    receipt = result.receipts["r1"]
    assert receipt["reason"] == "rule_type_conflict"
    assert "Error: runtime type conflict: rule references i13" in "\n".join(receipt["logs"])
    assert engine.rules == []


def test_block_apply_other_rejection_keeps_its_cause(in_process):
    in_process(codes=(13,), shrunk=frozenset())
    result = _apply_block(BARE_I13)
    logs = "\n".join(result.receipts["r1"]["logs"])
    assert f"Error: rule rejected by Tau: {ENGINE_TEXT}" in logs
    assert "without a width" not in logs
