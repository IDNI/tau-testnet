"""W7: a transaction an earlier check already rejected must not mutate state.

The routed `o5` clause path MUTATES before it validates anything of its own: it
resolves the sender's open approval requests (`resolve_all_for_sender`) and
replaces or removes their registered clause (`accepted_clauses`). It used to be
guarded only by the reserved-stream error, so a transaction already rejected by
the sequence check still had its policy replaced and its pending approvals
cancelled -- a "rejected" transaction with visible side effects.
"""
from unittest.mock import MagicMock, patch

import pytest

import tau_defs
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot

SENDER = "aa" * 48
PROPOSER = "bb" * 48
STREAM = tau_defs.USER_POLICY_STREAM_INDEX
# A registered clause carries NO i12 guard -- the composer supplies the scope.
CLAUSE = f"always ( o{STREAM}[t]:bv[24] = {{ #x000000 }}:bv[24] )."


class _Offers:
    def __init__(self):
        self.accepted_clauses = {(SENDER.lower(), STREAM): "PREVIOUS POLICY"}

    def clauses_for_stream(self, stream):
        return {k: v for k, v in self.accepted_clauses.items() if k[1] == stream}

    def composite_for_stream(self, stream):
        return f"always ( o{stream}[t]:bv[24] = {{ #x000001 }}:bv[24] )."


class _Approvals:
    def __init__(self):
        self.resolved = []

    def resolve_all_for_sender(self, sender, status):
        self.resolved.append((sender, status))
        return []


def _lifecycle():
    mgr = MagicMock()
    mgr.approval_slots_active = True
    mgr.rule_offers = _Offers()
    mgr.approval_requests = _Approvals()
    return mgr


def _apply(*, sequence_number, seq_state=None):
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    lifecycle = _lifecycle()
    tx = {
        "tx_id": "r1",
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "sequence_number": sequence_number,
        "fee_limit": "100",
        "operations": {"0": CLAUSE},
    }
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", return_value="ok"), \
         patch("tau_manager.communicate_with_tau_multi", return_value={9: "7"}), \
         patch("chain_state.get_application_rules_state", return_value=""):
        ready.is_set.return_value = True
        result = engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [tx], 1700000000,
            target_balances={SENDER: 1000},
            target_sequences=dict(seq_state or {}),
            proposer_pubkey=PROPOSER,
            block_height=1,
            target_lifecycle=lifecycle,
        )
    return result, lifecycle


def test_a_stale_sequence_number_leaves_policy_and_approvals_untouched():
    result, lifecycle = _apply(sequence_number=0, seq_state={SENDER: 5})
    assert "r1" in [t.get("tx_id") for t in result.rejected_transactions]
    assert lifecycle.rule_offers.accepted_clauses == {(SENDER.lower(), STREAM): "PREVIOUS POLICY"}, \
        "a rejected transaction replaced the sender's registered policy"
    assert lifecycle.approval_requests.resolved == [], \
        "a rejected transaction cancelled the sender's open approval requests"


def test_a_live_transaction_still_registers_its_clause():
    """Guard the guard: the verdict check must not disable routing itself."""
    _, lifecycle = _apply(sequence_number=0, seq_state={})
    assert lifecycle.rule_offers.accepted_clauses[(SENDER.lower(), STREAM)] != "PREVIOUS POLICY", \
        "a valid transaction must still register its clause"


# --- the rule must not survive a later rejection ------------------------------

RULE = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."


def _apply_rule_with_fee(*, fee_limit, saves, states):
    """Apply a rule-bearing tx whose fee settlement may reject it.

    `states` is consumed by the application-rules getter, so the state captured
    BEFORE the rule is applied differs from the state after it landed -- which is
    what makes the rollback assertion meaningful.
    """
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    tx = {
        "tx_id": "r1",
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "sequence_number": 0,
        "fee_limit": fee_limit,
        "operations": {"0": RULE},
    }

    def _get_state():
        return states.pop(0) if len(states) > 1 else states[0]

    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", return_value="ok"), \
         patch("tau_manager.communicate_with_tau_multi", return_value={9: "7"}), \
         patch("chain_state.get_application_rules_state", side_effect=_get_state), \
         patch("chain_state.save_application_rules_state",
               side_effect=lambda text: saves.append(text), create=True):
        ready.is_set.return_value = True
        return engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [tx], 1700000000,
            target_balances={SENDER: 1000},
            target_sequences={},
            proposer_pubkey=PROPOSER,
            block_height=1,
        )


def test_a_rule_rejected_by_fee_settlement_is_rolled_back():
    """Probe on the unpatched engine: receipt `fee_limit_exceeded`, fee_charged 0,
    transaction rejected -- and the returned snapshot still carried the rule."""
    saves = []
    result = _apply_rule_with_fee(fee_limit="1", saves=saves, states=["", RULE])
    assert "r1" in [t.get("tx_id") for t in result.rejected_transactions]
    assert saves == [""], (
        "a rejected transaction left its rule in canonical application state"
    )


def test_an_accepted_rule_is_not_rolled_back():
    """Guard the guard: the rollback must not fire for a transaction that stays."""
    saves = []
    result = _apply_rule_with_fee(fee_limit="1000", saves=saves, states=["", RULE])
    assert "r1" in [t.get("tx_id") for t in result.accepted_transactions]
    assert saves == [], "an accepted transaction must keep its rule"
