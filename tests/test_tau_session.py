"""The session abstraction and its step log.

`InProcessSession` must be exactly what the engine did before -- the point of it
is to name the calls and record them, not to change them.
"""
from unittest.mock import MagicMock

import pytest

import tau_session as ts


class _Manager:
    def __init__(self, receipt=None):
        self.tau_ready = MagicMock()
        self.tau_ready.is_set.return_value = True
        self.calls = []
        self._receipt = receipt

    def communicate_with_tau(self, **kwargs):
        self.calls.append(("single", kwargs))
        return "ok"

    def communicate_with_tau_multi(self, **kwargs):
        self.calls.append(("multi", kwargs))
        return {9: "7"}

    def get_last_revision_receipt(self):
        return self._receipt


def test_apply_rule_dispatches_exactly_as_before():
    m = _Manager()
    s = ts.InProcessSession(manager=m)
    assert s.apply_rule("always ( o5[t]:bv[24] = { #x1 }:bv[24] ).") == "ok"
    kind, kwargs = m.calls[0]
    assert kind == "single"
    assert kwargs["rule_text"].startswith("always")
    assert kwargs["target_output_stream_index"] == 0
    assert kwargs["apply_rules_update"] is True


def test_evaluate_dispatches_single_and_multi():
    m = _Manager()
    s = ts.InProcessSession(manager=m)
    s.evaluate({1: "5"}, target=5)
    s.evaluate({1: "5"}, multi=True)
    assert [k for k, _ in m.calls] == ["single", "multi"]


def test_the_log_records_order_and_payloads():
    m = _Manager(receipt={"outcome": "ACCEPTED_CHANGED"})
    s = ts.InProcessSession(manager=m)
    s.apply_rule("RULE")
    s.evaluate({1: "5"}, target=5)
    s.evaluate({12: "1"}, multi=True)
    trace = s.log.replay_trace()
    assert [e["kind"] for e in trace] == [ts.RULE, ts.EVAL, ts.EVAL]
    assert trace[0]["rule_text"] == "RULE"
    assert trace[1]["inputs"] == {1: "5"}
    assert s.log.entries()[0].outcome == "ACCEPTED_CHANGED"


def test_the_log_does_not_record_outputs():
    """A replay must RE-DERIVE outputs, not assume them -- otherwise it would
    confirm whatever it was told rather than reproducing the state."""
    m = _Manager()
    s = ts.InProcessSession(manager=m)
    s.evaluate({1: "5"}, target=5)
    assert "outputs" not in s.log.replay_trace()[0]


def test_advisory_reads_stay_out_of_the_log():
    """An unrecorded step desyncs a later replay, so anything that must not be
    part of the history says so explicitly."""
    m = _Manager()
    s = ts.InProcessSession(manager=m)
    s.evaluate({7: "1"}, target=7, record=False)
    assert len(s.log) == 0
    assert m.calls, "the call still happened; only the RECORD was suppressed"


def test_reset_clears_the_log_and_moves_the_anchor():
    m = _Manager()
    s = ts.InProcessSession(manager=m)
    s.apply_rule("RULE")
    s.log.reset(anchor="block-7")
    assert len(s.log) == 0 and s.log.anchor == "block-7"


def test_readiness_waits_then_reports():
    m = _Manager()
    m.tau_ready.is_set.side_effect = [False, True]
    s = ts.InProcessSession(manager=m)
    assert s.ready(timeout=0.01) is True
    m.tau_ready.wait.assert_called_once()


def test_the_default_session_is_replaceable():
    sentinel = object()
    ts.set_default_session(sentinel)
    try:
        assert ts.default_session() is sentinel
    finally:
        ts.reset_default_session()


# --- the engine drives the session it is given --------------------------------

def _apply_with(session, rule="always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."):
    from unittest.mock import patch
    from consensus.engine import TauConsensusEngine
    from consensus.state import TauStateSnapshot

    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    sender = "aa" * 48
    tx = {
        "tx_id": "r1", "tx_type": "user_tx", "sender_pubkey": sender,
        "sequence_number": 0, "fee_limit": "1000", "operations": {"0": rule},
    }
    # The session's own dispatches go through its injected manager; the engine's
    # OTHER evaluator calls (fees, transfers) still go to tau_manager directly --
    # they are not on the session yet, which is exactly what this stage is.
    with patch("tau_manager.communicate_with_tau_multi", return_value={9: "7"}), \
         patch("tau_manager.communicate_with_tau", return_value="ok"), \
         patch("tau_manager.tau_ready") as ready, \
         patch("chain_state.get_application_rules_state", return_value=rule):
        ready.is_set.return_value = True
        return engine.apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [tx], 1700000000,
            target_balances={sender: 1000},
            target_sequences={},
            proposer_pubkey="bb" * 48,
            block_height=1,
            session=session,
        )


def test_apply_uses_the_supplied_session():
    m = _Manager(receipt={"outcome": "ACCEPTED_CHANGED", "accepted": True})
    session = ts.InProcessSession(manager=m)
    _apply_with(session)
    assert any(kind == "single" and kwargs.get("rule_text")
               for kind, kwargs in m.calls), m.calls


def test_apply_records_the_rule_in_the_step_log():
    """The log is what a fresh worker replays to reach this state, so a rule the
    engine applied has to be in it."""
    m = _Manager(receipt={"outcome": "ACCEPTED_CHANGED", "accepted": True})
    session = ts.InProcessSession(manager=m)
    rule = "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
    _apply_with(session, rule=rule)
    rules = [e for e in session.log.entries() if e.kind == ts.RULE]
    assert rules, "the applied rule is missing from the step log"
    assert rules[0].rule_text.strip() == rule
    assert rules[0].outcome == "ACCEPTED_CHANGED"


def test_the_default_session_follows_a_substituted_manager():
    """Much of the suite drives apply by patching `consensus.engine.tau_manager`.
    A session that imported its own reference would evaluate against the real
    interpreter while the engine thought it had substituted one -- two evaluators
    disagreeing, which is the exact failure mode this refactor exists to remove.
    """
    from unittest.mock import patch
    import consensus.engine as engine

    fake = _Manager(receipt={"outcome": "ACCEPTED_CHANGED", "accepted": True})
    fake.tau_comm_lock = MagicMock()
    with patch.object(engine, "tau_manager", fake):
        session = ts.InProcessSession(manager=engine.tau_manager)
        session.apply_rule("RULE")
    assert fake.calls, "the substituted manager was bypassed"
