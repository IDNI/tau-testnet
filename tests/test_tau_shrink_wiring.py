"""Integration tests for the shrink wiring in tau_manager (opt-in).

These exercise the shrink TRANSFORM + plumbing with a fake direct interface:
the interpreter is fed the shrunk runtime spec, allowlisted address stream
values shrink to bare interned ids, the classifier picks the right streams, and
DB failures fail closed.

NOT covered here (intentionally): consensus-safe canonical persistence. Shrinking
is OFF by default because reconstructing a canonical full-width COMPOSED spec from
the stateful interpreter (whose get_current_spec() is shrunk) is unsolved -- so
persisted spec / state hash under a multi-rule interpreter is not yet safe. These
tests enable shrink explicitly and assert only the transform, not persistence.
"""
import pytest

import db
import tau_manager
import tau_native
import tau_shrink as ts
from errors import TauCommunicationError

HEX96 = "ab" * 48


class FakeIface:
    """Minimal stand-in for tau_native.TauInterface (no native engine)."""

    def __init__(self):
        self.spec = ""
        self.received_rules = []
        self.last_inputs = None

    def preprocess_spec_text(self, text):
        return tau_native.TauInterface.preprocess_spec_text(text)

    def _normalize_assignment_value(self, value, allow_hex_literal=True):
        return tau_native.TauInterface._normalize_assignment_value(
            value, allow_hex_literal=allow_hex_literal
        )

    def communicate(self, rule_text=None, target_output_stream_index=0,
                    input_stream_values=None, source="", apply_rules_update=True):
        if rule_text is not None:
            self.received_rules.append(rule_text)
            self.spec = rule_text
        self.last_inputs = input_stream_values
        return "1"

    def communicate_multi(self, rule_text=None, input_stream_values=None,
                          source="", apply_rules_update=True):
        self.last_inputs = input_stream_values
        return {1: "1"}

    def get_current_spec(self):
        return self.spec

    def update_spec(self, text):
        self.spec = text


@pytest.fixture()
def direct_mode(temp_database, monkeypatch):
    """Direct mode with a FakeIface, shrink explicitly ENABLED."""
    import config
    # Set it on the settings object too: set_database_path() re-runs
    # _sync_legacy_exports, which would otherwise reset the module global.
    monkeypatch.setattr(config.settings.tau, "shrink_enabled", True)
    monkeypatch.setattr("config.TAU_SHRINK_ENABLED", True)
    # Pin the process shrink width (tiny table -> bv[8]) for deterministic asserts.
    import tau_shrink
    monkeypatch.setattr(tau_shrink, "_current_shrink_width", 8)
    iface = FakeIface()
    monkeypatch.setattr(tau_manager, "tau_test_mode", False)
    monkeypatch.setattr(tau_manager, "tau_direct_interface", iface)
    monkeypatch.setattr(tau_manager, "last_known_tau_spec", None)
    monkeypatch.setattr(tau_manager, "_current_prepared_spec", None)
    monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset())
    monkeypatch.setattr(tau_manager, "_rules_handler", None)
    tau_manager.tau_ready.set()
    return iface


def _rule(body):
    return f"always ( {body} )."


EQ_RULE = _rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]")


def test_interpreter_receives_shrunk_rule(direct_mode):
    iface = direct_mode
    tau_manager.communicate_with_tau(rule_text=EQ_RULE, target_output_stream_index=0)
    assert iface.received_rules, "interpreter never got the rule"
    assert "bv[384]" not in iface.received_rules[-1]
    assert "i12[t]:bv[8]" in iface.received_rules[-1]  # smallest width for a tiny table
    assert tau_manager._runtime_shrunk_streams == frozenset({12})


def test_runtime_shrink_set_accumulates_across_loaded_rules(direct_mode):
    tau_manager.communicate_with_tau(rule_text=EQ_RULE, target_output_stream_index=0)
    assert tau_manager._runtime_shrunk_streams == frozenset({12})
    # The live interpreter accumulates rules via the u-stream, so a later rule
    # with no shrinkable streams must NOT drop i12 from the shrunk set. Replacing
    # (the old behavior) made e.g. the final builtin wipe i3/i4, after which a
    # transfer fed a raw `{ #x.. }:bv[384]` the engine rejects ("Unexpected '{'").
    tau_manager.communicate_with_tau(
        rule_text=_rule("o2[t]:bv[24] = i1[t]:bv[24]"), target_output_stream_index=0
    )
    assert tau_manager._runtime_shrunk_streams == frozenset({12})


def test_multi_shrinks_i12_stream_value_to_bare_id(direct_mode):
    tau_manager.communicate_with_tau(rule_text=EQ_RULE, target_output_stream_index=0)
    tau_manager.communicate_with_tau_multi(
        input_stream_values={1: "10", 12: f"{{ #x{HEX96} }}:bv[384]"}
    )
    sent = direct_mode.last_inputs
    assert "bv[384]" not in str(sent[12])
    assert sent[12] == "1"  # bare interned id, same id the rule literal got


def test_node_local_runtime_ids_differ_but_transform_is_deterministic(direct_mode, tmp_path):
    import config

    def _switch_db(name):
        if getattr(db, "_db_conn", None) is not None:
            db._db_conn.close()
            db._db_conn = None
        config.set_database_path(str(tmp_path / name))
        db.init_db()

    _switch_db("node_a.sqlite")
    tau_manager.communicate_with_tau(rule_text=EQ_RULE, target_output_stream_index=0)
    a = direct_mode.received_rules[-1]

    _switch_db("node_b.sqlite")
    db.get_string_id("bv384:unrelated-preseed")  # takes id 1
    iface_b = FakeIface()
    tau_manager.tau_direct_interface = iface_b
    tau_manager._runtime_shrunk_streams = frozenset()
    tau_manager.communicate_with_tau(rule_text=EQ_RULE, target_output_stream_index=0)
    b = iface_b.received_rules[-1]

    # Node-local ids differ -- which is why shrunk values are never persisted/hashed;
    # the canonical-raw application-rules accumulation (not this) drives the state hash.
    assert "{ 1 }:bv[8]" in a
    assert "{ 2 }:bv[8]" in b


def test_db_error_during_stream_shrink_aborts(direct_mode, monkeypatch):
    tau_manager.communicate_with_tau(rule_text=EQ_RULE, target_output_stream_index=0)
    assert tau_manager._runtime_shrunk_streams == frozenset({12})
    monkeypatch.setattr(db, "get_string_id",
                        lambda key: (_ for _ in ()).throw(RuntimeError("db down")))
    with pytest.raises(TauCommunicationError):
        tau_manager.communicate_with_tau_multi(
            input_stream_values={12: f"{{ #x{HEX96} }}:bv[384]"}
        )


def test_shrink_disabled_passes_full_width(direct_mode, monkeypatch):
    monkeypatch.setattr("config.TAU_SHRINK_ENABLED", False)
    tau_manager.communicate_with_tau(rule_text=EQ_RULE, target_output_stream_index=0)
    assert "bv[384]" in direct_mode.received_rules[-1]
    assert tau_manager._runtime_shrunk_streams == frozenset()


def test_application_rules_state_canonical_and_width_independent(temp_database, monkeypatch):
    """CONSENSUS CORE: the hashed application-rules state is canonical full-width
    and byte-identical whether shrink is ON or OFF -- the interpreter gets the
    shrunk form, but the state (and thus the consensus hash) never does."""
    import chain_state
    import config
    import tau_shrink

    monkeypatch.setattr(config.settings.tau, "shrink_enabled", True)
    monkeypatch.setattr(tau_manager, "tau_test_mode", False)
    tau_manager.tau_ready.set()
    tau_manager.set_rules_handler(chain_state.save_effective_tau_spec)
    try:
        def _apply(enabled):
            monkeypatch.setattr("config.TAU_SHRINK_ENABLED", enabled)
            monkeypatch.setattr(tau_shrink, "_current_shrink_width", 8)
            chain_state._application_rules_state = ""
            chain_state._consensus_rules_state = ""
            iface = FakeIface()
            monkeypatch.setattr(tau_manager, "tau_direct_interface", iface)
            monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset())
            tau_manager.communicate_with_tau(
                rule_text=EQ_RULE, target_output_stream_index=0, apply_rules_update=True
            )
            return chain_state.get_application_rules_state(), iface

        on_state, on_iface = _apply(True)
        off_state, _ = _apply(False)
    finally:
        tau_manager.set_rules_handler(None)

    assert on_state == off_state                      # width-independent
    assert f"#x{HEX96}" in on_state and "bv[384]" in on_state   # canonical full-width
    assert "{ 1 }:bv[8]" in on_iface.received_rules[-1]  # interpreter got the shrunk form
