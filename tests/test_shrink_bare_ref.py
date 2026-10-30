"""A bare stream reference takes its width from its equality partner.

The engine types `i4[t] = { #x.. }:bv[384]` as bv[384]. A planner that leaves
the bare `i4` wide makes a process with a shrunk `i4` refuse a valid rule.
"""
import pytest

import tau_manager
import tau_shrink as ts

HEX96 = "a1" * 48
OTHER96 = "cd" * 48


def _rule(body: str) -> str:
    return f"always ( {body} )."


def test_bare_ref_against_a_wide_literal_is_shrunk(temp_database):
    p = ts.prepare_rule(_rule(f"!(i4[t] = {{#x{HEX96}}}:bv[384])"))
    w = ts.current_shrink_width()
    assert p.shrunk_streams == frozenset({4})
    assert f"i4[t]:bv[{w}]" in p.runtime_text
    assert "bv[384]" not in p.runtime_text
    assert p.wide_streams_unshrunk == frozenset()


def test_bare_ref_takes_the_width_of_an_annotated_partner(temp_database):
    p = ts.prepare_rule(_rule("i3[t]:bv[384] = i4[t]"))
    assert p.shrunk_streams == frozenset({3, 4})


def test_bare_and_annotated_forms_give_one_id(temp_database):
    bare = ts.prepare_rule(_rule(f"i4[t] = {{ #x{HEX96} }}:bv[384]"))
    annotated = ts.prepare_rule(_rule(f"i4[t]:bv[384] = {{ #x{HEX96} }}:bv[384]"))
    assert bare.runtime_text == annotated.runtime_text


def test_bare_ref_with_a_wide_literal_left_wide_is_reported(temp_database):
    # Arithmetic keeps i4 plain. The fallback must still name it as wide.
    text = _rule(f"(i4[t] = {{ #x{HEX96} }}:bv[384]) && (i4[t]:bv[384] > {{ #x{OTHER96} }}:bv[384])")
    p = ts.prepare_rule(text)
    assert 4 not in p.shrunk_streams
    assert 4 in p.wide_streams_unshrunk
    assert 4 in ts.wide_input_streams(f"i4[t] = {{ #x{HEX96} }}:bv[384]")


def test_bare_ref_next_to_a_partner_of_another_width_is_not_shrunk(temp_database):
    p = ts.prepare_rule(_rule("(i4[t] = i3[t]:bv[384]) && (i4[t] = i5[t]:bv[64])"))
    assert 4 not in p.shrunk_streams


def test_bare_ref_takes_the_canonical_width_without_a_partner(temp_database):
    # No equality edge: the stream stays plain, and the guard can see it as wide.
    text = _rule(f"!(i4[t] = ({{ #x{HEX96} }}:bv[384]))")
    p = ts.prepare_rule(text)
    assert 4 not in p.shrunk_streams
    assert 4 in p.wide_streams_unshrunk
    assert 4 in ts.wide_input_streams(text)


def test_bare_refs_of_two_canonical_streams_are_shrunk(temp_database):
    p = ts.prepare_rule(_rule("i4[t] = i3[t]"))
    assert p.shrunk_streams == frozenset({3, 4})


def test_a_bare_ref_with_no_width_source_stays_unresolved(temp_database):
    # i13 has no canonical width, and its partner gives none.
    p = ts.prepare_rule(_rule("i13[t] = i14[t]"))
    assert p.shrunk_streams == frozenset()
    assert p.wide_streams_unshrunk == frozenset()


def test_the_guard_refuses_a_plain_bare_ref_of_a_shrunk_stream(temp_database, monkeypatch):
    p = ts.prepare_rule(_rule(f"!(i4[t] = ({{ #x{HEX96} }}:bv[384]))"))
    monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset({3, 4}))
    with pytest.raises(ts.ShrinkTypeConflict):
        tau_manager._assert_representation_compatible(p)


def test_a_plain_stream_makes_its_equality_partners_plain(temp_database):
    """Rule 02 compares i3 with i4. If a candidate needs i4 plain, i3 must be
    plain too, or the session feeds an interned i3 next to a full-width i4."""
    import chain_state
    import tau_reconstruction

    rule02 = chain_state._preprocess_tau_spec_text(chain_state.load_builtin_rules_from_disk()[1])
    candidate = _rule(f"!(i4[t] = ({{ #x{HEX96} }}:bv[384]))")
    plan = tau_reconstruction.plan_representation(history_rules=[rule02],
                                                  candidate_rules=[candidate])
    assert {3, 4} <= set(plan.plain)
    assert not ({3, 4} & set(plan.interned))
    plan = tau_reconstruction.plan_representation(history_rules=[rule02])
    assert plan.interned == frozenset({3, 4})
