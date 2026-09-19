"""W1: the shrink layer recognises a supported fragment and never emits a
partially-shrunk, retyped or semantically different rule.

The incident these pin: `->` tokenized as `-` then `>`, both disqualifying, so the
opposite literal was skipped while the stream annotation was rewritten anyway --
`i12[t]:bv[8] = { #x<pk> }:bv[384]`, which the engine refuses with
"Incompatible type information in i12".
"""
import pytest

import tau_shrink as ts

HEX96 = "aa" * 48
HEX96_B = "bb" * 48
WFF_OPS = ["->", "<-", "<->", "^^", "&&", "||"]


def _rule(body: str) -> str:
    return f"always ( {body} )."


def _guard(op: str, pk: str = HEX96) -> str:
    return _rule(
        f"i12[t]:bv[384] = {{ #x{pk} }}:bv[384] {op} "
        f"( o5[t]:bv[24] = {{ #x000001 }}:bv[24] )"
    )


# --- the incident regression --------------------------------------------------

@pytest.mark.parametrize("op", WFF_OPS)
def test_wff_connectives_shrink_both_operands(temp_database, op):
    """Every boolean connective must leave the comparison internally consistent."""
    p = ts.prepare_rule(_guard(op))
    w = ts.current_shrink_width()
    assert p.shrink_enabled, op
    assert p.shrunk_streams == frozenset({12}), op
    assert f"i12[t]:bv[{w}]" in p.runtime_text, op
    assert "bv[384]" not in p.runtime_text, op
    assert f"#x{HEX96}" not in p.runtime_text, op


def test_unparenthesized_implication_is_the_incident_shape(temp_database):
    """The exact text the swarm submitted; pre-fix this half-shrank."""
    p = ts.prepare_rule(
        _rule(
            f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] -> "
            f"( i1[t]:bv[24] >= {{ #x000064 }}:bv[24] )"
        )
    )
    assert p.shrink_enabled
    assert "bv[384]" not in p.runtime_text
    assert ":bv[8] = { #x" not in p.runtime_text  # no mixed-width comparison


# --- shapes that need no operator at all --------------------------------------

def test_juxtaposition_and_refuses_partial_shrink(temp_database):
    """`= A B` is a compound operand; no operator exists to enumerate."""
    p = ts.prepare_rule(
        _rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] {{ #x{HEX96_B} }}:bv[384]")
    )
    assert not p.shrink_enabled
    assert p.runtime_text == p.canonical_text


def test_postfix_complement_is_disqualifying(temp_database):
    """Complementing an interned id computes over a node-local value: a wrong
    answer rather than a crash, so it must never be optimized."""
    p = ts.prepare_rule(_rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]'"))
    assert 12 not in p.shrunk_streams
    assert p.runtime_text == p.canonical_text


# --- canonical types ----------------------------------------------------------

@pytest.mark.parametrize("body", [
    f"i12[t]:bv[384] = {{ #xaa }}:bv[256]",          # stream vs literal
    "i12[t]:bv[384] = i13[t]:bv[256]",               # stream vs stream
])
def test_mismatched_canonical_widths_are_not_narrowed(temp_database, body):
    """Narrowing both sides must never make an ill-typed comparison look valid."""
    p = ts.prepare_rule(_rule(body))
    assert not p.shrink_enabled
    assert p.runtime_text == p.canonical_text


def test_literal_must_be_a_complete_representable_constant(temp_database):
    for body in (
        f"i12[t]:bv[384] = {{ #x{HEX96} + 1 }}:bv[384]",   # expression, not a constant
        f"i12[t]:bv[384] = {{ #x{'f' * 100} }}:bv[384]",   # not representable at 384
    ):
        p = ts.prepare_rule(_rule(body))
        assert not p.shrink_enabled, body


def test_nested_parentheses_do_not_launder_a_function_call(temp_database):
    p = ts.prepare_rule(_rule(f"foo((i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]))"))
    assert 12 not in p.shrunk_streams


# --- occurrence accounting and time expressions -------------------------------

def test_time_expressions_are_preserved_exactly(temp_database):
    """Rewriting the whole reference would turn i12[t-1] into i12[t] -- a silent
    change of meaning from 'previous input' to 'current input'."""
    p = ts.prepare_rule(
        _rule(
            f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] && "
            f"i12[t-1]:bv[384] = {{ #x{HEX96_B} }}:bv[384]"
        )
    )
    w = ts.current_shrink_width()
    assert p.shrink_enabled
    assert f"i12[t-1]:bv[{w}]" in p.runtime_text
    assert f"i12[t]:bv[{w}]" in p.runtime_text


def test_an_unparsed_occurrence_disqualifies_rather_than_disappears(temp_database):
    """A bare `i12` the analyzer cannot resolve must not simply be skipped."""
    p = ts.prepare_rule(_rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] && i12"))
    assert 12 not in p.shrunk_streams


def test_unannotated_stream_is_unresolved_not_invented(temp_database):
    p = ts.prepare_rule(_rule(f"i12[t] = {{ #x{HEX96} }}:bv[384]"))
    assert 12 not in p.shrunk_streams


# --- the all-or-nothing invariant ---------------------------------------------

CORPUS = (
    [_guard(op) for op in WFF_OPS]
    + [
        _rule(f"(i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]) ? "
              f"( o5[t]:bv[24] = {{ #x000001 }}:bv[24] ) : "
              f"(o5[t]:bv[24] = {{ #x000001 }}:bv[24])"),
        _rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] {{ #x{HEX96_B} }}:bv[384]"),
        _rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]'"),
        _rule(f"i12[t]:bv[384] = {{ #xaa }}:bv[256]"),
        _rule("i12[t]:bv[384] = i13[t]:bv[256]"),
        _rule(f"i12[t]:bv[384] = {{ #x{HEX96} + 1 }}:bv[384]"),
        _rule(f"foo((i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]))"),
        _rule(f"i12[t] = {{ #x{HEX96} }}:bv[384]"),
        _rule(f"i12[t]:bv[384] > {{ #x{HEX96} }}:bv[384]"),
        _rule("i12[t]:bv[384] != 0"),
        _rule("i3[t]:bv[384] = i4[t]:bv[384]"),
        _rule(f"(i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]) && "
              f"(i3[t]:bv[384] > {{ #x{HEX96_B} }}:bv[384])"),
    ]
)


@pytest.mark.parametrize("rule_text", CORPUS)
def test_no_rule_is_ever_partially_shrunk(temp_database, rule_text):
    """Whatever the classifier decides, a shrunk stream is never left comparing
    against a wide literal, and a shrunk literal never faces a wide stream."""
    p = ts.prepare_rule(rule_text)
    if not p.shrink_enabled:
        assert p.runtime_text == p.canonical_text
        return
    for sidx in p.shrunk_streams:
        assert f"i{sidx}[t]:bv[384]" not in p.runtime_text


def test_independent_streams_keep_their_own_widths(temp_database):
    """The anti-regression against an over-strict post-condition: one stream may
    shrink while another legitimately stays wide, as long as no COMPARISON mixes
    them. A blanket `"bv[384]" not in runtime_text` check would break this."""
    p = ts.prepare_rule(
        _rule(
            f"(i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]) && "
            f"(i3[t]:bv[384] > {{ #x{HEX96_B} }}:bv[384])"
        )
    )
    w = ts.current_shrink_width()
    assert p.shrink_enabled
    assert p.shrunk_streams == frozenset({12})
    assert f"i12[t]:bv[{w}]" in p.runtime_text
    assert "i3[t]:bv[384]" in p.runtime_text      # untouched, deliberately
    assert p.wide_streams_unshrunk == frozenset({3})


# --- the independent edit audit ----------------------------------------------

def test_audit_rejects_a_rewrite_that_does_not_match_the_plan(temp_database, monkeypatch):
    """Exercise the audit on its own by corrupting edit APPLICATION after a valid
    classification -- not by faking the classifier, whose result is a triple and
    whose malformed return would merely hit the unpacking fallback."""
    real_apply = ts._apply_edits

    def corrupt(text, edits):
        out = real_apply(text, edits)
        return out.replace("i12[t]:bv[8]", "i12[t]:bv[384]", 1)

    monkeypatch.setattr(ts, "_apply_edits", corrupt)
    p = ts.prepare_rule(_guard("->"))
    assert not p.shrink_enabled                  # audit caught it, fell back whole
    assert p.runtime_text == p.canonical_text


def test_audit_rejects_a_changed_time_expression(temp_database, monkeypatch):
    real_apply = ts._apply_edits
    monkeypatch.setattr(
        ts, "_apply_edits",
        lambda text, edits: real_apply(text, edits).replace("[t-1]", "[t]"),
    )
    p = ts.prepare_rule(
        _rule(
            f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] && "
            f"i12[t-1]:bv[384] = {{ #x{HEX96_B} }}:bv[384]"
        )
    )
    assert not p.shrink_enabled
    assert p.runtime_text == p.canonical_text


def test_classify_still_returns_a_triple(temp_database):
    """Guards the shape the audit tests deliberately do not fake."""
    streams, literal_edits, toks = ts._classify(_guard("->"))
    assert streams == {12}
    assert len(literal_edits) == 1
    assert toks and all(hasattr(t, "start") for t in toks)


# --- wide_streams_unshrunk on every return path -------------------------------

def test_wide_streams_reported_on_every_return_path(temp_database, monkeypatch):
    wide = _rule(f"i12[t]:bv[384] > {{ #x{HEX96} }}:bv[384]")
    # nothing-to-shrink path
    assert ts.prepare_rule(wide).wide_streams_unshrunk == frozenset({12})
    # classifier-exception path
    monkeypatch.setattr(ts, "_plan", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert ts.prepare_rule(wide).wide_streams_unshrunk == frozenset({12})


def test_intern_failure_still_reports_wide_streams(temp_database, monkeypatch):
    import db
    monkeypatch.setattr(db, "get_shrink_id", lambda key: (_ for _ in ()).throw(RuntimeError("db down")))
    p = ts.prepare_rule(_guard("->"))
    assert not p.shrink_enabled
    assert p.wide_streams_unshrunk == frozenset({12})
