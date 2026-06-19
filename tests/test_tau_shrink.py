"""Unit tests for the eval-only bitvector shrink layer (tau_shrink.py)."""
import pytest

import db
import tau_shrink as ts

HEX96 = "ab" * 48          # 96 hex chars == 384-bit address
HEX96_B = "cd" * 48
ZERO96 = "0" * 96


def _rule(body: str) -> str:
    return f"always ( {body} )."


# --- interning / canonicalisation --------------------------------------------

def test_intern_bijective_and_starts_at_one(temp_database):
    a = ts.intern_value(HEX96, 384)
    b = ts.intern_value(HEX96_B, 384)
    assert a == 1            # autoincrement begins at 1
    assert b == 2
    assert ts.intern_value(HEX96, 384) == a   # stable


def test_canonicalisation_padding_same_id(temp_database):
    short = ts.intern_value("01", 384)
    padded = ts.intern_value("0" * 94 + "01", 384)
    assert short == padded


def test_zero_is_reserved_id_zero(temp_database):
    assert ts.intern_value(ZERO96, 384) == ts.RESERVED_EMPTY_ID == 0


def test_width_for_count_boundaries():
    assert [ts.width_for_count(n) for n in (0, 254, 255, 65534, 65535)] == [8, 8, 16, 16, 24]


def test_overflow_raises_widthoverflow(temp_database, monkeypatch):
    # An interned id beyond the current process width (default bv[8], usable<=254)
    # raises ShrinkWidthOverflow -> the node must re-exec to widen (not fail-closed).
    monkeypatch.setattr(db, "get_string_id", lambda key: "y9999")
    with pytest.raises(ts.ShrinkWidthOverflow):
        ts.intern_value(HEX96, 384)


# --- classifier: positives ----------------------------------------------------

def test_eq_stream_then_literal(temp_database):
    p = ts.prepare_rule(_rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]"))
    W = ts.current_shrink_width()
    assert p.shrink_enabled and p.shrunk_streams == frozenset({12})
    assert "bv[384]" not in p.runtime_text
    assert f"i12[t]:bv[{W}]" in p.runtime_text  # dynamic smallest width (bv[8] for a tiny table)


def test_eq_literal_then_stream(temp_database):
    p = ts.prepare_rule(_rule(f"{{ #x{HEX96} }}:bv[384] = i12[t]:bv[384]"))
    assert p.shrunk_streams == frozenset({12})


def test_emptiness_hex_and_decimal_zero(temp_database):
    for body in (
        f"i12[t]:bv[384] != {{ #x{ZERO96} }}:bv[384]",
        "i12[t]:bv[384] != { 0 }:bv[384]",
        "i12[t]:bv[384] != 0",
    ):
        p = ts.prepare_rule(_rule(body))
        assert p.shrink_enabled, body
        assert f"{{ 0 }}:bv[{ts.current_shrink_width()}]" in p.runtime_text, body


def test_stream_equals_stream_both_shrunk(temp_database):
    p = ts.prepare_rule(_rule("i3[t]:bv[384] = i4[t]:bv[384]"))
    assert p.shrunk_streams == frozenset({3, 4})


# --- classifier: negatives (fail closed) -------------------------------------

@pytest.mark.parametrize("body", [
    f"i12[t]:bv[384] > {{ #x{HEX96} }}:bv[384]",          # ordering
    f"i12[t]:bv[384] + i1[t]:bv[64] = {{ #x{HEX96} }}:bv[384]",  # arithmetic steal
    f"foo(i12[t]:bv[384]) = {{ #x{HEX96} }}:bv[384]",     # function wrap
    f"not(i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384])",     # negation wrap
])
def test_non_equality_contexts_not_shrunk(temp_database, body):
    p = ts.prepare_rule(_rule(body))
    assert not p.shrink_enabled
    assert p.runtime_text == p.canonical_text
    assert f"#x{HEX96}" in p.runtime_text


def test_stream_disqualified_if_any_arithmetic_use(temp_database):
    body = (
        f"(i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]) && "
        "(i12[t]:bv[384] + i1[t]:bv[64] = i2[t]:bv[64])"
    )
    p = ts.prepare_rule(_rule(body))
    assert not p.shrink_enabled


def test_unannotated_stream_not_shrunk(temp_database):
    # i12 used equality-only but with no/ambiguous bv width -> refuse.
    p = ts.prepare_rule(_rule(f"i12[t] = {{ #x{HEX96} }}:bv[384]"))
    assert 12 not in p.shrunk_streams


def test_bare_zero_in_arithmetic_untouched(temp_database):
    p = ts.prepare_rule(_rule("i1[t]:bv[64] + 0 = i2[t]:bv[64]"))
    assert not p.shrink_enabled
    assert "+ 0" in p.runtime_text


# --- literal/stream consistency ----------------------------------------------

def test_literal_and_stream_value_same_id(temp_database):
    p = ts.prepare_rule(_rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]"))
    # the runtime literal id ...
    import re
    m = re.search(rf"\{{ (\d+) \}}:bv\[{ts.current_shrink_width()}\]", p.runtime_text)
    literal_id = m.group(1)
    # ... must equal the id the stream value interns to (emitted BARE for the
    # native input parser, which rejects the { .. }:bv[N] wrapper on inputs).
    sv = ts.shrink_stream_value(f"{{ #x{HEX96} }}:bv[384]", 12, frozenset({12}))
    assert sv == literal_id


def test_stream_value_shrinks_to_bare_id(temp_database):
    # The native input parser rejects { .. }:bv[N] on inputs -> emit bare id.
    sv = ts.shrink_stream_value(f"{{ #x{HEX96} }}:bv[384]", 12, frozenset({12}))
    assert sv == str(ts.intern_value(HEX96, 384))
    assert "{" not in sv and "bv" not in sv
    # zero -> bare "0"
    assert ts.shrink_stream_value("{ #x" + ZERO96 + " }:bv[384]", 12, frozenset({12})) == "0"


def test_stream_value_idempotent(temp_database):
    assert ts.shrink_stream_value("5", 12, frozenset({12})) == "5"
    assert ts.shrink_stream_value("{ 5 }:bv[64]", 12, frozenset({12})) == "{ 5 }:bv[64]"
    # not in the shrink set -> untouched
    assert ts.shrink_stream_value(f"{{ #x{HEX96} }}:bv[384]", 12, frozenset()) == f"{{ #x{HEX96} }}:bv[384]"


def test_stream_value_shrink_raises_on_db_error(temp_database, monkeypatch):
    monkeypatch.setattr(db, "get_string_id", lambda key: (_ for _ in ()).throw(RuntimeError("db down")))
    with pytest.raises(ts.ShrinkUnavailable):
        ts.shrink_stream_value(f"{{ #x{HEX96} }}:bv[384]", 12, frozenset({12}))


# --- prepare_rule fail-closed / all-or-nothing -------------------------------

def test_prepare_rule_db_error_disables_whole_spec(temp_database, monkeypatch):
    monkeypatch.setattr(db, "get_string_id", lambda key: (_ for _ in ()).throw(RuntimeError("db down")))
    p = ts.prepare_rule(_rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]"))
    assert not p.shrink_enabled
    assert p.runtime_text == p.canonical_text   # no partial mix


def test_exclude_streams_overrides_classifier(temp_database):
    p = ts.prepare_rule(
        _rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]"),
        exclude_streams=frozenset({12}),
    )
    assert 12 not in p.shrunk_streams


def test_type_consistency_no_half_typed_stream(temp_database):
    p = ts.prepare_rule(_rule(f"i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384]"))
    # never a shrunk literal compared against an un-rewritten bv[384] stream
    assert "bv[384]" not in p.runtime_text


# --- output expansion guard ---------------------------------------------------

def test_expand_output_value_identity_on_verdict(temp_database):
    assert ts.expand_output_value("1", 1) == "1"
    assert ts.expand_output_value("0", 6) == "0"


def test_expand_output_guard_warns_on_leaked_id(temp_database, caplog):
    leaked = ts.intern_value(HEX96, 384)          # a real interned address id (>1)
    assert leaked >= 1
    # Make sure it is >1 so the heuristic fires.
    leaked2 = ts.intern_value(HEX96_B, 384)
    with caplog.at_level("ERROR"):
        ts.expand_output_value(str(leaked2), output_index=9)
    assert any("looks like a shrunk address" in r.message for r in caplog.records)
