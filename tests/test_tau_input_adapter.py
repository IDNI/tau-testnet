"""W4: one canonical -> runtime input boundary.

Two defects this pins, both of which produce wrong verdicts with no mixed widths
and no engine error at all:

* a bare decimal was assumed to be an internal id, so an externally supplied
  canonical "1" compared equal to whichever address held interned id 1;
* `int(k)` meant a string key `"i12"` was not recognised as stream 12 and skipped
  value encoding entirely, while the native adapter accepted it.
"""
import pytest
from unittest.mock import MagicMock

import tau_manager
import tau_shrink as ts

HEX96 = "aa" * 48
HEX96_B = "bb" * 48


# --- key grammar --------------------------------------------------------------

@pytest.mark.parametrize("key,expected", [
    (12, 12), ("12", 12), ("i12", 12), (" i12 ", 12), ("I12", 12),
    (0, 0), ("i0", 0), ("0", 0),
    ("012", None),        # leading zeros are ambiguous, not normalised
    ("i012", None),
    ("x12", None), ("", None), ("i", None), (None, None), (True, None), (-1, None),
])
def test_stream_key_grammar(key, expected):
    assert tau_manager.normalize_stream_key(key) == expected


def test_duplicate_aliases_are_rejected_before_any_merge():
    with pytest.raises(tau_manager.AmbiguousStreamKey):
        tau_manager._resolve_stream_keys({12: "a", "i12": "b"})


def test_distinct_streams_are_not_confused():
    resolved = tau_manager._resolve_stream_keys({12: "a", "i3": "b", "bogus": "c"})
    assert resolved[12] == 12 and resolved["i3"] == 3 and resolved["bogus"] is None


# --- encoding -----------------------------------------------------------------

def test_named_and_numeric_keys_encode_identically(temp_database):
    shrunk = frozenset({12})
    wrapped = f"{{ #x{HEX96} }}:bv[384]"
    by_int = tau_manager._normalize_inputs({12: wrapped}, shrunk)
    by_name = tau_manager._normalize_inputs({"i12": wrapped}, shrunk)
    assert by_int[12] == by_name["i12"] == str(ts.intern_value(HEX96, 384))


def test_untrusted_decimal_is_interned_by_value(temp_database):
    """The collision: "1" must not be read as internal id 1."""
    shrunk = frozenset({12})
    first = ts.intern_value(HEX96, 384)           # some address takes id 1
    out = tau_manager._normalize_inputs({12: "1"}, shrunk)[12]
    assert out != str(first)


def test_non_shrunk_streams_pass_through_canonically(temp_database):
    out = tau_manager._normalize_inputs({1: "100"}, frozenset({12}))
    assert out[1] == "100"


def test_rule_dispatch_comes_from_the_key_not_the_value(temp_database):
    """A value starting with "always" on a NON-rule stream must be treated as a
    value. Dispatch is the typed input contract, not the first word."""
    out = tau_manager._normalize_inputs({7: "always ( o5[t]:bv[24] = { #x1 }:bv[24] )."},
                                        frozenset())
    assert out[7].startswith("always"), out
    assert "runtime" not in out[7]


def test_ambiguous_keys_fail_the_whole_request(temp_database):
    with pytest.raises(tau_manager.AmbiguousStreamKey):
        tau_manager._normalize_inputs({12: "1", "i12": "2"}, frozenset({12}))


# --- W5: prepare once ---------------------------------------------------------

def test_an_i0_rule_is_prepared_exactly_once(temp_database, monkeypatch):
    """The dispatched bytes must be the validated bytes.

    `_normalize_inputs` used to re-prepare the same i0 text that
    `_collect_i0_prepared` had already prepared. A probe made the first
    preparation narrow and the second fall back, so the wrapper dispatched wide
    text while committing narrow bookkeeping.
    """
    calls = []
    real = tau_manager._prepare_rule_for_tau

    def counting(text):
        calls.append(text)
        return real(text)

    monkeypatch.setattr(tau_manager, "_prepare_rule_for_tau", counting)
    rule = f"always ( i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] -> ( o5[t]:bv[24] = {{ #x000001 }}:bv[24] ) )."
    values = {0: rule}
    preps, by_slot = tau_manager._collect_i0_prepared(values)
    out = tau_manager._normalize_inputs(values, frozenset({12}), i0_prepared=by_slot)
    assert len(calls) == 1, calls
    assert out[0] == preps[0].runtime_text


def test_dispatched_text_matches_the_committed_preparation(temp_database, monkeypatch):
    """Force the second preparation to differ; the cache must win."""
    real = tau_manager._prepare_rule_for_tau
    state = {"n": 0}

    def flaky(text):
        state["n"] += 1
        prep = real(text)
        if state["n"] > 1:      # a later re-preparation falls back to full width
            import tau_shrink
            return tau_shrink.PreparedTauSpec(prep.canonical_text, prep.canonical_text,
                                              False, frozenset(), frozenset({12}))
        return prep

    monkeypatch.setattr(tau_manager, "_prepare_rule_for_tau", flaky)
    rule = f"always ( i12[t]:bv[384] = {{ #x{HEX96} }}:bv[384] -> ( o5[t]:bv[24] = {{ #x000001 }}:bv[24] ) )."
    values = {0: rule}
    preps, by_slot = tau_manager._collect_i0_prepared(values)
    out = tau_manager._normalize_inputs(values, frozenset({12}), i0_prepared=by_slot)
    assert out[0] == preps[0].runtime_text
    assert "bv[384]" not in out[0]


# --- W3: the pinned-stream safety rule ----------------------------------------

@pytest.fixture(autouse=True)
def _clean_evaluator_state():
    """`_evaluator_state` is module-level and carries PROCESS commitments, which
    deliberately have no clear(); tests get a fresh process's worth instead."""
    tau_manager.reset_evaluator_state()
    yield
    tau_manager.reset_evaluator_state()


def test_a_wide_rule_against_a_pinned_stream_is_refused_not_dispatched(temp_database, monkeypatch):
    """Falling back to full width is correct at process start and fatal after the
    stream is typed: the engine commits a width on the first ACCEPTED revision and
    never re-types it (measured in W0), so neither form can be dispatched."""
    import config
    import tau_shrink
    monkeypatch.setattr(config, "TAU_SHRINK_ENABLED", True, raising=False)
    monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset({12}))
    # an ordering use of i12: canonically valid, outside the optimizer's fragment
    wide = f"always ( i12[t]:bv[384] > {{ #x{HEX96} }}:bv[384] )."
    with pytest.raises(tau_shrink.ShrinkTypeConflict) as exc:
        tau_manager._prepare_rule_for_tau(wide)
    assert "i12" in str(exc.value)


def test_no_conflict_when_the_stream_was_never_pinned(temp_database, monkeypatch):
    import config
    monkeypatch.setattr(config, "TAU_SHRINK_ENABLED", True, raising=False)
    monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset())
    wide = f"always ( i12[t]:bv[384] > {{ #x{HEX96} }}:bv[384] )."
    prep = tau_manager._prepare_rule_for_tau(wide)
    assert prep is not None and not prep.shrink_enabled


def test_conflict_is_not_swallowed_as_shrink_unavailable(temp_database):
    import tau_shrink
    assert not issubclass(tau_shrink.ShrinkTypeConflict, tau_shrink.ShrinkUnavailable)
    assert not issubclass(tau_shrink.ShrinkTypeConflict, tau_shrink.ShrinkWidthOverflow)


def test_a_whole_rule_fallback_is_checked_against_commitments(temp_database, monkeypatch):
    """A whole-rule fallback widens EVERY stream it touches, not just the one that
    caused it. Here interning fails, so a rule that would have shrunk i3 falls
    back to full width -- and i3 is already committed narrow, so the fallback is
    exactly what this process cannot type. Checking only the offending stream, or
    not checking the fallback at all, would dispatch it."""
    import config
    import db as db_mod
    import tau_shrink
    monkeypatch.setattr(config, "TAU_SHRINK_ENABLED", True, raising=False)
    monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset({3}))
    monkeypatch.setattr(db_mod, "get_shrink_id",
                        lambda key: (_ for _ in ()).throw(RuntimeError("db down")))
    rule = f"always ( i3[t]:bv[384] = {{ #x{HEX96_B} }}:bv[384] )."
    with pytest.raises(tau_shrink.ShrinkTypeConflict) as exc:
        tau_manager._prepare_rule_for_tau(rule)
    assert "i3" in str(exc.value)


def test_a_restore_is_checked_against_commitments(temp_database, monkeypatch):
    """`restore_full_tau_spec` builds its own preparation and rebuilds the
    interpreter -- but the engine's type commitments are process-global and
    survive that rebuild, so the restore needs the same gate."""
    import config
    import tau_shrink
    monkeypatch.setattr(config, "TAU_SHRINK_ENABLED", True, raising=False)
    monkeypatch.setattr(tau_manager, "tau_test_mode", False)
    iface = MagicMock()
    iface.preprocess_spec_text.side_effect = lambda text: text
    monkeypatch.setattr(tau_manager, "tau_direct_interface", iface)
    monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset({12}))
    wide = f"always ( i12[t]:bv[384] > {{ #x{HEX96} }}:bv[384] )."
    with pytest.raises(tau_shrink.ShrinkTypeConflict):
        tau_manager.restore_full_tau_spec(wide)
