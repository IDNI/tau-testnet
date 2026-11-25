"""Rules may not name the engine's update stream, its spec input, or unknown streams.

Textual only, so it runs without the engine.
"""
import os
import sys
import time

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from consensus.admission import (
    _screen_clause_domains,
    _screen_guard_domains,
    is_rule_fragment_error,
    screen_rule_fragment,
    screen_user_rule_text,
)
from tau_native import TauInterface

SENDER = "ab" * 48
ZERO = "{ #x000000 }:bv[24]"

REFUSED = [
    pytest.param("u[t] = 0", "u", id="u-write"),
    pytest.param("u[t] = i0[t]'", "u", id="u-from-i0"),
    pytest.param("o20[t]:bv[24] = this[t]:bv[24]", "this", id="this-read"),
    pytest.param("o20[t] = u [ t ]", "u", id="u-spaced"),
    pytest.param("u = 0", "u", id="u-unindexed"),
    pytest.param("foo[t] = 0", "foo", id="unknown-name"),
    pytest.param("U[t] = 0", "U", id="uppercase-u"),
    pytest.param("o20[t]:bv[24] = I1[t]:bv[24]", "I1", id="uppercase-input"),
    pytest.param("o20[t]:bv[24] = i1[t]:bv[24] && x[t] = 0", "x", id="unknown-after-valid"),
]

ACCEPTED = [
    pytest.param(
        f"always ( (i12[t]:bv[384] = {{ #x{SENDER} }}:bv[384]) -> "
        f"(o8[t]:bv[24] = {ZERO}) ).",
        id="scoped-o8-fee",
    ),
    pytest.param("always ( o20[t]:bv[24] = i1[t]:bv[24] ).", id="custom-output-o20"),
    pytest.param("always ( o20[t]:bv[24] = 0 ). # u[t] = 1 and this[t]", id="u-in-comment"),
    pytest.param("# u[t] = 0\nalways ( o20[t]:bv[24] = i1[t]:bv[24] ).", id="comment-line"),
    pytest.param("always ( o20[t]:bv[8] = { #x0a }:bv[8] ).", id="hex-literal"),
]


def _unit(body):
    return f"always ( {body} )."


@pytest.mark.parametrize("body,name", REFUSED)
def test_fragment_screen_names_the_offending_stream(body, name):
    error = screen_rule_fragment(_unit(body))
    assert error is not None
    assert f"'{name}'" in error
    assert is_rule_fragment_error(error)


@pytest.mark.parametrize("text", [pytest.param(p.values[0], id=p.id) for p in ACCEPTED])
def test_fragment_screen_accepts_ordinary_rules(text):
    assert screen_rule_fragment(TauInterface.preprocess_spec_text(text)) is None


@pytest.mark.parametrize("body,name", REFUSED)
def test_user_rule_screen_refuses_with_fragment_reason(body, name):
    rejection = screen_user_rule_text(_unit(body), "", False)
    assert rejection is not None
    assert rejection.reason == "rule_fragment"
    assert rejection.code == "RULE_FRAGMENT"
    assert f"'{name}'" in rejection.error


@pytest.mark.parametrize("text", [pytest.param(p.values[0], id=p.id) for p in ACCEPTED])
def test_user_rule_screen_accepts_ordinary_rules(text):
    rejection = screen_user_rule_text(text, "", False)
    assert rejection is None or rejection.reason not in ("rule_fragment", "temporal_reference")


@pytest.mark.parametrize("body,name", REFUSED)
def test_clause_screen_refuses_special_streams(body, name):
    error = _screen_clause_domains(body)
    assert error is not None and f"'{name}'" in error


@pytest.mark.parametrize("body,name", REFUSED)
def test_guard_screen_refuses_special_streams(body, name):
    error = _screen_guard_domains(body)
    assert error is not None and f"'{name}'" in error


def test_clause_and_guard_bodies_may_not_carry_comments():
    clause = "(o5[t]:bv[24] = i1[t]:bv[24]) # u[t] = 0"
    assert is_rule_fragment_error(_screen_clause_domains(clause))
    guard = "(o5[t]:bv[24] = i1[t]:bv[24]) # this[t]"
    assert is_rule_fragment_error(_screen_guard_domains(guard))


def test_a_wire_cap_sized_rule_is_screened_in_linear_time():
    term = "o20[t]:bv[24] = i1[t]:bv[24] && "
    text = "always ( " + term * (250 * 1024 // len(term)) + "o21[t]:bv[24] = i1[t]:bv[24] )."
    assert len(text) > 250 * 1024
    started = time.perf_counter()
    screen_rule_fragment(text)
    assert time.perf_counter() - started < 1.0
