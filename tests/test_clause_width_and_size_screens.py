"""Clause bodies carry an explicit width on every stream mention and stay within
the comparison and nesting limits, at admission and at apply, on every door."""
import pytest

from consensus.admission import _screen_clause_domains
from consensus.approvals import screen_stream_widths
from consensus.rule_offers import (
    MAX_CLAUSE_COMPARISONS,
    MAX_CLAUSE_DEPTH,
    clause_comparison_count,
    clause_paren_depth,
    screen_clause_structure,
)

from test_clause_domain_apply_screen import (  # noqa: F401  (fixture and harness)
    _ON,
    _OFF,
    ALICE,
    _accept_tx,
    _admit,
    _apply,
    _lifecycle,
    _offer,
    _offer_tx,
    _outcome,
    _rule_tx,
    tip_view,
)

NOT_APPLIED = "rule_not_applied"


def _clause(condition_terms, extra_depth=0):
    """A well-formed o5 clause whose condition holds `condition_terms` comparisons."""
    condition = " || ".join(condition_terms)
    for _ in range(extra_depth):
        condition = f"({condition})"
    return f"always ( ({condition}) ? {_ON} : {_OFF} )."


def _terms(count):
    return [f"i1[t]:bv[24] = {{ #x{k:06x} }}:bv[24]" for k in range(count)]


def _body_of(rule):
    return rule[len("always ( "):-len(" ).")]


def _with_comparisons(total):
    # The two o5 assignments are comparisons as well.
    return _clause(_terms(total - 2))


def _with_depth(total):
    # `_clause` is nested one level deep before any extra wrapping.
    return _clause(_terms(2), extra_depth=total - 1)


AT_COUNT = _with_comparisons(MAX_CLAUSE_COMPARISONS)
OVER_COUNT = _with_comparisons(MAX_CLAUSE_COMPARISONS + 1)
AT_DEPTH = _with_depth(MAX_CLAUSE_DEPTH)
OVER_DEPTH = _with_depth(MAX_CLAUSE_DEPTH + 1)

UNTYPED = _clause(["i1[t] > { #x000064 }:bv[24]"])
UNTYPED_NO_STEP = _clause(["i1 > { #x000064 }:bv[24]"])
TWO_WIDTHS = _clause([
    "i1[t]:bv[24] > { #x000064 }:bv[24]",
    "i1[t]:bv[16] > { #x0064 }:bv[16]",
])
TYPED_ELSEWHERE = _clause([
    "i1[t]:bv[8] > { #x64 }:bv[8]",
    "i5[t]:bv[40] > { #x0000000064 }:bv[40]",
])

BAD = {
    "untyped": (UNTYPED, "i1[t]:bv["),
    "two_widths": (TWO_WIDTHS, "several widths"),
    "over_count": (OVER_COUNT, "comparisons"),
    "over_depth": (OVER_DEPTH, "nests parentheses"),
}
GOOD = {"at_count": AT_COUNT, "at_depth": AT_DEPTH, "other_widths": TYPED_ELSEWHERE}


def test_the_generated_bodies_sit_exactly_on_the_limits():
    assert clause_comparison_count(_body_of(AT_COUNT)) == MAX_CLAUSE_COMPARISONS
    assert clause_comparison_count(_body_of(OVER_COUNT)) == MAX_CLAUSE_COMPARISONS + 1
    assert clause_paren_depth(_body_of(AT_DEPTH)) == MAX_CLAUSE_DEPTH
    assert clause_paren_depth(_body_of(OVER_DEPTH)) == MAX_CLAUSE_DEPTH + 1


# --- the screens themselves ---------------------------------------------------

@pytest.mark.parametrize("body, ok", [
    ("o5[t]:bv[24] = i1[t]:bv[24]", True),
    ("o5[t]:bv[24] = i1[ t ] : bv[ 24 ]", True),
    ("o5[t]:bv[24] = i1[t]", False),
    ("o5[t] = i1[t]:bv[24]", False),
    ("o5[t]:bv[24] = i1", False),
    ("o5[t]:bv[24] = i1[t]:bv[24] && i1[t]:bv[8] = i1[t]:bv[24]", False),
    ("o5[t]:bv[24] = i1[t]:bv[24] && i7[t]:bv[8] = i7[t]:bv[8]", True),
    ("# i1 in a comment\no5[t]:bv[24] = i1[t]:bv[24]", True),
    ("o5[t]:bv[24] = { #xa1b2c3 }:bv[24]", True),
])
def test_every_mention_needs_one_explicit_width(body, ok):
    assert (screen_stream_widths(body) is None) is ok


def test_the_error_names_the_stream_and_the_spelling():
    error = screen_stream_widths("o5[t]:bv[24] = i3[t]")
    assert "i3" in error and "i3[t]:bv[<width>]" in error
    conflict = screen_stream_widths(
        "o5[t]:bv[24] = i3[t]:bv[8] && i3[t]:bv[16] = i3[t]:bv[8]")
    assert "i3" in conflict and "bv[8]" in conflict and "bv[16]" in conflict


@pytest.mark.parametrize("body, count", [
    ("a = b", 1),
    ("a != b", 1),
    ("a <= b && a >= b", 2),
    ("a < b || a > b", 2),
    ("a -> b", 0),
    ("a <-> b", 0),
    ("(a = b) ? (c = d) : (e = f)", 3),
    ("# a = b\nc = d", 1),
])
def test_each_comparison_operator_counts_once(body, count):
    assert clause_comparison_count(body) == count


def test_nesting_depth_ignores_comments_and_brackets():
    assert clause_paren_depth("((a)) (b) # ((((x))))") == 2
    assert clause_paren_depth("i1[t]:bv[24]") == 0


def test_the_limits_are_inclusive():
    assert screen_clause_structure(_body_of(AT_COUNT)) is None
    assert screen_clause_structure(_body_of(AT_DEPTH)) is None
    assert "comparisons" in screen_clause_structure(_body_of(OVER_COUNT))
    assert "nests" in screen_clause_structure(_body_of(OVER_DEPTH))


@pytest.mark.parametrize("name", GOOD)
def test_the_domain_screen_accepts_a_body_within_the_limits(name):
    assert _screen_clause_domains(_body_of(GOOD[name])) is None


@pytest.mark.parametrize("name", BAD)
def test_the_domain_screen_refuses(name):
    rule, phrase = BAD[name]
    error = _screen_clause_domains(_body_of(rule))
    assert error is not None and phrase in error


# --- admission, every door ----------------------------------------------------

@pytest.mark.parametrize("door", ["routed", "offer", "accept"])
@pytest.mark.parametrize("name", BAD)
def test_admission_refuses(tip_view, door, name):
    rule, phrase = BAD[name]
    result = _admit(door, rule, tip_view)
    assert result.is_valid is False
    assert phrase in result.error


@pytest.mark.parametrize("door", ["routed", "offer", "accept"])
@pytest.mark.parametrize("name", GOOD)
def test_admission_accepts(tip_view, door, name):
    result = _admit(door, GOOD[name], tip_view)
    assert result.is_valid is True, (result.code, result.error)


# --- apply, both registration doors ------------------------------------------

@pytest.mark.parametrize("name", BAD)
def test_apply_hard_rejects_a_routed_clause(name):
    rule, _ = BAD[name]
    result, post, _fed = _apply(_rule_tx(rule), _lifecycle(slots=True))
    assert "rule" in result.invalid_tx_ids
    assert _outcome(result, "rule").reason == NOT_APPLIED
    assert post.rule_offers.clause_for(ALICE, 5) is None


@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize("name", BAD)
def test_apply_hard_rejects_an_offer(name, slots):
    rule, _ = BAD[name]
    result, post, _fed = _apply(_offer_tx(rule), _lifecycle(slots=slots))
    assert "offer" in result.invalid_tx_ids
    assert _outcome(result, "offer").reason == NOT_APPLIED
    assert post.rule_offers.get_offer(_offer(rule).offer_id) is None


@pytest.mark.parametrize("slots", [False, True])
@pytest.mark.parametrize("name", BAD)
def test_apply_hard_rejects_an_accept(name, slots):
    rule, _ = BAD[name]
    result, post, _fed = _apply(_accept_tx(rule), _lifecycle(slots=slots, open_offer=rule))
    assert "accept" in result.invalid_tx_ids
    assert _outcome(result, "accept").reason == NOT_APPLIED
    assert post.rule_offers.clause_for(ALICE, 5) is None


@pytest.mark.parametrize("name", GOOD)
def test_apply_registers_a_routed_clause_within_the_limits(name):
    result, post, _fed = _apply(_rule_tx(GOOD[name]), _lifecycle(slots=True))
    assert result.accepted_tx_ids == ["rule"]
    assert post.rule_offers.clause_for(ALICE, 5) is not None


@pytest.mark.parametrize("name", GOOD)
def test_apply_accepts_an_offer_and_its_accept_within_the_limits(name):
    result, _post, _fed = _apply(_offer_tx(GOOD[name]), _lifecycle(slots=True))
    assert result.accepted_tx_ids == ["offer"]
    result, post, _fed = _apply(
        _accept_tx(GOOD[name]), _lifecycle(slots=True, open_offer=GOOD[name]))
    assert result.accepted_tx_ids == ["accept"]
    assert post.rule_offers.clause_for(ALICE, 5) is not None
