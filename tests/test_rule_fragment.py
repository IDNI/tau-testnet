"""The rule allow-list: one `always ( wff )` unit over typed bitvector comparisons.

Pure text screening, so it runs without the engine.
"""
import importlib.util
import os
import sys
import time

import pytest

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import tau_policy
from consensus.rule_fragment import (
    FRAGMENT_CODE,
    RuleFragmentError,
    RuleShape,
    StreamRef,
    clause_unit,
    parse_rule_unit,
)
from tau_native import TauInterface

PUBKEY = "ab" * 48
A = "i1[t]:bv[24]"
B = "i2[t]:bv[24]"
OUT = "o12[t]:bv[24]"
ONE = "{ #x000001 }:bv[24]"
CMP = f"{OUT} = {ONE}"


def unit(body: str) -> str:
    return f"always ( {body} )."


def refused(text: str) -> RuleFragmentError:
    with pytest.raises(RuleFragmentError) as caught:
        parse_rule_unit(text)
    return caught.value


def test_fragment_code_name():
    assert FRAGMENT_CODE == "RULE_FRAGMENT"


def test_clause_unit_matches_policy_clause_spec():
    for body in ("o5[t]:bv[24] = 1", "", "(a)  (b)"):
        assert clause_unit(body) == tau_policy.clause_spec(body)


# ---------------------------------------------------------------- accepted

ACCEPTED = [
    pytest.param(unit(f"{OUT} = {{ #xF0 }}:bv[24]"), id="hex-upper"),
    pytest.param(unit(f"{OUT} = {{ #xFACE }}:bv[24]"), id="hex-face"),
    pytest.param(unit(f"{OUT} = {{ #xAE }}:bv[24]"), id="hex-ae"),
    pytest.param(unit(f"{OUT} = {{ #xb1 }}:bv[24]"), id="hex-b1"),
    pytest.param(unit(f"{OUT} = {{ #b1010 }}:bv[24]"), id="binary"),
    pytest.param(unit(f"{OUT} = {{ 10 }}:bv[24]"), id="decimal"),
    pytest.param(unit(f"{OUT} = {{0}}:bv[24]"), id="decimal-zero"),
    pytest.param(unit(f"{OUT} = 1"), id="bare-one"),
    pytest.param(unit(f"{OUT} = 0:bv[24]"), id="bare-zero-typed"),
    pytest.param(unit("o10[t]:bv[8] = i15[t]:bv[8]"), id="o10-i15"),
    pytest.param(unit("o12[t]:bv[24] = i125[t]:bv[24]"), id="i125"),
    pytest.param(unit(f"{OUT} = {A} + {B} + {A}"), id="same-op-chain"),
    pytest.param(unit(f"{OUT} = {A} + ({B} * {{3}}:bv[24])"), id="parenthesized-mix"),
    pytest.param(unit(f"{OUT} = {A} - {B}"), id="sub"),
    pytest.param(unit(f"{OUT} = {A} * {{3}}:bv[24]"), id="mul-literal"),
    pytest.param(unit(f"{OUT} = {{3}}:bv[24] * {A}"), id="mul-literal-left"),
    pytest.param(unit(f"{OUT} = {A} / 1"), id="div-one"),
    pytest.param(unit(f"{OUT} = {A} % ({{7}}:bv[24])"), id="mod-parenthesized-literal"),
    pytest.param(unit(f"{OUT} = {A} & {B} & {A}"), id="and-chain"),
    pytest.param(unit(f"{OUT} = {A} | {B}"), id="or"),
    pytest.param(unit(f"{OUT} = {A} ^ {B}"), id="xor"),
    pytest.param(unit(f"{OUT} = {A} !| {B}"), id="nor"),
    pytest.param(unit(f"{OUT} = {A} !^ {B}"), id="xnor"),
    pytest.param(unit(f"{OUT} = {A} !& {B}"), id="nand"),
    pytest.param(unit(f"{OUT} = {A} << {{2}}:bv[24]"), id="shl"),
    pytest.param(unit(f"{OUT} = {A} >> {{2}}:bv[24]"), id="shr"),
    pytest.param(unit(f"{OUT} = ({A})'"), id="postfix-complement"),
    pytest.param(unit(f"{OUT} = {A}'"), id="postfix-on-ref"),
    pytest.param(unit(f"{A} = {B} ? {CMP} : {OUT} = 0"), id="ternary"),
    pytest.param(unit(f"({A} = {B}) <-> ({CMP})"), id="equivalence"),
    pytest.param(unit(f"({A} = {B}) ^^ ({CMP})"), id="xor-wff"),
    pytest.param(unit(f"({A} = {B}) -> ({CMP})"), id="implication"),
    pytest.param(unit(f"({A} = {B}) <- ({CMP})"), id="reverse-implication"),
    pytest.param(unit(f"({A} = {B}) || ({CMP})"), id="or-wff"),
    pytest.param(unit(f"{A} = {B} && {CMP} || {A} != {B}"), id="precedence-mix"),
    pytest.param(unit(f"!({A} = {B})"), id="negation"),
    pytest.param(unit(f"!!({A} = {B})"), id="double-negation"),
    pytest.param(unit(f"! {A} !<= {B}"), id="negated-comparison"),
    pytest.param(unit(f"(({A} = {B}))"), id="double-parenthesized-wff"),
    pytest.param(unit(f"({A} + {B}) = {A}"), id="parenthesized-bf-start"),
    pytest.param(unit(f"{A} < {B}"), id="lt"),
    pytest.param(unit(f"{A} <= {B}"), id="lteq"),
    pytest.param(unit(f"{A} > {B}"), id="gt"),
    pytest.param(unit(f"{A} >= {B}"), id="gteq"),
    pytest.param(unit(f"{A} !< {B}"), id="nlt"),
    pytest.param(unit(f"{A} !<= {B}"), id="nlteq"),
    pytest.param(unit(f"{A} !> {B}"), id="ngt"),
    pytest.param(unit(f"{A} !>= {B}"), id="ngteq"),
    pytest.param(unit(f"{A} != {B}"), id="neq"),
    pytest.param(f"always({CMP})", id="tight-always"),
    pytest.param(f"always\t(\n{CMP}\n)\n.\n", id="whitespace-everywhere"),
    pytest.param(f"always ( {OUT.replace(':', ' : ').replace('bv[24]', 'bv [ 24 ]')} = {ONE} )", id="spaced-annotation"),
    pytest.param(
        "always ( o6[t]:bv[16] = i10[t]:bv[16] && o7[t]:bv[16] = { 1 }:bv[16] "
        "&& o9[t]:bv[24] = { #x00000a }:bv[24] ).",
        id="genesis-consensus-rule",
    ),
]


@pytest.mark.parametrize("text", ACCEPTED)
def test_accepted(text):
    shape = parse_rule_unit(text)
    assert isinstance(shape, RuleShape)
    assert shape.unit_bytes == len(text.encode())


def test_genesis_consensus_file_is_admitted():
    with open(os.path.join(project_root, "genesis_consensus.tau"), encoding="utf-8") as f:
        text = f.read()
    shape = parse_rule_unit(TauInterface.preprocess_spec_text(text))
    assert {(r.io, r.index) for r in shape.refs} >= {("o", 6), ("o", 7), ("i", 10)}


def test_shape_of_guarded_rule():
    text = (
        f"always ((i12[t]:bv[384] = {{#x{PUBKEY}}}:bv[384]) -> "
        f"o12[t]:bv[24] = {{#x000101}}:bv[24])."
    )
    shape = parse_rule_unit(text)
    assert (shape.nodes, shape.depth, shape.comparisons) == (7, 3, 2)
    assert shape.refs == (StreamRef("i", 12, 384), StreamRef("o", 12, 24))
    assert shape.unit_bytes == len(text.encode())


def test_shape_max_width_covers_refs_and_annotated_literals():
    guarded = parse_rule_unit(
        f"always ((i12[t]:bv[384] = {{#x{PUBKEY}}}:bv[384]) -> "
        f"o12[t]:bv[24] = {{#x000101}}:bv[24])."
    )
    assert guarded.max_width == 384
    assert parse_rule_unit(unit(f"{A} = {B}")).max_width == 24
    assert parse_rule_unit(unit(f"{A} = {{ #x0f }}:bv[48]")).max_width == 48
    assert parse_rule_unit(unit(f"{A} = 0:bv[40]")).max_width == 40


def test_shape_max_width_ignores_unannotated_numerals():
    assert parse_rule_unit(unit(f"{A} = 1")).max_width == 24
    assert parse_rule_unit(unit(f"{A}' = 0")).max_width == 24


def test_shape_counts_every_operator_and_leaf():
    shape = parse_rule_unit(unit(f"({A} + {B}) = {A}"))
    assert (shape.nodes, shape.depth, shape.comparisons) == (5, 3, 1)
    shape = parse_rule_unit(unit(f"!({A} = {B})"))
    assert (shape.nodes, shape.depth, shape.comparisons) == (4, 3, 1)
    shape = parse_rule_unit(unit(f"{A} = {B} ? {A} = {B} : {A} != {B}"))
    assert (shape.nodes, shape.depth, shape.comparisons) == (10, 3, 3)
    shape = parse_rule_unit(unit(f"{A}' = 0"))
    assert (shape.nodes, shape.depth, shape.comparisons) == (4, 3, 1)


def test_shape_refs_are_distinct_streams_with_widths():
    shape = parse_rule_unit(unit(f"{A} = {A} && {OUT} = {A}"))
    assert shape.refs == (StreamRef("i", 1, 24), StreamRef("o", 12, 24))


# ----------------------------------------------------------------- refused

TEMPORAL_WORDS = [
    "always", "sometimes", "once", "historically", "until", "release",
    "weak_until", "since", "trigger", "U", "R", "W", "S", "T", "F", "G", "O",
    "H", "A", "E",
]


@pytest.mark.parametrize("word", TEMPORAL_WORDS)
@pytest.mark.parametrize(
    "shape",
    [
        "{w}({c})",
        "{w} ({c})",
        "{w}\t({c})",
        "{w}\n({c})",
        "{w} {w} ({c})",
        "(({w}({c})))",
        "{c} ? {w}({c}) : {c}",
        "{c} ? {c} : {w}({c})",
        "{w}({c}) ? {c} : {c}",
        "({c}) && {w} ({c})",
        "({c}) -> ({w} ({c}))",
    ],
)
def test_operator_words_refused_in_any_position(word, shape):
    body = shape.format(w=word, c=CMP)
    assert isinstance(refused(unit(body)), RuleFragmentError)


@pytest.mark.parametrize("word", ["sometimes", "once", "historically", "F", "G"])
def test_operator_words_refused_instead_of_always(word):
    refused(f"{word} ( {CMP} ).")


@pytest.mark.parametrize("op", ["U", "R", "W", "S", "T", "until", "release", "weak_until", "since", "trigger"])
@pytest.mark.parametrize("spacing", [" {op} ", "\t{op}\t", "\n{op}\n"])
def test_binary_temporal_words_refused(op, spacing):
    refused(unit(f"({CMP}){spacing.format(op=op)}({CMP})"))


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(unit(f"<>({CMP})"), id="diamond"),
        pytest.param(unit(f"<> ({CMP})"), id="diamond-spaced"),
        pytest.param(unit(f"[]({CMP})"), id="box"),
        pytest.param(unit(f"[] ({CMP})"), id="box-spaced"),
        pytest.param(unit(f"-({CMP})"), id="semantic-negation"),
        pytest.param(unit(f"- ({CMP})"), id="semantic-negation-spaced"),
        pytest.param(unit(f"[t > 3] && {CMP}"), id="time-constraint"),
        pytest.param(unit(f"[t >= 3] -> ({CMP})"), id="time-constraint-implication"),
        pytest.param(unit(f"({CMP}) && [t < 2]"), id="trailing-constraint"),
        pytest.param(unit(f"ex x ({CMP})"), id="exists"),
        pytest.param(unit(f"all x ({CMP})"), id="forall"),
        pytest.param(unit(f"fex x ({A} = x)"), id="bf-exists"),
        pytest.param(unit(f"fall x ({A} = x)"), id="bf-forall"),
        pytest.param(unit(f"ex x:bv[24] ({CMP})"), id="typed-exists"),
        pytest.param(f"f(x) := {A} = x. always ( {CMP} ).", id="definition"),
        pytest.param(f"always ( {CMP} ). f(x) := x = 1.", id="trailing-definition"),
        pytest.param(f"o12[t]:bv[24] := out. always ( {CMP} ).", id="stream-def"),
        pytest.param(unit(f"{OUT} = $x"), id="capture"),
        pytest.param(unit(f"{OUT} = <a:b>"), id="uconst"),
        pytest.param(unit(f"f(o12[t]:bv[8]) = {A}"), id="function-ref"),
        pytest.param(unit(f"f(o12[t]:bv[8])"), id="predicate-ref"),
        pytest.param(unit(f"min({A}, {B}) = {A}"), id="min"),
        pytest.param(unit(f"max({A}, {B}) = {A}"), id="max"),
        pytest.param(unit(f"{A} = {B} <= {A} <= {B}"), id="interval"),
        pytest.param(unit(f"({A}):bv[24] = {B}"), id="cast-like-annotation"),
        pytest.param(unit(f"(bv[24]) {A} = {B}"), id="cast"),
        pytest.param(unit("T"), id="true-constant"),
        pytest.param(unit("F"), id="false-constant"),
        pytest.param(unit(f"{OUT} = T"), id="bf-true"),
        pytest.param(unit(f"{OUT} = F"), id="bf-false"),
    ],
)
def test_other_engine_constructs_refused(text):
    refused(text)


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(CMP, id="no-always"),
        pytest.param(f"({CMP})", id="parenthesized-no-always"),
        pytest.param(f"(always ( {CMP} ))", id="wrapped-always"),
        pytest.param(f"always ( {CMP} ) && ( {CMP} )", id="outside-conjunct"),
        pytest.param(f"always ( {CMP} ) && always ( {CMP} )", id="two-units-conjoined"),
        pytest.param(f"always ( {CMP} ). always ( {CMP} ).", id="two-units"),
        pytest.param(f"always ( {CMP} ) ( {CMP} )", id="trailing-group"),
        pytest.param(f"always ( {CMP} ).. ", id="double-period"),
        pytest.param(f"always ( {CMP} ) . x", id="text-after-period"),
        pytest.param(f"x always ( {CMP} )", id="text-before"),
        pytest.param("", id="empty"),
        pytest.param("   ", id="blank"),
        pytest.param("always", id="bare-always"),
        pytest.param("always ( )", id="empty-body"),
        pytest.param(f"always ( {CMP} ", id="unclosed"),
        pytest.param(f"always {CMP}", id="no-parentheses"),
        pytest.param(f"Always ( {CMP} )", id="capitalised-always"),
        pytest.param(f"always [ {CMP} ]", id="bracketed-always"),
    ],
)
def test_unit_shape_refused(text):
    refused(text)


@pytest.mark.parametrize(
    "text,name",
    [
        pytest.param(unit("u[t] = 0"), "u", id="u-write"),
        pytest.param(unit("u [ t ] = 0"), "u", id="u-spaced"),
        pytest.param(unit("u = 0"), "u", id="u-unindexed"),
        pytest.param(unit(f"{OUT} = this[t]:bv[24]"), "this", id="this-read"),
    ],
)
def test_special_streams_are_named(text, name):
    error = refused(text)
    assert f"'{name}'" in error.message
    assert not error.temporal_reference


@pytest.mark.parametrize(
    "text,name",
    [
        pytest.param(unit(f"{OUT} = foo[t]:bv[24]"), "foo", id="unknown-name"),
        pytest.param(unit(f"{OUT} = x [ t ]"), "x", id="spaced-unknown"),
        pytest.param(unit(f"{OUT} = I1[t]:bv[24]"), "I1", id="uppercase-input"),
        pytest.param(unit(f"{OUT} = U[t]:bv[24]"), "U", id="uppercase-u"),
        pytest.param(unit(f"{OUT} = bvx[t]:bv[24]"), "bvx", id="bv-prefix-name"),
    ],
)
def test_unknown_streams_are_named(text, name):
    error = refused(text)
    assert f"unknown stream '{name}'" in error.message
    assert "only i<N> inputs and o<N> outputs may be indexed" in error.message


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(unit("o05[t]:bv[24] = 1"), id="leading-zero-output"),
        pytest.param(unit("i01[t]:bv[24] = 1"), id="leading-zero-input"),
        pytest.param(unit("o00[t]:bv[24] = 1"), id="double-zero"),
        pytest.param(unit(f"{OUT} = i1:bv[24]"), id="bare-input"),
        pytest.param(unit(f"{OUT} = i1"), id="bare-input-untyped"),
        pytest.param(unit(f"o12 = {A}"), id="bare-output"),
        pytest.param(unit(f"{OUT} = i 1[t]:bv[24]"), id="split-name"),
        pytest.param(unit(f"{OUT} = i1 [t]:bv[24]"), id="space-before-bracket"),
        pytest.param(unit(f"{OUT} = i1[ t ]:bv[24]"), id="space-inside-bracket"),
        pytest.param(unit(f"{OUT} = i1[t ]:bv[24]"), id="space-trailing-bracket"),
        pytest.param(unit(f"{OUT} = i1[]:bv[24]"), id="empty-bracket"),
        pytest.param(unit(f"{OUT} = i1[t:bv[24]"), id="unterminated-bracket"),
        pytest.param(unit(f"{OUT} = [t]:bv[24]"), id="bare-bracket"),
        pytest.param(unit(f"{OUT} = i1[t][t]:bv[24]"), id="double-bracket"),
    ],
)
def test_malformed_stream_references_refused(text):
    error = refused(text)
    assert not error.temporal_reference


@pytest.mark.parametrize(
    "index", ["t-1", "t - 1", "t+1", "t + 1", "3", "0", "n", "t-0", "t*2", "t-t", "-1", "T"]
)
def test_other_steps_are_temporal_references(index):
    error = refused(unit(f"{OUT} = i1[{index}]:bv[24]"))
    assert error.temporal_reference
    assert "reads a step other than the current one" in error.message
    assert f"i1[{index}]" in error.message


def test_temporal_reference_on_output_stream():
    error = refused(unit("o12[t-1]:bv[24] = 1"))
    assert error.temporal_reference
    assert "o12[t-1]" in error.message


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(unit(f"{OUT} = {A} := 1"), id="definition-operator"),
        pytest.param(unit(f"{OUT} = {A}, {B}"), id="comma"),
        pytest.param(unit(f'{OUT} = "x"'), id="double-quote"),
        pytest.param(unit(f"{OUT} = {A}; {B}"), id="semicolon"),
        pytest.param(unit(f"{OUT} = @{A}"), id="at"),
        pytest.param(unit(f"{OUT} = ~{A}"), id="tilde"),
        pytest.param(unit(f"{OUT} = `{A}"), id="backtick"),
        pytest.param(unit(f"{OUT} = {A} \\ {B}"), id="backslash"),
        pytest.param(unit(f"{OUT} = {A} $x"), id="dollar"),
        pytest.param(unit(f"{OUT} = {{ {A} }}"), id="brace-around-ref"),
        pytest.param(unit(f"{OUT} = {{"), id="stray-open-brace"),
        pytest.param(unit(f"{OUT} = }}"), id="stray-close-brace"),
        pytest.param(unit(f"{OUT} = {{ {{3}} }}:bv[24]"), id="nested-braces"),
        pytest.param(unit(f"{OUT} = {{ spec }}:bv[24]"), id="spec-constant"),
        pytest.param(unit(f"{OUT} = {{ always (o1[t]:bv[8] = 1) }}:bv[24]"), id="spec-with-rule"),
        pytest.param(unit(f"{OUT} = {{ }}:bv[24]"), id="empty-braces"),
        pytest.param(unit(f"{OUT} = {{ #x }}:bv[24]"), id="empty-hex"),
        pytest.param(unit(f"{OUT} = {{ #xZZ }}:bv[24]"), id="bad-hex"),
        pytest.param(unit(f"{OUT} = {{ #b102 }}:bv[24]"), id="bad-binary"),
        pytest.param(unit(f"{OUT} = {{ #XFF }}:bv[24]"), id="uppercase-hex-marker"),
        pytest.param(unit(f"{OUT} = {{ 1 2 }}:bv[24]"), id="two-numbers"),
        pytest.param(unit(f"{OUT} = {{ -1 }}:bv[24]"), id="negative-constant"),
        pytest.param(unit(f"{OUT} = {{ 007 }}:bv[24]"), id="leading-zero-decimal"),
        pytest.param(unit(f"{OUT} = {{ 1.5 }}:bv[24]"), id="fraction"),
        pytest.param(unit(f"{OUT} = {{3}}"), id="untyped-braced-literal"),
        pytest.param(unit(f"{OUT} = {{ #xFF }}"), id="untyped-hex-literal"),
        pytest.param(unit(f"{OUT} = {{256}}:bv[8]"), id="decimal-out-of-width"),
        pytest.param(unit(f"{OUT} = {{ #x100 }}:bv[8]"), id="hex-out-of-width"),
        pytest.param(unit(f"{OUT} = {{ #b100 }}:bv[2]"), id="binary-out-of-width"),
        pytest.param(unit(f"{OUT} = 5"), id="bare-five"),
        pytest.param(unit(f"{OUT} = 10"), id="bare-ten"),
        pytest.param(unit(f"{OUT} = 01"), id="bare-zero-one"),
        pytest.param(unit(f"{OUT} = 00"), id="bare-double-zero"),
        pytest.param(unit(f"{OUT} = 0x10"), id="c-style-hex"),
        pytest.param(unit(f"{OUT} = #xF0"), id="hex-outside-braces"),
        pytest.param(unit(f"{OUT} = #b10"), id="binary-outside-braces"),
        pytest.param(unit(f"{OUT} = 1 # trailing\n"), id="comment"),
        pytest.param(f"# note\nalways ( {CMP} ).", id="comment-line"),
        pytest.param(unit(f"{OUT} = {A} #"), id="lone-hash"),
        pytest.param(unit(f"{OUT} = {A}") + "\x00", id="nul-tail"),
        pytest.param(unit(f"{OUT} = \x00{A}"), id="nul-inside"),
        pytest.param(unit(f"{OUT} = {A}\x0b"), id="vertical-tab"),
        pytest.param(unit(f"{OUT} = {A}\x0c"), id="form-feed"),
        pytest.param(unit(f"{OUT} = {A}\x7f"), id="delete-char"),
        pytest.param(unit(f"{OUT} = {A} "), id="non-breaking-space"),
        pytest.param(unit(f"{OUT} = {A}​"), id="zero-width-space"),
        pytest.param(unit(f"{OUT} = ı{A}"), id="non-ascii-letter"),
        pytest.param("﻿" + unit(CMP), id="byte-order-mark"),
    ],
)
def test_lexical_forms_refused(text):
    refused(text)


@pytest.mark.parametrize(
    "ann",
    [":tau", ":nlang", ":sbf", ":bv", ":bv[0]", ":bv[385]", ":bv[024]", ":bv[-1]",
     ":bv[2.5]", ":bv[]", ":bv[x]", ":bv[24", ":bv[24]]", ":BV[24]", ":bv[1e2]",
     ":tau[24]", ":bv[24]:bv[24]", ":"],
)
def test_annotations_outside_the_fragment_refused(ann):
    refused(unit(f"o12[t]{ann} = {A}"))
    refused(unit(f"{OUT} = {{3}}{ann}"))


@pytest.mark.parametrize("width", [1, 8, 16, 24, 64, 384])
def test_annotation_widths_in_range(width):
    parse_rule_unit(unit(f"o12[t]:bv[{width}] = 0"))


def test_missing_annotation_refused_on_streams_and_braced_literals():
    refused(unit(f"o12[t] = {A}"))
    refused(unit(f"{OUT} = i1[t]"))
    refused(unit(f"{OUT} = {{ #x01 }}"))


def test_stream_at_two_widths_refused():
    refused(unit("o12[t]:bv[24] = i1[t]:bv[24] && o12[t]:bv[16] = 1"))
    refused(unit("i1[t]:bv[24] = i1[t]:bv[16]"))


def test_same_index_on_input_and_output_may_differ_in_width():
    parse_rule_unit(unit("o12[t]:bv[24] = i12[t]:bv[384]"))


def test_bare_zero_and_one_may_omit_annotation():
    parse_rule_unit(unit(f"{OUT} = 0"))
    parse_rule_unit(unit(f"{OUT} = 1"))


@pytest.mark.parametrize(
    "body",
    [
        f"{OUT} = {A} + {B} * {{3}}:bv[24]",
        f"{OUT} = {A} * {{3}}:bv[24] + {B}",
        f"{OUT} = {A} + {B} - {A}",
        f"{OUT} = {A} | {B} & {A}",
        f"{OUT} = {A} ^ {B} | {A}",
        f"{OUT} = {A} << {{1}}:bv[24] + {B}",
        f"{OUT} = {A} !| {B} !^ {A}",
        f"{OUT} = {A} - {B} - {A}",
        f"{OUT} = {A} >> {{1}}:bv[24] >> {{1}}:bv[24]",
        f"{OUT} = {A} / {{2}}:bv[24] / {{2}}:bv[24]",
    ],
)
def test_mixed_or_nonassociative_bitvector_operators_need_parentheses(body):
    refused(unit(body))


def test_parenthesized_forms_of_the_same_expressions_are_accepted():
    parse_rule_unit(unit(f"{OUT} = {A} + ({B} * {{3}}:bv[24])"))
    parse_rule_unit(unit(f"{OUT} = ({A} - {B}) - {A}"))
    parse_rule_unit(unit(f"{OUT} = ({A} | {B}) & {A}"))


@pytest.mark.parametrize(
    "body",
    [
        f"{OUT} = {A} * {B}",
        f"{OUT} = {A} / {B}",
        f"{OUT} = {A} % {B}",
        f"{OUT} = ({A}) * ({B})",
        f"{OUT} = ({A} + {B}) * {A}",
        f"{OUT} = {A} * {B} * {{2}}:bv[24]",
    ],
)
def test_multiplicative_operators_need_a_constant_operand(body):
    refused(unit(body))


@pytest.mark.parametrize(
    "body",
    [
        f"{A} = {B} = {A}",
        f"{A} < {B} < {A}",
        f"{A} <= {B} <= {A}",
        f"{A} != {B} = {A}",
        f"{A} !< {B} < {A}",
    ],
)
def test_chained_comparisons_refused(body):
    refused(unit(body))


@pytest.mark.parametrize(
    "body",
    [
        f"{A} {B} = {A}",
        f"{A}{B} = {A}",
        f"{A} = {B} {A}",
        f"{OUT} = {{1}}:bv[24] {{2}}:bv[24]",
        f"{OUT} = (1) (1)",
        f"{OUT} = 1 1",
        f"{OUT} = {A} ({B})",
        f"({A}) ({B}) = {A}",
        f"{A}",
        f"{A} +",
        f"= {A}",
        f"{A} = ",
        f"{CMP} {CMP}",
        f"({CMP}) ({CMP})",
        f"{CMP} &&",
        f"&& {CMP}",
    ],
)
def test_juxtaposition_and_incomplete_expressions_refused(body):
    refused(unit(body))


@pytest.mark.parametrize(
    "body",
    [
        f"{CMP} ? {CMP} : {CMP} ? {CMP} : {CMP}",
        f"{CMP} ? {CMP}",
        f"{CMP} : {CMP}",
        f"? {CMP} : {CMP}",
        f"({A} = {B}) -> ({CMP}) -> ({A} = {B})",
        f"({A} = {B}) <-> ({CMP}) <-> ({A} = {B})",
    ],
)
def test_ambiguous_wff_forms_refused(body):
    refused(unit(body))


def test_deep_parentheses_fail_closed():
    for depth in (33, 200, 5000):
        text = "always ( " + "(" * depth + CMP + ")" * depth + " )."
        error = refused(text)
        assert "nested" in error.message


def test_deep_negation_chain_is_bounded():
    error = refused(unit("!" * 5000 + f"({CMP})"))
    assert isinstance(error, RuleFragmentError)


def test_deep_operator_chain_is_bounded():
    text = unit(" && ".join([f"({CMP})"] * 5000))
    refused(text)


def test_moderate_nesting_is_accepted():
    text = "always ( " + "(" * 20 + CMP + ")" * 20 + " )."
    shape = parse_rule_unit(text)
    assert shape.nodes == 3


def _nested(depth):
    return "always ( " + "(" * depth + CMP + ")" * depth + " )."


def _under_frames(frames, fn):
    if frames == 0:
        return fn()
    return _under_frames(frames - 1, fn)


def test_nesting_limit_holds_under_a_deep_caller_stack():
    shape = _under_frames(500, lambda: parse_rule_unit(_nested(32)))
    assert shape.nodes == 3


def test_nesting_over_the_limit_is_a_fragment_error_not_recursion():
    def call():
        with pytest.raises(RuleFragmentError) as caught:
            parse_rule_unit(_nested(33))
        return caught.value

    assert "nested" in _under_frames(500, call).message


def test_unbalanced_parentheses_refused():
    refused(f"always ( ( {CMP} )")
    refused(f"always ( {CMP} ) )")
    refused(f"always ( ) ( {CMP} )")


def test_large_rule_screens_quickly():
    clause = f"({A} = {B})"
    text = "always ( " + " && ".join([clause] * 9000) + " )."
    assert len(text) > 256 * 1024 // 2
    start = time.perf_counter()
    with pytest.raises(RuleFragmentError):
        parse_rule_unit(text)
    big_ok = "always ( " + " || ".join(f"({A} = {B})" for _ in range(200)) + " )."
    parse_rule_unit(big_ok)
    huge = "always ( " + "(" * 60 + CMP + ")" * 60 + " && " + " ".join(["x"] * 60000) + " )."
    with pytest.raises(RuleFragmentError):
        parse_rule_unit(huge)
    junk = "always ( " + "ab" * 130000 + " )."
    with pytest.raises(RuleFragmentError):
        parse_rule_unit(junk)
    assert time.perf_counter() - start < 1.0


def test_non_string_input_refused():
    with pytest.raises(RuleFragmentError):
        parse_rule_unit(None)  # type: ignore[arg-type]
    with pytest.raises(RuleFragmentError):
        parse_rule_unit(b"always ( )")  # type: ignore[arg-type]


# --------------------------------------------------------- shipped examples


def _load_wallet_templates():
    path = os.path.join(project_root, "tests", "test_web_wallet_examples.py")
    spec = importlib.util.spec_from_file_location("_wallet_examples", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.get_templates()


@pytest.mark.parametrize("index", range(len(_load_wallet_templates())))
def test_web_wallet_templates_are_admitted(index):
    text = _load_wallet_templates()[index]
    parse_rule_unit(TauInterface.preprocess_spec_text(text))


def test_web_wallet_templates_mirror_the_generator():
    with open(os.path.join(project_root, "web-wallet", "app.js"), encoding="utf-8") as f:
        source = f.read()
    start = source.index("function generateRandomTauRule")
    body = source[start:source.index("// --- Wallet Management Functions", start)]
    assert body.count("() => [") == len(_load_wallet_templates())


# ---------------------------------------------------------------- sender guard

GUARD_REF = "i12[t]:bv[384]"
GUARD_LIT = "{ #x" + PUBKEY + " }:bv[384]"
GUARD_CMP = f"{GUARD_REF} = {GUARD_LIT}"
FEE = "o8[t]:bv[24] = { #x000005 }:bv[24]"
PUBKEY_VALUE = int(PUBKEY, 16)


def guard_of(body: str):
    return parse_rule_unit(unit(body)).sender_guard


@pytest.mark.parametrize("body", [
    pytest.param(f"{GUARD_CMP} -> ({FEE})", id="bare-antecedent"),
    pytest.param(f"({GUARD_CMP}) -> ({FEE})", id="parenthesized-antecedent"),
    pytest.param(f"(({GUARD_CMP})) -> {FEE}", id="double-parenthesized-antecedent"),
    pytest.param(f"(({GUARD_CMP}) -> ({FEE}))", id="parenthesized-whole"),
    pytest.param(f"((({GUARD_CMP}) -> ({FEE})))", id="doubly-parenthesized-whole"),
    pytest.param(f"({GUARD_CMP}) -> ({FEE} || {CMP})", id="wide-consequent"),
    pytest.param(f"({GUARD_CMP}) -> (({A} > {B}) -> ({FEE}))", id="implication-in-consequent"),
])
def test_sender_guard_is_reported(body):
    assert guard_of(body) == PUBKEY_VALUE


def test_sender_guard_hex_is_case_insensitive():
    upper = "{ #x" + PUBKEY.upper() + " }:bv[384]"
    assert guard_of(f"({GUARD_REF} = {upper}) -> ({FEE})") == PUBKEY_VALUE


def test_sender_guard_ignores_leading_zeros_in_value():
    zeros = "{ #x00" + PUBKEY[2:] + " }:bv[384]"
    assert guard_of(f"({GUARD_REF} = {zeros}) -> ({FEE})") == int(PUBKEY[2:], 16)


@pytest.mark.parametrize("body", [
    pytest.param(f"({GUARD_CMP}) <- ({FEE})", id="reverse-implication"),
    pytest.param(f"({GUARD_CMP}) <-> ({FEE})", id="equivalence"),
    pytest.param(f"({GUARD_CMP}) || ({FEE})", id="or"),
    pytest.param(f"({GUARD_CMP}) && ({FEE})", id="and"),
    pytest.param(f"({GUARD_CMP}) ? ({FEE}) : ({CMP})", id="ternary"),
    pytest.param(f"({GUARD_CMP}) -> ({FEE}) ? ({CMP}) : ({CMP})", id="implication-in-ternary-condition"),
    pytest.param(f"(({GUARD_CMP}) -> ({FEE})) ? ({CMP}) : ({CMP})", id="parenthesized-implication-ternary"),
    pytest.param(f"!(({GUARD_CMP}) -> ({FEE}))", id="negated-implication"),
    pytest.param(f"!({GUARD_CMP}) -> ({FEE})", id="negated-antecedent"),
    pytest.param(f"({GUARD_REF} = {{ 1234 }}:bv[384]) -> ({FEE})", id="decimal-literal"),
    pytest.param(f"({GUARD_REF} = {{ #b101 }}:bv[384]) -> ({FEE})", id="binary-literal"),
    pytest.param(f"({GUARD_LIT} = {GUARD_REF}) -> ({FEE})", id="literal-on-the-left"),
    pytest.param(f"({GUARD_REF} != {GUARD_LIT}) -> ({FEE})", id="inequality"),
    pytest.param(f"(i3[t]:bv[384] = {GUARD_LIT}) -> ({FEE})", id="from-address-guard"),
    pytest.param(f"(i120[t]:bv[384] = {GUARD_LIT}) -> ({FEE})", id="other-input"),
    pytest.param(f"({GUARD_REF} = {{ #x{'ab' * 24} }}:bv[192]) -> ({FEE})", id="other-width"),
    pytest.param(f"(({GUARD_CMP}) -> ({CMP})) -> ({FEE})", id="nested-implication-antecedent"),
    pytest.param(f"(({GUARD_CMP}) && ({A} = {B})) -> ({FEE})", id="conjoined-antecedent"),
    pytest.param(f"(({GUARD_CMP}) || ({A} = {B})) -> ({FEE})", id="disjoined-antecedent"),
    pytest.param(f"(i12[t]:bv[384]' = {GUARD_LIT}) -> ({FEE})", id="complemented-ref"),
    pytest.param(f"({GUARD_REF} = {GUARD_LIT}') -> ({FEE})", id="complemented-literal"),
    pytest.param(f"({A} = {B}) -> ({FEE})", id="no-guard"),
    pytest.param(FEE, id="bare-comparison"),
])
def test_sender_guard_absent_for_other_shapes(body):
    assert guard_of(body) is None


def test_sender_guard_does_not_change_what_is_admitted():
    for text in (unit(f"({GUARD_CMP}) -> ({FEE})"), unit(f"({GUARD_CMP}) ? ({FEE}) : ({CMP})")):
        assert isinstance(parse_rule_unit(text), RuleShape)
    refused(unit(f"({GUARD_REF} = {{ #x{PUBKEY} }}) -> ({FEE})"))
