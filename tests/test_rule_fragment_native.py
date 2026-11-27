"""Every rule the allow-list admits builds on the REAL engine.

The corpus keeps one width per stream (the engine types streams process-wide) and
runs in a child process, as the other native suites do.
"""
import json

import pytest

from test_reserved_output_native import _run_child, requires_native
from test_web_wallet_examples import get_templates

PUBKEY = "ab" * 48
A = "i1[t]:bv[24]"
B = "i2[t]:bv[24]"
K = "i4[t]:bv[384]"
LONG = "{ #x" + PUBKEY + " }:bv[384]"


def unit(body: str) -> str:
    return f"always ( {body} )."


def lit(value) -> str:
    return f"{{ {value} }}:bv[24]"


CORPUS = [
    unit(f"o12[t]:bv[24] = {lit('#xF0')}"),
    unit(f"o13[t]:bv[24] = {lit('#xFACE')}"),
    unit(f"o14[t]:bv[24] = {lit('#xAE')}"),
    unit(f"o15[t]:bv[24] = {lit('#xb1')}"),
    unit(f"o16[t]:bv[24] = {lit('#b1010')}"),
    unit(f"o17[t]:bv[24] = {lit(10)}"),
    unit("o18[t]:bv[24] = 1"),
    unit(f"o19[t]:bv[24] = {A} + {B} + {A}"),
    unit(f"o20[t]:bv[24] = {A} + ({B} * {lit(3)})"),
    unit(f"o21[t]:bv[24] = {A} - {B}"),
    unit(f"o22[t]:bv[24] = {A} & {B}"),
    unit(f"o23[t]:bv[24] = {A} | {B}"),
    unit(f"o24[t]:bv[24] = {A} ^ {B}"),
    unit(f"o25[t]:bv[24] = {A} << {lit(2)}"),
    unit(f"o26[t]:bv[24] = {A} >> {lit(2)}"),
    unit(f"o27[t]:bv[24] = ({A} | {B})'"),
    unit(f"o28[t]:bv[24] = {A} * {lit(3)}"),
    unit(f"o29[t]:bv[24] = {A} / {lit(2)}"),
    unit(f"o30[t]:bv[24] = {A} % {lit(7)}"),
    unit(f"({A} > {lit(5)}) ? o12[t]:bv[24] = {lit(1)} : o12[t]:bv[24] = {lit(0)}"),
    unit(f"({A} = {B}) <-> (o13[t]:bv[24] = {lit(1)})"),
    unit(f"({A} != {B}) ^^ (o14[t]:bv[24] = {lit(1)})"),
    unit(f"({A} !<= {B}) -> (o15[t]:bv[24] = {lit(1)})"),
    unit(f"({A} <= {B}) || (o16[t]:bv[24] = {lit(1)})"),
    unit(f"(o17[t]:bv[24] = {lit(1)}) && (o18[t]:bv[24] = {lit(2)})"),
    unit(f"({A} >= {B}) -> (o19[t]:bv[24] = {lit(1)})"),
    unit(f"!({A} < {B}) || (o18[t]:bv[24] = {lit(1)})"),
    unit(f"({K} = {LONG}) -> o12[t]:bv[24] = {{ #x000101 }}:bv[24]"),
    unit(f"({K} = {LONG}) ? (o19[t]:bv[24] = {lit(1)}) : (o19[t]:bv[24] = {lit(0)})"),
    *get_templates(),
]


_BUILD_BODY = r'''
import tau_native
from consensus.rule_fragment import parse_rule_unit

failures = []
rules = json.loads(os.environ["CORPUS"])
for text in rules:
    parse_rule_unit(tau_native.TauInterface.preprocess_spec_text(text))
    spec = tempfile.NamedTemporaryFile("w", suffix=".tau", delete=False)
    spec.write(text)
    spec.close()
    try:
        iface = tau_native.TauInterface(spec.name)
        if iface.interpreter is None:
            failures.append([text, "no interpreter"])
    except Exception as exc:
        failures.append([text, repr(exc)])
emit({"built": len(rules), "failures": failures})
'''


@requires_native
def test_every_admitted_rule_builds_on_the_engine(tmp_path):
    out = _run_child(tmp_path, "rule_fragment_build", _BUILD_BODY,
                     {"CORPUS": json.dumps(CORPUS)})
    assert out["failures"] == []
    assert out["built"] == len(CORPUS)
