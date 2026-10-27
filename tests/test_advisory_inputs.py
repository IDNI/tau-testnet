"""The advisory evaluator feeds input VALUES, not in-spec literals.

No engine needed: this is the shape of what is handed to the worker session.
"""
import tau_advisory


def test_a_wrapped_bv_literal_is_fed_bare():
    """`{ #x.. }:bv[384]` is how the in-process shrink layer wants a pubkey; the
    engine refuses it as an input value, and the consensus answer came back with
    no o6/o7."""
    named = tau_advisory.AdvisoryEvaluator._named({13: "{ #x0a1b }:bv[384]"})
    assert named == {"i13": "#x0a1b"}


def test_bare_values_and_stream_names_pass_through():
    named = tau_advisory.AdvisoryEvaluator._named({"i10": "1", 14: 200000, "15": "0"})
    assert named == {"i10": "1", "i14": "200000", "i15": "0"}
