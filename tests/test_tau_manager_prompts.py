import tau_manager


def test_tau_prompt_regexes_distinguish_input_vs_output() -> None:
    # Input prompts should match only i*
    assert tau_manager.TAU_INPUT_PROMPT_RE.match("i0[0]:tau :=")
    assert tau_manager.TAU_INPUT_PROMPT_RE.match("i1[123]:bv[16] :=")
    assert tau_manager.TAU_INPUT_PROMPT_RE.match("i2[t]:untyped =")
    assert not tau_manager.TAU_INPUT_PROMPT_RE.match("o0[0]:tau :=")
    assert not tau_manager.TAU_INPUT_PROMPT_RE.match("o1[1]:bv :=")

    # Output prompts should match only o*
    assert tau_manager.TAU_OUTPUT_PROMPT_RE.match("o0[0]:tau :=")
    assert tau_manager.TAU_OUTPUT_PROMPT_RE.match("o1[1]:bv[16] =")
    assert not tau_manager.TAU_OUTPUT_PROMPT_RE.match("i0[0]:tau :=")

    # Any-prompt regex should match both (used as a delimiter when parsing "Updated specification")
    assert tau_manager.TAU_ANY_PROMPT_RE.match("i0[0]:tau :=")
    assert tau_manager.TAU_ANY_PROMPT_RE.match("o0[0]:tau :=")


def test_normalize_rule_bitvector_sizes_rewrites_unsized_bv() -> None:
    rule = (
        "always (((((i1[t] | i2[t]) & i3[t]) | { #b0 }:bv) = { #b0 }:bv) ? "
        "o12[t] = (((i1[t] | i2[t]) & i3[t]) | { #b0 }:bv) : "
        "o12[t] = ((((i1[t] | i2[t]) & i3[t]) | { #b0 }:bv))')."
    )
    normalized = tau_manager.normalize_rule_bitvector_sizes(rule)
    assert ":bv[64]" in normalized
    # All unsized annotations should be removed.
    assert ":bv)" not in normalized

    # Existing sizes must remain untouched.
    sized_rule = "always (o1[t]:bv[16] = i1[t]:bv[16])."
    assert tau_manager.normalize_rule_bitvector_sizes(sized_rule) == sized_rule


