"""The `Updated specification` marker regex, which gates interpreter rebuilds.

tau-lang prints the spec size in the marker on current builds:

    Updated specification (1110 chars): always (...)

The original pattern required `specification:` with nothing between, so it
matched NOTHING on such a build. The consequences are silent and total:
`_extract_latest_updated_spec` never rebuilds the interpreter from the printed
spec, so `TauInterface.get_current_spec()` keeps returning the boot spec, so
`createblock`'s post-simulation restore replaces the live spec with just the
genesis router -- wiping o6/o7 -- and every block carrying a transaction is
rejected with "o6: 0". A node in that state mines empty blocks forever and
accepts no transaction at all.

Found by running the co-signature e2e against a live native node; no mock test
sees it, because the marker only exists in real engine output.
"""
import tau_native


def test_the_current_build_marker_matches():
    line = "Updated specification (1110 chars): always (o1[t]:bv[24] = i1[t]:bv[24])"
    match = tau_native._UPDATED_SPEC_LINE_RE.match(line)
    assert match is not None
    assert match.group(1).startswith("always (")


def test_the_legacy_marker_still_matches():
    line = "Updated specification: always (o1[t]:bv[24] = i1[t]:bv[24])"
    match = tau_native._UPDATED_SPEC_LINE_RE.match(line)
    assert match is not None
    assert match.group(1) == "always (o1[t]:bv[24] = i1[t]:bv[24])"


def test_the_size_warning_is_not_mistaken_for_a_spec():
    """A sibling WARNING shares the prefix. Matching it would feed the warning
    text to the interpreter as a specification."""
    for line in (
        "Updated specification size 262145 chars exceeds the limit",
        "Updated specification size 10 chars",
    ):
        assert tau_native._UPDATED_SPEC_LINE_RE.match(line) is None, line


def test_extraction_picks_the_LAST_spec_in_a_capture():
    """One engine call can print several; the final one is the live spec.

    Blank-line separated, as the engine actually prints them: the extractor
    treats non-blank following lines as CONTINUATIONS of the spec, since a long
    spec wraps across lines.
    """
    output = "\n".join([
        "noise",
        "",
        "Updated specification (12 chars): always (o1[t] = 1).",
        "",
        "more noise",
        "",
        "Updated specification (13 chars): always (o1[t] = 2).",
    ])
    # Unbound call with the CLASS as self: the body only reaches
    # _ensure_trailing_period, which is a classmethod, so this exercises the
    # extractor without booting an engine.
    got = tau_native.TauInterface._extract_latest_updated_spec(
        tau_native.TauInterface, output)
    assert got == "always (o1[t] = 2)."


def test_no_marker_yields_nothing():
    assert not tau_native.TauInterface._extract_latest_updated_spec(
        tau_native.TauInterface, "just logs\n")
