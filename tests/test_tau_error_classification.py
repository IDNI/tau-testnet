"""W9: failures are classified by phase and owner, not lumped into one type.

The incident: a malformed runtime rule produced `dump_crash_log("TauEngineBug")`,
which an external monitor latched onto as a node CRASH_ANOMALY and used to block
governance for 27 hours. W0 measured that a parse/type refusal is a clean no-op --
`step` returns None, neither `spec_revision` nor `time_point` advances, no type is
established, and the interpreter keeps accepting later revisions. It is a verdict
about the input, not a node failure.
"""
import pytest

import tau_native
from errors import TauEngineBug, TauSpecIntegrationError, TauSpecRejected

ANSI = "\x1b[31;1m"
RESET = "\x1b[0m"


def _err(body: str) -> str:
    """The engine ANSI-colours its severity marker; a literal "(Error)" screen
    matches nothing. These fixtures keep the escape codes on purpose."""
    return f"({ANSI}Error{RESET}) {body}\n"


INPUT_FAULTS = [
    _err("Incompatible type information in i12, expected :bv[384], found :bv[8]"),
    _err("[tau] spec failed to transform to tau tree"),
    _err("Failed to parse input value always ( garbage"),
    _err("[tau] Syntax Error: Unexpected end of file at 1:28 (28)"),
    _err("Error creating bitvector constant from string 'fffffffff': overflow in "
         "bit-vector construction (specified bit-vector size 24 too small)"),
]


@pytest.mark.parametrize("text", INPUT_FAULTS)
def test_engine_input_faults_are_recognised(text):
    assert tau_native.tau_reports_error(text)
    assert tau_native.tau_error_is_input_fault(text)


def test_a_genuine_engine_fault_is_not_an_input_fault():
    text = _err("Found clause containing non-equation: o0[3]:tau' = 0 && 1")
    assert tau_native.tau_reports_error(text)
    assert not tau_native.tau_error_is_input_fault(text)


def test_clean_output_is_not_an_error():
    assert not tau_native.tau_error_is_input_fault("Updated specification (132 chars): ...")
    assert not tau_native.tau_error_is_input_fault("")
    assert not tau_native.tau_error_is_input_fault(None)


# --- what gets raised, and what gets dumped -----------------------------------

@pytest.mark.parametrize("text", INPUT_FAULTS)
def test_author_input_fault_raises_rejected_without_a_crash_dump(monkeypatch, text):
    dumped = []
    monkeypatch.setattr(tau_native.tau_io_logger, "dump_crash_log",
                        lambda *a, **k: dumped.append(a) or "/tmp/x")
    exc = tau_native._classify_step_error("msg", text, node_generated=False)
    assert isinstance(exc, TauSpecRejected)
    assert not isinstance(exc, TauEngineBug)
    assert dumped == []


def test_node_generated_fault_is_an_integration_failure_not_a_bad_rule(monkeypatch):
    """The incident itself: the author's rule was correct and the runtime text we
    built from it was not. Reporting that as an invalid rule hides our defect."""
    dumped = []
    monkeypatch.setattr(tau_native.tau_io_logger, "dump_crash_log",
                        lambda *a, **k: dumped.append(a) or "/tmp/x")
    exc = tau_native._classify_step_error("msg", INPUT_FAULTS[0], node_generated=True)
    assert isinstance(exc, TauSpecIntegrationError)
    assert not isinstance(exc, TauSpecRejected)
    assert dumped == []


def test_a_real_engine_fault_still_dumps(monkeypatch):
    dumped = []
    monkeypatch.setattr(tau_native.tau_io_logger, "dump_crash_log",
                        lambda *a, **k: dumped.append(a) or "/tmp/x")
    text = _err("Found clause containing non-equation: o0[3]:tau' = 0 && 1")
    exc = tau_native._classify_step_error("msg", text, node_generated=False)
    assert isinstance(exc, TauEngineBug)
    assert dumped, "a genuine engine fault must still produce a crash log"


def test_ansi_wrapped_marker_is_matched_by_the_helper_not_a_literal():
    """Guards the bug this replaced: `"(error)" in str(e).lower()` cannot match
    `(\\x1b[31;1mError\\x1b[0m)`, so the apply-side replay branch never fired."""
    wrapped = _err("anything at all")
    assert "(error)" not in wrapped.lower()
    assert tau_native.tau_reports_error(wrapped)
