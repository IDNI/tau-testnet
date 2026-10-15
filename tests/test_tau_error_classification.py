"""Failures are classified by report code and owner, not lumped into one type.

A malformed runtime rule once produced a `TauEngineBug` crash dump that an
external monitor treated as a node crash. Input-fault codes (parse, type,
unsat, ...) are a verdict about the input; only other codes are engine faults.
"""
from dataclasses import dataclass, field

import pytest

import tau_native
from errors import TauEngineBug, TauSpecIntegrationError, TauSpecRejected

INPUT_FAULT_CODES = [1, 4, 7, 8, 9, 10, 12, 13, 15]
ENGINE_CODES = [2, 14, 16, 5, 3]


@dataclass
class _Report:
    codes: list = field(default_factory=list)


@pytest.fixture
def dumped(monkeypatch):
    calls = []
    monkeypatch.setattr(tau_native.tau_io_logger, "dump_crash_log",
                        lambda *a, **k: calls.append(a) or "/tmp/x")
    return calls


@pytest.mark.parametrize("code", INPUT_FAULT_CODES)
def test_input_fault_code_raises_rejected_without_a_crash_dump(dumped, code):
    exc = tau_native._classify_report(_Report([code]), "msg", node_generated=False)
    assert isinstance(exc, TauSpecRejected)
    assert not isinstance(exc, TauEngineBug)
    assert dumped == []


def test_input_fault_wins_over_internal_error(dumped):
    exc = tau_native._classify_report(_Report([2, 13]), "msg", node_generated=False)
    assert isinstance(exc, TauSpecRejected)
    assert dumped == []


def test_node_generated_fault_is_an_integration_failure_not_a_bad_rule(dumped):
    """The author's rule was correct and the runtime text we built from it was
    not; reporting that as an invalid rule would hide our defect."""
    exc = tau_native._classify_report(_Report([4, 15]), "msg", node_generated=True)
    assert isinstance(exc, TauSpecIntegrationError)
    assert not isinstance(exc, TauSpecRejected)
    assert dumped == []


@pytest.mark.parametrize("codes", [[code] for code in ENGINE_CODES] + [[]])
def test_engine_codes_dump_and_raise_engine_bug(dumped, codes):
    exc = tau_native._classify_report(_Report(codes), "msg", node_generated=False)
    assert isinstance(exc, TauEngineBug)
    assert dumped, "a genuine engine fault must still produce a crash log"
