"""A full shrink width grows by a re-exec, and the re-exec carries the new width.

A speculative allocation never persists the id that did not fit, so the intern
table alone would give the fresh process the same full width again.
"""
import os
from types import SimpleNamespace

import pytest

import tau_admission
import tau_manager
import tau_shrink as ts


class _ReExec(BaseException):
    """Stands for os.execv, which never returns to the caller."""


@pytest.fixture
def execv(monkeypatch):
    calls = []

    def _execv(path, argv):
        calls.append(os.environ.get(ts.MIN_WIDTH_ENV))
        raise _ReExec()

    monkeypatch.setattr(tau_manager, "tau_test_mode", False)
    monkeypatch.delenv("TAU_NO_WIDTH_REEXEC", raising=False)
    monkeypatch.delenv(ts.MIN_WIDTH_ENV, raising=False)
    monkeypatch.setattr(os, "execv", _execv)
    yield calls
    # The handler writes os.environ itself, so monkeypatch cannot undo it.
    os.environ.pop(ts.MIN_WIDTH_ENV, None)


def _overflow(required_id=255):
    return ts.ShrinkWidthOverflow("id 255 exceeds bv[8]", required_id=required_id)


def test_the_reexec_carries_the_width_of_the_overflowing_id(execv):
    with pytest.raises(_ReExec):
        tau_manager._handle_width_overflow(_overflow(255))
    assert execv == ["16"]


def test_the_reexec_keeps_a_wider_minimum(execv, monkeypatch):
    monkeypatch.setenv(ts.MIN_WIDTH_ENV, "24")
    with pytest.raises(_ReExec):
        tau_manager._handle_width_overflow(_overflow(255))
    assert execv == ["24"]


def test_an_overflow_without_an_id_sets_no_minimum(execv):
    with pytest.raises(_ReExec):
        tau_manager._handle_width_overflow(_overflow(None))
    assert execv == [None]


# --- admission sends the overflow to the re-exec ---

class _Session:
    def __init__(self, exc):
        self.exc = exc

    def apply_rule(self, *a, **k):
        raise self.exc

    def evaluate(self, *a, **k):
        raise self.exc

    def dispose(self):
        pass


@pytest.fixture
def reexec_calls(monkeypatch):
    calls = []

    def _handler(exc):
        calls.append(exc)
        raise exc

    monkeypatch.setattr(tau_manager, "_handle_width_overflow", _handler)
    return calls


def _context(exc):
    return tau_admission.AdmissionContext(
        _Session(exc), anchor={}, plan=SimpleNamespace(width=8), label="admission",
        deadline=None, release=None)


@pytest.mark.parametrize("call", [
    lambda ctx: ctx.revise("always ( o8[t] = 0 )."),
    lambda ctx: ctx.step({1: "0"}),
], ids=["revise", "step"])
def test_an_admission_overflow_reaches_the_reexec(reexec_calls, call):
    with pytest.raises(tau_admission.AdmissionUnavailable):
        call(_context(_overflow()))
    assert [type(e) for e in reexec_calls] == [ts.ShrinkWidthOverflow]


def test_another_admission_error_does_not_reexec(reexec_calls):
    with pytest.raises(tau_admission.AdmissionUnavailable):
        _context(ts.ShrinkUnavailable("db")).step({1: "0"})
    assert reexec_calls == []
