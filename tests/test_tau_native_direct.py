from __future__ import annotations

import re
from dataclasses import dataclass, field

import pytest

import tau_native
from errors import TauEngineBug, TauSpecRejected


@dataclass(frozen=True)
class _FakeStreamAt:
    name: str
    time_point: int


@dataclass
class _FakeReport:
    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)
    infos: list = field(default_factory=list)
    codes: list = field(default_factory=list)
    code_names: list = field(default_factory=list)
    has_error: bool = False
    awaiting_input: bool = False


class _FakeResult:
    """Mirrors tau.result: value is None when disengaged, bool = has value."""

    def __init__(self, value, report=None, has_value=True):
        self.value = value if has_value else None
        self.report = report or _FakeReport()
        self._has_value = has_value

    def __bool__(self):
        return self._has_value


def _failure(code, message="boom"):
    return _FakeResult(
        None, _FakeReport(errors=[message], codes=[code], has_error=True), has_value=False
    )


class _FakeInterpreter:
    def __init__(self, spec: str):
        self.spec = spec
        self.time_point = 0
        self.spec_revision = 0
        self.input_names = self._extract_input_names(spec)

    def current_spec(self) -> str:
        return self.spec

    def set_spec(self, spec: str):
        if spec != self.spec:
            self.spec = spec
            self.spec_revision += 1
            self.input_names = self._extract_input_names(spec)

    @staticmethod
    def _extract_input_names(spec: str) -> set[str]:
        names = {"i0"}
        for match in re.findall(r"\bi(\d+)\[", spec or ""):
            names.add(f"i{int(match)}")
        return names


class _FakeTauModule:
    result = _FakeResult

    def __init__(self):
        self.last_assigned_inputs: dict[str, str] = {}
        self.calls: list[dict[str, str]] = []
        self.await_mode = None  # "same" | "moved": first step awaits input
        self.disengage = False
        self.unsat = False
        self.step_error = False
        self.empty_prompt = False
        self.empty_value = False
        self._awaited = False

    @staticmethod
    def init_report():
        return _FakeReport()

    def get_interpreter(self, spec: str):
        return _FakeResult(_FakeInterpreter(spec))

    def get_inputs_for_step(self, interpreter: _FakeInterpreter):
        if self.empty_prompt:
            return _FakeResult([])

        def _sort_key(name: str) -> int:
            return int(name[1:]) if name.startswith("i") and name[1:].isdigit() else 0

        return _FakeResult([
            _FakeStreamAt(name=n, time_point=interpreter.time_point)
            for n in sorted(interpreter.input_names, key=_sort_key)
        ])

    def step(self, interpreter: _FakeInterpreter, inputs: dict[_FakeStreamAt, str]):
        assigned: dict[str, str] = {}
        for stream_at, value in inputs.items():
            if stream_at.name not in interpreter.input_names:
                return _failure(9, f"Input stream {stream_at.name} not found in context")
            assigned[stream_at.name] = str(value)
        self.last_assigned_inputs = assigned
        self.calls.append(assigned)

        if self.await_mode and not self._awaited:
            self._awaited = True
            if self.await_mode == "moved":
                interpreter.time_point += 1
            return _FakeResult(
                None,
                _FakeReport(errors=["Auto continue is false"], codes=[6], has_error=True,
                            awaiting_input=True),
                has_value=False,
            )
        if self.disengage:
            return _failure(15, "Syntax error")

        i0_value = assigned.get("i0")
        if not self.unsat and i0_value and i0_value not in {"F", "0"}:
            lhs = interpreter.spec.rstrip(".")
            interpreter.set_spec(f"{lhs} && {i0_value.rstrip('.')}.")

        if self.empty_value:
            outputs = {}
        else:
            outputs = {
                _FakeStreamAt(name="o0", time_point=interpreter.time_point): "T" if self.unsat else "F",
                _FakeStreamAt(name="o1", time_point=interpreter.time_point): assigned.get("i1", "0"),
            }
        interpreter.time_point += 1
        report = _FakeReport(errors=["late fault"], codes=[15], has_error=True) if self.step_error else _FakeReport()
        return _FakeResult(outputs, report)


def _make_genesis_file(tmp_path):
    genesis = tmp_path / "genesis.tau"
    genesis.write_text("#tau i0 = console.\n(i0[t] = 0 ? o0[t] = 1 : o0[t] = 0).")
    return genesis


def test_preprocess_strips_directives_and_comments_preserves_bv_literals(tmp_path, monkeypatch):
    fake_tau = _FakeTauModule()
    monkeypatch.setattr(tau_native, "tau", fake_tau)

    genesis = tmp_path / "genesis_with_comments.tau"
    genesis.write_text(
        "#tau i0 = console.\n"
        "(i0[t] = 0 ? o0[t] = { 1 }:bv[16] : o0[t] = { 0 }:bv[16]). # trailing comment\n"
    )

    iface = tau_native.TauInterface(str(genesis))
    loaded = iface.get_current_spec()

    assert "#tau" not in loaded
    assert "trailing comment" not in loaded
    assert "1" in loaded
    assert "0" in loaded


def test_preprocess_multiline_conditional_with_comments_keeps_expression(tmp_path, monkeypatch):
    fake_tau = _FakeTauModule()
    monkeypatch.setattr(tau_native, "tau", fake_tau)

    genesis = tmp_path / "genesis_multiline.tau"
    genesis.write_text(
        "#tau i0 = console.\n\n"
        "((!(i0[t] = 0)) # Check if rule proposal data is present\n"
        "    ? ( # --- Process Rule Proposal from i0[t] ---\n"
        "        u[t] = i0[t] && o0[t] = 0\n"
        "    ) : o0[t] = 1\n"
        ")\n"
    )

    iface = tau_native.TauInterface(str(genesis))
    loaded = iface.get_current_spec()

    assert "?" in loaded
    assert ":" in loaded
    assert "Check if rule proposal" not in loaded
    assert "#tau" not in loaded


def test_accumulated_spec_follows_applied_revision(tmp_path, monkeypatch):
    fake_tau = _FakeTauModule()
    monkeypatch.setattr(tau_native, "tau", fake_tau)
    iface = tau_native.TauInterface(str(_make_genesis_file(tmp_path)))
    interpreter = iface.interpreter

    iface.communicate(
        rule_text="always (o1[t] = i1[t]).",
        target_output_stream_index=0,
        input_stream_values=None,
    )
    assert iface.interpreter is interpreter
    assert interpreter.spec_revision == 1
    assert "always (o1[t] = i1[t])" in iface.get_current_spec()

    out = iface.communicate(
        rule_text=None,
        target_output_stream_index=1,
        input_stream_values={1: "2"},
    )
    assert out == "2"


def test_missing_direct_inputs_use_docker_style_fallback(tmp_path, monkeypatch):
    fake_tau = _FakeTauModule()
    monkeypatch.setattr(tau_native, "tau", fake_tau)
    iface = tau_native.TauInterface(str(_make_genesis_file(tmp_path)))

    iface.communicate(
        rule_text="always (o1[t] = i1[t]).",
        target_output_stream_index=0,
        input_stream_values=None,
    )
    iface.communicate(
        rule_text=None,
        target_output_stream_index=1,
        input_stream_values={1: "9"},
    )
    assert fake_tau.last_assigned_inputs["i0"] == "F"
    assert fake_tau.last_assigned_inputs["i1"] == "9"


def test_preprocess_types_untyped_all_quantifier_from_updated_spec(tmp_path, monkeypatch):
    fake_tau = _FakeTauModule()
    monkeypatch.setattr(tau_native, "tau", fake_tau)

    # Minimal genesis with a typed input so we have a typed term to infer from.
    genesis = tmp_path / "genesis_quant.tau"
    genesis.write_text("#tau i0 = console.\n(always (o6[t]:bv[16] = i10[t]:bv[16])).")

    iface = tau_native.TauInterface(str(genesis))

    # Simulate an updated spec fragment similar to what the native engine can emit,
    # containing an untyped quantifier var compared against a typed bv[16] term.
    updated = (
        "always (o6[t]:bv[16] = i10[t]:bv[16] && "
        "(all b1 b1 != 0 || b1 != i10[t]:bv[16])"
        ")."
    )
    fixed = iface.preprocess_spec_text(updated)
    assert "all b1:bv[16]" in fixed


def _iface(tmp_path, monkeypatch, **flags):
    fake_tau = _FakeTauModule()
    for key, value in flags.items():
        setattr(fake_tau, key, value)
    monkeypatch.setattr(tau_native, "tau", fake_tau)
    monkeypatch.setattr(tau_native.tau_io_logger, "dump_crash_log", lambda *a, **k: None)
    return fake_tau, tau_native.TauInterface(str(_make_genesis_file(tmp_path)))


def test_engaged_empty_prompt_is_a_present_value(tmp_path, monkeypatch):
    fake_tau, iface = _iface(tmp_path, monkeypatch, empty_prompt=True)
    assert iface.communicate_multi()[0] == "F"
    assert fake_tau.calls == [{}]


def test_engaged_empty_outputs_are_a_present_value(tmp_path, monkeypatch):
    _, iface = _iface(tmp_path, monkeypatch, empty_value=True)
    assert iface.communicate_multi() == {}


def test_retry_at_same_time_point_reoffers_the_rule(tmp_path, monkeypatch):
    fake_tau, iface = _iface(tmp_path, monkeypatch, await_mode="same")
    iface.communicate(rule_text="always (o1[t] = i1[t]).")
    assert len(fake_tau.calls) == 2
    assert fake_tau.calls[0]["i0"] == fake_tau.calls[1]["i0"] == "always (o1[t] = i1[t])."
    assert iface.last_revision_receipt["delivered"] is True


def test_awaiting_input_after_time_moved_is_an_engine_bug(tmp_path, monkeypatch):
    _, iface = _iface(tmp_path, monkeypatch, await_mode="moved")
    with pytest.raises(TauEngineBug, match="dropped its outputs"):
        iface.communicate(rule_text="always (o1[t] = i1[t]).")


def test_value_with_error_report_raises_and_keeps_receipt(tmp_path, monkeypatch):
    _, iface = _iface(tmp_path, monkeypatch, step_error=True)
    with pytest.raises(TauSpecRejected) as info:
        iface.communicate(rule_text="always (o1[t] = i1[t]).")
    assert info.value.receipt is iface.last_revision_receipt
    assert iface.last_revision_receipt["delivered"] is True


def _use_fake_for_compile(monkeypatch, **flags):
    fake_tau = _FakeTauModule()
    for key, value in flags.items():
        setattr(fake_tau, key, value)
    monkeypatch.setattr(tau_native, "tau", fake_tau)
    monkeypatch.setattr(tau_native, "load_tau_module", lambda: fake_tau)
    return fake_tau


def test_compile_accepts_a_clean_revision(monkeypatch):
    _use_fake_for_compile(monkeypatch)
    assert tau_native.TauInterface.compile_revisions_isolated(
        "(i0[t] = 0).", ["always (o1[t] = i1[t])."]
    ) is None


def test_compile_rejects_a_disengaged_step(monkeypatch):
    _use_fake_for_compile(monkeypatch, disengage=True)
    err = tau_native.TauInterface.compile_revisions_isolated(
        "(i0[t] = 0).", ["always (o1[t] = i1[t])."]
    )
    assert err and err.startswith("Tau staging compile error")


def test_compile_rejects_an_unrouted_revision(monkeypatch):
    _use_fake_for_compile(monkeypatch, unsat=True)
    err = tau_native.TauInterface.compile_revisions_isolated(
        "(i0[t] = 0).", ["always (o1[t] = i1[t])."]
    )
    assert err == "Tau staging compile error: engine did not route revision (o0=T)"
