from __future__ import annotations

import re
from dataclasses import dataclass

import tau_native


@dataclass(frozen=True)
class _FakeStreamAt:
    name: str
    time_point: int


class _FakeInterpreter:
    def __init__(self, spec: str):
        self.spec = spec
        self.time_point = 0
        self.input_names = self._extract_input_names(spec)

    @staticmethod
    def _extract_input_names(spec: str) -> set[str]:
        names = {"i0"}
        for match in re.findall(r"\bi(\d+)\[", spec or ""):
            names.add(f"i{int(match)}")
        return names


class _FakeTauModule:
    def __init__(self):
        self.last_assigned_inputs: dict[str, str] = {}

    def get_interpreter(self, spec: str):
        return _FakeInterpreter(spec)

    def get_inputs_for_step(self, interpreter: _FakeInterpreter):
        def _sort_key(name: str) -> int:
            return int(name[1:]) if name.startswith("i") and name[1:].isdigit() else 0

        return [
            _FakeStreamAt(name=n, time_point=interpreter.time_point)
            for n in sorted(interpreter.input_names, key=_sort_key)
        ]

    def step(self, interpreter: _FakeInterpreter, inputs: dict[_FakeStreamAt, str]):
        assigned: dict[str, str] = {}
        for stream_at, value in inputs.items():
            if stream_at.name not in interpreter.input_names:
                print(f"(Error) Input stream {stream_at.name} not found in context")
                return None
            assigned[stream_at.name] = str(value)
        self.last_assigned_inputs = assigned

        i0_value = assigned.get("i0")
        if i0_value and i0_value not in {"F", "0"}:
            lhs = interpreter.spec.rstrip(".")
            rhs = i0_value.rstrip(".")
            updated = f"{lhs} && {rhs}."
            print(f"Updated specification: {updated}")
            interpreter.spec = updated
            interpreter.input_names = interpreter._extract_input_names(updated)

        outputs = {
            _FakeStreamAt(name="o0", time_point=interpreter.time_point): "F",
            _FakeStreamAt(name="o1", time_point=interpreter.time_point): assigned.get("i1", "0"),
        }
        interpreter.time_point += 1
        return outputs


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


def test_rebuilds_interpreter_after_spec_update(tmp_path, monkeypatch):
    fake_tau = _FakeTauModule()
    monkeypatch.setattr(tau_native, "tau", fake_tau)
    iface = tau_native.TauInterface(str(_make_genesis_file(tmp_path)))

    iface.communicate(
        rule_text="always (o1[t] = i1[t]).",
        target_output_stream_index=0,
        input_stream_values=None,
    )
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
