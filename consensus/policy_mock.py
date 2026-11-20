"""In-process stand-in for the policy evaluator: no subprocess, no engine."""
from __future__ import annotations

from typing import Any, Callable, Optional

from tau_policy import (
    PolicyBuild,
    PolicyBuildError,
    PolicyOutputs,
    PolicyStepError,
    PolicyVerdict,
    parse_o5,
)


class MockPolicyEvaluator:
    """Deterministic evaluator for tests. A verdict comes from `decide(body,
    inputs)`, which returns an o5 value or None (absent, so allowed)."""

    def __init__(self, decide: Optional[Callable[[str, dict], Any]] = None,
                 pool: str = "apply") -> None:
        self.pool = pool
        self._decide = decide or (lambda body, inputs: None)
        self._failing: dict = {}
        self._refused: dict = {}
        self._by_body: dict = {}
        self._outputs_by_body: dict = {}
        self.validate_calls: list = []
        self.verdict_calls: list = []
        self.outputs_calls: list = []
        self.closed = False

    def fail_build(self, body: str, error: str = "mock build failure") -> None:
        self._failing[body] = error

    def fail_step(self, body: str, error: str = "mock step failure") -> None:
        """The clause builds but the engine refuses to step it."""
        self._refused[body] = error

    def set_verdict(self, body: str, decide) -> None:
        """`decide` is a constant o5 value (or None) or a callable (inputs) -> o5."""
        self._by_body[body] = decide

    def set_outputs(self, body: str, decide) -> None:
        """`decide` is a dict of output values or a callable (inputs) -> dict,
        served by outputs() for this body (mirrors the real worker returning
        every stream the clause wrote)."""
        self._outputs_by_body[body] = decide

    def validate(self, body: str, *, timeout=None) -> PolicyBuild:
        self.validate_calls.append(body)
        error = self._build_error(body)
        if error:
            return PolicyBuild(ok=False, error=error)
        return PolicyBuild(ok=True, built=True)

    def verdict(self, body: str, inputs: dict, *, timeout=None) -> PolicyVerdict:
        self.verdict_calls.append((body, dict(inputs or {})))
        error = self._build_error(body)
        if error:
            raise PolicyBuildError(error)
        if body in self._refused:
            raise PolicyStepError(self._refused[body])
        rule = self._by_body.get(body, self._decide)
        if callable(rule):
            value = rule(inputs) if body in self._by_body else rule(body, inputs)
        else:
            value = rule
        o5 = None if value is None else str(value)
        return PolicyVerdict(blocked=parse_o5(o5) == 0, o5=o5, built=True)

    def outputs(self, body: str, inputs: dict, *, timeout=None) -> PolicyOutputs:
        """The mock's outputs(): same build/step failure discipline as
        verdict(). Without a set_outputs hook for the body, the outputs are
        whatever the verdict path decided ({"o5": ...} or {})."""
        self.outputs_calls.append((body, dict(inputs or {})))
        error = self._build_error(body)
        if error:
            raise PolicyBuildError(error)
        if body in self._refused:
            raise PolicyStepError(self._refused[body])
        if body in self._outputs_by_body:
            rule = self._outputs_by_body[body]
            produced = rule(inputs) if callable(rule) else rule
            return PolicyOutputs(
                outputs={str(k): str(v) for k, v in dict(produced or {}).items()},
                built=True)
        verdict = self.verdict(body, inputs)
        return PolicyOutputs(
            outputs={} if verdict.o5 is None else {"o5": verdict.o5},
            built=True)

    def stats(self) -> dict:
        return {"pool": self.pool, "builds": len(self.validate_calls),
                "steps": len(self.verdict_calls), "spawns": 0, "recycles": 0,
                "retries": 0, "fresh_fallbacks": 0}

    def close(self) -> None:
        self.closed = True

    def _build_error(self, body: str) -> str:
        if not body:
            return "empty clause body"
        return self._failing.get(body, "")
