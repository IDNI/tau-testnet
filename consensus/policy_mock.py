"""In-process stand-in for the policy evaluator: no subprocess, no engine."""
from __future__ import annotations

from typing import Any, Callable, Optional

from tau_policy import PolicyBuild, PolicyBuildError, PolicyVerdict, parse_o5


class MockPolicyEvaluator:
    """Deterministic evaluator for tests. A verdict comes from `decide(body,
    inputs)`, which returns an o5 value or None (absent, so allowed)."""

    def __init__(self, decide: Optional[Callable[[str, dict], Any]] = None,
                 pool: str = "apply") -> None:
        self.pool = pool
        self._decide = decide or (lambda body, inputs: None)
        self._failing: dict = {}
        self._by_body: dict = {}
        self.validate_calls: list = []
        self.verdict_calls: list = []
        self.closed = False

    def fail_build(self, body: str, error: str = "mock build failure") -> None:
        self._failing[body] = error

    def set_verdict(self, body: str, decide) -> None:
        """`decide` is a constant o5 value (or None) or a callable (inputs) -> o5."""
        self._by_body[body] = decide

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
        rule = self._by_body.get(body, self._decide)
        if callable(rule):
            value = rule(inputs) if body in self._by_body else rule(body, inputs)
        else:
            value = rule
        o5 = None if value is None else str(value)
        return PolicyVerdict(blocked=parse_o5(o5) == 0, o5=o5, built=True)

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
