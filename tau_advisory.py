"""Advisory evaluation, isolated from the authoritative evaluator.

Measured contamination this exists to remove. With a history-dependent policy
(`o5[t] = i1[t-1]`), inserting ONE advisory query between two authoritative
inputs changes the next verdict from 5 to 255 -- the advisory request's own input
leaks into the following transaction's view of the previous one. Eligibility is
queried every mining round and admission estimates fees per submission, so on a
live node this is continuous.

Logging those requests does not fix it. Replaying the log reproduces the
contamination faithfully; what has to change is that advisory work never runs on
the evaluator whose history is authoritative.

Representation: the advisory evaluator runs entirely in CANONICAL form -- the
full-width spec, full-width inputs, no interning. That is slower per step and
removes a whole class of failure: it has no mapping epoch, pins no widths that
matter, and cannot disagree with the authoritative encoding because it shares
nothing with it. Its answers are advisory by contract; the authoritative path
revalidates.
"""
from __future__ import annotations

import hashlib
import logging
import os

logger = logging.getLogger(__name__)

_evaluator = None


def _spec_fingerprint(spec_text: str) -> str:
    return hashlib.sha256((spec_text or "").encode("utf-8")).hexdigest()


class AdvisoryEvaluator:
    """A worker seeded from canonical state, refreshed when that state changes."""

    def __init__(self, *, cwd=None, env=None):
        self._cwd = cwd or os.getcwd()
        self._env = env
        self._session = None
        self._fingerprint = None

    # --- lifecycle ------------------------------------------------------------

    def _ensure(self, canonical_spec: str):
        import tau_speculation

        fingerprint = _spec_fingerprint(canonical_spec)
        if self._session is not None and self._fingerprint == fingerprint:
            return self._session
        self.dispose()
        env = dict(self._env or os.environ)
        env.setdefault("PYTHONPATH", "")
        if self._cwd not in env["PYTHONPATH"].split(os.pathsep):
            env["PYTHONPATH"] = self._cwd + os.pathsep + env["PYTHONPATH"]
        session = tau_speculation.SpeculationSession(cwd=self._cwd, env=env)
        session.init(canonical_spec)
        self._session = session
        self._fingerprint = fingerprint
        return session

    def dispose(self) -> None:
        if self._session is not None:
            try:
                self._session.kill()
            except Exception:
                pass
        self._session = None
        self._fingerprint = None

    # --- queries --------------------------------------------------------------

    def evaluate_many(self, canonical_spec: str, inputs: dict, targets):
        """Answer several advisory questions from ONE step, or None.

        One step, because asking twice would advance this evaluator between the
        two answers and they are meant to describe the same moment.
        """
        try:
            session = self._ensure(canonical_spec)
            result = session.step(self._named(inputs))
            outputs = result.get("outputs") or {}
            return {t: outputs.get(f"o{t}") for t in targets}
        except Exception as exc:
            logger.warning("advisory evaluation unavailable: %s", exc)
            self.dispose()
            return None

    @staticmethod
    def _named(inputs: dict) -> dict:
        named = {}
        for key, value in (inputs or {}).items():
            name = key if isinstance(key, str) and key.startswith("i") else f"i{key}"
            named[name] = "" if value is None else str(value)
        return named

    def evaluate(self, canonical_spec: str, inputs: dict, target: int):
        """Answer one advisory question. Returns the target stream's value or None.

        Never raises into the caller: an advisory answer that cannot be produced
        is None, which callers already treat as "no opinion". It must not be able
        to take down mining or admission.
        """
        try:
            session = self._ensure(canonical_spec)
            result = session.step(self._named(inputs))
            outputs = result.get("outputs") or {}
            return outputs.get(f"o{target}")
        except Exception as exc:
            logger.warning("advisory evaluation unavailable: %s", exc)
            self.dispose()
            return None


def evaluator(*, cwd=None, env=None) -> AdvisoryEvaluator:
    global _evaluator
    if _evaluator is None:
        _evaluator = AdvisoryEvaluator(cwd=cwd, env=env)
    return _evaluator


def reset() -> None:
    global _evaluator
    if _evaluator is not None:
        _evaluator.dispose()
    _evaluator = None
