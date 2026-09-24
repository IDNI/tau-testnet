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

    def _ensure_consensus(self, consensus_rules: str):
        """A session holding the CONSENSUS rules, applied the way the authority
        applies them: the program router, then the rules as a revision.

        Not seeded from the in-process interpreter's spec text. That text is the
        spec as the engine REVISED it, and revision encodes the previous state
        with `[t-1]` references: an interpreter built fresh from it answers
        o7 = 0 at its first step -- measured: the first eligibility query after
        every rule change said "not our turn". o6 and o7 are defined by the
        consensus rules alone (user rules may not write them), so nothing else
        belongs in this session.
        """
        import tau_speculation

        unit = _normalize_consensus(consensus_rules)
        fingerprint = _spec_fingerprint("consensus\x00" + unit)
        if self._session is not None and self._fingerprint == fingerprint:
            return self._session
        self.dispose()
        import tau_authority
        baseline = tau_authority.program_baseline()
        if not baseline or not unit:
            raise tau_speculation.SpeculationError("no consensus rules to evaluate")
        env = dict(self._env or os.environ)
        env.setdefault("PYTHONPATH", "")
        if self._cwd not in env["PYTHONPATH"].split(os.pathsep):
            env["PYTHONPATH"] = self._cwd + os.pathsep + env["PYTHONPATH"]
        session = tau_speculation.SpeculationSession(cwd=self._cwd, env=env)
        try:
            session.init(baseline)
            receipt = session.revise(unit, "consensus")
            if not receipt.accepted:
                raise tau_speculation.SpeculationError(
                    f"consensus rules not accepted: {receipt.get('outcome')}")
        except BaseException:
            session.kill()
            raise
        self._session = session
        self._fingerprint = fingerprint
        return session

    def evaluate_consensus(self, consensus_rules: str, inputs: dict, targets):
        """o6/o7 (or any consensus output) for one step, or None."""
        self._trace("evaluate_consensus", inputs, targets)
        try:
            session = self._ensure_consensus(consensus_rules)
            result = session.step(self._named(inputs))
            outputs = result.get("outputs") or {}
            return {t: outputs.get(f"o{t}") for t in targets}
        except Exception as exc:
            logger.warning("advisory consensus evaluation unavailable: %s", exc)
            self.dispose()
            return None

    def dispose(self) -> None:
        if self._session is not None:
            try:
                self._session.kill()
            except Exception:
                pass
        self._session = None
        self._fingerprint = None

    # --- queries --------------------------------------------------------------

    @staticmethod
    def _trace(kind, inputs, targets):
        """Advisory work reaches the OPERATIONAL TRACE and nothing else.

        Recording it in the committed journal would put it on the authoritative
        replay path, which is how the contamination this evaluator exists to
        remove would come back: replaying an advisory step reproduces its effect
        on the next transaction's history rather than eliminating it.
        """
        try:
            import tau_journal
            tau_journal.trace().record(
                tau_journal.PHASE_ADVISORY,
                {"kind": kind, "streams": sorted(str(k) for k in (inputs or {})),
                 "targets": list(targets)},
            )
        except Exception:
            pass

    def evaluate_many(self, canonical_spec: str, inputs: dict, targets):
        """Answer several advisory questions from ONE step, or None.

        One step, because asking twice would advance this evaluator between the
        two answers and they are meant to describe the same moment.
        """
        self._trace("evaluate_many", inputs, targets)
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
        self._trace("evaluate", inputs, (target,))
        try:
            session = self._ensure(canonical_spec)
            result = session.step(self._named(inputs))
            outputs = result.get("outputs") or {}
            return outputs.get(f"o{target}")
        except Exception as exc:
            logger.warning("advisory evaluation unavailable: %s", exc)
            self.dispose()
            return None


def _normalize_consensus(consensus_rules: str) -> str:
    """The consensus rules as the authority's restore plan feeds them."""
    try:
        import chain_state
        return chain_state._preprocess_tau_spec_text(consensus_rules or "").strip()
    except Exception:
        return (consensus_rules or "").strip()


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
