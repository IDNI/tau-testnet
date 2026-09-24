"""Admission preflight: validate what apply will actually feed the engine (W8).

The asymmetry this closes. `sendtx` validated a rule by compiling the CANONICAL
full-width text in a fresh subprocess seeded from the committed accumulation. A
fresh process has no type commitments and does no shrinking, so the text always
compiled and the transaction was admitted. Apply then ran in the live process,
where the shrink layer rewrote the rule and the engine had already typed its
streams -- and refused it. `{"ok": true}` followed by silence, every time.

So the preflight prepares the rule the way apply will, and validates THAT text in
an isolated one-shot worker. Canonical validation and shrunk-runtime validation
must not share a process: separate interpreter objects do not escape process-global
typing, and the second stepped interpreter wedges the first.

The guarantee is deliberately narrow, and is what the result says:

    preflight succeeded for the captured context;
    apply revalidates against its actual ordered execution context.

A context change produces revalidation or a bounded retry, never a promise that
admission and apply are identical.
"""
from __future__ import annotations

import logging

import tau_speculation

logger = logging.getLogger(__name__)

# What the caller should do, kept separate from WHY.
ADMIT = "ADMIT"
REJECT = "REJECT"
UNAVAILABLE = "UNAVAILABLE"


class PreflightResult:
    def __init__(self, verdict, *, outcome=None, detail="", context=None, receipt=None):
        self.verdict = verdict
        self.outcome = outcome
        self.detail = detail
        self.context = context or {}
        self.receipt = receipt

    @property
    def ok(self) -> bool:
        return self.verdict == ADMIT

    def __repr__(self) -> str:
        return f"PreflightResult({self.verdict}, outcome={self.outcome!r})"


def capture_context(evaluator_state=None, mapping_epoch=None) -> dict:
    """The context a preflight answer is scoped to.

    An interface generation alone is not enough: execution advances without the
    interface being replaced, and the encoding depends on the mapping epoch.
    """
    context = {"generation": None, "state_revision": None, "mapping_epoch": mapping_epoch}
    if evaluator_state is not None:
        snap = evaluator_state.snapshot()
        context["generation"] = snap.get("generation")
        context["state_revision"] = snap.get("state_revision")
        context["interned"] = snap.get("interned")
    return context


def context_changed(before: dict, after: dict) -> bool:
    keys = ("generation", "state_revision", "mapping_epoch")
    return any(before.get(k) != after.get(k) for k in keys)


def preflight_rule(baseline_spec: str, runtime_rule_text: str, *, context=None,
                   cwd=None, env=None, timeout: float = 120.0,
                   worker=None) -> PreflightResult:
    """Validate the PREPARED rule text against a baseline, in a fresh process.

    `runtime_rule_text` is what apply will feed -- already shrunk, if the node's
    encoding says so. `baseline_spec` must be in the same representation.
    """
    try:
        receipt = tau_speculation.validate_once(
            baseline_spec, runtime_rule_text, cwd=cwd, env=env,
            timeout=timeout, worker=worker,
        )
    except tau_speculation.SpeculationError as exc:
        # The worker could not answer. Operational: never a verdict about a rule.
        logger.warning("rule preflight unavailable: %s", exc)
        return PreflightResult(UNAVAILABLE, detail=str(exc), context=context)

    outcome = receipt.get("outcome")
    if outcome in (tau_speculation.ACCEPTED_CHANGED, tau_speculation.ACCEPTED_NOOP):
        if not receipt.get("capture_complete", False):
            # Acceptance that depends on diagnostics nobody could read is not
            # acceptance. Fail closed as operational, not as a rejection.
            return PreflightResult(
                UNAVAILABLE, outcome=outcome, receipt=receipt, context=context,
                detail="diagnostic capture was incomplete",
            )
        return PreflightResult(ADMIT, outcome=outcome, receipt=receipt, context=context)

    if outcome == "REJECTED_RULE":
        # Deterministic: the engine refused this text. Every node refuses it.
        return PreflightResult(
            REJECT, outcome=outcome, receipt=receipt, context=context,
            detail=_first_error(receipt) or "the engine refused the rule text",
        )

    # REJECTED_NOT_ROUTED and INCOMPLETE are NOT treated as rule rejections here.
    # An unsatisfiable rule is evaluated into the no-revision branch rather than
    # refused, and "the engine never asked for i0" says nothing about the
    # candidate. Both were admissible before this preflight existed; narrowing
    # admissibility is a separate decision from closing the asymmetry.
    logger.info("rule preflight inconclusive (%s); admitting as before", outcome)
    return PreflightResult(ADMIT, outcome=outcome, receipt=receipt, context=context,
                           detail="inconclusive; apply revalidates")


def _first_error(receipt) -> str:
    for key in ("diagnostics", "deferred_diagnostics"):
        text = receipt.get(key) or ""
        for line in text.splitlines():
            if "Error" in line:
                return line.strip()
    return ""
