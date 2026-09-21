"""Make proposal execution incapable of reaching committed state.

Not "try not to call those paths" -- the leak this prevents is the convenience
fallback, and a fallback is by definition what happens when nobody was thinking
about it. Two classes, both covered:

* WRITE leaks are obvious: a proposal persists something and is then rejected.
* READ leaks are subtler and just as wrong: a proposal built from parent H reads
  mutable canonical state directly, some other path changes it, and the proposal
  no longer represents H. Nothing is corrupted; the block was simply evaluated
  against a state that never existed.

Static configuration and pure parsing helpers are fine. What is forbidden is
committed state -- the mapping, the journal, the canonical rules, the store, and
the authoritative evaluator.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


class GlobalStateLeak(RuntimeError):
    """Proposal execution touched committed state.

    A programming error, not a transaction verdict and not an operational
    condition: the proposal was about to be evaluated against something it does
    not own.
    """


#: (module path, attribute, why). Committed-state MUTATION.
FORBIDDEN_WRITES = (
    ("chain_state", "save_effective_tau_spec", "canonical application rules"),
    ("chain_state", "save_application_rules_state", "canonical application rules"),
    ("chain_state", "commit_state_to_db", "canonical state"),
    ("db", "get_shrink_id", "committed allocator (inserts and commits)"),
    ("db", "publish_shrink_ids", "committed allocator publication"),
    ("db", "add_block", "committed chain"),
    ("db", "set_chain_state_value", "committed chain state"),
)

#: Reads of MUTABLE canonical state. A proposal owns its own copy of each.
FORBIDDEN_READS = (
    ("chain_state", "get_application_rules_state", "application rules"),
    ("chain_state", "get_committed_balance", "balances"),
    ("chain_state", "get_rules_state", "rules state"),
)

#: The authoritative evaluator. A proposal drives its own worker.
FORBIDDEN_EVALUATION = (
    ("tau_manager", "communicate_with_tau", "authoritative Tau step"),
    ("tau_manager", "communicate_with_tau_multi", "authoritative Tau step"),
    ("tau_manager", "restore_full_tau_spec", "authoritative interpreter"),
)


class ProposalIsolationGuard:
    """Fail loudly when proposal execution reaches committed state.

    `strict` raises at the call site, which is where the fallback is visible;
    otherwise violations are recorded for a caller to assert on.
    """

    def __init__(self, *, strict: bool = True, writes=True, reads=True,
                 evaluation=True, allow=()):
        self.strict = strict
        self.violations: list = []
        self._allow = set(allow)
        self._targets = []
        if writes:
            self._targets += [(m, a, w, "write") for m, a, w in FORBIDDEN_WRITES]
        if reads:
            self._targets += [(m, a, w, "read") for m, a, w in FORBIDDEN_READS]
        if evaluation:
            self._targets += [(m, a, w, "evaluation") for m, a, w in FORBIDDEN_EVALUATION]
        self._saved = []

    def __enter__(self) -> "ProposalIsolationGuard":
        import importlib
        for module_name, attribute, why, kind in self._targets:
            if f"{module_name}.{attribute}" in self._allow:
                continue
            try:
                module = importlib.import_module(module_name)
            except Exception:
                continue
            original = getattr(module, attribute, None)
            if original is None:
                continue
            self._saved.append((module, attribute, original))
            setattr(module, attribute, self._trap(module_name, attribute, why, kind,
                                                  original))
        return self

    def __exit__(self, *exc):
        for module, attribute, original in reversed(self._saved):
            setattr(module, attribute, original)
        self._saved = []
        return False

    def _trap(self, module_name, attribute, why, kind, original):
        def trapped(*args, **kwargs):
            where = f"{module_name}.{attribute}"
            self.violations.append({"call": where, "kind": kind, "why": why})
            message = (
                f"proposal execution touched committed state: {where} "
                f"({kind}, {why}). A proposal owns its own copy; reaching the "
                "committed one means it is no longer evaluating the state it was "
                "built from."
            )
            if self.strict:
                raise GlobalStateLeak(message)
            logger.error(message)
            return original(*args, **kwargs)
        trapped.__name__ = f"guarded_{attribute}"
        trapped.__wrapped__ = original
        return trapped

    # --- reporting ------------------------------------------------------------

    def calls(self) -> list:
        return [v["call"] for v in self.violations]

    def assert_clean(self) -> None:
        if self.violations:
            raise AssertionError(
                "proposal execution touched committed state: "
                + ", ".join(sorted({v["call"] for v in self.violations}))
            )
