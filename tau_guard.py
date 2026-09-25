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

Proposal execution installs a guard itself, so protection is not something a
caller can forget to switch on. Callers legitimately wrap that in one of their
own, which is why the trap is shared rather than nested: the patching happens
once, and EVERY active guard sees every call. A lax outer guard therefore cannot
relax the strict one proposal mode installs inside it, and a strict outer guard
still raises for calls made under a lax inner one.

A guard watches only the thread that entered it. The traps are process-wide
(they are module attributes), but a node serves RPC, gossip and the miner on
other threads while a block executes, and those threads legitimately read
committed state -- a `sendtx` admission reading a live balance is not a
proposal leak. Watching them turned every overlapping `sendtx`/`getbalance`
into a `GlobalStateLeak` that killed the client thread mid-request.
"""
from __future__ import annotations

import logging
import threading

logger = logging.getLogger(__name__)

#: Guards currently active in this process, outermost first. The traps are
#: installed by whoever pushes the first entry and removed by whoever pops the
#: last, so the module attributes are patched exactly once no matter how the
#: guards nest.
_STACK: list = []
_STACK_LOCK = threading.Lock()


class GlobalStateLeak(BaseException):
    """Proposal execution touched committed state.

    A programming error, not a transaction verdict and not an operational
    condition: the proposal was about to be evaluated against something it does
    not own.

    Deliberately NOT an `Exception`. The apply path is full of broad
    `except Exception` handlers that turn a failure into a rejected transaction,
    and every one of them would convert an isolation breach into "that
    transaction was invalid" -- the most misleading possible outcome, because the
    transaction was fine and the node was not. Measured: routed through
    `Exception` this was swallowed at the rule handler and reported as
    `rule_not_applied`. Inheriting from BaseException means no existing catch,
    and no catch added later without thinking about it, can absorb it. Catch it
    by name where aborting the proposal is genuinely the intent.
    """


#: (module path, attribute, why). Committed-state MUTATION.
FORBIDDEN_WRITES = (
    ("chain_state", "save_effective_tau_spec", "canonical application rules"),
    ("chain_state", "save_application_rules_state", "canonical application rules"),
    ("chain_state", "commit_state_to_db", "canonical state"),
    ("chain_state", "save_consensus_rules_state", "canonical consensus rules"),
    ("chain_state", "increment_sequence_number", "canonical sequence numbers"),
    ("db", "get_shrink_id", "committed allocator (inserts and commits)"),
    ("db", "publish_shrink_ids", "committed allocator publication"),
    ("db", "add_block", "committed chain"),
    ("db", "set_chain_state_value", "committed chain state"),
)

#: Reads of MUTABLE canonical state. A proposal owns its own copy of each.
#:
#: As aggressive as the write list on purpose. A proposal that writes only to
#: private state but reads a live balance instead of its captured parent's is
#: not corrupting anything -- it is evaluating a block against a state that
#: never existed, which is worse, because it looks fine. `get_tau_restore_plan`
#: is deliberately absent: it is read to BUILD a proposal, before the proposal
#: is running.
FORBIDDEN_READS = (
    ("chain_state", "get_application_rules_state", "application rules"),
    ("chain_state", "get_consensus_rules_state", "consensus rules"),
    ("chain_state", "get_balance", "balances"),
    ("chain_state", "get_committed_balance", "balances"),
    ("chain_state", "get_sequence_number", "sequence numbers"),
    ("chain_state", "get_rules_state", "rules state"),
    ("chain_state", "get_persisted_full_tau_spec", "the committed spec"),
    ("tau_manager", "get_canonical_spec", "the authoritative spec"),
)

#: The authoritative evaluator. A proposal drives its own worker.
FORBIDDEN_EVALUATION = (
    ("tau_manager", "communicate_with_tau", "authoritative Tau step"),
    ("tau_manager", "communicate_with_tau_multi", "authoritative Tau step"),
    ("tau_manager", "restore_full_tau_spec", "authoritative interpreter"),
)

#: Every trappable target, so the shared installer patches one fixed set. An
#: individual guard decides which of them it WATCHES; it never decides which are
#: patched, because a second guard entering later would otherwise need to patch
#: more while the first is running.
ALL_TARGETS = (
    tuple((m, a, w, "write") for m, a, w in FORBIDDEN_WRITES)
    + tuple((m, a, w, "read") for m, a, w in FORBIDDEN_READS)
    + tuple((m, a, w, "evaluation") for m, a, w in FORBIDDEN_EVALUATION)
)

_SAVED: list = []


def _install() -> None:
    import importlib
    for module_name, attribute, why, kind in ALL_TARGETS:
        try:
            module = importlib.import_module(module_name)
        except Exception:
            continue
        original = getattr(module, attribute, None)
        if original is None:
            continue
        _SAVED.append((module, attribute, original))
        setattr(module, attribute, _trap(module_name, attribute, why, kind, original))


def _uninstall() -> None:
    for module, attribute, original in reversed(_SAVED):
        setattr(module, attribute, original)
    _SAVED.clear()


def _trap(module_name, attribute, why, kind, original):
    where = f"{module_name}.{attribute}"

    def trapped(*args, **kwargs):
        me = threading.get_ident()
        watching = [g for g in list(_STACK) if g.thread == me and g.watches(where, kind)]
        if not watching:
            return original(*args, **kwargs)
        message = (
            f"proposal execution touched committed state: {where} "
            f"({kind}, {why}). A proposal owns its own copy; reaching the "
            "committed one means it is no longer evaluating the state it was "
            "built from."
        )
        for guard in watching:
            guard.violations.append({"call": where, "kind": kind, "why": why})
        # Strictness is a property of each guard, and the strictest active guard
        # decides. Otherwise wrapping a strict proposal in a lax observer would
        # silently turn an integration failure back into a logged warning.
        if any(g.strict for g in watching):
            raise GlobalStateLeak(message)
        logger.error(message)
        return original(*args, **kwargs)

    trapped.__name__ = f"guarded_{attribute}"
    trapped.__wrapped__ = original
    return trapped


class ProposalIsolationGuard:
    """Fail loudly when proposal execution reaches committed state.

    `strict` raises at the call site, which is where the fallback is visible;
    otherwise violations are recorded for a caller to assert on.
    """

    def __init__(self, *, strict: bool = True, writes=True, reads=True,
                 evaluation=True, allow=(), label="proposal"):
        self.strict = strict
        self.label = label
        self.violations: list = []
        self.thread = None
        self._allow = set(allow)
        self._kinds = set()
        if writes:
            self._kinds.add("write")
        if reads:
            self._kinds.add("read")
        if evaluation:
            self._kinds.add("evaluation")

    def watches(self, where: str, kind: str) -> bool:
        return kind in self._kinds and where not in self._allow

    def __enter__(self) -> "ProposalIsolationGuard":
        self.thread = threading.get_ident()
        with _STACK_LOCK:
            if not _STACK:
                _install()
            _STACK.append(self)
        return self

    def __exit__(self, *exc):
        with _STACK_LOCK:
            try:
                _STACK.remove(self)
            except ValueError:
                pass
            if not _STACK:
                _uninstall()
        return False

    # --- reporting ------------------------------------------------------------

    def calls(self) -> list:
        return [v["call"] for v in self.violations]

    def assert_clean(self) -> None:
        if self.violations:
            raise AssertionError(
                "proposal execution touched committed state: "
                + ", ".join(sorted({v["call"] for v in self.violations}))
            )
