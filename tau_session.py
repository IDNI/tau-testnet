"""One evaluator session, and an exact record of what was fed to it.

Why a session type exists at all: the apply path calls `tau_manager` directly,
which hardwires it to ONE evaluator -- the live in-process interpreter. Speculative
apply needs the same code to drive a disposable worker instead, and the engine
offers no rollback, so the choice of evaluator has to be a parameter rather than a
module-level fact.

Why the step log exists: reconstruction from specification text loses temporal
state (measured: a rebuild comes back at `time_point=0` with the history gone), so
a fresh worker is brought to a given state by REPLAYING what was fed. Replay was
then measured to be faithful -- a replayed session matches a live one including
`i1[t-1]`/`i1[t-3]` depth, reproduces type commitments, and clears a discarded
candidate's residue -- but only if the log is exact. Filler steps advance logical
time and belong in it.

This module changes no behaviour on its own: `InProcessSession` is exactly what the
engine did before, with the calls named and recorded.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

RULE = "rule"
EVAL = "eval"


@dataclass
class StepRecord:
    """One thing fed to the evaluator, in the order it was fed."""

    kind: str                      # RULE | EVAL
    rule_text: str | None = None
    inputs: dict = field(default_factory=dict)
    target: int | None = None
    outcome: str | None = None     # the revision outcome, for RULE entries

    def replayable(self) -> dict:
        """The payload a replay would re-feed. Deliberately not the outputs: a
        replay must RE-DERIVE those, not assume them."""
        return {"kind": self.kind, "rule_text": self.rule_text,
                "inputs": dict(self.inputs), "target": self.target}


class StepLog:
    """An ordered record since the last commit anchor.

    Reset at each commit, because promotion makes the evaluating worker the
    serving one -- so the log only ever has to cover the block being built.
    """

    def __init__(self, anchor: str | None = None):
        self.anchor = anchor
        self._entries: list = []

    def record(self, entry: StepRecord) -> None:
        self._entries.append(entry)

    def entries(self) -> list:
        return list(self._entries)

    def replay_trace(self) -> list:
        return [e.replayable() for e in self._entries]

    def reset(self, anchor: str | None = None) -> None:
        self.anchor = anchor
        self._entries = []

    def __len__(self) -> int:
        return len(self._entries)


class EvaluatorSession:
    """What the apply path needs from an evaluator."""

    def ready(self, timeout: float = 5.0) -> bool:
        raise NotImplementedError

    def apply_rule(self, rule_text: str, *, target: int = 0):
        raise NotImplementedError

    def evaluate(self, inputs: dict, *, target=None, source: str = "unknown"):
        raise NotImplementedError

    def last_receipt(self):
        raise NotImplementedError


class InProcessSession(EvaluatorSession):
    """The live interpreter, driven exactly as the engine drove it before.

    Every dispatch is appended to the step log, so a worker can be brought to this
    state by replay. Advisory reads pass `record=False`: an unrecorded step would
    desync a later replay, so anything that must NOT be part of the history says so
    explicitly rather than by accident.
    """

    def __init__(self, manager=None, log: StepLog | None = None):
        if manager is None:
            import tau_manager as manager  # late: chain_state imports this module
        self._manager = manager
        self.log = log if log is not None else StepLog()

    # --- readiness ------------------------------------------------------------

    def ready(self, timeout: float = 5.0) -> bool:
        ready_flag = self._manager.tau_ready
        if not ready_flag.is_set():
            ready_flag.wait(timeout=timeout)
        return ready_flag.is_set()

    # --- dispatch -------------------------------------------------------------

    def apply_rule(self, rule_text: str, *, target: int = 0, record: bool = True):
        output = self._manager.communicate_with_tau(
            rule_text=rule_text,
            target_output_stream_index=target,
            apply_rules_update=True,
        )
        receipt = self._manager.get_last_revision_receipt()
        if record:
            self.log.record(StepRecord(
                kind=RULE, rule_text=rule_text, target=target,
                outcome=(receipt or {}).get("outcome"),
            ))
        return output

    def evaluate(self, inputs: dict, *, target=None, source: str = "unknown",
                 multi: bool = False, apply_rules_update: bool = False,
                 record: bool = True):
        if multi:
            out = self._manager.communicate_with_tau_multi(
                input_stream_values=inputs, source=source,
                apply_rules_update=apply_rules_update,
            )
        else:
            out = self._manager.communicate_with_tau(
                input_stream_values=inputs, target_output_stream_index=target,
                source=source, apply_rules_update=apply_rules_update,
            )
        if record:
            self.log.record(StepRecord(kind=EVAL, inputs=dict(inputs or {}),
                                       target=target))
        return out

    def last_receipt(self):
        return self._manager.get_last_revision_receipt()


_default_session = None


def default_session() -> InProcessSession:
    """The session the node uses when no other is supplied."""
    global _default_session
    if _default_session is None:
        _default_session = InProcessSession()
    return _default_session


def set_default_session(session) -> None:
    global _default_session
    _default_session = session


def reset_default_session() -> None:
    global _default_session
    _default_session = None
