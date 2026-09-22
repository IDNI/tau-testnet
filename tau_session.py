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

import tau_journal

logger = logging.getLogger(__name__)

# One vocabulary, deliberately. These used to be separate string literals from
# the journal's, and a reconstruction compared a journal entry's kind against
# this module's -- replaying every recorded revision as an input step, so the
# rebuilt evaluator applied no rules at all and still looked like it worked.
RULE = tau_journal.REVISION
EVAL = tau_journal.STEP


def _shrink_width():
    import tau_shrink
    return tau_shrink.current_shrink_width()

#: Revision outcomes that mean the engine took the candidate.
_ACCEPTED = ("ACCEPTED_CHANGED", "ACCEPTED_NOOP")


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

    #: A speculative session evaluates without committing anything: its rule
    #: applications do not reach the canonical persistence handler, so the apply
    #: path must not demand evidence of persistence from it.
    is_speculative = False

    def ready(self, timeout: float = 5.0) -> bool:
        raise NotImplementedError

    def apply_rule(self, rule_text: str, *, target: int = 0,
                   accumulate: bool = True):
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

    def __init__(self, manager=None, log: StepLog | None = None, journal=None,
                 phase=tau_journal.PHASE_APPLY):
        if manager is None:
            import tau_manager as manager  # late: chain_state imports this module
        self._manager = manager
        self.log = log if log is not None else StepLog()
        # The COMMITTED journal by default: this session drives the authoritative
        # evaluator, so what it feeds defines the state a reconstruction has to
        # reproduce. Advisory and validation work does not come through here --
        # it runs on a different evaluator entirely, and only reaches the
        # operational trace.
        self._journal = journal if journal is not None else tau_journal.committed()
        self._phase = phase

    # --- readiness ------------------------------------------------------------

    def ready(self, timeout: float = 5.0) -> bool:
        ready_flag = self._manager.tau_ready
        if not ready_flag.is_set():
            ready_flag.wait(timeout=timeout)
        return ready_flag.is_set()

    # --- dispatch -------------------------------------------------------------

    def apply_rule(self, rule_text: str, *, target: int = 0, record: bool = True,
                   accumulate: bool = True):
        """`accumulate=False` feeds the interpreter without the rules handler.

        That is how a regenerated o5 composite is applied: it changes the
        evaluator but is not part of the application-rules accumulation, because
        the clause registry is what the restore plan rebuilds it from. It still
        goes in the journal -- an unrecorded revision that changed the evaluator
        is precisely what makes a replay diverge.
        """
        output = self._manager.communicate_with_tau(
            rule_text=rule_text,
            target_output_stream_index=target,
            apply_rules_update=accumulate,
        )
        receipt = self._manager.get_last_revision_receipt()
        outcome = (receipt or {}).get("outcome")
        if record:
            self.log.record(StepRecord(
                kind=RULE, rule_text=rule_text, target=target, outcome=outcome,
            ))
            self._journal.record(
                tau_journal.REVISION, phase=self._phase, rule_text=rule_text,
                target=target, outcome=outcome, result=output,
                accumulate=accumulate,
            )
        else:
            tau_journal.trace().record(self._phase,
                                       {"kind": "revision", "recorded": False})
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
            self._journal.record(tau_journal.STEP, phase=self._phase,
                                 inputs=inputs, target=target, result=out)
        else:
            tau_journal.trace().record(self._phase,
                                       {"kind": "step", "recorded": False})
        return out

    def last_receipt(self):
        return self._manager.get_last_revision_receipt()


class WorkerSession(EvaluatorSession):
    """A session backed by a disposable worker, in CANONICAL representation.

    Speculative evaluation cannot share a process with the authoritative
    evaluator: the engine commits a stream's width on the first accepted revision
    and offers no rollback, so an attempt that is later rejected cannot be undone
    in place. Disposal IS the rollback, which means the attempt has to run
    somewhere disposable.

    Canonical representation, for the same reason the advisory evaluator uses it:
    a worker that interns nothing has no mapping epoch and pins no width that has
    to agree with anybody else's. Slower per step, and a whole class of
    disagreement stops existing.
    """

    is_speculative = True

    def __init__(self, spec_session, log=None, normalize=None, journal=None,
                 allocation=None, plan=None):
        self._spec = spec_session
        self.log = log if log is not None else StepLog()
        self.last_outcome = None
        # A speculative session OWNS its allocation overlay and installs it around
        # every dispatch. Leaving that to the caller is how a speculative path
        # quietly interns into the live table: the session looks isolated, the
        # encoder is not. There is deliberately no "if no context, use the
        # committed allocator" fallback here.
        if allocation is None:
            import tau_allocator
            allocation = tau_allocator.Allocator(
                tau_allocator.DbMappingSnapshot(), width=_shrink_width(),
                label="proposal",
            )
        self.allocation = allocation
        # The representation this session runs under. The session encodes
        # canonical inputs itself: letting a caller supply pre-encoded values
        # alongside canonical rules is exactly how the miner ended up feeding
        # full-width rule literals against interned input values.
        self.plan = plan
        # A proposal journal: accepted speculative execution for the candidate
        # block, adopted into the committed record only if the block commits.
        self.journal = journal if journal is not None else tau_journal.Journal(
            authoritative=False
        )
        # A worker seeded with the RUNTIME (possibly shrunk) spec has to receive
        # runtime-encoded values, or its comparisons silently never match. The
        # caller supplies the same encoder the authoritative path uses; without
        # one the session is canonical end to end.
        self._normalize = normalize

    @classmethod
    def spawn(cls, baseline_spec, *, cwd=None, env=None, trace=None, normalize=None,
              allocation=None, plan=None):
        """Build a worker at `baseline_spec`, replaying `trace` onto it.

        Replay is how a worker reaches a state at all: reconstruction from
        specification text alone was measured to come back with the history gone.
        """
        import os as _os
        import tau_speculation

        cwd = cwd or _os.getcwd()
        env = dict(env or _os.environ)
        env["PYTHONPATH"] = cwd + _os.pathsep + env.get("PYTHONPATH", "")
        spec_session = tau_speculation.SpeculationSession(cwd=cwd, env=env)
        spec_session.init(baseline_spec)
        session = cls(spec_session, normalize=normalize, allocation=allocation,
                      plan=plan)
        for entry in (trace or []):
            if entry.get("kind") == RULE:
                session.apply_rule(entry.get("rule_text") or "")
            else:
                session.evaluate(entry.get("inputs") or {}, target=entry.get("target"))
        return session

    @classmethod
    def reconstruct(cls, baseline_spec, *, journal, plan, snapshot, descriptor=None,
                    cwd=None, env=None, verify=True):
        """Rebuild an authoritative evaluator from ONE anchor.

        Replay runs against a READ-ONLY view of the committed mapping, so a
        canonical value the journal references and the mapping lacks is reported
        as a disagreement between the two anchors rather than quietly allocated.

        Only SEMANTIC fingerprints are compared: a replay under a different
        representation is expected to produce different runtime payloads and the
        same meaning.
        """
        import tau_reconstruction

        replay_alloc = tau_reconstruction.ReplayAllocator(snapshot)
        session = cls.spawn(baseline_spec, cwd=cwd, env=env,
                            allocation=replay_alloc, plan=plan)
        session.descriptor = descriptor
        for entry, (seq, expected) in zip(journal.entries(), journal.fingerprints()):
            payload = entry.replayable()
            # journal kinds, not session kinds: tau_journal.REVISION is
            # "revision" while this module's RULE is "rule", and comparing
            # against the wrong one replays every recorded revision as an input
            # step -- a reconstruction that silently applies no rules at all
            if payload["kind"] == tau_journal.REVISION:
                session.apply_rule(payload["rule_text"], record=False,
                                   accumulate=payload.get("accumulate", True))
                observed = (session.last_outcome or {}).get("outputs")
                outcome = (session.last_outcome or {}).get("outcome")
            else:
                observed = session.evaluate(payload["inputs"], multi=True, record=False)
                outcome = None
            if verify:
                tau_journal.compare(expected, observed, seq=seq, outcome=outcome)
        return session

    def begin_proposal(self, allocation):
        """Leave replay behind: from here new canonical values may be allocated,
        in the proposal's own overlay."""
        self.allocation = allocation
        self.journal = tau_journal.Journal(authoritative=False)
        return self

    def dispose(self):
        try:
            self._spec.kill()
        except Exception:
            pass

    @staticmethod
    def _bare(value):
        """Input VALUES go bare; `{ .. }:bv[N]` is in-spec literal syntax and does
        not parse as an input."""
        text = "" if value is None else str(value).strip()
        if text.startswith("{") and ":bv[" in text and "}" in text:
            return text[1:text.index("}")].strip()
        return text

    def _named_inputs(self, inputs):
        if self.plan is not None:
            inputs = self._encode(inputs)
        elif self._normalize is not None:
            try:
                inputs = self._normalize(inputs)
            except Exception:
                raise
        named = {}
        for key, value in (inputs or {}).items():
            name = key if isinstance(key, str) and key.startswith("i") else f"i{key}"
            named[name] = self._bare(value)
        return named

    def _encode(self, inputs):
        """Canonical values in, runtime values out, under THIS session's plan."""
        import tau_shrink
        encoded = {}
        for key, value in (inputs or {}).items():
            index = key
            if isinstance(key, str):
                index = int(key[1:]) if key.startswith("i") else int(key)
            encoded[key] = tau_shrink.shrink_stream_value(
                value, index, self.plan.interned
            )
        return encoded

    @staticmethod
    def _by_index(outputs):
        indexed = {}
        for name, value in (outputs or {}).items():
            if name.startswith("o") and name[1:].isdigit():
                indexed[int(name[1:])] = str(value)
        return indexed

    def ready(self, timeout=5.0):
        return self._spec is not None

    def _allocating(self):
        import tau_shrink
        return tau_shrink.speculative_allocation(allocator=self.allocation)

    def apply_rule(self, rule_text, *, target=0, record=True, accumulate=True):
        # `accumulate` has no worker-side meaning: a worker owns no rules
        # handler and persists nothing, so every revision it takes is already
        # evaluator-only. Accepted for interface parity and recorded, so the
        # journal says how the authoritative path would have fed it.
        # The rule is PREPARED here, under this session's own overlay. Feeding
        # canonical rule text to a worker whose inputs are runtime-encoded mixes
        # representations: a granted sender's full-width literal never matches its
        # interned input value, and the simulation rejects transfers the
        # authoritative path accepts.
        import tau_shrink
        exclude = self.plan.excludes() if self.plan is not None else frozenset()
        with self._allocating():
            prepared = tau_shrink.prepare_rule(rule_text, exclude_streams=exclude)
            runtime_text = prepared.runtime_text
            receipt = self._spec.revise(runtime_text, "apply")
        self.last_outcome = receipt
        identity = tau_journal.candidate_identity(
            rule_text, mapping_epoch=self.allocation.epoch,
            width=getattr(self.allocation, "width", None), runtime_text=runtime_text,
        )
        outcome = receipt.get("outcome")
        # `accepted` is a property on the receipt, not a key: reading it with
        # .get() silently returns None and turns every acceptance into an error.
        accepted = bool(getattr(receipt, "accepted", False)) or outcome in _ACCEPTED
        if record:
            self.log.record(StepRecord(kind=RULE, rule_text=rule_text, target=target,
                                       outcome=outcome))
            # canonical text in the record, runtime payload only inside the
            # identity: ids are private to an allocation context, so runtime text
            # is not a portable name for anything
            self.journal.record(tau_journal.REVISION,
                                phase=tau_journal.PHASE_SPECULATIVE,
                                rule_text=rule_text, target=target, outcome=outcome,
                                identity=identity, accumulate=accumulate)
        return "ok" if accepted else f"error: {outcome}"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        with self._allocating():
            result = self._spec.step(self._named_inputs(inputs))
        indexed = self._by_index(result.get("outputs") or {})
        if record:
            self.log.record(StepRecord(kind=EVAL, inputs=dict(inputs or {}),
                                       target=target))
            self.journal.record(tau_journal.STEP,
                                phase=tau_journal.PHASE_SPECULATIVE,
                                inputs=inputs, target=target, result=indexed)
        if multi:
            return indexed
        return "" if target is None else indexed.get(target, "")

    def last_receipt(self):
        """A plain dict with an explicit `accepted` KEY.

        The worker's receipt exposes `accepted` as a property, and callers read
        receipts with `.get("accepted")` -- which returns None and makes every
        accepted rule look rejected. Normalizing here keeps that trap in one place
        instead of at every reader.
        """
        receipt = self.last_outcome
        if receipt is None:
            return None
        normalized = dict(receipt)
        normalized["accepted"] = bool(
            getattr(receipt, "accepted", False)
            or normalized.get("outcome") in _ACCEPTED
        )
        return normalized


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
