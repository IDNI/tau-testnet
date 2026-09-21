"""Three records, deliberately not one.

    operational trace          every call, for diagnosis. Never replayed.
    committed journal          only execution that DEFINES the authoritative
                               evaluator state. Replayed to reconstruct it.
    proposal journal           accepted speculative execution for the candidate
                               block. Discarded, or rebuilt without a rejected
                               transaction.

Logging everything into one record and replaying it would faithfully reproduce
the contamination that isolation just removed: an advisory fee estimate that
steps the evaluator changes what the next transaction reads, and replaying that
step reproduces the change rather than eliminating it. Membership of the
committed journal is therefore a statement about authority, not about whether a
call happened.

Entries hold CANONICAL logical values. A journal of runtime-encoded values cannot
be replayed at a different width or against a different mapping without
reinterpreting old ids as new values -- the same class of defect as reading a
bare decimal as an interned id.

Each entry also carries a fingerprint of what the original execution produced, so
a reconstruction that diverges is detected instead of quietly continuing from a
state nobody checked.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict

REVISION = "revision"
STEP = "step"

# Why an entry is authoritative -- or why it is not.
PHASE_APPLY = "apply"                 # committed block execution
PHASE_GOVERNANCE = "governance"       # activated consensus revision
PHASE_RESTORE = "restore"             # reconstruction replay
PHASE_ADVISORY = "advisory"           # never authoritative
PHASE_VALIDATION = "validation"       # never authoritative
PHASE_SPECULATIVE = "speculative"     # proposal only

AUTHORITATIVE_PHASES = frozenset({PHASE_APPLY, PHASE_GOVERNANCE, PHASE_RESTORE})


def canonical_stream_key(key) -> str:
    """Stream identity as a name, e.g. `i12`.

    Keys are normalized on the way IN so the record survives serialization: JSON
    turns an integer key into a string, and a journal whose keys change shape
    when it is written to disk cannot be replayed from disk.
    """
    if isinstance(key, str):
        text = key.strip()
        return text if text.startswith("i") else f"i{text}"
    return f"i{int(key)}"


def fingerprint(payload) -> str:
    """A stable digest of what an execution produced."""
    try:
        blob = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        blob = repr(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class JournalEntry:
    seq: int
    kind: str                      # REVISION | STEP
    phase: str
    rule_text: str | None = None   # canonical rule payload
    inputs: dict = field(default_factory=dict)   # canonical logical values
    target: int | None = None
    outcome: str | None = None     # the revision outcome, when known
    result_fingerprint: str | None = None

    def replayable(self) -> dict:
        """What a reconstruction re-feeds. Outputs are NOT included: a replay has
        to re-derive them, or it confirms what it was told instead of
        reproducing the state."""
        return {
            "kind": self.kind,
            "rule_text": self.rule_text,
            "inputs": dict(self.inputs),
            "target": self.target,
        }

    def to_dict(self) -> dict:
        return asdict(self)


class OperationalTrace:
    """Everything that happened, bounded, for diagnosis only.

    Deliberately has no `replay_trace`: nothing here is authoritative, and making
    it easy to replay would be making it easy to reintroduce contamination.
    """

    def __init__(self, limit: int = 2048):
        self._limit = limit
        self._entries: list = []

    def record(self, phase: str, detail: dict) -> None:
        self._entries.append({"phase": phase, **detail})
        if len(self._entries) > self._limit:
            del self._entries[: len(self._entries) - self._limit]

    def entries(self) -> list:
        return list(self._entries)

    def __len__(self) -> int:
        return len(self._entries)


class Journal:
    """An ordered record of execution that defines an evaluator's state."""

    def __init__(self, anchor: str | None = None, authoritative: bool = True):
        self.anchor = anchor
        self.authoritative = authoritative
        self._entries: list = []
        self._seq = 0

    # --- recording ------------------------------------------------------------

    def record(self, kind: str, *, phase: str, rule_text=None, inputs=None,
               target=None, outcome=None, result=None) -> JournalEntry:
        if self.authoritative and phase not in AUTHORITATIVE_PHASES:
            raise ValueError(
                f"phase {phase!r} is not authoritative; it belongs in the "
                "operational trace or a proposal journal"
            )
        self._seq += 1
        entry = JournalEntry(
            seq=self._seq,
            kind=kind,
            phase=phase,
            rule_text=rule_text,
            inputs={canonical_stream_key(k): v for k, v in (inputs or {}).items()},
            target=target,
            outcome=outcome,
            result_fingerprint=None if result is None else fingerprint(result),
        )
        self._entries.append(entry)
        return entry

    # --- reading --------------------------------------------------------------

    def entries(self) -> list:
        return list(self._entries)

    def replay_trace(self) -> list:
        return [e.replayable() for e in self._entries]

    def fingerprints(self) -> list:
        return [(e.seq, e.result_fingerprint) for e in self._entries]

    def __len__(self) -> int:
        return len(self._entries)

    # --- lifecycle ------------------------------------------------------------

    def reset(self, anchor: str | None = None) -> None:
        self.anchor = anchor
        self._entries = []
        self._seq = 0

    def branch(self) -> "Journal":
        """A proposal journal continuing from this one, recorded separately."""
        child = Journal(anchor=self.anchor, authoritative=False)
        return child

    def adopt(self, proposal: "Journal") -> None:
        """Fold an ACCEPTED proposal's execution into the committed record.

        The proposal's phase labels are rewritten to `apply`: they describe
        committed execution now, and a later reconstruction must replay them.
        """
        for entry in proposal.entries():
            self._seq += 1
            self._entries.append(JournalEntry(
                seq=self._seq,
                kind=entry.kind,
                phase=PHASE_APPLY,
                rule_text=entry.rule_text,
                inputs=dict(entry.inputs),
                target=entry.target,
                outcome=entry.outcome,
                result_fingerprint=entry.result_fingerprint,
            ))

    def serialize(self) -> str:
        return json.dumps({"anchor": self.anchor,
                           "entries": [e.to_dict() for e in self._entries]})

    @classmethod
    def deserialize(cls, blob: str) -> "Journal":
        data = json.loads(blob or '{"entries": []}')
        journal = cls(anchor=data.get("anchor"))
        for raw in data.get("entries", []):
            journal._entries.append(JournalEntry(**raw))
        journal._seq = journal._entries[-1].seq if journal._entries else 0
        return journal


class DivergenceError(RuntimeError):
    """A reconstruction did not reproduce the recorded execution.

    Continuing from here would mean computing on a state nobody checked, which is
    the thing the fingerprints exist to prevent.
    """


def compare(expected, observed, *, seq: int) -> None:
    if expected is None:
        return
    got = fingerprint(observed)
    if got != expected:
        raise DivergenceError(
            f"replay diverged at entry {seq}: expected {expected}, observed {got}"
        )


# --- process-wide records -----------------------------------------------------

_committed = Journal(authoritative=True)
_trace = OperationalTrace()


def committed() -> Journal:
    return _committed


def trace() -> OperationalTrace:
    return _trace


def reset_all(anchor: str | None = None) -> None:
    _committed.reset(anchor)
