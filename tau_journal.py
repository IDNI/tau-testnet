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
from dataclasses import dataclass, field, asdict, replace

REVISION = "revision"
STEP = "step"
#: Re-initialize the evaluator from the program baseline, then apply `units`.
#:
#: What a governance activation does to the evaluator. Every activated revision
#: goes through i0 and would otherwise LAYER on the previous consensus rules,
#: while the chain's hashed consensus state says "the last activation only" --
#: which is why the in-process path collapsed its interpreter after every
#: activation. Recording the collapse as an entry makes a running evaluator and
#: a reconstructed one collapse at the same point, and it bounds replay: nothing
#: before the last RESET can affect the evaluator.
RESET = "reset"

# Why an entry is authoritative -- or why it is not.
PHASE_APPLY = "apply"                 # committed block execution
PHASE_GOVERNANCE = "governance"       # activated consensus revision
PHASE_RESTORE = "restore"             # reconstruction replay
PHASE_ADVISORY = "advisory"           # never authoritative
PHASE_VALIDATION = "validation"       # never authoritative
PHASE_SPECULATIVE = "speculative"     # proposal only

AUTHORITATIVE_PHASES = frozenset({PHASE_APPLY, PHASE_GOVERNANCE, PHASE_RESTORE})


class AliasCollision(ValueError):
    """Two spellings of one stream arrived with different values.

    `12`, `"12"` and `"i12"` are the same stream. Letting dict or JSON
    normalization pick a winner would record an input nobody supplied.
    """


def canonical_inputs(inputs) -> dict:
    """Canonicalize input keys, refusing a collision rather than resolving it."""
    out = {}
    origin = {}
    for key, value in (inputs or {}).items():
        name = canonical_stream_key(key)
        if name in out and out[name] != value:
            raise AliasCollision(
                f"{origin[name]!r} and {key!r} both name {name} but carry "
                f"{out[name]!r} and {value!r}"
            )
        out[name] = value
        origin[name] = key
    return out


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


def candidate_identity(canonical_text, *, mapping_epoch=None, width=None,
                      runtime_text=None) -> dict:
    """What identifies a prepared candidate.

    A runtime payload hash alone is NOT an identity. Ids are private to an
    allocation context, so a discarded transaction B and a later transaction C can
    hold byte-identical runtime text meaning different things -- C legitimately
    reuses B's freed number for a different canonical value. A receipt or journal
    entry keyed on the runtime hash would let a stale B validate C.

    Identity is therefore canonical value, plus the mapping context that gives the
    ids meaning, plus the representation, plus the payload actually executed.
    """
    parts = {
        "canonical": fingerprint(canonical_text),
        "mapping_epoch": mapping_epoch,
        "width": width,
        "runtime": None if runtime_text is None else fingerprint(runtime_text),
    }
    parts["id"] = fingerprint(parts)
    return parts


def semantic_result(outputs=None, outcome=None, progressed=None) -> dict:
    """What an execution MEANS, independent of representation.

    A valid reconstruction may legitimately change representation -- interned
    bv[8] to bv[16] after a capacity retry, or interned to plain full width -- so
    the durable divergence criterion must not bind to a node-local id or a runtime
    width. Output PRESENCE is part of it: a stream that stopped materializing is a
    different computation even when the value that remains is equal.
    """
    values = {}
    present = []
    for name, value in (outputs or {}).items():
        label = str(name)
        # A worker's step outputs are indexed (5), a revision's are named (o5):
        # the same stream. Left as "5", no step value ever reached a fingerprint
        # -- replay compared WHICH streams a step produced and never WHAT, so a
        # reconstruction computing o5=1 where the original computed o5=0 passed.
        if label.isdigit():
            label = f"o{label}"
        present.append(label)
        # Values are recorded for OUTPUT streams only. The router echoes the
        # accepted specification on `u`, which carries interned ids and runtime
        # widths -- binding the semantic fingerprint to that would make every
        # legitimate representation change look like divergence, which is exactly
        # what the semantic/runtime split exists to avoid. Its PRESENCE still
        # counts.
        if label.startswith("o") and label[1:].isdigit():
            values[label] = None if value is None else str(value)
    return {
        "outcome": outcome,
        "present": sorted(present),
        "values": values,
        "progressed": progressed,
    }


def fingerprint(payload) -> str:
    """A stable digest of what an execution produced."""
    try:
        blob = json.dumps(payload, sort_keys=True, default=str)
    except Exception:
        blob = repr(payload)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16]


def journal_from_rows(rows, *, authoritative=True) -> "Journal":
    """Rebuild a Journal from committed storage rows.

    The committed journal IS the definition of the node's evaluator state, so
    recovery reads it back and replays it. Reconstructed entries keep their
    stored links rather than recomputing them: a row whose link does not match
    its content is corruption to be DETECTED, and recomputing would quietly
    repair it into something that verifies.
    """
    journal = Journal(authoritative=authoritative)
    for row in rows:
        entry = JournalEntry(
            seq=int(row["seq"]), kind=row["kind"], phase=row["phase"],
            rule_text=row.get("rule_text"), inputs=dict(row.get("inputs") or {}),
            target=row.get("target"), accumulate=bool(row.get("accumulate", True)),
            units=tuple((str(t), bool(p)) for t, p in (row.get("units") or ())),
            outcome=row.get("outcome"),
            result_fingerprint=row.get("result_fingerprint"),
            identity=row.get("identity"), prev=row.get("prev"), link=row["link"],
        )
        journal._entries.append(entry)
        journal._seq = entry.seq
    return journal


def last_reset_index(entries):
    """Index of the last RESET entry, or None. Replay can start there."""
    for index in range(len(entries) - 1, -1, -1):
        if entries[index].kind == RESET:
            return index
    return None


def verify_entries(entries, *, start_prev=None, start_seq=0) -> None:
    """Verify a hash-chained run of entries, detached from any Journal.

    Detached because a frozen commit artifact holds a tuple of entries rather
    than the journal they came out of, and re-attaching them to a Journal just to
    check them would mean building the very mutable object the artifact exists to
    stop being consulted.
    """
    prev = start_prev
    expected_seq = start_seq
    for entry in entries:
        expected_seq += 1
        if entry.seq != expected_seq:
            raise DivergenceError(
                f"journal sequence broken at {entry.seq}: expected {expected_seq}"
            )
        if entry.prev != prev:
            raise DivergenceError(f"journal link broken at entry {entry.seq}")
        if entry.link != entry.compute_link():
            raise DivergenceError(f"journal entry {entry.seq} was altered")
        prev = entry.link


@dataclass(frozen=True)
class JournalEntry:
    seq: int
    kind: str                      # REVISION | STEP
    phase: str
    rule_text: str | None = None   # canonical rule payload
    inputs: dict = field(default_factory=dict)   # canonical logical values
    target: int | None = None
    #: Whether the authoritative path ALSO accumulated this revision into the
    #: application-rules state. A regenerated o5 composite is fed with
    #: accumulate=False -- it changes the evaluator but the clause registry, not
    #: the accumulation, is what a restore rebuilds it from. Recorded because the
    #: two produce different canonical state from the same evaluator history.
    accumulate: bool = True
    #: RESET only: the (rule text, persist) units applied after re-initializing.
    units: tuple = ()
    outcome: str | None = None     # the revision outcome, when known
    result_fingerprint: str | None = None        # SEMANTIC: survives a valid
                                                 # representation change
    runtime_fingerprint: str | None = None       # optional, same-representation
    identity: dict | None = None                 # canonical + context + payload
    prev: str | None = None        # previous entry's link
    link: str | None = None        # this entry's link: H(content, prev)

    def content_digest(self) -> str:
        return fingerprint({
            "seq": self.seq, "kind": self.kind, "phase": self.phase,
            "rule_text": self.rule_text, "inputs": self.inputs,
            "target": self.target, "accumulate": self.accumulate,
            "units": [list(u) for u in self.units],
            "outcome": self.outcome,
            "result": self.result_fingerprint,
            "identity": None if self.identity is None else self.identity.get("id"),
        })

    def compute_link(self) -> str:
        return fingerprint({"content": self.content_digest(), "prev": self.prev})

    def replayable(self) -> dict:
        """What a reconstruction re-feeds. Outputs are NOT included: a replay has
        to re-derive them, or it confirms what it was told instead of
        reproducing the state."""
        return {
            "kind": self.kind,
            "rule_text": self.rule_text,
            "inputs": dict(self.inputs),
            "target": self.target,
            "accumulate": self.accumulate,
            "units": [list(u) for u in self.units],
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

    def __init__(self, anchor: str | None = None, authoritative: bool = True,
                 *, start_seq: int = 0, start_prev: str | None = None):
        """`start_seq`/`start_prev` continue an existing chain.

        A proposal journal is a CONTINUATION of the committed journal, not a new
        chain: its first entry has to link to the committed head and carry the
        next committed sequence number. Starting fresh would make the committed
        journal a string of independently-chained segments -- each fine on its
        own, and a record that no longer proves anything about order across them.
        """
        self.anchor = anchor
        self.authoritative = authoritative
        self.label = "committed" if authoritative else "proposal"
        self._entries: list = []
        self._seq = int(start_seq)
        self._start_seq = int(start_seq)
        self._start_prev = start_prev
        self._parent = None
        self._discarded = False

    @property
    def base_head(self):
        """The link this journal continues from (None for a fresh chain)."""
        return self._start_prev

    @property
    def base_seq(self) -> int:
        return self._start_seq

    # --- recording ------------------------------------------------------------

    def record(self, kind: str, *, phase: str, rule_text=None, inputs=None,
               target=None, outcome=None, result=None, runtime=None,
               identity=None, accumulate=True, units=()) -> JournalEntry:
        if self._discarded:
            raise ValueError(
                f"journal {self.label!r} was discarded; its execution is not part "
                "of any branch"
            )
        if self.authoritative and phase not in AUTHORITATIVE_PHASES:
            raise ValueError(
                f"phase {phase!r} is not authoritative; it belongs in the "
                "operational trace or a proposal journal"
            )
        self._seq += 1
        semantic = None
        if result is not None or outcome is not None:
            semantic = fingerprint(
                result if isinstance(result, dict) and "present" in result
                else semantic_result(outputs=result if isinstance(result, dict) else None,
                                     outcome=outcome)
            )
        entry = JournalEntry(
            seq=self._seq,
            kind=kind,
            phase=phase,
            rule_text=rule_text,
            inputs=canonical_inputs(inputs),
            target=target,
            accumulate=bool(accumulate),
            units=tuple((str(t), bool(p)) for t, p in (units or ())),
            outcome=outcome,
            result_fingerprint=semantic,
            runtime_fingerprint=None if runtime is None else fingerprint(runtime),
            identity=identity,
            prev=self._entries[-1].link if self._entries else self._start_prev,
        )
        entry = replace(entry, link=entry.compute_link())
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

    def verify_chain(self) -> None:
        """Order corruption must be impossible to mistake for valid history.

        A history-dependent rule catches many reorderings behaviourally, but the
        format itself should not permit a swapped, duplicated or altered entry to
        look like a legitimate record.
        """
        verify_entries(self._entries, start_prev=self._start_prev,
                       start_seq=self._start_seq)

    def child(self, label: str = "tx") -> "Journal":
        """A transaction-private journal.

        Rejection has to be a discard, not a filter: appending a transaction's
        steps straight into the proposal means rebuilding the accepted prefix
        requires taking them back out again, which is the problem the speculative
        session exists to avoid, reproduced one layer up.
        """
        child = Journal(anchor=self.anchor, authoritative=False)
        child._parent = self
        child.label = label
        return child

    def merge(self, child: "Journal") -> None:
        """Accept a transaction: its execution becomes part of this branch."""
        if getattr(child, "_parent", None) is not self:
            raise ValueError("cannot merge a journal from another parent")
        if child._discarded:
            raise ValueError("cannot merge a discarded journal")
        for entry in child.entries():
            # Every field that is part of the record, not just the ones replay
            # reads. Dropping `accumulate` recorded a merged o5 composite as part
            # of the application-rules accumulation, and dropping `identity`
            # erased which prepared payload the worker actually evaluated.
            self.record(entry.kind, phase=self._phase_for(entry), rule_text=entry.rule_text,
                        inputs=entry.inputs, target=entry.target, outcome=entry.outcome,
                        identity=entry.identity, accumulate=entry.accumulate,
                        units=entry.units)
            self._entries[-1] = replace(
                self._entries[-1],
                result_fingerprint=entry.result_fingerprint,
                runtime_fingerprint=entry.runtime_fingerprint,
            )
            self._entries[-1] = replace(self._entries[-1],
                                        link=self._entries[-1].compute_link())
        child._discarded = True

    def discard(self, child: "Journal") -> None:
        """Reject a transaction: nothing it executed is part of this branch."""
        if getattr(child, "_parent", None) is not self:
            raise ValueError("cannot discard a journal from another parent")
        child._discarded = True

    def _phase_for(self, entry) -> str:
        return entry.phase if not self.authoritative else PHASE_APPLY

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


def compare(expected, observed_outputs, *, seq: int, outcome=None) -> None:
    """Compare a replayed execution against its recorded SEMANTIC fingerprint.

    Semantic, so a reconstruction that legitimately changes representation -- a
    capacity retry at a wider width, say -- is not mistaken for divergence, while
    a changed value or a stream that stopped materializing still is.
    """
    if expected is None:
        return
    got = fingerprint(semantic_result(outputs=observed_outputs, outcome=outcome))
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
