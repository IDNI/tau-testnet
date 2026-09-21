"""Reconstruct an authoritative evaluator from one anchor, deterministically.

The criterion is not "can a worker replay?" -- that was settled. It is:

    given ONE committed journal/allocator anchor and a chosen representation
    plan, can a fresh process reconstruct exactly the authoritative semantic
    state without reading or mutating any ambient global state?

Three things this module exists to prevent.

**Reconstructing against whatever happens to be in the global allocator.** The
journal and the allocator snapshot are supposed to describe the same committed
history; if replay may allocate, a disagreement between them is silently
repaired instead of reported.

**Planning the representation after the interpreter is built.** A committed
history whose `i12` use is equality-only replays fine as interned bv[8]; a
candidate that uses `i12` in an ordering comparison needs plain bv[384]. Decide
the representation for committed history AND the candidate together, before
constructing anything -- otherwise the reconstruction pins the narrow width and
then cannot type the candidate, which is the original incident wearing a
different hat.

**Comparing runtime payloads across a representation change.** A replay at bv[16]
of history recorded at bv[8] is expected to produce different runtime payloads
and the same meaning. Only semantic fingerprints may be compared.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field

import tau_journal


class ReconstructionMismatch(Exception):
    """The anchor does not describe the state that was found.

    Fail closed for the authoritative evaluator: a node that reconstructs from a
    mismatched anchor is serving a state nobody committed.
    """


class StaleAnchor(Exception):
    """A speculative proposal's anchor moved on. Operational: discard the
    proposal and rebuild from the new committed anchor. Not node corruption, and
    not a verdict about any transaction."""


class RepresentationConflict(Exception):
    """The chosen representation cannot express what has to run. Carries the plan
    so a retry can choose a compatible one instead of rediscovering the conflict."""

    def __init__(self, message, *, required_plain=frozenset(), plan=None):
        super().__init__(message)
        self.required_plain = frozenset(required_plain)
        self.plan = plan


def native_build_id() -> str:
    """Identity of the engine binary in use. A reconstruction under a different
    build is not the same computation."""
    try:
        import tau_native
        module = tau_native.load_tau_module()
        path = getattr(module, "__file__", None)
        if not path:
            return "unknown"
        stat = os.stat(path)
        return tau_journal.fingerprint({"path": path, "size": stat.st_size,
                                        "mtime": int(stat.st_mtime)})
    except Exception:
        return "unavailable"


@dataclass(frozen=True)
class RepresentationPlan:
    """Which streams are interned, at what width, for one reconstruction."""

    width: int
    interned: frozenset = frozenset()
    plain: frozenset = frozenset()

    @property
    def plan_id(self) -> str:
        return tau_journal.fingerprint({
            "width": self.width,
            "interned": sorted(self.interned),
            "plain": sorted(self.plain),
        })

    def excludes(self) -> frozenset:
        """Streams the optimizer must leave alone under this plan."""
        return frozenset(self.plain)


def plan_representation(*, history_rules=(), candidate_rules=(), width=None):
    """Choose ONE representation for committed history and the candidate together.

    A stream any of them uses in a way the optimizer refuses to shrink must be
    plain everywhere, including throughout the replayed history -- deciding from
    history alone and meeting the candidate afterwards reproduces the conflict
    the whole design exists to avoid.
    """
    import tau_allocator
    import tau_shrink

    if width is None:
        width = tau_shrink.current_shrink_width()
    interned, plain = set(), set()
    # Planning must not ALLOCATE. It only needs to know which streams the
    # optimizer would shrink; running it against the live allocator would intern
    # every address it inspects, moving the committed mapping the reconstruction
    # is about to be anchored to.
    scratch = tau_allocator.Allocator(tau_allocator.DbMappingSnapshot(),
                                      width=width, label="planner")
    for text in list(history_rules) + list(candidate_rules):
        if not text or not str(text).strip():
            continue
        try:
            with tau_shrink.speculative_allocation(allocator=scratch):
                prepared = tau_shrink.prepare_rule(str(text))
        except Exception:
            # An unanalyzable rule cannot be shown to be shrinkable: everything it
            # touches stays plain.
            plain |= tau_shrink.wide_input_streams(str(text))
            continue
        interned |= set(prepared.shrunk_streams)
        plain |= set(prepared.wide_streams_unshrunk)
    # A stream that must be plain anywhere is plain everywhere.
    interned -= plain
    return RepresentationPlan(width=width, interned=frozenset(interned),
                              plain=frozenset(plain))


@dataclass(frozen=True)
class ReconstructionDescriptor:
    """The anchor a reconstruction is performed against."""

    committed_tip_id: str | None = None
    journal_head_hash: str | None = None
    journal_sequence: int = 0
    allocator_state_id: str | None = None
    representation_plan_id: str | None = None
    native_build_id: str | None = None

    @classmethod
    def capture(cls, *, journal, tip_id=None, plan=None, store=None):
        import db as _db
        store = store or _db
        entries = journal.entries()
        return cls(
            committed_tip_id=tip_id,
            journal_head_hash=entries[-1].link if entries else None,
            journal_sequence=len(entries),
            allocator_state_id=store.shrink_mapping_epoch(),
            representation_plan_id=None if plan is None else plan.plan_id,
            native_build_id=native_build_id(),
        )

    def mismatches(self, other: "ReconstructionDescriptor") -> list:
        out = []
        for name in ("committed_tip_id", "journal_head_hash", "journal_sequence",
                     "allocator_state_id", "representation_plan_id",
                     "native_build_id"):
            mine, theirs = getattr(self, name), getattr(other, name)
            if mine is not None and theirs is not None and mine != theirs:
                out.append(f"{name}: {mine!r} != {theirs!r}")
        return out


class ReplayAllocator:
    """READ ONLY against the committed mapping.

    Replay may not mint: the journal and the allocator snapshot describe the same
    committed history, so a canonical value the journal references and the mapping
    does not have is a disagreement between the two anchors. Allocating one
    silently would repair the inconsistency instead of reporting it -- and would
    consume committed capacity for a reconstruction.
    """

    def __init__(self, snapshot):
        self._snapshot = snapshot
        self.epoch = snapshot.epoch

    @property
    def width(self):
        return None

    def id_for(self, key: str) -> int:
        existing = self._snapshot.lookup(key)
        if existing is None:
            raise ReconstructionMismatch(
                f"the journal references {key!r}, which the committed mapping does "
                "not contain; the two anchors describe different histories"
            )
        return int(existing)

    def delta(self) -> dict:
        return {}
