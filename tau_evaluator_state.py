"""The four states the node has to keep apart (W2).

A single "which streams are shrunk" set cannot represent any of them properly,
and conflating them is what let a rule be dispatched in a representation the
process could not type.

| state | contents | lifetime |
|---|---|---|
| canonical execution context | accepted rules, composites, host contract, position | changes at transaction commit |
| process type commitments | widths this PROCESS established | until real process exit / re-exec |
| active evaluator state | reconstruction position, temporal state, protocol state, health | changes as execution advances |
| encoding context | canonical/runtime types, encoding kind, mapping identity | changes with accepted runtime updates |

Two measured facts drive the design:

* A stream's width is committed by the first ACCEPTED revision that mentions it,
  and the commitment OUTLIVES that rule -- it still applies after the rule is
  superseded and no longer appears in `current_spec()`. So commitments must never
  be cleared by `update_spec`, a restore, or `kill_tau_process` (which builds
  another interface in the SAME process).
* An ordinary `bv[8]` stream and a `bv[384]` stream represented by local `bv[8]`
  ids need different input handling, and the intern key is width-tagged. Runtime
  width alone is therefore not enough: the encoding kind and the mapping identity
  travel with it.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace

PLAIN = "plain"
INTERNED = "interned"
UNRESOLVED = "unresolved"

INPUT = "i"
OUTPUT = "o"


def qualified(io: str, index: int) -> tuple:
    """Stream identity. `i12` and `o12` are different streams and must never be
    conflated -- the old bare-int keying could not tell them apart."""
    if io not in (INPUT, OUTPUT):
        raise ValueError(f"stream side must be {INPUT!r} or {OUTPUT!r}, got {io!r}")
    return (io, int(index))


@dataclass(frozen=True)
class StreamEncoding:
    canonical_width: int | None = None
    runtime_width: int | None = None
    encoding: str = UNRESOLVED
    mapping_epoch: int | None = None

    @property
    def is_interned(self) -> bool:
        return self.encoding == INTERNED

    def describe(self) -> str:
        if self.encoding == UNRESOLVED:
            return "unresolved"
        if self.is_interned:
            return (f"canonical bv[{self.canonical_width}] as interned "
                    f"bv[{self.runtime_width}] (mapping {self.mapping_epoch})")
        return f"plain bv[{self.canonical_width}]"


class ProcessTypeCommitments:
    """Widths the native process has established. Additive, never cleared.

    Deliberately has no `clear()`: a commitment cannot be deleted from bookkeeping
    to imitate a rollback the engine did not perform. A fresh process is the only
    way to be rid of one.
    """

    def __init__(self):
        self._widths: dict = {}

    def commit(self, stream: tuple, width: int) -> None:
        current = self._widths.get(stream)
        if current is not None and current != width:
            raise ValueError(
                f"{stream[0]}{stream[1]} is already committed at bv[{current}]; "
                f"the engine never re-types a stream in-process"
            )
        self._widths[stream] = int(width)

    def width_of(self, stream: tuple):
        return self._widths.get(stream)

    def conflicts_with(self, stream: tuple, width: int) -> bool:
        current = self._widths.get(stream)
        return current is not None and current != width

    def committed(self) -> dict:
        return dict(self._widths)

    def __len__(self) -> int:
        return len(self._widths)


@dataclass
class EvaluatorState:
    """The live evaluator's own state, separate from process commitments."""

    process: ProcessTypeCommitments = field(default_factory=ProcessTypeCommitments)
    encodings: dict = field(default_factory=dict)
    # Bumped when the INTERFACE is replaced; a result prepared against an older
    # generation must not be published. Necessary but NOT sufficient -- it detects
    # a stale result, it does not prevent two interpreters racing (only single
    # ownership does).
    generation: int = 0
    # Bumped whenever execution advances, even with the same interface object.
    state_revision: int = 0
    healthy: bool = True
    unusable_reason: str | None = None

    # --- execution bookkeeping ------------------------------------------------

    def advance(self) -> int:
        self.state_revision += 1
        return self.state_revision

    def new_generation(self, reason: str = "") -> int:
        """The interface was replaced. Process commitments SURVIVE this."""
        self.generation += 1
        self.state_revision += 1
        return self.generation

    def mark_unusable(self, reason: str) -> None:
        """An error left native state uncertain. Nothing may run until a verified
        reconstruction succeeds; unchanged Python dicts prove nothing."""
        self.healthy = False
        self.unusable_reason = reason

    def mark_reconstructed(self) -> None:
        self.healthy = True
        self.unusable_reason = None
        self.new_generation("reconstructed")

    # --- encodings ------------------------------------------------------------

    def set_encoding(self, stream: tuple, enc: StreamEncoding) -> None:
        self.encodings[stream] = enc
        width = enc.runtime_width if enc.is_interned else enc.canonical_width
        if width is not None:
            self.process.commit(stream, width)

    def encoding_of(self, stream: tuple) -> StreamEncoding:
        return self.encodings.get(stream, StreamEncoding())

    def interned_streams(self) -> frozenset:
        """Input stream indices currently carried as interned ids."""
        return frozenset(
            index for (io, index), enc in self.encodings.items()
            if io == INPUT and enc.is_interned
        )

    def apply_prepared(self, prepared, *, width: int, mapping_epoch=None,
                       canonical_widths=None) -> None:
        """Record what a successful preparation means for the streams it touched."""
        canonical_widths = canonical_widths or {}
        for index in getattr(prepared, "shrunk_streams", ()) or ():
            stream = qualified(INPUT, index)
            self.set_encoding(stream, StreamEncoding(
                canonical_width=canonical_widths.get(index, 384),
                runtime_width=width,
                encoding=INTERNED,
                mapping_epoch=mapping_epoch,
            ))
        for index in getattr(prepared, "wide_streams_unshrunk", ()) or ():
            stream = qualified(INPUT, index)
            if self.encoding_of(stream).is_interned:
                continue          # an earlier interned commitment stands
            self.set_encoding(stream, StreamEncoding(
                canonical_width=canonical_widths.get(index, 384),
                runtime_width=canonical_widths.get(index, 384),
                encoding=PLAIN,
                mapping_epoch=None,
            ))

    # --- the compatibility question -------------------------------------------

    def conflicts(self, prepared, *, width: int) -> frozenset:
        """Input streams this preparation would type differently than the process
        already has. Non-empty means there is NO correct text to dispatch."""
        bad = set()
        for index in getattr(prepared, "shrunk_streams", ()) or ():
            if self.process.conflicts_with(qualified(INPUT, index), width):
                bad.add(index)
        for index in getattr(prepared, "wide_streams_unshrunk", ()) or ():
            stream = qualified(INPUT, index)
            committed = self.process.width_of(stream)
            if committed is not None and committed == width:
                bad.add(index)    # process holds it interned; wide text cannot type
        return frozenset(bad)

    def snapshot(self) -> dict:
        """A value usable as a request context: generation + state revision."""
        return {
            "generation": self.generation,
            "state_revision": self.state_revision,
            "healthy": self.healthy,
            "interned": sorted(self.interned_streams()),
            "committed": {f"{io}{idx}": w for (io, idx), w in self.process.committed().items()},
        }
