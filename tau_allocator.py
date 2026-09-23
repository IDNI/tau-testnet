"""Intern-id allocation with block-root inheritance and one publication point.

Measured problems this replaces (W0/C5):

* `db.get_shrink_id` INSERTs and COMMITs immediately, so a rejected or
  never-committed transaction permanently burns capacity -- and, on the shared
  connection, an intern performed inside an enclosing canonical transaction
  commits that transaction early.
* It also persists the id BEFORE the width check rejects it. Progress after an
  overflow currently depends on that leak: the recomputed width only grows because
  the failed id landed in the table. Stop the leak without changing anything else
  and a retry recomputes the same width from the unchanged high-water mark and
  overflows forever.

So: allocation happens in a private overlay, never touching the store; the retry
width is taken from the RETAINED plan, not from the committed high-water mark; and
publication happens once, by the commit owner, in a single transaction.

Hierarchy (C3):

    immutable committed snapshot
      -> block-private allocator
           -> transaction-private child overlay

A transaction reads THROUGH its parents, so it sees allocations made by earlier
accepted transactions in the same block. On acceptance its delta merges into the
block allocator; on rejection the child is discarded whole. Numeric reuse across
fully disposed contexts is fine -- what must never happen is a value, payload or
receipt from a disposed context being used in a live one, so every id carries the
identity of the context that minted it.
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field

RESERVED_EMPTY_ID = 0

_context_counter = itertools.count(1)


class AllocatorConflict(Exception):
    """Publication found the store moved underneath this plan.

    Operational: the speculative attempt is STALE and should be retried against a
    fresh snapshot. It is not a verdict about any transaction.
    """


class AllocatorCapacityExceeded(Exception):
    """The retained plan needs more ids than the current width can express.

    Carries the plan so a retry can pick a width that actually fits, instead of
    recomputing from the unchanged committed high-water mark and overflowing again.
    """

    def __init__(self, message: str, *, required_id: int, width: int, plan: dict):
        super().__init__(message)
        self.required_id = required_id
        self.width = width
        self.plan = plan


def usable_ceiling(width: int) -> int:
    """Largest assignable id at `width` (0 reserved, top value is the grow boundary)."""
    return (1 << width) - 2


def width_for_max_id(max_id: int) -> int:
    """Smallest byte-multiple width that can express `max_id`."""
    width = 8
    while usable_ceiling(width) < max_id:
        width += 8
    return width


class DbMappingSnapshot:
    """A read-through view of the committed mapping, pinned at an epoch.

    Read-through rather than loaded: the table is the node's whole address space
    and a proposal touches a handful of keys. `epoch` is a version that moves on
    any committed change, not a maximum -- a mapping could change without the
    maximum moving, and a proposal validated against the old one would publish
    into a table it no longer describes.
    """

    def __init__(self, store=None):
        import db as _db
        self._db = store or _db
        self.epoch = self._db.shrink_mapping_epoch()
        self._high_water = self._db.get_max_shrink_id()

    def lookup(self, key: str):
        return self._db.lookup_shrink_id(key)

    @property
    def high_water(self) -> int:
        return int(self._high_water)


class PinnedDbMappingSnapshot:
    """A read-through view of the committed mapping that STAYS where it was pinned.

    `DbMappingSnapshot` reads the live table, which is right for a proposal --
    it runs under the chain lock, so nothing commits underneath it -- and wrong
    for anything that runs beside block production. There a block can commit
    mid-evaluation and add bindings above the high-water mark this view minted
    from; an overlay that had already handed the same number to a different value
    would then see two values share one id, and every equality between them
    answer true.

    Committed ids only extend the table upward (publication refuses a moved
    epoch, and mints above the high-water mark it was planned against), so the
    pinned state is exactly the bindings at or below the pin.
    """

    def __init__(self, *, epoch, high_water: int, store=None):
        import db as _db
        self._db = store or _db
        self.epoch = epoch
        self._high_water = int(high_water)

    def lookup(self, key: str):
        found = self._db.lookup_shrink_id(key)
        if found is None or int(found) > self._high_water:
            return None
        return int(found)

    @property
    def high_water(self) -> int:
        return self._high_water


@dataclass(frozen=True)
class MappingSnapshot:
    """An immutable view of the committed mapping, pinned at an epoch."""

    epoch: int
    committed: dict = field(default_factory=dict)   # key -> id

    def lookup(self, key: str):
        return self.committed.get(key)

    @property
    def high_water(self) -> int:
        return max(self.committed.values(), default=0)

    @classmethod
    def capture(cls, store) -> "MappingSnapshot":
        """Capture the committed mapping and its epoch from a store.

        `store` supplies `snapshot_mapping()` -> (epoch, {key: id}).
        """
        epoch, mapping = store.snapshot_mapping()
        return cls(epoch=epoch, committed=dict(mapping))


class Allocator:
    """A private overlay over a snapshot or another allocator."""

    def __init__(self, parent, *, width: int, label: str = ""):
        self._parent = parent
        self._width = width
        self._own: dict = {}
        self.context_id = f"{label or 'ctx'}-{next(_context_counter)}"
        self._discarded = False

    # --- reads ----------------------------------------------------------------

    @property
    def width(self) -> int:
        return self._width

    @property
    def epoch(self) -> int:
        return self._root.epoch

    @property
    def _root(self) -> MappingSnapshot:
        node = self._parent
        while isinstance(node, Allocator):
            node = node._parent
        return node

    def _check_live(self):
        if self._discarded:
            raise RuntimeError(
                f"allocator {self.context_id} was discarded; its ids must not be reused"
            )

    def lookup(self, key: str):
        """Read through the whole chain: own overlay, then parents."""
        self._check_live()
        if key in self._own:
            return self._own[key]
        if isinstance(self._parent, Allocator):
            return self._parent.lookup(key)
        return self._parent.lookup(key)

    def _next_id(self) -> int:
        highest = self._high_water_chain()
        return highest + 1

    def _high_water_chain(self) -> int:
        own = max(self._own.values(), default=0)
        if isinstance(self._parent, Allocator):
            return max(own, self._parent._high_water_chain())
        return max(own, self._parent.high_water)

    # --- allocation -----------------------------------------------------------

    def id_for(self, key: str) -> int:
        """The id for `key`, allocating in THIS overlay when it is new."""
        self._check_live()
        existing = self.lookup(key)
        if existing is not None:
            return existing
        new_id = self._next_id()
        if new_id > usable_ceiling(self._width):
            raise AllocatorCapacityExceeded(
                f"id {new_id} exceeds bv[{self._width}] usable range",
                required_id=new_id,
                width=self._width,
                plan=self.retained_plan(),
            )
        self._own[key] = new_id
        return new_id

    def retained_plan(self) -> dict:
        """Everything this context and its parents added on top of the snapshot.

        This is what a capacity retry must be sized against.
        """
        plan = {}
        if isinstance(self._parent, Allocator):
            plan.update(self._parent.retained_plan())
        plan.update(self._own)
        return plan

    def required_width(self) -> int:
        """Width that fits the retained plan -- never recomputed from the store."""
        plan = self.retained_plan()
        return width_for_max_id(max(plan.values(), default=self._root.high_water))

    # --- nesting --------------------------------------------------------------

    def child(self, label: str = "tx") -> "Allocator":
        self._check_live()
        return Allocator(self, width=self._width, label=label)

    def merge(self, child: "Allocator") -> None:
        """Accept a child's allocations into this context."""
        self._check_live()
        if child._parent is not self:
            raise ValueError("cannot merge an allocator from another parent")
        if child._discarded:
            raise ValueError("cannot merge a discarded allocator")
        for key, value in child._own.items():
            existing = self.lookup(key)
            if existing is not None and existing != value:
                raise AllocatorConflict(
                    f"{key!r} is {existing} here and {value} in {child.context_id}"
                )
            self._own[key] = value
        child._discarded = True

    def discard(self, child: "Allocator") -> None:
        """Reject a child: its ids contribute nothing and may be minted again."""
        if child._parent is not self:
            raise ValueError("cannot discard an allocator from another parent")
        child._discarded = True

    # --- publication ----------------------------------------------------------

    def delta(self) -> dict:
        """The allocations this context adds to the committed mapping."""
        return dict(self.retained_plan())


class AllocationUnavailable(Exception):
    """The allocator could not answer. Operational, never a verdict about a
    transaction: storage down, worker gone, mapping unreadable."""


def publish_to_db(allocator: "Allocator", store=None) -> dict:
    """Publish a block's delta as EXACT bindings, in the store's transaction."""
    import db as _db
    store = store or _db
    delta = allocator.delta()
    if not delta:
        return {}
    try:
        store.publish_shrink_ids(delta, allocator.epoch)
    except ValueError as exc:
        raise AllocatorConflict(str(exc)) from exc
    except Exception as exc:
        raise AllocationUnavailable(str(exc)) from exc
    return delta


def publish(store, allocator: Allocator) -> dict:
    """Publish ONE block delta, in the store's own transaction.

    Aborts (AllocatorConflict) if the epoch moved, if an id is taken, or if a key
    is already bound to a different id. Never renumbers a value already embedded
    in validated runtime text.
    """
    delta = allocator.delta()
    if not delta:
        return {}
    epoch, committed = store.snapshot_mapping()
    if epoch != allocator.epoch:
        raise AllocatorConflict(
            f"mapping epoch moved {allocator.epoch} -> {epoch}; attempt is stale"
        )
    taken = {v: k for k, v in committed.items()}
    for key, value in delta.items():
        bound = committed.get(key)
        if bound is not None and bound != value:
            raise AllocatorConflict(f"{key!r} already bound to {bound}, plan says {value}")
        owner = taken.get(value)
        if owner is not None and owner != key:
            raise AllocatorConflict(f"id {value} already belongs to {owner!r}")
    store.publish_mapping(delta, expected_epoch=allocator.epoch)
    return delta
