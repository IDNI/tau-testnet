"""M2/C3/C5: block-root allocation, inheritance, and a retry that makes progress.

Measured defects this replaces: `db.get_shrink_id` commits immediately (so a
rejected transaction permanently burns capacity, and an intern inside an enclosing
canonical transaction commits it early), and it persists the id BEFORE the width
check rejects it -- which is the only reason a post-overflow retry currently picks
a wider width at all.
"""
import pytest

import tau_allocator as alloc


class FakeStore:
    """Stands in for the committed mapping table."""

    def __init__(self, mapping=None):
        self.committed = dict(mapping or {})
        self.epoch = len(self.committed)
        self.publishes = []

    def snapshot_mapping(self):
        return self.epoch, dict(self.committed)

    def publish_mapping(self, delta, expected_epoch):
        assert expected_epoch == self.epoch
        self.committed.update(delta)
        self.epoch += 1
        self.publishes.append(dict(delta))


def _block(store, width=8):
    snap = alloc.MappingSnapshot.capture(store)
    return alloc.Allocator(snap, width=width, label="block")


# --- inheritance (C3) ---------------------------------------------------------

def test_two_accepted_transactions_get_distinct_ids(): 
    store = FakeStore({"bv384:aa": 100})
    block = _block(store, width=16)
    a = block.child("A")
    assert a.id_for("bv384:alice") == 101
    block.merge(a)
    b = block.child("B")
    # B reads THROUGH the block allocator, so it cannot reuse 101 for Bob
    assert b.id_for("bv384:bob") == 102
    block.merge(b)
    assert block.delta() == {"bv384:alice": 101, "bv384:bob": 102}


def test_the_same_value_in_two_transactions_resolves_to_one_id():
    store = FakeStore({"bv384:aa": 100})
    block = _block(store, width=16)
    a = block.child("A")
    first = a.id_for("bv384:alice")
    block.merge(a)
    b = block.child("B")
    assert b.id_for("bv384:alice") == first
    block.merge(b)
    assert block.delta() == {"bv384:alice": first}


def test_a_rejected_transaction_contributes_nothing():
    """Isolation, not numeric novelty: B leaves no mapping entry and no capacity
    reservation, so C may legitimately mint the same NUMBER for another value."""
    store = FakeStore({"bv384:aa": 100})
    block = _block(store, width=16)
    a = block.child("A")
    a.id_for("bv384:alice")
    block.merge(a)

    b = block.child("B")
    b_id = b.id_for("bv384:bob")
    block.discard(b)

    c = block.child("C")
    c_id = c.id_for("bv384:carol")
    block.merge(c)

    assert c_id == b_id                      # numeric reuse after disposal is fine
    assert "bv384:bob" not in block.delta()  # but B contributed no entry
    assert block.delta() == {"bv384:alice": 101, "bv384:carol": 102}


def test_a_discarded_context_cannot_be_used_again():
    store = FakeStore()
    block = _block(store, width=16)
    b = block.child("B")
    b.id_for("bv384:bob")
    block.discard(b)
    with pytest.raises(RuntimeError):
        b.id_for("bv384:other")
    with pytest.raises(ValueError):
        block.merge(b)


def test_every_context_is_identifiable():
    store = FakeStore()
    block = _block(store)
    assert block.child("A").context_id != block.child("A").context_id


# --- publication --------------------------------------------------------------

def test_publication_is_one_delta_for_the_block():
    store = FakeStore({"bv384:aa": 100})
    block = _block(store, width=16)
    for name in ("alice", "bob"):
        child = block.child(name)
        child.id_for(f"bv384:{name}")
        block.merge(child)
    alloc.publish(store, block)
    assert len(store.publishes) == 1
    assert store.committed["bv384:alice"] == 101
    assert store.committed["bv384:bob"] == 102


def test_a_moved_epoch_makes_the_attempt_stale_not_invalid():
    store = FakeStore({"bv384:aa": 100})
    block = _block(store, width=16)
    child = block.child("A")
    child.id_for("bv384:alice")
    block.merge(child)
    store.publish_mapping({"bv384:someone_else": 101}, expected_epoch=store.epoch)
    with pytest.raises(alloc.AllocatorConflict) as exc:
        alloc.publish(store, block)
    assert "stale" in str(exc.value)


def test_publication_never_renumbers_an_embedded_id():
    store = FakeStore({"bv384:aa": 100})
    block = _block(store, width=16)
    child = block.child("A")
    child.id_for("bv384:alice")          # -> 101, now embedded in validated text
    block.merge(child)
    store.committed["bv384:zed"] = 101   # someone else took 101
    with pytest.raises(alloc.AllocatorConflict):
        alloc.publish(store, block)
    assert store.publishes == []


def test_speculation_does_not_touch_the_store():
    """Admission and preflight must not consume live capacity."""
    store = FakeStore({"bv384:aa": 100})
    block = _block(store, width=16)
    for i in range(50):
        child = block.child("probe")
        child.id_for(f"bv384:probe{i}")
        block.discard(child)
    assert store.committed == {"bv384:aa": 100}
    assert store.publishes == []
    assert store.epoch == 1


# --- capacity (C5) ------------------------------------------------------------

def test_capacity_exceeded_carries_the_retained_plan():
    store = FakeStore({f"bv384:{i}": i for i in range(1, 255)})   # bv[8] is full
    block = _block(store, width=8)
    child = block.child("A")
    with pytest.raises(alloc.AllocatorCapacityExceeded) as exc:
        child.id_for("bv384:one_too_many")
    assert exc.value.required_id == 255
    assert exc.value.width == 8


def test_the_retry_width_comes_from_the_plan_not_the_store():
    """The C5 trap: sizing a retry from the unchanged committed high-water mark
    reproduces the same overflow forever, because the speculative ids that caused
    it were never (and must never be) written."""
    store = FakeStore({f"bv384:{i}": i for i in range(1, 250)})
    block = _block(store, width=16)         # room to plan
    child = block.child("A")
    for i in range(20):                     # plan past the bv[8] ceiling
        child.id_for(f"bv384:new{i}")
    block.merge(child)
    assert max(block.retained_plan().values()) > alloc.usable_ceiling(8)
    assert block.required_width() == 16
    # and the store, untouched, would still have suggested bv[8]
    assert alloc.width_for_max_id(store.snapshot_mapping()[0]) == 8


def test_width_ladder():
    assert alloc.usable_ceiling(8) == 254
    assert alloc.width_for_max_id(254) == 8
    assert alloc.width_for_max_id(255) == 16
    assert alloc.width_for_max_id(65534) == 16
    assert alloc.width_for_max_id(65535) == 24
