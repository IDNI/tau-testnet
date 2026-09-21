"""Isolating the interpreter does not isolate the allocator.

`db.get_shrink_id` inserts and COMMITS, so a speculative evaluation that mentions
a never-before-seen address moves the committed mapping even when the proposal is
rejected and its worker destroyed. Measured before the fix: one rejected proposal
took the committed max shrink id from 0 to 1 -- capacity and the mapping epoch
burned for a block that never existed.
"""
import pytest

import db
import tau_shrink as ts

ADDR = "ab" * 48
OTHER = "cd" * 48


def test_speculative_interning_publishes_nothing(temp_database):
    before = db.get_max_shrink_id()
    with ts.speculative_allocation() as alloc:
        first = ts.intern_value(ADDR, 384)
        second = ts.intern_value(OTHER, 384)
        assert first != second, "distinct values must not collide speculatively"
    assert db.get_max_shrink_id() == before
    assert db.lookup_shrink_id(ts.canonical_intern_key(ADDR, 384)) is None
    assert sorted(alloc.minted.values()) == [first, second]


def test_speculative_ids_start_above_the_committed_high_water(temp_database):
    committed = ts.intern_value(ADDR, 384)
    with ts.speculative_allocation():
        speculative = ts.intern_value(OTHER, 384)
    assert speculative > committed


def test_committed_ids_are_reused_not_reminted(temp_database):
    """A speculative evaluation must agree with the committed mapping wherever one
    exists, or its comparisons answer differently from the authoritative path."""
    committed = ts.intern_value(ADDR, 384)
    with ts.speculative_allocation():
        assert ts.intern_value(ADDR, 384) == committed


def test_the_override_is_removed_afterwards(temp_database):
    before = db.get_max_shrink_id()
    with ts.speculative_allocation():
        ts.intern_value(ADDR, 384)
    ts.intern_value(OTHER, 384)          # outside the block: this one commits
    assert db.get_max_shrink_id() > before


def test_nesting_restores_the_previous_allocator(temp_database):
    with ts.speculative_allocation() as outer:
        ts.intern_value(ADDR, 384)
        with ts.speculative_allocation():
            ts.intern_value(OTHER, 384)
        assert ts._allocator is outer
    assert ts._allocator is None


def test_a_rejected_proposal_leaves_the_epoch_untouched(temp_database):
    """The regression in the shape the review asked for."""
    before_max = db.get_max_shrink_id()
    with ts.speculative_allocation():
        ts.intern_value(ADDR, 384)
        ts.intern_value(OTHER, 384)
        # proposal rejected: the block never happens
    assert db.get_max_shrink_id() == before_max


def test_an_accepted_value_publishes_exactly_what_was_tested(temp_database):
    """The other half: when the proposal IS accepted, the authoritative path
    interns the same canonical values -- the ids may differ, because equality is
    invariant under any injective relabeling and a speculative id never leaves
    the worker, but the VALUES must be the ones that were evaluated."""
    with ts.speculative_allocation():
        ts.intern_value(ADDR, 384)
    published = ts.intern_value(ADDR, 384)
    assert db.lookup_shrink_id(ts.canonical_intern_key(ADDR, 384)) == published
