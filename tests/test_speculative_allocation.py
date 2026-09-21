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
    assert sorted(alloc.delta().values()) == [first, second]


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


# --- the overlay hierarchy ----------------------------------------------------

import tau_allocator as alloc_mod


def _proposal():
    return alloc_mod.Allocator(alloc_mod.DbMappingSnapshot(),
                               width=16, label="proposal")


def test_an_accepted_transaction_is_visible_to_the_next_one(temp_database):
    """The block-prefix property: C must not be able to mint a colliding id for a
    different value just because it captured the same high-water mark as A."""
    proposal = _proposal()
    a = proposal.child("A")
    alice = a.id_for("bv384:alice")
    proposal.merge(a)

    c = proposal.child("C")
    carol = c.id_for("bv384:carol")
    proposal.merge(c)

    assert alice != carol
    assert proposal.delta() == {"bv384:alice": alice, "bv384:carol": carol}


def test_a_rejected_transaction_is_invisible_and_its_number_is_free(temp_database):
    """What must not survive B is the MAPPING, not necessarily the integer."""
    proposal = _proposal()
    a = proposal.child("A")
    a.id_for("bv384:alice")
    proposal.merge(a)

    b = proposal.child("B")
    bob = b.id_for("bv384:bob")
    proposal.discard(b)

    c = proposal.child("C")
    carol = c.id_for("bv384:carol")
    proposal.merge(c)

    assert carol == bob, "a fully disposed context's number may be reused"
    assert "bv384:bob" not in proposal.delta()


def test_the_same_new_value_in_two_transactions_gets_one_id(temp_database):
    proposal = _proposal()
    a = proposal.child("A")
    first = a.id_for("bv384:alice")
    proposal.merge(a)
    c = proposal.child("C")
    assert c.id_for("bv384:alice") == first


def test_a_committed_binding_cannot_be_shadowed(temp_database):
    """Every child must resolve a committed value to its committed id, even
    transiently."""
    committed = ts.intern_value(ADDR, 384)
    proposal = _proposal()
    child = proposal.child("A")
    assert child.id_for(ts.canonical_intern_key(ADDR, 384)) == committed
    assert proposal.delta() == {}, "resolving a committed binding allocates nothing"


def test_a_discarded_transaction_cannot_be_merged_or_reused(temp_database):
    proposal = _proposal()
    b = proposal.child("B")
    b.id_for("bv384:bob")
    proposal.discard(b)
    with pytest.raises(RuntimeError):
        b.id_for("bv384:other")
    with pytest.raises(ValueError):
        proposal.merge(b)


def test_width_planning_uses_the_proposal_high_water(temp_database, monkeypatch):
    """The 254 -> 255 boundary has to be known before the worker that embeds those
    ids is built, not discovered at publication."""
    proposal = alloc_mod.Allocator(alloc_mod.DbMappingSnapshot(), width=16)
    for i in range(3):
        child = proposal.child(f"t{i}")
        child.id_for(f"bv384:v{i}")
        proposal.merge(child)
    assert proposal.required_width() == alloc_mod.width_for_max_id(
        max(proposal.retained_plan().values())
    )


def test_publication_commits_exactly_the_tested_ids(temp_database):
    proposal = _proposal()
    child = proposal.child("A")
    planned = child.id_for("bv384:alice")
    proposal.merge(child)
    alloc_mod.publish_to_db(proposal)
    assert db.lookup_shrink_id("bv384:alice") == planned


def test_a_moved_epoch_aborts_publication_entirely(temp_database):
    proposal = _proposal()
    child = proposal.child("A")
    child.id_for("bv384:alice")
    child.id_for("bv384:bob")
    proposal.merge(child)
    ts.intern_value(OTHER, 384)          # someone else commits first
    with pytest.raises(alloc_mod.AllocatorConflict):
        alloc_mod.publish_to_db(proposal)
    assert db.lookup_shrink_id("bv384:alice") is None, "no partial publication"
    assert db.lookup_shrink_id("bv384:bob") is None


def test_the_epoch_moves_on_any_committed_change(temp_database):
    """`max(id)` alone would not: a mapping can change without the maximum moving,
    and a proposal validated against the old one would publish into a table it no
    longer describes."""
    before = db.shrink_mapping_epoch()
    ts.intern_value(ADDR, 384)
    assert db.shrink_mapping_epoch() != before


def test_the_epoch_is_a_mapping_digest_not_a_count(temp_database):
    """`(count, max)` is unchanged by a swap -- A->1,B->2 becoming A->2,B->1 --
    yet the mapping identity is different, and a proposal validated against the
    old one would publish into a table it no longer describes."""
    ts.intern_value(ADDR, 384)
    ts.intern_value(OTHER, 384)
    before = db.shrink_mapping_epoch()

    key_a = ts.canonical_intern_key(ADDR, 384)
    key_b = ts.canonical_intern_key(OTHER, 384)
    id_a, id_b = db.lookup_shrink_id(key_a), db.lookup_shrink_id(key_b)
    with db._db_lock:
        cur = db._db_conn.cursor()
        cur.execute('UPDATE tau_shrink_ids SET key = ? WHERE id = ?', ("tmp", id_a))
        cur.execute('UPDATE tau_shrink_ids SET key = ? WHERE id = ?', (key_a, id_b))
        cur.execute('UPDATE tau_shrink_ids SET key = ? WHERE id = ?', (key_b, id_a))
        db._db_conn.commit()

    assert db.shrink_mapping_epoch() != before, "a swap left the epoch unchanged"


def test_a_speculative_session_cannot_intern_into_the_live_table(temp_database, monkeypatch):
    """The API invariant: a speculative session owns its overlay and installs it
    around every dispatch, so a caller cannot forget to. There is deliberately no
    "no context, use the committed allocator" fallback."""
    import tau_session

    class _FakeSpec:
        def revise(self, text, cid):
            ts.intern_value(ADDR, 384)          # the encoder runs here
            return {"outcome": "ACCEPTED_CHANGED"}

        def step(self, inputs):
            ts.intern_value(OTHER, 384)
            return {"outputs": {}}

        def kill(self):
            pass

    before = db.shrink_mapping_epoch()
    session = tau_session.WorkerSession(_FakeSpec())
    session.apply_rule("R")
    session.evaluate({12: "x"}, multi=True)
    assert db.shrink_mapping_epoch() == before, "a speculative dispatch reached the live table"
    assert sorted(session.allocation.delta().values()) == [1, 2]
