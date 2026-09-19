"""W2: the four states, kept apart.

Measured facts these encode: a stream's width is committed by the first ACCEPTED
revision and OUTLIVES the rule that introduced it (it still applies after that
rule is superseded and no longer appears in `current_spec()`); and building
another interface in the same process does not undo any of it.
"""
import pytest

import tau_evaluator_state as st
import tau_shrink


I12 = st.qualified(st.INPUT, 12)
O12 = st.qualified(st.OUTPUT, 12)


def _prepared(shrunk=(), wide=()):
    return tau_shrink.PreparedTauSpec("c", "r", bool(shrunk), frozenset(shrunk), frozenset(wide))


# --- identity -----------------------------------------------------------------

def test_input_and_output_streams_are_different_identities():
    assert I12 != O12
    state = st.EvaluatorState()
    state.process.commit(I12, 8)
    assert state.process.width_of(I12) == 8
    assert state.process.width_of(O12) is None


def test_stream_side_must_be_explicit():
    with pytest.raises(ValueError):
        st.qualified("x", 12)


# --- process commitments ------------------------------------------------------

def test_a_commitment_cannot_be_changed_in_process():
    state = st.EvaluatorState()
    state.process.commit(I12, 384)
    with pytest.raises(ValueError):
        state.process.commit(I12, 8)


def test_commitments_survive_an_interface_replacement():
    """`kill_tau_process` builds another interface in the SAME process, and
    `restore_full_tau_spec` reloads a spec; neither undoes a native type."""
    state = st.EvaluatorState()
    state.set_encoding(I12, st.StreamEncoding(384, 8, st.INTERNED, mapping_epoch=1))
    before = state.process.committed()
    state.new_generation("kill_tau_process")
    assert state.process.committed() == before
    assert state.generation == 1


def test_there_is_no_way_to_clear_a_commitment():
    """Deleting the bookkeeping would imitate a rollback the engine never did."""
    assert not hasattr(st.ProcessTypeCommitments, "clear")
    assert not hasattr(st.ProcessTypeCommitments, "forget")


# --- encoding context ---------------------------------------------------------

def test_encoding_records_more_than_a_width():
    """An ordinary bv[8] stream and a bv[384] stream carried as bv[8] ids need
    different input handling, and the intern key is width-tagged."""
    plain = st.StreamEncoding(8, 8, st.PLAIN)
    interned = st.StreamEncoding(384, 8, st.INTERNED, mapping_epoch=3)
    assert plain.runtime_width == interned.runtime_width
    assert not plain.is_interned and interned.is_interned
    assert interned.canonical_width == 384
    assert interned.mapping_epoch == 3


def test_apply_prepared_records_both_sides():
    state = st.EvaluatorState()
    state.apply_prepared(_prepared(shrunk=(12,), wide=(3,)), width=8, mapping_epoch=1)
    assert state.encoding_of(I12).is_interned
    assert state.encoding_of(st.qualified(st.INPUT, 3)).encoding == st.PLAIN
    assert state.interned_streams() == frozenset({12})


def test_a_later_plain_mention_does_not_downgrade_an_interned_commitment():
    state = st.EvaluatorState()
    state.apply_prepared(_prepared(shrunk=(12,)), width=8, mapping_epoch=1)
    state.apply_prepared(_prepared(wide=(12,)), width=8, mapping_epoch=1)
    assert state.encoding_of(I12).is_interned


# --- the compatibility question ----------------------------------------------

def test_a_wide_stream_against_an_interned_commitment_conflicts():
    state = st.EvaluatorState()
    state.apply_prepared(_prepared(shrunk=(12,)), width=8, mapping_epoch=1)
    assert state.conflicts(_prepared(wide=(12,)), width=8) == frozenset({12})


def test_an_interned_stream_against_a_plain_commitment_conflicts():
    """The mirror direction: boot classified the composed spec as unshrinkable,
    then an incremental rule wants to shrink the same stream."""
    state = st.EvaluatorState()
    state.apply_prepared(_prepared(wide=(12,)), width=384, mapping_epoch=None)
    assert state.conflicts(_prepared(shrunk=(12,)), width=8) == frozenset({12})


def test_no_conflict_when_nothing_was_committed():
    state = st.EvaluatorState()
    assert state.conflicts(_prepared(shrunk=(12,)), width=8) == frozenset()
    assert state.conflicts(_prepared(wide=(12,)), width=8) == frozenset()


# --- health and generations ---------------------------------------------------

def test_an_uncertain_failure_marks_the_evaluator_unusable():
    state = st.EvaluatorState()
    state.mark_unusable("step raised after native entry")
    assert not state.healthy and state.unusable_reason
    state.mark_reconstructed()
    assert state.healthy and state.unusable_reason is None


def test_state_revision_advances_without_an_interface_swap():
    """A generation check alone cannot tell that execution moved on."""
    state = st.EvaluatorState()
    gen, rev = state.generation, state.state_revision
    state.advance()
    assert state.generation == gen and state.state_revision > rev


def test_snapshot_carries_both_revisions():
    state = st.EvaluatorState()
    state.apply_prepared(_prepared(shrunk=(12,)), width=8, mapping_epoch=1)
    snap = state.snapshot()
    assert snap["interned"] == [12]
    assert snap["committed"]["i12"] == 8
    assert "generation" in snap and "state_revision" in snap
