"""Three records, and what may go in each.

The separation is the point. Logging every Tau call into one record and replaying
it would faithfully reproduce the contamination isolation just removed: an
advisory query that steps the evaluator changes what the next transaction reads,
and replaying that step reproduces the change rather than eliminating it.
"""
import pytest

import tau_journal as tj


def test_only_authoritative_phases_reach_the_committed_journal():
    journal = tj.Journal(authoritative=True)
    journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text="R")
    journal.record(tj.STEP, phase=tj.PHASE_GOVERNANCE, inputs={1: "5"})
    for phase in (tj.PHASE_ADVISORY, tj.PHASE_VALIDATION, tj.PHASE_SPECULATIVE):
        with pytest.raises(ValueError):
            journal.record(tj.STEP, phase=phase, inputs={1: "5"})
    assert len(journal) == 2


def test_the_operational_trace_cannot_be_replayed():
    """Not an oversight: making it replayable would make it easy to reintroduce
    exactly the contamination the isolation work removed."""
    assert not hasattr(tj.OperationalTrace, "replay_trace")
    trace = tj.OperationalTrace()
    trace.record(tj.PHASE_ADVISORY, {"inputs": {1: "0xff"}})
    assert len(trace) == 1


def test_the_trace_is_bounded():
    trace = tj.OperationalTrace(limit=10)
    for i in range(50):
        trace.record(tj.PHASE_ADVISORY, {"i": i})
    assert len(trace) == 10
    assert trace.entries()[-1]["i"] == 49


def test_entries_hold_canonical_values():
    """A journal of runtime-encoded values cannot be replayed at a different
    width or mapping without reinterpreting old ids as new values."""
    journal = tj.Journal()
    journal.record(tj.STEP, phase=tj.PHASE_APPLY,
                   inputs={12: "{ #x" + "aa" * 48 + " }:bv[384]"})
    replay = journal.replay_trace()[0]
    # keys are normalized to stream NAMES on the way in, so the record survives
    # serialization: JSON turns an integer key into a string, and a journal whose
    # keys change shape when written to disk cannot be replayed from disk
    assert replay["inputs"]["i12"].startswith("{ #x")
    assert "bv[384]" in replay["inputs"]["i12"]


def test_replay_does_not_carry_outputs():
    journal = tj.Journal()
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "5"},
                   result={"o5": "66"})
    assert "outputs" not in journal.replay_trace()[0]
    assert journal.entries()[0].result_fingerprint is not None


def test_a_divergent_replay_is_detected():
    journal = tj.Journal()
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "5"},
                   result={"o5": "66"})
    seq, expected = journal.fingerprints()[0]
    tj.compare(expected, {"o5": "66"}, seq=seq)          # same -> fine
    with pytest.raises(tj.DivergenceError):
        tj.compare(expected, {"o5": "0"}, seq=seq)       # different value -> caught
    with pytest.raises(tj.DivergenceError):
        tj.compare(expected, {}, seq=seq)                # stream stopped -> caught


def test_a_proposal_branch_records_separately():
    committed = tj.Journal()
    committed.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text="A")
    proposal = committed.branch()
    proposal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="B")
    assert len(committed) == 1, "a proposal must not touch the committed record"
    assert len(proposal) == 1


def test_a_rejected_proposal_is_simply_dropped():
    committed = tj.Journal()
    committed.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text="A")
    proposal = committed.branch()
    proposal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="B")
    del proposal                                          # rejected
    assert [e.rule_text for e in committed.entries()] == ["A"]


def test_an_accepted_proposal_is_adopted_as_committed_execution():
    committed = tj.Journal()
    committed.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text="A")
    proposal = committed.branch()
    proposal.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="C")
    committed.adopt(proposal)
    assert [e.rule_text for e in committed.entries()] == ["A", "C"]
    # and it is authoritative now: a reconstruction must replay it
    assert all(e.phase == tj.PHASE_APPLY for e in committed.entries())
    assert [e.seq for e in committed.entries()] == [1, 2]


def test_stream_keys_survive_serialization():
    journal = tj.Journal()
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={12: "a", "i3": "b", "4": "c"})
    keys = set(journal.entries()[0].inputs)
    assert keys == {"i12", "i3", "i4"}
    assert set(tj.Journal.deserialize(journal.serialize()).entries()[0].inputs) == keys


def test_a_journal_round_trips():
    journal = tj.Journal(anchor="block-7")
    journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text="R",
                   outcome="ACCEPTED_CHANGED", result={"o0": "F"})
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "5"}, target=5)
    restored = tj.Journal.deserialize(journal.serialize())
    assert restored.anchor == "block-7"
    assert restored.replay_trace() == journal.replay_trace()
    assert restored.fingerprints() == journal.fingerprints()


# --- which layer each evaluator writes to -------------------------------------

def test_advisory_work_never_reaches_the_committed_journal():
    """Recording it there would put it on the authoritative replay path, which is
    how the contamination the isolated evaluator removed would come back."""
    import tau_advisory

    before = len(tj.committed())
    trace_before = len(tj.trace())
    tau_advisory.AdvisoryEvaluator._trace("evaluate", {1: "0xff"}, (5,))
    assert len(tj.committed()) == before
    assert len(tj.trace()) == trace_before + 1


def test_a_worker_session_writes_only_to_its_proposal_journal():
    import tau_session as ts

    class _FakeSpec:
        def revise(self, text, cid):
            return {"outcome": "ACCEPTED_CHANGED", "ok": True}

        def step(self, inputs):
            return {"outputs": {"o5": "1"}}

        def kill(self):
            pass

    before = len(tj.committed())
    session = ts.WorkerSession(_FakeSpec())
    session.apply_rule("R")
    session.evaluate({1: "5"}, target=5)
    assert len(session.journal) == 2
    assert len(tj.committed()) == before, "a proposal must not touch the committed record"
    assert all(e.phase == tj.PHASE_SPECULATIVE for e in session.journal.entries())


# --- transaction children -----------------------------------------------------

def test_a_rejected_transaction_never_enters_the_proposal():
    """Rejection is a discard, not a filter. Appending a transaction's steps
    straight into the proposal means rebuilding the accepted prefix requires
    taking them back out -- the problem the speculative session exists to avoid,
    reproduced one layer up."""
    committed = tj.Journal()
    proposal = committed.branch()

    a = proposal.child("A")
    a.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="A")
    proposal.merge(a)

    b = proposal.child("B")
    b.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="B")
    proposal.discard(b)                       # fee rejected B

    c = proposal.child("C")
    c.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text="C")
    proposal.merge(c)

    assert [e.rule_text for e in proposal.entries()] == ["A", "C"]
    # rebuilding the accepted prefix is a replay, with no filtering step
    assert [t["rule_text"] for t in proposal.replay_trace()] == ["A", "C"]


def test_a_discarded_transaction_journal_refuses_further_use():
    committed = tj.Journal()
    proposal = committed.branch()
    b = proposal.child("B")
    b.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "5"})
    proposal.discard(b)
    with pytest.raises(ValueError):
        b.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "6"})
    with pytest.raises(ValueError):
        proposal.merge(b)


def test_merging_preserves_order_and_relinks():
    committed = tj.Journal()
    proposal = committed.branch()
    for name in ("A", "B"):
        tx = proposal.child(name)
        tx.record(tj.REVISION, phase=tj.PHASE_SPECULATIVE, rule_text=name)
        tx.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: name})
        proposal.merge(tx)
    assert [e.seq for e in proposal.entries()] == [1, 2, 3, 4]
    proposal.verify_chain()


# --- alias collisions ---------------------------------------------------------

def test_alias_spellings_of_one_stream_are_the_same_stream():
    journal = tj.Journal()
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={12: "x", "i12": "x"})
    assert journal.entries()[0].inputs == {"i12": "x"}


def test_conflicting_aliases_are_rejected_not_resolved():
    """Letting dict or JSON normalization pick a winner would record an input
    nobody supplied."""
    journal = tj.Journal()
    with pytest.raises(tj.AliasCollision):
        journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={12: "a", "i12": "b"})
    with pytest.raises(tj.AliasCollision):
        journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={"12": "a", "i12": "b"})


# --- semantic vs runtime fingerprints -----------------------------------------

def test_the_durable_fingerprint_survives_a_representation_change():
    """A reconstruction may legitimately change representation -- a capacity retry
    at a wider width -- so the divergence criterion must not bind to a node-local
    id or a runtime width."""
    journal = tj.Journal()
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "5"},
                   result={"o5": "66"},
                   runtime={"width": 8, "ids": {"i12": 3}, "epoch": 1})
    seq, expected = journal.fingerprints()[0]
    # same meaning, different runtime encoding -> NOT divergence
    tj.compare(expected, {"o5": "66"}, seq=seq)
    entry = journal.entries()[0]
    assert entry.runtime_fingerprint is not None
    assert entry.runtime_fingerprint != entry.result_fingerprint


def test_output_presence_is_part_of_the_meaning():
    journal = tj.Journal()
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "5"},
                   result={"o5": "1", "o8": "0"})
    seq, expected = journal.fingerprints()[0]
    with pytest.raises(tj.DivergenceError):
        tj.compare(expected, {"o5": "1"}, seq=seq)   # o8 stopped materializing


# --- structural tamper detection ----------------------------------------------

def _three_entry_journal():
    journal = tj.Journal()
    journal.record(tj.REVISION, phase=tj.PHASE_APPLY, rule_text="R")
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "5"}, result={"o5": "0"})
    journal.record(tj.STEP, phase=tj.PHASE_APPLY, inputs={1: "9"}, result={"o5": "5"})
    return journal


def test_an_intact_journal_verifies():
    _three_entry_journal().verify_chain()


def test_a_swapped_pair_is_detected():
    journal = _three_entry_journal()
    journal._entries[1], journal._entries[2] = journal._entries[2], journal._entries[1]
    with pytest.raises(tj.DivergenceError):
        journal.verify_chain()


def test_a_duplicated_entry_is_detected():
    journal = _three_entry_journal()
    journal._entries.insert(2, journal._entries[1])
    with pytest.raises(tj.DivergenceError):
        journal.verify_chain()


def test_a_dropped_entry_is_detected():
    journal = _three_entry_journal()
    del journal._entries[1]
    with pytest.raises(tj.DivergenceError):
        journal.verify_chain()


def test_an_altered_canonical_input_is_detected():
    import dataclasses
    journal = _three_entry_journal()
    journal._entries[1] = dataclasses.replace(journal._entries[1], inputs={"i1": "999"})
    with pytest.raises(tj.DivergenceError):
        journal.verify_chain()


def test_the_chain_survives_serialization():
    journal = _three_entry_journal()
    tj.Journal.deserialize(journal.serialize()).verify_chain()


# --- candidate identity -------------------------------------------------------

def test_a_runtime_payload_hash_is_not_an_identity():
    """Ids are private to an allocation context, so a discarded transaction B and
    a later transaction C can hold byte-identical runtime text meaning different
    things -- C legitimately reuses B's freed number for a different canonical
    value. Keying on the runtime hash would let a stale B validate C."""
    same_runtime = "always ( i12[t]:bv[8] = { 2 }:bv[8] -> o5[t]:bv[24] = { #x000001 }:bv[24] )."
    b = tj.candidate_identity("RULE FOR BOB", mapping_epoch="e1", width=8,
                              runtime_text=same_runtime)
    c = tj.candidate_identity("RULE FOR CAROL", mapping_epoch="e1", width=8,
                              runtime_text=same_runtime)
    assert b["runtime"] == c["runtime"], "the payloads really are identical"
    assert b["id"] != c["id"], "identity must not collapse to the payload"


def test_identity_binds_the_mapping_context():
    """The same canonical rule prepared against a different mapping is a
    different thing to have validated."""
    first = tj.candidate_identity("R", mapping_epoch="e1", width=8, runtime_text="X")
    second = tj.candidate_identity("R", mapping_epoch="e2", width=8, runtime_text="X")
    assert first["id"] != second["id"]


def test_identity_binds_the_representation():
    narrow = tj.candidate_identity("R", mapping_epoch="e1", width=8, runtime_text="X")
    wide = tj.candidate_identity("R", mapping_epoch="e1", width=16, runtime_text="X")
    assert narrow["id"] != wide["id"]


def test_identity_is_stable_for_the_same_candidate_and_context():
    a = tj.candidate_identity("R", mapping_epoch="e1", width=8, runtime_text="X")
    b = tj.candidate_identity("R", mapping_epoch="e1", width=8, runtime_text="X")
    assert a == b


def test_the_session_and_the_journal_share_one_vocabulary():
    """These were separate string literals, and a reconstruction compared a
    journal entry's kind against the session's -- replaying every recorded
    revision as an input step, so the rebuilt evaluator applied no rules at all
    and still looked like it worked."""
    import tau_session as ts
    assert ts.RULE == tj.REVISION
    assert ts.EVAL == tj.STEP


def test_a_step_fingerprint_covers_output_values_not_just_presence():
    """A worker's step outputs are indexed by stream number. Named `5` rather
    than `o5`, no step value ever reached the fingerprint: replay compared
    WHICH streams a step produced and never WHAT, so a reconstruction computing
    o5=1 where the original computed o5=0 verified clean."""
    import tau_journal as tj
    journal = tj.Journal(authoritative=False)
    journal.record(tj.STEP, phase=tj.PHASE_SPECULATIVE, inputs={1: "5"},
                   result={5: "0", 9: "10"})
    (seq, expected), = journal.fingerprints()
    tj.compare(expected, {5: "0", 9: "10"}, seq=seq)          # same meaning
    tj.compare(expected, {"o5": "0", "o9": "10"}, seq=seq)    # same, named
    with pytest.raises(tj.DivergenceError):
        tj.compare(expected, {5: "1", 9: "10"}, seq=seq)
