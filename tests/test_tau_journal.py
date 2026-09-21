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
        tj.compare(expected, {"o5": "0"}, seq=seq)       # different -> caught


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
