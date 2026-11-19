"""`running_spec`: the specification the engine runs, rebuilt by the engine from
the committed rule history (tau_running_spec.py), and where the two reads carry it.

The engine itself is replaced here by a recording fake; the real engine runs the
same path in tests/test_running_spec_native.py.
"""
from __future__ import annotations

import hashlib
import json
import threading
import types
from unittest.mock import patch

import pytest

import db
import tau_authority
import tau_running_spec as rs
from commands import getaccountrules, getgovernance

A = "always ( o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24] )."
B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
BASE = "always ( o0[t]:tau = 0 )."


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rev(seq, rule, outcome="ACCEPTED_CHANGED"):
    return {"seq": seq, "kind": "revision", "rule_text": rule, "units": [],
            "outcome": outcome, "link": f"l{seq}"}


def _reset(seq, units):
    return {"seq": seq, "kind": "reset", "rule_text": None,
            "units": [(u, True) for u in units], "outcome": None, "link": f"l{seq}"}


class FakeEngine:
    """Records what it is fed; its spec is the units joined, newest last."""

    def __init__(self, refuse=()):
        self.spawned = 0
        self.fed = []
        self.refuse = set(refuse)

    def __call__(self):
        self.spawned += 1
        engine, units = self, []

        class Session:
            def init(self, base):
                engine.fed.append(("init", base))

            def revise(self, text, cid):
                engine.fed.append(("revise", text))
                if text in engine.refuse:
                    return {"outcome": "REJECTED_RULE"}
                units.append(text)
                return {"outcome": "ACCEPTED_CHANGED"}

            def current_spec(self):
                return " && ".join(units)

            def close(self):
                engine.fed.append(("close",))

        return Session()


class FakeStore:
    def __init__(self, head, entries):
        self.head, self.entries = head, list(entries)

    def committed_rule_history(self):
        return self.head, list(self.entries)


@pytest.fixture(autouse=True)
def _fresh_cache():
    rs.reset_cache()
    yield
    rs.reset_cache()


# --- which rules -------------------------------------------------------------

def test_units_are_the_last_reset_then_each_accepted_revision():
    entries = [_rev(1, "old"), _reset(2, ["c1", "c2"]), _rev(3, A), _rev(4, B)]
    assert rs.rule_units(entries) == ["c1", "c2", A, B]


def test_without_a_reset_every_accepted_revision_counts_from_the_start():
    assert rs.rule_units([_rev(1, A), _rev(2, B)]) == [A, B]


def test_a_revision_the_engine_did_not_accept_is_left_out():
    entries = [_rev(1, A), _rev(2, "bad", outcome="REJECTED_RULE"),
               _rev(3, B, outcome="ACCEPTED_NOOP")]
    assert rs.rule_units(entries) == [A, B]


# --- what the engine says ------------------------------------------------------

def test_the_text_is_the_engines_with_its_hash_and_the_head_it_was_read_at():
    engine = FakeEngine()
    out = rs.running_spec(FakeStore("h1", [_rev(1, A), _rev(2, B)]),
                          baseline=BASE, spawn=engine)
    assert out == {"text": f"{A} && {B}", "sha256": _sha(f"{A} && {B}"),
                   "block_hash": "h1"}
    assert engine.fed == [("init", BASE), ("revise", A), ("revise", B), ("close",)]


def test_it_is_rebuilt_only_when_a_rule_entry_commits():
    engine = FakeEngine()
    store = FakeStore("h1", [_rev(1, A)])
    first = rs.running_spec(store, baseline=BASE, spawn=engine)
    store.head = "h2"   # a block with no rule entry
    second = rs.running_spec(store, baseline=BASE, spawn=engine)
    assert engine.spawned == 1
    assert second["sha256"] == first["sha256"] and second["block_hash"] == "h2"

    store.entries.append(_rev(2, B))
    store.head = "h3"
    third = rs.running_spec(store, baseline=BASE, spawn=engine)
    assert engine.spawned == 2
    assert third["text"] == f"{A} && {B}" and third["block_hash"] == "h3"


def test_a_unit_the_engine_does_not_accept_again_gives_no_text():
    engine = FakeEngine(refuse={B})
    store = FakeStore("h1", [_rev(1, A), _rev(2, B)])
    out = rs.running_spec(store, baseline=BASE, spawn=engine)
    assert out["text"] is None and out["sha256"] is None and out["block_hash"] == "h1"
    assert "unit 1 was not accepted again" in out["unavailable"]
    assert engine.fed[-1] == ("close",), "the worker is closed on failure too"
    rs.running_spec(store, baseline=BASE, spawn=engine)
    assert engine.spawned == 2, "a failure is not cached"


def test_a_lost_worker_is_reported_as_unavailable_not_raised():
    import tau_speculation

    class Lost:
        def init(self, base):
            raise tau_speculation.WorkerTimeout("killed after its deadline")

        def close(self):
            raise tau_speculation.WorkerLost("already gone")

        def kill(self):
            pass

    out = rs.running_spec(FakeStore("h1", [_rev(1, A)]), baseline=BASE, spawn=Lost)
    assert out["text"] is None and out["block_hash"] == "h1"
    assert "WorkerTimeout" in out["unavailable"]


def test_a_node_without_the_authority_starts_no_engine():
    owner = tau_authority.AuthoritativeTauOwner()
    assert owner.enabled is False
    with patch.object(tau_authority, "owner", return_value=owner), \
            patch.object(rs, "_spawn", side_effect=AssertionError("spawned")):
        out = rs.at_head()
    assert out["text"] is None and out["block_hash"] is None
    assert out["unavailable"] == "this node runs without the authoritative engine"


# --- the store -----------------------------------------------------------------

def _journal_row(seq, kind, rule=None, units=(), outcome=None, prev=None):
    return {"seq": seq, "kind": kind, "phase": "apply", "rule_text": rule,
            "inputs": {"i1": "5"} if kind == "step" else {}, "target": 0,
            "accumulate": True, "units": [list(u) for u in units], "outcome": outcome,
            "result_fingerprint": "fp", "identity": None, "prev": prev,
            "link": f"link{seq}"}


def test_the_store_reads_head_and_rule_entries_together_without_steps(temp_database):
    db.commit_prepared_block(
        execution_id="exec-1", tip="tip-1", parent="tip-0",
        journal_entries=[
            _journal_row(1, "reset", units=[("c1", True)]),
            _journal_row(2, "revision", rule=A, outcome="ACCEPTED_CHANGED", prev="link1"),
            _journal_row(3, "step", prev="link2"),
            _journal_row(4, "revision", rule=B, outcome="ACCEPTED_CHANGED", prev="link3"),
        ],
        expected_journal_seq=0, allocation_delta={},
        expected_epoch=db.shrink_mapping_epoch(), journal_head="link4",
        allocator_digest="d", plan_id="p",
        canonical=dict(head_hash="tip-1", head_num=1, balances={}, sequences={},
                       application_rules="", consensus_rules="", active_consensus_id="",
                       pending_updates=[], votes=[], scheduled=[], archival=[]),
    )
    head, entries = db.committed_rule_history()
    assert head == "tip-1"
    assert [(e["seq"], e["kind"]) for e in entries] == [(1, "reset"), (2, "revision"),
                                                         (4, "revision")]
    assert entries[0]["units"] == [("c1", True)]
    assert rs.rule_units(entries) == ["c1", A, B]


# --- the two reads ---------------------------------------------------------------

def _chain_state(head):
    return types.SimpleNamespace(
        _balance_lock=threading.Lock(), _sequence_lock=threading.Lock(),
        _rules_lock=threading.Lock(), _lifecycle_manager=None,
        _application_rules_state="", _canonical_head_hash=head,
    )


def test_getaccountrules_reads_the_spec_at_the_head_it_answers_for():
    answers = iter([{"text": "x", "sha256": "s", "block_hash": "moved"},
                    {"text": "y", "sha256": "t", "block_hash": "h1"}])
    with patch.object(rs, "at_head", side_effect=lambda store=None: next(answers)):
        view, running = getaccountrules.tip_and_running_spec(_chain_state("h1"))
    assert view[0] == "h1" and running["block_hash"] == "h1" and running["text"] == "y"


def test_getaccountrules_keeps_an_unavailable_answer_as_it_is():
    gone = {"text": None, "sha256": None, "block_hash": None, "unavailable": "why"}
    with patch.object(rs, "at_head", return_value=gone) as read:
        _, running = getaccountrules.tip_and_running_spec(_chain_state("h1"))
    assert running == gone and read.call_count == 1


class _GovState:
    class _Lock:
        def __enter__(self):
            pass

        def __exit__(self, *a):
            pass

    def __init__(self):
        from consensus.governance import ConsensusLifecycleManager
        self._balance_lock = self._sequence_lock = self._rules_lock = self._Lock()
        self._active_consensus_id = None
        self._consensus_rules_state = "rules"
        self._application_rules_state = f"{A}\n{B}"
        self._lifecycle_manager = ConsensusLifecycleManager(active_validators=[f"{1:096x}"])


class _GovDB:
    def get_canonical_head_block(self):
        return {"block_hash": "h1", "header": {"block_number": 3}}


def test_getgovernance_lists_stored_units_and_the_running_spec():
    running = {"text": f"{B}", "sha256": _sha(B), "block_hash": "h1"}
    with patch.object(rs, "at_head", return_value=running) as read:
        data = json.loads(getgovernance.execute(
            "getgovernance", types.SimpleNamespace(chain_state=_GovState(), db=_GovDB())))["data"]
    assert data["application_rules"] == f"{A}\n{B}"
    assert data["running_spec"] == running
    assert read.call_count == 1


def test_getgovernance_reads_the_spec_again_when_a_block_moved_the_head():
    answers = iter([{"text": "x", "sha256": "s", "block_hash": "h0"},
                    {"text": "y", "sha256": "t", "block_hash": "h1"}])
    with patch.object(rs, "at_head", side_effect=lambda store=None: next(answers)):
        data = json.loads(getgovernance.execute(
            "getgovernance", types.SimpleNamespace(chain_state=_GovState(), db=_GovDB())))["data"]
    assert data["running_spec"]["block_hash"] == "h1" and data["running_spec"]["text"] == "y"
