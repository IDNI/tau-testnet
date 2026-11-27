"""Rules in force at one block, tamper vs not-found, cache re-verification, and
the positive registry check (issue #42, our deltas over PR #144).

The engine itself is replaced here by a recording fake; the real engine runs
the same paths in tests/test_running_spec_native.py and scripts/e2e_rules_in_force.py.
"""
from __future__ import annotations

import hashlib
import json
import threading
import types
from dataclasses import replace as dc_replace
from unittest.mock import patch

import pytest

import db
import tau_authority
import tau_journal
import tau_running_spec as rs
from block import Block
from commands import getrulesinforce, gettxstatus
from tau_commit import _entry_row
from test_rule_change_requests import ALICE, BOB
from test_running_spec import A, B, BASE, FakeEngine
from test_tx_outcomes import _chain_of, _set_head

C = "always ( o27[t]:bv[24] = { 4 }:bv[24] )."


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _journal_rows():
    """A real journal: reset(c1), A, a step, B -- links and chain verify."""
    journal = tau_journal.Journal(authoritative=True)
    journal.record("reset", phase=tau_journal.PHASE_APPLY, units=[("c1", True)])
    journal.record("revision", phase=tau_journal.PHASE_APPLY, rule_text=A,
                   outcome="ACCEPTED_CHANGED")
    journal.record("step", phase=tau_journal.PHASE_APPLY, inputs={"i1": "5"})
    journal.record("revision", phase=tau_journal.PHASE_APPLY, rule_text=B,
                   outcome="ACCEPTED_CHANGED")
    return [_entry_row(e) for e in journal.entries()]


def _slim(rows):
    return [{
        "seq": int(r["seq"]), "kind": r["kind"], "rule_text": r["rule_text"],
        "units": [tuple(u) for u in (r["units"] or [])],
        "outcome": r["outcome"], "link": r["link"],
    } for r in rows if r["kind"] in ("reset", "revision")]


class FakeStore:
    """A store with commit records, journal heads and full rows."""

    def __init__(self, rows, commits, head="head"):
        self.rows = list(rows)          # live: tests mutate it to tamper
        self.commits = dict(commits)    # block_hash -> commit record
        self.head = head
        self.registry = {}              # (account, stream) -> body

    def committed_rule_history(self):
        return self.head, _slim(self.rows)

    def committed_rule_history_at(self, block_hash):
        commit = self.commits.get(block_hash)
        if commit is None:
            return None, None
        head_link = commit.get("journal_head")
        if head_link is None:
            return commit, []
        for index, row in enumerate(self.rows):
            if row["link"] == head_link:
                return commit, _slim(self.rows[:index + 1])
        raise rs.JournalTampered(
            f"commit record for block {block_hash} names journal head "
            f"{head_link}, but no journal row carries that link")

    def committed_journal_entries(self):
        return list(self.rows)

    def get_block_commit(self, tip):
        return self.commits.get(tip)

    def get_block_hash_by_number(self, number):
        for block_hash, commit in self.commits.items():
            if commit.get("block_number") == number:
                return block_hash
        return None

    def get_block_by_hash(self, block_hash):
        if block_hash in self.commits:
            return {"block_hash": block_hash,
                    "header": {"block_number": self.commits[block_hash]["block_number"]}}
        return None

    def get_canonical_head_block(self):
        return {"block_hash": self.head,
                "header": {"block_number": max(
                    (c["block_number"] for c in self.commits.values()), default=0)}}

    def load_rule_clauses(self):
        return [{"acceptor_pubkey": account, "target_stream": stream,
                 "clause_body": body}
                for (account, stream), body in self.registry.items()]

    def rule_clause_body(self, account, stream):
        return self.registry.get((str(account).lower(), int(stream)))

    def get_canonical_rule_effects(self, account, limit=20):
        return []


class OutputsFakeEngine:
    """A fake whose revise receipts carry outputs, like the real worker."""

    def __init__(self, outputs_by_text):
        self.outputs_by_text = outputs_by_text
        self.spawned = 0
        self.fed = []

    def __call__(self):
        self.spawned += 1
        engine, units = self, []

        class Session:
            def init(self, base):
                engine.fed.append(("init", base))

            def revise(self, text, cid):
                engine.fed.append(("revise", text))
                units.append(text)
                return {"outcome": "ACCEPTED_CHANGED",
                        "outputs": dict(engine.outputs_by_text.get(text, {}))}

            def current_spec(self):
                return " && ".join(units)

            def close(self):
                engine.fed.append(("close",))

        return Session()


def _store_two_blocks():
    rows = _journal_rows()
    commits = {
        "b1": {"journal_head": rows[1]["link"], "spec_revision": 1,
               "block_number": 1, "tip": "b1"},
        "b2": {"journal_head": rows[3]["link"], "spec_revision": 2,
               "block_number": 2, "tip": "b2"},
    }
    return FakeStore(rows, commits, head="b2")


@pytest.fixture(autouse=True)
def _fresh_cache():
    rs.reset_cache()
    yield
    rs.reset_cache()


# --- at-block ---------------------------------------------------------------

def test_at_block_replays_only_up_to_that_blocks_head():
    engine = FakeEngine()
    store = _store_two_blocks()
    first = rs.running_spec_at(store, "b1", baseline=BASE, spawn=engine)
    assert first == {"text": f"c1 && {A}", "sha256": _sha(f"c1 && {A}"),
                     "block_hash": "b1", "spec_revision": 1}
    second = rs.running_spec_at(store, "b2", baseline=BASE, spawn=engine)
    assert second == {"text": f"c1 && {A} && {B}",
                      "sha256": _sha(f"c1 && {A} && {B}"),
                      "block_hash": "b2", "spec_revision": 2}
    assert engine.spawned == 2, "each block rebuilds in its own fresh worker"


def test_two_rules_in_one_block_each_advance_spec_revision():
    engine = FakeEngine()
    store = _store_two_blocks()
    out = rs.running_spec_at(store, "b2", baseline=BASE, spawn=engine)
    assert out["spec_revision"] == 2
    assert [call for call in engine.fed if call[0] == "revise"] == [
        ("revise", "c1"), ("revise", A), ("revise", B)]


def test_a_resent_rule_revises_back_and_forth():
    journal = tau_journal.Journal(authoritative=True)
    journal.record("reset", phase=tau_journal.PHASE_APPLY, units=[("c1", True)])
    for rule in (A, B, A):
        journal.record("revision", phase=tau_journal.PHASE_APPLY, rule_text=rule,
                       outcome="ACCEPTED_CHANGED")
    rows = [_entry_row(e) for e in journal.entries()]
    store = FakeStore(rows, {"b3": {"journal_head": rows[-1]["link"],
                                    "spec_revision": 3, "block_number": 3,
                                    "tip": "b3"}}, head="b3")
    engine = FakeEngine()
    out = rs.running_spec_at(store, "b3", baseline=BASE, spawn=engine)
    assert out["text"] == f"c1 && {A} && {B} && {A}"
    assert [c for c in engine.fed if c[0] == "revise"] == [
        ("revise", "c1"), ("revise", A), ("revise", B), ("revise", A)]


def test_restart_rebuilds_the_same_text():
    store = _store_two_blocks()
    first = rs.running_spec_at(store, "b2", baseline=BASE, spawn=FakeEngine())
    rs.reset_cache()  # a restart drops the process cache
    second = rs.running_spec_at(store, "b2", baseline=BASE, spawn=FakeEngine())
    assert first == second


# --- head that moves mid-read (AtticKnight review, PR #180) ------------------

@pytest.mark.parametrize("advance_after", ["header", "rule_index"])
def test_head_summary_matches_one_committed_block(monkeypatch, advance_after):
    store = _store_two_blocks()
    container = types.SimpleNamespace(db=store)
    monkeypatch.setattr(tau_authority, "owner", lambda: types.SimpleNamespace(enabled=True))
    monkeypatch.setattr(tau_authority, "program_baseline", lambda: BASE)
    monkeypatch.setattr(rs, "_spawn", FakeEngine())

    def snapshot(command):
        data = json.loads(getrulesinforce.execute(command, container))["data"]
        return (data["block_hash"], data["block_number"], data["spec_revision"],
                data["running_spec"]["sha256"])

    committed = {snapshot("getrulesinforce 1"), snapshot("getrulesinforce 2")}
    assert len(committed) == 2
    rs.reset_cache()
    monkeypatch.setattr(store, "get_canonical_head_block",
                        lambda: store.get_block_by_hash("b1"))
    if advance_after == "rule_index":
        old_entries = _slim(store.rows[:2])
        monkeypatch.setattr(store, "committed_rule_history", lambda: ("b1", old_entries))
    assert snapshot("getrulesinforce") in committed


def test_block_with_no_rule_history_stays_the_same_after_blocks_arrive():
    store = _store_two_blocks()
    store.commits["b0"] = {"journal_head": None, "spec_revision": 0,
                           "block_number": 0, "tip": "b0"}
    later_rows, store.rows = store.rows, []
    first = rs.running_spec_at(store, "b0", baseline=BASE, spawn=FakeEngine())
    store.rows = later_rows
    rs.reset_cache()
    again = rs.running_spec_at(store, "b0", baseline=BASE, spawn=FakeEngine())
    assert again == first

# --- replay fingerprints ------------------------------------------------------

def _fingerprinted_store():
    journal = tau_journal.Journal(authoritative=True)
    journal.record("reset", phase=tau_journal.PHASE_APPLY, units=[("c1", True)])
    journal.record("revision", phase=tau_journal.PHASE_APPLY, rule_text=A,
                   outcome="ACCEPTED_CHANGED", result={"o26": "7", "o27": "9"})
    journal.record("revision", phase=tau_journal.PHASE_APPLY, rule_text=B,
                   outcome="ACCEPTED_CHANGED", result={"o26": "3"})
    rows = [_entry_row(e) for e in journal.entries()]
    return FakeStore(rows, {"b2": {"journal_head": rows[-1]["link"],
                                   "spec_revision": 2, "block_number": 2,
                                   "tip": "b2"}}, head="b2")


def test_a_replay_matching_the_recorded_fingerprints_is_served():
    engine = OutputsFakeEngine({A: {"o26": "7", "o27": "9"}, B: {"o26": "3"}})
    out = rs.running_spec_at(_fingerprinted_store(), "b2",
                             baseline=BASE, spawn=engine)
    assert out["text"] == f"c1 && {A} && {B}"


def test_a_replay_that_diverges_from_the_recorded_fingerprint_is_refused():
    engine = OutputsFakeEngine({A: {"o26": "7", "o27": "9"}, B: {"o26": "9"}})
    out = rs.running_spec_at(_fingerprinted_store(), "b2",
                             baseline=BASE, spawn=engine)
    assert out["text"] is None
    assert "diverged" in out["unavailable"]


# --- tamper vs not-found (gap c) ---------------------------------------------

def test_an_unknown_block_is_not_found_not_tamper():
    out = rs.running_spec_at(_store_two_blocks(), "missing",
                             baseline=BASE, spawn=FakeEngine())
    assert out["text"] is None and out["code"] == "NOT_FOUND"
    assert "no commit record" in out["unavailable"]


def test_deleted_journal_rows_are_tamper_not_not_found():
    store = _store_two_blocks()
    store.rows = store.rows[:1]  # the commit record stays; its rows are gone
    out = rs.running_spec_at(store, "b2", baseline=BASE, spawn=FakeEngine())
    assert out["text"] is None and out["code"] == "TAMPERED"
    assert "no commit record" not in out["unavailable"]


def test_an_altered_row_is_tamper_not_a_different_spec():
    store = _store_two_blocks()
    store.rows[1]["rule_text"] = C  # the stored link no longer matches the content
    out = rs.running_spec_at(store, "b2", baseline=BASE, spawn=FakeEngine())
    assert out["text"] is None and out["code"] == "TAMPERED"


def test_blocks_before_the_altered_row_still_answer():
    store = _store_two_blocks()
    store.rows[3]["rule_text"] = C  # alter the last row: block 2's revision only
    before = rs.running_spec_at(store, "b1", baseline=BASE, spawn=FakeEngine())
    assert before["text"] == f"c1 && {A}" and before["spec_revision"] == 1
    after = rs.running_spec_at(store, "b2", baseline=BASE, spawn=FakeEngine())
    assert after["text"] is None and after["code"] == "TAMPERED"


def test_a_forged_step_result_without_relinking_is_caught_by_the_chain():
    store = _store_two_blocks()
    store.rows[2]["result_fingerprint"] = "forged"  # link now mismatches content
    out = rs.running_spec_at(store, "b2", baseline=BASE, spawn=FakeEngine())
    assert out["text"] is None and out["code"] == "TAMPERED"


def test_a_relinked_step_forgery_cannot_move_the_text():
    # Relink the chain over the forged step result, so the chain verifies:
    # the view still answers the same text, because steps are not inputs to
    # it -- only rule rows are replayed. The divergence check that catches a
    # relinked step forgery is the full reconstruction's
    # (WorkerSession.reconstruct(verify=True), which replays steps); this
    # read is immune by construction, and says so instead of pretending to
    # check what it does not replay.
    rows = _journal_rows()
    entries = tau_journal.journal_from_rows(rows).entries()
    prev = entries[1].link  # the link of the last untouched row (seq 2)
    relinked = []
    for entry in entries:
        if entry.seq < 3:
            relinked.append(entry)  # untouched: original prev and link stand
            continue
        if entry.seq == 3:
            entry = dc_replace(entry, result_fingerprint="forged")
        entry = dc_replace(entry, prev=prev)
        entry = dc_replace(entry, link=entry.compute_link())
        prev = entry.link
        relinked.append(entry)
    rows = [_entry_row(e) for e in relinked]
    commits = {"b2": {"journal_head": rows[3]["link"], "spec_revision": 2,
                      "block_number": 2, "tip": "b2"}}
    out = rs.running_spec_at(FakeStore(rows, commits, head="b2"), "b2",
                             baseline=BASE, spawn=FakeEngine())
    assert out["text"] == f"c1 && {A} && {B}"


# --- cache re-verification (gap 4) -------------------------------------------

def test_a_cached_head_is_refused_after_the_journal_is_tampered():
    engine = FakeEngine()
    store = _store_two_blocks()
    first = rs.running_spec(store, baseline=BASE, spawn=engine)
    assert first["text"] == f"c1 && {A} && {B}" and engine.spawned == 1
    store.rows[1]["rule_text"] = C  # tamper AFTER the cache was filled
    second = rs.running_spec(store, baseline=BASE, spawn=engine)
    assert second["text"] is None and second["code"] == "TAMPERED"
    assert engine.spawned == 1, "no worker is spent serving tampered text"


def test_the_cache_recovers_once_the_rows_verify_again():
    engine = FakeEngine()
    store = _store_two_blocks()
    rs.running_spec(store, baseline=BASE, spawn=engine)
    store.rows[1]["rule_text"] = C
    assert rs.running_spec(store, baseline=BASE, spawn=engine)["code"] == "TAMPERED"
    store.rows[1]["rule_text"] = A  # rows restored: the chain verifies again
    out = rs.running_spec(store, baseline=BASE, spawn=engine)
    assert out["text"] == f"c1 && {A} && {B}" and engine.spawned == 2


# --- getrulesinforce ----------------------------------------------------------

def _enabled_owner():
    owner = tau_authority.AuthoritativeTauOwner()
    owner.enabled = True
    return owner


def _chain_state():
    return types.SimpleNamespace(
        _balance_lock=threading.Lock(), _sequence_lock=threading.Lock(),
        _rules_lock=threading.Lock(), _lifecycle_manager=None,
        _application_rules_state="", _canonical_head_hash="b2",
    )


def test_getrulesinforce_unknown_height_is_not_found_and_bad_arg_is_invalid():
    store = _store_two_blocks()
    container = types.SimpleNamespace(db=store, chain_state=_chain_state())
    data = json.loads(getrulesinforce.execute("getrulesinforce 99", container))["data"]
    assert data["block_number"] == 99 and data["running_spec"]["code"] == "NOT_FOUND"
    err = json.loads(getrulesinforce.execute("getrulesinforce nope", container))
    assert err["status"] == "error" and err["error"]["code"] == "INVALID_PARAMS"


def test_getrulesinforce_lists_only_registry_clauses():
    store = _store_two_blocks()
    alice = "ab" * 48
    store.registry[(alice, 5)] = "always ( o5[t] = 0 )."
    container = types.SimpleNamespace(db=store, chain_state=_chain_state())
    with patch.object(tau_authority, "owner", return_value=_enabled_owner()), \
            patch.object(rs, "running_spec_at", return_value={
                "text": "x", "sha256": _sha("x"), "block_hash": "b2",
                "spec_revision": 2}):
        resp = json.loads(getrulesinforce.execute(
            f"getrulesinforce {alice}", container))
    assert resp["status"] == "ok", resp
    account = resp["data"]["account"]
    assert [c["stream"] for c in account["clauses"]] == [5]
    assert account["clauses"][0]["sha256"] == _sha("always ( o5[t] = 0 ).")
    assert account["rule_change_guard"] is None
    assert account["registry_as_of"] == "this block"


# --- gettxstatus: positive registry check (gap d) -----------------------------

class _TxDB:
    """A fake db for gettxstatus: outcome rows, block txs, registry."""

    def __init__(self, outcome, tx, registry=None):
        self._outcome = outcome
        self._tx = tx
        self.registry = registry or {}
        self._tx_hash = "ab" * 32
        self._block_hash = "cd" * 32

    def get_mempool_entry(self, tx_hash):
        return None

    def get_tx_block_locations(self, tx_hash):
        return [{"block_hash": self._block_hash, "block_number": 7}]

    def get_canonical_confirmation(self, block_hash, block_number):
        return True, 9

    def get_dropped_tx(self, tx_hash):
        return None

    def get_tx_outcome(self, tx_hash, block_hash):
        return self._outcome

    def get_block_by_hash(self, block_hash):
        return {"block_hash": block_hash, "transactions": [self._tx],
                "tx_ids": [self._tx_hash]}

    def rule_clause_body(self, account, stream):
        return self.registry.get((str(account).lower(), int(stream)))


def _status(txdb):
    resp = json.loads(gettxstatus.execute(
        f"gettxstatus {'ab' * 32}", types.SimpleNamespace(db=txdb)))
    assert resp["status"] == "ok", resp
    return resp["data"]


def test_a_clause_effect_is_confirmed_only_against_the_registry():
    alice = "ab" * 48
    body = "always ( o5[t] = 0 )."
    effect = {"account": alice, "kind": "clause", "stream": 5,
              "action": "registered", "sha256": _sha(body)}
    txdb = _TxDB({"status": "applied", "index": 0, "rule_effects": [effect]},
                 {"tx_type": "rule_offer_accept"}, {(alice, 5): body})
    data = _status(txdb)
    (shown,) = data["outcome"]["rule_effects"]
    assert shown["registry_confirmed"] is True
    assert data["outcome"]["rule_outcome"] == {
        "status": "clause", "registry_confirmed": True}


def test_a_clause_effect_with_nothing_in_the_registry_is_not_relabelled():
    alice = "ab" * 48
    effect = {"account": alice, "kind": "clause", "stream": 5,
              "action": "registered", "sha256": _sha("always ( o5[t] = 0 ).")}
    txdb = _TxDB({"status": "applied", "index": 0, "rule_effects": [effect]},
                 {"tx_type": "rule_offer_accept"}, {})
    data = _status(txdb)
    (shown,) = data["outcome"]["rule_effects"]
    assert shown["registry_confirmed"] is False
    assert shown["kind"] == "clause"  # recorded as one; the check only annotates
    assert data["outcome"]["rule_outcome"]["registry_confirmed"] is False


def test_a_rule_payload_with_no_effect_is_unmatched_not_a_clause():
    tx = {"tx_type": "user_tx",
          "operations": {"0": "always ( o26[t] = { 7 } )."}}
    txdb = _TxDB({"status": "applied", "index": 0}, tx)
    data = _status(txdb)
    outcome = data["outcome"]["rule_outcome"]
    assert outcome["status"] == "unmatched"
    assert "clause" not in outcome.get("detail", "")


def test_a_rule_outcome_carries_taken_and_both_revision_numbers():
    revision = {"taken": True, "engine_outcome": "ACCEPTED_CHANGED",
                "spec_revision": 5, "spec_revision_before": 4,
                "spec_revision_after": 5}
    effect = {"account": "ab" * 48, "kind": "application_rule",
              "action": "accumulated", "sha256": _sha(A), "revision": revision}
    txdb = _TxDB({"status": "applied", "index": 0, "rule_effects": [effect]},
                 {"tx_type": "user_tx", "operations": {"0": A}})
    data = _status(txdb)
    assert data["outcome"]["rule_outcome"] == {
        "engine_outcome": "ACCEPTED_CHANGED", "taken": True,
        "spec_revision_before": 4, "spec_revision_after": 5, "spec_revision": 5}


def test_a_plain_tx_gets_no_rule_outcome():
    tx = {"tx_type": "user_tx", "operations": {"1": "transfer"}}
    txdb = _TxDB({"status": "applied", "index": 0, "fee_charged": 3}, tx)
    data = _status(txdb)
    assert "rule_outcome" not in data["outcome"]


# --- in-place upgrade: a DB written by plain main -----------------------------

def test_a_db_written_before_outcomes_answers_old_blocks(temp_database):
    """Construct the DB the way plain main writes it -- journal rows + commit
    record, no tx_outcomes rows -- and read it with the new code. This row had
    no scripted evidence in the rival build; here it is scripted."""
    rows = _journal_rows()
    db.commit_prepared_block(
        execution_id="exec-1", tip="tip-1", parent="tip-0",
        journal_entries=[dict(r, inputs=dict(r["inputs"])) for r in rows],
        expected_journal_seq=0, allocation_delta={},
        expected_epoch=db.shrink_mapping_epoch(), journal_head=rows[-1]["link"],
        allocator_digest="d", plan_id="p", spec_revision=2,
        canonical=dict(head_hash="tip-1", head_num=1, balances={}, sequences={},
                       application_rules="", consensus_rules="", active_consensus_id="",
                       pending_updates=[], votes=[], scheduled=[], archival=[]),
    )
    commit, entries = db.committed_rule_history_at("tip-1")
    assert commit["spec_revision"] == 2
    assert rs.rule_units(entries) == ["c1", A, B]
    assert db.get_tx_outcome("ab" * 32, "tip-1") is None, "no outcome rows: old DB"
    rs.reset_cache()
    out = rs.running_spec_at(db, "tip-1", baseline=BASE, spawn=FakeEngine())
    assert out == {"text": f"c1 && {A} && {B}", "sha256": _sha(f"c1 && {A} && {B}"),
                   "block_hash": "tip-1", "spec_revision": 2}
    assert db.committed_rule_history_at("missing") == (None, None)


# --- getrulesinforce: fee rules from the tip -------------------------------------

_FEE_OWN = ("always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) -> "
            "(o8[t]:bv[24] = { #x00000a }:bv[24]) ).")
_FEE_OTHER = ("always ( ((i12[t]:bv[384] = { #x" + BOB + " }:bv[384]) || "
              "(i1[t]:bv[24] > { #x000000 }:bv[24])) -> (o8[t]:bv[24] = { #x000064 }:bv[24]) ).")
_FEE_GENESIS = "always ( (i3[t]:bv[384] = i3[t]:bv[384]) -> (o8[t]:bv[24] = { #x000001 }:bv[24]) )."


def test_getrulesinforce_account_lists_fee_rules_from_the_tip(temp_database):
    """Fee rules are the tip accumulation's o8 units with their senders (#183),
    even when the account section is read through getrulesinforce."""
    blocks = _chain_of(3)
    _set_head(blocks[2])
    db.record_tx_outcomes(blocks[1].block_hash, 1, [{
        "tx_hash": "01" * 32, "index": 0, "status": "applied",
        "rule_effects": [{"account": ALICE, "kind": "application_rule",
                          "action": "accumulated", "sha256": _sha(_FEE_OWN)}]}])
    db.record_tx_outcomes(blocks[2].block_hash, 2, [{
        "tx_hash": "02" * 32, "index": 0, "status": "applied",
        "rule_effects": [{"account": BOB, "kind": "application_rule",
                          "action": "accumulated", "sha256": _sha(_FEE_OTHER)}]}])
    state = types.SimpleNamespace(
        _balance_lock=threading.Lock(), _sequence_lock=threading.Lock(),
        _rules_lock=threading.Lock(), _lifecycle_manager=None,
        _application_rules_state="\n".join([_FEE_GENESIS, _FEE_OWN, _FEE_OTHER]),
        _canonical_head_hash=blocks[2].block_hash)
    container = types.SimpleNamespace(db=db, chain_state=state)
    with patch.object(tau_authority, "owner", return_value=_enabled_owner()), \
            patch.object(rs, "running_spec_at", return_value={
                "text": "x", "sha256": _sha("x"),
                "block_hash": blocks[2].block_hash, "spec_revision": 2}):
        resp = json.loads(getrulesinforce.execute(
            f"getrulesinforce {ALICE}", container))
    assert resp["status"] == "ok", resp
    account = resp["data"]["account"]
    assert account["fee_rules"] == [
        {"unit": _FEE_GENESIS, "sha256": _sha(_FEE_GENESIS),
         "names_this_account": False, "sent_by": None, "since": None},
        {"unit": _FEE_OWN, "sha256": _sha(_FEE_OWN),
         "names_this_account": True, "sent_by": [ALICE],
         "since": {"block_number": 1, "tx_hash": "01" * 32}},
        {"unit": _FEE_OTHER, "sha256": _sha(_FEE_OTHER),
         "names_this_account": False, "sent_by": [BOB],
         "since": {"block_number": 2, "tx_hash": "02" * 32}},
    ]
    assert account["fee_rules_as_of"] == "this block"
