"""Issue #42: the rules of an account at an earlier block, and what the engine
did with a rule, read from the committed journal.

`getaccountrules <address> <block>` answers for a block of the canonical chain:
the clauses and the guard from this node's record of rule effects (with the
texts it kept), the running spec from the committed journal up to that block's
journal head. `gettxstatus` adds `rule_outcome`, read from the journal rows the
block committed, so it also answers for a block the node kept no outcome for.

What the node cannot know is named and never guessed; the tests below pin each
of those cases. The engine is a recording fake here; the real one runs the same
path in tests/test_running_spec_native.py.
"""
from __future__ import annotations

import json
import types

import pytest

import chain_state
import db
import tau_commit
import tau_defs
import tau_journal
import tau_running_spec as rs
from block import Block
from commands import getaccountrules, gettxstatus

import test_approval_apply as ap
from test_rule_change_requests import ALICE, BOB, GUARD_BODY, POLICY_KEY, _lm as rc_lm
from test_running_spec import BASE, FakeEngine
from test_tx_outcomes import _chain_of, _effect, _set_head, _sha, _state

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
GUARD = tau_defs.RULE_CHANGE_GUARD_INDEX
FIRST = "o5[t]:bv[24] = { #x000001 }:bv[24]"
SECOND = "(i1[t]:bv[24] > { #x000064 }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])"
UNIT = ("always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) ? "
        "(o12[t]:bv[24] = i1[t]:bv[24]) : (o12[t]:bv[24] = { #x000000 }:bv[24]) ).")
OTHER = "always ( o13[t]:bv[24] = i1[t]:bv[24] )."
NOT_RECORDED = "this node did not record the block that set it"


@pytest.fixture(autouse=True)
def _fresh_cache():
    rs.reset_cache()
    yield
    rs.reset_cache()


def _record(block, *effects, tx="01", bodies=(), releases=()):
    """Record a block: one transaction carrying `effects`, or none at all."""
    rows = []
    if effects:
        rows.append({"tx_hash": tx * 32, "index": 0, "status": "applied",
                     "rule_effects": list(effects),
                     "rule_bodies": {_sha(body): body for body in bodies}})
    db.record_tx_outcomes(block.block_hash, block.header.block_number, rows, list(releases))


def _chain(n, recorded=None):
    """`n` blocks with the last as head; those in `recorded` (default: all but
    genesis) are recorded as blocks in which nothing happened."""
    blocks = _chain_of(n)
    _set_head(blocks[-1])
    for block in blocks[1:]:
        if recorded is None or block.header.block_number in recorded:
            _record(block)
    return blocks


def _ask(lm, head, block, address=ALICE, genesis_rules=""):
    state = _state(lm, head)
    state._genesis_application_rules = genesis_rules
    return json.loads(getaccountrules.execute(
        f"getaccountrules {address} {block}", types.SimpleNamespace(db=db, chain_state=state)))


def _at(lm, head, block, **kwargs):
    resp = _ask(lm, head, block, **kwargs)
    assert resp["status"] == "ok", resp
    return resp["data"]


def _history(blocks):
    """o5 registered in block 1, replaced in 3, revoked in 5; a guard released in 2."""
    _record(blocks[1], _effect("registered", _sha(FIRST)), tx="01", bodies=[FIRST])
    _record(blocks[2], releases=[{
        "request_id": "ab" * 32, "account": ALICE, "status": "executed",
        "rule_effects": [{"kind": "clause", "stream": GUARD, "action": "registered",
                          "sha256": _sha(GUARD_BODY)}],
        "rule_bodies": {_sha(GUARD_BODY): GUARD_BODY}}])
    _record(blocks[3], _effect("replaced", _sha(SECOND)), tx="03", bodies=[SECOND])
    _record(blocks[5], _effect("revoked"), tx="05")


# --- what the node keeps -----------------------------------------------------------

def test_the_text_behind_an_effect_is_kept_once_and_not_in_the_outcome(temp_database):
    blocks = _chain(3)
    _record(blocks[1], _effect("registered", _sha(FIRST)), tx="01", bodies=[FIRST])
    _record(blocks[2], _effect("replaced", _sha(FIRST)), tx="02", bodies=[FIRST])
    kept = db._db_conn.execute("SELECT sha256, body FROM rule_bodies").fetchall()
    assert kept == [(_sha(FIRST), FIRST)]
    outcome = db.get_tx_outcome("01" * 32, blocks[1].block_hash)
    assert outcome["rule_effects"] == [_effect("registered", _sha(FIRST))]
    rows = db.get_rule_effect_rows(account=ALICE)
    assert [(r["block_number"], r["action"], r["body"]) for r in rows] == [
        (1, "registered", FIRST), (2, "replaced", FIRST)]


def test_a_block_in_which_nothing_happened_is_recorded_too(temp_database):
    blocks = _chain_of(3)
    db.record_tx_outcomes(blocks[1].block_hash, 1, [], [])
    assert db.recorded_outcome_blocks(b.block_hash for b in blocks) == {blocks[1].block_hash}
    assert db.recorded_outcome_blocks([]) == set()


def test_chain_state_marks_every_block_it_has_outcomes_for(temp_database):
    blocks = _chain_of(3)
    chain_state._record_tx_outcomes(blocks[1], types.SimpleNamespace(
        metadata={"tx_outcomes": [], "rule_change_releases": []}))
    # A snapshot without outcomes says nothing about the block: not marked.
    chain_state._record_tx_outcomes(blocks[2], types.SimpleNamespace(metadata={}))
    assert db.recorded_outcome_blocks(b.block_hash for b in blocks) == {blocks[1].block_hash}


def test_the_engine_hands_over_the_text_with_the_effect():
    tx = ap.rule_tx(ap.UNGUARDED_RULE)
    result, _post, _ = ap._apply([tx])
    (row,) = result.next_snapshot.metadata["tx_outcomes"]
    (effect,) = row["rule_effects"]
    assert "body" not in effect
    (sha, body), = row["rule_bodies"].items()
    assert sha == effect["sha256"] == _sha(body)


def test_the_canonical_chain_is_indexed_by_height(temp_database):
    blocks = _chain_of(4)
    fork = Block.create(block_number=3, previous_hash=blocks[2].block_hash, transactions=[],
                        proposer_pubkey="b" * 96, timestamp=1_700_000_099)
    db.add_block(fork)
    assert db.canonical_chain() == []          # no head yet
    _set_head(blocks[3])
    assert db.canonical_chain() == [b.block_hash for b in blocks]
    _set_head(fork)
    assert db.canonical_chain()[3] == fork.block_hash


def test_a_chain_with_a_missing_block_is_not_answered_from(temp_database):
    blocks = _chain_of(3)
    _set_head(blocks[2])
    with db._db_lock:
        db._db_conn.execute("DELETE FROM blocks WHERE block_hash = ?", (blocks[1].block_hash,))
        db._db_conn.commit()
    assert db.canonical_chain() == []


def test_effects_come_in_block_order_transactions_before_the_release(temp_database):
    blocks = _chain(3)
    db.record_tx_outcomes(blocks[2].block_hash, 2, [
        {"tx_hash": "02" * 32, "index": 1, "status": "applied",
         "rule_effects": [_effect("replaced", "bb" * 32)]},
        {"tx_hash": "01" * 32, "index": 0, "status": "applied",
         "rule_effects": [_effect("registered", "aa" * 32)]}],
        [{"request_id": "cc" * 32, "account": ALICE, "status": "executed",
          "rule_effects": [{"kind": "clause", "stream": STREAM, "action": "revoked"}]}])
    assert [r["action"] for r in db.get_rule_effect_rows(account=ALICE)] == [
        "registered", "replaced", "revoked"]
    assert db.get_rule_effect_rows(account=BOB) == []
    assert db.get_rule_effect_rows(kind="application_rule") == []


# --- the clauses at a block --------------------------------------------------------

def test_the_clause_of_each_block_is_the_one_in_force_when_it_committed(temp_database):
    blocks = _chain(7)
    _history(blocks)
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[(ALICE, GUARD)] = GUARD_BODY
    seen = {}
    for number in range(7):
        data = _at(lm, blocks[-1], number)
        assert data["block_number"] == number
        assert data["block_hash"] == blocks[number].block_hash
        assert data["at_block"] is True and data["head_block_number"] == 6
        assert data["complete"] is True and data["recorded_from"] == (1 if number else None)
        seen[number] = [(c["stream"], c["body"]) for c in data["clauses"]]
    assert seen == {0: [], 1: [(STREAM, FIRST)], 2: [(STREAM, FIRST)],
                    3: [(STREAM, SECOND)], 4: [(STREAM, SECOND)], 5: [], 6: []}


def test_a_clause_says_what_put_it_in_place(temp_database):
    blocks = _chain(7)
    _history(blocks)
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[(ALICE, GUARD)] = GUARD_BODY
    data = _at(lm, blocks[-1], 4)
    assert data["clauses"] == [{
        "stream": STREAM, "name": "o5", "body": SECOND, "sha256": _sha(SECOND),
        "since": {"block_number": 3, "tx_hash": "03" * 32}}]
    assert data["rule_change_guard"] == {
        "body": GUARD_BODY, "sha256": _sha(GUARD_BODY),
        "since": {"block_number": 2, "request_id": "ab" * 32}}
    assert _at(lm, blocks[-1], 1)["rule_change_guard"] is None


def test_a_block_is_named_by_its_number_or_its_hash(temp_database):
    blocks = _chain(7)
    _history(blocks)
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[(ALICE, GUARD)] = GUARD_BODY
    assert _at(lm, blocks[-1], blocks[3].block_hash) == _at(lm, blocks[-1], 3)
    assert _at(lm, blocks[-1], blocks[3].block_hash.upper()) == _at(lm, blocks[-1], 3)


def test_the_history_stops_at_the_block(temp_database):
    blocks = _chain(7)
    _history(blocks)
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[(ALICE, GUARD)] = GUARD_BODY
    history = _at(lm, blocks[-1], 3)["history"]
    assert [(h["block_number"], h["action"]) for h in history] == [
        (3, "replaced"), (2, "registered"), (1, "registered")]
    assert history[0]["tx_hash"] == "03" * 32 and history[1]["request_id"] == "ab" * 32
    assert _at(lm, blocks[-1], 0)["history"] == []


def test_what_exists_only_at_the_tip_is_left_out(temp_database):
    blocks = _chain(3)
    data = _at(rc_lm(), blocks[-1], 1)
    for field in ("open_rule_changes", "awaiting_my_vote", "pending_offers", "mempool",
                  "rule_clauses_root"):
        assert field not in data
    assert data["running_spec"]["block_hash"] == blocks[1].block_hash


def test_at_the_tip_the_clauses_are_those_of_the_live_answer(temp_database):
    blocks = _chain(7)
    _history(blocks)
    _record(blocks[6], _effect("registered", _sha(FIRST)), tx="06", bodies=[FIRST])
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[(ALICE, GUARD)] = GUARD_BODY
    lm.rule_offers.accepted_clauses[POLICY_KEY] = FIRST
    state = _state(lm, blocks[-1])
    live = json.loads(getaccountrules.execute(
        f"getaccountrules {ALICE}", types.SimpleNamespace(db=db, chain_state=state)))["data"]
    then = _at(lm, blocks[-1], 6)
    assert then["clauses"] == live["clauses"]
    assert then["rule_change_guard"] == live["rule_change_guard"]
    assert (then["block_number"], then["block_hash"]) == (live["block_number"], live["block_hash"])


def test_effects_of_a_block_off_the_canonical_chain_are_not_counted(temp_database):
    blocks = _chain(4)
    fork = Block.create(block_number=2, previous_hash=blocks[1].block_hash, transactions=[],
                        proposer_pubkey="b" * 96, timestamp=1_700_000_099)
    db.add_block(fork)
    _record(fork, _effect("registered", _sha(FIRST)), tx="0f", bodies=[FIRST])
    data = _at(rc_lm(), blocks[-1], 3)
    assert data["clauses"] == [] and data["history"] == [] and data["complete"] is True


# --- what this node cannot know ------------------------------------------------------

def test_a_node_that_began_recording_later_answers_what_it_can_be_sure_of(temp_database):
    """Upgraded in place at block 3. The clause was set in block 1 and never
    touched again, so every recorded block had what the registry holds now."""
    blocks = _chain(6, recorded={3, 4, 5})
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[POLICY_KEY] = FIRST
    data = _at(lm, blocks[-1], 4)
    assert data["recorded_from"] == 3
    assert data["clauses"] == [{"stream": STREAM, "name": "o5", "body": FIRST,
                                "sha256": _sha(FIRST), "since": None}]
    # The units that name the account need every block from the first.
    assert data["application_rules"] is None and data["complete"] is False
    assert data["application_rules_unavailable"] == (
        "this node did not record every block up to this one")


def test_a_block_before_the_record_began_is_not_guessed(temp_database):
    blocks = _chain(6, recorded={3, 4, 5})
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[POLICY_KEY] = FIRST
    data = _at(lm, blocks[-1], 1)
    assert data["recorded_from"] is None and data["complete"] is False
    assert data["clauses"] == [{"stream": STREAM, "name": "o5", "body": None, "sha256": None,
                                "since": None, "unavailable": NOT_RECORDED}]


def test_a_clause_replaced_after_the_block_was_there_but_its_text_is_not_known(temp_database):
    blocks = _chain(6, recorded={3, 4, 5})
    _record(blocks[4], _effect("replaced", _sha(SECOND)), tx="04", bodies=[SECOND])
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[POLICY_KEY] = SECOND
    (clause,) = _at(lm, blocks[-1], 3)["clauses"]
    assert clause["body"] is None and clause["unavailable"] == NOT_RECORDED
    (clause,) = _at(lm, blocks[-1], 4)["clauses"]
    assert clause["body"] == SECOND and "unavailable" not in clause


def test_a_clause_first_registered_after_the_block_was_not_there(temp_database):
    blocks = _chain(6, recorded={3, 4, 5})
    _record(blocks[4], _effect("registered", _sha(FIRST)), tx="04", bodies=[FIRST])
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[POLICY_KEY] = FIRST
    assert _at(lm, blocks[-1], 3)["clauses"] == []


def test_a_gap_after_the_block_leaves_an_untouched_clause_unknown(temp_database):
    blocks = _chain(6, recorded={2, 3, 5})         # block 4 was not recorded
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[POLICY_KEY] = FIRST
    (clause,) = _at(lm, blocks[-1], 3)["clauses"]
    assert clause["body"] is None and clause["unavailable"] == NOT_RECORDED
    # A change this node recorded before the gap is still certain.
    _record(blocks[3], _effect("replaced", _sha(SECOND)), tx="03", bodies=[SECOND])
    (clause,) = _at(lm, blocks[-1], 3)["clauses"]
    assert clause["body"] == SECOND and "unavailable" not in clause


def test_a_record_that_contradicts_the_registry_is_not_answered_from(temp_database):
    blocks = _chain(5)
    _record(blocks[1], _effect("registered", _sha(FIRST)), tx="01", bodies=[FIRST])
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[POLICY_KEY] = SECOND     # the record never saw this
    data = _at(lm, blocks[-1], 2)
    (clause,) = data["clauses"]
    assert clause["body"] is None and data["complete"] is False
    assert clause["unavailable"] == "this node's record does not match its registry"
    lm.rule_offers.accepted_clauses.pop(POLICY_KEY)          # nor a revoke
    (clause,) = _at(lm, blocks[-1], 2)["clauses"]
    assert clause["unavailable"] == "this node's record does not match its registry"


def test_an_effect_recorded_without_its_text_names_the_hash_only(temp_database):
    """Rows written before the node kept texts: the hash is known, the text is
    known only while the registry still holds it."""
    blocks = _chain(5)
    _record(blocks[1], _effect("registered", _sha(FIRST)), tx="01")
    _record(blocks[3], _effect("replaced", _sha(SECOND)), tx="03")
    lm = rc_lm()
    lm.rule_offers.accepted_clauses[POLICY_KEY] = SECOND
    (old,) = _at(lm, blocks[-1], 2)["clauses"]
    assert old["body"] is None and old["sha256"] == _sha(FIRST)
    assert old["unavailable"] == "this node did not keep the text"
    assert old["since"] == {"block_number": 1, "tx_hash": "01" * 32}
    (new,) = _at(lm, blocks[-1], 3)["clauses"]
    assert new["body"] == SECOND and "unavailable" not in new


@pytest.mark.parametrize("block, why", [
    ("9", "block 9 is above the head (4)"),
    ("ab" * 32, "that block is not on the canonical chain"),
    ("latest", "the block is a block number or a 64-character block hash"),
    ("-1", "the block is a block number or a 64-character block hash"),
])
def test_a_block_this_node_cannot_answer_for_is_refused(temp_database, block, why):
    blocks = _chain(5)
    resp = _ask(rc_lm(), blocks[-1], block)
    assert resp["status"] == "error" and resp["error"]["code"] == "INVALID_PARAMS"
    assert resp["error"]["message"] == why


def test_a_fork_block_is_refused_by_its_hash(temp_database):
    blocks = _chain(4)
    fork = Block.create(block_number=2, previous_hash=blocks[1].block_hash, transactions=[],
                        proposer_pubkey="b" * 96, timestamp=1_700_000_099)
    db.add_block(fork)
    resp = _ask(rc_lm(), blocks[-1], fork.block_hash)
    assert resp["error"]["message"] == "that block is not on the canonical chain"


def test_a_fourth_word_is_refused(temp_database):
    blocks = _chain(2)
    resp = json.loads(getaccountrules.execute(
        f"getaccountrules {ALICE} 1 2",
        types.SimpleNamespace(db=db, chain_state=_state(rc_lm(), blocks[-1]))))
    assert resp["error"]["code"] == "INVALID_PARAMS"


# --- the application rules at a block ---------------------------------------------------

def _unit(text, sender=BOB):
    return {"account": sender, "kind": "application_rule", "action": "accumulated",
            "sha256": _sha(text)}


def test_the_units_naming_the_account_are_those_accumulated_up_to_the_block(temp_database):
    genesis_unit = UNIT.replace("o12", "o14")
    blocks = _chain(5)
    _record(blocks[2], _unit(OTHER), tx="02", bodies=[OTHER])      # names nobody
    _record(blocks[3], _unit(UNIT), tx="03", bodies=[UNIT])        # sent by Bob, names Alice
    lm = rc_lm()
    at = lambda n: _at(lm, blocks[-1], n, genesis_rules=genesis_unit + "\n" + OTHER)
    assert at(2)["application_rules"] == [
        {"unit": genesis_unit, "sha256": _sha(genesis_unit), "since": None}]
    assert at(3)["application_rules"] == at(4)["application_rules"] == [
        {"unit": genesis_unit, "sha256": _sha(genesis_unit), "since": None},
        {"unit": UNIT, "sha256": _sha(UNIT),
         "since": {"block_number": 3, "tx_hash": "03" * 32}}]
    assert at(4)["complete"] is True and "application_rules_unavailable" not in at(4)
    assert _at(lm, blocks[-1], 4, address=BOB)["application_rules"] == []


def test_units_recorded_without_their_text_are_not_guessed(temp_database):
    blocks = _chain(4)
    _record(blocks[2], _unit(UNIT), tx="02")
    data = _at(rc_lm(), blocks[-1], 3)
    assert data["application_rules"] is None and data["complete"] is False
    assert data["application_rules_unavailable"] == (
        "this node did not keep the text of every unit")


FEE_BOB = ("always ( ((i12[t]:bv[384] = { #x" + BOB + " }:bv[384]) || "
           "(i1[t]:bv[24] > { #x000000 }:bv[24])) -> (o8[t]:bv[24] = { #x000064 }:bv[24]) ).")


def test_the_fee_rules_of_a_block_are_those_accumulated_up_to_it(temp_database):
    genesis_fee = "always ( (i3[t]:bv[384] = i3[t]:bv[384]) -> (o8[t]:bv[24] = { #x000001 }:bv[24]) )."
    blocks = _chain(5)
    _record(blocks[2], _unit(OTHER), tx="02", bodies=[OTHER])
    _record(blocks[3], _unit(FEE_BOB), tx="03", bodies=[FEE_BOB])
    lm = rc_lm()
    at = lambda n: _at(lm, blocks[-1], n, genesis_rules=genesis_fee + "\n" + OTHER)
    genesis_row = {"unit": genesis_fee, "sha256": _sha(genesis_fee),
                   "names_this_account": False, "sent_by": None, "since": None}
    assert at(2)["fee_rules"] == [genesis_row]
    assert at(3)["fee_rules"] == at(4)["fee_rules"] == [genesis_row, {
        "unit": FEE_BOB, "sha256": _sha(FEE_BOB), "names_this_account": False,
        "sent_by": [BOB], "since": {"block_number": 3, "tx_hash": "03" * 32}}]
    assert at(4)["application_rules"] == []


def test_fee_rules_recorded_without_their_text_are_not_guessed(temp_database):
    blocks = _chain(4)
    _record(blocks[2], _unit(FEE_BOB), tx="02")
    data = _at(rc_lm(), blocks[-1], 3)
    assert data["fee_rules"] is None and data["complete"] is False


# --- the running spec at a block -----------------------------------------------------------

RULE_A = "always ( o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24] )."
RULE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
RULE_C = "always ( o27[t]:bv[24] = { 4 }:bv[24] )."


def _commit(journal, tip, parent, *, spec_revision=None, record):
    """Commit one block whose journal rows are those `record` adds."""
    before = len(journal)
    record(journal)
    delta = journal.entries()[before:]
    db.commit_prepared_block(
        execution_id=f"exec-{tip}", tip=tip, parent=parent,
        journal_entries=[tau_commit._entry_row(e) for e in delta],
        expected_journal_seq=before, allocation_delta={},
        expected_epoch=db.shrink_mapping_epoch(),
        journal_head=journal.entries()[-1].link if len(journal) else None,
        allocator_digest="d", plan_id="p", spec_revision=spec_revision,
        canonical=dict(head_hash=tip, head_num=1, balances={}, sequences={},
                       application_rules="", consensus_rules="", active_consensus_id="",
                       pending_updates=[], votes=[], scheduled=[], archival=[]),
    )


def _revise(text, outcome="ACCEPTED_CHANGED"):
    def record(journal):
        journal.record(tau_journal.REVISION, phase=tau_journal.PHASE_APPLY, rule_text=text,
                       target=0, outcome=outcome)
    return record


def _step(journal):
    journal.record(tau_journal.STEP, phase=tau_journal.PHASE_APPLY, inputs={"i1": "5"},
                   target=0, result={"o1": "5"})


def _three_blocks():
    """tip-1 revises with A, tip-2 only steps, tip-3 revises with B."""
    journal = tau_journal.Journal()
    _commit(journal, "tip-1", "tip-0", spec_revision=1, record=_revise(RULE_A))
    _commit(journal, "tip-2", "tip-1", spec_revision=1, record=_step)
    _commit(journal, "tip-3", "tip-2", spec_revision=2, record=_revise(RULE_B))
    return journal


def test_the_spec_of_a_block_is_built_from_the_journal_up_to_its_head(temp_database):
    _three_blocks()
    engine = FakeEngine()
    first = rs.at_block("tip-1", db, baseline=BASE, spawn=engine)
    assert first == {"text": RULE_A, "sha256": _sha(RULE_A), "block_hash": "tip-1",
                     "spec_revision": 1}
    assert engine.fed == [("init", BASE), ("revise", RULE_A), ("close",)]
    last = rs.at_block("tip-3", db, baseline=BASE, spawn=engine)
    assert last["text"] == f"{RULE_A} && {RULE_B}" and last["spec_revision"] == 2
    # ... and it is the text the read at the head gives.
    assert rs.running_spec(db, baseline=BASE, spawn=FakeEngine())["sha256"] == last["sha256"]


def test_a_block_without_a_rule_entry_costs_no_engine(temp_database):
    _three_blocks()
    engine = FakeEngine()
    first = rs.at_block("tip-1", db, baseline=BASE, spawn=engine)
    assert engine.spawned == 1
    again = rs.at_block("tip-1", db, baseline=BASE, spawn=engine)
    assert again == first and engine.spawned == 1
    # tip-2 has another journal head (a step), so it is built once more ...
    second = rs.at_block("tip-2", db, baseline=BASE, spawn=engine)
    assert second["text"] == first["text"] and second["block_hash"] == "tip-2"
    assert engine.spawned == 2
    # ... and only a few texts are kept.
    assert len(rs._block_cache) == 2 <= rs._BLOCK_CACHE_SIZE


def test_a_block_without_a_commit_record_has_no_text(temp_database):
    _three_blocks()
    engine = FakeEngine()
    out = rs.at_block("tip-9", db, baseline=BASE, spawn=engine)
    assert out == {"text": None, "sha256": None, "block_hash": "tip-9",
                   "unavailable": "this node holds no commit record for that block"}
    assert engine.spawned == 0


@pytest.mark.parametrize("damage", [
    "UPDATE tau_journal_v1 SET rule_text = 'always ( o26[t]:bv[24] = { 8 }:bv[24] ).' WHERE seq = 1",
    "UPDATE tau_journal_v1 SET outcome = 'ACCEPTED_NOOP' WHERE seq = 1",
    "UPDATE tau_journal_v1 SET prev = 'ff' WHERE seq = 2",
    "DELETE FROM tau_journal_v1 WHERE seq = 2",
])
def test_a_journal_that_was_altered_is_reported_and_not_built_from(temp_database, damage):
    _three_blocks()
    with db._db_lock:
        db._db_conn.execute(damage)
        db._db_conn.commit()
    engine = FakeEngine()
    out = rs.at_block("tip-3", db, baseline=BASE, spawn=engine)
    assert out["text"] is None and engine.spawned == 0
    assert out["unavailable"].startswith("the committed journal does not verify")


def test_a_journal_head_that_is_gone_is_reported(temp_database):
    _three_blocks()
    with db._db_lock:
        db._db_conn.execute("DELETE FROM tau_journal_v1 WHERE seq = 3")
        db._db_conn.commit()
    out = rs.at_block("tip-3", db, baseline=BASE, spawn=FakeEngine())
    assert out["text"] is None
    assert out["unavailable"].startswith("the block's journal could not be read")
    # An earlier block does not depend on the missing row.
    assert rs.at_block("tip-1", db, baseline=BASE, spawn=FakeEngine())["text"] == RULE_A


def test_a_unit_the_engine_does_not_accept_again_gives_no_text_for_the_block(temp_database):
    _three_blocks()
    out = rs.at_block("tip-3", db, baseline=BASE, spawn=FakeEngine(refuse=[RULE_B]))
    assert out["text"] is None and "unit 1 was not accepted again" in out["unavailable"]


def test_a_node_without_the_authority_starts_no_engine_for_a_block(temp_database):
    _three_blocks()
    out = rs.at_block("tip-1", db, spawn=FakeEngine())
    assert out["unavailable"] == "this node runs without the authoritative engine"


# --- what the engine did with a rule, from the journal ----------------------------------------

def _rule_tx(text, seq=0):
    return {"tx_type": "user_tx", "sender_pubkey": ALICE, "sequence_number": seq,
            "operations": {"0": text}}


def _block_with(*txs):
    genesis = Block.create(block_number=0, previous_hash="00" * 32, transactions=[],
                           proposer_pubkey="a" * 96, timestamp=1_700_000_000)
    block = Block.create(block_number=1, previous_hash=genesis.block_hash,
                         transactions=list(txs), proposer_pubkey="a" * 96,
                         timestamp=1_700_000_001)
    db.add_block(genesis)
    db.add_block(block)
    _set_head(block)
    return block


def _journal_for(block, *revisions, spec_revision=None):
    def record(journal):
        for text, outcome in revisions:
            journal.record(tau_journal.REVISION, phase=tau_journal.PHASE_APPLY,
                           rule_text=text, target=0, outcome=outcome)
            _step(journal)
    _commit(tau_journal.Journal(), block.block_hash, block.header.previous_hash,
            spec_revision=spec_revision, record=record)
    _set_head(block)


def _status(tx_hash):
    resp = json.loads(gettxstatus.execute(
        f"gettxstatus {tx_hash}", types.SimpleNamespace(db=db)))
    assert resp["status"] == "ok", resp
    return resp["data"]


def test_a_block_this_node_kept_no_outcome_for_still_says_what_the_engine_did(temp_database):
    block = _block_with(_rule_tx(RULE_A))
    _journal_for(block, (RULE_A, "ACCEPTED_CHANGED"), spec_revision=4)
    assert _status(block.tx_ids[0])["outcome"] == {
        "status": "not_recorded",
        "rule_outcome": {"source": "committed_journal", "engine_outcome": "ACCEPTED_CHANGED",
                         "accepted": True, "taken": True, "spec_revision": 4}}


def test_a_rule_the_engine_already_implied_is_accepted_and_not_taken(temp_database):
    block = _block_with(_rule_tx(RULE_A))
    _journal_for(block, (RULE_A, "ACCEPTED_NOOP"))
    assert _status(block.tx_ids[0])["outcome"]["rule_outcome"] == {
        "source": "committed_journal", "engine_outcome": "ACCEPTED_NOOP",
        "accepted": True, "taken": False}


def test_each_transaction_gets_its_own_row_also_with_the_same_text(temp_database):
    """The k-th transaction with a text is the k-th row with it; the revision
    counter of each is the block's, less the revisions taken after it."""
    block = _block_with(_rule_tx(RULE_A, 0), _rule_tx(RULE_B, 1), _rule_tx("  " + RULE_A + " ", 2),
                        _rule_tx(RULE_C, 3))
    _journal_for(block, (RULE_A, "ACCEPTED_CHANGED"), (RULE_B, "ACCEPTED_CHANGED"),
                 (RULE_A, "ACCEPTED_NOOP"), (RULE_C, "ACCEPTED_CHANGED"), spec_revision=9)
    got = [_status(tx)["outcome"]["rule_outcome"] for tx in block.tx_ids]
    assert [(g["engine_outcome"], g["taken"], g["spec_revision"]) for g in got] == [
        ("ACCEPTED_CHANGED", True, 7), ("ACCEPTED_CHANGED", True, 8),
        ("ACCEPTED_NOOP", False, 8), ("ACCEPTED_CHANGED", True, 9)]


def test_a_count_that_does_not_match_is_reported_not_guessed(temp_database):
    block = _block_with(_rule_tx(RULE_A, 0), _rule_tx(RULE_A, 1))
    _journal_for(block, (RULE_A, "ACCEPTED_CHANGED"))
    for tx in block.tx_ids:
        assert _status(tx)["outcome"]["rule_outcome"] == {
            "source": "committed_journal",
            "unavailable": "the block carries this rule 2 time(s) and its journal 1"}


def test_a_transaction_the_journal_holds_no_revision_for_names_none(temp_database):
    transfer = {"tx_type": "user_tx", "sender_pubkey": ALICE, "sequence_number": 0,
                "operations": {"1": [[ALICE, BOB, "1"]]}}
    clause = _rule_tx("always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) ).", 1)   # kept in the registry
    block = _block_with(transfer, clause, _rule_tx(RULE_A, 2))
    _journal_for(block, (RULE_A, "ACCEPTED_CHANGED"))
    assert _status(block.tx_ids[0])["outcome"] == {"status": "not_recorded"}
    assert _status(block.tx_ids[1])["outcome"] == {"status": "not_recorded"}
    assert "rule_outcome" in _status(block.tx_ids[2])["outcome"]


def test_the_record_and_the_journal_stand_side_by_side(temp_database):
    block = _block_with(_rule_tx(RULE_A))
    _journal_for(block, (RULE_A, "ACCEPTED_CHANGED"), spec_revision=3)
    revision = {"taken": True, "engine_outcome": "ACCEPTED_CHANGED", "spec_revision": 3}
    db.record_tx_outcomes(block.block_hash, 1, [{
        "tx_hash": block.tx_ids[0], "index": 0, "status": "applied", "fee_charged": 10,
        "rule_effects": [{"account": ALICE, "kind": "application_rule",
                          "action": "accumulated", "sha256": _sha(RULE_A),
                          "revision": revision}]}])
    outcome = _status(block.tx_ids[0])["outcome"]
    assert outcome["status"] == "applied"
    journal = outcome["rule_outcome"]
    assert {k: journal[k] for k in ("taken", "engine_outcome", "spec_revision")} == \
        outcome["rule_effects"][0]["revision"]


def test_the_journal_rows_of_a_block_are_read_with_its_counter(temp_database):
    block = _block_with(_rule_tx(RULE_A))
    _journal_for(block, (RULE_A, "ACCEPTED_CHANGED"), (RULE_B, "REJECTED_NOT_ROUTED"),
                 spec_revision=5)
    journal = db.journal_revisions_of_block(block.block_hash)
    assert journal["spec_revision"] == 5
    assert [(r["rule_text"], r["outcome"], r["phase"]) for r in journal["revisions"]] == [
        (RULE_A, "ACCEPTED_CHANGED", "apply"), (RULE_B, "REJECTED_NOT_ROUTED", "apply")]
    assert db.journal_revisions_of_block("ee" * 32) == {"revisions": [], "spec_revision": None}
