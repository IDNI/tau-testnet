"""Issue #42, step 3: the per-submitted-unit survival ledger, plus the
step-1/2 reconciliations the coverage audit called for (U6, U7).

A current-spec view cannot answer the wallet's real question -- "is the
rule I submitted still protecting me?" When unit 2 displaces part of
unit 1, the displaced fragment silently vanishes from the view; its
absence looks identical to "never installed". The ledger records, per
submitted shared-spec unit, `in_force` / `partially_displaced` (with the
surviving normalized fragment) / `displaced`, plus the displacing
transaction -- recomputed at query time by replaying the canonical
blocks' shadow feeds (db.spec_unit_feeds), so a reorg that drops the
displacing block restores the earlier unit's status with no reversal
records.

Same harness discipline as steps 1-2: the engine side is the scripted
driver behind the production driver's interface (pointwise revision for
assignment units), because the native tau module is not built in every
environment. What is under test is the feed attribution, the fragment
diff, the canonical replay, and the view -- not Tau semantics.
"""
import json
import types

import pytest

import chain_state
import db
import tau_defs
from commands import gettxstatus
from consensus import sender_policy
from consensus.policy_mock import MockPolicyEvaluator

import test_rule_outcomes as step1
import test_shadow_spec as step2

ALICE = step1.ALICE
STREAM = tau_defs.USER_POLICY_STREAM_INDEX

FULL_UNIT_1 = "always ( o26[t]:bv[24] = { 7 }:bv[24] )."
UNIT_O27 = "always ( o27[t]:bv[24] = { 9 }:bv[24] )."
UNSAT_UNIT = (
    "always ( o26[t]:bv[24] = "
    "o26[t]:bv[24]*{ 3 }:bv[24]+{ 1 }:bv[24] )."
)


@pytest.fixture()
def shadow_driver():
    driver = step2.ScriptedTauDriver()
    chain_state.set_shadow_driver_factory(lambda: driver)
    yield driver
    chain_state.set_shadow_driver_factory(None)


@pytest.fixture(autouse=True)
def _reset_evaluators():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def _probe_chain():
    """The maintainer's probe: unit 1 installs o26={7} && o27={9}, unit 2
    then installs o26={3}, displacing exactly half of unit 1."""
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    b1 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_1, seq=0)])
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 2, 3)
    b2 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_2, seq=1)])
    assert not b1[1].invalid_tx_ids, b1[1].outcomes
    assert not b2[1].invalid_tx_ids, b2[1].outcomes
    return chain, b1, b2


# --- the ledger ---------------------------------------------------------------

def test_probe_unit1_partially_displaced(temp_database, shadow_driver):
    chain, b1, b2 = _probe_chain()
    step2._commit(chain, [b1, b2])
    tx1_hash, tx2_hash = b1[0].tx_ids[0], b2[0].tx_ids[0]

    entries = {e["unit"]: e for e in db.get_survival_ledger()}
    e1 = entries[step2.PROBE_UNIT_1]
    assert e1["tx_hash"] == tx1_hash
    assert e1["account"] == ALICE.lower()
    assert e1["block_height"] == b1[0].header.block_number
    assert e1["status"] == "partially_displaced"
    # The surviving fragment, in its normalized form: o27 is still in
    # force at { 9 }; o26 was displaced to { 3 } by unit 2.
    assert e1["surviving_fragment"] == "o27[t]:bv[24] = { 9 }:bv[24]"
    assert e1["displacer_tx_hash"] == tx2_hash
    assert e1["displacer_block_height"] == b2[0].header.block_number

    e2 = entries[step2.PROBE_UNIT_2]
    assert e2["tx_hash"] == tx2_hash
    assert e2["status"] == "in_force"
    assert e2["displacer_tx_hash"] is None

    # The same answer through the view, stamped with the snapshot.
    data = step2._view()
    status = {s["unit"]: s for s in data["shared_spec"]["unit_status"]}
    v1 = status[step2.PROBE_UNIT_1]
    assert v1["status"] == "partially_displaced"
    assert v1["surviving_fragment"] == "o27[t]:bv[24] = { 9 }:bv[24]"
    assert v1["displacer"] == {
        "tx_hash": tx2_hash,
        "block_height": b2[0].header.block_number,
    }
    assert status[step2.PROBE_UNIT_2]["status"] == "in_force"
    assert "displacer" not in status[step2.PROBE_UNIT_2]


def test_resent_unit_displaces_in_turn(temp_database, shadow_driver):
    # The resend case in the ledger: A installs o26={7} && o27={9}, B
    # displaces o26 to {3}, then A is submitted again. The ledger
    # replays the journal-order feeds with no dedup, so the resend is
    # a step like any other: A is in force again (its entry keeps the
    # first feed's attribution), and B -- in force until the resend --
    # is displaced BY the resend.
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    b1 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_1, seq=0)])
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 2, 3)
    b2 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_2, seq=1)])
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 3, 4)
    b3 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_1, seq=2)])
    assert not b3[1].invalid_tx_ids, b3[1].outcomes
    step2._commit(chain, [b1, b2, b3])
    tx3_hash = b3[0].tx_ids[0]

    entries = {e["unit"]: e for e in db.get_survival_ledger()}
    e1 = entries[step2.PROBE_UNIT_1]
    assert e1["status"] == "in_force"
    assert e1["tx_hash"] == b1[0].tx_ids[0]
    assert e1["account"] == ALICE.lower()
    assert e1["block_height"] == b1[0].header.block_number
    assert e1["displacer_tx_hash"] is None

    e2 = entries[step2.PROBE_UNIT_2]
    assert e2["status"] == "displaced"
    assert e2["surviving_fragment"] is None
    assert e2["displacer_tx_hash"] == tx3_hash
    assert e2["displacer_block_height"] == b3[0].header.block_number

    # The same answer through the view.
    data = step2._view()
    assert "{ 7 }" in data["shared_spec"]["normalized_text"]
    status = {s["unit"]: s for s in data["shared_spec"]["unit_status"]}
    assert status[step2.PROBE_UNIT_1]["status"] == "in_force"
    assert "displacer" not in status[step2.PROBE_UNIT_1]
    assert status[step2.PROBE_UNIT_2]["status"] == "displaced"
    assert status[step2.PROBE_UNIT_2]["displacer"] == {
        "tx_hash": tx3_hash,
        "block_height": b3[0].header.block_number,
    }


def test_resent_unit_step_attributed_to_resend_tx(
        temp_database, shadow_driver):
    # The resent-unit attribution rule: a step's identity is its
    # journal entry, not its text. A, B, then A again -- the resend's
    # step is the third journal entry, attributed to the resend
    # transaction with its own shadow revision, even though its text
    # equals the first submission's. The in-process journal is
    # consumed monotonically (each entry once, in order), so the
    # resend is never re-read as the first occurrence. The in-process
    # journal is process-global, so reset it first: this test's three
    # entries are then the whole journal.
    import tau_journal as _tau_journal

    _tau_journal.reset_all()
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    b1 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_1, seq=0)])
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 2, 3)
    b2 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_2, seq=1)])
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 3, 4)
    b3 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_1, seq=2)])
    assert not b3[1].invalid_tx_ids, b3[1].outcomes
    step2._commit(chain, [b1, b2, b3])
    tx1_hash = b1[0].tx_ids[0]
    tx3_hash = b3[0].tx_ids[0]

    # All three journal entries consumed exactly once, in order: the
    # consumption cursor sits past the resend's entry, at the end of
    # the in-process journal's accumulated revisions.
    import tau_journal as _tau_journal

    shadow = chain_state.get_shadow_spec()
    assert shadow.fed_units == [
        step2.PROBE_UNIT_1, step2.PROBE_UNIT_2, step2.PROBE_UNIT_1]
    revision_count = sum(
        1 for entry in _tau_journal.committed().entries()
        if entry.kind == _tau_journal.REVISION and entry.accumulate
        and entry.rule_text)
    assert shadow.memory_cursor == revision_count

    # The resend block's persisted feed step names the resend tx.
    with db._db_lock:
        rows = db._db_conn.execute(
            "SELECT tx_hash FROM spec_unit_feeds "
            "WHERE block_hash = ? AND unit_text IS NOT NULL",
            (b3[0].block_hash,)).fetchall()
    assert [row[0] for row in rows] == [tx3_hash]

    # Each receipt carries its own step's shadow revision: the first
    # submission's is 1, the resend's is 3 -- the resend is not
    # labelled with the first occurrence's revision.
    container = types.SimpleNamespace(db=db)
    for tx_hash, expected in ((tx1_hash, 1), (tx3_hash, 3)):
        resp = json.loads(gettxstatus.execute(
            f"gettxstatus {tx_hash}", container))
        assert resp["status"] == "ok", resp
        served = resp["data"]["rule_outcome"]
        assert served["evidence"]["shadow_revision"] == expected


def test_resend_within_one_block_attributed_in_order(
        temp_database, shadow_driver):
    # A, B, A again inside ONE block: positional attribution gives
    # each step its own transaction in journal order, and B is
    # displaced by the third transaction at the same height.
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    block, result = chain.apply([
        step1._rule_tx(step2.PROBE_UNIT_1, seq=0),
        step1._rule_tx(step2.PROBE_UNIT_2, seq=1),
        step1._rule_tx(step2.PROBE_UNIT_1, seq=2),
    ])
    assert not result.invalid_tx_ids, result.outcomes
    step2._commit(chain, [(block, result)])
    tx1_hash, tx2_hash, tx3_hash = block.tx_ids
    height = block.header.block_number

    with db._db_lock:
        rows = db._db_conn.execute(
            "SELECT tx_hash FROM spec_unit_feeds "
            "WHERE block_hash = ? AND unit_text IS NOT NULL "
            "ORDER BY rowid",
            (block.block_hash,)).fetchall()
    assert [row[0] for row in rows] == [tx1_hash, tx2_hash, tx3_hash]

    entries = {e["unit"]: e for e in db.get_survival_ledger()}
    assert entries[step2.PROBE_UNIT_1]["status"] == "in_force"
    assert entries[step2.PROBE_UNIT_1]["tx_hash"] == tx1_hash
    e2 = entries[step2.PROBE_UNIT_2]
    assert e2["status"] == "displaced"
    assert e2["displacer_tx_hash"] == tx3_hash
    assert e2["displacer_block_height"] == height


def test_two_updates_in_one_block_keep_own_attribution(
        temp_database, shadow_driver):
    # Two updates to independent outputs in ONE block: each unit's
    # ledger entry and receipt carry its OWN transaction and shadow
    # revision -- the second update is not labelled with the first
    # update's revision (the same-block attribution case from #42).
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    block, result = chain.apply([
        step1._rule_tx(FULL_UNIT_1, seq=0),
        step1._rule_tx(UNIT_O27, seq=1),
    ])
    assert not result.invalid_tx_ids, result.outcomes
    step2._commit(chain, [(block, result)])
    tx1_hash, tx2_hash = block.tx_ids[0], block.tx_ids[1]
    height = block.header.block_number

    entries = {e["unit"]: e for e in db.get_survival_ledger()}
    e1 = entries[FULL_UNIT_1]
    assert e1["tx_hash"] == tx1_hash
    assert e1["block_height"] == height
    assert e1["status"] == "in_force"
    assert e1["displacer_tx_hash"] is None

    e2 = entries[UNIT_O27]
    assert e2["tx_hash"] == tx2_hash
    assert e2["block_height"] == height
    assert e2["status"] == "in_force"
    assert e2["displacer_tx_hash"] is None

    # Each receipt's shadow revision is the step that fed ITS unit:
    # 1 for the first update, 2 for the second.
    container = types.SimpleNamespace(db=db)
    served = []
    for tx_hash in (tx1_hash, tx2_hash):
        resp = json.loads(gettxstatus.execute(
            f"gettxstatus {tx_hash}", container))
        assert resp["status"] == "ok", resp
        served.append(resp["data"]["rule_outcome"]["evidence"])
    assert served[0]["shadow_revision"] == 1
    assert served[1]["shadow_revision"] == 2

    # The view after the block reflects both updates.
    data = step2._view()
    text = data["shared_spec"]["normalized_text"]
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in text
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in text
    status = {s["unit"]: s for s in data["shared_spec"]["unit_status"]}
    assert status[FULL_UNIT_1]["status"] == "in_force"
    assert status[UNIT_O27]["status"] == "in_force"


def test_same_output_twice_in_one_block_displaces_first(
        temp_database, shadow_driver):
    # The same output updated twice in ONE block: the view shows the
    # second value, and the ledger marks the first unit displaced BY
    # the second transaction -- displacement attribution stays exact
    # inside a single block.
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    block, result = chain.apply([
        step1._rule_tx(FULL_UNIT_1, seq=0),
        step1._rule_tx(step2.PROBE_UNIT_2, seq=1),
    ])
    assert not result.invalid_tx_ids, result.outcomes
    step2._commit(chain, [(block, result)])
    tx1_hash, tx2_hash = block.tx_ids[0], block.tx_ids[1]
    height = block.header.block_number

    entries = {e["unit"]: e for e in db.get_survival_ledger()}
    e1 = entries[FULL_UNIT_1]
    assert e1["tx_hash"] == tx1_hash
    assert e1["status"] == "displaced"
    assert e1["surviving_fragment"] is None
    assert e1["displacer_tx_hash"] == tx2_hash
    assert e1["displacer_block_height"] == height

    e2 = entries[step2.PROBE_UNIT_2]
    assert e2["tx_hash"] == tx2_hash
    assert e2["status"] == "in_force"
    assert e2["displacer_tx_hash"] is None

    data = step2._view()
    text = data["shared_spec"]["normalized_text"]
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in text
    assert "{ 7 }" not in text
    status = {s["unit"]: s for s in data["shared_spec"]["unit_status"]}
    assert status[FULL_UNIT_1]["status"] == "displaced"
    assert status[FULL_UNIT_1]["displacer"] == {
        "tx_hash": tx2_hash,
        "block_height": height,
    }
    assert status[step2.PROBE_UNIT_2]["status"] == "in_force"


def test_full_displacement_marks_unit_displaced(temp_database, shadow_driver):
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    b1 = chain.apply([step1._rule_tx(FULL_UNIT_1, seq=0)])
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 2, 3)
    b2 = chain.apply([step1._rule_tx(step2.PROBE_UNIT_2, seq=1)])
    assert not b1[1].invalid_tx_ids, b1[1].outcomes
    assert not b2[1].invalid_tx_ids, b2[1].outcomes
    step2._commit(chain, [b1, b2])

    entries = {e["unit"]: e for e in db.get_survival_ledger()}
    e1 = entries[FULL_UNIT_1]
    # Unit 1's only fragment was the o26 assignment; nothing survives.
    assert e1["status"] == "displaced"
    assert e1["surviving_fragment"] is None
    assert e1["displacer_tx_hash"] == b2[0].tx_ids[0]
    assert e1["displacer_block_height"] == b2[0].header.block_number

    # A displaced unit is absent from the in-force text but present in
    # the view's ledger: the absence is the answer, made explicit.
    data = step2._view()
    assert "{ 7 }" not in data["shared_spec"]["normalized_text"]
    status = {s["unit"]: s for s in data["shared_spec"]["unit_status"]}
    assert status[FULL_UNIT_1]["status"] == "displaced"


def test_displacement_ledger_reorg_restores_unit(temp_database, shadow_driver):
    chain, b1, b2 = _probe_chain()
    snapshot_after_b1 = chain.snapshot
    step2._commit(chain, [b1, b2])

    before = {e["unit"]: e for e in db.get_survival_ledger()}
    assert before[step2.PROBE_UNIT_1]["status"] == "partially_displaced"

    # A competing block at b2's height, extending b1, becomes canonical:
    # the displacing block leaves the chain, and the displacement it
    # caused leaves with it. No reversal record is written anywhere --
    # the ledger replay simply never sees the fork block's feeds.
    fork = step2.Chain()
    fork.snapshot = snapshot_after_b1
    fork.height = b2[0].header.block_number
    fork.prev_hash = b1[0].block_hash
    b2f = fork.apply([])
    chain_state._record_rule_outcomes(b2f[0], b2f[1].next_snapshot)
    chain_state._record_shadow_snapshot(b2f[0], b2f[1].next_snapshot)
    db.add_block(b2f[0])
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_hash', ?)", (b2f[0].block_hash,))
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_number', ?)",
            (str(b2f[0].header.block_number),))
        db._db_conn.commit()

    after = {e["unit"]: e for e in db.get_survival_ledger()}
    e1 = after[step2.PROBE_UNIT_1]
    assert e1["status"] == "in_force"
    assert e1["displacer_tx_hash"] is None
    # Unit 2's entry is gone entirely: its only feed was in the block
    # that left the canonical chain.
    assert step2.PROBE_UNIT_2 not in after

    data = step2._view()
    status = {s["unit"]: s for s in data["shared_spec"]["unit_status"]}
    assert status[step2.PROBE_UNIT_1]["status"] == "in_force"


def test_registry_units_are_not_in_the_ledger(temp_database, shadow_driver):
    # A clause install is routed into the registry; it never enters the
    # shadow, so the ledger must not imply it is tracked there -- the
    # registry half of the view is its only representation.
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.set_verdict(step1.CLAUSE_BODY, "1")
    sender_policy.set_evaluator("apply", evaluator)

    chain = step2.Chain()
    b1 = chain.apply([step1._rule_tx(step1.CLAUSE_RULE, seq=0)])
    assert not b1[1].invalid_tx_ids, b1[1].outcomes
    step2._commit(chain, [b1])
    chain_state._lifecycle_manager = chain.lifecycle
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO rule_clauses_v1 "
            "(acceptor_pubkey, target_stream, clause_body) VALUES (?, ?, ?)",
            (ALICE, STREAM, step1.CLAUSE_BODY))
        db._db_conn.commit()

    ledger = db.get_survival_ledger(account=ALICE.lower())
    assert ledger == []

    data = step2._view()
    assert data["registry"]["accepted_clauses"] == [
        {"target_stream": STREAM, "clause_body": step1.CLAUSE_BODY}
    ]
    # No shared-spec unit was ever fed on this chain, so there is no
    # snapshot and no shared-spec half to carry a unit_status.
    assert data["shared_spec"] is None


# --- U6: the receipt carries the shadow revision ------------------------------

def test_confirmed_rule_tx_receipt_carries_shadow_revision(
        temp_database, shadow_driver):
    chain = step2.Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 3, 4)
    tx = step1._rule_tx(step1.SHARED_RULE, seq=0)
    block, result = chain.apply([tx])
    assert not result.invalid_tx_ids, result.outcomes
    step2._commit(chain, [(block, result)])

    container = types.SimpleNamespace(db=db)
    resp = json.loads(gettxstatus.execute(
        f"gettxstatus {block.tx_ids[0]}", container))
    assert resp["status"] == "ok", resp
    served = resp["data"]["rule_outcome"]
    # The design's receipt schema: the live spec-revision pair captured
    # at apply, plus the revision the shadow took when it fed this
    # transaction's unit at commit -- here the shadow's first feed.
    assert served["evidence"]["spec_revision_before"] == 3
    assert served["evidence"]["spec_revision_after"] == 4
    assert served["evidence"]["shadow_revision"] == 1


# --- U7: the rejected side is NOT ours to claim -------------------------------

def test_unsatisfiable_clause_rejected_not_routed(temp_database):
    # o26 = o26*3+1 has no fixed point: the engine hard-rejects it. The
    # design's receipt schema covers CONFIRMED rule transactions; the
    # rejected side is served by the pre-existing dropped-tx branch of
    # gettxstatus (aee9fcc), whose detail carries the engine's outcome.
    # This pins that division: no rule_outcome record may claim the
    # rejected transaction.
    chain = step1.Chain()
    chain.receipt = step1._receipt("REJECTED_NOT_ROUTED", 3, 3)
    tx = step1._rule_tx(UNSAT_UNIT, seq=0)
    block, result = chain.apply([tx])
    tx_hash = block.tx_ids[0]

    assert tx["tx_id"] in result.invalid_tx_ids, result.outcomes
    assert step1._outcomes_of(result) == []

    # The commit path records no rule outcome for it either.
    chain_state._record_rule_outcomes(block, result.next_snapshot)
    assert db.get_rule_outcome(tx_hash, block.block_hash) is None

    # What createblock does with the verdict (its step 6): derive the
    # dropped-tx detail from the apply outcome exactly as
    # commands/createblock.py builds rejected_details, and record the
    # drop. (In production the mempool's tx_id IS the hash gettxstatus is
    # queried by; the harness's synthetic tx_id is not, so the drop is
    # keyed by the block-computed hash.)
    rejected_details = {}
    for outcome in result.outcomes or []:
        if outcome.tx_id in result.invalid_tx_ids:
            logs = [str(line) for line in (outcome.receipt_logs or [])]
            rejected_details[tx_hash] = (outcome.reason, " | ".join(logs))
    assert tx_hash in rejected_details
    db.record_dropped_txs([tx_hash], "rejected", rejected_details)

    container = types.SimpleNamespace(db=db)
    resp = json.loads(gettxstatus.execute(f"gettxstatus {tx_hash}", container))
    assert resp["status"] == "ok", resp
    data = resp["data"]
    assert data["status"] == "rejected"
    assert data["reason"] == "rule_rejected"
    assert "REJECTED_NOT_ROUTED" in data["detail"]
    assert "rule_outcome" not in data
