"""Issue #42 stage 2 (B02-5): getpaymentconditions, two sides at one block.

The command evaluates the sender's and the recipient's registered o5
clauses against one hypothetical transfer, through the same helper
admission and apply use (`sender_policy.clause_blocks`), pinned to one
block's spec view. The clause verdicts here come from the mock policy
evaluator with per-body decide functions over the transfer inputs --
the parity assertions compare the command's verdict against a direct
`clause_blocks` call on the identical input map, which is exactly the
call sendtx's admission makes for the sender side.
"""
import json
from types import SimpleNamespace

import pytest

import chain_state
import db
import tau_defs
from bls_keys import pubkey_hex
from commands import getpaymentconditions
from consensus import active_rules, sender_policy
from consensus.policy_mock import MockPolicyEvaluator

SENDER = pubkey_hex(33333)
RECIPIENT = pubkey_hex(44444)
STRANGER = pubkey_hex(55555)

SENDER_CLAUSE = "(i1[t] <= { 500 }) ? o5[t] = { 1 } : o5[t] = { 0 }"
RECIPIENT_CLAUSE = "(i1[t] <= { 300 }) ? o5[t] = { 1 } : o5[t] = { 0 }"

GENESIS_HASH = "aa" * 32


def _exec(raw):
    container = SimpleNamespace(db=db, chain_state=chain_state)
    return json.loads(getpaymentconditions.execute(raw, container))


def _build_chain_with_snapshot():
    """One canonical block at height 1 with a commit record, and a spec
    snapshot recorded for it -- the minimum chain the command resolves
    against. Returns the block hash."""
    block_hash = f"{1:064x}"
    ts = 1700000100
    with db._db_lock:
        cur = db._db_conn.cursor()
        cur.execute(
            'INSERT INTO blocks (block_hash, block_number, previous_hash, '
            'timestamp, block_data) VALUES (?,?,?,?,?)',
            (GENESIS_HASH, 0, "", 1700000000, "{}"))
        cur.execute(
            'INSERT INTO blocks (block_hash, block_number, previous_hash, '
            'timestamp, block_data) VALUES (?,?,?,?,?)',
            (block_hash, 1, GENESIS_HASH, ts, "{}"))
        cur.execute(
            'INSERT INTO block_commits_v1 (execution_id, tip, parent, '
            'journal_head, allocator_digest, plan_id, plan_json, '
            'spec_revision, time_point, committed_at) '
            'VALUES (?,?,?,?,?,?,?,?,?,?)',
            ("exec-1", block_hash, GENESIS_HASH, "headlink", "digest",
             None, None, 1, ts, ts))
        cur.execute(
            'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
            ("canonical_head_hash", block_hash))
        db._db_conn.commit()
    spec = "always ( o26[t]:bv[24] = { #x000003 }:bv[24] )."
    db.record_spec_snapshot(1, 1, spec, active_rules.spec_hash_of(spec))
    return block_hash


def _register_clause(account, body):
    with db._db_lock:
        db._db_conn.execute(
            'INSERT OR REPLACE INTO rule_clauses_v1 '
            '(acceptor_pubkey, target_stream, clause_body) VALUES (?, ?, ?)',
            (account.lower(), tau_defs.USER_POLICY_STREAM_INDEX, body))
        db._db_conn.commit()


@pytest.fixture
def clauses(temp_database):
    """Both sides registered; the mock evaluator judges by amount:
    the sender's clause blocks above 500, the recipient's above 300."""
    _build_chain_with_snapshot()
    _register_clause(SENDER, SENDER_CLAUSE)
    _register_clause(RECIPIENT, RECIPIENT_CLAUSE)
    mock = MockPolicyEvaluator(pool="admission")
    mock.set_verdict(
        SENDER_CLAUSE, lambda inputs: "1" if int(inputs["i1"]) <= 500 else "0")
    mock.set_verdict(
        RECIPIENT_CLAUSE,
        lambda inputs: "1" if int(inputs["i1"]) <= 300 else "0")
    sender_policy.set_evaluator("admission", mock)
    chain_state._balances[SENDER] = 100000
    yield mock
    sender_policy.set_evaluator("admission", None)
    chain_state._balances.pop(SENDER, None)


def _direct_verdict(body, amount):
    """The node's own verdict call on the same map the command builds."""
    values = {
        1: str(amount), 2: "100000",
        3: "{ #x" + SENDER + " }:bv[384]",
        4: "{ #x" + RECIPIENT + " }:bv[384]",
        12: "{ #x" + SENDER + " }:bv[384]",
        5: "1700000100",
    }
    for slot in tau_defs.approval_slot_indices():
        values[slot] = "0"
    blocked, _detail = sender_policy.clause_blocks(
        body, values, pool="admission")
    return blocked


def test_both_sides_evaluated_at_one_block(clauses):
    resp = _exec(f"getpaymentconditions {SENDER} {RECIPIENT} 250")
    assert resp["status"] == "ok", resp
    data = resp["data"]
    assert data["available"] is True
    assert data["advisory"] is True
    assert data["block"]["height"] == 1
    assert data["spec"]["spec_revision"] == 1
    assert data["clauses_from"] == "current_registry"
    assert data["sender_side"] == {
        "account": SENDER, "has_clause": True,
        "blocked": False, "detail": "1"}
    assert data["recipient_side"]["has_clause"] is True
    assert data["recipient_side"]["blocked"] is False
    assert data["allowed"] is True


def test_recipient_cap_refusal_matches_node_verdict(clauses):
    """Parity: an amount above the recipient's cap is refused by the
    command's recipient side, and the node's own clause_blocks call on
    the identical map refuses it too; the sender side (cap 500) still
    admits 400, so the refusal is the recipient's alone."""
    data = _exec(f"getpaymentconditions {SENDER} {RECIPIENT} 400")["data"]
    assert data["sender_side"]["blocked"] is False
    assert data["recipient_side"]["blocked"] is True
    assert data["allowed"] is False
    assert _direct_verdict(RECIPIENT_CLAUSE, 400) is True
    assert _direct_verdict(SENDER_CLAUSE, 400) is False


def test_sender_clause_refusal(clauses):
    data = _exec(f"getpaymentconditions {SENDER} {RECIPIENT} 600")["data"]
    assert data["sender_side"]["blocked"] is True
    assert data["allowed"] is False
    assert _direct_verdict(SENDER_CLAUSE, 600) is True


def test_side_without_clause_is_neutral(temp_database):
    _build_chain_with_snapshot()
    _register_clause(SENDER, SENDER_CLAUSE)
    mock = MockPolicyEvaluator(pool="admission")
    mock.set_verdict(SENDER_CLAUSE, "1")
    sender_policy.set_evaluator("admission", mock)
    try:
        data = _exec(
            f"getpaymentconditions {SENDER} {STRANGER} 250")["data"]
    finally:
        sender_policy.set_evaluator("admission", None)
    assert data["recipient_side"] == {
        "account": STRANGER, "has_clause": False,
        "blocked": False, "detail": None}
    assert data["allowed"] is True


def test_explicit_height_and_usage_errors(clauses):
    data = _exec(f"getpaymentconditions {SENDER} {RECIPIENT} 250 1")["data"]
    assert data["block"]["height"] == 1
    assert data["allowed"] is True

    bad = _exec(f"getpaymentconditions {SENDER} {RECIPIENT}")
    assert bad["status"] == "error"
    bad = _exec(f"getpaymentconditions xyz {RECIPIENT} 250")
    assert bad["status"] == "error"
    bad = _exec(f"getpaymentconditions {SENDER} {RECIPIENT} -5")
    assert bad["status"] == "error"
