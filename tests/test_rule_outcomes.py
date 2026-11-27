"""Issue #42: a confirmed rule transaction exposes its apply outcome.

Step 1 of the bounty-02 design. Both rule paths record ONE receipt shape on
the transaction at apply --

* shared spec path: the engine's revision receipt (outcome + the
  spec-revision pair as evidence);
* clause registry path: the registry outcome (registered / replaced /
  revoked + the clause-registry root pair as evidence) -- and NEVER a spec
  revision, because a registry install takes none. Claiming one is the lie
  the original bug report is about.

The records ride the block's snapshot to the commit path, which persists
them per block (chain_state._record_rule_outcomes, mirroring the
retractable-events write), and gettxstatus serves the record on the
confirmed branch.

Mock evaluator throughout: what is under test is the capture, persistence
and serving of the outcome, not Tau semantics (the native suites cover the
real engine's receipts).
"""
import json
import types
from unittest.mock import patch

import pytest

import chain_state
import db
import tau_defs
from block import Block
from bls_keys import SK_ALICE, pubkey_hex, sign_payload
from commands import gettxstatus
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.rule_offers import clause_body_v1
from consensus.state import TauStateSnapshot

import test_approval_apply as ap

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
HEIGHT = 20

ALICE = pubkey_hex(SK_ALICE)

# A rule that does NOT write o5: it takes the shared accumulation path.
SHARED_RULE = "always ( o12[t]:bv[24] = i1[t]:bv[24] )."
# An o5 policy rule: always routed into the clause registry.
CLAUSE_RULE = (
    "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
    ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
CLAUSE_BODY = clause_body_v1(CLAUSE_RULE)


@pytest.fixture(autouse=True)
def _reset_evaluators():
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def _receipt(outcome, before, after):
    return {
        "outcome": outcome,
        "accepted": outcome in ("ACCEPTED_CHANGED", "ACCEPTED_NOOP"),
        "changed": outcome == "ACCEPTED_CHANGED",
        "delivered": True,
        "outputs": {"o0": "F"},
        "spec_revision_before": before,
        "spec_revision_after": after,
    }


class Chain:
    """Applies blocks through the real engine on a mock evaluator, in the
    shape of test_clause_registration.Chain. The manager's last revision
    receipt is scripted per test via `receipt`."""

    def __init__(self):
        self.height = HEIGHT
        self.receipt = None
        self.lifecycle = ConsensusLifecycleManager(active_validators=[ap.ALICE])
        self.lifecycle.activate_approval_slots()
        self.snapshot = TauStateSnapshot(
            state_hash="0" * 64,
            tau_bytes=b"always (o0[t]=1).",
            metadata={
                "balances": {ALICE: 1_000_000, ap.ALICE: 1_000_000},
                "sequence_numbers": {},
                "last_transfer_ts": {},
                "lifecycle_manager": self.lifecycle,
                "consensus_rules_state": "always (o6[t]:bv[16] = i10[t]:bv[16]).",
                "active_consensus_id": "",
            },
        )

    def apply(self, txs):
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=self.snapshot.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ap.ALICE)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash="00" * 32, transactions=txs,
            proposer_pubkey=ap.ALICE, timestamp=1234567890,
        )
        persisted = []

        def single(**kwargs):
            if kwargs.get("rule_text") and kwargs.get("apply_rules_update"):
                persisted.append(str(kwargs["rule_text"]).strip())
            return "T"

        def multi(**kwargs):
            vals = kwargs.get("input_stream_values") or {}
            return {1: str(vals.get(1, "0")), 5: "1", 8: "0", 9: "0"}

        with patch("tau_manager.communicate_with_tau", side_effect=single), \
             patch("tau_manager.communicate_with_tau_multi", side_effect=multi), \
             patch("tau_manager.get_last_revision_receipt",
                   side_effect=lambda: self.receipt), \
             patch("chain_state.get_application_rules_state",
                   side_effect=lambda: "\n".join(persisted)), \
             patch("tau_manager.tau_ready") as ready:
            ready.is_set.return_value = True
            result = TauConsensusEngine().apply_block(view, block, self.snapshot)
        self.snapshot = result.next_snapshot
        self.lifecycle = self.snapshot.metadata["lifecycle_manager"]
        self.height += 1
        return block, result


def _rule_tx(rule, seq=0):
    tx = {
        "tx_id": f"rule-{seq}-{abs(hash(rule)) % 99999}",
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "expire_at_height": 5000,
        "fee_limit": "100",
        "operations": {"0": rule},
    }
    return sign_payload(tx, SK_ALICE)


def _commit_and_status(block, result, tx_hash):
    """Run the commit-path recorder exactly as process_new_block does, then
    serve the tx through gettxstatus on a canonical chain containing it."""
    chain_state._record_rule_outcomes(block, result.next_snapshot)
    genesis = Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey=ap.ALICE, timestamp=1_700_000_000)
    db.add_block(genesis)
    db.add_block(block)
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_hash', ?)", (block.block_hash,))
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_number', ?)", (str(block.header.block_number),))
        db._db_conn.commit()
    container = types.SimpleNamespace(db=db)
    resp = json.loads(gettxstatus.execute(f"gettxstatus {tx_hash}", container))
    assert resp["status"] == "ok", resp
    return resp["data"]


def _outcomes_of(result):
    return result.next_snapshot.metadata.get("rule_outcomes") or []


# --- shared spec path ---------------------------------------------------------

def test_confirmed_rule_tx_exposes_revision_taken(temp_database):
    chain = Chain()
    chain.receipt = _receipt("ACCEPTED_CHANGED", 3, 4)
    tx = _rule_tx(SHARED_RULE)
    block, result = chain.apply([tx])

    assert not result.invalid_tx_ids, result.outcomes
    records = _outcomes_of(result)
    assert len(records) == 1
    tx_hash, record = records[0]
    assert tx_hash == block.tx_ids[0]
    assert record["account"] == ALICE.lower()
    assert record["path"] == "shared_spec"
    assert record["outcome"] == "ACCEPTED_CHANGED"
    assert record["evidence"] == {
        "spec_revision_before": 3, "spec_revision_after": 4}

    data = _commit_and_status(block, result, tx_hash)
    assert data["status"] == "confirmed"
    served = data["rule_outcome"]
    assert served["tx_hash"] == tx_hash
    assert served["block_height"] == block.header.block_number
    assert served["path"] == "shared_spec"
    assert served["outcome"] == "ACCEPTED_CHANGED"
    assert served["evidence"]["spec_revision_after"] == 4


def test_confirmed_rule_tx_noop_outcome(temp_database):
    chain = Chain()
    chain.receipt = _receipt("ACCEPTED_NOOP", 7, 7)
    tx = _rule_tx(SHARED_RULE)
    block, result = chain.apply([tx])

    assert not result.invalid_tx_ids, result.outcomes
    records = _outcomes_of(result)
    assert len(records) == 1
    tx_hash, record = records[0]
    assert record["path"] == "shared_spec"
    assert record["outcome"] == "ACCEPTED_NOOP"
    # A no-op is told apart from a change BY the evidence: the revision pair
    # does not advance.
    assert record["evidence"] == {
        "spec_revision_before": 7, "spec_revision_after": 7}

    data = _commit_and_status(block, result, tx_hash)
    assert data["rule_outcome"]["outcome"] == "ACCEPTED_NOOP"


# --- clause registry path -----------------------------------------------------

def test_clause_install_receipt_claims_no_revision(temp_database):
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.set_verdict(CLAUSE_BODY, "1")
    sender_policy.set_evaluator("apply", evaluator)

    chain = Chain()
    root_before = chain.lifecycle.rule_offers.clauses_root().hex()
    tx = _rule_tx(CLAUSE_RULE)
    block, result = chain.apply([tx])

    assert not result.invalid_tx_ids, result.outcomes
    assert chain.lifecycle.rule_offers.clause_for(ALICE, STREAM) == CLAUSE_BODY
    root_after = chain.lifecycle.rule_offers.clauses_root().hex()
    assert root_after != root_before

    records = _outcomes_of(result)
    assert len(records) == 1
    tx_hash, record = records[0]
    assert record["account"] == ALICE.lower()
    assert record["path"] == "registry"
    assert record["outcome"] == "CLAUSE_REGISTERED"
    assert record["evidence"] == {
        "rule_clauses_root_before": root_before,
        "rule_clauses_root_after": root_after,
    }
    # The headline invariant: a registry install takes NO spec revision, so
    # no revision field may appear anywhere in the record.
    assert "spec_revision" not in json.dumps(record)

    data = _commit_and_status(block, result, tx_hash)
    assert data["status"] == "confirmed"
    served = data["rule_outcome"]
    assert served["path"] == "registry"
    assert served["outcome"] == "CLAUSE_REGISTERED"
    assert served["evidence"]["rule_clauses_root_after"] == root_after
    assert "spec_revision" not in json.dumps(served)


# --- absence: no behaviour change for non-rule transactions -------------------

def test_confirmed_plain_transfer_has_no_rule_outcome(temp_database):
    tx = {"tx_id": "t", "operations": {"1": [["a" * 96, "b" * 96, "1"]]}}
    genesis = Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey="a" * 96, timestamp=1_700_000_000)
    blk = Block.create(
        block_number=1, previous_hash=genesis.block_hash, transactions=[tx],
        proposer_pubkey="a" * 96, timestamp=1_700_000_001)
    db.add_block(genesis)
    db.add_block(blk)
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_hash', ?)", (blk.block_hash,))
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_number', ?)", ("1",))
        db._db_conn.commit()
    container = types.SimpleNamespace(db=db)
    resp = json.loads(gettxstatus.execute(
        f"gettxstatus {blk.tx_ids[0]}", container))
    assert resp["status"] == "ok", resp
    assert resp["data"]["status"] == "confirmed"
    assert "rule_outcome" not in resp["data"]
