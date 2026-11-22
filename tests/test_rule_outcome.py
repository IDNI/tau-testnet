"""Issue #42, milestone 1: gettxstatus exposes the apply outcome of a
confirmed rule transaction.

The engine's revision receipt for a rule step lives in a process global
that every later Tau step of the same transaction overwrites (the fee
steps included), so the outcome is captured inside the op-"0" branch of
block apply, immediately after the rule step. These tests drive the real
apply_block with Tau communication stubbed at the manager seam (the
pattern of tests/test_apply_block_outcome_key.py): the stub hands back
revision receipts of exactly the shape tau_native._build_revision_receipt
produces, and the assertions follow the outcome from the apply receipt
to the snapshot metadata, into the node's persistent record, and out of
gettxstatus.

The native test at the bottom projects a real TauInterface receipt
through the same code when the native bindings are usable, and skips
otherwise.
"""
import json
import os
import types
from pathlib import Path
from unittest.mock import patch

import pytest

import chain_state
import db
from block import Block
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_tx
from commands import gettxstatus
from consensus.engine import (
    ActiveConsensusView,
    TauConsensusEngine,
    _rule_outcome_from_receipt,
)
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot

REPO_ROOT = Path(__file__).resolve().parents[1]
HEIGHT = 1
ALICE = pubkey_hex(SK_ALICE)
CONSENSUS_RULES = "always (o6[t]:bv[16] = i10[t]:bv[16])."

# The maintainers' displacement probe from issue #42, as two rule units.
RULE_INSTALL = (
    "always ( o26[t]:bv[64] = { 7 }:bv[64] && o27[t]:bv[64] = { 9 }:bv[64] )."
)
RULE_DISPLACE = "always ( o26[t]:bv[64] = { 3 }:bv[64] )."


def _receipt(outcome, before, after, o0="F"):
    """A revision receipt in tau_native._build_revision_receipt's shape."""
    return {
        "outcome": outcome,
        "accepted": outcome in ("ACCEPTED_CHANGED", "ACCEPTED_NOOP"),
        "changed": outcome == "ACCEPTED_CHANGED",
        "delivered": True,
        "outputs": {"o0": o0} if o0 is not None else None,
        "spec_revision_before": before,
        "spec_revision_after": after,
    }


def _receipt_feed(receipts):
    """get_last_revision_receipt stand-in.

    The receipt is read twice per rule step (the session records it, then
    the engine reads it back), and both reads must see the same receipt;
    the feed advances every second read.
    """
    state = {"reads": 0}

    def _next():
        idx = min(state["reads"] // 2, len(receipts) - 1)
        state["reads"] += 1
        return receipts[idx]

    return _next


def _rule_tx(tx_id, rule, seq=0):
    return sign_tx({
        "tx_id": tx_id,
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "fee_limit": "100",
        "operations": {"0": rule},
    })


def _apply_block(txs, receipts, landed_rules):
    """Run the real apply_block with the Tau seam stubbed.

    `landed_rules` is the application-rules accumulation the landed check
    reads back: the preprocessed units, as the rules handler would have
    persisted them.
    """
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    parent_snapshot = TauStateSnapshot(
        state_hash="0" * 64,
        tau_bytes=b"always (o0[t]=1).",
        metadata={
            "balances": {ALICE: 100000},
            "sequence_numbers": {},
            "last_transfer_ts": {},
            "lifecycle_manager": lm,
            "consensus_rules_state": CONSENSUS_RULES,
            "active_consensus_id": "",
        },
    )
    active_view = ActiveConsensusView(
        target_height=HEIGHT,
        consensus_rules=CONSENSUS_RULES,
        active_validators=[bytes.fromhex(ALICE)],
        mechanism_specific_metadata={"poa": True},
    )
    block_obj = Block.create(
        block_number=HEIGHT, previous_hash="00" * 32, transactions=txs,
        proposer_pubkey=ALICE, timestamp=1234567890,
    )
    landed_text = "\n".join(
        chain_state._preprocess_tau_spec_text(r) or r for r in landed_rules
    )

    def _fake_multi(**kwargs):
        return {5: "1", 6: "1", 7: "1", 8: "0", 9: "0"}

    engine = TauConsensusEngine()
    with patch("tau_manager.communicate_with_tau", return_value="T"), \
         patch("tau_manager.communicate_with_tau_multi", side_effect=_fake_multi), \
         patch("tau_manager.get_last_revision_receipt",
               side_effect=_receipt_feed(receipts)), \
         patch("chain_state.get_application_rules_state", return_value=landed_text), \
         patch("chain_state.save_application_rules_state", return_value=None), \
         patch("tau_manager.tau_ready") as ready:
        ready.is_set.return_value = True
        return engine.apply_block(active_view, block_obj, parent_snapshot), block_obj


def _set_canonical_head(block_hash, number):
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_hash', ?)",
            (block_hash,),
        )
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_number', ?)",
            (str(number),),
        )
        db._db_conn.commit()


def _status(tx_hash):
    resp = json.loads(
        gettxstatus.execute(
            f"gettxstatus {tx_hash}", types.SimpleNamespace(db=db)
        )
    )
    assert resp["status"] == "ok", resp
    return resp["data"]


def _confirm(block_obj, result):
    """Persist the block and the outcomes its apply produced, as commit does."""
    genesis = Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey=ALICE, timestamp=1234567889,
    )
    db.add_block(genesis)
    db.add_block(block_obj)
    _set_canonical_head(block_obj.block_hash, HEIGHT)
    chain_state._record_rule_outcomes(block_obj, result.next_snapshot)


# --- the projection itself ---------------------------------------------------


def test_projection_of_a_missing_or_foreign_receipt_is_none():
    assert _rule_outcome_from_receipt(None) is None
    assert _rule_outcome_from_receipt("not a receipt") is None


def test_projection_without_outputs_has_no_verdict():
    outcome = _rule_outcome_from_receipt(
        _receipt("ACCEPTED_CHANGED", 3, 4, o0=None)
    )
    assert outcome["revision_taken"] is None
    assert outcome["spec_revision_before"] == 3
    assert outcome["spec_revision_after"] == 4


# --- apply: capture and harvest ----------------------------------------------


def test_confirmed_rule_tx_exposes_revision_taken(temp_database):
    """The named test for milestone 1 (issue #42, point 2).

    A confirmed rule transaction's gettxstatus carries the apply outcome:
    the revision taken (the engine's o0 verdict) and the spec_revision
    before/after its rule step, advanced -- the wallet-side proof that the
    rule took effect, with no engine re-run.
    """
    tx = _rule_tx("install-1", RULE_INSTALL)
    result, block_obj = _apply_block(
        [tx], [_receipt("ACCEPTED_CHANGED", 3, 4)], [RULE_INSTALL]
    )
    assert result.accepted_tx_ids == ["install-1"]
    tx_hash = block_obj.tx_ids[0]

    (recorded_hash, outcome), = result.next_snapshot.metadata["rule_outcomes"]
    assert recorded_hash == tx_hash
    assert outcome["spec_revision_before"] == 3
    assert outcome["spec_revision_after"] == 4
    assert outcome["spec_revision_after"] > outcome["spec_revision_before"]
    assert outcome["revision_taken"] == "F"
    assert outcome["outcome"] == "ACCEPTED_CHANGED"
    assert any("Rule applied" in log for log in outcome["logs"])

    _confirm(block_obj, result)
    data = _status(tx_hash)
    assert data["status"] == "confirmed"
    served = data["rule_outcome"]
    assert served["spec_revision_before"] == 3
    assert served["spec_revision_after"] == 4
    assert served["revision_taken"] == "F"
    assert served["outcome"] == "ACCEPTED_CHANGED"


def test_displacing_confirmation_reports_the_revision_it_took(temp_database):
    """Two rule transactions in one block: the second displaces part of the
    first (the o26 probe), and its recorded outcome reports the revision IT
    took -- before == the first outcome's after -- not the first one's."""
    first = _rule_tx("install-1", RULE_INSTALL, seq=0)
    second = _rule_tx("displace-1", RULE_DISPLACE, seq=1)
    result, block_obj = _apply_block(
        [first, second],
        [_receipt("ACCEPTED_CHANGED", 3, 4), _receipt("ACCEPTED_CHANGED", 4, 5)],
        [RULE_INSTALL, RULE_DISPLACE],
    )
    assert result.accepted_tx_ids == ["install-1", "displace-1"]
    outcomes = dict(result.next_snapshot.metadata["rule_outcomes"])
    first_hash, second_hash = block_obj.tx_ids
    assert outcomes[first_hash]["spec_revision_before"] == 3
    assert outcomes[first_hash]["spec_revision_after"] == 4
    assert outcomes[second_hash]["spec_revision_before"] == 4
    assert outcomes[second_hash]["spec_revision_after"] == 5
    assert outcomes[second_hash]["revision_taken"] == "F"

    _confirm(block_obj, result)
    served = _status(second_hash)["rule_outcome"]
    assert served["spec_revision_before"] == 4
    assert served["spec_revision_after"] == 5


def test_noop_confirmation_is_recorded_as_a_noop(temp_database):
    """A rule the engine consumes without changing the spec (ACCEPTED_NOOP)
    is confirmed and charged like any rule transaction; its outcome is
    recorded with after == before, so a wallet can tell 'took effect as a
    no-op' apart from 'not recorded'."""
    tx = _rule_tx("noop-1", RULE_INSTALL)
    result, block_obj = _apply_block(
        [tx], [_receipt("ACCEPTED_NOOP", 4, 4)], [RULE_INSTALL]
    )
    assert result.accepted_tx_ids == ["noop-1"]
    (recorded_hash, outcome), = result.next_snapshot.metadata["rule_outcomes"]
    assert recorded_hash == block_obj.tx_ids[0]
    assert outcome["outcome"] == "ACCEPTED_NOOP"
    assert outcome["spec_revision_before"] == 4
    assert outcome["spec_revision_after"] == 4
    assert outcome["revision_taken"] == "F"

    _confirm(block_obj, result)
    served = _status(block_obj.tx_ids[0])["rule_outcome"]
    assert served["outcome"] == "ACCEPTED_NOOP"
    assert served["spec_revision_after"] == served["spec_revision_before"]


def test_rejected_rule_tx_records_no_outcome():
    """A rule the engine does not route is hard-rejected; rejected
    transactions keep exactly their previous behaviour and record nothing."""
    tx = _rule_tx("rejected-1", RULE_INSTALL)
    result, _ = _apply_block(
        [tx], [_receipt("REJECTED_NOT_ROUTED", 3, 3, o0="T")], [RULE_INSTALL]
    )
    assert result.next_snapshot.metadata["rule_outcomes"] == []
    assert result.invalid_tx_ids == ["rejected-1"]


def test_confirmed_non_rule_tx_has_no_rule_outcome(temp_database):
    """A plain transfer confirms as before, with no rule_outcome key: the
    field's absence stays meaningful."""
    tx = sign_tx({
        "tx_id": "plain-1",
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, pubkey_hex(SK_BOB), "5"]]},
    })
    result, block_obj = _apply_block([tx], [], [])
    assert result.accepted_tx_ids == ["plain-1"]
    assert result.next_snapshot.metadata["rule_outcomes"] == []
    _confirm(block_obj, result)
    data = _status(block_obj.tx_ids[0])
    assert data["status"] == "confirmed"
    assert "rule_outcome" not in data


# --- the real engine's receipt, when the bindings are usable ------------------


def _native_available():
    try:
        import tau_native

        tau_native.load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not _native_available(), reason="native tau bindings unavailable"
)
def test_native_receipt_projects_to_rule_outcome():
    """Against the real engine: the displacement probe's two rule steps
    produce revision receipts whose projections chain (the second step's
    before is the first step's after) and report the o0 verdict 'F'."""
    import tau_native

    iface = tau_native.TauInterface(str(REPO_ROOT / "genesis.tau"))
    iface.communicate(rule_text=RULE_INSTALL)
    first = _rule_outcome_from_receipt(iface.last_revision_receipt)
    assert first["revision_taken"] == "F"
    assert first["outcome"] == "ACCEPTED_CHANGED"
    assert first["spec_revision_after"] > first["spec_revision_before"]

    iface.communicate(rule_text=RULE_DISPLACE)
    second = _rule_outcome_from_receipt(iface.last_revision_receipt)
    assert second["revision_taken"] == "F"
    assert second["spec_revision_before"] == first["spec_revision_after"]
    assert second["spec_revision_after"] > second["spec_revision_before"]


# --- the worker session's receipt (the live block-apply path) -----------------
#
# Block application drives rules through a WorkerSession, whose receipt is
# built by the speculation worker in its own process. That receipt used to
# carry the outcome and the o0 verdict but NOT the revision counters (it
# exposed only the post-step `spec_revision` from its state observation),
# so on live nodes the projection above recorded null before/after while
# the in-process path -- the one the tests up to here exercise -- populated
# them. The worker now reports `spec_revision_before` / `spec_revision_after`
# bracketing the revise call, under the same names as the in-process
# receipt. The first test below runs the real worker; the second pins the
# WorkerSession-side contract with a faithful stand-in for its receipt, so
# the regression is covered even where the native bindings are unavailable.


def _router_spec():
    genesis = (REPO_ROOT / "genesis.tau").read_text(encoding="utf-8")
    return f"always ( {genesis.strip()} )."


@pytest.mark.skipif(
    not _native_available(), reason="native tau bindings unavailable"
)
def test_worker_session_receipt_carries_revision_counters():
    """Through a real WorkerSession (the live apply path): the displacement
    probe's two rule steps record populated, chaining revision counters --
    install 0 -> 1, displacement 1 -> 2 -- with the o0 verdict 'F'."""
    import tau_session

    env = dict(os.environ)
    env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    session = tau_session.WorkerSession.spawn(
        _router_spec(), cwd=str(REPO_ROOT), env=env
    )
    try:
        assert session.apply_rule(RULE_INSTALL) == "ok"
        first = _rule_outcome_from_receipt(session.last_receipt())
        assert first["outcome"] == "ACCEPTED_CHANGED"
        assert first["revision_taken"] == "F"
        assert first["spec_revision_before"] == 0
        assert first["spec_revision_after"] == 1

        assert session.apply_rule(RULE_DISPLACE) == "ok"
        second = _rule_outcome_from_receipt(session.last_receipt())
        assert second["outcome"] == "ACCEPTED_CHANGED"
        assert second["revision_taken"] == "F"
        assert second["spec_revision_before"] == first["spec_revision_after"]
        assert second["spec_revision_after"] == 2
    finally:
        session.dispose()


def test_worker_session_passes_the_workers_counters_through():
    """A faithful stand-in for the speculation worker's receipt, driven
    through a real WorkerSession: last_receipt() must hand the projection
    the worker's own before/after pair for the step, not a later read."""
    import tau_session
    from tau_speculation import RevisionReceipt

    worker_receipt = RevisionReceipt({
        "ok": True,
        "outcome": "ACCEPTED_CHANGED",
        "candidate_id": "apply",
        "consumed": True,
        "asked": ["i0"],
        "outputs": {"o0": "F"},
        "filler_steps": [],
        "diagnostics": "",
        "report": {"errors": [], "warnings": [], "codes": [],
                   "has_error": False, "awaiting_input": False},
        "deferred_diagnostics": "",
        "capture_complete": True,
        "binding_id": "fake",
        "spec_revision_before": 7,
        "spec_revision_after": 8,
        "time_point": 0,
        "spec_revision": 8,
    })

    class _FakeSpec:
        def revise(self, candidate, candidate_id="", *, timeout=None):
            return worker_receipt

        def step(self, inputs, *, timeout=None):
            return {"ok": True, "outputs": {}}

        def kill(self):
            pass

    session = tau_session.WorkerSession(_FakeSpec())
    assert session.apply_rule(RULE_INSTALL) == "ok"
    outcome = _rule_outcome_from_receipt(session.last_receipt())
    assert outcome["spec_revision_before"] == 7
    assert outcome["spec_revision_after"] == 8
    assert outcome["revision_taken"] == "F"
    assert outcome["outcome"] == "ACCEPTED_CHANGED"
