"""Bounty 02 (issue #42): the active-rules view and confirmed rule outcomes.

The seven tests named in the design are here verbatim:

  point 2 -- test_confirmed_rule_tx_shows_apply_outcome,
             test_receipt_capture_not_clobbered_by_later_steps
  point 1 -- test_displacement_probe_view_matches_engine,
             test_view_text_and_hash_equal_across_nodes_and_replay,
             test_view_uses_canonical_full_width_text
  both    -- test_displacing_tx_receipt_and_view_agree,
             test_same_block_install_and_replace

plus supporting cases (no-op outcome, unrouted rule, non-rule transaction,
account attribution, pre-snapshot heights, gettaustate compatibility) and
the follow-up hardening cases: the view's text composed from the persisted
accumulation with the manager global poisoned, registry-routed rule
outcomes, and receipt logs in the stored outcome.

Execution path: the native Tau engine cannot run in this environment (no
tau-lang build is present), so the tests drive the real apply_block with
Tau communication stubbed at the tau_manager seam -- the pattern of
tests/test_apply_block_outcome_key.py -- using a fake evaluator that
implements the one engine behaviour the view depends on: pointwise
revision of the composed spec, with a revision counter that advances only
when the composed text changes, and revision receipts in exactly the
shape tau_native._build_revision_receipt produces. Assertions follow the
outcome from the apply receipt into the node's persistent record and out
of gettxstatus / getactiverules. The companion native test lives in
tests/test_active_rules_view_native.py, registered in the native-tau-tests
CI job: it checks the real receipt's shape against what gettxstatus
serves, on the real engine.
"""
import hashlib
import json
import re
import types
from contextlib import ExitStack
from unittest.mock import patch

import pytest

import chain_state
import config
import db
import tau_defs
from block import Block
from bls_keys import SK_ALICE, SK_BOB, pubkey_hex, sign_tx
from commands import getactiverules, gettaustate, gettxstatus
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.state import TauStateSnapshot

ALICE = pubkey_hex(SK_ALICE)
BOB = pubkey_hex(SK_BOB)
CONSENSUS_RULES = "always (o6[t]:bv[16] = i10[t]:bv[16])."
GENESIS_TS = 1_700_000_000

# The maintainers' displacement probe from issue #42, as two rule units.
RULE_INSTALL = (
    "always ( o26[t]:bv[64] = { 7 }:bv[64] && o27[t]:bv[64] = { 9 }:bv[64] )."
)
RULE_DISPLACE = "always ( o26[t]:bv[64] = { 3 }:bv[64] )."
# A rule scoped to one sender by an i12 guard (the account-view case).
RULE_GUARDED_ALICE = (
    "always ( ( i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]"
    " -> ( o26[t]:bv[64] = { 5 }:bv[64] ) ) )."
)
# Two pointwise-contradictory assignments in one unit: the engine cannot
# route it, so the revision is not taken.
RULE_UNROUTABLE = (
    "always ( o26[t]:bv[64] = { 7 }:bv[64] && o26[t]:bv[64] = { 8 }:bv[64] )."
)

_ASSIGNMENT_RE = re.compile(
    r"(o\d+)\[t\]:(bv\[\d+\])\s*=\s*\{\s*([0-9]+|#x[0-9a-fA-F]+)\s*\}:bv\[\d+\]"
)


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


class FakeTauEngine:
    """Pointwise-revision stand-in for the native interpreter.

    State the view depends on:
      assignments -- output stream -> (literal, width), composed pointwise:
                     a later assignment to a stream replaces the earlier one
      extras      -- guarded units, kept as bodies in arrival order
      revision    -- the spec revision counter; advances only when the
                     composed text actually changes
      accumulation-- the submitted units, as the rules handler persists them
      last_receipt-- the receipt slot: EVERY step overwrites it, fee steps
                     included (arm `clobber_receipt` to make them leave a
                     marker behind) -- the hazard the capture defends against
    """

    def __init__(self):
        self.assignments = {}
        self.extras = []
        self.revision = 0
        self.accumulation = []
        self.last_receipt = None
        self.clobber_receipt = None

    # -- the composed (canonical) spec ------------------------------------
    def composed_text(self):
        parts = []
        for stream in sorted(self.assignments, key=lambda s: int(s[1:])):
            literal, width = self.assignments[stream]
            parts.append(f"{stream}[t]:{width} = {{ {literal} }}:{width}")
        parts.extend(self.extras)
        if not parts:
            return ""
        return "always ( " + " && ".join(parts) + " )."

    def shrunk_text(self):
        """What the live interpreter would report as its current spec while
        address streams are shrunk: widths collapsed, addresses interned.
        Deliberately different from the canonical text."""
        text = self.composed_text()
        text = text.replace(":bv[384]", ":bv[8]")
        return re.sub(r"#x[0-9a-fA-F]{96}", "#x2a", text)

    # -- tau_manager seam ---------------------------------------------------
    def communicate(self, rule_text=None, target_output_stream_index=0,
                    input_stream_values=None, source="unknown",
                    apply_rules_update=True, wait_for_ready=True, **_kw):
        if target_output_stream_index != 0 or rule_text is None:
            if self.clobber_receipt is not None:
                self.last_receipt = self.clobber_receipt
            return tau_defs.TAU_VALUE_ONE
        before = self.revision
        text_before = self.composed_text()
        unroutable = self._apply_unit(rule_text)
        if unroutable:
            self.last_receipt = _receipt("REJECTED_NOT_ROUTED", before, before, o0="T")
            return tau_defs.TAU_VALUE_ONE
        changed = self.composed_text() != text_before
        if changed:
            self.revision += 1
        if apply_rules_update:
            unit = chain_state._preprocess_tau_spec_text(rule_text) or rule_text
            if unit not in self.accumulation:
                self.accumulation.append(unit)
        self.last_receipt = _receipt(
            "ACCEPTED_CHANGED" if changed else "ACCEPTED_NOOP",
            before, self.revision,
        )
        return tau_defs.ACK_RULE_PROCESSED

    def communicate_multi(self, input_stream_values=None, source="unknown",
                          apply_rules_update=True, wait_for_ready=True, **_kw):
        # Verdict/policy/fee steps: everything passes, no fee is charged --
        # and the step passes through the receipt slot like any other.
        if self.clobber_receipt is not None:
            self.last_receipt = self.clobber_receipt
        return {5: "1", 6: "1", 7: "1", 8: "0", 9: "0"}

    # -- internals ----------------------------------------------------------
    def _apply_unit(self, rule_text):
        """Apply one rule unit pointwise. True when the unit is unroutable."""
        if "i12" in rule_text:
            body = getactiverules.top_level_conjuncts(
                chain_state._preprocess_tau_spec_text(rule_text) or rule_text
            )
            for piece in body:
                if piece not in self.extras:
                    self.extras.append(piece)
            return False
        seen = {}
        for stream, width, literal in _ASSIGNMENT_RE.findall(rule_text):
            if stream in seen and seen[stream] != literal:
                return True  # contradictory assignments: never routed
            seen[stream] = literal
            self.assignments[stream] = (literal, width)
        return False


def _rule_tx(tx_id, rule, seq=0):
    return sign_tx({
        "tx_id": tx_id,
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "operations": {"0": rule},
    })


def _genesis_snapshot():
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    return TauStateSnapshot(
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


def _apply_block(fake, txs, height, parent_snapshot, previous_hash,
                 patch_canonical=True):
    active_view = ActiveConsensusView(
        target_height=height,
        consensus_rules=CONSENSUS_RULES,
        active_validators=[bytes.fromhex(ALICE)],
        mechanism_specific_metadata={"poa": True},
    )
    block_obj = Block.create(
        block_number=height, previous_hash=previous_hash, transactions=txs,
        proposer_pubkey=ALICE, timestamp=GENESIS_TS + height * 10,
    )
    engine = TauConsensusEngine()
    with ExitStack() as stack:
        stack.enter_context(
            patch("tau_manager.communicate_with_tau", side_effect=fake.communicate))
        stack.enter_context(
            patch("tau_manager.communicate_with_tau_multi",
                  side_effect=fake.communicate_multi))
        stack.enter_context(
            patch("tau_manager.get_last_revision_receipt",
                  side_effect=lambda: fake.last_receipt))
        if patch_canonical:
            # The historical seam: the fake's composed text served as the
            # manager's canonical spec. One test opts out to prove the view
            # no longer reads this slot at all.
            stack.enter_context(
                patch("tau_manager.get_canonical_spec",
                      side_effect=fake.composed_text))
        stack.enter_context(
            patch("chain_state.get_application_rules_state",
                  side_effect=lambda: "\n".join(fake.accumulation)))
        stack.enter_context(
            patch("chain_state.save_application_rules_state",
                  side_effect=lambda text: None))
        ready = stack.enter_context(patch("tau_manager.tau_ready"))
        ready.is_set.return_value = True
        result = engine.apply_block(active_view, block_obj, parent_snapshot)
    return result, block_obj


def _use_database(path):
    if db._db_conn is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(str(path))
    db.init_db()


def _set_canonical_head(block_hash, number):
    db.set_chain_state_value("canonical_head_hash", block_hash)
    db.set_chain_state_value("canonical_head_number", str(number))


class _Node:
    """One simulated node: its own fake engine and its own database file."""

    def __init__(self, db_path):
        _use_database(db_path)
        self.fake = FakeTauEngine()
        self.parent_snapshot = _genesis_snapshot()
        genesis = Block.create(
            block_number=0, previous_hash="00" * 32, transactions=[],
            proposer_pubkey=ALICE, timestamp=GENESIS_TS,
        )
        db.add_block(genesis)
        _set_canonical_head(genesis.block_hash, 0)
        self.prev_hash = genesis.block_hash
        self.height = 0

    def apply_and_commit(self, txs, patch_canonical=True):
        """Apply a block and persist it the way chain_state commit does."""
        self.height += 1
        result, block_obj = _apply_block(
            self.fake, txs, self.height, self.parent_snapshot, self.prev_hash,
            patch_canonical=patch_canonical,
        )
        db.add_block(block_obj)
        _set_canonical_head(block_obj.block_hash, self.height)
        chain_state._record_rule_view_data(block_obj, result.next_snapshot)
        self.parent_snapshot = result.next_snapshot
        self.prev_hash = block_obj.block_hash
        return result, block_obj


def _status(tx_hash):
    resp = json.loads(
        gettxstatus.execute(
            f"gettxstatus {tx_hash}", types.SimpleNamespace(db=db)
        )
    )
    assert resp["status"] == "ok", resp
    return resp["data"]


def _view(*args):
    command = "getactiverules" + "".join(f" {a}" for a in args)
    resp = json.loads(
        getactiverules.execute(command, types.SimpleNamespace(db=db))
    )
    assert resp["status"] == "ok", resp
    return resp["data"]


# --- point 2: a confirmed rule transaction shows its apply outcome ---------


def test_confirmed_rule_tx_shows_apply_outcome(temp_database, tmp_path):
    node = _Node(tmp_path / "node.sqlite")
    tx = _rule_tx("install-1", RULE_INSTALL)
    result, block_obj = node.apply_and_commit([tx])
    assert result.accepted_tx_ids == ["install-1"]

    data = _status(block_obj.tx_ids[0])
    assert data["status"] == "confirmed"
    outcome = data["rule_outcome"]
    assert outcome["outcome"] == "ACCEPTED_CHANGED"
    # The revision taken: the engine's o0 verdict in the receipt's outputs.
    assert outcome["outputs"]["o0"] == "F"
    assert outcome["spec_revision_after"] > outcome["spec_revision_before"]

    # The wallet-side check needs no engine: the hash of the text the view
    # returns at that revision equals the snapshot hash.
    snapshot = db.get_spec_snapshot(outcome["spec_revision_after"])
    assert snapshot is not None
    view = _view(1)
    assert view["spec_revision"] == outcome["spec_revision_after"]
    assert view["sha256"] == snapshot["sha256"]
    assert view["sha256"] == hashlib.sha256(
        view["canonical_text"].encode("utf-8")
    ).hexdigest()


def test_receipt_capture_not_clobbered_by_later_steps(temp_database, tmp_path):
    """Later Tau steps in the same block apply -- here a transfer's steps,
    with the fee/policy seam armed to leave a marker receipt behind --
    overwrite the manager's last-receipt slot. The recorded outcome must
    still carry the rule step's own revision numbers."""
    node = _Node(tmp_path / "node.sqlite")
    node.fake.clobber_receipt = _receipt("ACCEPTED_NOOP", 777, 777, o0="T")
    rule_tx = _rule_tx("install-1", RULE_INSTALL, seq=0)
    transfer_tx = sign_tx({
        "tx_id": "plain-1",
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": 1,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, "5"]]},
    })
    result, block_obj = node.apply_and_commit([rule_tx, transfer_tx])
    assert result.accepted_tx_ids == ["install-1", "plain-1"]
    # The clobber really happened: the slot no longer describes the rule step.
    assert node.fake.last_receipt["spec_revision_after"] == 777

    outcome = _status(block_obj.tx_ids[0])["rule_outcome"]
    assert outcome["spec_revision_before"] == 0
    assert outcome["spec_revision_after"] == 1
    assert outcome["outcome"] == "ACCEPTED_CHANGED"


def test_noop_rule_tx_outcome_recorded_as_noop(temp_database, tmp_path):
    """Re-applying the same rule changes nothing: the outcome is recorded
    as ACCEPTED_NOOP with after == before, so 'took effect as a no-op' is
    distinguishable from 'not recorded'."""
    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([_rule_tx("install-1", RULE_INSTALL, seq=0)])
    _, block2 = node.apply_and_commit([_rule_tx("install-again", RULE_INSTALL, seq=1)])
    outcome = _status(block2.tx_ids[0])["rule_outcome"]
    assert outcome["outcome"] == "ACCEPTED_NOOP"
    assert outcome["spec_revision_before"] == 1
    assert outcome["spec_revision_after"] == 1


def test_unroutable_rule_tx_records_no_outcome(temp_database, tmp_path):
    node = _Node(tmp_path / "node.sqlite")
    tx = _rule_tx("unroutable-1", RULE_UNROUTABLE)
    result, block_obj = node.apply_and_commit([tx])
    assert result.invalid_tx_ids == ["unroutable-1"]
    assert result.next_snapshot.metadata["rule_outcomes"] == []
    assert db.get_rule_outcome(block_obj.tx_ids[0], block_obj.block_hash) is None


def test_confirmed_non_rule_tx_has_no_rule_outcome(temp_database, tmp_path):
    node = _Node(tmp_path / "node.sqlite")
    tx = sign_tx({
        "tx_id": "plain-1",
        "tx_type": "user_tx",
        "sender_pubkey": ALICE,
        "sequence_number": 0,
        "expiration_time": 9999999999,
        "fee_limit": "100",
        "operations": {"1": [[ALICE, BOB, "5"]]},
    })
    result, block_obj = node.apply_and_commit([tx])
    assert result.accepted_tx_ids == ["plain-1"]
    data = _status(block_obj.tx_ids[0])
    assert data["status"] == "confirmed"
    assert "rule_outcome" not in data


# --- point 1: the view is the spec the engine runs --------------------------


def test_displacement_probe_view_matches_engine(temp_database, tmp_path):
    """The maintainers' probe: install o26 = {7} && o27 = {9}, then
    o26 = {3}. The view reports the displaced form, exactly as the engine
    composed it; o26 = 7 appears nowhere as in force."""
    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([_rule_tx("install-1", RULE_INSTALL, seq=0)])
    node.apply_and_commit([_rule_tx("displace-1", RULE_DISPLACE, seq=1)])

    view = _view()
    assert view["available"] is True
    assert view["spec_revision"] == 2
    assert view["canonical_text"] == node.fake.composed_text()
    assert "o26[t]:bv[64] = { 3 }:bv[64]" in view["canonical_text"]
    assert "o27[t]:bv[64] = { 9 }:bv[64]" in view["canonical_text"]
    assert "o26[t]:bv[64] = { 7 }:bv[64]" not in view["canonical_text"]
    assert view["sha256"] == hashlib.sha256(
        view["canonical_text"].encode("utf-8")
    ).hexdigest()


def test_view_text_and_hash_equal_across_nodes_and_replay(temp_database, tmp_path):
    """Two independent nodes apply the same blocks; a third re-applies them
    from block 0 (the mock-path stand-in for replay). At every revision the
    recorded snapshot text and hash are identical on all three."""
    txs_by_height = [
        [_rule_tx("install-1", RULE_INSTALL, seq=0)],
        [_rule_tx("displace-1", RULE_DISPLACE, seq=1)],
    ]
    observed = []
    for name in ("node-a", "node-b", "node-replay"):
        node = _Node(tmp_path / f"{name}.sqlite")
        for txs in txs_by_height:
            node.apply_and_commit(txs)
        observed.append([
            (
                db.get_spec_snapshot_at_height(h)["canonical_text"],
                db.get_spec_snapshot_at_height(h)["sha256"],
            )
            for h in (1, 2)
        ])
    assert observed[0] == observed[1] == observed[2]
    for text, digest in observed[0]:
        assert digest == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_view_uses_canonical_full_width_text(temp_database, tmp_path):
    """With the live interpreter's address streams shrunk, the snapshot
    still equals the canonical full-width form: shrink state cannot leak
    into the view or make two nodes disagree."""
    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([_rule_tx("guarded-1", RULE_GUARDED_ALICE, seq=0)])

    # Sanity: the shrunk form really is different, so the test can tell
    # the two sources apart.
    assert node.fake.shrunk_text() != node.fake.composed_text()

    view = _view()
    assert view["canonical_text"] == node.fake.composed_text()
    assert view["canonical_text"] != node.fake.shrunk_text()
    assert ":bv[384]" in view["canonical_text"]
    assert ALICE in view["canonical_text"]
    assert view["sha256"] == hashlib.sha256(
        node.fake.composed_text().encode("utf-8")
    ).hexdigest()


def test_live_apply_path_ends_on_the_snapshot_spec(temp_database, tmp_path):
    """The evaluator that actually applied the blocks ends on exactly the
    text the view serves for the final revision: the snapshot is the spec
    the engine runs, read back through the view -- not a parallel
    reconstruction that merely agrees on the probe values. The revision
    counter advances once per applied rule unit."""
    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([_rule_tx("install-1", RULE_INSTALL, seq=0)])
    node.apply_and_commit([_rule_tx("displace-1", RULE_DISPLACE, seq=1)])

    view = _view()
    assert view["available"] is True
    assert view["spec_revision"] == 2
    assert view["canonical_text"] == node.fake.composed_text()
    assert view["sha256"] == hashlib.sha256(
        node.fake.composed_text().encode("utf-8")
    ).hexdigest()
    # The probe reads what the engine runs: 3 and 9, no trace of 7.
    assert "o26[t]:bv[64] = { 3 }:bv[64]" in view["canonical_text"]
    assert "o27[t]:bv[64] = { 9 }:bv[64]" in view["canonical_text"]
    assert "{ 7 }:bv[64]" not in view["canonical_text"]


def test_accumulation_rebuilds_the_engine_spec(temp_database, tmp_path):
    """The persisted accumulation alone is enough to rebuild the spec the
    engine runs: feed the recorded units, one by one, into a FRESH
    evaluator -- the same seeding the node's startup restore performs
    from the persisted full spec -- and its composed spec is exactly the
    snapshot text the view serves, at every revision. This is why the
    snapshot source IS the spec the engine runs, not submitted text and
    not the tau_manager debug global: the accumulation is the engine's
    seed."""
    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([_rule_tx("install-1", RULE_INSTALL, seq=0)])
    node.apply_and_commit([_rule_tx("displace-1", RULE_DISPLACE, seq=1)])

    rebuilt = FakeTauEngine()
    for height, unit in enumerate(node.fake.accumulation, start=1):
        rebuilt.communicate(rule_text=unit)
        snapshot = db.get_spec_snapshot_at_height(height)
        assert snapshot["canonical_text"] == rebuilt.composed_text()
        assert snapshot["sha256"] == hashlib.sha256(
            rebuilt.composed_text().encode("utf-8")
        ).hexdigest()

    view = _view()
    assert view["canonical_text"] == rebuilt.composed_text()
    assert view["canonical_text"] == node.fake.composed_text()


def test_height_before_first_snapshot_is_not_available(temp_database, tmp_path):
    # Nothing recorded at all.
    assert _view()["available"] is False
    assert _view(5)["available"] is False

    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([_rule_tx("install-1", RULE_INSTALL, seq=0)])
    # The first snapshot is at height 1; height 0 predates it.
    data = _view(0)
    assert data["available"] is False
    assert data["requested_height"] == 0


def test_account_view_attributes_guarded_conjuncts(temp_database, tmp_path):
    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([
        _rule_tx("install-1", RULE_INSTALL, seq=0),
        _rule_tx("guarded-1", RULE_GUARDED_ALICE, seq=1),
    ])

    view = _view(ALICE)
    assert view["account"] == ALICE
    assert len(view["rules"]) == 1
    assert "i12[t]" in view["rules"][0] and ALICE in view["rules"][0]
    # The unguarded install conjuncts are in force but not Alice's: they
    # are listed as unattributed, not dropped.
    assert any("o26" in c for c in view["unattributed"])
    assert any("o27" in c for c in view["unattributed"])

    other = _view(BOB)
    assert other["rules"] == []
    assert any("i12[t]" in c for c in other["unattributed"])


def test_gettaustate_still_returns_the_accumulation(temp_database, tmp_path):
    """Compatibility: gettaustate keeps serving the submitted text --
    including the displaced unit the view no longer shows."""
    node = _Node(tmp_path / "node.sqlite")
    node.apply_and_commit([_rule_tx("install-1", RULE_INSTALL, seq=0)])
    node.apply_and_commit([_rule_tx("displace-1", RULE_DISPLACE, seq=1)])

    previous = chain_state.get_application_rules_state()
    try:
        chain_state.save_application_rules_state("\n".join(node.fake.accumulation))
        resp = json.loads(gettaustate.execute(
            "gettaustate", types.SimpleNamespace(chain_state=chain_state)
        ))
    finally:
        chain_state.save_application_rules_state(previous)
    assert resp["status"] == "ok", resp
    submitted = resp["data"]["rules_state"]
    assert "o26" in submitted and "{ 7 }" in submitted  # displaced, still there
    assert "o26[t]:bv[64] = { 7 }:bv[64]" not in _view()["canonical_text"]


def test_getactiverules_is_registered(temp_database):
    from app.container import ServiceContainer

    container = ServiceContainer.build()
    assert "getactiverules" in container.command_handlers


# --- both points -------------------------------------------------------------


def test_displacing_tx_receipt_and_view_agree(temp_database, tmp_path):
    node = _Node(tmp_path / "node.sqlite")
    _, block1 = node.apply_and_commit([_rule_tx("install-1", RULE_INSTALL, seq=0)])
    _, block2 = node.apply_and_commit([_rule_tx("displace-1", RULE_DISPLACE, seq=1)])

    first = db.get_rule_outcome(block1.tx_ids[0], block1.block_hash)
    second = db.get_rule_outcome(block2.tx_ids[0], block2.block_hash)
    # The displacing transaction's receipt chains onto the first one's.
    assert second["spec_revision_before"] == first["spec_revision_after"]
    assert second["spec_revision_after"] > second["spec_revision_before"]
    # The view shows the surviving form...
    assert "o26[t]:bv[64] = { 3 }:bv[64]" in _view()["canonical_text"]
    # ...and the first transaction's recorded receipt was not rewritten.
    reread = db.get_rule_outcome(block1.tx_ids[0], block1.block_hash)
    assert reread == first


def test_same_block_install_and_replace(temp_database, tmp_path):
    """Two rule transactions in one block, the second displacing the first:
    both receipts persist in apply order with consecutive revisions, the
    end-of-block view shows only the survivor, and the per-revision
    snapshots keep the intra-block states addressable."""
    node = _Node(tmp_path / "node.sqlite")
    result, block_obj = node.apply_and_commit([
        _rule_tx("install-1", RULE_INSTALL, seq=0),
        _rule_tx("displace-1", RULE_DISPLACE, seq=1),
    ])
    assert result.accepted_tx_ids == ["install-1", "displace-1"]

    first_hash, second_hash = block_obj.tx_ids
    first = db.get_rule_outcome(first_hash, block_obj.block_hash)
    second = db.get_rule_outcome(second_hash, block_obj.block_hash)
    assert (first["spec_revision_before"], first["spec_revision_after"]) == (0, 1)
    assert (second["spec_revision_before"], second["spec_revision_after"]) == (1, 2)

    # Both intra-block revisions kept their own snapshot, at this height.
    intra = db.get_spec_snapshot(1)
    assert intra["height"] == 1
    assert "o26[t]:bv[64] = { 7 }:bv[64]" in intra["canonical_text"]
    final = db.get_spec_snapshot(2)
    assert final["height"] == 1
    assert "o26[t]:bv[64] = { 3 }:bv[64]" in final["canonical_text"]

    view = _view(1)
    assert view["spec_revision"] == 2
    assert "o26[t]:bv[64] = { 7 }:bv[64]" not in view["canonical_text"]
    assert "o27[t]:bv[64] = { 9 }:bv[64]" in view["canonical_text"]


# --- point 1, hardened: the view's text source ------------------------------


def test_view_ignores_manager_global_spec(temp_database, tmp_path):
    """The snapshot text is composed from the persisted canonical
    accumulation, NOT read from tau_manager's process global. Poison the
    global -- the slot tau_manager itself documents as a debug aid that
    is "NEVER hashed or persisted", holding the interpreter's composed
    (possibly shrunk) spec -- and leave the real get_canonical_spec in
    place to read it: the displacement probe's view is unaffected, still
    reporting o26 = {3} and o27 = {9}."""
    import tau_manager

    node = _Node(tmp_path / "node.sqlite")
    poisoned = "always ( o26[t]:bv[8] = { 99 }:bv[8] )."
    with patch.object(tau_manager, "last_known_tau_spec", poisoned):
        node.apply_and_commit(
            [_rule_tx("install-1", RULE_INSTALL, seq=0)], patch_canonical=False
        )
        node.apply_and_commit(
            [_rule_tx("displace-1", RULE_DISPLACE, seq=1)], patch_canonical=False
        )
    # Sanity: the poisoned slot really is what get_canonical_spec serves.
    with patch.object(tau_manager, "last_known_tau_spec", poisoned):
        assert tau_manager.get_canonical_spec() == poisoned

    view = _view()
    assert view["available"] is True
    assert view["spec_revision"] == 2
    assert view["canonical_text"] == node.fake.composed_text()
    assert "o26[t]:bv[64] = { 3 }:bv[64]" in view["canonical_text"]
    assert "o27[t]:bv[64] = { 9 }:bv[64]" in view["canonical_text"]
    assert "o26[t]:bv[64] = { 7 }:bv[64]" not in view["canonical_text"]
    assert "99" not in view["canonical_text"]
    assert view["sha256"] == hashlib.sha256(
        view["canonical_text"].encode("utf-8")
    ).hexdigest()


# --- point 2, registry-routed rules ------------------------------------------

# User o5 rules land in the per-account clause registry, not the shared
# spec. The second replaces the first; the third is the neutral body,
# which revokes.
RULE_O5_REGISTER = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
RULE_O5_REPLACE = (
    "always ( (i1[t]:bv[24] > { #x0003e8 }:bv[24]) "
    "? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
)
RULE_O5_REVOKE = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."


def test_registry_routed_rule_tx_records_registry_outcome(
    temp_database, tmp_path
):
    """A registry-routed rule transaction takes no spec revision, so no
    engine receipt and no snapshot exist for it. Its confirmed outcome is
    registry evidence instead: the clause-registry root before/after,
    explicitly marked -- and it never claims a spec revision."""
    from consensus import sender_policy
    from consensus.policy_mock import MockPolicyEvaluator

    sender_policy.set_evaluator("apply", MockPolicyEvaluator(pool="apply"))
    try:
        node = _Node(tmp_path / "node.sqlite")

        result, block1 = node.apply_and_commit(
            [_rule_tx("clause-1", RULE_O5_REGISTER, seq=0)]
        )
        assert result.accepted_tx_ids == ["clause-1"]
        registered = _status(block1.tx_ids[0])["rule_outcome"]
        assert registered["outcome"] == "CLAUSE_REGISTERED"
        assert registered["evidence"] == "clause_registry"
        assert registered["account"] == ALICE.lower()
        assert registered["stream"] == 5
        assert (
            registered["registry_root_before"]
            != registered["registry_root_after"]
        )
        # The invariant: registry evidence never claims a spec revision.
        assert "spec_revision" not in registered
        assert "spec_revision_before" not in registered
        assert "spec_revision_after" not in registered
        # The routing step's own log line rides along, like any outcome.
        assert any("o5 clause" in line for line in registered["logs"])
        # No revision was taken, so no snapshot exists either.
        assert db.get_latest_spec_snapshot() is None
        assert _view()["available"] is False

        result, block2 = node.apply_and_commit(
            [_rule_tx("clause-2", RULE_O5_REPLACE, seq=1)]
        )
        assert result.accepted_tx_ids == ["clause-2"]
        replaced = _status(block2.tx_ids[0])["rule_outcome"]
        assert replaced["outcome"] == "CLAUSE_REPLACED"
        assert replaced["evidence"] == "clause_registry"
        assert (
            replaced["registry_root_before"]
            == registered["registry_root_after"]
        )
        assert (
            replaced["registry_root_after"] != replaced["registry_root_before"]
        )

        result, block3 = node.apply_and_commit(
            [_rule_tx("clause-3", RULE_O5_REVOKE, seq=2)]
        )
        assert result.accepted_tx_ids == ["clause-3"]
        revoked = _status(block3.tx_ids[0])["rule_outcome"]
        assert revoked["outcome"] == "CLAUSE_REVOKED"
        assert (
            revoked["registry_root_before"] == replaced["registry_root_after"]
        )
        # Revoking the only clause returns the registry to its empty root.
        assert (
            revoked["registry_root_after"] == registered["registry_root_before"]
        )
    finally:
        sender_policy.set_evaluator("apply", None)


# --- point 2, receipt logs in the stored outcome -----------------------------


def test_confirmed_rule_outcome_carries_receipt_logs(temp_database, tmp_path):
    """Ask 1 names the receipt logs: the stored outcome carries the
    transaction receipt's log lines -- the rule step's own trail among
    them -- bounded to 16 lines of 400 chars."""
    node = _Node(tmp_path / "node.sqlite")
    _, block_obj = node.apply_and_commit(
        [_rule_tx("install-1", RULE_INSTALL, seq=0)]
    )
    outcome = _status(block_obj.tx_ids[0])["rule_outcome"]
    logs = outcome["logs"]
    assert any(line.startswith("Tau(rule) o0:") for line in logs)
    assert any("Rule applied" in line for line in logs)
    assert len(logs) <= 16
    assert all(len(line) <= 400 for line in logs)


def test_bounded_receipt_logs_caps_lines_and_width():
    from consensus.engine import _bounded_receipt_logs

    lines = [f"line-{i} " + "x" * 500 for i in range(20)]
    bounded = _bounded_receipt_logs(lines)
    assert len(bounded) == 16
    assert all(len(line) == 400 for line in bounded)
    assert bounded[0].startswith("line-0 ")
    assert bounded[-1].startswith("line-15 ")
    assert _bounded_receipt_logs(None) == []
    assert _bounded_receipt_logs(["short"]) == ["short"]
