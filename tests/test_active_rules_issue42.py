"""Issue #42: confirmed rule outcomes + the getactiverules view.

Two maintainer check-points (Sep 27 reply on #42):

1. The view of active rules comes from the spec the engine runs, not the
   append-only text. Probe: apply `o26 = {7} && o27 = {9}`, then `o26 = {3}`;
   the view reports o26 = 3 and o27 = 9, and a second node and a replay from
   block 0 give the same text and hash.
2. A confirmed rule transaction shows its apply outcome (revision taken,
   spec_revision), so a wallet can confirm a rule took effect without
   re-running the engine.

The native tau-lang bindings are not available in every environment; the
engine-level tests therefore drive apply() through a scripted session that
models pointwise revision exactly as the probe defines it, and through the
live InProcessSession with tau_manager patched (the pattern of
test_apply_rejection_atomicity.py). The maintainers' probe on the real
engine lives in test_active_rules_issue42_native.py, so the real-Tau CI
job can register exactly that file; it skips when the bindings are
absent.
"""
import hashlib
import json
import re
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

import chain_state
import db
import tau_manager
from bls_keys import pubkey_hex, sign_payload
from commands import getactiverules, gettxstatus
from consensus import active_rules
from consensus.engine import TauConsensusEngine
from consensus.state import TauStateSnapshot

SK_SENDER = 33333
SENDER = pubkey_hex(SK_SENDER)
PROPOSER = "bb" * 48

PROBE_TX1 = "always ( o26[t]:bv[24] = { #x000007 }:bv[24] && o27[t]:bv[24] = { #x000009 }:bv[24] )."
PROBE_TX2 = "always ( o26[t]:bv[24] = { #x000003 }:bv[24] )."

_ASSIGN_RE = re.compile(r"o(\d+)\[t\]:bv\[24\] = \{ #x([0-9a-fA-F]+) \}:bv\[24\]")


def _exec(module, raw, container):
    return json.loads(module.execute(raw, container))


def _rule_tx(tx_id, rule, seq):
    return sign_payload({
        "tx_id": tx_id,
        "tx_type": "user_tx",
        "sender_pubkey": SENDER,
        "sequence_number": seq,
        "expiration_time": 9999999999,
        "fee_limit": "1000",
        "operations": {"0": rule},
    }, SK_SENDER)


def _engine():
    engine = TauConsensusEngine(state_store=MagicMock())
    engine._state_store.commit.side_effect = lambda snap: snap
    return engine


# --- A scripted evaluator session modelling pointwise revision ------------
#
# apply_rule parses `oN[t] = { V }` assignments out of the rule text and
# displaces earlier assignments to the same stream -- the semantics of the
# Sep 27 probe -- advancing spec_revision once per accepted rule and
# building the same revision receipt shape tau_native._build_revision_receipt
# produces. Every later Tau step (fee evaluation, the next transaction's
# rule) overwrites the session's last receipt, exactly as the manager's
# last-receipt global behaves in production.

class _PointwiseSession:
    is_speculative = True

    def __init__(self):
        self.assignments = {}
        self.spec_revision = 0
        self._receipt = None

    def ready(self, timeout=5.0):
        return True

    def apply_rule(self, rule_text, *, target=0, accumulate=True):
        before = self.spec_revision
        changed = False
        for stream, value in _ASSIGN_RE.findall(rule_text or ""):
            value = int(value, 16)
            if self.assignments.get(stream) != value:
                self.assignments[stream] = value
                changed = True
        self.spec_revision += 1
        self._receipt = {
            "outcome": "ACCEPTED_CHANGED" if changed else "ACCEPTED_NOOP",
            "accepted": True,
            "changed": changed,
            "delivered": True,
            "outputs": {"o0": "F"},
            "spec_revision_before": before,
            "spec_revision_after": self.spec_revision,
        }
        return "F"

    def evaluate(self, inputs, *, target=None, source="unknown", multi=False,
                 apply_rules_update=False, record=True):
        # A non-rule step: in production this is where a stale read of the
        # last-receipt global would go wrong, so the fake clobbers its own
        # receipt with a marker the tests can recognise.
        self._receipt = {
            "outcome": "CLOBBERED_BY_LATER_STEP",
            "accepted": True,
            "changed": False,
            "delivered": True,
            "outputs": {"o0": "F"},
            "spec_revision_before": 900,
            "spec_revision_after": 900,
        }
        if multi:
            return {9: "7"}
        return "1"

    def last_receipt(self):
        return self._receipt

    def canonical_spec(self):
        parts = [
            f"o{s}[t]:bv[24] = {{ #x{v:06x} }}:bv[24]"
            for s, v in sorted(self.assignments.items(), key=lambda kv: int(kv[0]))
        ]
        return "always ( " + " && ".join(parts) + " )."


def _apply_block(session, txs, *, height, sequences, snapshot=None):
    """Apply one block of rule txs through the engine with `session`."""
    state = {"text": ""}
    with patch.object(chain_state, "get_application_rules_state",
                      lambda: state["text"]), \
         patch.object(chain_state, "save_application_rules_state",
                      lambda text: state.__setitem__("text", text), create=True):
        result = _engine().apply(
            snapshot or TauStateSnapshot(b"hash", b"rules", {}),
            txs, 1700000000,
            target_balances={SENDER: 100000},
            target_sequences=sequences,
            proposer_pubkey=PROPOSER,
            block_height=height,
            session=session,
        )
    return result


def _record_snapshot(session, height):
    text = session.canonical_spec()
    db.record_spec_snapshot(
        session.spec_revision, height, text, active_rules.spec_hash_of(text)
    )


# --- Storage: rule outcomes ------------------------------------------------

def test_rule_outcome_storage_round_trip(temp_database):
    db.record_rule_outcomes("ab" * 32, 29, {
        "cd" * 32: {"outcome": "ACCEPTED_CHANGED",
                    "spec_revision_before": 4, "spec_revision_after": 5},
    })
    got = db.get_rule_outcome("cd" * 32, "ab" * 32)
    assert got == {"outcome": "ACCEPTED_CHANGED",
                   "spec_revision_before": 4, "spec_revision_after": 5}
    assert db.get_rule_outcome("cd" * 32, "ef" * 32) is None
    assert db.get_rule_outcome("00" * 32) is None


# --- gettxstatus: the confirmed branch shows the apply outcome -------------

def test_confirmed_rule_tx_shows_apply_outcome(temp_database):
    """Point 2: after the outcome is persisted (as createblock does at
    commit), gettxstatus for the confirmed tx carries rule_outcome with
    spec_revision_after > spec_revision_before; and the wallet-side check
    needs no engine -- the hash of the text getactiverules returns at that
    revision equals the snapshot hash."""
    tx_hash = "cd" * 32
    block_hash = "ab" * 32
    db.record_rule_outcomes(block_hash, 29, {
        tx_hash: {"outcome": "ACCEPTED_CHANGED",
                  "spec_revision_before": 4, "spec_revision_after": 5},
    })
    db.record_spec_snapshot(5, 29, PROBE_TX2, active_rules.spec_hash_of(PROBE_TX2))

    class _Db:
        def get_mempool_entry(self, h):
            return None

        def get_tx_block_locations(self, h):
            return [{"block_hash": block_hash, "block_number": 29}]

        def get_canonical_confirmation(self, bh, bn):
            return True, 29

        def get_rule_outcome(self, h, b=None):
            return db.get_rule_outcome(h, b)

        def get_block_by_hash(self, bh):
            return {}

    container = SimpleNamespace(db=_Db(), chain_state=chain_state)
    resp = _exec(gettxstatus, f"gettxstatus {tx_hash}", container)
    assert resp["status"] == "ok", resp
    data = resp["data"]
    assert data["status"] == "confirmed"
    assert data["rule_outcome"] == {
        "outcome": "ACCEPTED_CHANGED",
        "spec_revision_before": 4,
        "spec_revision_after": 5,
    }
    assert data["rule_outcome"]["spec_revision_after"] > data["rule_outcome"]["spec_revision_before"]

    view = _exec(getactiverules, "getactiverules", container)
    assert view["status"] == "ok", view
    vdata = view["data"]
    assert vdata["spec_revision"] == 5
    assert hashlib.sha256(vdata["effective_spec"].encode()).hexdigest() == vdata["spec_hash"]


def test_gettxstatus_confirmed_without_outcome_has_no_rule_outcome(temp_database):
    tx_hash = "cd" * 32
    block_hash = "ab" * 32

    class _Db:
        def get_mempool_entry(self, h):
            return None

        def get_tx_block_locations(self, h):
            return [{"block_hash": block_hash, "block_number": 29}]

        def get_canonical_confirmation(self, bh, bn):
            return True, 29

        def get_rule_outcome(self, h, b=None):
            return db.get_rule_outcome(h, b)

        def get_block_by_hash(self, bh):
            return {}

    container = SimpleNamespace(db=_Db(), chain_state=chain_state)
    resp = _exec(gettxstatus, f"gettxstatus {tx_hash}", container)
    assert resp["data"]["status"] == "confirmed"
    assert "rule_outcome" not in resp["data"]


# --- getactiverules: availability + height resolution ----------------------

def test_getactiverules_unavailable_without_snapshots(temp_database):
    container = SimpleNamespace(db=db, chain_state=chain_state)
    resp = _exec(getactiverules, "getactiverules", container)
    assert resp["status"] == "ok", resp
    assert resp["data"]["available"] is False
    # Never substitutes the append-only accumulation for the running spec.
    assert "effective_spec" not in resp["data"]


def test_getactiverules_height_resolution(temp_database):
    db.record_spec_snapshot(1, 10, "spec-one", active_rules.spec_hash_of("spec-one"))
    db.record_spec_snapshot(2, 20, "spec-two", active_rules.spec_hash_of("spec-two"))
    container = SimpleNamespace(db=db, chain_state=chain_state)

    latest = _exec(getactiverules, "getactiverules", container)["data"]
    assert latest["spec_revision"] == 2 and latest["height"] == 20

    at15 = _exec(getactiverules, "getactiverules 15", container)["data"]
    assert at15["spec_revision"] == 1 and at15["height"] == 10
    assert at15["requested_height"] == 15

    # Before the first snapshot: the earliest is returned with both heights
    # visible, so the substitution is explicit rather than silent.
    at5 = _exec(getactiverules, "getactiverules 5", container)["data"]
    assert at5["spec_revision"] == 1 and at5["height"] == 10
    assert at5["requested_height"] == 5


# --- Point 1: the displacement probe through block apply -------------------

def test_displacement_probe_view_matches_engine(temp_database):
    """The maintainers' probe as rule transactions through block apply:
    o26 = {7} && o27 = {9}, then o26 = {3}. The recorded view must report
    o26 = 3 and o27 = 9, with o26 = 7 nowhere as in force -- while the
    append-only accumulation (what gettaustate returns) still shows both
    submitted units, o26 = 7 included."""
    session = _PointwiseSession()
    r1 = _apply_block(session, [_rule_tx("p1", PROBE_TX1, 0)], height=1,
                      sequences={})
    assert "p1" in [t.get("tx_id") for t in r1.accepted_transactions]
    _record_snapshot(session, 1)
    r2 = _apply_block(session, [_rule_tx("p2", PROBE_TX2, 1)], height=2,
                      sequences={SENDER: 1}, snapshot=r1.snapshot)
    assert "p2" in [t.get("tx_id") for t in r2.accepted_transactions]
    _record_snapshot(session, 2)

    container = SimpleNamespace(db=db, chain_state=chain_state)
    view = _exec(getactiverules, "getactiverules", container)["data"]
    assert view["effective_spec"] == session.canonical_spec()
    assert "o26[t]:bv[24] = { #x000003 }" in view["effective_spec"]
    assert "o27[t]:bv[24] = { #x000009 }" in view["effective_spec"]
    assert "#x000007" not in view["effective_spec"]
    assert view["spec_hash"] == active_rules.spec_hash_of(view["effective_spec"])


def _run_probe_sequence(db_path):
    """One node's full run of the probe: fresh DB, fresh session, two
    blocks, snapshots after each commit. Returns the snapshot rows."""
    import config

    if getattr(db, "_db_conn", None) is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(str(db_path))
    db.init_db()

    session = _PointwiseSession()
    r1 = _apply_block(session, [_rule_tx("p1", PROBE_TX1, 0)], height=1,
                      sequences={})
    _record_snapshot(session, 1)
    _apply_block(session, [_rule_tx("p2", PROBE_TX2, 1)], height=2,
                 sequences={SENDER: 1}, snapshot=r1.snapshot)
    _record_snapshot(session, 2)
    rows = []
    for rev in (1, 2):
        snap = db.get_spec_snapshot_by_revision(rev)
        rows.append((snap["spec_revision"], snap["height"],
                     snap["spec_text"], snap["spec_hash"]))
    return rows


def test_view_text_and_hash_equal_across_nodes_and_replay(tmp_path):
    """Two independent nodes applying the same blocks, and a third run
    replaying from block 0, produce identical snapshot text and hash at
    every revision."""
    node_a = _run_probe_sequence(tmp_path / "node_a.db")
    node_b = _run_probe_sequence(tmp_path / "node_b.db")
    replay = _run_probe_sequence(tmp_path / "replay.db")
    assert node_a == node_b == replay
    assert node_a[-1][2].find("#x000003") >= 0  # sanity: probe really ran


def test_displacing_tx_receipt_and_view_agree(temp_database):
    """A second transaction displaces part of an earlier unit: its receipt
    shows the revision taken, the view shows the surviving form, and the
    first transaction's recorded receipt is not rewritten."""
    session = _PointwiseSession()
    _apply_block(session, [_rule_tx("p1", PROBE_TX1, 0)], height=1,
                 sequences={})
    _record_snapshot(session, 1)
    r2 = _apply_block(session, [_rule_tx("p2", PROBE_TX2, 1)], height=2,
                      sequences={SENDER: 1})
    _record_snapshot(session, 2)

    receipt2 = r2.receipts["p2"]["rule_outcome"]
    assert receipt2["outcome"] == "ACCEPTED_CHANGED"
    assert receipt2["spec_revision_before"] == 1
    assert receipt2["spec_revision_after"] == 2

    # Persist both blocks' outcomes the way createblock does at commit.
    db.record_rule_outcomes("aa" * 32, 1, {"p1hash": {
        "outcome": "ACCEPTED_CHANGED",
        "spec_revision_before": 0, "spec_revision_after": 1}})
    db.record_rule_outcomes("bb" * 32, 2, {"p2hash": receipt2})

    container = SimpleNamespace(db=db, chain_state=chain_state)
    view = _exec(getactiverules, "getactiverules", container)["data"]
    assert "#x000003" in view["effective_spec"]
    assert "#x000007" not in view["effective_spec"]
    # History is not rewritten: tx1's receipt still records its own effect.
    first = db.get_rule_outcome("p1hash", "aa" * 32)
    assert first["spec_revision_after"] == 1


def test_same_block_install_and_replace(temp_database):
    """Two rule transactions in ONE block, the second displacing the first:
    both receipts are recorded in apply order with consecutive
    spec_revisions, and the end-of-block view shows only the survivor."""
    session = _PointwiseSession()
    result = _apply_block(
        session,
        [_rule_tx("s1", PROBE_TX1, 0), _rule_tx("s2", PROBE_TX2, 1)],
        height=1, sequences={},
    )
    accepted = [t.get("tx_id") for t in result.accepted_transactions]
    assert accepted == ["s1", "s2"], accepted
    o1 = result.receipts["s1"]["rule_outcome"]
    o2 = result.receipts["s2"]["rule_outcome"]
    assert (o1["spec_revision_before"], o1["spec_revision_after"]) == (0, 1)
    assert (o2["spec_revision_before"], o2["spec_revision_after"]) == (1, 2)

    _record_snapshot(session, 1)
    container = SimpleNamespace(db=db, chain_state=chain_state)
    view = _exec(getactiverules, "getactiverules", container)["data"]
    assert "#x000003" in view["effective_spec"]
    assert "#x000007" not in view["effective_spec"]
    # The intra-block state stays addressable by revision.
    snap1 = db.get_spec_snapshot_by_revision(2)
    assert snap1["height"] == 1


def test_receipt_capture_not_clobbered_by_later_steps(temp_database):
    """The session's last receipt is overwritten by every later Tau step
    (the fake's evaluate() installs a CLOBBERED marker, and a second rule
    transaction follows in the same block). The first transaction's
    recorded outcome must still carry the first rule step's own revision
    numbers -- the reason the capture happens at the apply site."""
    session = _PointwiseSession()
    result = _apply_block(
        session,
        [_rule_tx("c1", PROBE_TX1, 0), _rule_tx("c2", PROBE_TX2, 1)],
        height=1, sequences={},
    )
    o1 = result.receipts["c1"]["rule_outcome"]
    assert o1["outcome"] == "ACCEPTED_CHANGED"
    assert o1["spec_revision_before"] == 0
    assert o1["spec_revision_after"] == 1
    # And the session's last receipt is indeed no longer tx1's.
    assert session.last_receipt()["spec_revision_after"] != 1


# --- Capture on the live (non-speculative) path ----------------------------

def test_live_path_capture_via_manager_receipt():
    """The InProcessSession path: tau_manager's last-receipt global is set
    by the rule step, and the engine copies it into the receipt of the
    transaction whose rule landed (the _application_rule_landed branch)."""
    state = {"text": ""}
    revision = {"n": 0}

    def _communicate(rule_text=None, **kwargs):
        if rule_text is not None and kwargs.get("apply_rules_update", True):
            unit = (chain_state._preprocess_tau_spec_text(rule_text)
                    or rule_text).strip()
            units = [u for u in state["text"].split("\n") if u.strip()]
            if unit not in units:
                units.append(unit)
            state["text"] = "\n".join(units)
            before = revision["n"]
            revision["n"] += 1
            tau_manager._last_revision_receipt = {
                "outcome": "ACCEPTED_CHANGED",
                "accepted": True,
                "changed": True,
                "delivered": True,
                "outputs": {"o0": "F"},
                "spec_revision_before": before,
                "spec_revision_after": revision["n"],
            }
        return "F"

    tx = _rule_tx("live1", PROBE_TX1, 0)
    with patch("tau_manager.tau_ready") as ready, \
         patch("tau_manager.communicate_with_tau", side_effect=_communicate), \
         patch("tau_manager.communicate_with_tau_multi", return_value={9: "7"}), \
         patch.object(chain_state, "get_application_rules_state",
                      lambda: state["text"]), \
         patch.object(chain_state, "save_application_rules_state",
                      lambda text: state.__setitem__("text", text), create=True):
        ready.is_set.return_value = True
        result = _engine().apply(
            TauStateSnapshot(b"hash", b"rules", {}),
            [tx], 1700000000,
            target_balances={SENDER: 100000},
            target_sequences={},
            proposer_pubkey=PROPOSER,
            block_height=1,
        )
    assert "live1" in [t.get("tx_id") for t in result.accepted_transactions]
    outcome = result.receipts["live1"]["rule_outcome"]
    assert outcome == {"outcome": "ACCEPTED_CHANGED",
                       "spec_revision_before": 0, "spec_revision_after": 1}


# --- Snapshots use the canonical full-width text ---------------------------

def test_view_uses_canonical_full_width_text(temp_database, monkeypatch):
    """The interpreter's runtime spec may present an address stream shrunk
    below bv[384]; the snapshot must still be the canonical full-width
    text (tau_manager.get_canonical_spec), so two nodes with different
    shrink state cannot disagree on the view or its hash."""
    full_width = (
        "always ( ( i12[t] = { #x" + "ab" * 48 + " }:bv[384] ) ? "
        "o5[t]:bv[24] = { #x000001 }:bv[24] : o5[t]:bv[24] = { #x000000 }:bv[24] )."
    )
    shrunk = full_width.replace("bv[384]", "bv[8]")

    class _ShrunkIface:
        def get_current_spec(self):
            return shrunk

    monkeypatch.setattr(tau_manager, "tau_direct_interface", _ShrunkIface())
    monkeypatch.setattr(tau_manager, "get_canonical_spec", lambda: full_width)
    monkeypatch.setattr(active_rules, "current_spec_revision", lambda: 7)

    stored = active_rules.record_snapshot_after_commit(30)
    assert stored is not None
    assert stored["spec_text"] == full_width
    assert ":bv[384]" in stored["spec_text"]
    assert stored["spec_hash"] == active_rules.spec_hash_of(full_width)
    assert stored["spec_hash"] != active_rules.spec_hash_of(shrunk)

    # A second call at the same revision stores nothing (no advance).
    assert active_rules.record_snapshot_after_commit(31) is None


# --- Account attribution ----------------------------------------------------

def test_account_attribution_from_effective_text(temp_database):
    alice = "aa" * 48
    bob = "bb" * 48
    spec = (
        f"always ( ( i12[t] = {{ #x{alice} }}:bv[384] ) ? "
        "o5[t]:bv[24] = { #x000001 }:bv[24] : o5[t]:bv[24] = { #x000000 }:bv[24] ).\n"
        f"always ( ( i12[t] = {{ #x{bob} }}:bv[384] ) ? "
        "o5[t]:bv[24] = { #x000000 }:bv[24] : o5[t]:bv[24] = { #x000001 }:bv[24] ).\n"
        "always ( o13[t]:bv[24] = { #x000001 }:bv[24] )."
    )
    db.record_spec_snapshot(3, 12, spec, active_rules.spec_hash_of(spec))
    container = SimpleNamespace(db=db, chain_state=chain_state)

    data = _exec(getactiverules, f"getactiverules {alice}", container)["data"]
    assert len(data["account_rules"]) == 1
    assert alice in data["account_rules"][0]
    # Bob's statement is attributable -- to Bob -- so it is not listed as
    # unattributed for Alice; the unguarded statement is.
    assert len(data["unattributed"]) == 1
    assert "o13" in data["unattributed"][0]
    assert all(bob not in s for s in data["unattributed"])


def test_split_statements_respects_bracket_depth():
    spec = "always ( o26[t] = { #x000007 } ). always ( o27[t] = { #x000009 } )."
    stmts = active_rules.split_statements(spec)
    assert len(stmts) == 2
    assert active_rules.guard_accounts("always ( i12[t] = { #x" + "cd" * 48 + " } ).") == {"cd" * 48}


# --- Survival ledger ---------------------------------------------------------
#
# Per-unit survival derived from the stored snapshots + outcome receipts:
# what a confirmed unit installed, whether it is still in force, partly
# displaced or displaced at the viewed revision, and which later
# transaction displaced the parts that are gone.

SPEC_V1 = ("always ( o26[t]:bv[24] = { #x000007 }:bv[24] && "
           "o27[t]:bv[24] = { #x000009 }:bv[24] ).")
SPEC_V2 = ("always ( o26[t]:bv[24] = { #x000003 }:bv[24] && "
           "o27[t]:bv[24] = { #x000009 }:bv[24] ).")
SPEC_SINGLE_V1 = "always ( o26[t]:bv[24] = { #x000007 }:bv[24] )."
SPEC_SINGLE_V2 = "always ( o26[t]:bv[24] = { #x000003 }:bv[24] )."

FRAG_O26_7 = "o26[t]:bv[24] = { #x000007 }:bv[24]"
FRAG_O26_3 = "o26[t]:bv[24] = { #x000003 }:bv[24]"
FRAG_O27_9 = "o27[t]:bv[24] = { #x000009 }:bv[24]"

UNIT_A = "aa" * 32
UNIT_B = "bb" * 32


def _record_unit(tx_hash, block, before, after, outcome="ACCEPTED_CHANGED"):
    db.record_rule_outcomes(f"{block:064x}", block, {tx_hash: {
        "outcome": outcome,
        "spec_revision_before": before,
        "spec_revision_after": after,
    }})


def _snap(revision, height, text):
    db.record_spec_snapshot(revision, height, text,
                            active_rules.spec_hash_of(text))


def test_spec_fragments_split_top_level_conjuncts():
    assert active_rules.spec_fragments(SPEC_V1) == [FRAG_O26_7, FRAG_O27_9]
    assert active_rules.spec_fragments(SPEC_SINGLE_V1) == [FRAG_O26_7]
    # A guarded conditional is one fragment: its parts are not top-level
    # conjuncts, and a conjunction nested inside it stays nested.
    guarded = (
        "always ( ( i12[t] = { #x" + "ab" * 48 + " }:bv[384] ) ? "
        "o5[t]:bv[24] = { #x000001 }:bv[24] : o5[t]:bv[24] = { #x000000 }:bv[24] )."
    )
    frags = active_rules.spec_fragments(guarded)
    assert len(frags) == 1
    assert "i12[t]" in frags[0]


def test_survival_ledger_unit_in_force(temp_database):
    _snap(1, 10, SPEC_V1)
    _record_unit(UNIT_A, 10, 0, 1)
    ledger = active_rules.survival_ledger()
    assert len(ledger) == 1
    entry = ledger[0]
    assert entry["tx_hash"] == UNIT_A
    assert entry["block_number"] == 10
    assert entry["spec_revision_before"] == 0
    assert entry["spec_revision_after"] == 1
    assert entry["status"] == "in_force"
    assert entry["installed_fragments"] == [FRAG_O26_7, FRAG_O27_9]
    assert entry["surviving_fragments"] == [FRAG_O26_7, FRAG_O27_9]
    assert entry["displaced_fragments"] == []
    assert entry["displaced_by"] == []


def test_survival_ledger_unit_fully_displaced(temp_database):
    _snap(1, 10, SPEC_SINGLE_V1)
    _snap(2, 11, SPEC_SINGLE_V2)
    _record_unit(UNIT_A, 10, 0, 1)
    _record_unit(UNIT_B, 11, 1, 2)
    ledger = {e["tx_hash"]: e for e in active_rules.survival_ledger()}
    a = ledger[UNIT_A]
    assert a["status"] == "displaced"
    assert a["surviving_fragments"] == []
    assert a["displaced_fragments"] == [
        {"fragment": FRAG_O26_7, "displaced_by": [UNIT_B]}]
    assert a["displaced_by"] == [UNIT_B]
    b = ledger[UNIT_B]
    assert b["status"] == "in_force"
    assert b["installed_fragments"] == [FRAG_O26_3]


def test_survival_ledger_unit_partially_displaced(temp_database):
    """The maintainers' displacement scenario at the data layer: unit A
    installs o26 = {7} && o27 = {9}; unit B then installs o26 = {3}. The
    o27 fragment of A survives, the o26 fragment is displaced by B."""
    _snap(1, 10, SPEC_V1)
    _snap(2, 11, SPEC_V2)
    _record_unit(UNIT_A, 10, 0, 1)
    _record_unit(UNIT_B, 11, 1, 2)
    ledger = {e["tx_hash"]: e for e in active_rules.survival_ledger()}
    a = ledger[UNIT_A]
    assert a["status"] == "partially_displaced"
    assert a["surviving_fragments"] == [FRAG_O27_9]
    assert a["displaced_fragments"] == [
        {"fragment": FRAG_O26_7, "displaced_by": [UNIT_B]}]
    assert a["displaced_by"] == [UNIT_B]
    assert ledger[UNIT_B]["status"] == "in_force"

    # At the earlier snapshot the same unit was fully in force, and the
    # later unit is not part of that revision's ledger at all.
    at_rev1 = active_rules.survival_ledger(db.get_spec_snapshot_by_revision(1))
    assert [e["tx_hash"] for e in at_rev1] == [UNIT_A]
    assert at_rev1[0]["status"] == "in_force"


def test_survival_ledger_empty_without_outcomes(temp_database):
    _snap(1, 10, SPEC_V1)
    assert active_rules.survival_ledger() == []
    container = SimpleNamespace(db=db, chain_state=chain_state)
    data = _exec(getactiverules, "getactiverules", container)["data"]
    assert data["survival_ledger"] == []


def test_survival_ledger_maintainer_scenario_via_engine(temp_database):
    """End to end through block apply: the probe's two transactions land,
    their receipts are persisted as createblock persists them, and the
    getactiverules answer's ledger shows the first unit partially
    displaced by the second -- the same story the effective_spec text
    tells, per unit."""
    session = _PointwiseSession()
    r1 = _apply_block(session, [_rule_tx("p1", PROBE_TX1, 0)], height=1,
                      sequences={})
    _record_snapshot(session, 1)
    db.record_rule_outcomes("aa" * 32, 1,
                            {"p1": r1.receipts["p1"]["rule_outcome"]})
    r2 = _apply_block(session, [_rule_tx("p2", PROBE_TX2, 1)], height=2,
                      sequences={SENDER: 1}, snapshot=r1.snapshot)
    _record_snapshot(session, 2)
    db.record_rule_outcomes("bb" * 32, 2,
                            {"p2": r2.receipts["p2"]["rule_outcome"]})

    container = SimpleNamespace(db=db, chain_state=chain_state)
    data = _exec(getactiverules, "getactiverules", container)["data"]
    ledger = {e["tx_hash"]: e for e in data["survival_ledger"]}
    assert set(ledger) == {"p1", "p2"}
    assert ledger["p1"]["status"] == "partially_displaced"
    assert ledger["p1"]["displaced_by"] == ["p2"]
    assert ledger["p1"]["surviving_fragments"] == [FRAG_O27_9]
    assert ledger["p2"]["status"] == "in_force"
    assert ledger["p2"]["installed_fragments"] == [FRAG_O26_3]

