"""Issue #42, step 2: the shadow replay and the getaccountrules view.

The view of active shared rules must come from the spec the engine runs,
not from the append-only accumulation: apply `o26={7} && o27={9}`, then
`o26={3}`, and the accumulation still contains BOTH units (it would still
show o26 = 7), while the running spec is `o26 = 3 && o27 = 9`. The node
therefore keeps an isolated shadow interface, advanced at commit with
exactly the units that entered the accumulation, and serves the view from
its normalized spec, snapshotted per block with its sha256.

The native tau module is not built in every environment, so -- exactly as
tests/test_rule_outcomes.py does for receipts -- the engine side here is a
scripted driver behind the same interface the production driver uses
(TauInterface.communicate / get_current_spec): pointwise revision for
assignment units is implemented directly, and the satisfiable-mirror
unit's normalized form is scripted from the form measured on the real
engine in the issue thread ({5} !< o26 || o26*3+1 = o26). What is under
test is the feed discipline (registry txs never advance the shadow), the
snapshot persistence, the rebuild equality, and the view -- not Tau
semantics, which the native suites cover.
"""
import hashlib
import json
import re
import types
from unittest.mock import patch

import pytest

import chain_state
import db
import tau_defs
from block import Block
from bls_keys import SK_ALICE, pubkey_hex
from commands import getaccountrules
from consensus import sender_policy
from consensus.engine import ActiveConsensusView, TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager
from consensus.policy_mock import MockPolicyEvaluator
from consensus.shadow_spec import ShadowSpec
from consensus.state import TauStateSnapshot

import test_approval_apply as ap
import test_rule_outcomes as step1

ALICE = step1.ALICE
STREAM = tau_defs.USER_POLICY_STREAM_INDEX
HEIGHT = step1.HEIGHT

PROBE_UNIT_1 = "always ( o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24] )."
PROBE_UNIT_2 = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
MIRROR_UNIT = (
    "always ( (o26[t]:bv[24] > { 5 }:bv[24]) "
    "-> (o26[t]:bv[24] = o26[t]:bv[24]*{ 3 }:bv[24]+{ 1 }:bv[24]) )."
)
# The mirror clause in force, in the normalized form measured on the real
# engine in the issue thread (andrei-idni, 2026-09-27).
MIRROR_NORMALIZED = (
    "always ( { 5 }:bv[24] !< o26[t]:bv[24] "
    "|| o26[t]:bv[24]*{ 3 }:bv[24]+{ 1 }:bv[24] = o26[t]:bv[24] )."
)

_ASSIGN_RE = re.compile(
    r"o(\d+)\[t\](?::bv\[\d+\])?\s*=\s*(\{[^}]*\}(?::bv\[\d+\])?)"
)


class ScriptedTauDriver:
    """A TauInterface-shaped double with pointwise-revision semantics.

    Assignment units (`oN = {v}` conjunctions) revise a per-stream
    assignment map -- a later assignment to the same stream displaces the
    earlier one, which is the whole displacement story. Any other unit is
    conjoined verbatim, unless a test scripts its normalized effect via
    `script_as`. Revisions count accepted changes, like the real
    interpreter's spec_revision.
    """

    def __init__(self):
        self.assignments = {}
        self.extras = []
        self.revision = 0
        self.fed = []
        self._scripted = {}

    def script_as(self, unit, normalized_unit):
        self._scripted[unit.strip()] = normalized_unit

    # -- the TauInterface shape the shadow driver uses --------------------

    def feed(self, unit):
        unit = unit.strip()
        self.fed.append(unit)
        before = self.revision
        if unit in self._scripted:
            normalized = self._scripted[unit]
            if normalized not in self.extras:
                self.extras.append(normalized)
            self.revision += 1
        else:
            assignments = _ASSIGN_RE.findall(unit)
            remainder = _ASSIGN_RE.sub("", unit)
            if assignments and not re.search(r"o\d+\[t\]", remainder):
                changed = False
                for stream, value in assignments:
                    value = re.sub(r"\s+", " ", value).strip()
                    if self.assignments.get(stream) != value:
                        self.assignments[stream] = value
                        changed = True
                if changed:
                    self.revision += 1
            elif unit not in self.extras:
                self.extras.append(unit)
                self.revision += 1
        return {
            "outcome": "ACCEPTED_CHANGED" if self.revision > before
                       else "ACCEPTED_NOOP",
            "accepted": True,
            "changed": self.revision > before,
            "spec_revision_before": before,
            "spec_revision_after": self.revision,
        }

    def current_spec(self):
        lines = []
        if self.assignments:
            conjuncts = " && ".join(
                f"o{stream}[t]:bv[24] = {self.assignments[stream]}"
                for stream in sorted(self.assignments, key=int)
            )
            lines.append(f"always ( {conjuncts} ).")
        lines.extend(self.extras)
        return "\n".join(lines)

    def spec_revision(self):
        return self.revision


class Chain(step1.Chain):
    """step1.Chain with real previous-hash linkage, so the canonicality
    walk behind at-height snapshot queries can reach older blocks."""

    def __init__(self):
        super().__init__()
        self.prev_hash = "00" * 32

    def apply(self, txs):
        view = ActiveConsensusView(
            target_height=self.height,
            consensus_rules=self.snapshot.metadata["consensus_rules_state"],
            active_validators=[bytes.fromhex(ap.ALICE)],
            mechanism_specific_metadata={"poa": True, "approval_slots_active": True},
        )
        block = Block.create(
            block_number=self.height, previous_hash=self.prev_hash,
            transactions=txs, proposer_pubkey=ap.ALICE, timestamp=1234567890,
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
        self.prev_hash = block.block_hash
        return block, result


@pytest.fixture()
def shadow_driver():
    driver = ScriptedTauDriver()
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


def _genesis_block():
    return Block.create(
        block_number=0, previous_hash="00" * 32, transactions=[],
        proposer_pubkey=ap.ALICE, timestamp=1_700_000_000)


def _commit(chain, blocks_results, genesis=None):
    """Run the commit-path recorders exactly as process_new_block does and
    make the last block the canonical head."""
    genesis = genesis or _genesis_block()
    db.add_block(genesis)
    head = genesis
    for block, result in blocks_results:
        chain_state._record_rule_outcomes(block, result.next_snapshot)
        chain_state._record_shadow_snapshot(block, result.next_snapshot)
        db.add_block(block)
        head = block
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_hash', ?)", (head.block_hash,))
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) "
            "VALUES ('canonical_head_number', ?)",
            (str(head.header.block_number),))
        db._db_conn.commit()
    return head


def _view(address=ALICE, height=None):
    container = types.SimpleNamespace(db=db, chain_state=chain_state)
    cmd = f"getaccountrules {address}"
    if height is not None:
        cmd += f" {height}"
    resp = json.loads(getaccountrules.execute(cmd, container))
    assert resp["status"] == "ok", resp
    return resp["data"]


def _mixed_chain(shadow_driver):
    """shared unit, then a clause (registry) unit, then a shared unit."""
    chain = Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 3, 4)
    b1 = chain.apply([step1._rule_tx(step1.SHARED_RULE, seq=0)])

    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.set_verdict(step1.CLAUSE_BODY, "1")
    sender_policy.set_evaluator("apply", evaluator)
    b2 = chain.apply([step1._rule_tx(step1.CLAUSE_RULE, seq=1)])

    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 4, 5)
    shared2 = "always ( o13[t]:bv[24] = i2[t]:bv[24] )."
    b3 = chain.apply([step1._rule_tx(shared2, seq=2)])
    return chain, [b1, b2, b3]


# --- the shadow's feed discipline --------------------------------------------

def test_shadow_matches_live_running_spec(temp_database, shadow_driver):
    chain, blocks = _mixed_chain(shadow_driver)
    _commit(chain, blocks)

    shadow = chain_state.get_shadow_spec()
    # Only the two shared-spec units ever reached the shadow: the clause
    # transaction was routed into the registry and must not advance it.
    assert shadow.fed_units == [step1.SHARED_RULE, "always ( o13[t]:bv[24] = i2[t]:bv[24] )."]
    assert shadow_driver.fed == shadow.fed_units

    # The live running spec, as an independent oracle: a fresh driver fed
    # the same shared units in the same order (the differential pattern
    # the design's native variant runs against a fresh TauInterface).
    oracle = ScriptedTauDriver()
    for unit in shadow.fed_units:
        oracle.feed(unit)
    assert shadow.normalized_text == oracle.current_spec()
    assert shadow.revision == oracle.revision == 2

    # Snapshots exist for the two shared blocks and NOT for the clause
    # block: its height serves the previous snapshot, unchanged.
    snap_clause_height = db.get_spec_snapshot_at(blocks[1][0].header.block_number)
    snap_shared2 = db.get_spec_snapshot_at(blocks[2][0].header.block_number)
    assert snap_clause_height["height"] == blocks[0][0].header.block_number
    assert snap_shared2["height"] == blocks[2][0].header.block_number
    assert snap_shared2["sha256"] == hashlib.sha256(
        snap_shared2["normalized_text"].encode("utf-8")).hexdigest()


def test_shadow_rebuild_from_accumulation_equals_incremental(
        temp_database, shadow_driver):
    chain, blocks = _mixed_chain(shadow_driver)
    _commit(chain, blocks)

    incremental = []
    for block, _result in blocks:
        snap = db.get_spec_snapshot_at(block.header.block_number)
        if snap and (not incremental or incremental[-1]["height"] != snap["height"]):
            incremental.append(snap)
    assert len(incremental) == 2

    # Replay from block 0: a fresh shadow fed the per-block unit groups
    # (the accumulation lines of each block's committed snapshot, in
    # order) must reproduce every snapshot -- same text, same sha256.
    groups = []
    for block, result in blocks:
        text = result.next_snapshot.tau_bytes.decode("utf-8")
        groups.append((block.header.block_number, block.block_hash,
                       [u for u in text.split("\n") if u.strip()]))
    _rebuilt, snapshots = ShadowSpec.replay(ScriptedTauDriver, groups)
    assert len(snapshots) == len(incremental)
    for rebuilt, recorded in zip(snapshots, incremental):
        assert rebuilt["height"] == recorded["height"]
        assert rebuilt["normalized_text"] == recorded["normalized_text"]
        assert rebuilt["sha256"] == recorded["sha256"]
        assert rebuilt["shadow_revision"] == recorded["shadow_revision"]


# --- the maintainer's probe, through the view ---------------------------------

def test_displacement_probe_matches_running_spec(temp_database, shadow_driver):
    chain = Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 1, 2)
    b1 = chain.apply([step1._rule_tx(PROBE_UNIT_1, seq=0)])
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 2, 3)
    b2 = chain.apply([step1._rule_tx(PROBE_UNIT_2, seq=1)])
    _commit(chain, [b1, b2])

    data = _view()
    assert data["status"] == "recorded"
    text = data["shared_spec"]["normalized_text"]
    # The running spec after pointwise revision: o26 displaced to 3, o27
    # survives at 9. The accumulation would still show o26 = { 7 }.
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in text
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in text
    assert "{ 7 }" not in text
    assert data["snapshot"]["height"] == b2[0].header.block_number
    assert data["snapshot"]["sha256"] == hashlib.sha256(
        text.encode("utf-8")).hexdigest()

    # A second node / a replay from block 0 derives the same answer.
    groups = [
        (blk.header.block_number, blk.block_hash,
         [u for u in res.next_snapshot.tau_bytes.decode("utf-8").split("\n")
          if u.strip()])
        for blk, res in (b1, b2)
    ]
    _shadow2, snaps = ShadowSpec.replay(ScriptedTauDriver, groups)
    assert snaps[-1]["normalized_text"] == text
    assert snaps[-1]["sha256"] == data["snapshot"]["sha256"]

    # At-height: the first block's snapshot still reports the pre-displacement
    # spec -- history is served from snapshots, not recomputed.
    at_first = _view(height=b1[0].header.block_number)
    assert at_first["snapshot"]["height"] == b1[0].header.block_number
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in at_first["shared_spec"]["normalized_text"]


def test_mirror_satisfiable_rule_in_force(temp_database, shadow_driver):
    # The scripted driver's normalization of the mirror unit is the form
    # measured on the real engine in the thread; the harness cannot run
    # the native normalizer (bindings not built here), so what is asserted
    # is that the VIEW serves the engine-produced normalized form as in
    # force -- not the submitted text, and not "missing".
    shadow_driver.script_as(MIRROR_UNIT, MIRROR_NORMALIZED)

    chain = Chain()
    chain.receipt = step1._receipt("ACCEPTED_CHANGED", 5, 6)
    b1 = chain.apply([step1._rule_tx(MIRROR_UNIT, seq=0)])
    assert not b1[1].invalid_tx_ids, b1[1].outcomes
    _commit(chain, [b1])

    data = _view()
    assert data["status"] == "recorded"
    text = data["shared_spec"]["normalized_text"]
    assert MIRROR_NORMALIZED in text
    assert "!<" in text and "o26[t]:bv[24]*{ 3 }:bv[24]+{ 1 }:bv[24] = o26[t]:bv[24]" in text
    # Not quoted back as submitted: the implication form the user sent is
    # not what the engine runs.
    assert "->" not in text


# --- the view's other half + the not_recorded answer ---------------------------

def test_view_registry_half_and_not_recorded(temp_database, shadow_driver):
    # Before any rule block: no snapshot exists, and the view must say
    # not_recorded rather than reconstructing anything from submitted text.
    data = _view()
    assert data["status"] == "not_recorded"
    assert data["snapshot"] is None
    assert data["shared_spec"] is None
    assert data["registry"]["accepted_clauses"] == []
    # A height with no snapshot at or before it is likewise not served.
    assert _view(height=1)["status"] == "not_recorded"

    # A clause install lands in the registry: the view's registry half
    # shows it with the registry root. The clause transaction itself must
    # NOT advance the shadow -- the only unit the shadow ever sees here is
    # the genesis accumulation the commit-path recorder catches up on,
    # exactly as a restarted node replays the persisted accumulation.
    evaluator = MockPolicyEvaluator(pool="apply")
    evaluator.set_verdict(step1.CLAUSE_BODY, "1")
    sender_policy.set_evaluator("apply", evaluator)

    genesis = _genesis_block()
    chain = Chain()
    chain.prev_hash = genesis.block_hash
    # Height 1, not the usual 20: the canonicality walk behind snapshot
    # queries steps height-by-height, and this test needs it to reach the
    # genesis snapshot (production chains have every height; the harness
    # normally jumps straight to 20).
    chain.height = 1
    chain_state._record_shadow_snapshot(genesis, chain.snapshot)
    fed_at_genesis = chain_state.get_shadow_spec().fed_units
    assert fed_at_genesis == ["always (o0[t]=1)."]

    b1 = chain.apply([step1._rule_tx(step1.CLAUSE_RULE, seq=0)])
    _commit(chain, [b1], genesis)
    chain_state._lifecycle_manager = chain.lifecycle
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO rule_clauses_v1 "
            "(acceptor_pubkey, target_stream, clause_body) VALUES (?, ?, ?)",
            (ALICE, STREAM, step1.CLAUSE_BODY))
        db._db_conn.commit()

    # The clause block recorded no new snapshot: the newest canonical
    # snapshot is still the genesis one, and the shadow fed nothing more.
    shadow = chain_state.get_shadow_spec()
    assert shadow.fed_units == fed_at_genesis
    assert db.get_spec_snapshot_at()["height"] == 0

    data = _view()
    assert data["status"] == "recorded"
    assert data["snapshot"]["height"] == 0
    assert data["registry"]["accepted_clauses"] == [
        {"target_stream": STREAM, "clause_body": step1.CLAUSE_BODY}
    ]
    assert data["registry"]["rule_clauses_root"] == \
        chain.lifecycle.rule_offers.clauses_root().hex()
