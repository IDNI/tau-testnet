"""Bounty 02 (issue #42), PR #151: the Sep 27 displacement probe under
worker-backed authority -- the one evaluator mode this PR's other
native evidence does not run.

tests/test_active_rules_probe_native.py runs the probe against a real
TauInterface and through tau_manager's in-process communicate seam.
But a node running worker-backed authority (tau_authority) has no
in-process block application at all: consensus/engine.py refuses it
(_refuse_in_process_authority), each block is evaluated by a proposal's
worker session, committed through the tau_commit protocol, and the
exact worker that evaluated the committed block is promoted to serve
as the node's evaluator. The active-rules view is served from the
persisted accumulation's snapshots (commands/getactiverules.py), whose
text is composed Python-side from that accumulation, so it SHOULD be
evaluator-agnostic -- and gettxstatus's per-transaction outcome SHOULD
be the executing worker's own revision receipt. Until this file, both
were unproven under authority: every B02 native run exercised the
in-process evaluator only.

This file drives the real entry points with authority enabled, the
way tests/test_authority_cutover_native.py does -- sendtx admission,
createblock mining, the commit protocol, promotion -- submits the
maintainers' probe as two confirmed rule transactions in two blocks,
and then reads the two public surfaces:

  1. getactiverules reports o26 = 3 and o27 = 9 in force, no
     assignment in force carries 7, and the served text hashes to the
     served sha256;
  2. gettxstatus for each rule transaction reports it confirmed with
     its apply outcome -- ACCEPTED_CHANGED, the engine's o0 verdict,
     and a revision chain across the displacement -- and the revision
     the displacement took is exactly the revision the view serves at
     the head. Both records derive from the executing session's own
     receipt (consensus/engine.py harvests rule_outcome and
     spec_snapshot from that one receipt at apply), so under authority
     this is the worker's receipt agreeing with itself through two
     independent stores -- the same agreement the mock suite asserts
     on the in-process path
     (tests/test_active_rules_view.py::test_confirmed_rule_tx_shows_apply_outcome).

Gate: idiom A (module-level native probe, as in
tests/test_tau_authority_native.py). Locally every test skips; in the
native-tau-tests CI job the preflight hard-fails if the module is
missing, so a green job cannot be a disguised skip.

What is NOT asserted, deliberately:

  * No absolute revision numbers. The authority owner commits the
    genesis units to its journal at initialize(), each revising the
    evaluator once, so the probe starts wherever genesis left the
    counter. The claims are the chain (each step's before is the
    previous step's after, strictly advancing) and the agreement
    between the outcome record and the view -- never a value.
  * The sender is funded by direct balance injection (the cutover
    suite's _sender), not a genesis account: this file never replays
    or rebuilds, so the injection is reproducible here. Restart and
    journal-rebuild agreement under authority are the cutover suite's
    claims, not this file's.
  * The view is read at the head only. Height-addressed reads and the
    per-unit survival ledger are read-side derivations over the same
    snapshot sequence the mock suite already covers; the authority
    question is whether the snapshots and outcomes exist and agree
    when a worker produced them.
"""
import hashlib
import json
import os
import re
import threading
import time
import types

import pytest
from py_ecc.bls import G2Basic as bls
from unittest.mock import patch

import chain_state
import db
import tau_authority as auth
import tau_commit as tc
from commands import createblock, getactiverules, gettxstatus, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The maintainers' displacement probe from issue #42, as two rule units.
# Copied verbatim from tests/test_active_rules_view_native.py.
RULE_INSTALL = (
    "always ( o26[t]:bv[64] = { 7 }:bv[64] && o27[t]:bv[64] = { 9 }:bv[64] )."
)
RULE_DISPLACE = "always ( o26[t]:bv[64] = { 3 }:bv[64] )."

# Current-[t] constant assignments in a composed spec text -- the same
# pattern the probe suite parses the engine's spec with
# (tests/test_active_rules_probe_native.py's _ASSIGNMENT_RE).
_ASSIGNMENT_RE = re.compile(
    r"(o\d+)\[t\]:(bv\[\d+\])\s*=\s*\{\s*([0-9]+|#x[0-9a-fA-F]+)\s*\}:bv\[\d+\]"
)


def _assignments_in_force(spec_text):
    """Map of output stream -> the set of literals its current [t]
    assignments carry in the composed spec text."""
    in_force = {}
    for stream, _width, literal in _ASSIGNMENT_RE.findall(spec_text):
        in_force.setdefault(stream, set()).add(literal)
    return in_force


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built"
)


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _baseline():
    return "always ( " + open(os.path.join(REPO, "genesis.tau")).read().strip() + " )."


@pytest.fixture
def authority(node_state):
    """Enable worker-backed authority on the in-process test node.

    The fixture body is tests/test_authority_cutover_native.py's: the
    owner is installed as THE authority (auth.reset) and initialized
    against the node's database, committing the genesis units to the
    journal. node_state supplies the temp database, the loaded
    genesis and the dummy miner; its fake in-process engine is never
    stepped for block production under authority (the cutover suite's
    test_block_production_never_steps_the_in_process_interpreter).
    """
    ready = threading.Event()
    owner = auth.AuthoritativeTauOwner(ready=ready, program_baseline=_baseline())
    auth.reset(owner)
    tc.registry().discard()
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    tc.registry().discard()
    auth.reset(None)


@pytest.fixture(autouse=True)
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True):
        yield


def _sender(tag, balance=1_000_000):
    sk = bls.KeyGen(tag.encode())
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = balance
    return sk, pk


def _submit(sk, pk, ops, seq=0, fee_limit="100000"):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": ops, "fee_limit": fee_limit}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return db.get_canonical_head()


def _run_probe(authority):
    """Install, then displace, as two confirmed rule transactions in
    two blocks, under the worker-backed authority. Returns the two
    admission results (each carries its transaction hash)."""
    sk, pk = _sender("activerules_authority")
    install = _submit(sk, pk, {"0": RULE_INSTALL}, seq=0)
    assert install.get("ok"), install
    head1 = _mine()
    displace = _submit(sk, pk, {"0": RULE_DISPLACE}, seq=1)
    assert displace.get("ok"), displace
    head2 = _mine()
    assert head2["block_number"] == head1["block_number"] + 1
    # The evaluator serving the node after both commits is the
    # authority, and it describes the committed journal.
    assert authority.state == auth.ACTIVE
    assert authority.descriptor.journal_head_hash == db.committed_journal_head()[0], (
        "the serving evaluator does not describe the committed journal"
    )
    return install, displace


def _view():
    resp = json.loads(
        getactiverules.execute(
            "getactiverules", types.SimpleNamespace(db=db)
        )
    )
    assert resp["status"] == "ok", resp
    return resp["data"]


def _status(tx_hash):
    resp = json.loads(
        gettxstatus.execute(
            f"gettxstatus {tx_hash}", types.SimpleNamespace(db=db)
        )
    )
    assert resp["status"] == "ok", resp
    return resp["data"]


def test_the_displacement_probe_view_under_worker_backed_authority(authority):
    """o26 = {7} && o27 = {9}, then o26 = {3}, as confirmed rule
    transactions evaluated by the authority's worker: the active-rules
    view reports o26 = 3 and o27 = 9 in force, no assignment in force
    carries 7, and the served text hashes to the served sha256."""
    _run_probe(authority)

    view = _view()
    assert view["available"] is True
    in_force = _assignments_in_force(view["canonical_text"])
    assert in_force.get("o26") == {"3"}
    assert in_force.get("o27") == {"9"}
    assert all("7" not in literals for literals in in_force.values())
    assert view["sha256"] == hashlib.sha256(
        view["canonical_text"].encode("utf-8")
    ).hexdigest()


def test_a_confirmed_rule_tx_shows_its_apply_outcome_under_authority(authority):
    """Each probe transaction is confirmed with the apply outcome of
    its own rule step -- outcome classification, the engine's o0
    verdict, and the revision it took -- recorded from the worker
    session's receipt. The revisions chain across the displacement,
    and the revision the displacement took is the revision the view
    serves at the head."""
    install, displace = _run_probe(authority)

    install_data = _status(install["tx_hash"])
    assert install_data["status"] == "confirmed"
    first = install_data["rule_outcome"]
    assert first["outcome"] == "ACCEPTED_CHANGED"
    assert first["outputs"]["o0"] == "F"
    assert first["spec_revision_after"] > first["spec_revision_before"]

    displace_data = _status(displace["tx_hash"])
    assert displace_data["status"] == "confirmed"
    second = displace_data["rule_outcome"]
    assert second["outcome"] == "ACCEPTED_CHANGED"
    assert second["outputs"]["o0"] == "F"
    assert second["spec_revision_before"] == first["spec_revision_after"]
    assert second["spec_revision_after"] > second["spec_revision_before"]

    # The revision the displacement took is the revision the view
    # serves: the snapshot recorded for that revision is the view's
    # head state, not a parallel reconstruction.
    view = _view()
    assert view["available"] is True
    assert view["spec_revision"] == second["spec_revision_after"]
    snapshot = db.get_spec_snapshot(second["spec_revision_after"])
    assert snapshot is not None
    assert view["sha256"] == snapshot["sha256"]
