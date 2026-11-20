"""Issue #42: the maintainers' probe on the native tau-lang engine.

Kept in its own file so the real-Tau CI job can register exactly this
file: the probe needs the native bindings, which the mock test job does
not have. The skip below is environment-driven -- in the real-Tau job's
image the bindings are present (its preflight imports them), so the
skip lifts and the probe runs for real. Everywhere else it skips,
exactly as it did when it lived in test_active_rules_issue42.py.
"""
import hashlib
import json
import os
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic as bls

import chain_state
import db
import tau_admission
import tau_authority as auth
import tau_commit as tc
from commands import createblock, getactiverules, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus import active_rules
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _native_available():
    try:
        from tau_native import load_tau_module

        load_tau_module()
        return True
    except Exception:
        return False


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_displacement_probe_on_native_engine(tmp_path):
    """The Sep 27 probe on the real engine: two fresh interpreters fed the
    same units must run the same spec (o26 = 3, o27 = 9), with identical
    text and hash -- the determinism premise the snapshot view relies on."""
    from tau_native import TauInterface

    unit1 = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
             "o27[t]:bv[24] = { 9 }:bv[24] ).")
    unit2 = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."
    specs = []
    for _ in range(2):
        ti = TauInterface("genesis.tau")
        ti.communicate(rule_text=unit1, target_output_stream_index=0)
        ti.communicate(rule_text=unit2, target_output_stream_index=0)
        specs.append(ti.get_current_spec())
    assert specs[0] == specs[1]
    assert hashlib.sha256(specs[0].encode()).hexdigest() == \
        hashlib.sha256(specs[1].encode()).hexdigest()
    assert "o26" in specs[0] and "{ 3 }" in specs[0]
    assert "{ 7 }" not in specs[0].split("o27")[0]


# --- The same probe in production mode: worker-backed authority ------------
#
# A node outside test mode runs the authoritative worker (server.py:
# authority is enabled unless the mock configuration was requested). The
# in-process interpreter is then only an advisory mirror and is never fed
# the application-rule revisions, and the persisted `full_tau_spec` row is
# the append-only accumulation. The snapshot behind getactiverules must
# still serve the spec the engine runs.

PROBE_A = ("always ( o26[t]:bv[24] = { 7 }:bv[24] && "
           "o27[t]:bv[24] = { 9 }:bv[24] ).")
PROBE_B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _reset_spec_mirror():
    reset = getattr(active_rules, "reset_spec_mirror", None)
    if reset is not None:
        reset()


@pytest.fixture
def authority(node_state):
    baseline = "always ( " + open(
        os.path.join(REPO, "genesis.tau")).read().strip() + " )."
    owner = auth.AuthoritativeTauOwner(
        ready=threading.Event(), program_baseline=baseline)
    auth.reset(owner)
    tc.registry().discard()
    tau_admission.reset()
    _reset_spec_mirror()
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    _reset_spec_mirror()
    tc.registry().discard()
    tau_admission.reset()
    auth.reset(None)


@pytest.fixture
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility",
                      lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header",
                      lambda *a, **k: True), \
         patch("consensus.bls.verify", lambda *a, **k: True):
        yield


def _sender(tag):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = 1_000_000
    return sk, pk


def _submit(sk, pk, ops, seq):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk,
          "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600,
          "expire_at_height": 5000,
          "operations": ops, "fee_limit": "100000"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return out


@pytest.mark.skipif(
    not _native_available(),
    reason="native tau-lang bindings not available in this environment",
)
def test_active_rules_view_under_authority(authority, _mining_allowed):
    """The maintainers' probe mined through real blocks with the
    authoritative worker enabled: after `o26 = {7} && o27 = {9}` the
    recorded view runs o26 = 7; after `o26 = {3}` it runs o26 = 3 and
    o27 = 9, with the displaced {7} nowhere in the served text — the
    same answer direct mode gives, from the production configuration."""
    sk, pk = _sender("authority-probe")

    assert _submit(sk, pk, {"0": PROBE_A}, seq=0).get("ok")
    _mine()
    snap = active_rules.resolve_snapshot()
    assert snap is not None, "no snapshot recorded after the first block"
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in snap["spec_text"], \
        snap["spec_text"]
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in snap["spec_text"], \
        snap["spec_text"]

    assert _submit(sk, pk, {"0": PROBE_B}, seq=1).get("ok")
    _mine()
    snap = active_rules.resolve_snapshot()
    assert snap is not None, "no snapshot recorded after the second block"
    text = snap["spec_text"]
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in text, text
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in text, text
    assert "{ 7 }" not in text, text

    container = SimpleNamespace(db=db, chain_state=chain_state)
    data = json.loads(
        getactiverules.execute("getactiverules", container))["data"]
    assert data["effective_spec"] == text
    assert data["spec_hash"] == active_rules.spec_hash_of(text)
