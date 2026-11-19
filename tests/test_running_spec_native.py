"""`running_spec` on the real engine, through real blocks: the probe of Sep 27 (#42).

Sent `o26 = {7} && o27 = {9}`, then `o26 = {3}`: the engine runs
`o26 = 3 && o27 = 9`, while the stored application rules still list both units.
The read has to say what the engine runs, the same text the authoritative worker
holds, and give the same text and hash when it is rebuilt from the journal alone.
"""
import hashlib
import json
import os
import re
import threading
import time

import pytest
from py_ecc.bls import G2Basic as bls
from unittest.mock import patch

import chain_state
import tau_admission
import tau_authority as auth
import tau_commit as tc
import tau_running_spec as rs
from commands import createblock, getgovernance, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

A = "always ( o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24] )."
B = "always ( o26[t]:bv[24] = { 3 }:bv[24] )."


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(), reason="native tau module not built")


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def authority(node_state):
    baseline = "always ( " + open(os.path.join(REPO, "genesis.tau")).read().strip() + " )."
    owner = auth.AuthoritativeTauOwner(ready=threading.Event(), program_baseline=baseline)
    auth.reset(owner)
    tc.registry().discard()
    tau_admission.reset()
    rs.reset_cache()
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    rs.reset_cache()
    tc.registry().discard()
    tau_admission.reset()
    auth.reset(None)


@pytest.fixture(autouse=True)
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True), \
         patch("consensus.bls.verify", lambda *a, **k: True):
        yield


def _sender(tag):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = 1_000_000
    return sk, pk


def _submit(sk, pk, ops, seq):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": ops, "fee_limit": "100000"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return out


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_the_probe_of_sep_27_reads_what_the_engine_runs(authority, monkeypatch):
    # the baseline, without the probe: no o26 anywhere yet
    before = rs.at_head()
    assert before["text"] and "o26" not in before["text"], before

    sk, pk = _sender("probe")
    assert _submit(sk, pk, {"0": A}, seq=0).get("ok")
    _mine()
    first = rs.at_head()
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in first["text"], first["text"]

    assert _submit(sk, pk, {"0": B}, seq=1).get("ok")
    _mine()
    out = rs.at_head()
    text = out["text"]

    # what the engine runs: o26 = 3 && o27 = 9, the 7 is gone
    assert "o26[t]:bv[24] = { 3 }:bv[24]" in text, text
    assert "o27[t]:bv[24] = { 9 }:bv[24]" in text, text
    assert "{ 7 }" not in text, text
    assert out["sha256"] == _sha(text)
    assert out["block_hash"] == chain_state._canonical_head_hash

    # what was sent: the stored units still hold both
    stored = chain_state._application_rules_state
    assert "{ 7 }" in stored and "{ 3 }" in stored and "{ 9 }" in stored, stored

    # the authoritative worker runs the same rules, in its own representation:
    # the same o26/o27 terms, while it feeds address streams shrunk (bv[8]),
    # which is why the read rebuilds the canonical text instead of quoting it
    worker_text = authority.current()._spec.current_spec()
    probe = re.compile(r"o2[67]\[t\]:bv\[24\] = \{ \d+ \}:bv\[24\]")
    assert probe.findall(worker_text) == probe.findall(text) == [
        "o27[t]:bv[24] = { 9 }:bv[24]", "o26[t]:bv[24] = { 3 }:bv[24]"]
    assert "i3[t]:bv[384]" in text and "i3[t]:bv[384]" not in worker_text

    # rebuilt from the committed journal alone, the same text and hash
    rs.reset_cache()
    again = rs.at_head()
    assert (again["text"], again["sha256"]) == (text, out["sha256"])

    # and getgovernance carries the same answer next to the stored units
    import db
    import types
    data = json.loads(getgovernance.execute(
        "getgovernance", types.SimpleNamespace(chain_state=chain_state, db=db)))["data"]
    assert data["running_spec"]["sha256"] == out["sha256"]
    assert data["running_spec"]["block_hash"] == data["head_hash"]


def test_a_new_rule_entry_rebuilds_it_and_a_plain_block_does_not(authority, monkeypatch):
    sk, pk = _sender("cache")
    assert _submit(sk, pk, {"0": A}, seq=0).get("ok")
    _mine()
    spawned = []
    real = rs._spawn
    monkeypatch.setattr(rs, "_spawn", lambda: spawned.append(1) or real())

    first = rs.at_head()
    sk_b, pk_b = _sender("peer")
    assert _submit(sk_b, pk_b, {"1": [[pk_b, pk, "3"]]}, seq=0).get("ok")
    _mine()  # a block with a transfer only: steps, no rule entry
    second = rs.at_head()
    assert len(spawned) == 1, "a block without a rule entry rebuilt the spec"
    assert second["sha256"] == first["sha256"]
    assert second["block_hash"] == chain_state._canonical_head_hash != first["block_hash"]

    assert _submit(sk, pk, {"0": B}, seq=1).get("ok")
    _mine()
    third = rs.at_head()
    assert len(spawned) == 2
    assert "{ 7 }" not in third["text"]
