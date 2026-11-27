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


def _revision(queued):
    """What the confirmed transaction says the engine did with its rule."""
    import db
    out = db.get_tx_outcome(queued["tx_hash"], chain_state._canonical_head_hash)
    assert out and out["status"] == "applied", out
    (effect,) = [e for e in out["rule_effects"] if e["action"] == "accumulated"]
    return effect["revision"]


def test_the_probe_of_sep_27_reads_what_the_engine_runs(authority, monkeypatch):
    # the baseline, without the probe: no o26 anywhere yet
    before = rs.at_head()
    assert before["text"] and "o26" not in before["text"], before

    sk, pk = _sender("probe")
    queued_a = _submit(sk, pk, {"0": A}, seq=0)
    assert queued_a.get("ok")
    _mine()
    took_a = _revision(queued_a)
    first = rs.at_head()
    assert "o26[t]:bv[24] = { 7 }:bv[24]" in first["text"], first["text"]

    queued_b = _submit(sk, pk, {"0": B}, seq=1)
    assert queued_b.get("ok")
    _mine()
    took_b = _revision(queued_b)
    out = rs.at_head()
    text = out["text"]

    # each confirmed transaction says the engine took its revision, in order
    assert took_a["taken"] and took_a["engine_outcome"] == "ACCEPTED_CHANGED", took_a
    assert took_b["taken"] and took_b["engine_outcome"] == "ACCEPTED_CHANGED", took_b
    assert took_b["spec_revision"] > took_a["spec_revision"], (took_a, took_b)

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

    # nor the in-process interpreter's text: a node outside test mode runs the
    # authoritative evaluator (server.py), so tau_manager.get_canonical_spec()
    # holds none of the committed rules
    import tau_manager
    assert "o26" not in (tau_manager.get_canonical_spec() or "")

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


# --- an earlier block ------------------------------------------------------------

def _journal_outcome(queued, block_hash):
    import db
    from commands import gettxstatus
    return gettxstatus.journal_rule_outcome(db, queued["tx_hash"], block_hash)


def _rules_at(pk, block):
    import db
    from commands import getaccountrules
    return getaccountrules.at_block(chain_state, db, pk, str(block))


def test_each_block_of_the_probe_reads_what_the_engine_ran_then(authority):
    """The probe again, read block by block afterwards: every block answers
    with the text the head gave while that block was the head."""
    import db
    sk, pk = _sender("then")
    _, peer = _sender("then-peer")
    scoped = ("always ( (i12[t]:bv[384] = { #x" + pk + " }:bv[384]) ? "
              "(o28[t]:bv[24] = { 5 }:bv[24]) : (o28[t]:bv[24] = { 0 }:bv[24]) ).")
    heads, sent, stored = [], [], []
    for seq, ops in enumerate(({"0": A}, {"0": B}, {"1": [[pk, peer, "3"]]}, {"0": scoped},
                               {"0": B}, {"0": A})):
        queued = _submit(sk, pk, ops, seq=seq)
        assert queued.get("ok"), queued
        _mine()
        sent.append(queued)
        heads.append((chain_state._canonical_head_hash, rs.at_head()))
        stored.append(chain_state._application_rules_state)

    rs.reset_cache()
    then = [rs.at_block(block_hash) for block_hash, _ in heads]
    for (block_hash, at_head), at_block in zip(heads, then):
        assert at_block["block_hash"] == block_hash
        assert (at_block["text"], at_block["sha256"]) == (at_head["text"], at_head["sha256"])
    with_7, with_3, plain, with_28, same_again, back_to_7 = then
    assert "{ 7 }" in with_7["text"] and "{ 3 }" not in with_7["text"]
    assert "{ 3 }" in with_3["text"] and "{ 7 }" not in with_3["text"]
    assert plain["sha256"] == with_3["sha256"]          # a transfer revises nothing
    assert "o28" in with_28["text"] and "o28" not in plain["text"]

    # The unit in force sent once more: the engine counts a revision, and the
    # text it runs is the same. The two blocks' hashes are what say so.
    assert same_again["sha256"] == with_28["sha256"]
    # The first unit sent once more: its `7` is back in force, while the stored
    # units, which hold each text once, are what they were. Only the rule
    # history in order, which the journal keeps, gives the right answer.
    assert "{ 7 }" in back_to_7["text"] and "{ 3 }" not in back_to_7["text"]
    assert "{ 9 }" in back_to_7["text"] and "o28" in back_to_7["text"]
    assert stored[5] == stored[4] == stored[3]

    # the revision counter of each block's commit record
    counters = [at["spec_revision"] for at in then]
    assert [n - counters[0] for n in counters] == [0, 1, 1, 2, 3, 4]

    # the journal says for each rule transaction what the engine did with it,
    # and agrees with what the node recorded when it applied the block
    for i in (0, 1, 3, 4, 5):
        recorded = db.get_tx_outcome(sent[i]["tx_hash"], heads[i][0])
        (effect,) = [e for e in recorded["rule_effects"] if e["action"] == "accumulated"]
        assert _journal_outcome(sent[i], heads[i][0]) == {
            "source": "committed_journal", "engine_outcome": "ACCEPTED_CHANGED",
            "accepted": True, "taken": True, "spec_revision": counters[i]}
        assert effect["revision"] == {"taken": True, "engine_outcome": "ACCEPTED_CHANGED",
                                      "spec_revision": counters[i]}
    assert _journal_outcome(sent[2], heads[2][0]) is None      # a transfer carries no rule

    # the account's own unit is listed from the block that accumulated it
    numbers = [db.get_block_by_hash(h)["header"]["block_number"] for h, _ in heads]
    before, after = _rules_at(pk, numbers[2]), _rules_at(pk, numbers[3])
    assert before["complete"] and before["application_rules"] == []
    assert [u["since"]["block_number"] for u in after["application_rules"]] == [numbers[3]]
    assert after["application_rules"][0]["since"]["tx_hash"] == sent[3]["tx_hash"]
    assert after["running_spec"]["sha256"] == with_28["sha256"]
    assert before["running_spec"]["sha256"] == plain["sha256"]
    # and the tip, asked for by its number, is the answer of the head
    tip = _rules_at(pk, numbers[5])
    assert tip["running_spec"]["sha256"] == rs.at_head()["sha256"] == back_to_7["sha256"]


def test_a_clause_is_read_at_the_block_it_held(authority):
    """An o5 clause registered, replaced and revoked in three blocks: each block
    answers with the clause it held, and the tip with what is in force now."""
    import db
    sk, pk = _sender("clause")
    limit = "always ( (i1[t]:bv[24] > { #x0000fa }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    stricter = limit.replace("#x0000fa", "#x000064")
    neutral = "always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) )."
    numbers, sent = [], []
    for seq, rule in enumerate((limit, stricter, neutral)):
        queued = _submit(sk, pk, {"0": rule}, seq=seq)
        assert queued.get("ok"), queued
        _mine()
        sent.append(queued)
        numbers.append(db.get_block_by_hash(
            chain_state._canonical_head_hash)["header"]["block_number"])

    held = [_rules_at(pk, n) for n in numbers]
    assert all(answer["complete"] for answer in held)
    (first,), (second,) = held[0]["clauses"], held[1]["clauses"]
    assert "#x0000fa" in first["body"] and "#x000064" in second["body"]
    assert first["sha256"] == _sha(first["body"]) != second["sha256"]
    assert first["since"] == {"block_number": numbers[0], "tx_hash": sent[0]["tx_hash"]}
    assert second["since"] == {"block_number": numbers[1], "tx_hash": sent[1]["tx_hash"]}
    assert held[2]["clauses"] == []                       # revoked in the third
    assert [row["action"] for row in held[2]["history"]] == ["revoked", "replaced", "registered"]
    assert [row["action"] for row in held[0]["history"]] == ["registered"]
    # a clause is kept in the registry, not in the engine's specification
    assert _journal_outcome(sent[0], db.canonical_chain()[numbers[0]]) is None
