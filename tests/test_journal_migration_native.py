"""`TAU_REBUILD_JOURNAL` in every state the committed metadata can be in.

    old chain + no journal            -> =1 rebuilds it from the stored blocks
    complete, consistent journal      -> nothing destructive, whatever the flag
    partial or contradictory journal  -> fail closed; only =discard, a separate
                                         explicit request, replaces it

A contradiction is never repaired implicitly: nothing at startup can know which
of two disagreeing records the chain believes.
"""
import hashlib
import json
import os
import threading
import time

import pytest
from py_ecc.bls import G2Basic as bls
from unittest.mock import patch

import chain_state
import db
import tau_authority as auth
import tau_commit as tc
import tau_journal as tj
from commands import createblock, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _native_available(),
                                reason="native tau module not built")

HISTORY_RULE = "always ( o12[t]:bv[24] = i1[t-1]:bv[24] )."
CONTINUATION = ("#x000011", "#x000022", "#x000033")


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _baseline():
    return "always ( " + open(os.path.join(REPO, "genesis.tau")).read().strip() + " )."


def _owner():
    return auth.AuthoritativeTauOwner(ready=threading.Event(), program_baseline=_baseline())


@pytest.fixture(autouse=True)
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True):
        yield


@pytest.fixture
def chain(node_state, monkeypatch):
    """Two committed blocks, built so that replaying them reproduces them: every
    sender is a genesis account, and the genesis globals describe the genesis
    this chain actually started from."""
    monkeypatch.setattr(chain_state, "_genesis_accounts_state",
                        dict(chain_state._genesis_accounts_state))
    empty = chain_state._lifecycle_manager
    monkeypatch.setattr(chain_state, "_genesis_active_validators",
                        list(empty.active_validators))
    monkeypatch.setattr(chain_state, "_genesis_vote_quorum", empty.quorum_policy)
    monkeypatch.setattr(chain_state, "_genesis_eligibility_mode", empty.eligibility_mode)
    monkeypatch.setattr(chain_state, "_genesis_fee_beneficiary", empty.fee_beneficiary)

    owner = _owner()
    auth.reset(owner)
    tc.registry().discard()
    owner.initialize(cwd=REPO, env=_env())

    senders = [_genesis_sender("migrate_a"), _genesis_sender("migrate_b")]
    (sk_a, pk_a), (sk_b, pk_b) = senders
    assert _submit(sk_a, pk_a, {"0": HISTORY_RULE}).get("ok")
    _mine()
    assert _submit(sk_b, pk_b, {"1": [[pk_b, "aa" * 48, "4"]]}).get("ok")
    _mine()
    yield {"owner": owner, "continuation": _continue(owner.current()),
           "head": db.get_canonical_head()["block_hash"]}
    tc.registry().discard()
    auth.reset(None)


def _genesis_sender(tag, balance=1_000_000):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = balance
    chain_state._genesis_accounts_state[pk] = balance
    chain_state._sequence_numbers.setdefault(pk, 0)
    return sk, pk


def _submit(sk, pk, ops, seq=0):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": ops, "fee_limit": "100000"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out


def _continue(session):
    series = [session.evaluate({1: "{ %s }:bv[24]" % v}, multi=True, record=False)
              for v in CONTINUATION]
    out = [step.get(12) for step in series]
    assert any(v is not None for v in out), series
    return out


def _metadata():
    """Everything a rebuild would replace, to prove it was not replaced."""
    with db._db_lock:
        commits = db._db_conn.execute(
            "SELECT execution_id, tip, journal_head, allocator_digest, plan_id "
            "FROM block_commits_v1 ORDER BY rowid").fetchall()
    return json.dumps({"journal": db.committed_journal_entries(),
                       "commits": [list(r) for r in commits]}, sort_keys=True,
                      default=str)


def _start(mode, **patches):
    owner = _owner()
    auth.reset(owner)
    return owner, owner.initialize(cwd=REPO, env=_env(), rebuild=mode)


def _refuses(mode, *, match):
    before = _metadata()
    owner = _owner()
    auth.reset(owner)
    with patch.object(auth.AuthoritativeTauOwner, "_rebuild_journal",
                      side_effect=AssertionError("rebuilt without being asked")):
        with pytest.raises(auth.AuthorityMismatch, match=match):
            owner.initialize(cwd=REPO, env=_env(), rebuild=mode)
    assert owner.state == auth.UNAVAILABLE and not owner.active
    assert _metadata() == before, "a refused start changed the committed metadata"
    return owner


def _consistent(chain, owner):
    assert db.get_canonical_head()["block_hash"] == chain["head"]
    assert db.latest_block_commit()["tip"] == chain["head"]
    tj.journal_from_rows(db.committed_journal_entries()).verify_chain()
    owner.verify_committed_anchors()
    assert _continue(owner.current()) == chain["continuation"], (
        "the rebuilt evaluator does not continue the way the original did"
    )


# --- state 1: a chain from before the journal ----------------------------------

def test_a_chain_without_a_journal_is_rebuilt_only_when_asked(chain):
    db.reset_committed_journal()
    _refuses(None, match="TAU_REBUILD_JOURNAL=1")
    owner, _ = _start(auth.REBUILD_MISSING)
    try:
        _consistent(chain, owner)
    finally:
        owner.dispose()


# --- state 2: complete and consistent -------------------------------------------

@pytest.mark.parametrize("mode", [None, auth.REBUILD_MISSING, auth.REBUILD_DISCARD])
def test_a_complete_journal_is_never_rebuilt(chain, mode):
    before = _metadata()
    owner = _owner()
    auth.reset(owner)
    with patch.object(auth.AuthoritativeTauOwner, "_rebuild_journal",
                      side_effect=AssertionError("a complete journal was rebuilt")):
        owner.initialize(cwd=REPO, env=_env(), rebuild=mode)
    try:
        assert _metadata() == before, "starting changed a consistent journal"
        _consistent(chain, owner)
    finally:
        owner.dispose()


# --- state 3: partial or contradictory ------------------------------------------

def _drop_commit_records():
    with db._db_lock:
        db._db_conn.execute("DELETE FROM block_commits_v1")
        db._db_conn.commit()


def _drop_last_block():
    """The journal and the records cover block 1; the tip is block 2."""
    last = db.latest_block_commit()
    with db._db_lock:
        db._db_conn.execute("DELETE FROM tau_journal_v1 WHERE tip = ?", (last["tip"],))
        db._db_conn.execute("DELETE FROM block_commits_v1 WHERE execution_id = ?",
                            (last["execution_id"],))
        db._db_conn.commit()


def _misname_head():
    with db._db_lock:
        db._db_conn.execute(
            "UPDATE block_commits_v1 SET journal_head = 'elsewhere' WHERE rowid = "
            "(SELECT MAX(rowid) FROM block_commits_v1)")
        db._db_conn.commit()


def _break_chain():
    with db._db_lock:
        db._db_conn.execute(
            "UPDATE tau_journal_v1 SET prev = 'tampered' WHERE seq = "
            "(SELECT MAX(seq) - 1 FROM tau_journal_v1)")
        db._db_conn.commit()


def _falsify_a_result():
    """A step the journal says produced something else: the rows still chain,
    the records still agree -- only replay can tell."""
    rows = db.committed_journal_entries()
    victim = [r for r in rows if r["kind"] == tj.STEP][-1]
    with db._db_lock:
        db._db_conn.execute("UPDATE tau_journal_v1 SET result_fp = ? WHERE seq = ?",
                            ("0" * 16, victim["seq"]))
        db._db_conn.commit()


CONTRADICTIONS = {
    "a journal no record describes": (_drop_commit_records, "no commit record"),
    "a journal that stops short of the tip": (_drop_last_block, "committed tip"),
    "a record naming another head": (_misname_head, "journal head"),
    "a broken chain": (_break_chain, "does not reconstruct|corrupt"),
    "a journal that does not replay to itself": (_falsify_a_result, "does not reconstruct"),
}


@pytest.mark.parametrize("case", sorted(CONTRADICTIONS))
def test_a_contradiction_fails_closed_even_with_the_migration_flag(chain, case):
    damage, match = CONTRADICTIONS[case]
    damage()
    _refuses(None, match=match)
    refused = _refuses(auth.REBUILD_MISSING, match=match)
    assert "TAU_REBUILD_JOURNAL=discard" in (refused.reason or ""), (
        "the refusal does not name the explicit repair path"
    )


@pytest.mark.parametrize("case", sorted(CONTRADICTIONS))
def test_only_an_explicit_discard_replaces_a_contradictory_journal(chain, case):
    damage, _ = CONTRADICTIONS[case]
    damage()
    owner, _ = _start(auth.REBUILD_DISCARD)
    try:
        _consistent(chain, owner)
    finally:
        owner.dispose()


def test_an_operational_failure_is_not_offered_as_a_contradiction(chain):
    """A worker that will not start says nothing about the journal. Suggesting
    `discard` for it would invite an operator to throw a sound journal away."""
    import tau_session
    before = _metadata()
    owner = _owner()
    auth.reset(owner)
    with patch.object(tau_session.WorkerSession, "spawn",
                      side_effect=OSError("Resource temporarily unavailable")), \
         patch.object(auth.AuthoritativeTauOwner, "_rebuild_journal",
                      side_effect=AssertionError("rebuilt over a spawn failure")):
        with pytest.raises(OSError):
            owner.initialize(cwd=REPO, env=_env(), rebuild=auth.REBUILD_DISCARD)
    assert "discard" not in (owner.reason or "")
    assert _metadata() == before


# --- the flag itself -------------------------------------------------------------

@pytest.mark.parametrize("value,mode", [
    (None, None), ("", None), ("0", None),
    ("1", auth.REBUILD_MISSING), ("discard", auth.REBUILD_DISCARD),
])
def test_the_flag_is_read_exactly(value, mode):
    assert auth.rebuild_mode_from_env(value) == mode


@pytest.mark.parametrize("value", ["yes", "true", "DISCARD", "2"])
def test_an_unknown_flag_value_is_refused(value):
    with pytest.raises(ValueError):
        auth.rebuild_mode_from_env(value)
