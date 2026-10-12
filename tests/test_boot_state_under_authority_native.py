"""Boot order under worker-backed authority.

`initialize_persistent_state` runs before the authority can judge the chain, so
it must not rebuild or write canonical state: a disagreement between the head
key and its block row fails closed and leaves every committed row as found.
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
import tau_manager
from commands import createblock, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.engine import TauConsensusEngine

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GENESIS = "data/genesis.json"


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
    """Two committed blocks under worker-backed authority."""
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

    (sk_a, pk_a), (sk_b, pk_b) = [_genesis_sender("boot_a"), _genesis_sender("boot_b")]
    assert _submit(sk_a, pk_a, {"0": HISTORY_RULE}).get("ok")
    _mine()
    assert _submit(sk_b, pk_b, {"1": [[pk_b, "aa" * 48, "4"]]}).get("ok")
    _mine()
    # A production chain always has validators persisted; without them boot under
    # authority refuses, which is not what the other cases are testing.
    with open(os.path.join(REPO, GENESIS), encoding="utf-8") as f:
        validators = json.load(f)["consensus_meta"]["active_validators"]
    db.set_chain_state_value("active_validators", json.dumps(validators))
    head = db.get_canonical_head()
    yield {"head": head["block_hash"], "parent": head["header"]["previous_hash"]}
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


def _committed():
    """Every canonical row, the journal and the commit records."""
    with db._db_lock:
        state = db._db_conn.execute(
            "SELECT key, value FROM chain_state ORDER BY key").fetchall()
        accounts = db._db_conn.execute("SELECT * FROM accounts ORDER BY 1").fetchall()
        commits = db._db_conn.execute(
            "SELECT execution_id, tip, journal_head, allocator_digest, plan_id "
            "FROM block_commits_v1 ORDER BY rowid").fetchall()
    return json.dumps({"state": [list(r) for r in state],
                       "accounts": [list(r) for r in accounts],
                       "journal": db.committed_journal_entries(),
                       "commits": [list(r) for r in commits]},
                      sort_keys=True, default=str)


def _exec(sql, *args):
    with db._db_lock:
        db._db_conn.execute(sql, args)
        db._db_conn.commit()


@pytest.fixture
def fresh_process(monkeypatch):
    """No authority enabled, no interpreter, nothing in memory."""
    auth.reset(_owner())
    monkeypatch.setattr(tau_manager, "tau_direct_interface", None)
    was_ready = tau_manager.tau_ready.is_set()
    tau_manager.tau_ready.clear()
    monkeypatch.setattr(chain_state, "_balances", {})
    monkeypatch.setattr(chain_state, "_sequence_numbers", {})
    monkeypatch.setattr(chain_state, "_canonical_head_hash", "")
    yield
    if was_ready:
        tau_manager.tau_ready.set()


def _boot_state():
    with patch.object(chain_state, "_rebuild_state_from_blockchain_internal",
                      side_effect=AssertionError("rebuilt ahead of the authority")), \
         patch.object(chain_state, "commit_state_to_db",
                      side_effect=AssertionError("wrote canonical state")):
        chain_state.initialize_persistent_state(GENESIS, authority=True)


def _boot_authority():
    owner = _owner()
    auth.reset(owner)
    owner.initialize(cwd=REPO, env=_env())
    return owner


def test_a_consistent_chain_boots_and_the_authority_accepts_it(chain, fresh_process):
    chain_state.initialize_persistent_state(GENESIS, authority=True)
    assert chain_state._canonical_head_hash == chain["head"]
    owner = _boot_authority()
    try:
        assert owner.active
        assert db.latest_block_commit()["tip"] == chain["head"]
    finally:
        owner.dispose()


def test_a_head_row_naming_another_block_fails_closed(chain, fresh_process):
    row = db.get_block_by_hash(chain["head"])
    row["block_hash"] = chain["parent"]
    _exec("UPDATE blocks SET block_data = ? WHERE block_hash = ?",
          json.dumps(row), chain["head"])
    before = _committed()
    with pytest.raises(ValueError, match="FATAL: Canonical head .* disagrees"):
        _boot_state()
    assert _committed() == before, "a refused boot changed the committed rows"


@pytest.mark.parametrize("keep_accounts", [True, False])
def test_a_missing_head_key_is_not_a_fresh_chain(chain, fresh_process, keep_accounts):
    _exec("DELETE FROM chain_state WHERE key = 'canonical_head_hash'")
    if not keep_accounts:
        _exec("DELETE FROM accounts")
    before = _committed()
    with pytest.raises(ValueError, match="FATAL: Canonical head is missing or unreadable"):
        _boot_state()
    assert _committed() == before, "a refused boot changed the committed rows"


def test_a_head_key_behind_the_tip_is_left_to_the_authority(chain, fresh_process):
    _exec("UPDATE chain_state SET value = ? WHERE key = 'canonical_head_hash'",
          chain["parent"])
    before = _committed()
    _boot_state()
    assert _committed() == before
    owner = _owner()
    auth.reset(owner)
    with pytest.raises(auth.AuthorityMismatch):
        owner.initialize(cwd=REPO, env=_env())
    assert owner.state == auth.UNAVAILABLE and not owner.active
    assert _committed() == before, "a refused authority changed the committed rows"


@pytest.mark.parametrize("damage", ["deleted", "malformed"])
def test_a_damaged_validator_row_refuses_boot_before_the_authority_starts(
        chain, fresh_process, damage):
    if damage == "deleted":
        _exec("DELETE FROM chain_state WHERE key = 'active_validators'")
    else:
        _exec("UPDATE chain_state SET value = ? WHERE key = 'active_validators'",
              "{not json")
    before = _committed()
    with patch.object(auth.AuthoritativeTauOwner, "initialize",
                      side_effect=AssertionError("authority started after a refused boot")) as init:
        with pytest.raises(ValueError, match="FATAL: Persisted active validator set"):
            _boot_state()
            _boot_authority()
    assert not init.called
    assert _committed() == before, "a refused boot changed the committed rows"
