"""A node at 254 interned ids grows its shrink width by a re-exec.

Block 1 commits a rule that interns its recipient stream. Block 2 transfers to a
new address, which needs the id 255. The width is node-local, so the block must
give the same state hash on a node at 10 ids and on a node at 254 ids.
"""
import hashlib
import json
import os
import threading
import time

import pytest
from py_ecc.bls import G2Basic as bls
from unittest.mock import patch

import block as block_module
import chain_state
import config
import db
import tau_authority as auth
import tau_commit as tc
import tau_manager
import tau_shrink
from block import Block
from commands import createblock, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.engine import TauConsensusEngine
from consensus.governance import ConsensusLifecycleManager

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RECIPIENT = bls.SkToPk(bls.KeyGen(b"swc_recipient_one_padding_32bytes")).hex()


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = [
    pytest.mark.skipif(not _native_available(), reason="native tau module not built"),
    pytest.mark.usefixtures("allow_history_rules"),
]


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _baseline():
    with open(os.path.join(REPO, "genesis.tau")) as fh:
        return "always ( " + fh.read().strip() + " )."


@pytest.fixture(autouse=True)
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True):
        yield


@pytest.fixture
def reexec(node_state, monkeypatch):
    """The real re-exec handler. Each call records the minimum width it passes on."""
    calls = []

    def _execv(path, argv):
        calls.append(os.environ.get(tau_shrink.MIN_WIDTH_ENV))
        # The process is gone here. Unwind with the overflow, as test mode does.
        raise

    monkeypatch.setattr(tau_manager, "tau_test_mode", False)
    monkeypatch.delenv("TAU_NO_WIDTH_REEXEC", raising=False)
    monkeypatch.delenv(tau_shrink.MIN_WIDTH_ENV, raising=False)
    monkeypatch.setattr(os, "execv", _execv)
    monkeypatch.setattr(createblock, "_deferred", {})
    yield calls
    # The handler writes os.environ itself, so monkeypatch cannot undo it.
    os.environ.pop(tau_shrink.MIN_WIDTH_ENV, None)
    tc.registry().discard()
    auth.reset(None)
    tau_shrink.reset_shrink_width()


def _genesis_sender(tag="swc_sender", balance=1_000_000):
    sk = bls.KeyGen(tag.encode())
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = balance
    chain_state._genesis_accounts_state[pk] = balance
    chain_state._sequence_numbers.setdefault(pk, 0)
    return sk, pk


def _fill(target):
    i = 0
    while db.get_max_shrink_id() < target:
        db.get_shrink_id(f"bv384:{0xdead0000 + i:096x}")
        i += 1


def _process():
    """What a fresh process does: pick the width once, then build the authority."""
    tau_shrink.reset_shrink_width()
    width = tau_shrink.set_shrink_width_from_db()
    createblock._deferred.clear()
    owner = auth.AuthoritativeTauOwner(ready=threading.Event(), program_baseline=_baseline())
    auth.reset(owner)
    tc.registry().discard()
    owner.initialize(cwd=REPO, env=_env())
    return width


def _start(fill_to):
    sk, pk = _genesis_sender()
    _fill(fill_to)
    return sk, pk, _process()


def _switch_node(tmp_path, name):
    """A second node in the same test: its own DB, the same genesis."""
    tc.registry().discard()
    auth.reset(None)
    db._db_conn.close()
    config.set_database_path(str(tmp_path / f"{name}.sqlite"))
    db._db_conn = None
    db.init_db()
    db.clear_mempool()
    chain_state._balances = {}
    chain_state._sequence_numbers = {}
    chain_state._application_rules_state = ""
    chain_state._lifecycle_manager = ConsensusLifecycleManager()
    chain_state.load_genesis("data/genesis.json")
    chain_state._lifecycle_manager = ConsensusLifecycleManager()


def _tx(sk, pk, ops, seq):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": ops, "fee_limit": "100000"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return tx


def _submit(tx):
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _queue_unchecked(tx):
    tx_hash = block_module.compute_tx_hash(tx)
    db.add_mempool_tx(json.dumps(tx), tx_hash, int(time.time() * 1000), fee_limit=100000)
    return tx_hash


def _rule(pk):
    # i4 in equality with a literal makes the recipient an interned stream.
    return (f"always ( ((i12[t]:bv[384] = {{ #x{pk} }}:bv[384]) && "
            f"(i4[t]:bv[384] = {{ #x{pk} }}:bv[384])) ? "
            f"(o8[t]:bv[24] = {{ #x000002 }}:bv[24]) : "
            f"(o8[t]:bv[24] = {{ #x000001 }}:bv[24]) ).")


def _transfer(sk, pk, amount):
    return _tx(sk, pk, {"1": [[pk, RECIPIENT, str(amount)]]}, 1)


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return db.get_canonical_head()


def _head():
    head = db.get_canonical_head() or {}
    header = head.get("header") or {}
    return {"number": header.get("block_number"), "state_hash": header.get("state_hash"),
            "hash": head.get("block_hash")}


def _rule_block(sk, pk):
    admitted = _submit(_tx(sk, pk, {"0": _rule(pk)}, 0))
    assert admitted.get("ok"), admitted
    return _mine()


def test_a_node_at_254_ids_reaches_the_state_hash_of_a_node_at_10_ids(reexec, tmp_path):
    sk, pk, width = _start(10)
    assert width == 8
    b1 = _rule_block(sk, pk)
    admitted = _submit(_transfer(sk, pk, 5))
    assert admitted.get("ok"), admitted
    b2 = _mine()
    assert len(b2["transactions"]) == 1
    reference = _head()

    _switch_node(tmp_path, "at_254")
    _genesis_sender()
    _fill(253)
    assert _process() == 8
    assert chain_state.process_new_block(Block.from_dict(b1)) is True
    assert db.get_max_shrink_id() == 254

    # The id 255 does not fit bv[8]. The re-exec asks for bv[16].
    assert chain_state.process_new_block(Block.from_dict(b2)) is False
    assert reexec == ["16"]
    assert _head()["number"] == 1

    assert _process() == 16
    assert chain_state.process_new_block(Block.from_dict(b2)) is True
    assert _head() == reference
    assert chain_state._balances.get(RECIPIENT) == 5


def test_admission_and_proposal_at_254_ids_grow_the_width(reexec):
    sk, pk, width = _start(253)
    assert width == 8
    _rule_block(sk, pk)
    assert db.get_max_shrink_id() == 254
    tx = _transfer(sk, pk, 3)

    out = _submit(tx)
    assert out.get("code") == "ADMISSION_UNAVAILABLE", out
    assert reexec == ["16"]

    # The proposer holds the transfer back, and never rejects it.
    tx_hash = _queue_unchecked(tx)
    out = createblock.create_block_from_mempool()
    assert "error" in out, out
    assert reexec == ["16", "16"]
    assert tx_hash in createblock._deferred
    assert _head()["number"] == 1

    # The re-exec'd process mines the held transfer in its next round.
    assert _process() == 16
    b2 = _mine()
    assert [block_module.compute_tx_hash(t) for t in b2["transactions"]] == [tx_hash]
    assert chain_state._balances.get(RECIPIENT) == 3


def test_a_restart_at_254_ids_starts_wide_and_admits_a_new_address(reexec):
    sk, pk, _ = _start(253)
    _rule_block(sk, pk)
    assert db.get_max_shrink_id() == 254

    assert _process() == 16
    admitted = _submit(_transfer(sk, pk, 3))
    assert admitted.get("ok"), admitted
    b2 = _mine()
    assert len(b2["transactions"]) == 1
    assert chain_state._balances.get(RECIPIENT) == 3
    assert reexec == []
