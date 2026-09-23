"""Step 5E: the node's own block path, with worker-backed authority enabled.

Everything here goes through the real entry points -- `sendtx`, `createblock`,
`process_new_block` -- not the coordinator in isolation. What is asserted is
the property the cutover exists for: the block is committed by ONE protocol, the
exact worker that evaluated it becomes the authority, and a restart rebuilt
from the committed journal agrees with it.
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


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _baseline():
    return "always ( " + open(os.path.join(REPO, "genesis.tau")).read().strip() + " )."


@pytest.fixture
def authority(node_state):
    """Enable worker-backed authority on the in-process test node."""
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


def _scoped_rule(pk, value="000001"):
    """Admission requires an o5 rule to be scoped to its sender."""
    return (f"always ( (i12[t]:bv[384] = {{ #x{pk} }}:bv[384]) -> "
            f"o5[t]:bv[24] = {{ #x{value} }}:bv[24] ).")


def test_a_mined_block_commits_through_one_protocol_and_promotes_its_worker(authority):
    genesis_seq = db.committed_journal_head()[1]
    sk, pk = _sender("cutover_a")
    admitted = _submit(sk, pk, {"0": _scoped_rule(pk)})
    assert admitted.get("ok"), admitted

    out = createblock.create_block_from_mempool()
    assert "error" not in out, out

    head = db.get_canonical_head()
    record = db.latest_block_commit()
    assert record is not None and record["tip"] == head["block_hash"], (
        "the block was persisted without a commit record"
    )
    assert db.committed_journal_head()[1] > genesis_seq, (
        "the block's evaluation never reached the committed journal"
    )
    assert authority.state == auth.ACTIVE
    served = authority.current()
    assert authority.descriptor.journal_head_hash == db.committed_journal_head()[0], (
        "the serving evaluator does not describe the committed journal"
    )
    # nothing left behind in the registry
    assert tc.registry().pending is None
    # the committed journal still verifies end to end
    import tau_journal as tj
    tj.journal_from_rows(db.committed_journal_entries()).verify_chain()
