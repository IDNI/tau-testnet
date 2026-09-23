"""While the authority is LENT, nothing else reaches it.

The authoritative worker goes to the next block's proposal instead of being
rebuilt. For as long as it is out, every other path must get "unavailable" or a
worker of its own -- never the lent one -- and when two candidate blocks share a
parent, only the artifact bound to the block that actually commits may commit.
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
import tau_admission
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

HISTORY_RULE = "always ( o12[t]:bv[24] = i1[t-1]:bv[24] )."


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
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    tc.registry().discard()
    tau_admission.reset()
    auth.reset(None)


@pytest.fixture(autouse=True)
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True):
        yield


def _sender(tag):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = 1_000_000
    return sk, pk


def _submit(sk, pk, ops, seq=0):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": ops, "fee_limit": "100000"}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return sendtx.queue_transaction(json.dumps(tx), propagate=False)


def _requests(session) -> int:
    """How many requests a worker has ever been sent."""
    return session._spec._next_id


def _hold_candidate():
    """Build candidate A the way the miner does, and stop before it is
    processed: its artifact stays in the registry, holding the lent worker."""
    captured = {}

    def _held(block):
        captured["block"] = block
        return True

    with patch.object(chain_state, "process_new_block", _held):
        out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    key = tc.registry().pending
    assert key is not None, "the miner left no artifact"
    prepared, proposal = tc.registry()._entry
    return captured["block"], key, prepared, proposal


def test_while_lent_every_other_path_is_refused_or_gets_a_worker_of_its_own(authority):
    sk, pk = _sender("lend_a")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")
    served = authority.current()
    _, _, _, proposal_a = _hold_candidate()

    assert authority.state == auth.LENT
    lent = proposal_a.session
    assert lent is served, "candidate A did not run on the lent authority"
    seen = _requests(lent)

    # the owner refuses to hand it out
    with pytest.raises(auth.AuthorityUnavailable):
        authority.current()
    # a second proposal off the same committed state gets its own worker
    other = authority.build_proposal(label="candidate-b")
    try:
        assert other.session is not lent
        assert authority.state == auth.LENT
    finally:
        other.dispose()
    # admission answers from a context of its own
    sk_b, pk_b = _sender("lend_b")
    assert _submit(sk_b, pk_b, {"1": [[pk_b, "aa" * 48, "3"]]}).get("ok")

    assert _requests(lent) == seen, (
        "something other than candidate A's proposal stepped the lent worker"
    )


def test_two_candidates_off_one_parent_only_the_bound_artifact_commits(authority):
    """Both candidates in the SAME second: the shape that made two different
    blocks share one execution id while transactions were identified by a label
    the persisted block does not carry."""
    import types
    parent = db.get_canonical_head()["block_hash"]
    moment = int(time.time()) + 1
    same_second = types.SimpleNamespace(time=lambda: moment, sleep=time.sleep,
                                        monotonic=time.monotonic)
    sk, pk = _sender("fork_a")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")
    with patch.object(createblock, "time", same_second):
        block_a, key_a, prepared_a, proposal_a = _hold_candidate()
    lent = proposal_a.session
    seen = _requests(lent)
    assert block_a.header.previous_hash == parent

    # Candidate B: same parent, different content, and NO local artifact -- the
    # shape of a block that arrives from a peer while A is still pending.
    sk_b, pk_b = _sender("fork_b")
    assert _submit(sk_b, pk_b, {"1": [[pk_b, "aa" * 48, "3"]]}).get("ok")
    evaluated = {}
    real_freeze = tc.PreparedBlockCommit.freeze.__func__

    def _no_offer(self, key, prepared, proposal):
        proposal.dispose()      # this node never built B

    def _capture(cls, proposal, **kw):
        evaluated.setdefault("workers", []).append(proposal.session)
        return real_freeze(cls, proposal, **kw)

    with patch.object(tc.ProposalRegistry, "offer", _no_offer), \
         patch.object(tc.PreparedBlockCommit, "freeze", classmethod(_capture)), \
         patch.object(createblock, "time", same_second):
        out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    assert out["header"]["timestamp"] == block_a.header.timestamp == moment

    head = db.get_canonical_head()
    assert head["block_hash"] != block_a.block_hash, "A committed without being processed"
    assert db.get_block_by_hash(head["block_hash"])["header"]["previous_hash"] == parent
    record = db.latest_block_commit()
    assert record["tip"] == head["block_hash"] and record["execution_id"] != key_a, (
        "the commit record names candidate A's execution"
    )
    assert db.find_block_commit(key_a) is None, "A's artifact committed for B"

    # B was evaluated in its own proposal, never on the lent worker, and that
    # worker is what the node now serves
    assert authority.state == auth.ACTIVE
    served = authority.current()
    assert served is not lent
    assert served in evaluated["workers"]
    assert _requests(lent) == seen, "B's processing stepped the lent worker"

    # A's artifact is still pending, bound to A -- and stale: its gate refuses
    # it against the state B committed
    assert tc.registry().pending == key_a
    prepared, proposal = tc.registry().claim(key_a)
    with pytest.raises(Exception):
        prepared.verify(proposal=proposal, execution_id=key_a)
    proposal.dispose()
    # returning the lent worker after the fact changes nothing
    assert authority.state == auth.ACTIVE and authority.current() is served
    assert lent._spec._proc.poll() is not None, "the stale candidate's worker leaked"


def test_a_stale_loan_returned_late_does_not_take_the_authority_out_of_service(authority):
    """Candidate A borrowed the authority and was left pending; B committed on a
    worker of its own and became the authority; the NEXT proposal borrowed
    that. Disposing A's leftover proposal then marked the authority unavailable
    -- A no longer held anything the owner was lending."""
    sk, pk = _sender("late_a")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")
    _hold_candidate()                                    # A: pending, lent
    sk_b, pk_b = _sender("late_b")
    assert _submit(sk_b, pk_b, {"1": [[pk_b, "aa" * 48, "3"]]}).get("ok")
    with patch.object(tc.ProposalRegistry, "offer",
                      lambda self, key, prepared, proposal: proposal.dispose()):
        out = createblock.create_block_from_mempool()    # B: its own worker
    assert "error" not in out, out
    assert authority.state == auth.ACTIVE

    current = authority.build_proposal(label="next")     # borrows B's worker
    assert authority.state == auth.LENT
    try:
        tc.registry().discard()                          # A's leftover goes now
        assert authority.state == auth.LENT, (
            f"a stale loan's disposal took the authority out of service: "
            f"{authority.state} ({authority.reason})"
        )
    finally:
        current.dispose()
    # the CURRENT borrower's abandonment still does
    assert authority.state == auth.UNAVAILABLE


# --- a block received from a peer --------------------------------------------------

def test_a_received_extension_is_committed_not_rebuilt(authority):
    """Every block a peer sends reaches chain_state through ingestion and fork
    choice. For a block that simply extends the head, that meant a full rebuild
    from genesis -- the committed journal reset and derived again, per block.
    It is committed now the way a locally built block is, and only a real fork
    rebuilds."""
    from network.service import NetworkService

    sk, pk = _sender("received")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")
    block, _, _, _ = _hold_candidate()
    tc.registry().discard()                  # the receiving node built nothing
    journal_before = db.committed_journal_entries()
    served_before = authority.state

    with patch.object(chain_state, "_rebuild_state_from_blockchain_internal",
                      side_effect=AssertionError("an extension was rebuilt")):
        ingested = NetworkService._ingest_blocks([block.to_dict()], "peer-x")
    assert ingested == 1
    head = db.get_canonical_head()
    assert head["block_hash"] == block.block_hash, "the received block did not commit"
    assert db.latest_block_commit()["tip"] == block.block_hash
    after = db.committed_journal_entries()
    assert after[:len(journal_before)] == journal_before, (
        "the committed journal was rewritten, not extended"
    )
    assert len(after) > len(journal_before)
    assert authority.state == auth.ACTIVE and served_before == auth.UNAVAILABLE, (
        authority.state, served_before)
