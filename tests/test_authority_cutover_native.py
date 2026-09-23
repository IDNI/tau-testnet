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


def _genesis_sender(tag, balance=1_000_000):
    """A sender funded AS A GENESIS ACCOUNT.

    `_sender` injects a balance straight into the live state, which no block and
    no genesis entry can reproduce -- fine for tests that never replay, fatal for
    one that rebuilds from the stored blocks, where every mined state hash has to
    come out the same the second time.
    """
    sk, pk = _sender(tag, balance)
    chain_state._genesis_accounts_state[pk] = balance
    chain_state._sequence_numbers.setdefault(pk, 0)
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


HISTORY_RULE = "always ( o12[t]:bv[24] = i1[t-1]:bv[24] )."

#: Fed one stream at a time: inputs are requested lazily. o12 = i1[t-1], so the
#: series depends on the evaluator's temporal history, not just its rules.
CONTINUATION = ("#x000011", "#x000022", "#x000033")


def _continue(session):
    series = [session.evaluate({1: "{ %s }:bv[24]" % v}, multi=True, record=False)
              for v in CONTINUATION]
    state = session._spec.state()
    out = {"o12": [step.get(12) for step in series],
           "o1": [step.get(1) for step in series],
           "time_point": state["time_point"],
           "spec_revision": state["spec_revision"]}
    assert any(v is not None for v in out["o12"]), (
        f"the continuation produced no o12 at all -- it would compare as equal "
        f"for two evaluators that both answer nothing: {series}"
    )
    return out


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return db.get_canonical_head()


def _fresh_owner():
    ready = threading.Event()
    return auth.AuthoritativeTauOwner(ready=ready, program_baseline=_baseline()), ready


def _history_block(tag="hist"):
    """One block carrying a history-dependent rule, then some history."""
    sk, pk = _sender(tag)
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")
    _mine()
    return sk, pk


# --- local block: proposal -> atomic commit -> exact worker promotion ----------

def test_the_mined_block_is_served_by_the_worker_that_evaluated_it(authority):
    sk, pk = _sender("exact_worker")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")

    evaluated = {}
    real_freeze = tc.PreparedBlockCommit.freeze.__func__

    def _capture(cls, proposal, **kw):
        evaluated["worker"] = proposal.session
        return real_freeze(cls, proposal, **kw)

    with patch.object(tc.PreparedBlockCommit, "freeze", classmethod(_capture)):
        _mine()

    assert authority.state == auth.ACTIVE
    assert authority.current() is evaluated["worker"], (
        "the authority is not the exact worker that evaluated the block -- it was "
        "rebuilt, which is what promotion exists to avoid"
    )
    record = db.latest_block_commit()
    assert record["tip"] == db.get_canonical_head()["block_hash"]
    assert authority.descriptor.journal_head_hash == db.committed_journal_head()[0]


def test_the_next_block_runs_on_the_lent_authority(authority):
    """Lending is what makes promotion pay off: the next proposal starts on the
    worker that already holds the committed state, with nothing replayed."""
    _history_block("lend_a")
    before = authority.current()
    sk, pk = _sender("lend_b")
    assert _submit(sk, pk, {"1": [[pk, "aa" * 48, "5"]]}).get("ok")

    spawned = []
    import tau_session as ts
    real_spawn = ts.WorkerSession.spawn.__func__

    def _count(cls, *a, **k):
        spawned.append(True)
        return real_spawn(cls, *a, **k)

    with patch.object(ts.WorkerSession, "spawn", classmethod(_count)):
        _mine()

    assert not spawned, (
        f"{len(spawned)} worker(s) were spawned for a block that could have run on "
        "the lent authority"
    )
    assert authority.current() is before, "the lent worker did not come back"


# --- imported block: same protocol --------------------------------------------

def test_a_block_without_a_local_artifact_takes_the_same_protocol(authority):
    """A received block has no artifact. It is evaluated in a proposal built
    from the committed anchor, verified against its own state hash, and
    committed and promoted exactly like a mined one."""
    sk, pk = _sender("imported")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")
    seq_before = db.committed_journal_head()[1]

    # No artifact reaches ingestion: exactly the situation of a received block.
    with patch.object(tc.ProposalRegistry, "offer",
                      lambda self, key, prepared, proposal: proposal.dispose()):
        _mine()

    assert db.committed_journal_head()[1] > seq_before
    assert db.latest_block_commit()["tip"] == db.get_canonical_head()["block_hash"]
    assert authority.state == auth.ACTIVE
    assert authority.descriptor.journal_head_hash == db.committed_journal_head()[0]


# --- restart ------------------------------------------------------------------

def test_a_restart_rebuilds_the_same_evaluator_from_the_journal(authority):
    _history_block("restart_a")
    sk, pk = _sender("restart_b")
    assert _submit(sk, pk, {"1": [[pk, "aa" * 48, "7"]]}).get("ok")
    _mine()

    promoted = authority.current()
    before = promoted._spec.state()

    restarted, ready = _fresh_owner()
    try:
        restarted.initialize(cwd=REPO, env=_env())
        after = restarted.current()._spec.state()
        assert (after["spec_revision"], after["time_point"]) == \
            (before["spec_revision"], before["time_point"]), (
                f"restart reconstructed {after}, the running authority is at {before}"
            )
        assert _continue(restarted.current()) == _continue(promoted), (
            "the restarted evaluator answers the continuation differently"
        )
    finally:
        restarted.dispose()


# --- promotion failure through the real entry point ---------------------------

def test_a_failed_promotion_leaves_the_block_committed_and_nothing_served(authority):
    sk, pk = _sender("promo_fail")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")

    evaluated = {}
    real_freeze = tc.PreparedBlockCommit.freeze.__func__

    def _capture(cls, proposal, **kw):
        prepared = real_freeze(cls, proposal, **kw)
        evaluated["state"] = prepared.worker._spec.state()
        evaluated["worker"] = prepared.worker
        return prepared

    def _die(self, proposal, prepared):
        # Past the durable commit, so stepping the proposal worker here cannot
        # change what was committed; it records what that exact worker answers.
        evaluated["continuation"] = _continue(prepared.worker)
        raise RuntimeError("the worker died between commit and promotion")

    with patch.object(tc.PreparedBlockCommit, "freeze", classmethod(_capture)), \
         patch.object(auth.AuthoritativeTauOwner, "promote", _die):
        _mine()

    # 1-4. the block is durable and named by its commit record
    head = db.get_canonical_head()
    assert db.latest_block_commit()["tip"] == head["block_hash"]
    # 5. nothing is served -- in particular not the superseded evaluator
    assert authority.state == auth.UNAVAILABLE
    with pytest.raises(auth.AuthorityUnavailable):
        authority.current()
    # 6-7. rebuilt from the newly committed journal
    authority.initialize(cwd=REPO, env=_env())
    assert authority.state == auth.ACTIVE
    rebuilt = authority.current()
    assert rebuilt is not evaluated["worker"]
    st = rebuilt._spec.state()
    assert (st["spec_revision"], st["time_point"]) == \
        (evaluated["state"]["spec_revision"], evaluated["state"]["time_point"])
    # 8. and it answers exactly as the proposal worker that computed the block
    assert _continue(rebuilt) == evaluated["continuation"], (
        "the evaluator rebuilt from the committed journal answers differently "
        "from the worker that computed the committed state"
    )


# --- idempotent reprocessing --------------------------------------------------

def test_reprocessing_the_same_block_applies_nothing_twice(authority):
    sk, pk = _sender("idem")
    assert _submit(sk, pk, {"1": [[pk, "aa" * 48, "9"]]}).get("ok")
    _mine()
    head = db.get_canonical_head()
    def _observe():
        return (db.committed_journal_head(), db.get_max_shrink_id(),
                db.shrink_mapping_epoch(), dict(chain_state._balances),
                dict(chain_state._sequence_numbers),
                chain_state._lifecycle_manager.consensus_meta_hash(),
                db.latest_block_commit()["execution_id"],
                authority.descriptor.journal_head_hash)

    snapshot = _observe()

    from block import Block
    chain_state.process_new_block(Block.from_dict(head))

    assert _observe() == snapshot, (
        "reprocessing a committed block changed the journal, the mapping, "
        "balances, sequences, lifecycle state, the commit record or the authority"
    )


# --- no authoritative in-process fallback -------------------------------------

def test_block_production_never_steps_the_in_process_interpreter(authority):
    """Admission may still read the in-process interpreter as an advisory
    mirror. Block evaluation may not touch it at all, except to keep that mirror
    current AFTER the block is committed."""
    import tau_manager

    sk, pk = _sender("no_fallback")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")

    calls = []
    real_single = tau_manager.communicate_with_tau
    real_multi = tau_manager.communicate_with_tau_multi

    def _single(*a, **k):
        calls.append(("single", k.get("source"), k.get("apply_rules_update")))
        return real_single(*a, **k)

    def _multi(*a, **k):
        calls.append(("multi", k.get("source"), k.get("apply_rules_update")))
        return real_multi(*a, **k)

    with patch.object(tau_manager, "communicate_with_tau", _single), \
         patch.object(tau_manager, "communicate_with_tau_multi", _multi):
        _mine()

    offending = [c for c in calls if c[1] != "advisory_mirror"]
    assert not offending, (
        f"block production stepped the in-process interpreter: {offending}"
    )
    assert all(c[2] is False for c in calls), (
        f"the advisory mirror was asked to accumulate canonical state: {calls}"
    )


# --- process death at every point around the irreversible step ----------------

class _Death(BaseException):
    """The process stops here. Not an Exception, so nothing on the way out can
    handle it -- exactly like a kill."""


def _restart():
    """What a restarted node has: the durable state, nothing else."""
    assert chain_state.load_state_from_db() is True
    owner, _ = _fresh_owner()
    owner.initialize(cwd=REPO, env=_env())
    return owner


@pytest.mark.parametrize("point, committed", [
    ("before the commit transaction", False),
    ("inside the commit transaction", False),
    ("right after the commit transaction", True),
    ("after promotion, before returning", True),
])
def test_the_outcome_of_a_crash_is_decided_by_durable_state_alone(
        authority, point, committed):
    _history_block(f"death_seed_{committed}_{point[:6]}")
    pre = authority.current()._spec.state()
    pre_head = db.get_canonical_head()["block_hash"]

    sk, pk = _sender(f"death_{point[:10]}")
    assert _submit(sk, pk, {"1": [[pk, "aa" * 48, "3"]]}).get("ok")

    post = {}
    real_freeze = tc.PreparedBlockCommit.freeze.__func__

    def _capture(cls, proposal, **kw):
        prepared = real_freeze(cls, proposal, **kw)
        post["state"] = prepared.worker._spec.state()
        return prepared

    def _die(*a, **k):
        raise _Death(point)

    targets = {
        "before the commit transaction": ("db.commit_prepared_block", None),
        "inside the commit transaction": ("db._write_canonical_state_rows", None),
        "right after the commit transaction": ("chain_state._swap_in_memory_state", None),
        "after promotion, before returning": ("chain_state._sync_advisory_mirror", None),
    }
    target, _ = targets[point]
    with patch.object(tc.PreparedBlockCommit, "freeze", classmethod(_capture)), \
         patch(target, side_effect=_die):
        with pytest.raises(_Death):
            createblock.create_block_from_mempool()

    restarted = _restart()
    try:
        head = db.get_canonical_head()["block_hash"]
        state = restarted.current()._spec.state()
        if committed:
            assert head != pre_head, f"{point}: the committed block was lost"
            assert db.latest_block_commit()["tip"] == head
            assert (state["spec_revision"], state["time_point"]) == \
                (post["state"]["spec_revision"], post["state"]["time_point"]), (
                    f"{point}: the restart did not reconstruct the committed block"
                )
        else:
            assert head == pre_head, f"{point}: a block that never committed appeared"
            assert (state["spec_revision"], state["time_point"]) == \
                (pre["spec_revision"], pre["time_point"]), (
                    f"{point}: the restart reconstructed a state that was never "
                    f"committed"
                )
        # and the durable anchors agree with each other either way
        restarted.verify_committed_anchors()
    finally:
        restarted.dispose()


# --- rebuild: the one migration ------------------------------------------------

def test_a_lost_journal_is_rebuilt_from_the_stored_blocks(authority, monkeypatch):
    """Every stored block is re-evaluated through the commit protocol; each must
    reproduce the state hash it was mined with, and the evaluator at the end
    must be the one the node had."""
    monkeypatch.setattr(chain_state, "_genesis_accounts_state",
                        dict(chain_state._genesis_accounts_state))
    # node_state replaces the genesis lifecycle with an EMPTY one after loading
    # genesis, so its dummy miner passes the PoA gate. A rebuild reseeds from the
    # genesis globals, so they must describe the genesis this chain actually
    # started from -- otherwise the meta hash differs at block 1, and so does
    # where fees are credited, for reasons that have nothing to do with replay.
    empty = chain_state._lifecycle_manager
    monkeypatch.setattr(chain_state, "_genesis_active_validators",
                        list(empty.active_validators))
    monkeypatch.setattr(chain_state, "_genesis_vote_quorum", empty.quorum_policy)
    monkeypatch.setattr(chain_state, "_genesis_eligibility_mode", empty.eligibility_mode)
    monkeypatch.setattr(chain_state, "_genesis_fee_beneficiary", empty.fee_beneficiary)
    # Both funded before the first block: a genesis account that appears after
    # block 1 is a balance injected mid-chain, which is exactly what a rebuild
    # cannot reproduce.
    sk_a, pk_a = _genesis_sender("rebuild_a")
    sk, pk = _genesis_sender("rebuild_b")
    assert _submit(sk_a, pk_a, {"0": HISTORY_RULE}).get("ok")
    _mine()
    assert _submit(sk, pk, {"1": [[pk, "aa" * 48, "4"]]}).get("ok")
    _mine()
    before = authority.current()._spec.state()
    head_before = db.get_canonical_head()["block_hash"]
    continuation_before = _continue(authority.current())

    db.reset_committed_journal()

    fresh, _ = _fresh_owner()
    with pytest.raises(auth.AuthorityMismatch, match="TAU_REBUILD_JOURNAL"):
        fresh.initialize(cwd=REPO, env=_env())

    rebuilt, _ = _fresh_owner()
    auth.reset(rebuilt)
    rebuilt.initialize(cwd=REPO, env=_env(), rebuild_if_needed=True)
    try:
        assert db.get_canonical_head()["block_hash"] == head_before
        assert db.latest_block_commit()["tip"] == head_before
        state = rebuilt.current()._spec.state()
        assert (state["spec_revision"], state["time_point"]) == \
            (before["spec_revision"], before["time_point"]), (
                f"the rebuilt evaluator is at {state}, the original was at {before}"
            )
        assert _continue(rebuilt.current()) == continuation_before
    finally:
        rebuilt.dispose()



# --- stale artifact -----------------------------------------------------------

def test_an_artifact_for_a_different_block_is_never_reused(authority):
    """An artifact offered for one execution must not be committed for another,
    and its worker must not be partially reused: the block is evaluated in a
    proposal of its own, and the stale artifact is left for its own execution
    (and disposed by the next offer)."""
    sk, pk = _sender("stale_art")
    assert _submit(sk, pk, {"0": HISTORY_RULE}).get("ok")

    offered = {}
    real_offer = tc.ProposalRegistry.offer

    def _mislabel(self, key, prepared, proposal):
        # the artifact arrives keyed to some OTHER execution
        offered["worker"] = prepared.worker
        return real_offer(self, "not-this-block", prepared, proposal)

    with patch.object(tc.ProposalRegistry, "offer", _mislabel):
        _mine()

    head = db.get_canonical_head()
    assert db.latest_block_commit()["tip"] == head["block_hash"]
    assert authority.state == auth.ACTIVE
    assert authority.current() is not offered["worker"], (
        "the stale artifact's worker was promoted for a block it did not describe"
    )
    assert tc.registry().pending == "not-this-block", (
        "the stale artifact was consumed by the wrong block"
    )
