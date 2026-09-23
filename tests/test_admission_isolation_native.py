"""Step 5F: admission evaluates in a context of its own.

With worker-backed authority the committed state is right, but admission used
to step the in-process interpreter, one evaluator shared by every submission.
Stepping is not read-only, so under a history-dependent policy one request's
inputs became the next request's `[t-1]`:

    valid transaction          -> falsely rejected at admission, or
    admitted under that history -> rejected at inclusion

-- the second being the original incident's user-visible shape, `sendtx` and
the block disagreeing. Everything here goes through `sendtx.queue_transaction`,
`createblock` and the committed store, with the authority initialized on a
disposable database.
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
import tau_manager
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
    ready = threading.Event()
    owner = auth.AuthoritativeTauOwner(ready=ready, program_baseline=_baseline())
    auth.reset(owner)
    tc.registry().discard()
    tau_admission.reset()
    owner.initialize(cwd=REPO, env=_env())
    yield owner
    tau_admission.reset()
    tc.registry().discard()
    auth.reset(None)


@pytest.fixture(autouse=True)
def _mining_allowed():
    with patch.object(TauConsensusEngine, "query_eligibility", lambda *a, **k: True), \
         patch.object(TauConsensusEngine, "verify_block_header", lambda *a, **k: True):
        yield


def _sender(tag, balance=1_000_000):
    sk = bls.KeyGen(tag.encode().ljust(32, b"_"))
    pk = bls.SkToPk(sk).hex()
    chain_state._balances[pk] = balance
    return sk, pk


def _signed(sk, pk, ops, seq, fee_limit="100000"):
    tx = {"tx_type": "user_tx", "sender_pubkey": pk, "sequence_number": seq,
          "expiration_time": int(time.time()) + 3600, "expire_at_height": 5000,
          "operations": ops, "fee_limit": fee_limit}
    tx["signature"] = bls.Sign(sk, hashlib.sha256(
        _get_signing_message_bytes(tx)).digest()).hex()
    return tx


def _submit(sk, pk, ops, seq=None, fee_limit="100000"):
    if seq is None:
        seq = chain_state.get_sequence_number(pk)
        pending = db.get_pending_sequence(pk)
        if pending is not None and pending >= seq:
            seq = pending + 1
    return sendtx.queue_transaction(json.dumps(_signed(sk, pk, ops, seq, fee_limit)),
                                    propagate=False)


def _force_queue(sk, pk, ops, seq, fee_limit="100000"):
    """Put a transaction in the mempool WITHOUT admission -- to ask what
    inclusion does with it on its own."""
    payload = _signed(sk, pk, ops, seq, fee_limit)
    tx_hash, blob = sendtx._compute_transaction_message_id(payload)
    db.add_mempool_tx(blob, tx_hash, int(time.time() * 1000))
    return tx_hash


def _mine():
    out = createblock.create_block_from_mempool()
    assert "error" not in out, out
    return out


def _included(tx_hash):
    """Whether the durable head block carries `tx_hash`."""
    return tx_hash in ((db.get_canonical_head_block() or {}).get("tx_ids") or [])


def _recipient(tag):
    return bls.SkToPk(bls.KeyGen(tag.encode().ljust(32, b"_"))).hex()


def _history_policy(pk, previous="000007"):
    """`pk` is blocked when the PREVIOUS step's amount was `previous`.

    Total form on every branch: a bare `guard -> o5 = ...` leaves o5
    unconstrained elsewhere, and an unconstrained o5 materializes as 0 --
    BLOCK -- for every other sender on the network.
    """
    return ("always ( (i12[t]:bv[384] = { #x%s }:bv[384]) ? "
            "((i1[t-1]:bv[24] = { #x%s }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24])) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )." % (pk, previous))


def _transfer(pk, to, amount):
    return {"1": [[pk, to, str(amount)]]}


def _policy_chain():
    """Committed: S's history policy, then one transfer of 5 as the last step."""
    s_sk, s_pk = _sender("policy_owner")
    t_sk, t_pk = _sender("bystander")
    assert _submit(s_sk, s_pk, {"0": _history_policy(s_pk)}).get("ok")
    _mine()
    assert _submit(t_sk, t_pk, _transfer(t_pk, _recipient("sink"), 5)).get("ok")
    _mine()
    return s_sk, s_pk, t_sk, t_pk


def _influence(amount, times=3):
    """Requests that reach the Tau step with i1=`amount`, then are refused
    AFTER it (insufficient funds), so none of them is ever queued."""
    u_sk, u_pk = _sender("influencer", balance=1)
    for _ in range(times):
        out = _submit(u_sk, u_pk, _transfer(u_pk, _recipient("elsewhere"), amount))
        assert not out.get("ok") and out.get("code") == "INSUFFICIENT_FUNDS", out


# --- one submission cannot become another's history -----------------------------

def test_admission_requests_cannot_influence_one_another(authority):
    s_sk, s_pk, _, _ = _policy_chain()
    _influence(7)
    # committed history ends at amount 5, so S is allowed -- whatever was asked
    # in between
    admitted = _submit(s_sk, s_pk, _transfer(s_pk, _recipient("s_target"), 3))
    assert admitted.get("ok"), (
        "a valid transaction was refused because of what earlier, unrelated "
        f"admission requests fed: {admitted}"
    )
    _mine()
    assert _included(admitted["tx_hash"]), "admitted, then not included"


def test_the_same_requests_through_one_shared_evaluator_do_contaminate(authority):
    """The discriminator: route every request through ONE context -- the shared
    evaluator this change removes -- and the same sequence refuses S."""
    s_sk, s_pk, _, _ = _policy_chain()
    shared = {}
    real_open = tau_admission.open_context

    def _shared_open(**kw):
        if "ctx" not in shared:
            shared["ctx"] = real_open(**{**kw, "budget": 120})
        ctx = shared["ctx"]

        class _Keep:
            def __getattr__(self, name):
                return getattr(ctx, name)

            def dispose(self):
                pass
        return _Keep()

    try:
        with patch.object(tau_admission, "open_context", _shared_open):
            _influence(7)
            refused = _submit(s_sk, s_pk, _transfer(s_pk, _recipient("s_target"), 3))
    finally:
        if "ctx" in shared:
            shared["ctx"].dispose()
    assert not refused.get("ok") and "user policy" in refused.get("message", ""), (
        f"a shared evaluator should have carried i1=7 into S's request: {refused}"
    )


def test_admission_does_not_admit_what_inclusion_refuses(authority):
    """The other direction. Committed history ends at 7, so S is blocked; a
    request feeding 5 must not make S look allowed."""
    s_sk, s_pk = _sender("policy_owner")
    t_sk, t_pk = _sender("bystander")
    assert _submit(s_sk, s_pk, {"0": _history_policy(s_pk)}).get("ok")
    _mine()
    assert _submit(t_sk, t_pk, _transfer(t_pk, _recipient("sink"), 7)).get("ok")
    _mine()
    _influence(5)
    refused = _submit(s_sk, s_pk, _transfer(s_pk, _recipient("s_target"), 3))
    assert not refused.get("ok") and "user policy" in refused.get("message", ""), refused

    # and inclusion agrees: the same transaction, bypassing admission, is refused
    tx_hash = _force_queue(s_sk, s_pk, _transfer(s_pk, _recipient("s_target"), 3),
                           seq=chain_state.get_sequence_number(s_pk))
    _mine()
    assert not _included(tx_hash), "inclusion accepted what admission refused"


# --- nothing reaches committed state or the in-process interpreter --------------

def test_admission_writes_nothing_committed(authority):
    """A transfer to an address the chain has never seen: the old path interned
    it into the committed mapping from the RPC thread, outside any block."""
    sk, pk = _sender("writes_nothing")
    epoch, high = db.shrink_mapping_epoch(), db.get_max_shrink_id()
    head = db.committed_journal_head()
    fresh = _recipient("never_seen_before")
    assert _submit(sk, pk, _transfer(pk, fresh, 11)).get("ok")
    assert db.shrink_mapping_epoch() == epoch, "admission moved the committed mapping"
    assert db.get_max_shrink_id() == high
    assert db.committed_journal_head() == head, "admission wrote the committed journal"


def test_admission_never_steps_the_in_process_interpreter(authority):
    sk, pk = _sender("no_mirror")

    def _refuse(*a, **k):
        raise AssertionError("admission stepped the in-process interpreter")

    with patch.object(tau_manager, "communicate_with_tau", _refuse), \
         patch.object(tau_manager, "communicate_with_tau_multi", _refuse), \
         patch("tau_native.compile_revisions_isolated_subprocess", _refuse), \
         patch.object(sendtx, "_preflight_prepared_rule", _refuse):
        rule = _submit(sk, pk, {"0": "always ( o12[t]:bv[24] = i13[t]:bv[24] )."})
        assert rule.get("ok"), rule
        transfer = _submit(sk, pk, _transfer(pk, _recipient("no_mirror_to"), 4))
        assert transfer.get("ok"), transfer
        custom = _submit(sk, pk, {"13": "9"})
        assert custom.get("ok"), custom


def test_every_context_is_disposed(authority):
    sk, pk = _sender("disposed")
    before = dict(tau_admission.stats)
    for amount in (1, 2, 3):
        assert _submit(sk, pk, _transfer(pk, _recipient(f"d{amount}"), amount)).get("ok")
    opened = tau_admission.stats["opened"] - before.get("opened", 0)
    disposed = tau_admission.stats["disposed"] - before.get("disposed", 0)
    assert opened == 3 and disposed == 3, (opened, disposed)


# --- verdicts admission shares with inclusion -----------------------------------

UNSAT = ("always ( (o12[t]:bv[24] = { #x000001 }:bv[24]) && "
         "(o12[t]:bv[24] = { #x000002 }:bv[24]) ).")


def test_an_unsatisfiable_rule_is_refused_at_admission_as_at_inclusion(authority):
    """It used to compile fine in a fresh process, be admitted as
    "inconclusive", and then be refused by the block: `sendtx` said yes, the
    chain said no."""
    sk, pk = _sender("unsat")
    refused = _submit(sk, pk, {"0": UNSAT})
    assert not refused.get("ok") and refused.get("code") == "TX_REJECTED", refused

    tx_hash = _force_queue(sk, pk, {"0": UNSAT}, seq=chain_state.get_sequence_number(pk))
    _mine()
    assert not _included(tx_hash), "inclusion accepted a rule admission refused"


def test_a_rule_is_judged_against_the_committed_type_history(authority):
    """i13 is typed bv[24] by a committed rule; a candidate re-typing it at bv[8]
    is refused by the engine that carries that history -- the refusal comes
    from the context, not from a compile that never saw the history."""
    sk, pk = _sender("typed")
    assert _submit(sk, pk, {"0": "always ( o12[t]:bv[24] = i13[t]:bv[24] )."}).get("ok")
    _mine()
    with patch("tau_native.compile_revisions_isolated_subprocess",
               side_effect=AssertionError("fresh-process compile used")):
        refused = _submit(sk, pk, {"0": "always ( o13[t]:bv[8] = i13[t]:bv[8] )."})
    assert not refused.get("ok") and refused.get("code") == "TX_REJECTED", refused
    assert "i13" in refused.get("message", ""), refused


# --- custom inputs reach the evaluator as values --------------------------------

def _custom_policy(pk):
    """`pk` is blocked when its own custom input i13 is 7."""
    return ("always ( (i12[t]:bv[384] = { #x%s }:bv[384]) ? "
            "((i13[t]:bv[24] = { #x000007 }:bv[24]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24])) "
            ": (o5[t]:bv[24] = { #x000001 }:bv[24]) )." % pk)


def test_a_policy_on_custom_inputs_is_enforced_at_inclusion(authority):
    """Custom inputs are lists by the time they reach an evaluator. The worker
    session fed them as `['7']`, the engine refused the step, and the block went
    on with NO outputs for it -- so the policy never ran and the blocked
    transfer was included."""
    sk, pk = _sender("custom_policy")
    assert _submit(sk, pk, {"0": _custom_policy(pk)}).get("ok")
    _mine()

    blocked = {**_transfer(pk, _recipient("c_to"), 2), "13": "7"}
    refused = _submit(sk, pk, blocked)
    assert not refused.get("ok") and "user policy" in refused.get("message", ""), refused

    tx_hash = _force_queue(sk, pk, blocked, seq=chain_state.get_sequence_number(pk))
    _mine()
    assert not _included(tx_hash), (
        "inclusion let through a transfer the sender's policy blocks"
    )

    allowed = _submit(sk, pk, {**_transfer(pk, _recipient("c_to"), 2), "13": "5"})
    assert allowed.get("ok"), allowed
    _mine()
    assert _included(allowed["tx_hash"])


# --- operational outcomes --------------------------------------------------------

def test_an_exhausted_budget_is_a_timeout_and_kills_the_worker(authority):
    sk, pk = _sender("slow")
    spawned = []
    import tau_session
    real_spawn = tau_session.WorkerSession.spawn.__func__

    def _spawn(cls, *a, **k):
        session = real_spawn(cls, *a, **k)
        spawned.append(session)
        time.sleep(0.5)
        return session

    with patch.object(tau_admission, "default_budget", lambda: 0.2), \
         patch.object(tau_session.WorkerSession, "spawn", classmethod(_spawn)):
        out = _submit(sk, pk, _transfer(pk, _recipient("slow_to"), 1))
    assert not out.get("ok") and out.get("code") == "ADMISSION_TIMEOUT", out
    assert spawned and all(s._spec._proc.poll() is not None for s in spawned), (
        "the timed-out worker is still running"
    )


def test_a_corrupt_journal_is_unavailable_not_answered_elsewhere(authority):
    sk, pk = _sender("corrupt")
    with db._db_lock:
        db._db_conn.execute("UPDATE tau_journal_v1 SET link = 'tampered' "
                            "WHERE seq = (SELECT MAX(seq) FROM tau_journal_v1)")
        db._db_conn.commit()

    def _refuse(*a, **k):
        raise AssertionError("fell back to the in-process interpreter")

    with patch.object(tau_manager, "communicate_with_tau_multi", _refuse):
        out = _submit(sk, pk, _transfer(pk, _recipient("corrupt_to"), 1))
    assert not out.get("ok") and out.get("code") == "ADMISSION_UNAVAILABLE", out


# --- the standby -----------------------------------------------------------------

def test_a_standby_is_used_once_and_never_after_a_commit(authority):
    s_sk, s_pk, t_sk, t_pk = _policy_chain()
    tau_admission.enable_standby(True, cwd=REPO, env=_env())
    deadline = time.time() + 60
    while tau_admission._standby._ready is None and time.time() < deadline:
        time.sleep(0.1)
    assert tau_admission._standby._ready is not None, "no standby was built"

    hits = tau_admission.stats["standby_hits"]
    assert _submit(s_sk, s_pk, _transfer(s_pk, _recipient("st1"), 3)).get("ok")
    assert tau_admission.stats["standby_hits"] == hits + 1

    # a block moves committed history to amount 7: a standby built before it
    # would still say "5" and admit S -- it must not be used
    db.clear_mempool()
    assert _submit(t_sk, t_pk, _transfer(t_pk, _recipient("sink"), 7)).get("ok")
    while tau_admission._standby._ready is None and time.time() < deadline:
        time.sleep(0.1)
    stale = tau_admission._standby._ready
    assert stale is not None, "the standby was not rebuilt after being used"
    with patch.object(tau_admission._Standby, "committed", lambda self, **k: None):
        _mine()   # the commit hook is suppressed: only the anchor check remains
    assert tau_admission._standby._ready is stale
    refused = _submit(s_sk, s_pk, _transfer(s_pk, _recipient("st2"), 3))
    assert not refused.get("ok") and "user policy" in refused.get("message", ""), (
        f"a context built before the last commit answered for it: {refused}"
    )


# --- the representation a lent worker runs under ---------------------------------

def test_a_rule_does_not_shrink_what_its_session_feeds_plain(authority):
    """The first sender-scoped rule lands on the LENT authority, whose plan was
    made before any rule mentioned i12 and so feeds i12 full width. Letting the
    optimizer shrink the rule's i12 literal anyway typed i12 bv[8]; from then on
    every step that fed i12 was refused, and the fee query read as "no fee"."""
    sk, pk = _sender("lent_i12")
    before = chain_state.get_balance(pk)
    assert _submit(sk, pk, {"0": _history_policy(pk)}).get("ok")
    _mine()
    charged = before - chain_state.get_balance(pk)
    assert charged > 0, (
        "the rule transaction's fee query produced nothing -- the step that feeds "
        "i12 was refused under the lent worker's representation"
    )
    # and a later step that feeds i12 still evaluates: a transfer is charged
    before = chain_state.get_balance(pk)
    assert _submit(sk, pk, _transfer(pk, _recipient("after_rule"), 2)).get("ok")
    _mine()
    assert before - chain_state.get_balance(pk) > 2, "the transfer paid no fee"


def test_a_refused_step_is_never_read_as_no_outputs(authority):
    """A custom input the engine cannot parse at the stream's width. The worker
    refuses the step; apply used to receive an empty output dict, read o5 as
    absent -- ALLOW -- and the fee as zero, and included the transfer."""
    sk, pk = _sender("refused_step")
    assert _submit(sk, pk, {"0": _custom_policy(pk)}).get("ok")
    _mine()
    too_wide = {**_transfer(pk, _recipient("r_to"), 2), "13": "#xffffffffff"}
    refused = _submit(sk, pk, too_wide)
    assert not refused.get("ok") and refused.get("code") == "TX_REJECTED", refused
    tx_hash = _force_queue(sk, pk, too_wide, seq=chain_state.get_sequence_number(pk))
    _mine()
    assert not _included(tx_hash), (
        "a transfer whose step the engine refused was included as if its policy "
        "had allowed it"
    )
