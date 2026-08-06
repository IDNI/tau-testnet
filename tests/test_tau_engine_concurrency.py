"""Regression tests for native-engine serialization.

`tau_native.StdOutCapture` dups and closes FD 1 to capture the C++-level stdout
of the nanobind engine, so two threads inside the engine at once corrupt each
other's capture: FD 1 ends up wired to a closed pipe (the next native call dies
with "[Errno 9] Bad file descriptor", surfaced as
`TX_REJECTED: ... Direct Tau multi-output communication failed`) or a reader
blocks forever on a pipe whose write end still lives on FD 1.

That happened for real whenever an admission-path `sendtx`
(`commands/sendtx.py` -> `communicate_with_tau_multi`) overlapped a
`createblock` on the block-producer thread -- even with a single serial
submitter, because the producer runs on its own thread. Dropped transactions
then desynced the sender's sequence, cascading into INVALID_SEQUENCE.

Two layers are asserted here:
  * `tau_manager.tau_comm_lock` (reentrant) serializes whole evaluations, which
    is what the *stateful* interpreter needs -- StdOutCapture is entered once
    per `tau.step`, so capture-level locking alone would still let a second
    thread interleave inputs between steps of one evaluation.
  * `tau_native._stdout_capture_lock` protects FD 1 for engine entries that do
    not go through tau_manager (interpreter construction, `update_spec`).
"""

import errno
import hashlib
import json
import os
import threading
import time
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic as bls

import chain_state
import config
import db
import tau_manager
import tau_native
from commands import createblock, sendtx
from commands.sendtx import _get_signing_message_bytes


# --------------------------------------------------------------------------
# Layer 1: StdOutCapture must be mutually exclusive (real file descriptors).
# --------------------------------------------------------------------------

def test_stdout_capture_serializes_across_threads():
    """Concurrent captures keep their own output and leave FD 1 intact.

    Pre-fix this hangs (a thread blocks reading a pipe whose write end leaked
    onto FD 1) or reports foreign/empty output.
    """
    real_stdout = os.dup(1)
    before = os.fstat(real_stdout)
    errors: list[str] = []
    n_threads, rounds = 6, 25

    def worker(tid: int) -> None:
        for r in range(rounds):
            marker = f"T{tid}R{r}"
            try:
                with tau_native.StdOutCapture() as cap:
                    os.write(1, marker.encode())
            except Exception as exc:  # pragma: no cover - only on regression
                errors.append(f"{marker}: {type(exc).__name__}: {exc}")
                continue
            if cap.output != marker:
                errors.append(f"{marker}: captured {cap.output!r}")

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(n_threads)]
    try:
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        # daemon threads: a regression leaves one blocked in the pipe read
        # instead of hanging the whole suite.
        assert not any(t.is_alive() for t in threads), "StdOutCapture deadlocked"
        assert errors == [], f"captures interfered: {errors[:5]}"

        after = os.fstat(1)
        assert (after.st_dev, after.st_ino) == (before.st_dev, before.st_ino), \
            "FD 1 was not restored to the original stdout"
        os.write(1, b"")  # would raise EBADF/EPIPE on a corrupted FD 1
    finally:
        os.close(real_stdout)


def test_stdout_capture_is_reentrant_on_one_thread():
    """A nested capture (interpreter rebuild inside a step) must not self-deadlock."""
    with tau_native.StdOutCapture() as outer:
        os.write(1, b"outer-a")
        with tau_native.StdOutCapture() as inner:
            os.write(1, b"inner")
        os.write(1, b"outer-b")
    assert inner.output == "inner"
    assert outer.output == "outer-aouter-b"


# --------------------------------------------------------------------------
# Layer 2: tau_manager serializes whole evaluations.
# --------------------------------------------------------------------------

# `FakeEngine` and the `fake_engine` / `node_state` fixtures live in
# tests/conftest.py -- tests/test_block_production_serialization.py needs the
# same in-process node.


def _run_threads(targets, timeout=60):
    threads = [threading.Thread(target=t, daemon=True) for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=timeout)
    alive = [t for t in threads if t.is_alive()]
    assert not alive, f"{len(alive)} thread(s) deadlocked in the Tau comm path"


def test_multi_output_comm_serializes_engine_entry(fake_engine):
    """`communicate_with_tau_multi` must hold tau_comm_lock (it used to not)."""
    failures: list[str] = []

    def caller(tid: int):
        def run():
            for i in range(4):
                try:
                    out = tau_manager.communicate_with_tau_multi(
                        input_stream_values={1: "5", 2: "100"},
                        source=f"thread{tid}",
                        apply_rules_update=False,
                    )
                    assert out.get(1) == "1"
                except Exception as exc:
                    failures.append(f"t{tid}#{i}: {type(exc).__name__}: {exc}")
        return run

    _run_threads([caller(i) for i in range(5)])
    assert failures == [], failures
    assert fake_engine.overlaps == [], f"concurrent engine entry: {fake_engine.overlaps}"
    assert fake_engine.max_concurrent == 1
    assert fake_engine.calls == 20


def test_single_and_multi_output_comms_share_one_lock(fake_engine):
    """The o-stream path and the multi path must exclude each other too."""
    failures: list[str] = []

    def single():
        for _ in range(4):
            try:
                tau_manager.communicate_with_tau(
                    target_output_stream_index=1,
                    input_stream_values={1: "5", 2: "100"},
                    source="single",
                    apply_rules_update=False,
                    wait_for_ready=False,
                )
            except Exception as exc:
                failures.append(f"single: {type(exc).__name__}: {exc}")

    def multi():
        for _ in range(4):
            try:
                tau_manager.communicate_with_tau_multi(
                    input_stream_values={1: "5", 2: "100"},
                    source="multi",
                    apply_rules_update=False,
                )
            except Exception as exc:
                failures.append(f"multi: {type(exc).__name__}: {exc}")

    _run_threads([single, multi, single, multi])
    assert failures == [], failures
    assert fake_engine.max_concurrent == 1


def test_multi_output_comm_is_reentrant_under_comm_lock(fake_engine):
    """consensus/engine.py wraps its calls in tau_comm_lock; nesting must not deadlock.

    This is why the lock is an RLock -- with a plain Lock this call self-deadlocks
    (the reason the multi path was originally left unlocked).
    """
    done = threading.Event()

    def nested():
        with tau_manager.tau_comm_lock:
            tau_manager.communicate_with_tau_multi(
                input_stream_values={1: "5", 2: "100"},
                source="consensus_verify",
                apply_rules_update=False,
            )
            tau_manager.communicate_with_tau(
                target_output_stream_index=6,
                input_stream_values={1: "5"},
                source="consensus_verify",
                apply_rules_update=False,
                wait_for_ready=False,
            )
        done.set()

    _run_threads([nested], timeout=30)
    assert done.is_set(), "nested comm under tau_comm_lock deadlocked"


def test_spec_restore_serializes_against_comms(fake_engine, monkeypatch):
    """`restore_full_tau_spec` is an engine entry (update_spec) -- same lock.

    createblock runs it in a `finally` after the miner simulation while
    admission traffic keeps arriving.
    """
    monkeypatch.setattr(tau_manager, "_runtime_shrunk_streams", frozenset())
    failures: list[str] = []

    def restorer():
        for _ in range(4):
            try:
                tau_manager.restore_full_tau_spec("always o0[t] = 1.")
            except Exception as exc:
                failures.append(f"restore: {type(exc).__name__}: {exc}")

    def admitter():
        for _ in range(4):
            try:
                tau_manager.communicate_with_tau_multi(
                    input_stream_values={1: "5", 2: "100"},
                    source="admission",
                    apply_rules_update=False,
                )
            except Exception as exc:
                failures.append(f"admit: {type(exc).__name__}: {exc}")

    _run_threads([restorer, admitter, admitter])
    assert failures == [], failures
    assert fake_engine.overlaps == []
    assert fake_engine.max_concurrent == 1


# --------------------------------------------------------------------------
# The reported failure: admission-path sendtx overlapping a createblock.
# --------------------------------------------------------------------------

def _sign_tx(tx_dict: dict, sk) -> str:
    msg_hash = hashlib.sha256(_get_signing_message_bytes(tx_dict)).digest()
    tx_dict["signature"] = bls.Sign(sk, msg_hash).hex()
    return json.dumps(tx_dict)


def test_concurrent_sendtx_and_createblock(node_state):
    """A `sendtx` admitted while the block producer is inside Tau must survive.

    Before the fix the two threads collided inside the native engine and
    admission returned
    `TX_REJECTED: ... Direct Tau multi-output communication failed:
    [Errno 9] Bad file descriptor`, dropping a valid tx (and desyncing the
    sender's sequence for every later one).
    """
    engine = node_state
    n_senders = 6
    # One tx per sender, all at sequence 0: the producer committing a block
    # cannot shift another sender's expected sequence, so a rejection here is a
    # real engine-level failure and never sequence bookkeeping.
    senders = []
    for i in range(n_senders):
        sk = bls.KeyGen(f"engine_concurrency_sender_{i}".encode())
        pk = bls.SkToPk(sk).hex()
        chain_state._balances[pk] = 1_000
        senders.append((sk, pk))
    recipient = bls.SkToPk(bls.KeyGen(b"engine_concurrency_recipient")).hex()

    admission_results: list[dict] = []
    producer_errors: list[str] = []
    stop_producing = threading.Event()

    def submit():
        for sk, pk in senders:
            tx = {
                "tx_type": "user_tx",
                "sender_pubkey": pk,
                "sequence_number": 0,
                "expiration_time": int(time.time()) + 3600,
                "operations": {"1": [[pk, recipient, "10"]]},
                "fee_limit": "0",
            }
            admission_results.append(
                sendtx.queue_transaction(_sign_tx(tx, sk), propagate=False)
            )

    def produce():
        while not stop_producing.is_set():
            try:
                createblock.create_block_from_mempool()
            except Exception as exc:
                producer_errors.append(f"{type(exc).__name__}: {exc}")
                return

    with patch("consensus.engine.TauConsensusEngine.query_eligibility", return_value=True), \
         patch("consensus.engine.TauConsensusEngine.verify_block_header", return_value=True):
        producer = threading.Thread(target=produce, daemon=True)
        producer.start()
        try:
            submitter = threading.Thread(target=submit, daemon=True)
            submitter.start()
            submitter.join(timeout=120)
            assert not submitter.is_alive(), "sendtx admission deadlocked"
        finally:
            stop_producing.set()
            producer.join(timeout=120)
        assert not producer.is_alive(), "createblock deadlocked"

    assert engine.overlaps == [], \
        f"admission and block production entered the engine together: {engine.overlaps}"
    assert engine.max_concurrent == 1
    rejected = [r for r in admission_results if not r.get("ok")]
    assert rejected == [], f"transactions rejected during concurrent mining: {rejected}"
    assert len(admission_results) == n_senders
    assert producer_errors == [], producer_errors
    # Guard against a vacuous pass: both threads must really have driven the
    # engine (admission tags its calls with the sender pubkey; the producer's
    # apply path does not pass a source).
    admission_sources = {pk for _, pk in senders} & set(engine.sources)
    assert len(admission_sources) == n_senders, \
        f"admission never reached the engine: {sorted(set(engine.sources))}"
    assert engine.calls > n_senders, "block production never reached the engine"
