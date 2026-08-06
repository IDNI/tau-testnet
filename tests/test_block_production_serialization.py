"""Regression tests for block-production serialization and mempool safety.

Block production used to run unlocked: the chain head was read before any lock,
and only the mempool reservation was protected. Two producers -- an RPC
connection thread, the SoleMiner loop, or the network sync worker -- therefore
built competing blocks on the same parent. The loser could not persist (it
collided on the block-hash primary key, tripped the state-hash invariant, or was
routed to the orphan path), and `create_block_from_mempool` then *deleted* the
transactions the engine had accepted for it. Those txs existed nowhere
afterwards: `gettxstatus` reported `unknown`, and because the senders' on-chain
sequence numbers never advanced, every later tx from them failed
INVALID_SEQUENCE.

A separate defect in the same function: with an empty mempool it fell through
and sealed an *empty* block, so a caller polling `createblock` minted an
unbounded run of them (291 in one benchmark run).

Both are asserted here through the real `create_block_from_mempool`, against the
in-process `node_state` node (temp DB, genesis, dummy miner key, fake engine).
"""

import hashlib
import json
import threading
import time
from unittest.mock import patch

import pytest
from py_ecc.bls import G2Basic as bls

import block as block_mod
import chain_state
import config
import db
from commands import createblock, sendtx
from commands.sendtx import _get_signing_message_bytes
from consensus.engine import ApplyBlockResult, TauConsensusEngine
from consensus.state import TauStateSnapshot


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _sign_tx(tx_dict: dict, sk) -> str:
    msg_hash = hashlib.sha256(_get_signing_message_bytes(tx_dict)).digest()
    tx_dict["signature"] = bls.Sign(sk, msg_hash).hex()
    return json.dumps(tx_dict)


def _seed_senders(count: int, tag: str, balance: int = 1_000):
    """Fund `count` accounts and return [(sk, pubkey), ...]."""
    senders = []
    for i in range(count):
        sk = bls.KeyGen(f"{tag}_sender_{i}".encode())
        pk = bls.SkToPk(sk).hex()
        chain_state._balances[pk] = balance
        senders.append((sk, pk))
    return senders


def _submit(senders, recipient, amount: str = "10") -> list:
    """Admit one tx per sender (all at sequence 0). Returns their hashes."""
    hashes = []
    for sk, pk in senders:
        tx = {
            "tx_type": "user_tx",
            "sender_pubkey": pk,
            "sequence_number": 0,
            "expiration_time": int(time.time()) + 3600,
            "operations": {"1": [[pk, recipient, amount]]},
            "fee_limit": "0",
        }
        result = sendtx.queue_transaction(_sign_tx(tx, sk), propagate=False)
        assert result.get("ok"), f"admission rejected the setup tx: {result}"
        hashes.append(result["tx_hash"])
    return hashes


def _canonical_chain() -> list:
    """Canonical blocks, genesis-first, walked back from the head."""
    head = db.get_canonical_head_block()
    chain = []
    seen = set()
    while head is not None:
        if head['block_hash'] in seen:  # defensive: never loop on a cycle
            break
        seen.add(head['block_hash'])
        chain.append(head)
        prev = head['header'].get('previous_hash')
        if not prev or prev == "0" * 64:
            break
        head = db.get_block_by_hash(prev)
    return list(reversed(chain))


def _locate(tx_hash: str) -> str:
    """Where a transaction ended up: confirmed | mempool | dropped | LOST."""
    for loc in db.get_tx_block_locations(tx_hash):
        is_canonical, _ = db.get_canonical_confirmation(
            loc["block_hash"], loc["block_number"]
        )
        if is_canonical:
            return "confirmed"
    if db.get_mempool_entry(tx_hash) is not None:
        return "mempool"
    if db.get_dropped_tx(tx_hash) is not None:
        return "dropped"
    return "LOST"


def _mining_allowed():
    """Bypass the consensus gates; these tests are about serialization."""
    return patch.multiple(
        TauConsensusEngine,
        query_eligibility=lambda *a, **k: True,
        verify_block_header=lambda *a, **k: True,
    )


@pytest.fixture
def spawn(node_state):
    """Start daemon threads that are guaranteed to be joined before teardown.

    `node_state` closes the SQLite connection when it finalizes, and a worker
    still inside sqlite at that moment segfaults the interpreter -- which is how
    an ordinary assertion failure turns into a crashed test session. Fixture
    teardown is LIFO, so joining here (this fixture depends on `node_state`)
    happens while the connection is still open.
    """
    threads: list[threading.Thread] = []

    def _spawn(target) -> threading.Thread:
        thread = threading.Thread(target=target, daemon=True)
        threads.append(thread)
        thread.start()
        return thread

    yield _spawn

    for thread in threads:
        thread.join(timeout=120)


# --------------------------------------------------------------------------
# Concurrency
# --------------------------------------------------------------------------
def test_racing_producers_keep_every_transaction(node_state, spawn):
    """Two producers racing must not lose a transaction or fork the head.

    Pre-fix the loser's parent is stale by the time it persists, so
    `process_new_block` returns False and the accepted transactions of that
    round are hard-deleted -- `_locate` reports LOST.
    """
    senders = _seed_senders(8, "race")
    recipient = bls.SkToPk(bls.KeyGen(b"race_recipient")).hex()
    hashes = _submit(senders, recipient)

    errors: list[str] = []
    outcomes: list[dict] = []
    barrier = threading.Barrier(2)

    def produce():
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError:
            return
        for _ in range(20):  # bounded: MINING_BUSY returns immediately
            try:
                outcomes.append(createblock.create_block_from_mempool())
            except Exception as exc:
                errors.append(f"{type(exc).__name__}: {exc}")
                return
            if db.count_mempool_txs() == 0:
                return

    with _mining_allowed():
        threads = [spawn(produce) for _ in range(2)]
        for thread in threads:
            thread.join(timeout=120)
        assert not any(t.is_alive() for t in threads), "block production deadlocked"

    assert errors == [], errors

    chain = _canonical_chain()
    numbers = [b['header']['block_number'] for b in chain]
    assert len(numbers) == len(set(numbers)), f"duplicate heights on canonical chain: {numbers}"

    located = {h: _locate(h) for h in hashes}
    assert "LOST" not in located.values(), f"transactions destroyed: {located}"
    assert node_state.max_concurrent == 1, (
        f"producers entered the engine together: {node_state.overlaps}"
    )


def test_second_producer_reports_busy_instead_of_racing(node_state, spawn):
    """With the chain lock held, a producer bails out fast and changes nothing."""
    _seed_senders(1, "busy")
    senders = _seed_senders(2, "busy_tx")
    recipient = bls.SkToPk(bls.KeyGen(b"busy_recipient")).hex()
    _submit(senders, recipient)

    mempool_before = db.count_mempool_txs()
    head_before = db.get_canonical_head_block()
    result = {}

    def produce():
        result["value"] = createblock.create_block_from_mempool()

    with _mining_allowed(), chain_state._chain_lock:
        thread = spawn(produce)
        thread.join(timeout=10)
        assert not thread.is_alive(), (
            "producer blocked on the chain lock instead of returning busy"
        )

    assert "block_hash" not in result["value"], result["value"]
    code, _ = createblock._classify_createblock_error(result["value"])
    assert code == "MINING_BUSY", result["value"]
    assert db.count_mempool_txs() == mempool_before, "busy round touched the mempool"
    assert (db.get_canonical_head_block() or {}).get('block_hash') == \
        (head_before or {}).get('block_hash')


def test_production_serializes_against_network_ingest(node_state, spawn):
    """A synced batch and a local round must not interleave."""
    from network.service import NetworkService

    senders = _seed_senders(4, "ingest")
    recipient = bls.SkToPk(bls.KeyGen(b"ingest_recipient")).hex()
    hashes = _submit(senders, recipient)

    # A competing block at the same height as the one the producer is about to
    # build: this is the collision that used to strand the producer's batch.
    head = db.get_canonical_head_block()
    competitor = block_mod.Block.create(
        block_number=head['header']['block_number'] + 1,
        previous_hash=head['block_hash'],
        transactions=[],
        proposer_pubkey=bls.SkToPk(bls.KeyGen(b"ingest_peer_proposer")).hex(),
        timestamp=int(time.time()),
    )

    ingested_blocks: list[int] = []
    order_lock = threading.Lock()
    real_ingest_block = chain_state.ingest_block

    def traced_ingest_block(blk):
        with order_lock:
            ingested_blocks.append(blk.header.block_number)
        return real_ingest_block(blk)

    errors: list[str] = []
    barrier = threading.Barrier(2)

    def produce():
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError:
            return
        try:
            createblock.create_block_from_mempool()
        except Exception as exc:
            errors.append(f"producer: {type(exc).__name__}: {exc}")

    def ingest():
        try:
            barrier.wait(timeout=30)
        except threading.BrokenBarrierError:
            return
        try:
            NetworkService._ingest_blocks([competitor.to_dict()], "peer-under-test")
        except Exception as exc:
            errors.append(f"ingest: {type(exc).__name__}: {exc}")

    with _mining_allowed(), patch.object(chain_state, "ingest_block", traced_ingest_block):
        threads = [spawn(produce), spawn(ingest)]
        for thread in threads:
            thread.join(timeout=120)
        assert not any(t.is_alive() for t in threads), "ingest/production deadlocked"

    assert errors == [], errors
    assert ingested_blocks, "the competing block never reached ingest"
    located = {h: _locate(h) for h in hashes}
    assert "LOST" not in located.values(), f"transactions destroyed: {located}"
    new_head = db.get_canonical_head_block()
    assert new_head is not None
    assert chain_state._canonical_head_hash in ("", new_head['block_hash']), (
        "in-memory head disagrees with the persisted canonical head"
    )


def test_chain_lock_is_reentrant(node_state):
    """One producer nests the lock three deep; a plain Lock would self-deadlock."""
    with chain_state._chain_lock:
        with chain_state._chain_lock:
            assert chain_state.maybe_update_canonical_head() in (None, True, False)


# --------------------------------------------------------------------------
# Mempool safety
# --------------------------------------------------------------------------
def _forced_apply_result(execution_ids):
    """An apply_block result that accepts/skips/rejects one tx each."""
    accepted, skipped, invalid = execution_ids[0:1], execution_ids[1:2], execution_ids[2:3]

    def _apply(self, snapshot, block, *args, **kwargs):
        return ApplyBlockResult(
            next_snapshot=TauStateSnapshot(
                state_hash="a" * 64,
                tau_bytes=b"",
                metadata={
                    "source": "test",
                    "balances": dict(chain_state._balances),
                    "sequence_numbers": dict(chain_state._sequence_numbers),
                    "lifecycle_manager": chain_state._lifecycle_manager,
                    "consensus_rules_state": chain_state._consensus_rules_state,
                    "active_consensus_id": chain_state._active_consensus_id,
                },
            ),
            outcomes=[],
            accepted_tx_ids=list(accepted),
            skipped_tx_ids=list(skipped),
            invalid_tx_ids=list(invalid),
            governance_changes={},
            mempool_hints={},
        )

    return _apply


def test_failed_persist_returns_every_transaction_to_pending(node_state, monkeypatch):
    """A block that does not persist may not dispose of a single transaction.

    Pre-fix this deleted the accepted *and* skipped txs (both are in the block
    body) plus the invalid one, and pre-recorded the invalid one as `rejected`
    even though the verdict belonged to a block that never landed.
    """
    senders = _seed_senders(3, "persist_fail")
    recipient = bls.SkToPk(bls.KeyGen(b"persist_fail_recipient")).hex()
    hashes = _submit(senders, recipient)

    monkeypatch.setattr(chain_state, "process_new_block", lambda blk: False)
    monkeypatch.setattr(TauConsensusEngine, "apply_block", _forced_apply_result(hashes))

    with _mining_allowed():
        result = createblock.create_block_from_mempool()

    assert "block_hash" not in result
    code, _ = createblock._classify_createblock_error(result)
    assert code == "MINING_FAILED", result

    for tx_hash in hashes:
        entry = db.get_mempool_entry(tx_hash)
        assert entry is not None, f"{tx_hash[:12]} was deleted for a block that never landed"
        assert entry["status"] == "pending", f"{tx_hash[:12]} left {entry['status']}"
        assert db.get_dropped_tx(tx_hash) is None, (
            f"{tx_hash[:12]} recorded as dropped without a persisted block"
        )


def test_malformed_mempool_row_is_dropped_and_recorded(node_state):
    """Unparseable payloads are final -- remove them, but leave a trace."""
    senders = _seed_senders(1, "malformed")
    recipient = bls.SkToPk(bls.KeyGen(b"malformed_recipient")).hex()
    good_hash = _submit(senders, recipient)[0]

    bad_hash = "b" * 64
    db.add_mempool_tx("{not json", bad_hash, int(time.time() * 1000))

    with _mining_allowed():
        createblock.create_block_from_mempool()

    assert db.get_mempool_entry(bad_hash) is None, "malformed row left in the mempool"
    dropped = db.get_dropped_tx(bad_hash)
    assert dropped is not None and dropped["reason"] == "rejected", (
        "malformed row vanished without a mempool_dropped record -> gettxstatus 'unknown'"
    )
    assert _locate(good_hash) != "LOST"


# --------------------------------------------------------------------------
# Empty blocks
# --------------------------------------------------------------------------
def test_empty_mempool_is_refused_by_default(node_state):
    db.clear_mempool()
    head_before = db.get_canonical_head_block()

    with _mining_allowed():
        result = createblock.create_block_from_mempool()

    assert "block_hash" not in result
    code, _ = createblock._classify_createblock_error(result)
    assert code == "MEMPOOL_EMPTY", result
    assert (db.get_canonical_head_block() or {}).get('block_hash') == \
        (head_before or {}).get('block_hash')


def test_empty_block_is_sealed_when_explicitly_allowed(node_state):
    db.clear_mempool()

    with _mining_allowed():
        result = createblock.create_block_from_mempool(allow_empty=True)

    assert "block_hash" in result, result
    assert result["transactions"] == []


@pytest.mark.parametrize("command,expected", [
    ("createblock", "MEMPOOL_EMPTY"),
    ("createblock allow-empty", None),
    ("createblock bogus-flag", "INVALID_PARAMS"),
])
def test_execute_parses_allow_empty(node_state, command, expected):
    db.clear_mempool()

    with _mining_allowed():
        envelope = json.loads(createblock.execute(command, container=None))

    if expected is None:
        assert envelope["status"] == "ok", envelope
        assert envelope["data"]["tx_count"] == 0
    else:
        assert envelope["status"] == "error", envelope
        assert envelope["error"]["code"] == expected, envelope
