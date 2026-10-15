"""The miner seals an empty block when a retractable release is due.

The miner thread's check is a hint over persisted rows; the block builder
re-decides under the chain lock with the candidate's own height and timestamp.
"""
import os
import time

import pytest

import chain_state
import config
import db
from commands import createblock
from consensus.engine import TauConsensusEngine
from consensus.retractable import KIND_HEIGHT, KIND_TIME, RetractableEntry
from miner.service import SoleMiner

SENDER = "a" * 96
RECIPIENT = "b" * 96
AMOUNT = 40


@pytest.fixture()
def node(tmp_path, monkeypatch):
    original_path = config.STRING_DB_PATH
    config.set_database_path(str(tmp_path / "node.sqlite"))
    if getattr(db, "_db_conn", None) is not None:
        db._db_conn.close()
        db._db_conn = None
    db.init_db()
    chain_state.load_genesis("data/genesis.json")
    chain_state._lifecycle_manager.active_validators = {config.MINER_PUBKEY}
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._application_rules_state = ""
    chain_state._tau_engine_state_hash = ""
    chain_state._balances[SENDER] = 100

    import tau_manager
    from py_ecc.bls import G2Basic

    monkeypatch.setattr(config, "MINER_PRIVKEY", "1" * 64)
    monkeypatch.setattr(tau_manager, "communicate_with_tau", lambda **kw: "require_bls_sig")
    monkeypatch.setattr(tau_manager, "communicate_with_tau_multi", lambda **kw: {})
    monkeypatch.setattr(createblock, "_validate_signature", lambda p: True)
    monkeypatch.setattr(createblock, "_BLS_AVAILABLE", True)
    monkeypatch.setattr(G2Basic, "Verify", lambda *a, **k: True)
    monkeypatch.setattr(TauConsensusEngine, "query_eligibility", lambda self, *a, **k: True)
    tau_manager.tau_ready.set()

    yield
    tau_manager.tau_ready.clear()
    if db._db_conn is not None:
        db._db_conn.close()
        db._db_conn = None
    config.set_database_path(original_path)


def seed(kind, release_at, *, persist=True, sequence=0):
    """An escrowed entry in the in-memory book and, optionally, the persisted rows."""
    lm = chain_state._lifecycle_manager
    lm.retractable_transfers.submit(
        RetractableEntry(SENDER, RECIPIENT, AMOUNT, sequence, kind, release_at)
    )
    if persist:
        with db._db_lock, db._db_conn:
            db._write_retractable_rows(chain_state._retractable_state(lm))


def head_number():
    return db.get_canonical_head_block()["header"]["block_number"]


def open_ids():
    return set(chain_state._lifecycle_manager.retractable_transfers.open)


def snapshot():
    return (
        dict(chain_state._balances),
        dict(chain_state._sequence_numbers),
        open_ids(),
        chain_state._lifecycle_manager.retractable_transfers.resolved_state(),
    )


def test_has_due_retractables_reads_persisted_rows(node):
    assert not db.has_due_retractables(1, int(time.time()))
    seed(KIND_HEIGHT, 5)
    assert not db.has_due_retractables(4, 0)
    assert db.has_due_retractables(5, 0)
    seed(KIND_TIME, 1000, sequence=1)
    assert db.has_due_retractables(1, 1000)
    assert not db.has_due_retractables(1, 999)


def test_height_release_due_seals_empty_block(node):
    seed(KIND_HEIGHT, 1)
    miner = SoleMiner(threshold=10, max_block_interval=3600.0)

    miner.try_mine()

    assert head_number() == 1
    assert open_ids() == set()
    assert chain_state._balances[RECIPIENT] == AMOUNT


def test_time_release_due_seals_empty_block(node):
    seed(KIND_TIME, int(time.time()) - 5)
    miner = SoleMiner(threshold=10, max_block_interval=3600.0)

    miner.try_mine()

    assert head_number() == 1
    assert open_ids() == set()
    assert chain_state._balances[RECIPIENT] == AMOUNT


def test_not_due_seals_nothing(node):
    seed(KIND_HEIGHT, 50)
    before = snapshot()

    SoleMiner(threshold=1, max_block_interval=0.0).try_mine()

    assert head_number() == 0
    assert snapshot() == before


def test_wake_refused_when_nothing_is_due_under_the_lock(node):
    # Persisted rows say due, but the manager (another producer swept) says no.
    seed(KIND_HEIGHT, 1, persist=True)
    chain_state._lifecycle_manager.retractable_transfers.release_due(1, 0)
    before = snapshot()
    assert db.has_due_retractables(1, 0)

    SoleMiner(threshold=10, max_block_interval=3600.0).try_mine()

    assert head_number() == 0
    assert snapshot() == before


def test_wake_if_due_flag_is_required_for_an_empty_block(node):
    seed(KIND_HEIGHT, 1)

    refused = createblock.create_block_from_mempool()
    assert "block_hash" not in refused
    assert head_number() == 0

    sealed = createblock.create_block_from_mempool(wake_if_due=True)
    assert "block_hash" in sealed
    assert head_number() == 1


def test_decision_uses_the_candidate_header_timestamp(node, monkeypatch):
    base = int(time.time())
    seed(KIND_TIME, base + 50)
    real_time = time.time
    clock = {"now": base + 49}
    monkeypatch.setattr(createblock.time, "time", lambda: clock["now"])
    try:
        refused = createblock.create_block_from_mempool(wake_if_due=True)
        assert "block_hash" not in refused
        assert head_number() == 0

        clock["now"] = base + 50
        sealed = createblock.create_block_from_mempool(wake_if_due=True)
    finally:
        monkeypatch.setattr(createblock.time, "time", real_time)
    assert sealed["header"]["timestamp"] == base + 50
    assert open_ids() == set()


def test_failed_attempt_resolves_nothing(node, monkeypatch):
    seed(KIND_HEIGHT, 1)
    before = snapshot()
    monkeypatch.setattr(TauConsensusEngine, "query_eligibility", lambda self, *a, **k: False)

    SoleMiner(threshold=10, max_block_interval=3600.0).try_mine()

    assert head_number() == 0
    assert snapshot() == before
    assert db.has_due_retractables(1, 0)


def test_eligibility_gate_still_applies(node, monkeypatch):
    seed(KIND_HEIGHT, 1)
    calls = []

    def not_our_turn(self, *args, **kwargs):
        calls.append(args)
        return False

    monkeypatch.setattr(TauConsensusEngine, "query_eligibility", not_our_turn)
    miner = SoleMiner(threshold=10, max_block_interval=3600.0)
    monkeypatch.setattr(createblock, "create_block_from_mempool",
                        lambda **kw: pytest.fail("must not build a block"))

    miner.try_mine()

    assert calls


def test_membership_gate_still_applies(node, monkeypatch):
    seed(KIND_HEIGHT, 1)
    chain_state._lifecycle_manager.active_validators = {"f" * 96}
    monkeypatch.setattr(createblock, "create_block_from_mempool",
                        lambda **kw: pytest.fail("must not build a block"))

    SoleMiner(threshold=10, max_block_interval=3600.0).try_mine()

    assert head_number() == 0


def test_due_wake_is_throttled(node, monkeypatch):
    seed(KIND_HEIGHT, 1)
    attempts = []
    monkeypatch.setattr(
        createblock, "create_block_from_mempool",
        lambda **kw: attempts.append(kw) or {"message": "lost"},
    )
    miner = SoleMiner(threshold=10, max_block_interval=3600.0)

    miner.try_mine()
    miner.try_mine()
    assert attempts == [{"wake_if_due": True}]

    miner._last_due_attempt -= 3.0
    miner.try_mine()
    assert len(attempts) == 2


def test_nonempty_mempool_keeps_the_ordinary_gates(node, monkeypatch):
    seed(KIND_HEIGHT, 50)
    db.add_mempool_tx('{"sender_pubkey": "%s"}' % SENDER, "t1", int(time.time() * 1000))
    monkeypatch.setattr(createblock, "create_block_from_mempool",
                        lambda **kw: pytest.fail("below threshold and interval"))

    SoleMiner(threshold=10, max_block_interval=3600.0).try_mine()
