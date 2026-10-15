"""A real engine under a budget it cannot meet: deferred or left for a retry, never judged.

A revision costs tens of milliseconds, so a one-millisecond budget always runs out,
and replay and block-level work must not run out with it.
"""
import logging
from unittest.mock import patch

import pytest

import chain_state
import config
import tau_authority as auth
import tau_commit as tc
from commands import createblock

import test_worker_lost_native as wln
from test_worker_lost_native import _mining_allowed, authority  # noqa: F401 - fixtures

pytestmark = wln.pytestmark

TINY = 0.001


@pytest.fixture(autouse=True)
def _no_deferrals():
    createblock._deferred.clear()
    yield
    createblock._deferred.clear()


# --- mining -----------------------------------------------------------------------

def test_a_request_that_outruns_the_mining_budget_defers_its_transaction(authority, monkeypatch):
    tx_hash = wln._queue_a_rule("budget_mining")
    head = wln._head()

    monkeypatch.setattr(config, "MINING_BUDGET", TINY)
    out = createblock.create_block_from_mempool()

    assert "error" in out and "block_hash" not in out, out
    assert "evaluator lost" in out["error"] and "no answer within" in out["error"], out
    assert wln._head() == head, "a block landed although its evaluation timed out"
    wln._queued(tx_hash)
    assert set(createblock._deferred) == {tx_hash}
    wln._assert_serves_no_dead_worker(authority)

    # Backing off: nothing left to mine, and the transaction is not evaluated again.
    monkeypatch.setattr(config, "MINING_BUDGET", 60)
    idle = createblock.create_block_from_mempool()
    assert "error" not in idle and idle["message"].startswith("Mempool is empty"), idle
    wln._queued(tx_hash)

    # Replay and the proposal behind it never carry the budget: the history is
    # replayed into a fresh worker under a budget no rule revision could meet.
    monkeypatch.setattr(config, "MINING_BUDGET", TINY)
    empty = createblock.create_block_from_mempool(allow_empty=True)
    assert "block_hash" in empty, empty
    wln._queued(tx_hash)

    monkeypatch.setattr(config, "MINING_BUDGET", 60)
    createblock._deferred.clear()
    mined = createblock.create_block_from_mempool()
    assert "error" not in mined, mined
    assert wln._included(tx_hash), "the transaction was not included once it fit the budget"
    assert authority.state == auth.ACTIVE and authority.active


# --- validation ----------------------------------------------------------------------

def test_a_block_that_outruns_the_validation_ceiling_is_left_for_a_later_retry(
        authority, monkeypatch, caplog):
    """The miner's own artifact is refused, so ingestion evaluates the block itself
    under the ceiling: not accepted now, not invalid, transactions kept."""
    tx_hash = wln._queue_a_rule("budget_validation")
    head = wln._head()
    ingestion = []
    real_process = chain_state.process_new_block

    def _spy(block):
        result = real_process(block)
        ingestion.append(result)
        return result

    monkeypatch.setattr(config, "VALIDATION_CEILING", TINY)
    with patch.object(tc.registry(), "offer", side_effect=RuntimeError("no artifact")), \
         patch.object(chain_state, "process_new_block", _spy), \
         caplog.at_level(logging.ERROR, logger="chain_state"):
        out = createblock.create_block_from_mempool()

    assert ingestion == [False], ingestion
    assert "error" in out and "block_hash" not in out, out
    assert wln._head() == head
    wln._queued(tx_hash)
    assert "validation ceiling" in caplog.text and "not accepted now" in caplog.text
    assert tx_hash in caplog.text, "the log does not name the transaction that outran the ceiling"
    assert createblock._deferred == {}, "the miner's own healthy round deferred something"
    wln._assert_serves_no_dead_worker(authority)

    monkeypatch.setattr(config, "VALIDATION_CEILING", 600)
    mined = createblock.create_block_from_mempool()
    assert "error" not in mined, mined
    assert wln._included(tx_hash)
    assert authority.state == auth.ACTIVE and authority.active
