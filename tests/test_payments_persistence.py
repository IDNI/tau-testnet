"""The programmable-payments books survive a restart, and fail atomically.

Mirrors test_retractable_persistence.py: the same commit/load cycle, the
same id-recompute validation on restore -- a stored row whose terms do
not reproduce its entry id, or a duplicated entry, refuses the load
instead of silently dropping part of a payment book.
"""
import json

import pytest

import chain_state
import db
from consensus.governance import ConsensusLifecycleManager
from consensus.payments import (
    DictLedger,
    GrantTerms,
    PayoutTerms,
    RouteTerms,
    StandingTerms,
)
from errors import DatabaseError

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
TS0 = 1_700_000_000
WEEK = 604_800


class _OpenGate:
    def allows_debit(self, payer, recipient, amount):
        return True


class _ZeroFees:
    def execution_fee(self, payer, recipient, amount):
        return 0


def _seed(lm):
    chain_state._balances.clear()
    chain_state._sequence_numbers.clear()
    chain_state._balances.update({A: 500, B: 7})
    chain_state._sequence_numbers.update({A: 3})
    chain_state._application_rules_state = "app rules"
    chain_state._consensus_rules_state = "consensus rules"
    chain_state._active_consensus_id = ""
    lm.quorum_policy = "majority"
    lm.eligibility_mode = ""
    lm.recompute_approval_threshold()
    chain_state._lifecycle_manager = lm
    return lm


def _populated():
    lm = _seed(ConsensusLifecycleManager(active_validators=[A]))
    books = lm.programmable_payments
    ledger = DictLedger({A: 100_000, B: 0, C: 0})
    books.standing.create(StandingTerms(
        payer=A, payee=B, amount=100, period_kind="week", start_ts=TS0,
        end_kind="count", end_value=3, max_fee_per_execution=10,
        genesis_hash="ab" * 32, sequence_number=0,
    ))
    books.standing.sweep(ts=TS0, network_id="", ledger=ledger,
                         gate=_OpenGate(), fees=_ZeroFees())
    books.routes.install(RouteTerms(owner=B, destinations=((C, 2000),)))
    rule_id = books.payouts.install(PayoutTerms(
        owner=A, candidates=((B, 500), (C, 500)), max_per_execution=1000,
        max_per_period=1000, period_kind="week", anchor_ts=TS0,
        sequence_number=0,
    ))
    books.payouts.execute(rule_id, "sale-1", {}, lambda inputs: [(0, 200)],
                          ts=TS0, ledger=ledger)
    books.grants.set_shared_cap(A, 5000)
    grant_id = books.grants.create(GrantTerms(
        grantor=A, grantee=B, principal=1000, period_cap=500,
        period_kind="week", start_ts=TS0, expires_ts=TS0 + 2 * WEEK,
        max_fee_per_execution=10, shared_cap=True, sequence_number=0,
    ), ledger=ledger)
    books.grants.draw(grant_id, 200, ts=TS0 + 10, ledger=ledger)
    return lm


def _reload():
    chain_state.commit_state_to_db("head-hash", 20)
    chain_state._lifecycle_manager = ConsensusLifecycleManager(
        active_validators=["d" * 96])
    assert chain_state.load_state_from_db() is True
    return chain_state._lifecycle_manager


def test_books_rows_root_and_meta_hash_round_trip(temp_database):
    lm = _populated()
    books = lm.programmable_payments
    rows_before = books.snapshot_rows()
    root_before = books.root()
    meta_before = lm.consensus_meta_hash()
    assert not books.is_empty()

    reloaded = _reload()

    assert reloaded.programmable_payments.snapshot_rows() == rows_before
    assert reloaded.programmable_payments.root() == root_before
    assert reloaded.consensus_meta_hash() == meta_before


def test_empty_books_reload_empty_with_the_same_hash(temp_database):
    lm = _seed(ConsensusLifecycleManager(active_validators=[A]))
    meta_before = lm.consensus_meta_hash()

    reloaded = _reload()

    assert reloaded.programmable_payments.is_empty()
    assert reloaded.consensus_meta_hash() == meta_before


def test_the_table_holds_exactly_the_snapshot_rows(temp_database):
    lm = _populated()
    chain_state.commit_state_to_db("head-hash", 20)
    stored = {
        row[0]: json.loads(row[1])
        for row in db._db_conn.execute(
            "SELECT section, row_json FROM programmable_payments_v1")
    }
    assert stored == lm.programmable_payments.snapshot_rows()


def test_a_duplicated_stored_grant_refuses_to_load(temp_database):
    _populated()
    chain_state.commit_state_to_db("head-hash", 20)
    with db._db_conn as conn:
        row = conn.execute(
            "SELECT row_json FROM programmable_payments_v1 "
            "WHERE section = 'grants'").fetchone()
        section = json.loads(row[0])
        section["grants"].append(section["grants"][0])
        conn.execute(
            "UPDATE programmable_payments_v1 SET row_json = ? "
            "WHERE section = 'grants'", (json.dumps(section),))

    chain_state._lifecycle_manager = ConsensusLifecycleManager(
        active_validators=["d" * 96])
    with pytest.raises(DatabaseError, match="programmable payments"):
        chain_state.load_state_from_db()
