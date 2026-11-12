"""Admission and block apply read approval_slots_active from one source.

Apply reads the flag of the lifecycle manager. The chain_state row of the
database can differ from it, so admission must not read the row. The policy is
an unguarded o5 rule: it is a routed clause while the slots are active, and an
unscoped rule otherwise.
"""
import pytest

import chain_state
import config
import db
from consensus.admission import TipAdmissionView, validate_mempool_admission
from consensus.governance import ConsensusLifecycleManager
from test_user_rule_apply_screen import (
    MALLORY, ROUTED_O5, TX_ID, _apply, _outcome, _tx,
)

STATES = [
    pytest.param(False, False, id="database-0-lifecycle-off"),
    pytest.param(True, True, id="database-1-lifecycle-on"),
    pytest.param(True, False, id="database-1-lifecycle-off"),
    pytest.param(False, True, id="database-0-lifecycle-on"),
]


@pytest.fixture
def tip_state(tmp_path):
    prev_path = config.STRING_DB_PATH
    prev_conn = db._db_conn
    prev_lm = chain_state._lifecycle_manager
    config.set_database_path(str(tmp_path / "slot_parity.sqlite"))
    db._db_conn = None
    db.init_db()
    chain_state._lifecycle_manager = ConsensusLifecycleManager(active_validators=[MALLORY])
    yield
    db._db_conn.close()
    db._db_conn = prev_conn
    config.set_database_path(prev_path)
    chain_state._lifecycle_manager = prev_lm


def _set_flags(database, lifecycle):
    db.set_chain_state_value("approval_slots_active", "1" if database else "0")
    if lifecycle:
        chain_state._lifecycle_manager.activate_approval_slots()


def _apply_at_tip(tx):
    """Apply one tx on top of the tip lifecycle, as the miner does."""
    lifecycle = chain_state._lifecycle_manager.approval_slots_active
    return _apply(tx, "slots_on" if lifecycle else "slots_off")


@pytest.mark.parametrize("database,lifecycle", STATES)
def test_admission_and_apply_agree_on_an_unguarded_policy(tip_state, database, lifecycle):
    _set_flags(database, lifecycle)
    admitted = validate_mempool_admission(_tx(ROUTED_O5), TipAdmissionView())
    result, _, _, _ = _apply_at_tip(_tx(ROUTED_O5))

    accepted_at_apply = result.accepted_tx_ids == [TX_ID]
    assert admitted.is_valid == accepted_at_apply, (
        admitted.code, admitted.error, _outcome(result).reason)
    assert admitted.is_valid == lifecycle


@pytest.mark.parametrize("database,lifecycle", STATES)
def test_tip_view_follows_the_lifecycle(tip_state, database, lifecycle):
    _set_flags(database, lifecycle)
    assert TipAdmissionView().approval_slots_active is lifecycle

