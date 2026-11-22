"""Admission screens for payout rules and grants (Bounty 01, #63).

Mirrors tests/test_routes_admission.py: validators run against a
stub tip view whose rows are written through the real db writers.
"""

import pytest
from py_ecc.bls import G2Basic

import db
from consensus.admission import (
    validate_grant_create_payload,
    validate_grant_draw_payload,
    validate_payout_execute_payload,
    validate_payout_install_payload,
    validate_payout_remove_payload,
)
from consensus.facade import TipAdmissionView
from consensus.grants import GrantBook, GrantTerms
from consensus.payouts import PAYOUT_STREAM_INDEX, PayoutBook, PayoutTerms

pytestmark = pytest.mark.usefixtures("isolated_chain_state")

JAN1 = 1767225600
DEC1 = 1764547200
WEEK = 604800


def _pk(seed):
    return G2Basic.SkToPk(seed).hex()


ALICE = _pk(11111)
BOB = _pk(44444)
CAROL = _pk(55555)


class _View(TipAdmissionView):
    def __init__(self, ts):
        self._ts = ts

    @property
    def next_block_timestamp(self):
        return self._ts

    @property
    def next_block_height(self):
        return 100


def _install_payout_row(ts=JAN1):
    book = PayoutBook()
    terms = PayoutTerms(
        owner=ALICE, max_per_execution=1000, max_per_period=1500,
        recipients=(BOB, CAROL), anchor_ts=JAN1, sequence_number=1,
    )
    book.install(terms)
    db.init_db()
    with db._db_lock:
        db._write_payout_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()
    return terms


def _install_grant_row():
    book = GrantBook()
    terms = GrantTerms(
        sender=ALICE, recipient=BOB, total=5000, cap_per_period=500,
        opens_at=DEC1, deadline=DEC1 + 4 * WEEK, sequence_number=1,
    )
    book.create(terms)
    db.init_db()
    with db._db_lock:
        db._write_grant_rows({"rows": book.snapshot_rows()})
        db._db_conn.commit()
    return terms


def _payout_install_tx(**kw):
    tx = {
        "tx_type": "payout_rule_install",
        "sender_pubkey": ALICE,
        "max_per_execution": 1000,
        "max_per_period": 1500,
        "recipients": [BOB, CAROL],
        "period_kind": 2,
        "anchor_ts": JAN1,
        "sequence_number": 1,
    }
    tx.update(kw)
    return tx


def test_payout_install_admission():
    view = _View(JAN1)
    ok = validate_payout_install_payload(_payout_install_tx(), view)
    assert ok.is_valid, ok
    bad = validate_payout_install_payload(
        _payout_install_tx(max_per_period=10), view)
    assert not bad.is_valid
    # The owner is parsed FROM sender_pubkey (as with routes), so a
    # sender/owner mismatch cannot be expressed in this payload; the
    # signature check upstream binds the tx to that sender.


def test_payout_execute_admission():
    terms = _install_payout_row()
    view = _View(JAN1)
    # No clause published yet -> refused at admission too.
    tx = {
        "tx_type": "payout_execute", "sender_pubkey": CAROL,
        "owner": ALICE, "settlement_id": "s1", "gross": 101,
    }
    refused = validate_payout_execute_payload(tx, view)
    assert not refused.is_valid
    assert refused.code == "NO_PAYOUT_CLAUSE"

    import chain_state
    from consensus.governance import ConsensusLifecycleManager
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.rule_offers.accepted_clauses[(ALICE, PAYOUT_STREAM_INDEX)] = "always (o20[t]=1)."

    class _ClauseView(_View):
        def clause_for(self, owner, stream):
            return lm.rule_offers.clause_for(owner, stream)

    ok = validate_payout_execute_payload(tx, _ClauseView(JAN1))
    assert ok.is_valid, ok
    unknown = validate_payout_execute_payload(
        {**tx, "owner": BOB}, _ClauseView(JAN1))
    assert not unknown.is_valid


def test_payout_remove_admission():
    terms = _install_payout_row()
    view = _View(JAN1)
    tx = {
        "tx_type": "payout_rule_remove", "sender_pubkey": ALICE,
        "rule_id": terms.rule_id,
    }
    assert validate_payout_remove_payload(tx, view).is_valid
    bad = validate_payout_remove_payload({**tx, "rule_id": "0" * 64}, view)
    assert not bad.is_valid


def test_grant_create_admission():
    view = _View(DEC1)
    tx = {
        "tx_type": "grant_create", "sender_pubkey": ALICE,
        "recipient_pubkey": BOB, "total": 5000, "cap_per_period": 500,
        "opens_at": DEC1, "deadline": DEC1 + 4 * WEEK, "sequence_number": 1,
    }
    assert validate_grant_create_payload(tx, view).is_valid
    undrawable = validate_grant_create_payload(
        {**tx, "opens_at": DEC1 + 4 * WEEK}, view)
    assert not undrawable.is_valid
    _install_grant_row()
    dupe = validate_grant_create_payload(tx, view)
    assert not dupe.is_valid
    assert dupe.code == "DUPLICATE_GRANT"


def test_grant_draw_admission():
    terms = _install_grant_row()
    view = _View(DEC1 + 60)
    tx = {
        "tx_type": "grant_draw", "sender_pubkey": BOB,
        "grant_id": terms.grant_id, "amount": 500,
    }
    # No grant clause published by the sender yet -> refused at
    # admission too, mirroring the payout clause gate.
    refused = validate_grant_draw_payload(tx, view)
    assert not refused.is_valid
    assert refused.code == "NO_GRANT_CLAUSE"

    from consensus.governance import ConsensusLifecycleManager
    from consensus.grants import CANONICAL_GRANT_CLAUSE, GRANT_STREAM_INDEX
    lm = ConsensusLifecycleManager(active_validators=[ALICE])
    lm.rule_offers.accepted_clauses[(ALICE, GRANT_STREAM_INDEX)] = (
        CANONICAL_GRANT_CLAUSE
    )

    class _ClauseView(_View):
        def clause_for(self, owner, stream):
            return lm.rule_offers.clause_for(owner, stream)

    view = _ClauseView(DEC1 + 60)
    assert validate_grant_draw_payload(tx, view).is_valid
    too_much = validate_grant_draw_payload({**tx, "amount": 5001}, view)
    assert not too_much.is_valid
    stranger = validate_grant_draw_payload({**tx, "sender_pubkey": CAROL}, view)
    assert not stranger.is_valid
    early = validate_grant_draw_payload(tx, _ClauseView(DEC1 - 10))
    assert not early.is_valid
