"""Mempool admission for the programmable-payments transaction types.

Admission and block apply share ONE check per action (the books'
``can_*`` functions); these tests pin the admission half against a tip
view over a real ProgrammablePayments instance, in the idiom of
test_retractable_admission.py. The Tau-measured half of execute-type
checks (policy verdict, fee) cannot run at admission -- it runs at apply
through the same book check -- so admission screens the state
conditions, which is what these cases exercise.
"""
from unittest.mock import MagicMock

import pytest
from py_ecc.bls import G2Basic

from consensus.admission import TipAdmissionView, validate_mempool_admission
from consensus.payments import (
    GRANT_ESCROW_PUBKEY,
    DictLedger,
    GrantTerms,
    PayoutTerms,
    ProgrammablePayments,
    StandingTerms,
)

ALICE = G2Basic.SkToPk(11111).hex()
BOB = G2Basic.SkToPk(44444).hex()
CAROL = G2Basic.SkToPk(55555).hex()
TS = 1_700_000_000
WEEK = 604_800
FAR = 9_999_999_999
GENESIS_HASH = "ab" * 32


@pytest.fixture
def books():
    return ProgrammablePayments()


@pytest.fixture
def tip(books):
    balances = {}
    view = MagicMock(spec=TipAdmissionView)
    view.next_block_height = 50
    view.tip_timestamp = TS
    view.next_block_timestamp = TS
    view.payment_books.return_value = books
    view.balance_of.side_effect = lambda pubkey: balances.get(pubkey, 0)
    view.payment_balances = balances
    return view


def _base(tx_type, sender, seq=0):
    return {
        "tx_type": tx_type,
        "sender_pubkey": sender,
        "sequence_number": seq,
        "expiration_time": FAR,
        "expire_at_height": 70,
        "fee_limit": "100",
    }


def standing_terms(**over):
    fields = dict(
        payer=ALICE, payee=BOB, amount=100, period_kind="week",
        start_ts=TS, end_kind="count", end_value=2,
        max_fee_per_execution=10, genesis_hash=GENESIS_HASH,
        max_catch_up=0, sequence_number=0,
    )
    fields.update(over)
    return StandingTerms(**fields)


def standing_create_tx(**over):
    terms = standing_terms()
    tx = _base("standing_authorization_create", ALICE)
    tx.update({
        "payer": terms.payer, "payee": terms.payee, "amount": terms.amount,
        "period_kind": terms.period_kind, "start_ts": terms.start_ts,
        "end_kind": terms.end_kind, "end_value": terms.end_value,
        "max_fee_per_execution": terms.max_fee_per_execution,
        "genesis_hash": terms.genesis_hash,
        "max_catch_up": terms.max_catch_up,
    })
    tx.update(over)
    return tx


# --- standing authorizations ---------------------------------------------------

def test_standing_create_is_admitted_and_reports_the_id(tip, books):
    result = validate_mempool_admission(standing_create_tx(), tip)
    assert result.is_valid is True, result.error
    assert result.data["authorization_id"] == standing_terms().auth_id.hex()


def test_standing_create_duplicate_is_refused(tip, books):
    books.standing.create(standing_terms())
    result = validate_mempool_admission(standing_create_tx(), tip)
    assert result.is_valid is False


def test_standing_create_for_another_payer_is_refused(tip, books):
    tx = standing_create_tx()
    tx["sender_pubkey"] = BOB
    result = validate_mempool_admission(tx, tip)
    assert result.is_valid is False


def test_standing_cancel_admission_follows_the_book(tip, books):
    tx = _base("standing_authorization_cancel", ALICE, seq=1)
    tx["authorization_id"] = standing_terms().auth_id.hex()
    assert validate_mempool_admission(tx, tip).is_valid is False

    books.standing.create(standing_terms())
    assert validate_mempool_admission(tx, tip).is_valid is True

    tx["sender_pubkey"] = BOB
    assert validate_mempool_admission(tx, tip).is_valid is False


# --- grants --------------------------------------------------------------------

def _grant_in_books(books):
    ledger = DictLedger({ALICE: 10_000})
    terms = GrantTerms(
        grantor=ALICE, grantee=BOB, principal=1000, period_cap=500,
        period_kind="week", start_ts=TS, expires_ts=TS + 2 * WEEK,
        max_fee_per_execution=10, sequence_number=0,
    )
    grant_id = books.grants.create(terms, ledger=ledger)
    return terms, grant_id


def test_grant_draw_admission(tip, books):
    _terms, grant_id = _grant_in_books(books)
    tip.payment_balances[GRANT_ESCROW_PUBKEY] = 1000

    draw = _base("payment_grant_draw", BOB)
    draw.update({"grant_id": grant_id.hex(), "amount": 200})
    assert validate_mempool_admission(draw, tip).is_valid is True

    draw["sender_pubkey"] = ALICE
    assert validate_mempool_admission(draw, tip).is_valid is False

    draw["sender_pubkey"] = BOB
    draw["amount"] = 600  # over the signed per-period cap
    assert validate_mempool_admission(draw, tip).is_valid is False


def test_grant_refund_claim_waits_for_the_deadline(tip, books):
    _terms, grant_id = _grant_in_books(books)
    claim = _base("payment_grant_refund_claim", CAROL)
    claim["grant_id"] = grant_id.hex()
    assert validate_mempool_admission(claim, tip).is_valid is False

    tip.next_block_timestamp = TS + 2 * WEEK
    assert validate_mempool_admission(claim, tip).is_valid is True


def test_shared_cap_set_admission(tip, books):
    tx = _base("payment_shared_cap_set", ALICE)
    tx.update({"payer": ALICE, "limit": 5000})
    assert validate_mempool_admission(tx, tip).is_valid is True

    books.grants.set_shared_cap(ALICE, 5000)
    assert validate_mempool_admission(tx, tip).is_valid is False


# --- payout rules ---------------------------------------------------------------

def test_payout_execute_replay_is_refused_at_admission(tip, books):
    terms = PayoutTerms(
        owner=ALICE, candidates=((BOB, 500), (CAROL, 500)),
        max_per_execution=1000, max_per_period=1000,
        period_kind="week", anchor_ts=TS, sequence_number=0,
    )
    rule_id = books.payouts.install(terms)
    ledger = DictLedger({ALICE: 10_000})
    books.payouts.execute(rule_id, "sale-1", {}, lambda inputs: [(0, 200)],
                          ts=TS, ledger=ledger)

    tx = _base("payout_rule_execute", ALICE, seq=1)
    tx.update({
        "payout_rule_id": rule_id.hex(),
        "event_id": "sale-1",
        "legs": [[0, 200]],
    })
    result = validate_mempool_admission(tx, tip)
    assert result.is_valid is False
    assert result.code == "PAYOUT_ALREADY_SETTLED"

    tx["event_id"] = "sale-2"
    assert validate_mempool_admission(tx, tip).is_valid is True


# --- routes ---------------------------------------------------------------------

def test_route_install_and_remove_admission(tip, books):
    install = _base("payment_route_install", BOB)
    install.update({"owner": BOB, "destinations": [[CAROL, 2000]]})
    assert validate_mempool_admission(install, tip).is_valid is True

    remove = _base("payment_route_remove", BOB, seq=1)
    remove["owner"] = BOB
    assert validate_mempool_admission(remove, tip).is_valid is False

    from consensus.payments import RouteTerms
    books.routes.install(RouteTerms(owner=BOB, destinations=((CAROL, 2000),)))
    assert validate_mempool_admission(remove, tip).is_valid is True
    # A second install over the live route is a duplicate, not an update.
    assert validate_mempool_admission(install, tip).is_valid is False
