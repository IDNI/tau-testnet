"""Bounty 01, stage 1 (FIX 2): standing payments + receive routes in
Tau clause form, at book level.

The clause form of stage 1, beside the declared forms PR-1 shipped:
the payer's (standing) or owner's (routes) own Tau clause, stepped by
the node through the existing policy-evaluation path, names the legs
of a settlement under the stage's shared output encoding (o30 count,
o31.. candidate/amount pairs); the books re-check every leg against
the candidate set, the caps and the balance, and settle atomically or
not at all. The clause machinery is G4's (the payout form's), one
stage earlier; the calendar/window/at-most-once machinery (standing)
and the credit-class check (routes) are the books' own and shared by
both forms.

Covered: the byte-for-byte pin (a declared entry's id, record bytes
and book root are the values the pre-clause code computed — the
goldens below were measured on the base tree before this form
existed, and a clause entry beside a declared one moves none of
them); id domain separation with the clause inside the hash; parse
form selection and the cross-field refusals; shape bounds; the input
maps and the leg decoder; clause execution under every shared check
(candidate set, per-execution cap, per-period attribution, max_total,
balance, at-most-once); the routes product cap; restore round-trips
and the Tau-form restore invariant; the capability records.
"""
import pytest

from consensus.receive_routes import (
    CREDIT_ORDINARY_TRANSFER,
    CREDIT_ROUTE_OUTPUT,
    FORM_DECLARED as ROUTE_FORM_DECLARED,
    FORM_TAU_CLAUSE as ROUTE_FORM_TAU_CLAUSE,
    ReceiveRouteBook,
    ReceiveRouteEntry,
    ReceiveRouteShapeError,
    decode_clause_legs as decode_route_legs,
    parse_install_receive_route,
    route_capabilities,
    route_clause_inputs,
    validate_route_shape,
)
from consensus.serialization import (
    encode_receive_route_entry,
    encode_standing_payment_record,
)
from consensus.standing_payments import (
    FORM_DECLARED,
    FORM_TAU_CLAUSE,
    SCHEDULE_DAILY,
    SCHEDULE_MONTHLY,
    StandingPaymentBook,
    StandingPaymentEntry,
    StandingPaymentShapeError,
    decode_clause_legs,
    parse_create_standing_payment,
    standing_clause_inputs,
    standing_payment_capabilities,
    validate_standing_payment_shape,
)

PAYER = "aa" * 48
RECIPIENT = "bb" * 48
DEST = "cc" * 48
OTHER = "dd" * 48
DAY = 86_400
TS = 1_800_000_000
ANCHOR_31 = 1_769_817_600  # 2026-01-31 00:00 UTC

CLAUSE = (
    "((o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 200 }:bv[64]))"
)

# Goldens measured on the base tree (18410d7b) BEFORE the clause form
# existed, for exactly the entries built by _golden_standing_entry /
# _golden_route_entry below. The byte-for-byte pin: the clause form's
# arrival must not move any of these values.
GOLDEN_STANDING_AUTH_ID = (
    "746df97e702971776b20c3ef43092703328991fb5aa4e62702cd36cfbf16f36c"
)
GOLDEN_STANDING_ROOT_SETTLED = (
    "531e86b76a36349842c0e9251c0af3ad0eb273377ec106dd02d8ba20b65ab2c9"
)
GOLDEN_STANDING_ROOT_UNSETTLED = (
    "63fa1d9a39b1bd53f2cb2469824ff36fc405096b8531d407147fa55eb515a1a6"
)
GOLDEN_ROUTE_ID = (
    "ef7fa348dbac84636c712832e71b31ecdde41dd4006ceb21b34db98f85d93477"
)
GOLDEN_ROUTE_ROOT = (
    "a8dbe0196757f73ae75db86d1ec93ab7db651d233fb2943ceb7fd623f57fc722"
)


def _u64(value):
    return int(value).to_bytes(8, "big").hex()


def _golden_standing_record_hex():
    """The pre-clause record encoding, rebuilt field by field from the
    original field order — independent of the code under test."""
    return (
        GOLDEN_STANDING_AUTH_ID
        + PAYER + RECIPIENT
        + _u64(500) + _u64(3) + _u64(31) + _u64(ANCHOR_31)
        + _u64(28 * DAY) + _u64(0) + _u64(12) + _u64(0) + _u64(0)
        + _u64(0) + _u64(0) + _u64(1)
        + (1).to_bytes(4, "big").hex() + _u64(0)  # settled periods [0]
        + _u64(500) + _u64(ANCHOR_31) + _u64(0) + _u64(0)
    )


def _golden_route_entry_hex():
    return (
        GOLDEN_ROUTE_ID
        + PAYER + DEST
        + _u64(2000) + _u64(0) + _u64(0) + _u64(0) + _u64(0) + _u64(1)
    )


def _golden_standing_entry():
    return StandingPaymentEntry(
        PAYER, RECIPIENT, 500, SCHEDULE_MONTHLY, 31, ANCHOR_31, 28 * DAY,
        0, 12, 0, 0, 0, False, 1,
    )


def _golden_route_entry():
    return ReceiveRouteEntry(PAYER, DEST, 2000, 0, 0, 0, 0, 1)


def _standing_entry(**kw):
    fields = dict(
        payer_pubkey=PAYER, recipient_pubkey=RECIPIENT, amount=500,
        schedule_kind=SCHEDULE_DAILY, signed_day=0, anchor_ts=TS - 100,
        window_seconds=3600, final_ts=0, max_occurrences=0,
        max_total=100_000, fee_limit=0, policy_version_ref=0,
        allow_catch_up=False, version=1,
    )
    fields.update(kw)
    return StandingPaymentEntry(**fields)


def _clause_standing(**kw):
    kw.setdefault("form", FORM_TAU_CLAUSE)
    kw.setdefault("clause_text", CLAUSE)
    return _standing_entry(**kw)


def _route_entry(**kw):
    fields = dict(
        owner_pubkey=PAYER, destination_pubkey=DEST, bps=2000,
        min_amount=0, activation_ts=0, expiry_ts=0, locked_until_ts=0,
        version=1,
    )
    fields.update(kw)
    return ReceiveRouteEntry(**fields)


def _clause_route(**kw):
    kw.setdefault("bps", 0)
    kw.setdefault("form", ROUTE_FORM_TAU_CLAUSE)
    kw.setdefault("clause_text", CLAUSE)
    return _route_entry(**kw)


# --- the byte-for-byte pin ------------------------------------------------------


def test_declared_standing_id_record_and_roots_unchanged():
    entry = _golden_standing_entry()
    assert entry.auth_id.hex() == GOLDEN_STANDING_AUTH_ID
    book = StandingPaymentBook()
    book.create(entry, ANCHOR_31)
    assert book.root().hex() == GOLDEN_STANDING_ROOT_UNSETTLED
    decision = book.execute(entry.auth_id, ANCHOR_31, 10_000)
    assert decision.executed and decision.amount == 500
    assert book.root().hex() == GOLDEN_STANDING_ROOT_SETTLED
    record = encode_standing_payment_record(*book.rows()[0])
    assert record.hex() == _golden_standing_record_hex()


def test_declared_route_id_record_and_root_unchanged():
    entry = _golden_route_entry()
    assert entry.route_id.hex() == GOLDEN_ROUTE_ID
    book = ReceiveRouteBook()
    book.install(entry, 1000)
    assert book.root().hex() == GOLDEN_ROUTE_ROOT
    assert encode_receive_route_entry(*book.rows()[0]).hex() == (
        _golden_route_entry_hex()
    )


def test_clause_entries_do_not_move_declared_standing_values():
    declared = _golden_standing_entry()
    book = StandingPaymentBook()
    book.create(declared, ANCHOR_31)
    book.execute(declared.auth_id, ANCHOR_31, 10_000)
    clause_entry = _clause_standing(
        payer_pubkey=OTHER, recipient_pubkey=PAYER, anchor_ts=ANCHOR_31,
        schedule_kind=SCHEDULE_MONTHLY, signed_day=31,
        window_seconds=28 * DAY, max_occurrences=12, max_total=0,
    )
    book.create(clause_entry, ANCHOR_31)
    assert declared.auth_id.hex() == GOLDEN_STANDING_AUTH_ID
    row = next(r for r in book.rows() if r[0] == declared.auth_id)
    assert encode_standing_payment_record(*row).hex() == (
        _golden_standing_record_hex()
    )


def test_clause_route_does_not_move_declared_route_values():
    declared = _golden_route_entry()
    book = ReceiveRouteBook()
    book.install(declared, 1000)
    book.install(_clause_route(owner_pubkey=OTHER), 1000)
    assert declared.route_id.hex() == GOLDEN_ROUTE_ID
    row = next(r for r in book.rows() if r[0] == declared.route_id)
    assert encode_receive_route_entry(*row).hex() == _golden_route_entry_hex()


# --- ids: domain separation, the clause inside the hash --------------------------


def test_standing_tau_id_is_domain_separated_and_binds_the_clause():
    declared = _standing_entry()
    clause = _clause_standing()
    assert clause.auth_id != declared.auth_id
    tampered = _clause_standing(clause_text=CLAUSE + " ")
    assert tampered.auth_id != clause.auth_id


def test_route_tau_id_is_domain_separated_and_binds_the_clause():
    declared = _route_entry(bps=0)
    clause = _clause_route()
    assert clause.route_id != declared.route_id
    tampered = _clause_route(clause_text=CLAUSE + " ")
    assert tampered.route_id != clause.route_id


# --- parse + shape ---------------------------------------------------------------


def _create_tx(**kw):
    tx = {
        "sender_pubkey": PAYER,
        "standing_recipient_pubkey": RECIPIENT,
        "standing_amount": 500,
        "standing_schedule": "daily",
        "standing_signed_day": 0,
        "standing_anchor_ts": TS - 100,
        "standing_window_seconds": 3600,
        "standing_final_ts": 0,
        "standing_max_occurrences": 0,
        "standing_max_total": 100_000,
        "standing_fee_limit": 0,
        "standing_policy_version_ref": 0,
        "standing_allow_catch_up": 0,
        "standing_version": 1,
    }
    tx.update(kw)
    return tx


def test_parse_standing_form_selection_and_cross_field_refusals():
    entry = parse_create_standing_payment(_create_tx())
    assert entry.form == FORM_DECLARED and entry.clause_text == ""
    entry = parse_create_standing_payment(
        _create_tx(standing_form=2, standing_clause=CLAUSE))
    assert entry.form == FORM_TAU_CLAUSE and entry.clause_text == CLAUSE
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment(_create_tx(standing_form=2))
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment(_create_tx(standing_clause=CLAUSE))
    with pytest.raises(StandingPaymentShapeError):
        parse_create_standing_payment(_create_tx(standing_form=3))


def test_standing_shape_clause_bounds():
    assert validate_standing_payment_shape(_clause_standing(), TS) is None
    problem = validate_standing_payment_shape(
        _clause_standing(clause_text=""), TS)
    assert "must carry a clause" in problem
    problem = validate_standing_payment_shape(
        _clause_standing(clause_text="x" * 8193), TS)
    assert "at most 8192 bytes" in problem
    problem = validate_standing_payment_shape(
        _standing_entry(clause_text=CLAUSE), TS)
    assert "carries no clause" in problem


def _install_route_tx(**kw):
    tx = {
        "sender_pubkey": PAYER,
        "route_destination_pubkey": DEST,
        "route_bps": 2000,
        "route_min_amount": 0,
        "route_activation_ts": 0,
        "route_expiry_ts": 0,
        "route_locked_until_ts": 0,
        "route_version": 1,
    }
    tx.update(kw)
    return tx


def test_parse_route_form_selection_and_shape():
    entry = parse_install_receive_route(_install_route_tx())
    assert entry.form == ROUTE_FORM_DECLARED and entry.clause_text == ""
    entry = parse_install_receive_route(
        _install_route_tx(route_form=2, route_clause=CLAUSE, route_bps=0))
    assert entry.form == ROUTE_FORM_TAU_CLAUSE
    assert validate_route_shape(entry, TS) is None
    with pytest.raises(ReceiveRouteShapeError):
        parse_install_receive_route(_install_route_tx(route_form=2))
    with pytest.raises(ReceiveRouteShapeError):
        parse_install_receive_route(_install_route_tx(route_clause=CLAUSE))
    # A Tau-form route carrying a bps is refused by the shared shape
    # screen: the clause names the share, the bps field is not a
    # second, conflicting decision.
    entry = parse_install_receive_route(
        _install_route_tx(route_form=2, route_clause=CLAUSE, route_bps=2000))
    assert "carries no bps" in validate_route_shape(entry, TS)
    problem = validate_route_shape(_route_entry(clause_text=CLAUSE), TS)
    assert "carries no clause" in problem


# --- input maps + leg decoding ----------------------------------------------------


def test_standing_clause_inputs_exact():
    entry = _clause_standing()
    values = standing_clause_inputs(entry, OTHER, TS, 777, 42)
    assert values[1] == "500"          # the signed per-period cap
    assert values[2] == "777"
    assert values[3] == "{ #x" + PAYER + " }:bv[384]"
    assert values[4] == "{ #x" + OTHER + " }:bv[384]"
    assert values[5] == str(TS)
    assert values[26] == "42"          # the period's recorded paid total


def test_route_clause_inputs_exact():
    entry = _clause_route()
    values = route_clause_inputs(entry, OTHER, 101, TS, 555)
    assert values[1] == "101"
    assert values[2] == "555"
    assert values[3] == "{ #x" + PAYER + " }:bv[384]"
    assert values[4] == "{ #x" + OTHER + " }:bv[384]"
    assert values[5] == str(TS)
    assert values[26] == "0"           # routes keep no per-period total


def test_decode_clause_legs_standing():
    entry = _clause_standing()
    legs, why = decode_clause_legs(
        entry, {"o30": "2", "o31": "0", "o32": "100", "o33": "0", "o34": "0"})
    assert legs == ((RECIPIENT, 100),) and why == ""  # zero legs dropped
    legs, why = decode_clause_legs(entry, {"o30": "1", "o31": "1", "o32": "5"})
    assert legs is None and "outside the declared set" in why
    legs, why = decode_clause_legs(entry, {"o31": "0", "o32": "5"})
    assert legs is None and "did not report a leg count" in why
    legs, why = decode_clause_legs(
        entry, {"o30": "33", "o31": "0", "o32": "5"})
    assert legs is None and "reported 33 legs" in why
    legs, why = decode_clause_legs(
        entry, {"o30": "1", "o31": "0", "o32": "soon"})
    assert legs is None and "unreadable leg" in why


def test_decode_clause_legs_route():
    entry = _clause_route()
    legs, why = decode_route_legs(
        entry, {"o30": "1", "o31": "0", "o32": "20"})
    assert legs == ((DEST, 20),) and why == ""
    legs, why = decode_route_legs(
        entry, {"o30": "1", "o31": "1", "o32": "20"})
    assert legs is None and "outside the declared set" in why


# --- standing clause execution -----------------------------------------------------


def _live_clause_book(**kw):
    book = StandingPaymentBook()
    entry = _clause_standing(**kw)
    book.create(entry, TS - 100)
    return book, entry


def test_clause_execution_settles_and_marks_once():
    book, entry = _live_clause_book()
    decision = book.execute(
        entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 200),))
    assert decision.executed and decision.amount == 200
    assert decision.legs == ((RECIPIENT, 200),)
    fact = book.paid_for_period(entry.auth_id, 0)
    assert fact is not None and fact.amount == 200
    assert book.total_executed(entry.auth_id) == (1, 200)
    again = book.execution_due(
        entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 200),))
    assert not again.executed and "already settled" in again.reason


def test_clause_execution_requires_and_rechecks_legs():
    book, entry = _live_clause_book()
    missing = book.execution_due(entry.auth_id, TS, 10_000)
    assert not missing.executed and "was not evaluated" in missing.reason
    outside = book.execution_due(
        entry.auth_id, TS, 10_000, clause_legs=((OTHER, 100),))
    assert not outside.executed and "outside the declared set" in outside.reason
    empty = book.execution_due(entry.auth_id, TS, 10_000, clause_legs=())
    assert not empty.executed and "named no legs" in empty.reason
    assert book.total_executed(entry.auth_id) == (0, 0)


def test_clause_leg_above_per_execution_cap_settles_nothing():
    book, entry = _live_clause_book()
    decision = book.execute(
        entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 501),))
    assert not decision.executed and "per-execution cap" in decision.reason
    assert book.total_executed(entry.auth_id) == (0, 0)
    assert book.paid_for_period(entry.auth_id, 0) is None


def test_clause_execution_max_total_and_balance_bounds():
    book, entry = _live_clause_book(max_total=400)
    decision = book.execution_due(
        entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 500),))
    assert not decision.executed and "end condition" in decision.reason
    book2, entry2 = _live_clause_book()
    decision = book2.execution_due(
        entry2.auth_id, TS, 150, clause_legs=((RECIPIENT, 200),))
    assert not decision.executed and "insufficient funds" in decision.reason


def test_clause_execution_attribution_over_catch_up():
    book, entry = _live_clause_book(
        anchor_ts=TS - 3 * DAY, window_seconds=3600, allow_catch_up=True)
    # Three periods are due (0, 1, 2); the clause names 1200 against a
    # 500 per-period cap: attribution fills oldest first, 500/500/200,
    # and every fact records its own period's attributed amount.
    decision = book.execute(
        entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 1200),))
    assert decision.executed and decision.amount == 1200
    assert decision.period_amounts == ((0, 500), (1, 500), (2, 200))
    assert [book.paid_for_period(entry.auth_id, p).amount
            for p in (0, 1, 2)] == [500, 500, 200]
    assert book.total_executed(entry.auth_id) == (3, 1200)
    # The i26 feed reads the recorded facts: TS-1 sits in period 2
    # (paid 200 by attribution); TS itself opens period 3, unpaid.
    assert book.period_paid_total(entry.auth_id, TS - 1) == 200
    assert book.period_paid_total(entry.auth_id, TS) == 0


def test_standing_restore_round_trip_and_tau_invariant():
    book, entry = _live_clause_book()
    book.execute(entry.auth_id, TS, 10_000, clause_legs=((RECIPIENT, 200),))
    declared = _standing_entry(payer_pubkey=OTHER)
    book.create(declared, TS - 100)
    clone = StandingPaymentBook.restore(book.rows(), book.fact_rows())
    assert clone.root() == book.root()
    rows = [list(r) for r in book.rows()]
    tau_row = next(r for r in rows if r[0] == entry.auth_id)
    tau_row[16] += 1  # total_paid no longer matches the facts
    with pytest.raises(ValueError):
        StandingPaymentBook.restore(
            [tuple(r) for r in rows], book.fact_rows())


# --- routes clause application -------------------------------------------------------


def test_apply_route_clause_splits_within_cap():
    book = ReceiveRouteBook()
    book.install(_clause_route(), TS)
    app = book.apply_route(
        PAYER, 101, CREDIT_ORDINARY_TRANSFER, TS,
        clause_legs=((DEST, 20),))
    assert app.applied and app.routed == 20 and app.net == 81
    assert app.destination_pubkey == DEST


def test_apply_route_clause_refusals_land_whole():
    book = ReceiveRouteBook()
    book.install(_clause_route(), TS)
    # Above the product cap: floor(101 * 9000 / 10000) = 90.
    app = book.apply_route(
        PAYER, 101, CREDIT_ORDINARY_TRANSFER, TS,
        clause_legs=((DEST, 95),))
    assert not app.applied and app.routed == 0 and app.net == 101
    assert "product cap" in app.reason
    # A leg outside the candidate set.
    app = book.apply_route(
        PAYER, 101, CREDIT_ORDINARY_TRANSFER, TS,
        clause_legs=((OTHER, 10),))
    assert not app.applied and "outside the declared set" in app.reason
    # No legs handed in (the clause was not stepped / produced none).
    app = book.apply_route(PAYER, 101, CREDIT_ORDINARY_TRANSFER, TS)
    assert not app.applied and "was not evaluated" in app.reason
    app = book.apply_route(
        PAYER, 101, CREDIT_ORDINARY_TRANSFER, TS, clause_legs=())
    assert not app.applied and "no routed share" in app.reason


def test_apply_route_clause_class_check_stays_first():
    book = ReceiveRouteBook()
    book.install(_clause_route(), TS)
    # A route output never triggers a route, in either form: the book
    # refuses on the class before any leg is consulted.
    app = book.apply_route(
        PAYER, 101, CREDIT_ROUTE_OUTPUT, TS, clause_legs=((DEST, 20),))
    assert not app.applied and "never routes" in app.reason


def test_route_restore_round_trip():
    book = ReceiveRouteBook()
    book.install(_clause_route(), TS)
    book.install(_route_entry(owner_pubkey=OTHER), TS)
    clone = ReceiveRouteBook.restore(book.rows())
    assert clone.root() == book.root()
    assert clone.get(PAYER).form == ROUTE_FORM_TAU_CLAUSE


# --- capability records -----------------------------------------------------------------


def test_capabilities_pin_the_clause_forms():
    caps = standing_payment_capabilities()
    assert caps["forms"] == {"declared": 1, "tau_clause": 2}
    assert caps["clause_form"]["candidate_set"].startswith("the signed recipient")
    assert caps["clause_form"]["max_clause_bytes"] == 8192
    rcaps = route_capabilities()
    assert rcaps["forms"] == {"declared": 1, "tau_clause": 2}
    assert rcaps["clause_form"]["candidate_set"].startswith("the signed destination")
    assert rcaps["clause_form"]["max_clause_bytes"] == 8192
