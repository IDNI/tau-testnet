"""Receive routes (#35): parsing, shape, the book, settlement (model only).

No block apply here: the terms, the streams and the book are pure. Block
apply lives in tests/test_routes_apply.py.
"""
import pytest

from consensus.payout import PayoutShapeError, PayoutTerms
from consensus.routes import (
    KIND_BLOCKS,
    RouteBook,
    RouteRefused,
    RouteShapeError,
    RouteTerms,
    describe,
    parse_route_revoke,
    parse_route_set,
    parse_route_spec,
    route_inputs,
    route_spec_text,
    settle_route,
    validate_terms_shape,
)
from tests.test_standing_apply import ALICE, BOB, CAROL, HEIGHT, TS

FULL = "always ( o30[t]:bv[24] = i27[t]:bv[24] )."
FIFTH = "always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] )."


def _fields(**over):
    tx = {"sender_pubkey": ALICE, "sequence_number": 7, "rule_text": FIFTH,
          "destination": BOB, "min_amount": 0, "active_from": 0,
          "expiry_blocks": HEIGHT + 500}
    tx.update(over)
    return tx


def _terms(**over):
    return parse_route_set(_fields(**over))


# --- parsing -------------------------------------------------------------------


def test_parse_set_reads_every_field():
    terms = _terms(min_amount=10, active_from=HEIGHT + 5)
    assert terms.account_pubkey == ALICE and terms.sequence_number == 7
    assert terms.destination == BOB and terms.min_amount == 10
    assert terms.active_from == HEIGHT + 5 and terms.expires_at == HEIGHT + 500
    assert terms.kind == KIND_BLOCKS
    assert terms.rule_id == parse_route_set(_fields(min_amount=10, active_from=HEIGHT + 5)).rule_id


def test_parse_set_defaults_min_amount_and_active_from_to_zero():
    terms = parse_route_set({"sender_pubkey": ALICE, "sequence_number": 0,
                             "rule_text": FULL, "destination": BOB,
                             "expiry_seconds": TS + 500})
    assert (terms.min_amount, terms.active_from) == (0, 0)
    assert terms.kind == 1  # seconds


@pytest.mark.parametrize("over, why", [
    ({"destination": ALICE}, "may not be the account itself"),
    ({"destination": "zz"}, "96-hex-char public key"),
    ({"destination": None}, "96-hex-char public key"),
    ({"expiry_blocks": None}, "exactly one of expiry_blocks and expiry_seconds"),
    ({"expiry_seconds": TS + 9}, "exactly one of expiry_blocks and expiry_seconds"),
    ({"min_amount": -1}, "unsigned 64-bit integer"),
    ({"min_amount": 2 ** 64}, "unsigned 64-bit integer"),
    ({"active_from": True}, "unsigned 64-bit integer"),
    ({"rule_text": ""}, "non-empty string"),
    ({"rule_text": "always ( o31[t]:bv[24] = i27[t]:bv[24] )."}, "not part of the payout ABI"),
    ({"rule_text": "always ( o30[t]:bv[24] = i13[t]:bv[384] )."}, "may not read i13"),
    ({"rule_text": "always ( o30[t]:bv[24] = i40[t]:bv[24] )."}, "may not read i40"),
    ({"rule_text": "always ( o30[t]:bv[24] = i26[t]:bv[24] )."}, "may not read i26"),
    ({"rule_text": "always ( o5[t]:bv[24] = i27[t]:bv[24] )."}, "not part of the payout ABI"),
    ({"rule_text": "always ( o30[t]:bv[24] = { #x000001 }:bv[24] )."}, "read at least one input"),
    ({"rule_text": "always ( o30[t-1]:bv[24] = i27[t]:bv[24] )."}, ""),
])
def test_parse_set_refuses_bad_terms(over, why):
    with pytest.raises(RouteShapeError) as exc:
        parse_route_set(_fields(**over))
    assert why in str(exc.value)


def test_parse_revoke_reads_the_sender():
    assert parse_route_revoke({"sender_pubkey": ALICE}) == ALICE
    with pytest.raises(RouteShapeError):
        parse_route_revoke({"sender_pubkey": "zz"})


# --- spec text -----------------------------------------------------------------


def test_spec_text_round_trips_and_refuses_non_canonical():
    terms = _terms()
    text = route_spec_text(_fields(), terms.sequence_number)
    assert parse_route_spec(text, ALICE) == terms
    # Same terms, different key order or spacing: not canonical.
    assert route_spec_text(_fields(), 7) == text
    with pytest.raises(RouteShapeError):
        parse_route_spec(text.replace('"destination"', '"destination" '), ALICE)
    with pytest.raises(RouteShapeError):
        parse_route_spec(route_spec_text(_fields()), ALICE)  # no sequence anywhere
    with pytest.raises(RouteShapeError):
        parse_route_spec(text, ALICE, sequence_number=8)  # sequence in both places


# --- shape validation ------------------------------------------------------------


def test_validate_terms_shape():
    assert validate_terms_shape(_terms(), HEIGHT, TS) is None
    assert "already ended" in validate_terms_shape(
        _terms(expiry_blocks=HEIGHT), HEIGHT, TS)
    assert "longer than the lifetime limit" in validate_terms_shape(
        _terms(expiry_blocks=HEIGHT + 10_000_001), HEIGHT, TS)
    assert "before expires_at" in validate_terms_shape(
        _terms(active_from=HEIGHT + 500), HEIGHT, TS)
    assert "over the largest transfer" in validate_terms_shape(
        _terms(min_amount=2 ** 24), HEIGHT, TS)


# --- inputs and settlement -------------------------------------------------------


def test_route_inputs_carry_the_arrival():
    values = route_inputs(_terms(), gross=101, payer=CAROL,
                          parent_balance=1_000, height=HEIGHT + 1, ts=TS + 1)
    assert values == {2: "1000", 5: str(TS + 1), 6: str(HEIGHT + 1),
                      27: "101", 28: "{ #x" + CAROL + " }:bv[384]"}
    capped = route_inputs(_terms(), gross=1, payer=CAROL,
                          parent_balance=2 ** 24 + 5, height=HEIGHT, ts=TS)
    assert capped[2] == str(2 ** 24 - 1)


def test_settle_route():
    terms = _terms()
    assert settle_route(terms, {"o30": "5"}, gross=101) == 5
    assert settle_route(terms, {}, gross=101) == 0
    assert settle_route(terms, {"o30": "101"}, gross=101) == 101
    with pytest.raises(RouteRefused, match="over the gross credit"):
        settle_route(terms, {"o30": "102"}, gross=101)


# --- the book --------------------------------------------------------------------


def test_book_install_replace_revoke_expire():
    book = RouteBook()
    assert book.is_empty() and book.count() == 0
    terms = _terms()
    ok, reason = book.can_admit_set(terms, HEIGHT, TS)
    assert (ok, reason) == (True, "")
    assert book.install(terms, HEIGHT) is None
    assert book.get(ALICE) == terms and book.state_of(ALICE).anchor == HEIGHT
    assert book.count() == 1 and not book.is_empty()
    ok, reason = book.can_admit_set(terms, HEIGHT, TS)
    assert (ok, reason) == (False, "this receive route is already installed")

    replaced = book.install(_terms(rule_text=FULL), HEIGHT + 1)
    assert replaced == terms.rule_id and book.count() == 1
    assert book.resolved_count == 1  # the replacement folded into the commitment

    gone = book.revoke(ALICE)
    assert gone.destination == BOB and book.count() == 0
    assert book.resolved_count == 2
    ok, reason = book.can_admit_revoke(ALICE)
    assert (ok, reason) == (False, "the account has no receive route")

    book.install(_terms(), HEIGHT)
    assert book.expire(HEIGHT, TS) == []
    gone = book.expire(HEIGHT + 500, TS)
    assert [t.account_pubkey for t in gone] == [ALICE] and book.count() == 0

    seconds = _terms(expiry_blocks=None, expiry_seconds=TS + 10)
    book.install(seconds, TS)
    assert book.has_expiring(HEIGHT, TS + 10)
    assert [t.account_pubkey for t in book.expire(HEIGHT, TS + 10)] == [ALICE]


def test_book_restore_round_trips_and_refuses_a_tampered_id():
    book = RouteBook()
    book.install(_terms(), HEIGHT)
    book.install(parse_route_set(_fields(sender_pubkey=BOB, sequence_number=3,
                                         destination=CAROL)), HEIGHT)
    rows = book.store_rows()
    count, acc = book.resolved_state()
    restored = RouteBook.restore(rows, count, acc)
    assert restored.root() == book.root()
    assert restored.get(ALICE) == book.get(ALICE)
    assert restored.get(BOB).destination == CAROL

    bad = [list(r) for r in rows]
    bad[0][0] = bytes(32)  # the stored id no longer recomputes
    with pytest.raises(ValueError, match="does not match its terms"):
        RouteBook.restore([tuple(r) for r in bad], count, acc)


def test_book_root_changes_on_install_and_is_deterministic():
    one, two = RouteBook(), RouteBook()
    one.install(_terms(), HEIGHT)
    two.install(_terms(), HEIGHT)
    assert one.root() == two.root()
    assert RouteBook().root() != one.root()
    assert describe(one.get(ALICE), one.state_of(ALICE), height=HEIGHT, ts=TS)[
        "active"] is True


# --- sealed payout terms (the id binds the seal) ---------------------------------


def test_sealed_and_unsealed_terms_have_different_ids():
    base = {"account_pubkey": ALICE, "sequence_number": 1, "body": "x",
            "slots": (BOB,), "cap_per_execution": 100, "cap_per_period": 250,
            "kind": 0, "period": 10, "expires_at": HEIGHT + 500}
    plain = PayoutTerms(**base)
    sealed = PayoutTerms(**base, sealed=True)
    assert plain.rule_id != sealed.rule_id
    assert plain.sealed is False and sealed.sealed is True


def test_sealed_is_part_of_the_payout_spec_text():
    from consensus.payout import parse_payout_spec, payout_spec_text
    fields = {"rule_text": "always ( o30[t]:bv[24] = i40[t]:bv[24] ).",
              "slots": [BOB], "cap_per_execution": 100, "cap_per_period": 250,
              "period_blocks": 10, "expires_at": HEIGHT + 500, "sealed": True}
    text = payout_spec_text(fields, 4)
    terms = parse_payout_spec(text, ALICE)
    assert terms.sealed is True and terms.sequence_number == 4
    assert payout_spec_text(fields) != payout_spec_text(
        {k: v for k, v in fields.items() if k != "sealed"})
    with pytest.raises(PayoutShapeError, match="sealed must be true or left out"):
        parse_payout_spec(payout_spec_text({**fields, "sealed": False}, 4), ALICE)
