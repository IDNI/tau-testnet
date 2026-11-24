"""Bounty 01, issue #63 (G4): payout rules — the Tau form, at book level.

The Tau form beside the declared leg program: the owner installs an actual
Tau clause as the payout rule; the clause's stepped outputs name the legs
(recipient candidate indices + amounts, the encoding pinned in the
capability record); the book checks them against the declared recipient
set, both declared caps and the balance, exactly as it checks the declared
program's computed legs. The book itself never steps a clause — callers
step it and hand the decoded legs in — so this suite proves the book half:
form selection and parsing, the id's domain separation, shape rules, the
output decoding, the input map's exact contents, execution with clause
legs under every shared check, and the restore round-trip.
"""
import pytest

import tau_defs
from consensus.payout_rules import (
    FORM_DECLARED_PROGRAM,
    FORM_TAU_RULE,
    LEG_BPS_OF_BASE,
    MAX_PAYOUT_CLAUSE_BYTES,
    PayoutLeg,
    PayoutRuleBook,
    PayoutRuleEntry,
    PayoutRuleShapeError,
    decode_clause_legs,
    parse_install_payout_rule,
    payout_clause_inputs,
    payout_rule_capabilities,
    period_index_at,
    validate_payout_rule_shape,
)
from consensus.serialization import compute_payout_rule_id

OWNER = "a" * 96
ARTIST = "b" * 96  # index 0 in the canonical (sorted) recipient tuple
WORKER = "c" * 96  # index 1
OTHER = "d" * 96
EXECUTOR = "e" * 96

ANCHOR = 1_700_000_000
WEEK = 604_800
SID_1 = bytes.fromhex("11" * 32)
SID_2 = bytes.fromhex("22" * 32)
SID_3 = bytes.fromhex("33" * 32)

CLAUSE = (
    "(i5[t]:bv[64] < { 1700604800 }:bv[64]) "
    "? ((o30[t]:bv[64] = { 1 }:bv[64]) && (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 500 }:bv[64])) "
    ": ((o30[t]:bv[64] = { 0 }:bv[64]) && (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 0 }:bv[64]))"
)


def tau_rule(
    owner=OWNER,
    recipients=(ARTIST, WORKER),
    clause=CLAUSE,
    max_exec=0,
    max_period=0,
    period_seconds=WEEK,
    anchor=ANCHOR,
    version=1,
):
    return PayoutRuleEntry(
        owner_pubkey=owner,
        recipients=tuple(sorted(set(recipients))),
        legs=(),
        max_per_execution=max_exec,
        max_per_period=max_period,
        period_seconds=period_seconds,
        period_anchor_ts=anchor,
        version=version,
        form=FORM_TAU_RULE,
        clause_text=clause,
    )


def installed(entry=None, ts=ANCHOR):
    book = PayoutRuleBook()
    entry = entry or tau_rule()
    book.install(entry, ts)
    return book, entry


# --- Form selection: parsing reads exactly one leg source ----------------------


def test_parse_defaults_to_the_declared_form():
    entry = parse_install_payout_rule({
        "sender_pubkey": OWNER,
        "payout_recipients": [ARTIST],
        "payout_legs": [[ARTIST, LEG_BPS_OF_BASE, 500]],
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": ANCHOR,
    })
    assert entry.form == FORM_DECLARED_PROGRAM and entry.clause_text == ""
    assert len(entry.legs) == 1


def test_parse_tau_form_reads_the_clause_and_no_program():
    entry = parse_install_payout_rule({
        "sender_pubkey": OWNER,
        "payout_recipients": [WORKER, ARTIST],
        "payout_form": FORM_TAU_RULE,
        "payout_clause": CLAUSE,
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": ANCHOR,
    })
    assert entry.form == FORM_TAU_RULE and entry.clause_text == CLAUSE
    assert entry.legs == ()
    assert entry.recipients == (ARTIST, WORKER)  # canonical: sorted


def test_parse_refuses_mixed_or_missing_leg_sources():
    base = {
        "sender_pubkey": OWNER,
        "payout_recipients": [ARTIST],
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": ANCHOR,
    }
    for extra in (
        {"payout_form": FORM_TAU_RULE},                                  # no clause
        {"payout_form": FORM_TAU_RULE, "payout_clause": CLAUSE,
         "payout_legs": [[ARTIST, 1, 5]]},                               # both sources
        {"payout_clause": CLAUSE,
         "payout_legs": [[ARTIST, 1, 5]]},                               # clause, declared form
        {"payout_form": 3, "payout_legs": [[ARTIST, 1, 5]]},             # unknown form
        {"payout_form": True, "payout_legs": [[ARTIST, 1, 5]]},         # bool is not an int
        {"payout_form": FORM_TAU_RULE, "payout_clause": 7},              # clause not a string
    ):
        with pytest.raises(PayoutRuleShapeError):
            parse_install_payout_rule({**base, **extra})


# --- The rule id: domain-separated, and the clause is inside the hash ---------


def test_tau_id_is_domain_separated_and_covers_the_clause():
    declared = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 500),),
        max_per_execution=0, max_per_period=0,
        period_seconds=WEEK, period_anchor_ts=ANCHOR, version=1,
    )
    tau = tau_rule(recipients=(ARTIST,))
    # Same owner, recipients, caps, period and version: the two forms are
    # different rules, never the same id with different semantics.
    assert tau.rule_id != declared.rule_id
    # The declared form's id is byte-identical to the pre-Tau-form
    # computation — PR #155's declared rules do not move.
    assert declared.rule_id == compute_payout_rule_id(
        OWNER, (ARTIST,), ((ARTIST, LEG_BPS_OF_BASE, 500),), 0, 0,
        WEEK, ANCHOR, 1)
    # The clause is a signed field of the Tau form: changing one character
    # is a different rule.
    other_clause = tau_rule(recipients=(ARTIST,), clause=CLAUSE + " ")
    assert other_clause.rule_id != tau.rule_id
    capped = tau_rule(recipients=(ARTIST,), max_exec=10)
    assert capped.rule_id != tau.rule_id


# --- Shape rules for the Tau form ----------------------------------------------


def test_tau_shape_rules():
    assert validate_payout_rule_shape(tau_rule(), ANCHOR) is None
    assert validate_payout_rule_shape(
        tau_rule(clause=""), ANCHOR) is not None
    with_legs = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, 1, 5),),
        max_per_execution=0, max_per_period=0,
        period_seconds=WEEK, period_anchor_ts=ANCHOR, version=1,
        form=FORM_TAU_RULE, clause_text=CLAUSE)
    assert validate_payout_rule_shape(with_legs, ANCHOR) is not None
    too_long = tau_rule(clause="x" * (MAX_PAYOUT_CLAUSE_BYTES + 1))
    assert validate_payout_rule_shape(too_long, ANCHOR) is not None
    at_bound = tau_rule(clause="x" * MAX_PAYOUT_CLAUSE_BYTES)
    assert validate_payout_rule_shape(at_bound, ANCHOR) is None
    declared_with_clause = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, 1, 5),),
        max_per_execution=0, max_per_period=0,
        period_seconds=WEEK, period_anchor_ts=ANCHOR, version=1,
        form=FORM_DECLARED_PROGRAM, clause_text=CLAUSE)
    assert validate_payout_rule_shape(declared_with_clause, ANCHOR) is not None
    unknown_form = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,), legs=(),
        max_per_execution=0, max_per_period=0,
        period_seconds=WEEK, period_anchor_ts=ANCHOR, version=1, form=9)
    assert validate_payout_rule_shape(unknown_form, ANCHOR) is not None


# --- The output encoding ---------------------------------------------------------


def test_decode_clause_legs_reads_the_pinned_encoding():
    entry = tau_rule()
    legs, why = decode_clause_legs(entry, {
        "o30": "2", "o31": "0", "o32": "700", "o33": "1", "o34": "5",
    })
    assert why == "" and legs == ((ARTIST, 700), (WORKER, 5))
    # Tau value spellings (hex with annotation) decode the same way.
    legs, _ = decode_clause_legs(entry, {
        "o30": "{ #x00000001 }:bv[64]",
        "o31": "{ #x00000001 }:bv[64]",
        "o32": "{ #x000001f4 }:bv[64]",
    })
    assert legs == ((WORKER, 500),)
    # Zero legs are dropped, as compute_legs drops them.
    legs, _ = decode_clause_legs(entry, {
        "o30": "2", "o31": "0", "o32": "0", "o33": "1", "o34": "9",
    })
    assert legs == ((WORKER, 9),)
    legs, _ = decode_clause_legs(entry, {"o30": "0"})
    assert legs == ()


def test_decode_clause_legs_refuses_what_the_node_cannot_settle():
    entry = tau_rule()
    for outputs in (
        {},                                                     # no count
        {"o30": "not-a-number"},                                # unreadable count
        {"o30": "33"},                                          # over MAX_LEGS
        {"o30": "1", "o31": "0"},                               # missing amount
        {"o30": "1", "o31": "x", "o32": "5"},                   # unreadable index
        {"o30": "1", "o31": "2", "o32": "5"},                   # outside the set
    ):
        legs, why = decode_clause_legs(entry, outputs)
        assert legs is None and why, outputs


# --- The input map: one definition, exact contents -------------------------------


def test_payout_clause_inputs_map_contents():
    entry = tau_rule()
    values = payout_clause_inputs(entry, EXECUTOR, 101, ANCHOR + 5, 10_000, 7)
    assert values == {
        1: "101",
        2: "10000",
        3: "{ #x" + OWNER + " }:bv[384]",
        4: "{ #x" + EXECUTOR + " }:bv[384]",
        5: str(ANCHOR + 5),
        tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX: "7",
    }
    # The paid-total stream is i26 in this tree — the index the map feeds
    # is the index tau_defs reserves for it.
    assert tau_defs.PAYOUT_PERIOD_PAID_STREAM_INDEX == 26
    assert tau_defs.TAU_INPUT_STREAM_PAYOUT_PERIOD_PAID == "i26"


def test_period_paid_total_reads_the_books_own_totals():
    book, entry = installed()
    assert book.period_paid_total(entry, ANCHOR - 1) == 0  # before period 0
    book.execute(entry.rule_id, SID_1, 1, ANCHOR, 10_000,
                 clause_legs=((ARTIST, 40),))
    assert book.period_paid_total(entry, ANCHOR) == 40
    assert book.period_paid_total(entry, ANCHOR + WEEK) == 0  # next period


# --- Execution with clause legs: every shared check binds ------------------------


def test_tau_execution_requires_and_uses_clause_legs():
    book, entry = installed()
    # Without stepped legs the book refuses: there is no second way to
    # compute a Tau-form rule's legs.
    refused = book.evaluate_execution(entry.rule_id, SID_1, 1, ANCHOR, 10_000)
    assert not refused.executed and "was not evaluated" in refused.reason
    # Legs naming a recipient outside the declared set are refused by the
    # book's own check, whoever produced them.
    outside = book.execute(entry.rule_id, SID_1, 1, ANCHOR, 10_000,
                           clause_legs=((OTHER, 5),))
    assert not outside.executed and "undeclared recipient" in outside.reason
    assert not book.is_settled(entry.rule_id, SID_1)
    # A well-formed execution settles, records, and advances the period.
    settled = book.execute(entry.rule_id, SID_1, 1, ANCHOR, 10_000,
                           clause_legs=((ARTIST, 5), (WORKER, 7)))
    assert settled.executed and settled.total == 12
    assert book.period_total(entry.rule_id, 0) == 12
    # And it pays once: the same settlement id settles nothing again.
    again = book.execute(entry.rule_id, SID_1, 1, ANCHOR, 10_000,
                         clause_legs=((ARTIST, 5),))
    assert not again.executed and "already recorded" in again.reason


def test_tau_execution_caps_bind_the_clause_exactly():
    book, entry = installed(tau_rule(max_exec=100, max_period=150))
    over_exec = book.execute(entry.rule_id, SID_1, 1, ANCHOR, 10_000,
                             clause_legs=((ARTIST, 101),))
    assert not over_exec.executed and "max per execution" in over_exec.reason
    first = book.execute(entry.rule_id, SID_1, 1, ANCHOR, 10_000,
                         clause_legs=((ARTIST, 100),))
    assert first.executed
    # 100 of the period's 150 are paid; a second 100 passes the
    # per-execution cap but breaks the period cap.
    over_period = book.execute(entry.rule_id, SID_2, 1, ANCHOR, 10_000,
                               clause_legs=((WORKER, 100),))
    assert not over_period.executed and "max per period" in over_period.reason
    # Balance binds too, and a refused execution records nothing.
    broke = book.execute(entry.rule_id, SID_3, 1, ANCHOR, 40,
                         clause_legs=((ARTIST, 50),))
    assert not broke.executed and "insufficient funds" in broke.reason
    assert not book.is_settled(entry.rule_id, SID_3)
    assert book.period_total(entry.rule_id, 0) == 100


# --- Restore: the form and the clause round-trip, tamper-evident ------------------


def test_tau_restore_round_trip_and_tamper_refusal():
    book, entry = installed()
    book.execute(entry.rule_id, SID_1, 1, ANCHOR, 10_000,
                 clause_legs=((ARTIST, 5),))
    clone = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert clone.root() == book.root()
    restored = clone.get(OWNER)
    assert restored.form == FORM_TAU_RULE and restored.clause_text == CLAUSE
    assert restored.rule_id == entry.rule_id
    assert clone.is_settled(entry.rule_id, SID_1)
    # A row whose clause was tampered with no longer recomputes its id.
    rows = book.rows()
    tampered = [rows[0][:-1] + (CLAUSE + " ",)]
    with pytest.raises(ValueError):
        PayoutRuleBook.restore(tampered, book.settlement_rows())


# --- The capability record pins the form ------------------------------------------


def test_capabilities_pin_the_tau_form():
    caps = payout_rule_capabilities()
    assert caps["forms"] == {
        "declared_program": FORM_DECLARED_PROGRAM,
        "tau_rule": FORM_TAU_RULE,
        # FIX 10: the deciding-rule form joined the record — the pin
        # grows by exactly the new form, nothing else moved.
        "tau_deciding_rule": 3,
    }
    tau = caps["tau_rule"]
    assert tau["inputs"]["i1"] and tau["inputs"]["i5"]
    assert tau["inputs"][tau_defs.TAU_INPUT_STREAM_PAYOUT_PERIOD_PAID]
    assert "o30" in str(tau["outputs"])
    assert tau["max_clause_bytes"] == MAX_PAYOUT_CLAUSE_BYTES
    # The declared form's record is untouched.
    assert caps["leg_modes"] == {"fixed": 1, "bps_of_base": 2}
    assert period_index_at(tau_rule(), ANCHOR) == 0
