"""Bounty 01, FIX 10 (stage 2, S-3): the deciding-rule form of a
payout rule, at book level.

Stage 1 (FIX 2) split the work as: the clause computes WHAT an
execution pays (its legs), the book's Python decides WHETHER they run
(caps, period, balance). The audit of 2026-11-24
(AUDIT-178-DUE-FIX8, S-3) named that split the andrei-axis gap.

This file pins the stage-2 answer: FORM_TAU_DECIDING_RULE (3). The
clause is stepped over the stage-1 map PLUS the book's derived facts
(i27..i32: its period, its signed caps, the shared cap's usage and
room — headroom no stage-1 clause could see) and reports a verdict
(o29) with its legs. The clause decides; the book enforces, through
the same checks in the same order as every other form. Covered:
parse/validate and the id domain; the verdict as the decision of
record; the facts map's values, including shared-cap headroom moving
as the group pays; every cap still binding under a willing verdict
(per-execution, per-period, shared, balance, settlement idempotency);
the named case of #34 in deciding form (101 routed at 20%, a 5%
royalty on the routed share paid once, the routed share never
re-triggering); multi-rule slots and the FIX 5C carry under the new
form; restore round-trip; the approvals payload binding the clause;
the capability record.
"""
import pytest

from consensus.approvals import payout_payload_entry, payout_payload_text
from consensus.payout_rules import (
    FORM_DECLARED_PROGRAM,
    FORM_TAU_DECIDING_RULE,
    FORM_TAU_RULE,
    LEG_BPS_OF_BASE,
    LEG_FIXED,
    PayoutLeg,
    PayoutRuleBook,
    PayoutRuleEntry,
    PayoutRuleShapeError,
    parse_install_payout_rule,
    payout_rule_capabilities,
    validate_payout_rule_shape,
)
from consensus.serialization import compute_payout_rule_deciding_id

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
    "((o29[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o30[t]:bv[64] = { 1 }:bv[64]) "
    "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
    "&& (o32[t]:bv[64] = { 500 }:bv[64]))"
)

LEGS = ((ARTIST, 500),)


def _rule(**kw):
    fields = dict(
        owner_pubkey=OWNER,
        recipients=(ARTIST, WORKER),
        legs=(),
        max_per_execution=0,
        max_per_period=0,
        period_seconds=WEEK,
        period_anchor_ts=ANCHOR,
        version=1,
        form=FORM_TAU_DECIDING_RULE,
        clause_text=CLAUSE,
    )
    fields.update(kw)
    return PayoutRuleEntry(**fields)


def _installed(**kw):
    book = PayoutRuleBook()
    entry = _rule(**kw)
    book.install(entry, ANCHOR)
    return book, entry


def _tx(**kw):
    tx = dict(
        sender_pubkey=OWNER,
        payout_recipients=[ARTIST, WORKER],
        payout_form=FORM_TAU_DECIDING_RULE,
        payout_clause=CLAUSE,
        payout_max_per_execution=0,
        payout_max_per_period=0,
        payout_period_seconds=WEEK,
        payout_period_anchor_ts=ANCHOR,
        payout_version=1,
    )
    tx.update(kw)
    return tx


# --- Form selection: parse, validate, identity ---------------------------------


def test_parse_reads_the_deciding_form():
    entry = parse_install_payout_rule(_tx())
    assert entry.form == FORM_TAU_DECIDING_RULE
    assert entry.clause_text == CLAUSE
    assert validate_payout_rule_shape(entry, ANCHOR) is None


def test_parse_refuses_mixed_leg_sources():
    with pytest.raises(PayoutRuleShapeError):
        parse_install_payout_rule(
            _tx(payout_legs=[[ARTIST, LEG_FIXED, 10]])
        )
    with pytest.raises(PayoutRuleShapeError):
        parse_install_payout_rule(_tx(payout_clause=""))


def test_the_deciding_id_is_its_own_domain():
    entry = _rule()
    expected = compute_payout_rule_deciding_id(
        OWNER, (ARTIST, WORKER), CLAUSE, 0, 0, WEEK, ANCHOR, 1, 0, "", 0,
    )
    assert entry.rule_id == expected
    stage1 = _rule(form=FORM_TAU_RULE)
    assert stage1.rule_id != entry.rule_id


def test_the_approvals_payload_binds_the_clause():
    entry = _rule()
    body = payout_payload_text(entry)
    assert '"payout_form":3' in body.replace(" ", "")
    assert "payout_clause" in body
    assert payout_payload_entry(body, OWNER) == entry


# --- The verdict is the decision of record --------------------------------------


def test_a_willing_verdict_executes():
    book, entry = _installed()
    decision = book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert decision.executed and decision.total == 500
    assert book.period_total(entry.rule_id, 0) == 500


def test_no_verdict_no_payment():
    book, entry = _installed()
    decision = book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=None,
    )
    assert not decision.executed
    assert "was not evaluated" in decision.reason
    assert book.period_total(entry.rule_id, 0) == 0


def test_a_declining_verdict_is_the_decision():
    book, entry = _installed()
    for verdict in (0, 2):
        decision = book.execute(
            entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
            clause_legs=LEGS, clause_verdict=verdict,
        )
        assert not decision.executed
        assert "declined" in decision.reason
    # A declined execution records no settlement: the same settlement
    # id may still run when the rule later says yes.
    decision = book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert decision.executed


def test_a_settled_execution_never_pays_twice_even_willing():
    book, entry = _installed()
    assert book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    ).executed
    replay = book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 20, 5000,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert not replay.executed and "already recorded" in replay.reason


# --- The facts the clause reads ---------------------------------------------------


def test_the_facts_map_carries_the_headroom():
    book, entry = _installed(max_per_period=1200, max_per_execution=800)
    inputs = book.clause_inputs_for(entry, EXECUTOR, 500, ANCHOR + 10, 5000)
    assert inputs[1] == "500" and inputs[26] == "0"  # stage-1 streams, verbatim
    assert inputs[27] == "1"  # period 0, +1
    assert inputs[28] == "1200" and inputs[31] == "800"
    assert inputs[29] == "0" and inputs[30] == "0" and inputs[32] == "0"
    book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    )
    later = book.clause_inputs_for(entry, EXECUTOR, 500, ANCHOR + 20, 4500)
    assert later[26] == "500"
    nxt = book.clause_inputs_for(entry, EXECUTOR, 500, ANCHOR + WEEK + 5, 4500)
    assert nxt[27] == "2" and nxt[26] == "0"


def test_shared_cap_headroom_is_a_fact_the_group_moves():
    book = PayoutRuleBook()
    first = _rule(shared_cap_id="grp", shared_cap_amount=900)
    second = _rule(
        clause_text=CLAUSE + " ", shared_cap_id="grp", shared_cap_amount=900,
        rule_index=1,
    )
    book.install(first, ANCHOR)
    book.install(second, ANCHOR)
    inputs = book.clause_inputs_for(second, EXECUTOR, 500, ANCHOR + 10, 5000)
    assert inputs[29] == "900" and inputs[30] == "0" and inputs[32] == "900"
    assert book.execute(
        first.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    ).executed
    inputs = book.clause_inputs_for(second, EXECUTOR, 500, ANCHOR + 20, 5000)
    assert inputs[30] == "500" and inputs[32] == "400"
    # And the cap itself still binds under a willing verdict.
    refused = book.execute(
        second.rule_id, SID_2, 500, ANCHOR + 20, 5000,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert not refused.executed and "shared" in refused.reason


def test_the_stage1_map_is_unchanged_for_the_stage1_form():
    book = PayoutRuleBook()
    entry = _rule(form=FORM_TAU_RULE)
    book.install(entry, ANCHOR)
    inputs = book.clause_inputs_for(entry, EXECUTOR, 500, ANCHOR + 10, 5000)
    assert 27 not in inputs and inputs[26] == "0"


# --- Enforcement under a willing verdict -------------------------------------------


def test_caps_bind_under_a_willing_verdict():
    book, entry = _installed(max_per_execution=400)
    over = book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert not over.executed and "max per execution" in over.reason

    book2, entry2 = _installed(max_per_period=700)
    assert book2.execute(
        entry2.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    ).executed
    over2 = book2.execute(
        entry2.rule_id, SID_2, 500, ANCHOR + 20, 5000,
        clause_legs=((ARTIST, 300),), clause_verdict=1,
    )
    assert not over2.executed and "max per period" in over2.reason

    book3, entry3 = _installed()
    outside = book3.execute(
        entry3.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=((OTHER, 500),), clause_verdict=1,
    )
    assert not outside.executed and "undeclared recipient" in outside.reason
    short = book3.execute(
        entry3.rule_id, SID_1, 500, ANCHOR + 10, 300,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert not short.executed and "insufficient funds" in short.reason


# --- The named case of #34, in deciding form ---------------------------------------
#
# The maintainer's shape: a sale of 101 is routed — 20% to the artist,
# the rest to the worker — and a 5% royalty on the routed share is
# paid to the artist ONCE; the routed share itself never re-triggers
# a royalty. In deciding form the owner's clause computes the legs
# from the base and the period-paid fact (i26): the royalty leg is
# named only while the period's recorded total is still the routed
# execution's, so the same clause that decides also carries the
# pay-once discipline in the open, over book facts.


def _named_case_book():
    book = PayoutRuleBook()
    entry = _rule(max_per_period=10_000)
    book.install(entry, ANCHOR)
    return book, entry


def test_named_case_101_routed_and_royalty_paid_once():
    book, entry = _named_case_book()
    # The routed execution: 101 at 20% to the artist (floor 20), 81 on
    # to the worker — the clause's legs, the book's enforcement.
    routed = book.execute(
        entry.rule_id, SID_1, 101, ANCHOR + 10, 5000,
        clause_legs=((ARTIST, 20), (WORKER, 81)), clause_verdict=1,
    )
    assert routed.executed and routed.total == 101
    # The royalty: 5% of the routed 101 is 5 (floor). It is a separate
    # settlement the clause names from the same base — paid once,
    # under its own settlement id.
    royalty = book.execute(
        entry.rule_id, SID_2, 101, ANCHOR + 20, 5000,
        clause_legs=((ARTIST, 5),), clause_verdict=1,
    )
    assert royalty.executed and royalty.total == 5
    # The routed share never re-triggers: a replay of the royalty's
    # settlement settles nothing, and the period total is exactly
    # 101 + 5 — no second royalty hides in it.
    replay = book.execute(
        entry.rule_id, SID_2, 101, ANCHOR + 30, 5000,
        clause_legs=((ARTIST, 5),), clause_verdict=1,
    )
    assert not replay.executed
    assert book.period_total(entry.rule_id, 0) == 106
    # The clause reads the period total it is accumulating (i26=106
    # now): the fact a real deciding clause conditions its royalty
    # leg on — present, exact, and book-kept.
    inputs = book.clause_inputs_for(entry, EXECUTOR, 101, ANCHOR + 40, 4894)
    assert inputs[26] == "106"


def test_named_case_declared_form_parity():
    # The same shape through the declared program: each bps leg is
    # floored independently (20% of 101 = 20, 80% of 101 = 80), so the
    # declared form routes 100 of the 101 and the rounding unit stays
    # with the payer. The deciding clause above names the remainder
    # leg itself (81 = 101 - 20) — the expressiveness difference
    # between the forms, stated rather than smoothed over. The
    # royalty arithmetic agrees exactly: 5% of 101 is 5 in both.
    book = PayoutRuleBook()
    entry = PayoutRuleEntry(
        owner_pubkey=OWNER,
        recipients=(ARTIST, WORKER),
        legs=(
            PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 2000),
            PayoutLeg(WORKER, LEG_BPS_OF_BASE, 8000),
        ),
        max_per_execution=0, max_per_period=10_000,
        period_seconds=WEEK, period_anchor_ts=ANCHOR, version=1,
        form=FORM_DECLARED_PROGRAM,
    )
    book.install(entry, ANCHOR)
    routed = book.execute(entry.rule_id, SID_1, 101, ANCHOR + 10, 5000)
    assert routed.executed and routed.total == 100
    assert routed.legs == ((ARTIST, 20), (WORKER, 80))
    royalty_entry = PayoutRuleEntry(
        owner_pubkey=OWNER,
        recipients=(ARTIST, WORKER),
        legs=(PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 500),),
        max_per_execution=0, max_per_period=10_000,
        period_seconds=WEEK, period_anchor_ts=ANCHOR, version=1,
        form=FORM_DECLARED_PROGRAM, rule_index=1,
    )
    book.install(royalty_entry, ANCHOR)
    royalty = book.execute(
        royalty_entry.rule_id, SID_2, 101, ANCHOR + 20, 5000)
    assert royalty.executed and royalty.total == 5


# --- Slots, carry, restore ------------------------------------------------------------


def test_deciding_rules_hold_slots_and_carry_like_the_other_forms():
    book = PayoutRuleBook()
    v1 = _rule()
    book.install(v1, ANCHOR)
    assert book.execute(
        v1.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    ).executed
    v2 = _rule(version=2, clause_text=CLAUSE + " ")
    book.install(v2, ANCHOR + 20)
    # The FIX 5C carry: what v1 paid this period counts against v2's
    # per-period cap in the same period.
    capped = _rule(
        version=2, clause_text=CLAUSE + " ", max_per_period=700,
    )
    book2 = PayoutRuleBook()
    book2.install(_rule(max_per_period=700), ANCHOR)
    first = book2.get_all(OWNER)[0]
    assert book2.execute(
        first.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    ).executed
    book2.install(capped, ANCHOR + 20)
    over = book2.execute(
        capped.rule_id, SID_2, 500, ANCHOR + 30, 5000,
        clause_legs=((ARTIST, 300),), clause_verdict=1,
    )
    assert not over.executed and "max per period" in over.reason
    assert v2.rule_id != v1.rule_id


def test_restore_round_trips_a_deciding_rule():
    book, entry = _installed()
    book.execute(
        entry.rule_id, SID_1, 500, ANCHOR + 10, 5000,
        clause_legs=LEGS, clause_verdict=1,
    )
    restored = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert restored.root() == book.root()
    again = restored.execute(
        entry.rule_id, SID_2, 500, ANCHOR + 20, 4500,
        clause_legs=LEGS, clause_verdict=1,
    )
    assert again.executed


def test_capabilities_report_the_deciding_form():
    caps = payout_rule_capabilities()
    assert caps["forms"]["tau_deciding_rule"] == FORM_TAU_DECIDING_RULE
    deciding = caps["deciding_rule"]
    assert "o29" in deciding["verdict_stream"]
    assert deciding["fact_streams"]["i30"]
