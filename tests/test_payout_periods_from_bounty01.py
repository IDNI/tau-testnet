"""Bounty 01, issue #63: payout rules — the periods_from anchor.

A payout rule's periods count from its recorded anchor — in practice
the install moment, so "500 a week from 1 December" counted its weeks
from whenever the rule happened to be installed. Every amendment on
issue #34 (ours included) concedes that as an open limit. These tests
pin the fix: an optional signed `periods_from` anchor on the entry.

- When the anchor is set, period boundaries, the per-period cap totals
  and the i26 paid-total feed all count from that fixed start — a rule
  installed on 26 November with periods_from 1 December runs its weeks
  1 Dec, 8 Dec, 15 Dec, not 26 Nov, 3 Dec, 10 Dec.
- When it is absent, the entry is byte-identical to before the field
  existed: same rule id, same stored row, same book root. The ids and
  the root pinned below were computed on the pristine base of this
  branch (the dupfix head) with the pins script, before the field was
  added — they are the pre-change values, not re-computed ones.
- The anchor is signed (tx_signing) and inside the rule id under its
  own domain, and install validation refuses anchors absurdly far from
  the install moment in either direction.
"""
import pytest

from consensus.payout_rules import (
    FORM_TAU_RULE,
    LEG_BPS_OF_BASE,
    LEG_FIXED,
    MAX_PERIODS_FROM_SKEW_SECONDS,
    PayoutLeg,
    PayoutRuleBook,
    PayoutRuleEntry,
    parse_install_payout_rule,
    payout_clause_inputs,
    payout_rule_capabilities,
    period_index_at,
    period_origin,
    validate_payout_rule_shape,
)
from consensus.tx_signing import signing_message_bytes

OWNER = "a" * 96
ARTIST = "b" * 96
WORKER = "c" * 96
TAU_OWNER = "e" * 96

WEEK = 604_800
DAY = 86_400
NOV12 = 1_794_441_600
NOV26 = 1_795_651_200
NOV28 = 1_795_824_000
DEC1 = 1_796_083_200
DEC3 = 1_796_256_000
DEC5 = 1_796_428_800
DEC8 = 1_796_688_000

SID_1 = bytes.fromhex("11" * 32)
SID_2 = bytes.fromhex("22" * 32)
SID_3 = bytes.fromhex("33" * 32)

# Pre-change pins, computed on the pristine base (see module docstring).
PIN_DECLARED_ID = "8eee67a75aa58006fc1c14d1860075bd34441c81e2c0a10d2337e12eed2f9f2b"
PIN_TAU_ID = "d08f7aa1238ec2cf6fbdb78dea3594948a5abf612133b4bb18b4616008ca83ba"
PIN_ROOT = "0d878e1e2e0eec802de071b24c66dd78f456261f810a9777faea6ed7a03b3979"


def rule(
    owner=OWNER,
    recipients=(ARTIST,),
    legs=((ARTIST, LEG_FIXED, 500),),
    max_exec=0,
    max_period=0,
    period_seconds=WEEK,
    anchor=NOV26,
    version=1,
    form=1,
    clause_text="",
    periods_from=0,
):
    return PayoutRuleEntry(
        owner_pubkey=owner,
        recipients=tuple(sorted(set(recipients))),
        legs=tuple(PayoutLeg(r, m, v) for r, m, v in legs),
        max_per_execution=max_exec,
        max_per_period=max_period,
        period_seconds=period_seconds,
        period_anchor_ts=anchor,
        version=version,
        form=form,
        clause_text=clause_text,
        periods_from_ts=periods_from,
    )


def install_tx(**overrides):
    tx = {
        "sender_pubkey": OWNER,
        "payout_recipients": [ARTIST],
        "payout_legs": [[ARTIST, LEG_FIXED, 500]],
        "payout_max_per_execution": 0,
        "payout_max_per_period": 0,
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": NOV26,
        "payout_version": 1,
    }
    tx.update(overrides)
    return tx


# --- Absent means byte-identical ----------------------------------------------


def _pin_book():
    declared = PayoutRuleEntry(
        owner_pubkey=OWNER,
        recipients=tuple(sorted({ARTIST, WORKER})),
        legs=(
            PayoutLeg(WORKER, LEG_FIXED, 700),
            PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 500),
        ),
        max_per_execution=705,
        max_per_period=2000,
        period_seconds=WEEK,
        period_anchor_ts=1_700_000_000,
        version=1,
    )
    tau = PayoutRuleEntry(
        owner_pubkey=TAU_OWNER,
        recipients=(ARTIST,),
        legs=(),
        max_per_execution=500,
        max_per_period=1500,
        period_seconds=WEEK,
        period_anchor_ts=1_700_000_000,
        version=1,
        form=FORM_TAU_RULE,
        clause_text="o5 = 1",
    )
    book = PayoutRuleBook()
    book.install(declared, 1_700_000_000)
    book.install(tau, 1_700_000_000)
    decision = book.execute(declared.rule_id, SID_1, 101, 1_700_000_000, 10_000)
    assert decision.executed, decision.reason
    return book, declared, tau


def test_absent_periods_from_is_byte_identical():
    book, declared, tau = _pin_book()
    assert declared.periods_from_ts == 0 and tau.periods_from_ts == 0
    # Same rule ids as before the field existed.
    assert declared.rule_id.hex() == PIN_DECLARED_ID
    assert tau.rule_id.hex() == PIN_TAU_ID
    # Same stored rows: twelve fields, the pre-change shape.
    for row in book.rows():
        assert len(row) == 12
    # Same book root.
    assert book.root().hex() == PIN_ROOT
    # And a restore of those rows reproduces the same root.
    clone = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert clone.root() == book.root()


def test_parse_without_periods_from_defaults_to_unset():
    entry = parse_install_payout_rule(install_tx())
    assert entry.periods_from_ts == 0
    assert period_origin(entry) == NOV26


# --- The anchored grid ----------------------------------------------------------


def test_period_index_boundaries_on_the_anchored_grid():
    entry = rule(periods_from=DEC1)
    assert period_origin(entry) == DEC1
    assert period_index_at(entry, DEC1 - 1) == -1
    assert period_index_at(entry, DEC1) == 0
    assert period_index_at(entry, DEC1 + WEEK - 1) == 0
    assert period_index_at(entry, DEC1 + WEEK) == 1
    assert period_index_at(entry, DEC1 + 3 * WEEK) == 3
    # The crisp difference: on 5 December the install-anchored grid is
    # already in period 1 (26 Nov + 7 days = 3 Dec), while the anchored
    # grid is still in period 0 (the week that began 1 December).
    assert period_index_at(rule(), DEC5) == 1
    assert period_index_at(entry, DEC5) == 0


def test_future_anchor_install_in_november_periods_from_december():
    # The official shape: installed 26 November, "500 a week from
    # 1 December", per-period cap 500, one fixed 500 leg.
    entry = rule(max_period=500, periods_from=DEC1)
    book = PayoutRuleBook()
    book.install(entry, NOV26)
    # Before 1 December the rule exists but its first period has not
    # begun: an execution settles nothing.
    early = book.execute(entry.rule_id, SID_1, 1, NOV28, 10_000)
    assert not early.executed
    assert "precedes the rule's first period" in early.reason
    # 1 December: period 0 opens and the week's 500 settles.
    first = book.execute(entry.rule_id, SID_1, 1, DEC1, 10_000)
    assert first.executed, first.reason
    assert first.period_index == 0 and first.total == 500
    # 5 December is the same anchored week: the cap is spent.
    same_week = book.execute(entry.rule_id, SID_2, 1, DEC5, 10_000)
    assert not same_week.executed
    assert "max per period" in same_week.reason
    # 8 December opens anchored period 1 and the cap resets — on the
    # December grid, not the install grid (which would have reset on
    # 3 December and again on 10 December).
    second = book.execute(entry.rule_id, SID_2, 1, DEC8, 10_000)
    assert second.executed, second.reason
    assert second.period_index == 1
    assert book.period_total(entry.rule_id, 0) == 500
    assert book.period_total(entry.rule_id, 1) == 500


def test_mid_period_install_with_a_past_anchor():
    # Installed 26 November on a grid that began 12 November: the
    # install lands mid-period, in anchored period 2.
    entry = rule(max_period=500, periods_from=NOV12)
    book = PayoutRuleBook()
    book.install(entry, NOV26)
    assert period_index_at(entry, NOV26) == 2
    first = book.execute(entry.rule_id, SID_1, 1, NOV26, 10_000)
    assert first.executed, first.reason
    assert first.period_index == 2
    # The anchored period's cap binds from the install onward — periods
    # 0 and 1 are history the rule never paid in and cannot spend now.
    over = book.execute(entry.rule_id, SID_2, 1, NOV26 + DAY, 10_000)
    assert not over.executed
    assert "max per period" in over.reason
    # 3 December opens anchored period 3 (12 Nov + 3 weeks).
    nxt = book.execute(entry.rule_id, SID_2, 1, DEC3, 10_000)
    assert nxt.executed, nxt.reason
    assert nxt.period_index == 3
    assert book.period_total(entry.rule_id, 2) == 500
    assert book.period_total(entry.rule_id, 3) == 500
    assert book.period_total(entry.rule_id, 0) == 0


def test_i26_paid_total_feed_is_keyed_to_the_anchored_period():
    # A Tau-form rule with the anchor set: what the clause reads at i26
    # is the anchored period's paid total — the release-schedule input.
    entry = rule(
        legs=(), form=FORM_TAU_RULE, clause_text="o5 = 1",
        max_period=1500, periods_from=DEC1,
    )
    book = PayoutRuleBook()
    book.install(entry, NOV26)
    decision = book.execute(
        entry.rule_id, SID_1, 1, DEC3, 10_000,
        clause_legs=((ARTIST, 500),),
    )
    assert decision.executed, decision.reason
    assert decision.period_index == 0
    # In the anchored week the feed reports the 500 already paid; in
    # the next anchored week it reports 0 again.
    assert book.period_paid_total(entry, DEC5) == 500
    assert book.period_paid_total(entry, DEC8) == 0
    inputs = payout_clause_inputs(
        entry, WORKER, 1, DEC5, 10_000, book.period_paid_total(entry, DEC5)
    )
    assert inputs[26] == "500"


# --- Signed, hashed, validated ---------------------------------------------------


def test_periods_from_is_inside_the_signature():
    base = {
        "sender_pubkey": OWNER,
        "sequence_number": 1,
        "expiration_time": NOV26 + 3600,
        "fee_limit": "50",
        "tx_type": "install_payout_rule",
        "expire_at_height": 5000,
    }
    tx_a = dict(base, **install_tx(payout_periods_from_ts=DEC1))
    tx_b = dict(base, **install_tx(payout_periods_from_ts=DEC8))
    tx_c = dict(base, **install_tx())
    # Changing only the anchor changes the signed bytes: a proposer
    # cannot move a rule's period grid after the owner signed it.
    assert signing_message_bytes(tx_a) != signing_message_bytes(tx_b)
    assert signing_message_bytes(tx_a) != signing_message_bytes(tx_c)


def test_periods_from_is_inside_the_rule_id():
    plain = rule()
    anchored = rule(periods_from=DEC1)
    other_anchor = rule(periods_from=DEC8)
    assert anchored.rule_id != plain.rule_id
    assert anchored.rule_id != other_anchor.rule_id
    # The form is inside the anchored id too: a declared-form and a
    # Tau-form rule over the same terms and anchor never collide.
    tau_anchored = rule(
        legs=(), form=FORM_TAU_RULE, clause_text="o5 = 1", periods_from=DEC1
    )
    assert tau_anchored.rule_id != anchored.rule_id
    # Parse carries the field through from the transaction.
    parsed = parse_install_payout_rule(
        install_tx(payout_periods_from_ts=DEC1))
    assert parsed.periods_from_ts == DEC1


def test_periods_from_validation_window():
    now = NOV26
    # Inside the window, both directions: fine.
    assert validate_payout_rule_shape(rule(periods_from=DEC1), now) is None
    assert validate_payout_rule_shape(rule(periods_from=NOV12), now) is None
    assert validate_payout_rule_shape(
        rule(periods_from=now - MAX_PERIODS_FROM_SKEW_SECONDS), now) is None
    assert validate_payout_rule_shape(
        rule(periods_from=now + MAX_PERIODS_FROM_SKEW_SECONDS), now) is None
    # Absurdly far either way: refused at install, naming the field.
    for bad in (
        now - MAX_PERIODS_FROM_SKEW_SECONDS - 1,
        now + MAX_PERIODS_FROM_SKEW_SECONDS + 1,
        1,  # 1970: a grid older than the chain
    ):
        problem = validate_payout_rule_shape(rule(periods_from=bad), now)
        assert problem is not None and "periods_from" in problem
    # Unset is never refused on anchor grounds, whatever the time.
    assert validate_payout_rule_shape(rule(), now) is None
    # And the book's install screen applies the same refusal.
    book = PayoutRuleBook()
    ok, reason = book.can_install(rule(periods_from=1), now)
    assert not ok and "periods_from" in reason


# --- Storage ---------------------------------------------------------------------


def test_rows_and_restore_with_periods_from():
    entry = rule(max_period=500, periods_from=DEC1)
    book = PayoutRuleBook()
    book.install(entry, NOV26)
    decision = book.execute(entry.rule_id, SID_1, 1, DEC1, 10_000)
    assert decision.executed, decision.reason
    (row,) = book.rows()
    # The anchor rides as a thirteenth field, after the legacy twelve.
    assert len(row) == 13 and row[12] == DEC1
    clone = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    restored = clone.get(OWNER)
    assert restored is not None
    assert restored.periods_from_ts == DEC1
    assert restored.rule_id == entry.rule_id
    assert clone.root() == book.root()
    assert clone.period_total(entry.rule_id, 0) == 500


def test_mixed_book_of_legacy_and_anchored_rows_restores():
    legacy = rule(owner=OWNER)
    anchored = rule(owner=TAU_OWNER, periods_from=DEC1)
    book = PayoutRuleBook()
    book.install(legacy, NOV26)
    book.install(anchored, NOV26)
    rows = book.rows()
    assert sorted(len(r) for r in rows) == [12, 13]
    clone = PayoutRuleBook.restore(rows, book.settlement_rows())
    assert clone.root() == book.root()
    assert clone.get(OWNER).periods_from_ts == 0
    assert clone.get(TAU_OWNER).periods_from_ts == DEC1


def test_capabilities_state_the_periods_from_semantics():
    caps = payout_rule_capabilities()
    assert "periods_from" in caps
    assert "fixed start" in caps["periods_from"]
    assert "install" in caps["periods_from"]
