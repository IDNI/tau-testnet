"""Bounty 01, issue #63: payout rules — the book level (slice 5).

The named tests below carry the exact names the jr11ikhsan design posted on
issue #63 promised, for the cases a pure book can prove: all six #63 rows at
book level, including named case 2 in its settlement-idempotency form. The
engine-wiring assertions (legs settling through the transfer seam, the
owner's o5 re-checked per leg, admission/apply parity) land in the engine
suite of the same slice.
"""
import copy

import pytest

from consensus.payout_rules import (
    BASE_RECORDED_RECEIPT,
    BASE_SUBMITTED,
    LEG_BPS_OF_BASE,
    LEG_FIXED,
    PayoutLeg,
    PayoutReceipt,
    PayoutRuleBook,
    PayoutRuleEntry,
    PayoutRuleShapeError,
    compute_legs,
    parse_execute_payout_receipt_id,
    parse_execute_payout_rule,
    parse_install_payout_rule,
    payout_rule_capabilities,
    validate_payout_rule_shape,
)

OWNER = "a" * 96
ARTIST = "b" * 96  # the royalty recipient
WORKER = "c" * 96  # a fixed-leg recipient
OTHER = "d" * 96

ANCHOR = 1_700_000_000
WEEK = 604_800
SID_1 = bytes.fromhex("11" * 32)
SID_2 = bytes.fromhex("22" * 32)


def rule(
    owner=OWNER,
    recipients=(ARTIST,),
    legs=((ARTIST, LEG_BPS_OF_BASE, 500),),
    max_exec=0,
    max_period=0,
    period_seconds=WEEK,
    anchor=ANCHOR,
    version=1,
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
    )


def installed(entry=None, ts=ANCHOR):
    book = PayoutRuleBook()
    entry = entry or rule()
    book.install(entry, ts)
    return book, entry


# --- Named case 2: a 5% royalty on 101 pays 5, once --------------------------


def test_royalty_5pct_on_101_pays_5_once():
    book, entry = installed()
    decision = book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    assert decision.executed, decision.reason
    assert decision.legs == ((ARTIST, 5),)
    assert decision.total == 5
    # A repeat execution carrying the same settlement id — a replay of the
    # same transaction or a fresh one — settles nothing, ever.
    again = book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    assert not again.executed
    assert "already recorded" in again.reason
    assert book.period_total(entry.rule_id, 0) == 5
    # The settlement record itself is the consensus proof of the one payment.
    record = book.settlement(entry.rule_id, SID_1)
    assert record is not None and record.total == 5 and record.base_amount == 101
    # A different settlement is a different payment and settles normally.
    other = book.execute(entry.rule_id, SID_2, 101, ANCHOR, 10_000)
    assert other.executed and other.total == 5
    assert book.period_total(entry.rule_id, 0) == 10


# --- #63 row 1: the rule computes; the node enforces the declared caps -------


def test_payout_rule_outputs_checked_against_declared_caps():
    entry = rule(
        recipients=(ARTIST, WORKER),
        legs=((WORKER, LEG_FIXED, 700), (ARTIST, LEG_BPS_OF_BASE, 500)),
        max_exec=705,
    )
    book, entry = installed(entry)
    # The node computes the legs from the stored program and the submitted
    # base alone: fixed 700 + floor(101 * 500 / 10000) = 5 -> 705, at the cap.
    decision = book.evaluate_execution(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    assert decision.executed, decision.reason
    assert decision.legs == ((WORKER, 700), (ARTIST, 5))
    assert decision.total == 705
    # One more unit of base changes nothing for the fixed leg but the cap is
    # checked against the computed total, not the submitter's claim: a base
    # whose computed total exceeds the declared cap settles nothing.
    over = book.evaluate_execution(entry.rule_id, SID_2, 10_000, ANCHOR, 10_000_000)
    assert not over.executed and "max per execution" in over.reason


# --- #63 row 2 (book half): all legs atomic or none --------------------------


def test_payout_all_legs_atomic_or_none():
    entry = rule(
        recipients=(ARTIST, WORKER),
        legs=((WORKER, LEG_FIXED, 700), (ARTIST, LEG_BPS_OF_BASE, 500)),
    )
    book, entry = installed(entry)
    # The owner can cover the first leg but not both: the execution settles
    # nothing — no partial first leg, no settlement, no period movement.
    decision = book.execute(entry.rule_id, SID_1, 101, ANCHOR, 702)
    assert not decision.executed and "insufficient funds" in decision.reason
    assert not book.is_settled(entry.rule_id, SID_1)
    assert book.period_total(entry.rule_id, 0) == 0
    # Funded, the same settlement settles both legs together.
    decision = book.execute(entry.rule_id, SID_1, 101, ANCHOR, 705)
    assert decision.executed and decision.total == 705
    assert book.period_total(entry.rule_id, 0) == 705


# --- #63 row 4: an execution cannot pay an undeclared recipient ---------------


def test_payout_cannot_pay_undeclared_recipient():
    # A leg naming a recipient outside the declared set is refused at
    # installation: the program can never even be stored.
    bad = rule(legs=((OTHER, LEG_FIXED, 10),))
    assert validate_payout_rule_shape(bad, ANCHOR) is not None
    book = PayoutRuleBook()
    ok, reason = book.can_install(bad, ANCHOR)
    assert not ok and "outside the declared set" in reason
    with pytest.raises(ValueError):
        book.install(bad, ANCHOR)
    # The owner is not a payable recipient either.
    selfish = rule(recipients=(OWNER, ARTIST), legs=((OWNER, LEG_FIXED, 1),))
    assert validate_payout_rule_shape(selfish, ANCHOR) is not None


# --- #63 row 5: per-execution and per-period caps both bind -------------------


def test_payout_period_cap_binds_across_executions():
    entry = rule(max_period=12)
    book, entry = installed(entry)
    first = book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    assert first.executed and first.total == 5
    second = book.execute(entry.rule_id, SID_2, 101, ANCHOR, 10_000)
    assert second.executed and second.total == 5
    # 10 of the period's 12 are paid; a third 5 would pass the (uncapped)
    # per-execution check but breaks the period cap, so it settles nothing.
    third = book.execute(
        entry.rule_id, bytes.fromhex("33" * 32), 101, ANCHOR, 10_000
    )
    assert not third.executed and "max per period" in third.reason
    assert book.period_total(entry.rule_id, 0) == 10
    # The next period has its own budget.
    nxt = book.execute(
        entry.rule_id, bytes.fromhex("44" * 32), 101, ANCHOR + WEEK, 10_000
    )
    assert nxt.executed and nxt.period_index == 1
    assert book.period_total(entry.rule_id, 1) == 5


# --- #63 row 6: removal follows the account's normal rules --------------------


def test_payout_rule_removal_follows_account_rules():
    book, entry = installed()
    ok, _ = book.can_remove(OWNER, ANCHOR)
    assert ok
    removed = book.remove(OWNER, ANCHOR)
    assert removed.rule_id == entry.rule_id
    assert book.get(OWNER) is None and book.get_by_id(entry.rule_id) is None
    # After removal the rule cannot execute, and a second removal is refused.
    with pytest.raises(ValueError):
        book.evaluate_execution(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    ok, reason = book.can_remove(OWNER, ANCHOR)
    assert not ok and "no payout rule" in reason
    # Removal does not rewrite history: the settlement stays recorded, and
    # reinstalling the identical rule cannot re-pay it.
    book2, entry2 = installed()
    book2.execute(entry2.rule_id, SID_1, 101, ANCHOR, 10_000)
    book2.remove(OWNER, ANCHOR)
    book2.install(entry2, ANCHOR)
    replay = book2.execute(entry2.rule_id, SID_1, 101, ANCHOR, 10_000)
    assert not replay.executed and "already recorded" in replay.reason


# --- Shape, versions, parsing, restore ----------------------------------------


def test_install_shape_and_version_rules():
    book = PayoutRuleBook()
    entry = rule()
    ok, reason = book.can_install(entry, ANCHOR)
    assert ok, reason
    book.install(entry, ANCHOR)
    # The identical rule again is a duplicate, not an update.
    ok, reason = book.can_install(entry, ANCHOR)
    assert not ok and "already exists" in reason
    # A replacement must be the next version, and supersedes wholesale.
    v3 = rule(max_exec=50, version=3)
    ok, reason = book.can_install(v3, ANCHOR)
    assert not ok and "next version" in reason
    v2 = rule(max_exec=50, version=2)
    book.install(v2, ANCHOR)
    assert book.get(OWNER).rule_id == v2.rule_id
    assert book.get_by_id(entry.rule_id) is None
    # A first rule for another owner must start at version 1.
    ok, reason = book.can_install(rule(owner=OTHER, version=2), ANCHOR)
    assert not ok and "version 1" in reason


def test_shape_fail_closed():
    assert validate_payout_rule_shape(rule(), ANCHOR) is None
    bad_entries = [
        rule(recipients=()),                                   # no recipients
        rule(legs=()),                                         # no legs
        rule(legs=((ARTIST, 99, 5),)),                         # unknown mode
        rule(legs=((ARTIST, LEG_BPS_OF_BASE, 0),)),            # zero share
        rule(legs=((ARTIST, LEG_BPS_OF_BASE, 10_001),)),       # share > 100%
        rule(legs=((ARTIST, LEG_FIXED, 0),)),                  # zero fixed leg
        rule(period_seconds=0),                                # no period
        rule(version=0),                                       # version floor
    ]
    for entry in bad_entries:
        assert validate_payout_rule_shape(entry, ANCHOR) is not None, entry


def test_parse_install_and_execute_from_root_fields():
    tx = {
        "sender_pubkey": OWNER,
        "payout_recipients": [WORKER, ARTIST],
        "payout_legs": [[WORKER, LEG_FIXED, 700], [ARTIST, LEG_BPS_OF_BASE, 500]],
        "payout_max_per_execution": 705,
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": ANCHOR,
        # Unsigned nested data must be ignored by the parser.
        "payload": {"payout_recipients": [OTHER]},
    }
    entry = parse_install_payout_rule(tx)
    assert entry.recipients == tuple(sorted({ARTIST, WORKER}))
    assert [leg.recipient_pubkey for leg in entry.legs] == [WORKER, ARTIST]
    assert entry.max_per_execution == 705 and entry.version == 1
    rule_id, settlement_id, base = parse_execute_payout_rule({
        "payout_rule_id": entry.rule_id.hex(),
        "payout_settlement_id": SID_1.hex(),
        "payout_base_amount": 101,
    })
    assert (rule_id, settlement_id, base) == (entry.rule_id, SID_1, 101)
    for malformed in (
        {"payout_recipients": "not-a-list"},
        {"payout_recipients": [ARTIST], "payout_legs": [[ARTIST, 1]]},
        {"payout_recipients": [ARTIST], "payout_legs": [["zz", 1, 2]]},
    ):
        bad = {"sender_pubkey": OWNER, **malformed}
        with pytest.raises(PayoutRuleShapeError):
            parse_install_payout_rule(bad)


def test_compute_legs_floor_and_zero_drop():
    entry = rule(legs=((ARTIST, LEG_BPS_OF_BASE, 500), (WORKER, LEG_FIXED, 3)),
                 recipients=(ARTIST, WORKER))
    assert compute_legs(entry, 101) == ((ARTIST, 5), (WORKER, 3))
    # A base so small the share rounds to zero drops the leg entirely.
    assert compute_legs(entry, 10) == ((WORKER, 3),)
    tiny = rule()
    assert compute_legs(tiny, 10) == ()


def test_execution_before_first_period_and_zero_compute_refused():
    book, entry = installed()
    early = book.execute(entry.rule_id, SID_1, 101, ANCHOR - 1, 10_000)
    assert not early.executed and "first period" in early.reason
    zero = book.execute(entry.rule_id, SID_1, 10, ANCHOR, 10_000)
    assert not zero.executed and "no payment" in zero.reason
    # Neither refusal recorded the settlement: it can still settle properly.
    assert not book.is_settled(entry.rule_id, SID_1)
    ok = book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    assert ok.executed


def test_restore_recomputes_ids_and_root_is_deterministic():
    book, entry = installed()
    book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    clone = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert clone.root() == book.root()
    assert clone.is_settled(entry.rule_id, SID_1)
    assert clone.period_total(entry.rule_id, 0) == 5
    # A tampered row is refused: the id no longer recomputes.
    rows = book.rows()
    tampered = [rows[0][:4] + (999,) + rows[0][5:]]
    with pytest.raises(ValueError):
        PayoutRuleBook.restore(tampered, book.settlement_rows())
    # Copies are deep where it matters: settling the clone leaves the
    # original's period totals alone.
    twin = copy.deepcopy(book)
    twin.execute(entry.rule_id, SID_2, 101, ANCHOR, 10_000)
    assert book.period_total(entry.rule_id, 0) == 5
    assert twin.period_total(entry.rule_id, 0) == 10


def test_capabilities_match_the_module_constants():
    caps = payout_rule_capabilities()
    assert caps["supported"] is True
    assert caps["leg_modes"] == {"fixed": LEG_FIXED, "bps_of_base": LEG_BPS_OF_BASE}
    assert caps["credit_class"] == "payout_leg"


# --- FIX 1-B: the royalty base is the recorded receipt, not the submission ---

BUYER = "e" * 96
RECEIPT_1 = bytes.fromhex("aa" * 32)
RECEIPT_2 = bytes.fromhex("bb" * 32)


def receipt_entry(version=1):
    return PayoutRuleEntry(
        owner_pubkey=OWNER,
        recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 500),),
        max_per_execution=0,
        max_per_period=0,
        period_seconds=WEEK,
        period_anchor_ts=ANCHOR,
        version=version,
        base_source=BASE_RECORDED_RECEIPT,
    )


def record_sale(book, receipt_id=RECEIPT_1, amount=101, sender=BUYER,
                recipient=OWNER):
    receipt = PayoutReceipt(
        receipt_id=receipt_id, recipient_pubkey=recipient,
        sender_pubkey=sender, amount=amount, recorded_ts=ANCHOR,
    )
    assert book.record_receipt(receipt)
    return receipt_id


def test_receipt_base_ignores_inflated_submitted_base():
    """Spec test (a): the royalty settles over the recorded 101, whatever
    base the execution submits — inflated, exact, or absent (0)."""
    book, entry = installed(receipt_entry())
    rid = record_sale(book)
    decision = book.execute(
        entry.rule_id, SID_1, 1_010_000, ANCHOR, 10_000, receipt_id=rid)
    assert decision.executed, decision.reason
    assert decision.legs == ((ARTIST, 5),)
    assert decision.total == 5
    # The settlement record proves the base that was used: the recorded
    # 101, never the submitted 1,010,000.
    record = book.settlement(entry.rule_id, SID_1)
    assert record is not None and record.base_amount == 101
    assert record.receipt_id == rid
    assert book.receipt_consumed(rid)

    # A second sale settles the same way with NO base submitted at all:
    # the submitted field is not merely capped, it is not read.
    rid2 = record_sale(book, receipt_id=RECEIPT_2)
    decision = book.execute(
        entry.rule_id, SID_2, 0, ANCHOR, 10_000, receipt_id=rid2)
    assert decision.executed, decision.reason
    assert decision.total == 5
    assert book.period_total(entry.rule_id, 0) == 10


def test_second_execution_on_same_receipt_refused():
    """Spec test (b): one receipt funds exactly one execution."""
    book, entry = installed(receipt_entry())
    rid = record_sale(book)
    first = book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000,
                         receipt_id=rid)
    assert first.executed
    # A fresh settlement id does not help: the receipt is spent.
    again = book.execute(entry.rule_id, SID_2, 101, ANCHOR, 10_000,
                         receipt_id=rid)
    assert not again.executed
    assert "already funded an execution" in again.reason
    assert not book.is_settled(entry.rule_id, SID_2)
    assert book.period_total(entry.rule_id, 0) == 5
    # Evaluation agrees with execution (admission reads the same state).
    peek = book.evaluate_execution(entry.rule_id, SID_2, 101, ANCHOR,
                                   10_000, receipt_id=rid)
    assert not peek.executed


def test_receipt_execution_refusals():
    book, entry = installed(receipt_entry())
    rid = record_sale(book)
    # No receipt named.
    noname = book.evaluate_execution(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    assert not noname.executed and "must name" in noname.reason
    # An id the node never recorded.
    unknown = book.evaluate_execution(
        entry.rule_id, SID_1, 101, ANCHOR, 10_000,
        receipt_id=bytes.fromhex("ff" * 32))
    assert not unknown.executed and "no recorded receipt" in unknown.reason
    # A receipt of somebody else's sale.
    other_rid = record_sale(book, receipt_id=RECEIPT_2, recipient=OTHER)
    foreign = book.evaluate_execution(
        entry.rule_id, SID_1, 101, ANCHOR, 10_000, receipt_id=other_rid)
    assert not foreign.executed and "not received by" in foreign.reason
    # A submitted-base rule gains nothing by naming a receipt.
    legacy_book, legacy = installed()
    named = legacy_book.evaluate_execution(
        legacy.rule_id, SID_1, 101, ANCHOR, 10_000, receipt_id=rid)
    assert not named.executed and "submitted amount" in named.reason


def test_receipt_rule_shape_and_parse():
    # A receipt-based rule with no basis-point leg has nothing for the
    # recorded base to compute over: refused at install shape.
    fixed_only = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, LEG_FIXED, 5),),
        max_per_execution=0, max_per_period=0, period_seconds=WEEK,
        period_anchor_ts=ANCHOR, version=1,
        base_source=BASE_RECORDED_RECEIPT,
    )
    problem = validate_payout_rule_shape(fixed_only, ANCHOR)
    assert problem is not None and "basis-point" in problem
    assert validate_payout_rule_shape(receipt_entry(), ANCHOR) is None
    bad_source = PayoutRuleEntry(
        owner_pubkey=OWNER, recipients=(ARTIST,),
        legs=(PayoutLeg(ARTIST, LEG_BPS_OF_BASE, 500),),
        max_per_execution=0, max_per_period=0, period_seconds=WEEK,
        period_anchor_ts=ANCHOR, version=1, base_source=7,
    )
    assert validate_payout_rule_shape(bad_source, ANCHOR) is not None
    # Parsing: the signed root fields land on the entry / the execution.
    tx = {
        "sender_pubkey": OWNER,
        "payout_recipients": [ARTIST],
        "payout_legs": [[ARTIST, LEG_BPS_OF_BASE, 500]],
        "payout_max_per_execution": 0,
        "payout_max_per_period": 0,
        "payout_period_seconds": WEEK,
        "payout_period_anchor_ts": ANCHOR,
        "payout_version": 1,
        "payout_base_source": BASE_RECORDED_RECEIPT,
    }
    assert parse_install_payout_rule(tx).base_source == BASE_RECORDED_RECEIPT
    del tx["payout_base_source"]
    assert parse_install_payout_rule(tx).base_source == BASE_SUBMITTED
    assert parse_execute_payout_receipt_id({}) is None
    assert parse_execute_payout_receipt_id(
        {"payout_receipt_id": "aa" * 32}) == RECEIPT_1
    with pytest.raises(PayoutRuleShapeError):
        parse_execute_payout_receipt_id({"payout_receipt_id": "not-hex"})


def test_legacy_rule_ids_and_book_root_unchanged():
    """The byte-for-byte pin: pre-1-B rules and books hash as before."""
    from consensus.serialization import (
        compute_payout_rule_book_root,
        compute_payout_rule_id,
    )

    entry = rule()
    legacy_id = compute_payout_rule_id(
        entry.owner_pubkey, entry.recipients,
        tuple((leg.recipient_pubkey, leg.mode, leg.value) for leg in entry.legs),
        entry.max_per_execution, entry.max_per_period,
        entry.period_seconds, entry.period_anchor_ts, entry.version,
    )
    assert entry.rule_id == legacy_id
    book, entry = installed()
    book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000)
    rows_legacy = [r[:10] for r in book.rows()]
    settlements_legacy = [s[:5] for s in book.settlement_rows()]
    assert book.root() == compute_payout_rule_book_root(
        rows_legacy, settlements_legacy)
    # And a receipt-based rule is a DIFFERENT rule from its submitted-base
    # twin: the base source is inside its id.
    assert receipt_entry().rule_id != rule().rule_id


def test_receipt_restore_roundtrip_keeps_consumption():
    book, entry = installed(receipt_entry())
    rid = record_sale(book)
    book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000, receipt_id=rid)
    clone = PayoutRuleBook.restore(
        book.rows(), book.settlement_rows(), book.receipt_rows())
    assert clone.root() == book.root()
    assert clone.receipt_consumed(rid)
    assert clone.get_receipt(rid).amount == 101
    again = clone.execute(entry.rule_id, SID_2, 101, ANCHOR, 10_000,
                          receipt_id=rid)
    assert not again.executed


def test_receipt_survives_removal_and_replacement():
    book, entry = installed(receipt_entry())
    rid = record_sale(book)
    book.execute(entry.rule_id, SID_1, 101, ANCHOR, 10_000, receipt_id=rid)
    book.remove(OWNER, ANCHOR)
    # The receipt (and its consumption) outlives the rule, like a
    # settlement: reinstalling can never make the same sale pay twice.
    assert not book.is_empty()
    assert book.receipts_for(OWNER)[0].receipt_id == rid
    book.install(receipt_entry(version=1), ANCHOR)
    again = book.evaluate_execution(
        book.get(OWNER).rule_id, SID_2, 101, ANCHOR, 10_000, receipt_id=rid)
    assert not again.executed and "already funded" in again.reason
