"""Bounty 01, FIX 7: multi-rule payout books on the REAL Tau engine.

Kept in its own file so the real-Tau CI job can register exactly this
file (the pattern of the other Bounty 01 native suites): the payout
clauses and the guard clause below step through the real
policy-evaluation path, which needs the native bindings the mock job
does not have. The skip is environment-driven.

The gap (differential audit vs #178 @ 47a110e and #160 @ cb8c42d): both
rivals key their payout book by (account, rule slot) — an account holds
several independent payout rules. FIX 5C's book held ONE rule per owner.
FIX 7 closes the gap: up to MAX_RULES_PER_OWNER (8) rules per account,
each addressed by its signed slot (payout_rule_index, 0..7), each with
its own caps, period anchor, period totals, settlements, version chain
and FIX 5C replacement carry — per rule, never across rules.

What this proves, with real Tau clauses stepped by the real evaluator:

(a) Eight rules install for one owner and pay independently — each
    rule's clause is stepped through sender_policy.clause_outputs, and
    each execution settles under its own rule id and period total.
(b) A ninth rule is refused: slot 8 is outside the signed slot range,
    at shape level and at the book.
(c) Per-rule caps bind separately: rule A exhausts its own per-period
    cap and refuses further executions while rule B of the same owner,
    in the same period, still pays in full — no borrowing across rules.
(d) The FIX 5C replacement carry is per rule: replacing rule 1 carries
    rule 1's current-period paid total into its replacement's first
    period, and rule 0's replacement carries rule 0's total only —
    neither sees the other's payments.
(e) Guard kinds 7/8/9 act per rule: a kind 7 body naming slot 3
    installs there and nowhere else; a kind 8 body naming slot 1
    replaces slot 1 only; a kind 9 request naming slot 2's rule id in
    offer_id revokes slot 2 only — and a kind 9 naming another owner's
    rule is refused. A kind-selective guard clause stepped on the real
    evaluator still judges kinds 7/8/9 individually.
(f) Retry is per rule: payout executions carry no node-side due point
    by design (a refused execution settles nothing and records no
    settlement — the book's standing discipline), so a retry is an
    explicit resubmission. Two rules of one owner refused in the same
    period for insufficient balance are retried independently: funding
    the owner and resubmitting rule A settles A alone; rule B remains
    unsettled with its own period total untouched until its own
    resubmission settles it.
"""
import hashlib
import os
import pathlib

import pytest

import tau_defs
from consensus import sender_policy
from consensus.approvals import RuleChangeRequest, payout_payload_text
from consensus.engine import _write_payment_book_change
from consensus.governance import ConsensusLifecycleManager
from consensus.payout_rules import (
    FORM_TAU_RULE,
    MAX_RULES_PER_OWNER,
    PayoutRuleBook,
    PayoutRuleEntry,
    decode_clause_legs,
    payout_clause_inputs,
    validate_payout_rule_shape,
)
from consensus.rule_offers import clause_body_v1


def _native_available():
    try:
        import tau_native
        tau_native.load_tau_module()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(
    not _native_available(), reason="native tau module not built")

REPO = str(pathlib.Path(__file__).resolve().parent.parent)
TIMEOUT = 120.0

ANCHOR = 1_700_000_000
WEEK = 604_800
TS = ANCHOR + 1000  # inside every rule's first period


def _key(label):
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest()
        for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


OWNER = _key("owner")
OTHER_OWNER = _key("other-owner")
EXECUTOR = _key("executor")
RECIPIENTS = [_key(f"recipient-{i}") for i in range(8)]


def _env():
    env = dict(os.environ)
    env["PYTHONPATH"] = REPO + os.pathsep + env.get("PYTHONPATH", "")
    return env


@pytest.fixture
def real():
    """A real policy worker behind both consensus pools."""
    import tau_policy

    ev = tau_policy.PolicyEvaluator(cwd=REPO, env=_env(), timeout=TIMEOUT)
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, ev)
    yield ev
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)
    ev.close()


def _pay_clause(amount):
    """A Tau clause paying candidate 0 exactly `amount`, unconditionally."""
    return (
        "((o30[t]:bv[64] = { 1 }:bv[64]) "
        "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
        f"&& (o32[t]:bv[64] = {{ {amount} }}:bv[64]))"
    )


def _rule(index, amount, *, owner=OWNER, max_period=0, max_exec=0,
          version=1, anchor=ANCHOR):
    return PayoutRuleEntry(
        owner_pubkey=owner,
        recipients=(RECIPIENTS[index],),
        legs=(),
        max_per_execution=max_exec,
        max_per_period=max_period,
        period_seconds=WEEK,
        period_anchor_ts=anchor,
        version=version,
        form=FORM_TAU_RULE,
        clause_text=_pay_clause(amount),
        rule_index=index,
    )


def _sid(n):
    return bytes([n]) * 32


def _execute(book, entry, sid, balance, ts=TS):
    """Step the rule's REAL clause and settle through the book — the
    admission/apply construction: node-built inputs, decoded legs, the
    book's own checks."""
    outputs, detail = sender_policy.clause_outputs(
        entry.clause_text,
        payout_clause_inputs(
            entry, EXECUTOR, 1, ts, balance,
            book.period_paid_total(entry, ts)),
        pool="apply",
    )
    assert outputs is not None, f"clause did not step: {detail}"
    legs, why = decode_clause_legs(entry, outputs)
    assert legs is not None, why
    return book.execute(
        entry.rule_id, sid, 1, ts, balance, clause_legs=legs)


# --- (a) eight rules install and pay independently ------------------------------


def test_eight_rules_install_and_pay_independently(real):
    book = PayoutRuleBook()
    entries = [_rule(i, 100 + i) for i in range(MAX_RULES_PER_OWNER)]
    for entry in entries:
        ok, reason = book.can_install(entry, TS)
        assert ok, reason
        book.install(entry, TS)
    assert book.rule_count() == MAX_RULES_PER_OWNER
    assert book.rule_count_for_owner(OWNER) == MAX_RULES_PER_OWNER
    # Distinct slots are distinct rules even before terms differ.
    assert len({e.rule_id for e in entries}) == MAX_RULES_PER_OWNER

    for i, entry in enumerate(entries):
        decision = _execute(book, entry, _sid(10 + i), balance=10_000)
        assert decision.executed, decision.reason
        assert decision.legs == ((RECIPIENTS[i], 100 + i),)
        assert book.period_total(entry.rule_id, 0) == 100 + i
        assert book.is_settled(entry.rule_id, _sid(10 + i))


# --- (b) the ninth rule is refused ----------------------------------------------


def test_a_ninth_rule_is_refused(real):
    book = PayoutRuleBook()
    for i in range(MAX_RULES_PER_OWNER):
        book.install(_rule(i, 100), TS)
    ninth = _rule(MAX_RULES_PER_OWNER, 100)
    # The slot itself is out of range: a shape refusal, before the book.
    assert validate_payout_rule_shape(ninth, TS) is not None
    ok, reason = book.can_install(ninth, TS)
    assert not ok and "at most" in reason
    # And with every slot full, the only remaining installs are version
    # bumps of existing slots — a "ninth rule" wearing slot 0's address
    # at version 1 is the slot's own chain refusing it.
    impostor = _rule(0, 999)
    ok, reason = book.can_install(impostor, TS)
    assert not ok


# --- (c) per-rule caps bind separately -------------------------------------------


def test_per_rule_caps_bind_separately(real):
    book = PayoutRuleBook()
    rule_a = _rule(0, 400, max_period=500)
    rule_b = _rule(1, 400, max_period=500)
    book.install(rule_a, TS)
    book.install(rule_b, TS)

    first = _execute(book, rule_a, _sid(21), balance=10_000)
    assert first.executed
    # Rule A's next execution would push ITS period total to 800 > 500.
    refused = _execute(book, rule_a, _sid(22), balance=10_000)
    assert not refused.executed
    assert "max per period" in refused.reason
    assert book.period_total(rule_a.rule_id, 0) == 400
    # Rule B's allowance is its own: the same amount pays in full.
    other = _execute(book, rule_b, _sid(23), balance=10_000)
    assert other.executed, other.reason
    assert book.period_total(rule_b.rule_id, 0) == 400


# --- (d) the replacement carry is per rule ---------------------------------------


def test_replacement_carry_is_per_rule(real):
    book = PayoutRuleBook()
    rule_0 = _rule(0, 100, max_period=1000)
    rule_1 = _rule(1, 300, max_period=1000)
    book.install(rule_0, TS)
    book.install(rule_1, TS)
    assert _execute(book, rule_0, _sid(31), balance=10_000).executed
    assert _execute(book, rule_1, _sid(32), balance=10_000).executed

    # Replace slot 1: its replacement's first period starts at 300 —
    # rule 1's own paid total carried (FIX 5C), nothing of rule 0's.
    rule_1_v2 = _rule(1, 300, max_period=1000, version=2)
    book.install(rule_1_v2, TS)
    assert book.period_total(rule_1_v2.rule_id, 0) == 300
    # Slot 0 is untouched by its neighbour's replacement.
    assert book.get(OWNER, 0).rule_id == rule_0.rule_id
    assert book.period_total(rule_0.rule_id, 0) == 100

    # Replace slot 0: it carries its OWN 100, not slot 1's 300.
    rule_0_v2 = _rule(0, 100, max_period=1000, version=2)
    book.install(rule_0_v2, TS)
    assert book.period_total(rule_0_v2.rule_id, 0) == 100
    assert book.period_total(rule_1_v2.rule_id, 0) == 300


# --- (e) guard kinds 7/8/9 act per rule ------------------------------------------


def _request(kind, *, sender=OWNER, text="", offer_id="", seq=1):
    return RuleChangeRequest(
        sender_pubkey=sender, sequence_number=seq, kind=kind,
        rule_text=text, offer_id=offer_id, approvers={},
        expire_at_height=5000,
    )


def test_guard_kinds_act_per_rule(real):
    lm = ConsensusLifecycleManager(active_validators=[EXECUTOR])
    book = lm.payout_rules
    for i in range(3):
        book.install(_rule(i, 100 + i), TS)
    ids_before = {i: book.get(OWNER, i).rule_id for i in range(3)}

    # Kind 7 naming slot 3 installs there — and only there.
    new_rule = _rule(3, 700)
    problem = _write_payment_book_change(
        lm, _request(tau_defs.RULE_CHANGE_KIND_SET_PAYOUT,
                     text=payout_payload_text(new_rule)), 50, TS)
    assert problem is None
    assert book.get(OWNER, 3).rule_id == new_rule.rule_id
    for i in range(3):
        assert book.get(OWNER, i).rule_id == ids_before[i]

    # Kind 7 naming an occupied slot is refused; the slot is untouched.
    problem = _write_payment_book_change(
        lm, _request(tau_defs.RULE_CHANGE_KIND_SET_PAYOUT,
                     text=payout_payload_text(_rule(1, 999))), 50, TS)
    assert problem is not None
    assert book.get(OWNER, 1).rule_id == ids_before[1]

    # Kind 8 naming slot 1 replaces slot 1 only.
    rule_1_v2 = _rule(1, 555, version=2)
    problem = _write_payment_book_change(
        lm, _request(tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT,
                     text=payout_payload_text(rule_1_v2)), 50, TS)
    assert problem is None
    assert book.get(OWNER, 1).rule_id == rule_1_v2.rule_id
    assert book.get(OWNER, 0).rule_id == ids_before[0]
    assert book.get(OWNER, 2).rule_id == ids_before[2]
    assert book.get(OWNER, 3).rule_id == new_rule.rule_id

    # Kind 9 naming slot 2's rule id revokes slot 2 only.
    problem = _write_payment_book_change(
        lm, _request(tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT,
                     offer_id=ids_before[2].hex()), 50, TS)
    assert problem is None
    assert book.get(OWNER, 2) is None
    assert book.get(OWNER, 0).rule_id == ids_before[0]
    assert book.get(OWNER, 1).rule_id == rule_1_v2.rule_id
    assert book.get(OWNER, 3).rule_id == new_rule.rule_id

    # Kind 9 naming another owner's rule is refused, whoever sends it.
    foreign = _rule(0, 100, owner=OTHER_OWNER)
    book.install(foreign, TS)
    problem = _write_payment_book_change(
        lm, _request(tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT,
                     offer_id=foreign.rule_id.hex()), 50, TS)
    assert problem is not None
    assert book.get(OTHER_OWNER, 0).rule_id == foreign.rule_id


def test_a_kind_selective_guard_judges_each_payment_kind(real):
    # Block exactly kind 9 (the revoke), allow 7 and 8 — stepped on the
    # real evaluator, the FIX 5B granularity carried into multi-rule.
    body = clause_body_v1(
        "always ( ((i1[t]:bv[24] = { #x000009 }:bv[24]) ? "
        "(o5[t]:bv[24] = { #x000000 }:bv[24]) : "
        "(o5[t]:bv[24] = { #x000001 }:bv[24])) ).")
    assert real.validate(body).ok
    for kind, expected in (
        (tau_defs.RULE_CHANGE_KIND_SET_PAYOUT, False),
        (tau_defs.RULE_CHANGE_KIND_UPDATE_PAYOUT, False),
        (tau_defs.RULE_CHANGE_KIND_REVOKE_PAYOUT, True),
    ):
        blocked, _detail = sender_policy.rule_change_blocked(
            lambda who, idx: body, OWNER, kind, TS, pool="apply")
        assert blocked is expected, kind


# --- (f) retry is per rule --------------------------------------------------------


def test_retry_is_per_rule(real):
    book = PayoutRuleBook()
    rule_a = _rule(0, 400)
    rule_b = _rule(1, 400)
    book.install(rule_a, TS)
    book.install(rule_b, TS)

    # Both executions are refused for insufficient balance: nothing
    # settles, no settlement is recorded, no period total advances —
    # for either rule.
    for entry, sid in ((rule_a, _sid(41)), (rule_b, _sid(42))):
        decision = _execute(book, entry, sid, balance=100)
        assert not decision.executed
        assert "insufficient funds" in decision.reason
        assert not book.is_settled(entry.rule_id, sid)
        assert book.period_total(entry.rule_id, 0) == 0

    # Fund the owner and resubmit rule A alone (the same settlement id —
    # the refusal recorded nothing, so the retry is the same execution):
    # A settles; B remains exactly as refused.
    retried = _execute(book, rule_a, _sid(41), balance=10_000)
    assert retried.executed, retried.reason
    assert book.period_total(rule_a.rule_id, 0) == 400
    assert not book.is_settled(rule_b.rule_id, _sid(42))
    assert book.period_total(rule_b.rule_id, 0) == 0

    # Rule B's own resubmission settles it, on its own terms.
    retried_b = _execute(book, rule_b, _sid(42), balance=10_000)
    assert retried_b.executed, retried_b.reason
    assert book.period_total(rule_b.rule_id, 0) == 400
