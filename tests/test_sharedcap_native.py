"""Bounty 01, FIX 8: shared caps on the REAL Tau engine.

Kept in its own file so the real-Tau CI job can register exactly this
file (the pattern of the other Bounty 01 native suites): the payout
clauses below step through the real policy-evaluation path, which needs
the native bindings the mock job does not have. The skip is
environment-driven.

The gap (differential audit vs #178 @ 0df68c2): clHODL's payout rules
can draw on one shared limit via shared_cap_id + shared_cap_amount.
FIX 7's book gave every rule its own caps only. FIX 8 closes the gap:
a rule may name a shared cap — both fields signed and inside the rule
id — and every rule of the same owner naming the same id draws on that
one amount per period, on top of its own caps.

What this proves, with real Tau clauses stepped by the real evaluator:

(a) Two rules sharing one cap stop exactly at it: 100 + 150 settle
    against a shared amount of 250; a further execution of either rule
    is refused by the shared cap.
(b) A rule's own per-period cap still binds first when it is smaller:
    refused by its own cap while group room remains.
(c) A shared-cap refusal settles nothing — no settlement recorded, no
    period total moved — and when a member is revoked the room frees
    and the SAME settlement id then settles: no debt, no false
    completion.
(d) A signed mid-period update lowering the shared amount respects the
    draws already made: usage stands over the new amount, the room is
    gone, nothing is clawed back.
(e) Restore round-trips the shared terms: the rebuilt book has the
    same root, the same group usage and the same remaining room.
"""
import hashlib
import os
import pathlib

import pytest

from consensus import sender_policy
from consensus.payout_rules import (
    FORM_TAU_RULE,
    PayoutRuleBook,
    PayoutRuleEntry,
    decode_clause_legs,
    payout_clause_inputs,
)


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

GROUP = "royalty-pool"
GROUP_AMOUNT = 250


def _key(label):
    """96 hex digits, not all decimal (an all-digit key reads back as a number)."""
    digits = "".join(
        hashlib.sha256(label.encode() + bytes([i])).hexdigest()
        for i in range(2))[:96]
    assert not digits.isdigit()
    return digits


OWNER = _key("owner")
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


def _pay_clause():
    """A Tau clause paying candidate 0 the submitted base amount (i1).

    The clause MUST read an input stream: the real policy worker refuses
    to step a clause that reads no input stream ("clause cannot be
    evaluated: it reads no input stream"), so a constant clause — however
    correct its arithmetic — can never settle on the native engine. (The
    same rule is documented by the grant clause in
    test_payout_tau_rule_native.py.) The amount paid is the base the
    caller submits; _execute passes the rule's amount as base.
    """
    return (
        "((o30[t]:bv[64] = { 1 }:bv[64]) "
        "&& (o31[t]:bv[64] = { 0 }:bv[64]) "
        "&& (o32[t]:bv[64] = i1[t]:bv[64]))"
    )


def _rule(index, amount, *, max_period=0, version=1, shared=GROUP,
          shared_amount=GROUP_AMOUNT):
    # `amount` is the rule's intended payment. It is NOT baked into the
    # clause text anymore: a constant clause cannot step on the real
    # worker, so the clause pays i1 and the caller passes `amount` as
    # the execution's base to _execute.
    return PayoutRuleEntry(
        owner_pubkey=OWNER,
        recipients=(RECIPIENTS[index],),
        legs=(),
        max_per_execution=0,
        max_per_period=max_period,
        period_seconds=WEEK,
        period_anchor_ts=ANCHOR,
        version=version,
        form=FORM_TAU_RULE,
        clause_text=_pay_clause(),
        rule_index=index,
        shared_cap_id=shared or "",
        shared_cap_amount=shared_amount if shared else 0,
    )


def _sid(n):
    return bytes([n]) * 32


def _execute(book, entry, sid, balance, base, ts=TS):
    """Step the rule's REAL clause and settle through the book — the
    admission/apply construction: node-built inputs, decoded legs, the
    book's own checks.

    `base` is the execution's submitted base amount. The clause pays
    i1, so the base IS the amount that settles — it must be the rule's
    own amount (passing 1 would settle 1, not the rule's terms). The
    same base goes to the book, whose settlement records it.
    """
    outputs, detail = sender_policy.clause_outputs(
        entry.clause_text,
        payout_clause_inputs(
            entry, EXECUTOR, base, ts, balance,
            book.period_paid_total(entry, ts)),
        pool="apply",
    )
    assert outputs is not None, f"clause did not step: {detail}"
    legs, why = decode_clause_legs(entry, outputs)
    assert legs is not None, why
    return book.execute(
        entry.rule_id, sid, base, ts, balance, clause_legs=legs)


def _group_book():
    book = PayoutRuleBook()
    a = _rule(0, 100)
    b = _rule(1, 150)
    book.install(a, TS)
    book.install(b, TS)
    return book, a, b


# --- (a) the group stops exactly at the shared amount ---------------------------


def test_two_tau_rules_share_one_cap_and_stop_at_it(real):
    book, a, b = _group_book()
    first = _execute(book, a, _sid(1), balance=10_000, base=100)
    assert first.executed and first.total == 100, first.reason
    second = _execute(book, b, _sid(2), balance=10_000, base=150)
    assert second.executed and second.total == 150, second.reason
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250
    assert book.shared_cap_left(a, TS) == 0
    for entry, amount in ((a, 100), (b, 150)):
        refused = _execute(book, entry, _sid(3), balance=10_000, base=amount)
        assert not refused.executed
        assert "shared cap" in refused.reason


# --- (b) the rule's own cap binds first -------------------------------------------


def test_the_rules_own_cap_binds_before_the_shared_cap(real):
    book = PayoutRuleBook()
    a = _rule(0, 100, max_period=100)
    b = _rule(1, 150)
    book.install(a, TS)
    book.install(b, TS)
    assert _execute(book, a, _sid(1), balance=10_000, base=100).executed
    # A is at its own per-period cap: refused by THAT cap, with 150 of
    # group room still standing.
    refused = _execute(book, a, _sid(2), balance=10_000, base=100)
    assert not refused.executed
    assert "shared cap" not in refused.reason
    assert "max per period" in refused.reason
    # B draws the remaining group room exactly.
    assert _execute(book, b, _sid(3), balance=10_000, base=150).executed
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250


# --- (c) refusal settles nothing; revocation frees the room ------------------------


def test_a_refusal_settles_nothing_and_revoke_frees_the_room(real):
    book, a, b = _group_book()
    assert _execute(book, a, _sid(1), balance=10_000, base=100).executed
    assert _execute(book, b, _sid(2), balance=10_000, base=150).executed
    refused = _execute(book, a, _sid(3), balance=10_000, base=100)
    assert not refused.executed and "shared cap" in refused.reason
    # The refusal recorded nothing: no settlement, no period movement.
    assert not book.is_settled(a.rule_id, _sid(3))
    assert book.period_total(a.rule_id, 0) == 100
    # Revoking B frees its 150 at once, and the very settlement the cap
    # refused now settles — the refusal left no debt behind it.
    book.remove(OWNER, TS, 1)
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 100
    settled = _execute(book, a, _sid(3), balance=10_000, base=100)
    assert settled.executed and settled.total == 100, settled.reason
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 200


# --- (d) a signed mid-period update respects the draws ------------------------------


def test_a_signed_update_lowering_the_amount_respects_the_draws(real):
    book, a, b = _group_book()
    assert _execute(book, a, _sid(1), balance=10_000, base=100).executed
    assert _execute(book, b, _sid(2), balance=10_000, base=150).executed
    # A's next version lowers the shared amount to 220 — below the 250
    # the group already drew. Nothing is clawed back; the room is gone.
    a2 = _rule(0, 100, version=2, shared_amount=220)
    book.install(a2, TS)
    assert book.shared_cap_usage(OWNER, GROUP, TS) == 250
    assert book.shared_cap_left(a2, TS) == 0
    refused = _execute(book, a2, _sid(3), balance=10_000, base=100)
    assert not refused.executed and "shared cap" in refused.reason


# --- (e) restore round-trips the shared terms ----------------------------------------


def test_restore_round_trips_the_shared_terms(real):
    book, a, b = _group_book()
    assert _execute(book, a, _sid(1), balance=10_000, base=100).executed
    assert _execute(book, b, _sid(2), balance=10_000, base=150).executed
    clone = PayoutRuleBook.restore(book.rows(), book.settlement_rows())
    assert clone.root() == book.root()
    restored = clone.get(OWNER, 0)
    assert restored.shared_cap_id == GROUP
    assert restored.shared_cap_amount == GROUP_AMOUNT
    assert clone.shared_cap_usage(OWNER, GROUP, TS) == 250
    assert clone.shared_cap_left(restored, TS) == 0
    # And the restored book still enforces the cap on the real path.
    refused = _execute(clone, restored, _sid(3), balance=10_000, base=100)
    assert not refused.executed and "shared cap" in refused.reason
