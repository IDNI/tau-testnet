"""Rule-computed payouts (#63): the PayoutBook in consensus/payments.py.

The payout `clause` callable passed to ``PayoutBook.execute`` is the
scripted double for the native Tau clause evaluation: in production the
installed Tau clause is stepped in its isolated pool and outputs
(candidate_index, amount) legs; here a plain Python callable stands in
for it. Everything around the clause — the signed candidate set,
per-candidate caps, per-execution and per-period caps, owner balance,
atomic-or-none settlement and pays-once per event — is enforced by the
book itself and is what these tests pin down.

Deterministic, no native bindings.
"""
from __future__ import annotations

import pytest

from consensus.payments import (
    DictLedger,
    PaymentRefused,
    PaymentShapeError,
    PayoutBook,
    PayoutTerms,
)

TS0 = 1_800_000_000
SECONDS_PER_WEEK = 7 * 24 * 60 * 60


def pk(i: int) -> str:
    return f"{i:096x}"


def _terms(owner, candidates, max_per_execution=10_000, max_per_period=10_000):
    return PayoutTerms(
        owner=owner,
        candidates=tuple(candidates),
        max_per_execution=max_per_execution,
        max_per_period=max_per_period,
        period_kind="week",
        anchor_ts=TS0,
        sequence_number=0,
    )


def _book_and_ledger(owner, balance, terms):
    ledger = DictLedger({owner: balance})
    book = PayoutBook()
    rule_id = book.install(terms)
    return book, ledger, rule_id


# 1. gmikeyg case 2: a 5% royalty on a gross of 101 pays exactly 5, once.
def test_royalty_5pct_on_101_pays_5_once():
    owner, artist = pk(1), pk(2)
    terms = _terms(owner, ((artist, 1000),))
    book, ledger, rule_id = _book_and_ledger(owner, 1000, terms)
    clause = lambda inputs: [(0, inputs["gross"] * 5 // 100)]

    receipt = book.execute(
        rule_id, "sale-1", {"gross": 101}, clause, ts=TS0, ledger=ledger)
    assert receipt.total == 5
    assert receipt.legs == ((artist, 5),)
    assert ledger.balance(artist) == 5
    assert ledger.balance(owner) == 995

    # Same event again: pays-once is a book property (the clause itself is
    # stateless), so the replay is refused and nothing moves.
    with pytest.raises(PaymentRefused):
        book.execute(
            rule_id, "sale-1", {"gross": 101}, clause, ts=TS0, ledger=ledger)
    assert ledger.balance(artist) == 5
    assert ledger.balance(owner) == 995


# 2. The rule computes RECIPIENTS within the signed candidate set, not
# just amounts: different inputs select different candidates.
def test_payout_rule_selects_recipient_from_candidates():
    owner = pk(1)
    worker, reviewer, poster = pk(2), pk(3), pk(4)
    terms = _terms(
        owner,
        ((worker, 1000), (reviewer, 1000), (poster, 1000)),
        max_per_execution=1000,
    )
    book, ledger, rule_id = _book_and_ledger(owner, 1000, terms)
    clause = lambda inputs: [(inputs["winner"], inputs["amount"])]

    r1 = book.execute(rule_id, "job-1", {"winner": 0, "amount": 120},
                      clause, ts=TS0, ledger=ledger)
    assert r1.legs == ((worker, 120),)
    assert ledger.balance(worker) == 120
    assert ledger.balance(reviewer) == 0
    assert ledger.balance(poster) == 0

    r2 = book.execute(rule_id, "job-2", {"winner": 2, "amount": 80},
                      clause, ts=TS0, ledger=ledger)
    assert r2.legs == ((poster, 80),)
    assert ledger.balance(worker) == 120
    assert ledger.balance(reviewer) == 0
    assert ledger.balance(poster) == 80
    assert ledger.balance(owner) == 1000 - 120 - 80


# 3. There is no leg shape that pays an account outside the signed
# candidate set: legs name candidates by index only.
def test_payout_to_undeclared_account_impossible():
    owner = pk(1)
    candidates = (pk(2), pk(3), pk(4))
    outsider = pk(99)
    terms = _terms(owner, tuple((c, 1000) for c in candidates))
    book, ledger, rule_id = _book_and_ledger(owner, 1000, terms)

    with pytest.raises(PaymentRefused):
        book.execute(rule_id, "bad-high", {}, lambda inputs: [(7, 10)],
                     ts=TS0, ledger=ledger)
    with pytest.raises(PaymentRefused):
        book.execute(rule_id, "bad-negative", {}, lambda inputs: [(-1, 10)],
                     ts=TS0, ledger=ledger)

    assert ledger.balance(owner) == 1000
    for cand in candidates:
        assert ledger.balance(cand) == 0
    assert ledger.balance(outsider) == 0

    # Even a successful execution can only ever resolve to candidate
    # pubkeys — pk(99) is not a candidate, so no clause output reaches it.
    receipt = book.execute(rule_id, "good", {}, lambda inputs: [(1, 10)],
                           ts=TS0, ledger=ledger)
    assert receipt.legs == ((pk(3), 10),)
    assert all(pubkey in candidates for pubkey, _ in receipt.legs)
    assert ledger.balance(outsider) == 0


# 4. The #63 work-escrow evidence scenario: a locked amount of 1000 is
# settled in full on every path, to candidates only, owner drained to 0.
def test_work_escrow_settlement_matches_locked_amount():
    owner = pk(1)
    worker, rev1, rev2 = pk(2), pk(3), pk(4)
    defect_claimant, holdback, poster = pk(5), pk(6), pk(7)
    candidate_pubkeys = (worker, rev1, rev2, defect_claimant, holdback, poster)
    # Indices: 0 worker, 1 rev1, 2 rev2, 3 defect_claimant, 4 holdback, 5 poster.
    paths = {
        "clean acceptance": [(0, 600), (1, 50), (2, 50), (4, 100), (5, 200)],
        "defect upheld": [(0, 400), (3, 150), (1, 50), (2, 50), (4, 100), (5, 250)],
        "work rejected": [(4, 100), (5, 900)],
    }
    for name, legs in paths.items():
        terms = _terms(
            owner,
            tuple((c, 1000) for c in candidate_pubkeys),
            max_per_execution=1000,
            max_per_period=1000,
        )
        book, ledger, rule_id = _book_and_ledger(owner, 1000, terms)
        clause = lambda inputs: list(inputs["legs"])

        receipt = book.execute(rule_id, f"settle-{name}", {"legs": legs},
                               clause, ts=TS0, ledger=ledger)

        assert sum(amount for _, amount in legs) == 1000, name
        assert receipt.total == 1000, name
        assert sum(amount for _, amount in receipt.legs) == 1000, name
        assert ledger.balance(owner) == 0, name
        assert all(pubkey in candidate_pubkeys
                   for pubkey, _ in receipt.legs), name
        expected = {c: 0 for c in candidate_pubkeys}
        for index, amount in legs:
            expected[candidate_pubkeys[index]] += amount
        for cand, amount in expected.items():
            assert ledger.balance(cand) == amount, (name, cand)


# 5. A leg over its candidate cap refuses the WHOLE execution: leg 2 was
# within its own cap and still settles nothing.
def test_payout_candidate_cap_enforced_atomically():
    owner, capped, other = pk(1), pk(2), pk(3)
    terms = _terms(owner, ((capped, 100), (other, 1000)))
    book, ledger, rule_id = _book_and_ledger(owner, 1000, terms)

    with pytest.raises(PaymentRefused):
        book.execute(rule_id, "over-cap", {},
                     lambda inputs: [(0, 150), (1, 50)],
                     ts=TS0, ledger=ledger)
    assert ledger.balance(owner) == 1000
    assert ledger.balance(capped) == 0
    assert ledger.balance(other) == 0


# 6. Per-execution cap, then per-period cap within one week, then the
# same spend settles again once the next weekly period opens.
def test_payout_execution_and_period_caps():
    owner, payee = pk(1), pk(2)
    terms = _terms(owner, ((payee, 10_000),),
                   max_per_execution=300, max_per_period=500)
    book, ledger, rule_id = _book_and_ledger(owner, 5000, terms)
    clause = lambda inputs: [(0, inputs["amount"])]

    with pytest.raises(PaymentRefused):
        book.execute(rule_id, "over-exec", {"amount": 301},
                     clause, ts=TS0, ledger=ledger)
    assert ledger.balance(owner) == 5000
    assert ledger.balance(payee) == 0

    book.execute(rule_id, "w1-a", {"amount": 300},
                 clause, ts=TS0, ledger=ledger)
    assert ledger.balance(payee) == 300

    with pytest.raises(PaymentRefused):
        book.execute(rule_id, "w1-b", {"amount": 300},
                     clause, ts=TS0 + 3600, ledger=ledger)
    assert ledger.balance(owner) == 5000 - 300
    assert ledger.balance(payee) == 300

    book.execute(rule_id, "w2-a", {"amount": 300},
                 clause, ts=TS0 + SECONDS_PER_WEEK, ledger=ledger)
    assert ledger.balance(owner) == 5000 - 600
    assert ledger.balance(payee) == 600


# 7. Owner balance below the clause total: refused, no credits at all.
def test_payout_insufficient_balance_settles_nothing():
    owner, payee = pk(1), pk(2)
    terms = _terms(owner, ((payee, 1000),))
    book, ledger, rule_id = _book_and_ledger(owner, 40, terms)

    with pytest.raises(PaymentRefused):
        book.execute(rule_id, "too-big", {}, lambda inputs: [(0, 50)],
                     ts=TS0, ledger=ledger)
    assert ledger.balance(owner) == 40
    assert ledger.balance(payee) == 0


# 8. Install-time shape bounds on the signed candidate set: 1..8
# candidates, no duplicates. The shape error fires when the terms are
# constructed, before any rule reaches the book.
def test_payout_install_shape_bounds():
    owner = pk(1)
    nine = tuple((pk(10 + i), 100) for i in range(9))
    with pytest.raises(PaymentShapeError):
        PayoutTerms(owner=owner, candidates=nine,
                    max_per_execution=1000, max_per_period=1000,
                    period_kind="week", anchor_ts=TS0, sequence_number=0)

    with pytest.raises(PaymentShapeError):
        PayoutTerms(owner=owner, candidates=(),
                    max_per_execution=1000, max_per_period=1000,
                    period_kind="week", anchor_ts=TS0, sequence_number=0)

    with pytest.raises(PaymentShapeError):
        PayoutTerms(owner=owner, candidates=((pk(2), 100), (pk(2), 200)),
                    max_per_execution=1000, max_per_period=1000,
                    period_kind="week", anchor_ts=TS0, sequence_number=0)
