"""The grant clause is the draw's decision-maker (Bounty 01, #63).

Since the clause reframe, a draw is approved by the sender's Tau
clause on the grant stream, stepped with the draw's facts -- not by
book arithmetic. These tests pin the three properties that make
that a mechanism change and not a relabelling, through the same
scripted-evaluator Chain as test_grants_apply (whose evaluator
plays the Tau engine's role for the seeded clause):

- with no clause published, a draw the book alone would have
  allowed is refused, and the money stays escrowed until the
  refund sweep returns it in full;
- a stricter clause than the book's caps refuses a draw the book
  alone would have allowed, and allows one within its own limit --
  the clause narrows, visibly;
- the canonical clause and the book guardrail agree on the worked
  example's boundary: a draw of exactly the period cap lands, one
  unit more does not move.
"""

from consensus.grants import GRANT_STREAM_INDEX, parse_grant_create
from test_grants_apply import (
    ALICE,
    BOB,
    CAROL,
    DEC1,
    DEADLINE,
    PROPOSER,
    Chain,
    create_tx,
    draw_tx,
)

# A clause stricter than the grant's own 500/week cap: it approves
# only draws of at most 250, whatever the book would allow. The
# scripted evaluator answers for it via ch.verdict below; the text
# itself is the registry entry a live node would step.
STRICT_250_CLAUSE = (
    "always ( (i5[t]:bv[64] >= i28[t]:bv[64]"
    " && i5[t]:bv[64] < i29[t]:bv[64]"
    " && i24[t]:bv[64] <= { #x00000000000000fa }:bv[64])"
    " ? (o29[t]:bv[64] = { #x0000000000000001 }:bv[64])"
    " : (o29[t]:bv[64] = { #x0000000000000000 }:bv[64]) )."
)


def _created_chain():
    ch = Chain({ALICE: 10_000, BOB: 0, CAROL: 0, PROPOSER: 0})
    create = create_tx()
    ch.block([create], height=20, ts=DEC1 - 60)
    assert ch.accepted(create), ch.receipt(create)
    return ch, parse_grant_create(create).grant_id


def test_draw_refused_when_sender_published_no_clause():
    ch, grant_id = _created_chain()
    del ch.lm.rule_offers.accepted_clauses[(ALICE, GRANT_STREAM_INDEX)]
    draw = draw_tx(grant_id, 500)
    ch.block([draw], height=21, ts=DEC1 + 60)
    assert not ch.accepted(draw), ch.receipt(draw)
    assert "no grant clause" in str(ch.receipt(draw))
    # Nothing moved: BOB is empty and the full 5,000 is still held,
    # so the deadline sweep refunds every unit to the sender.
    assert ch.bal[BOB] == 0
    assert ch.book.get(grant_id).remaining == 5000
    ch.block([], height=22, ts=DEADLINE + 1)
    assert ch.bal[ALICE] == 10_000
    assert ch.book.get(grant_id).refunded


def test_stricter_clause_binds_below_the_book_cap():
    ch, grant_id = _created_chain()
    ch.lm.rule_offers.accepted_clauses[(ALICE, GRANT_STREAM_INDEX)] = (
        STRICT_250_CLAUSE
    )
    # The book's cap is 500/week; the clause's is 250. A 500 draw
    # the book alone would allow is refused on the clause's verdict.
    ch.verdict = "0"
    big = draw_tx(grant_id, 500)
    ch.block([big], height=21, ts=DEC1 + 60)
    assert not ch.accepted(big), ch.receipt(big)
    assert "clause refused" in str(ch.receipt(big))
    assert ch.bal[BOB] == 0
    # A 250 draw is inside the clause's limit and lands in full.
    # (The refused draw was ignored, so BOB's sequence is still 0.)
    ch.verdict = "1"
    small = draw_tx(grant_id, 250, seq=0)
    ch.block([small], height=22, ts=DEC1 + 120)
    assert ch.accepted(small), ch.receipt(small)
    assert ch.bal[BOB] == 250
    assert ch.book.get(grant_id).remaining == 4750


def test_canonical_clause_boundary_matches_book_guardrail():
    ch, grant_id = _created_chain()
    # Exactly the period cap: clause and guardrail both allow.
    at_cap = draw_tx(grant_id, 500)
    ch.block([at_cap], height=21, ts=DEC1 + 60)
    assert ch.accepted(at_cap), ch.receipt(at_cap)
    # One unit past the cap inside the same period: refused, and
    # nothing moves -- the same verdict the book alone produced
    # before the reframe.
    over = draw_tx(grant_id, 1, seq=1)
    ch.block([over], height=22, ts=DEC1 + 120)
    assert not ch.accepted(over), ch.receipt(over)
    assert ch.bal[BOB] == 500
    assert ch.book.get(grant_id).remaining == 4500
