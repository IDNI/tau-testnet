# Payout rules and conditional grants (Bounty 01, issue #63)

Two node-held books extend programmable payments from fixed standing
payments to rule-computed payouts and held, conditioned money.

## Payout rules

An owner installs **one** payout rule (`payout_rule_install`): a
maximum per execution, a maximum per period, a declared recipient
set (1..8 pubkeys) and a period kind with an anchor. Every term is
inside the signing preimage.

Anyone may submit `payout_execute` with a settlement id and a gross
input. The node steps the owner's rule -- its accepted clause on
stream 24 -- with the gross on i1, the executor on i3 and the owner
on i12, and reads the legs from the outputs: a count on o20, then
(amount, recipient index) pairs on o21/o22, o23/o24, o25/o26,
o27/o28 (at most 4 legs). The node, never the rule, checks:

- every leg's recipient is in the declared set (by construction of
  the index encoding, an undeclared recipient cannot be named);
- the total is within the per-execution cap AND the per-period cap
  (period spend lives in the book, so the cap binds across
  executions and across executors);
- the owner's balance covers the total;
- the settlement id has never settled.

All legs then apply atomically with the debit, or none do. The
executor pays the standard transaction fee; the owner is never
charged for an execution. `payout_rule_remove` is owner-signed and
follows the account's normal rules, like a standing cancel.

Settlement ids are the idempotency property: a 5% royalty rule
stepped twice with the same settlement id pays 5, once.

## Conditional grants

`grant_create` debits the sender immediately into a book entry: the
money is held by the grant, not by the recipient's balance, so a
refund never pulls from a balance that may no longer hold it.
Conditions combine by AND:

- a per-period draw cap; the period is one week (604800 s) from the
  grant's opening anchor, the same period arithmetic as standing
  payments;
- optionally, a shared cap: `grant_create` may name a `cap_group`
  and a `cap_group_cap`, and every grant of the same sender in that
  group then shares one per-period draw budget on top of the
  per-grant caps -- a draw must satisfy both. All grants in a group
  declare the same group cap and open at the same anchor (a grant
  that disagrees is refused at creation), so the group's
  spent-in-period is exactly the sum of the members' own period
  counters in the current window: the shared counter lives in the
  same book rows that feed the consensus root and persistence,
  never in a side channel. Grants without a group behave exactly
  as before;
- draws open at `opens_at` and close at `deadline`.

A grant whose draws could never open before its deadline is refused
at creation. Only the recipient may draw (`grant_draw`, signed).
At the deadline the refund wins: the end-of-block sweep returns the
full unspent remainder to the sender, fee-free like the codebase's
other sweep movements, so the remainder is never reduced by a fee
nobody signed for. Held grant money is part of the chain's supply
invariant, counted alongside the retractable escrow.

Whether a draw may happen is decided by the sender's Tau clause,
not by the book: the sender publishes a clause on the grant stream
(stream 29), and a draw steps it -- on the same evaluation path as
payout executions -- with the draw's facts: the requested amount,
the remaining grant, the amount already drawn in the current
period, the declared per-period cap, the opens/deadline window and,
for a grouped grant, the group's drawn-in-period and cap. The
clause's verdict on o29 approves (1) or refuses the draw for its
full requested amount. `CANONICAL_GRANT_CLAUSE` in
`consensus/grants.py` states the conditions above as such a clause,
so publishing it reproduces exactly the semantics first shipped;
a sender may publish a stricter clause (its own extra conditions),
never a looser one, because the book re-checks its declared caps
after the clause approves -- the same defence in depth payout
executions keep. A sender who has published no grant clause cannot
be drawn on at all: admission and apply both refuse.

Worked example (the bounty page's demo): 5,000 granted, cap
500/week, draws open December 1, remainder refunds at the deadline
-- `test_grant_5000_week_cap_refund_returns_remainder`.

## Deliberate limits

- One payout rule per owner; at most 4 legs per execution; legs are
  chosen by index into the declared set (the rule cannot invent a
  recipient, and the encoding keeps leg outputs in plain integer
  streams).
- Payout legs and grant draws are book movements: they never
  trigger receive routes, standing payments or each other.
- Grant periods are weeks from the opening anchor; calendar-month
  grant periods are future work.
