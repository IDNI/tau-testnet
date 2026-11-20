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
- draws open at `opens_at` and close at `deadline`.

A grant whose draws could never open before its deadline is refused
at creation. Only the recipient may draw (`grant_draw`, signed).
At the deadline the refund wins: the end-of-block sweep returns the
full unspent remainder to the sender, fee-free like the codebase's
other sweep movements, so the remainder is never reduced by a fee
nobody signed for. Held grant money is part of the chain's supply
invariant, counted alongside the retractable escrow.

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
