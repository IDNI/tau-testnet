# Programmable payments

Rules on this chain can allow or block a transfer. They cannot start one, and
they cannot decide what happens to money after it arrives. This adds four
consensus objects that do. None of them reads the node's wall clock or an
outside attestation. Time is the block header timestamp, the same value rules
already see on `i5`, already required to be at least the parent's timestamp and
at most `MAX_BLOCK_FUTURE_DRIFT_SECONDS` (120s) ahead of a verifier's clock.

Maintainer approval of a design was not a condition of issues #34, #35 or #63.
Bounty 02 is the bounty that asks for a plan before code. This document is the
design anyway, because the bounty page asks the questions below to be answered,
and because no posted design has been approved.

## Design answers

**Who pays the network fee when a rule sends money.** The account that submits
the transaction pays that transaction's ordinary fee (`o8` + `o9`, capped by
the signed `fee_limit`). Creating or replacing a standing payment, opening an
allowance, drawing from one, installing a route and installing or executing a
payout are fee-bearing. Cancelling, removing and releasing are not, so an
owner can always stop an instruction. The end-of-block sweep is fee-free, like
a retractable release: a standing payment that the sweep pays, and an allowance
refund, move the principal and nothing else. The signed
`max_fee_per_execution` on a standing payment is required to be 0 in this
version, so a sweep cannot debit a fee the payer did not see at creation. An
explicit `standing_payment_execute` is paid by whoever submits it.

**Which events can trigger a payment.** Three.

1. The post-transaction sweep: a standing occurrence whose window is open, and
   an allowance whose refund point has been reached.
2. An ordinary user-transfer credit, for a receive route only.
3. An explicit transaction: `standing_payment_execute` or `payout_execute`,
   which anyone may submit.

A balance threshold, a rule firing another rule, and an outside clock are not
triggers.

**How rules are stopped from triggering each other.** A credit produced by a
route, a standing payment, a payout, a draw or a refund is not routable.
Only an ordinary `user_tx` transfer is. Routing is one hop, in the same
transaction as the gross credit, and the gross, the net and the routed amount
commit together or not at all. A route to the owner, a duplicate destination,
or a destination that already routes back, is rejected at installation. The
back-route check is extra; the credit class is what makes a loop impossible
even if the other route is installed later. Sweep work is capped at 32
mutations a block, oldest due first.

**How a period is measured, and how per-recipient spend is tracked.** A day is
86,400 seconds and a week is 604,800 seconds, counted from the anchor the
signer chose (an allowance's unlock, a shared meter's anchor, a payout's
anchor). A month is a real UTC calendar month from that anchor. The 31st of a
short month falls on its last day, and the day is computed from the original
anchor, so February does not push March off the 31st. An allowance records
what its own grantee has drawn in the current period, on the allowance. A
shared meter, keyed by grantor, grantee and a signed name, records the same
draw a second time when several allowances must share one cap. The first
allowance to use a name defines the cap and the period; a later one with
different terms is rejected. The meter resets when its period index changes.
Nothing carries over.

**Where the time comes from.** The applying block's timestamp. Not the node
clock, and not a trusted outside clock. Issue #62 asks for attested inputs
carried in a transaction. The sweep has no transaction to carry one, and a
draw that depended on an attester being online would not be something every
node could replay. A proposer can move the timestamp forward by at most the
existing 120 second drift, and cannot move it backwards past its parent. That
can open a window or a refund early by about two minutes. It cannot pay an
occurrence twice.

**What starts a refund, and who pays its fee.** An allowance has a required
`expires_at`. It may also have `refund_idle`: if the grantee draws nothing for
that long after the unlock (or after the last draw), the remainder returns
then. The earlier point wins. In the block whose timestamp reaches it, draws
are refused and the sweep returns the full remainder to the grantor. Nobody
pays a fee, and the refund is not routed. A partial draw does not restart an
expiry; it does restart an idle timer.

**How several conditions on one payment combine.** They are fields of one
allowance and a draw must pass all of them. The check order is: open, then
the grantee, then the amount, then expiry, then the lock (`start_at` and a
hold measured from the funding block), then the weekday and hour masks, then
the per-draw cap, then this allowance's period cap, then the shared cap.
Expiry wins over a fresh period: at the deadline the refund happens and the
draw is refused. A mix that can never be drawn, because the unlock is already
at or after the expiry or no hour in between matches the masks, is refused
when the allowance is opened and the coins stay with the sender.

## The four objects

### Standing payment (#34)

`standing_payment_create` is signed by the payer. It names the recipient, the
amount, a schedule (`blocks` at least 128 apart, `seconds` at least an hour
apart, or `months`), the first due point, a window no longer than the
interval (27 days for a month), and a required `max_occurrences` (1..1200).
There is no open-ended authorization and no catch-up: a missed window is
skipped, and one execution pays one occurrence. Creation reserves nothing.
The sweep pays an open window; anyone may also submit
`standing_payment_execute` for that same occurrence. The payer's current o5
clause is checked again, against the real recipient and amount. A block
misses the occurrence. Too little balance does not: the occurrence stays open
until the window ends, with no partial payment and no debt. `cancel` stops
every later occurrence and wins over the sweep in the same block, because
transactions run first. `update` cancels the old row and creates a new
version; the signed terms of the old row are not edited.

The chain id (the genesis hash, or the pinned id a test puts on the parent
snapshot) is part of the signature and of the id. A payment signed for
another network is rejected at admission and at apply.

### Receive route (#35)

The recipient signs one route: up to four destinations whose shares sum to at
most 9,000 basis points. `routed = floor(gross * bps / 10000)` and the dust
stays with the recipient, so 101 at 20% is 20 and 81. There is no second fee.
A locked route (`locked_until` set) must also expire, and until the lock the
owner cannot replace or remove it. A named destination can release it. The
route applies to ordinary transfers only. Faucet, genesis, fees, refunds,
draws, standing payments, payouts and routed credits do not.

### Payout rule (#63)

The owner signs up to eight legs. Each leg is `floor(gross * bps / 10000)`,
a constant, or a single remainder (the gross minus the earlier legs) and the
remainder must be last. Anyone submits `payout_execute` with the owner's key,
a 32-byte event id and the gross. The same event pays once. All legs are
paid or none are: over a cap, over the balance, over the gross when
`bounded_by_gross` is set, or blocked by the owner's current o5 clause or by
the optional clause installed with the rule. Amounts are the signed integer
expression, not an `o5` value. The policy worker reports `o5` only, and 0
there already means "block", so it cannot also be an amount. The clause is a
gate. Declared recipients are the only accounts a leg can pay.

### Allowance (the conditions, and the demo)

The sender's coins leave their balance and sit in the allowance, which is
counted in the supply check next to retractable escrow. They are not part of
the grantee's free balance, so replacing the grantee's wallet rules cannot
lift the cap. The grantee draws to any other account, paying the draw's fee
from their own free balance. The sender may release the remainder to the
grantee early. The sender may not take it back early.

Per period, per payment (`per_draw_cap`), per recipient (each allowance, plus
an optional shared meter), resetting when the period changes. Time lock
(`start_at`), a hold counted from the funding block, weekday and hour masks
in UTC. Weekday bit 0 is Monday. A zero mask means "every". Refund at expiry
or after an idle stretch, as above.

The demo is one `allowance_open`: 5,000 to Bob, cap 500, period week, unlock
2026-12-01 00:00 UTC, expiry 2027-01-01 00:00 UTC. Draws of 300, 200, 500 and
200 succeed (1,200). A draw before 1 December is refused, a draw over the
week's remainder is refused, and 3,800 returns to Alice in the block dated
1 January. No refund transaction is required.

```bash
python scripts/demo_programmable_payments.py
```

## What is deliberately not in this version

- Consensus daily and weekly spend totals (#31). An allowance tracks its own
  draws, and a standing payment stamps the payer's cooldown clock once. It
  does not increment a network-wide total that does not exist on main.
- Protected administration (#33). Conditions live on the payment the node
  holds, not in the grantee's policy text, so the grantee cannot delete them.
  Replacing a route or a payout rule is still the owner's signature.
- Attested inputs (#62), including an attested clock and an attested sale
  price. The gross of a payout is chosen by the executor and bounded by the
  caps the owner signed. A sale that must be proven by a third party waits
  for #62.
- Catch-up of missed standing occurrences. The issue allows it only when the
  authorization says so. This version never does.
- A non-zero UTC offset on an allowance. The field is signed and must be 0,
  so the slot exists without two nodes applying a timezone database.

## State, upgrade, admission

Each book is a field of `ConsensusLifecycleManager`. Its root is added to the
consensus meta hash only once the book has held an entry, so an unused chain
keeps the hash it has today. Rows are persisted as canonical JSON under
`programmable_payments_v1` and refused on load when a standing id does not
recompute. Admission and apply call the same staging function. Apply is the
one that moves money. The sweep runs after the block's transactions and before
the supply check, after retractable releases.

`getpayments capability` reports the time source, the rounding, the hop rule
and which side pays which fee.
