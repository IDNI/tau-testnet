# Standing payments

A standing payment is an authorization a payer signs once. Afterwards
anyone may submit an execution for an occurrence that is currently due,
and the node — not the submitter — decides whether it is due, whether
the payer's current policy allows it, and whether the payer can cover
it. This implements the standing-payment half of Bounty 01 (issue #34);
receive routes (#35) and payout rules (#63) build on the same books and
period arithmetic.

## Lifecycle

```
create ──► open ──execute (once per period)──► open ──► completed
             │                                    (end condition met)
             ├──cancel (payer only)────────────► cancelled
             └──create with supersedes_id──────► superseded
```

Closed authorizations leave the open set; only a count and a running
hash of their ids and outcomes remain in consensus state.

## Creating

`standing_payment_create` root fields (a nested `payload` is unsigned
and ignored):

| Field | Meaning |
|---|---|
| `sender_pubkey` | the payer; must be the signer |
| `recipient_pubkey` | who gets paid |
| `amount` | per occurrence, `1..MAX_TRANSFER_VALUE` |
| `sequence_number` | the payer's account sequence for this tx |
| `period_kind` | `0` day, `1` week, `2` calendar month |
| `anchor_timestamp` | start of the first due period (UTC) |
| `window_start_offset` / `window_end_offset` | the execution window inside each period, seconds from its start |
| exactly one of `final_period` / `max_occurrences` / `max_total` | the **required** end condition |
| `supersedes_id` | optional: the open authorization this one replaces |

There is no open-ended authorization: an end condition is required.
Update is a new version that supersedes; signed terms are never edited
in place.

### Periods and the 31st

Day and week periods are fixed-length from the anchor. Month periods
are UTC calendar months: the day is the anchor's day-of-month, clamped
to the target month's last day, and restored in the next month that has
it. A payment anchored on January 31 is due on February 28 (29 in a
leap year) and again on March 31 — it never drifts to the 28th.

### Windows and lapsing

Each period has one execution window. An occurrence that is not
executed inside its window lapses: it is never collected later, and the
next window offers only its own period. There is no catch-up.

## Executing

`standing_payment_execute` root fields: `sender_pubkey` (anyone) and
`standing_id`. At apply, the node checks, in order:

1. the authorization is open and an occurrence is due (inside its
   window, not settled, end condition not reached);
2. the payer's **current** o5 policy — the registered clause and the
   rule output are evaluated at execution time, not at signing time;
3. the payer's balance covers the amount.

Only when the transfer actually moves does the occurrence settle. An
execution that fails on funds or policy leaves the period unsettled:
it stays due for the rest of its window and then lapses — no debt, no
partial payment, no false completion marker. A second execution in the
same period finds nothing due.

### Fees

Fees are the ordinary rule-emitted fees, settled the ordinary way:

- `standing_payment_create` is fee-bearing like any state-writing tx.
- `standing_payment_execute`: the transfer's fee is measured by the
  transfer evaluation and charged to the **executor** (the tx signer),
  capped by the execute tx's own `fee_limit` field. The payer is
  debited exactly `amount`.
- `standing_payment_cancel` is free, like `retract_transfer`.

An earlier design draft also sketched payer-funded execution fees (a
signed per-execution fee cap inside the authorization). Fee settlement
in this engine debits the transaction signer, so that variant would
need new settlement machinery; it is deferred rather than signed but
unenforced.

## Cancelling

`standing_payment_cancel` root fields: `sender_pubkey` (must be the
payer) and `standing_id`. A cancel in the same block as an execution is
resolved by canonical block order: whichever transaction comes first
decides — a cancel that lands first prevents the execution in that
block and every later one.

## Reading

`getstandingpayments <pubkey>` lists the open authorizations where the
account is payer or recipient, each with its terms, `executed_count`,
`total_executed`, `last_executed_period`, and the next due period and
its window start. Other rules can read whether a specific period
settled (`paid_for_period`) — the membership/keep-alive fact.

## Limits

Consensus-frozen module constants, not config: at most 16 open
authorizations per payer and 4,096 in total; an authorization may not
reach more than 365 days into the future.

## Consensus notes

The book is a field of the consensus lifecycle manager. Its root is
bound into the consensus meta hash **only once the book has been
touched**, so a chain that never uses standing payments hashes exactly
as it did before the feature existed, and genesis is unaffected. Open
rows and the resolved commitment persist in the canonical state write;
restore recomputes every authorization id from its stored fields and
refuses a mismatch.

Consensus spend totals (#31) and cooldown (#30) are not on main yet.
Until they land, per-authorization totals live in the authorization's
own book (exact for the authorization itself) and the payer's current
o5 is evaluated at execution; this implementation does not claim the
#30/#31 counters end-to-end.

## Error codes

Admission rejections carry machine-readable codes:
`DUPLICATE_STANDING`, `TOO_MANY_STANDING`, `STANDING_BOOK_FULL`,
`UNKNOWN_SUPERSEDES`, `UNKNOWN_STANDING`, `STANDING_NOT_DUE`,
`NOT_STANDING_PAYER`.
