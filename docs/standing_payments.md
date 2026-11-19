# Standing payments

A standing payment is a standing order: the payer signs once that a fixed
amount goes to a fixed recipient on a schedule. After that **anyone** — the
payee, the payer's wallet, a validator, a relayer — can submit the execution
when an occurrence is due, and the node is the authoritative gate for whether
it is. The payer's private key is never needed again, and no key is handed to a
background service.

Capability request: [IDNI/tau-testnet#34](https://github.com/IDNI/tau-testnet/issues/34).
Related: [conditional grants](grants.md), which share the period arithmetic.

## Example: monthly rent

1,000 to the landlord on the 31st of every month (the last day in shorter
months), executable for 5 days after the due point, 12 times:

```bash
tau-testnet standing create --key tenant --to <landlord_pubkey> --amount 1000 \
  --every month --day 31 --window 432000 --start 2026-12-01 --times 12
# standing id: <64 hex>

# From the 31st, the landlord (or anyone) triggers the payment:
tau-testnet standing execute --key landlord <standing_id>

tau-testnet standing list --key tenant --role out   # next_due_at, paid_this_period
tau-testnet standing cancel --key tenant <standing_id>
```

## Schedule semantics

All times are the **block header timestamp, UTC**. Period arithmetic is pure
integer code (`consensus/periods.py`), identical on every node.

| `period_kind` | Period | Due point |
|---|---|---|
| `3` month | UTC calendar month | day `due_day` (1..31) at `due_offset_seconds`; a day the month does not have means its **last day** (31 in April → 30th, in February → 28th/29th) |
| `2` week | ISO week, Monday 00:00 UTC | `due_offset_seconds` after Monday 00:00 |
| `1` day | UTC day | `due_offset_seconds` after midnight |
| `0` fixed | `period_seconds` (3600..31536000), anchored at `start_at` | `due_offset_seconds` after the period starts |

- An occurrence can execute from its due point for `window_seconds`
  (at least one hour, at most the shortest length of the period), then the
  window closes.
- **No catch-up.** A missed window is skipped. One execution moves exactly one
  occurrence, never several, and only the period that is due right now.
- The first occurrence is the first due point at or after `start_at`.
- **An end is required:** `end_at` (no execution at or after it), or
  `max_occurrences`, or both. There is no open-ended authorization. The first
  block at or past `end_at` resolves the payment; reaching `max_occurrences`
  completes it.

## What an execution checks

`standing_payment_execute` carries only the `standing_id` and the `period`.
Amount, recipient, schedule and end come from the stored, signed terms, so an
executor cannot change any of them. The execution is applied only if:

1. that period is the one due now, inside its window, and not yet executed;
2. the payer's **current** transfer policy (`o1`/`o5`, including their own
   policy clause) allows this transfer to this recipient for this amount — a
   freeze or stricter policy added later stops it;
3. the payer's balance covers the amount.

If any check fails the whole transaction is rejected: no debt, no partial
payment, and the period is **not** marked executed, so it can be retried inside
the same window. The payer's last-transfer time (the cooldown clock) moves for
an executed payment, exactly once.

Cancellation (`standing_payment_cancel`, payer only, fee-exempt) is visible to
admission from the latest committed state. A cancel and an execution in the
same block are decided by block order.

## Fees

- `standing_payment_create` is fee-bearing (the payer pays). Creation reserves
  no funds.
- `standing_payment_execute` is fee-bearing and the **executor** pays the fee
  for their own transaction, through the ordinary fee steps. This keeps anyone
  from spamming executions for free and needs no fee fields in the terms.
- `standing_payment_cancel` is fee-exempt.

## Replay safety

Each standing payment id is a hash of every signed term plus the payer's
sequence number. An execution names a period; it is valid only while that
period is due and unexecuted, so replaying it later, in another period, or
twice in one period fails.

## Bounds

| Constant (`consensus/standing.py`) | Value |
|---|---|
| `MAX_OPEN_STANDING_PER_PAYER` | 16 |
| `MAX_OPEN_STANDING_TOTAL` | 4096 |
| `MAX_STANDING_HORIZON_SECONDS` | 5 years |
| `MAX_OCCURRENCES` | 10,000 |
| `MIN_WINDOW_SECONDS` | 3,600 |

## State, hashing and RPC

The `StandingBook` is a field of the consensus lifecycle manager. Its root
enters the consensus meta hash only once the first standing payment exists, so
existing chains keep their state hash. It is persisted as one canonical JSON
value (`standing_v1`) and every id is recomputed on load.

`getstandingpayments <address> [in|out|all]` returns, per payment, its terms,
`executions`, `total_executed`, `due_period` (what anyone may execute now, or
`null`), `paid_this_period` (the "paid for this period" fact requested on
#34) and `next_due_at`.

## Transactions

`standing_payment_create` (payer): `recipient_pubkey`, `amount`, `period_kind`,
`period_seconds`, `start_at`, `due_day`, `due_offset_seconds`,
`window_seconds`, `end_at`, `max_occurrences` — all signed.

`standing_payment_execute` (anyone): `standing_id`, `period`.

`standing_payment_cancel` (payer): `standing_id`.

Every transaction above also signs `chain_id` (the network's genesis hash,
RPC `getchainid`); a node of any other network refuses it. See
[programmable_payments.md](programmable_payments.md#design-decisions).
