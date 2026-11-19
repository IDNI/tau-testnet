# Conditional grants (programmable payments)

A conditional grant locks funds for a **grantee** under conditions the
**grantor** signs once. The funds leave the grantor's balance but are **not**
credited to the grantee: the grantee spends them only with `grant_draw`, and
every draw is checked against the signed terms. Whatever is left when the grant
expires goes back automatically, with no transaction from anyone.

It covers the conditions of Bounty 01 (programmable payments): spending limits
that reset each period, time locks, allowed days and hours, refunds at expiry,
and any combination of them on one payment.

Design discussion: [IDNI/tau-testnet#34](https://github.com/IDNI/tau-testnet/issues/34).
Related: [retractable transfers](retractable.md), which use the same escrow-book
pattern.

## Example

Alice sends Bob 5,000. Bob can spend up to 500 a week, only from December 1,
and what he has not spent returns to Alice on March 1:

```bash
tau-testnet grant create --key alice --to <bob_pubkey> --amount 5000 \
  --start 2026-12-01 --cap 500 --cap-period week --expires 2027-03-01
# grant id: <64 hex>

tau-testnet grant list --key bob --role in      # shows drawable_now
tau-testnet grant draw --key bob <grant_id> --to <shop_pubkey> --amount 300
```

## Lifecycle

```
open ──► exhausted   (a draw spends the last of it)
  ├────► expired     (a block reaches expires_at; the rest goes to refund_to)
  └────► cancelled   (the grantor cancels a revocable grant; the rest goes to refund_to)
```

All end states are final.

## Terms

Every term is signed by the grantor and bound into the grant id, so nobody,
including the block proposer, can loosen a limit or redirect the refund.

| Field | Meaning | Default |
|---|---|---|
| `grantee_pubkey` | Who may draw. Must differ from the grantor. | required |
| `amount` | Funds locked, `1..MAX_TRANSFER_VALUE`. | required |
| `expires_at` | Unix time. No draw at or after it; the first block at or past it refunds the rest. At most one year ahead. | required |
| `start_at` | Time lock: no draw before it. Must be before `expires_at`. | `0` (none) |
| `spend_cap` | Most that may be drawn per period; `0` = no periodic limit. At most `amount`. | `0` |
| `cap_period_kind` | `1` day, `2` ISO week (Monday 00:00 UTC), `3` month (UTC), `0` fixed length. | `2` |
| `cap_period_seconds` | Length of a fixed period (`3600..31536000`), anchored at `start_at`. Only with kind `0`. | `0` |
| `per_payment_cap` | Most per single draw; `0` = none. | `0` |
| `weekday_mask` | Allowed UTC weekdays, bit 0 = Monday … bit 6 = Sunday. | all |
| `hour_mask` | Allowed UTC hours, bit h = hour h. | all |
| `refund_to_pubkey` | Who receives what is left at expiry or cancel. | grantor |
| `revocable` | Whether the grantor may cancel early. | `false` |

## Rules

- **Time source.** Every check uses the block header timestamp (UTC), never a
  node clock. Periods are computed by pure integer code in
  `consensus/periods.py`, identical on every node.
- **All conditions apply together.** A draw happens only if every condition
  passes: after `start_at`, before `expires_at`, on an allowed day and hour,
  within `per_payment_cap`, within what is left this period and within
  `remaining`.
- **Limits reset automatically.** Spending is tracked per period; the first
  draw in a new period starts from zero. Unused allowance does not carry over.
- **Draw versus refund.** The block's transactions apply first and the expiry
  sweep after them. A draw needs `ts < expires_at`, so a draw and the refund of
  the same grant never happen in one block; at the deadline only the refund can.
- **No debt, no partial draws.** A draw that breaks any condition is rejected
  whole.

## Fees and policy

- `grant_create` is fee-bearing and runs through the same gates as a transfer:
  the grantor's `o1`/`o5` policy, the fee steps and the balance check. A policy
  block or insufficient funds creates nothing.
- `grant_draw` is fee-bearing; the grantee pays the fee from their own balance.
  The grantee's `o5` policy is not applied to the draw, because the funds were
  never the grantee's balance: the grant's terms are the policy for them.
- `grant_cancel` and the expiry refund are fee-exempt, like `retract_transfer`.

## Bounds

Consensus-frozen constants in `consensus/grants.py`:

| Constant | Value |
|---|---|
| `MAX_OPEN_GRANTS_PER_GRANTOR` | 16 |
| `MAX_OPEN_GRANTS_TOTAL` | 4096 |
| `MAX_GRANT_HORIZON_SECONDS` | 31,536,000 (one year) |

## State and hashing

Open grants and their spending state live in a `GrantBook`, a field of the
consensus lifecycle manager next to the retractable book. Its root (sorted open
entries plus an order-dependent accumulator of resolutions) enters the
consensus meta hash only once the first grant exists, so a chain that never
used grants keeps a byte-identical state hash. The book is persisted as one
canonical JSON value (`grants_v1`) and every grant id is recomputed on load, so
a tampered row refuses to load.

Escrowed grant funds are counted in the supply-conservation check, exactly like
retractable escrow.

## RPC

`getgrants <address> [in|out|all]` — open grants the address made (`out`),
can draw from (`in`) or both, with each grant's terms, `remaining`,
`spent_this_period` and `drawable_now` at the node's next-block timestamp.

## Transactions

All fields are root fields of the signed payload.

`grant_create`: `grantee_pubkey`, `refund_to_pubkey`, `amount`, `start_at`,
`expires_at`, `spend_cap`, `cap_period_kind`, `cap_period_seconds`,
`per_payment_cap`, `weekday_mask`, `hour_mask`, `revocable`.

`grant_draw` (signed by the grantee): `grant_id`, `recipient_pubkey`, `amount`.

`grant_cancel` (signed by the grantor): `grant_id`.

Every transaction above also signs `chain_id` (the network's genesis hash,
RPC `getchainid`); a node of any other network refuses it. See
[programmable_payments.md](programmable_payments.md#design-decisions).
