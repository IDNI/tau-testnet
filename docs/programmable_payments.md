# Programmable payments

Until now a rule could only **allow or block** a payment someone submitted.
Programmable payments let rules **start** payments and let senders attach
**conditions** to money, with standing instructions that keep working while the
wallet is offline.

| Need | Feature | Guide |
|---|---|---|
| Spending limits per period, time locks, allowed days/hours, refunds at expiry, any combination | Conditional grants | [grants.md](grants.md) |
| Recurring payments without signing each time (#34) | Standing payments | [standing_payments.md](standing_payments.md) |
| Auto-split incoming funds (#35) | Receive routes | [receive_routes.md](receive_routes.md) |
| Amounts a rule computes: royalties, escrow release (#63) | Payout rules | [payout_rules.md](payout_rules.md) |

## The demo: Alice sends Bob 5,000

> Bob can spend up to 500 a week, only from December 1, and unspent funds
> return to Alice at the deadline.

```bash
# Alice locks 5,000 for Bob under the three conditions.
tau-testnet grant create --key alice --to <bob_pubkey> --amount 5000 \
  --start 2026-12-01 --cap 500 --cap-period week --expires 2027-03-01
# grant id: <id>

# Before December 1 every draw is refused (time lock):
tau-testnet grant draw --key bob <id> --to <shop_pubkey> --amount 100
#   -> grant_draw rejected: grant is time-locked until start_at

# From December 1, Bob spends; a 501st unit in the same ISO week is refused:
tau-testnet grant draw --key bob <id> --to <shop_pubkey> --amount 300
tau-testnet grant draw --key bob <id> --to <shop_pubkey> --amount 200
tau-testnet grant draw --key bob <id> --to <shop_pubkey> --amount 1
#   -> grant_draw rejected: amount exceeds the spending cap for this period

tau-testnet grant list --key bob --role in      # remaining, drawable_now

# On March 1 the first block refunds what is left to Alice -- no transaction.
```

The same flow runs on real nodes, scaled to minutes, in
`scripts/e2e_programmable_payments.py` (scenario `g`), and with the exact
dates in `tests/test_grant_apply.py::test_alice_bob_demo_end_to_end`.

## Design decisions

These answer the design questions of the bounty.

**Time source.** Every time-based rule uses the block header timestamp (UTC).
Block validation already keeps it non-decreasing and bounds how far into the
future a proposer may stamp it, so a proposer can shift "now" by at most that
bound and never backwards. Period arithmetic is pure integer code
(`consensus/periods.py`) with no clock, locale or timezone database. A trusted
outside clock (#62) can replace the accessor later.

**Periods.** UTC day, ISO week (Monday 00:00 UTC), UTC calendar month, or a
fixed length (1 hour to 1 year) anchored at the object's start. A monthly due
day that a month lacks means the month's last day. Limits reset automatically
when a new period starts; unused allowance does not carry over.

**Which events can trigger a payment.** Exactly three: the post-transaction
sweep at block apply (grant expiry refunds), an ordinary credit (receive
routes, inline), and an explicit execution transaction (`grant_draw`,
`standing_payment_execute`, `payout_execute`) that anyone may submit for
standing payments and payouts. The chain never wakes itself up beyond the sweep.

**No endless trigger chains.** Routing is single hop: a routed share, a refund
or a payout leg never triggers another route or payment. Executions are
explicit transactions, one per payment, so nothing cascades inside a block.
Every book is bounded by consensus-frozen limits.

**Who pays the network fee.** The account that originates the money pays to
create (grant, standing payment, payout rule, route). An execution's fee is
paid by whoever submits it (the executor), through the ordinary fee steps; this
keeps spam unprofitable and needs no fee terms in the signed object. Refunds,
cancellations and removals are fee-exempt, like `retract_transfer`.

**Policy.** Every debit from an account's own balance (standing payments,
payout legs, grant creation) runs that account's **current** `o1`/`o5` policy
and own policy clause, so a later freeze stops it. Insufficient funds or a
policy block reject the whole transaction: no debt, no partial payment, no
falsely completed occurrence. The payer's last-transfer time moves exactly once
per payment.

**Refunds.** A grant refunds what is left to `refund_to` (default: the
grantor) at `expires_at`, in the first block at or past it, or when a
revocable grant is cancelled. Refunds are fee-exempt.

**Conflicts between conditions.** All conditions on one object are AND-ed. In
one block the transactions apply first and the sweep after them, so a draw
(which needs `ts < expires_at`) and the refund of the same grant can never both
happen; a cancel and an execution in the same block are decided by block order.

**Replay protection.** Every programmable-payment transaction signs
`chain_id`, the genesis block hash of its network (RPC `getchainid`; the CLI
fetches it). Admission and block apply refuse a transaction whose `chain_id`
is not the chain's own, so a transaction signed for one network cannot be
replayed on another; the check fails closed on a node that does not know its
genesis yet. Older transaction types sign exactly as before. Within a chain,
replay is prevented by the sender's sequence number and, for executions, by
binding them to an object id and period.

**State and compatibility.** Each feature is a book inside the consensus
lifecycle manager (like retractable transfers), with a root bound into the
consensus meta hash **only once the feature is first used**, so an existing
chain keeps a byte-identical state hash and needs no regenesis. Every book is
persisted as canonical JSON and every object id is recomputed on load, so a
tampered row refuses to load. Escrowed grant funds are counted in the
supply-conservation check.

## Transaction types

| Type | Signed by | Fee |
|---|---|---|
| `grant_create` / `grant_draw` / `grant_cancel` | grantor / grantee / grantor | yes / yes / no |
| `standing_payment_create` / `_execute` / `_cancel` | payer / anyone / payer | yes / yes / no |
| `receive_route_set` / `receive_route_remove` | owner | yes / no |
| `payout_rule_install` / `payout_execute` / `payout_rule_remove` | owner / anyone / owner | yes / yes / no |

RPC: `getgrants`, `getstandingpayments`, `getreceiveroute`, `getpayoutrules`.
CLI: `tau-testnet grant|standing|route|payout ...`.
