# Programmable payments

Programmed money moves on exactly three triggers: **time** (a sweep that runs
after every block's transactions), an **ordinary credit** (a receive route
that splits an incoming credit), and an **explicit execution transaction**.
No other trigger exists, and no programmed movement ever runs inside the
transaction loop itself.

Time is the only source of truth for when something is due: the block header
timestamp. There is no wall clock in consensus.

This guide covers what exists today. The work lands in stages; each section
names its stage.

## Stage 1 — period measurement, credit classes, sweep framework

Stage 1 is the foundation the later stages build on. It adds no new
transaction type and no new user-facing behaviour: a block with no programmed
objects applies exactly as before, and the sweep runs nothing.

### Periods (`consensus/periods.py`)

A period is how a schedule measures time. Four kinds exist:

| Kind | Meaning |
|---|---|
| `PERIOD_FIXED` | A fixed length in seconds from an anchor (1 hour to 1 year). |
| `PERIOD_DAY` | A UTC calendar day. |
| `PERIOD_WEEK` | A UTC calendar week, Monday to Sunday. |
| `PERIOD_MONTH` | A UTC calendar month, on the anchor day. |

`period_index(kind, ts)` names the period a timestamp falls in;
`period_start(kind, index)` is that period's first second;
`period_bounds(kind, ts)` is the `[start, next start)` pair;
`next_period_start(kind, ts)` is the next period boundary after `ts`.

Two details matter for implementers. A month anchored on day 31 clamps to the
month's last day (February 28, or 29 in a leap year), and the clamp is
recomputed per month, so a schedule anchored on the 31st lands on the 31st
again in March. A week is always Monday-based: week 0 is the week of Monday
1969-12-29, so the Unix epoch (a Thursday) sits inside week 0.

Period bounds are consensus: `MIN_FIXED_PERIOD_SECONDS` (3600) and
`MAX_FIXED_PERIOD_SECONDS` (31536000) are module constants, not config, so two
nodes can never disagree about whether a schedule is valid. The calendar math
is integer-only (Hinnant's days-from-civil algorithm); `datetime` never
appears in consensus code.

### Credit classes (`consensus/credits.py`)

Every credit a block lands on an account carries a class:

| Class | Meaning | Routable |
|---|---|---|
| `CREDIT_TRANSFER` | An ordinary transfer | yes |
| `CREDIT_STANDING_PAYMENT` | A standing-payment instalment | yes |
| `CREDIT_FAUCET` | A first-account faucet grant | no |
| `CREDIT_GENESIS` | A genesis allocation | no |
| `CREDIT_FEE_REWARD` | A fee paid to the block beneficiary | no |
| `CREDIT_REFUND` | A refund | no |
| `CREDIT_ROUTE_OUTPUT` | The output leg of a receive route | no |
| `CREDIT_GRANT_DRAW` | A grant draw | no |
| `CREDIT_GRANT_REFUND` | A grant refund | no |
| `CREDIT_PAYOUT_LEG` | A payout leg | no |
| `CREDIT_RETRACTABLE_RELEASE` | A matured retractable release | no |

Only `transfer` and `standing_payment` credits are routable: a receive route
(Stage 4) may split them, and nothing else. `is_routable_credit` is total
and fail-closed — an unknown class is not routable. Class numbers are part of
the consensus vocabulary and must never be renumbered.

A block's credits are collected in a `CreditLedger` while the block is
applied and returned on the execution result (`TauExecutionResult.credits`,
`ApplyBlockResult.credits`). The ledger is ephemeral and never persisted: it
is fully determined by the block's transactions plus the sweep, so any node
recomputes it.

### Sweep (`consensus/sweep.py`)

After the transaction loop, `_apply_block` runs the programmable sweep: each
registered book reports what is due at this height and timestamp, the
framework orders the work by `(due_ts, object_id)`, runs it up to
`MAX_SWEEP_ACTIONS_PER_BLOCK` (256) items, and leaves the overflow due in
its book — the next block collects it again, so overflow carries forward in
deterministic order. One item failing never fails the block: the failure is
recorded and the sweep goes on.

A book plugs in by registering one handler per object kind:

```python
from consensus import sweep

sweep.register_handler("grant", _grant_sweep_handler)
```

A handler implements `collect_due(lm, height, ts)` (the due items, each a
`SweepDue` with the timestamp it fell due and the object id) and
`execute(item, ctx)` (one item, returning an outcome name). A handler that
moves funds must conserve supply exactly like the retractable release does.

Stage 1 registers no handlers: the sweep is a tested no-op until Stage 2
registers the grant book. The retractable release keeps its own code path
and is not rewired through the sweep — its resolved-accumulator order is
consensus-critical — but its releases are recorded in the credit ledger with
class `CREDIT_RETRACTABLE_RELEASE`.

### What Stage 1 does not do

- No new transaction types and no chain binding: binding a transaction to a
  chain id is a Stage 2/3 dependency, added when the first new transaction
  type lands.
- No standing payments, grants, or receive routes: those are Stages 2–4 and
  are built on the framework above.
- No execution transaction: that is Stage 5, the fallback for anything the
  sweep and the routes do not cover.

## Stage 2 — conditional grants + chain binding

A grant is a funded promise with spending rules. Alice locks `amount` coins
for Bob; Bob draws them down with explicit `grant_draw` transactions, but
only inside the rules Alice wrote at creation:

- `spend_cap` — the most Bob may draw in one period (day / ISO week /
  calendar month / fixed window, from `consensus.periods`);
- `per_payment_cap` — the most Bob may draw in a single transaction;
- `weekday_mask` / `hour_mask` (UTC) — the times draws are allowed;
- `start_at` — draws are locked before this timestamp;
- `expires_at` — the grant dies at this timestamp; whatever Bob has not
  drawn is refunded to `refund_to` (usually the granter) by the sweep.

Lifecycle: open -> exhausted | expired | cancelled. The grant is exhausted
when Bob has drawn the full amount; it expires when the sweep sees
`expires_at` pass; the granter may cancel it at any time (a revocable
promise). A cancelled or expired grant refunds the remainder; an exhausted
grant refunds nothing.

The funds are escrowed in the book, exactly like a retractable park: the
create transaction debits the granter and credits nobody (`escrow=True`); a
draw credits the grantee from the book's escrow; a cancel or an expiry
refund credits `refund_to` from the escrow. The grantee never holds the
un-drawn funds, so they cannot spend them outside the grant's rules. The
book's escrow counter is part of the supply: `engine._escrow_total` sums
every book that holds escrow.

Demo: Alice grants Bob 5,000, 500/week from Dec 1, refund at deadline
(`tests/test_grants.py::test_demo_alice_bob_5000_500_per_week_from_dec_1`).

### Chain binding

Every new transaction type carries `chain_id` — the genesis block hash of
the network it was signed for. Admission and the engine reject a
transaction whose `chain_id` does not match this node's genesis hash
(`WRONG_CHAIN_ID`, see `consensus/chain_binding.py`), so a grant signed on
one Tau network cannot be replayed on another. The genesis hash is pinned
on the lifecycle manager by `chain_state` at genesis load (the same way
`faucet_amount` is pinned) and bound into the consensus meta hash only
when set, so a chain that predates the field keeps a byte-identical hash.
Clients read it with the `getchainid` command. `grant_create` is
fee-bearing; `grant_draw` and `grant_cancel` are fee-exempt, like a retract.

## Stage 3 — standing payments

`consensus/standing.py` — `StandingPaymentBook`: recurring payments from
a payer to a payee, one execution per period, no catch-up. The payer keeps
the funds until an execution moves them, so the book holds no escrow
(`escrowed_total()` is always 0). Schedules are calendar month (month-end
clamp), ISO week, day, or fixed; `start_at` is at most 90 days ahead; at
most 16 open standing payments per payer, 4096 total.

Execution has two paths through ONE shared apply function
(`apply_standing_execution`): the post-transaction sweep is primary, and
`standing_payment_execute` is a manual fallback for a period the sweep
missed. Both debit the payer first, then credit through the (possibly
staged) view — aliasing-safe, like the engine's fee settlement. A period
is executed once; a missed period is skipped, never caught up. The payer's
`max_fee_per_execution` caps the fee: on the sweep path the engine
measures one Tau fee-query step per execution (the same way a
transfer-less `user_tx` is charged) and skips the period when the fee
exceeds the cap; on the manual path admission rejects a `fee_limit` above
the cap. If the payer's balance is below amount + fee, the period is
skipped and stays due for retry; if the fee has nowhere to go (no fee
beneficiary), the period also stays due. Only advancing outcomes
(`executed`, `skipped_fee_cap`, `skipped_insufficient_funds`) move the
schedule forward.

`standing_payment_update` never mutates the old terms: it resolves the old
version as SUPERSEDED and submits a new version (same `standing_id`,
version + 1) — this beats both competing PRs, neither of which offers an
update at all. `standing_payment_cancel` is fee-exempt, like a retract.
`standing_payment`, `standing_payment_execute` and
`standing_payment_update` are fee-bearing and carry `chain_id` (genesis
binding, see above).

Demo: Alice pays Bob 100/week (`tests/test_standing.py::test_demo_alice_bob_100_per_week`).

## Stage 4 — receive routes

`consensus/routes.py` — `RouteBook`: one receive route per account. When
a routable credit lands on the account, a share of it is forwarded to a
destination: `routed = floor(gross * bps / 10000)`, `net = gross - routed`,
with `bps` in 1..9,000, so the recipient always keeps at least 10%.

Only two credit classes are routable (design 1.4 / 2.2): ordinary
`transfer` credits and `standing_payment` credits. The routed share is
recorded as `CREDIT_ROUTE_OUTPUT`, which is itself NOT routable — so the
split is a single hop by construction, even when the destination has its
own route. Everything else passes through untouched (faucet, genesis,
fee/reward, refunds, grant draws/refunds, payout legs, retractable
releases). The receipt is atomic: recipient and destination balances move
in the same staged-write step and both credits carry the same transaction
id, so net + routed always equals the gross.

A route is active only inside `[activate_at, expires_at)` and only for
grosses at or above `min_incoming`. `locked_until` is an optional binding
lock: while it is in the future the route cannot be changed or removed.
`route_set` is fee-bearing and carries `chain_id`; `route_remove` is
fee-exempt, like a retract.

The split hooks into the engine's single transfer choke point
(`_execute_fee_era_transfer`) and into the shared standing-payment apply
function, so every routable credit — a user transfer, a parked-transfer
completion, a standing execution (manual or sweep) — splits the same way.

Demo: Bob routes 25% of every incoming transfer to Carol
(`tests/test_routes.py::test_demo_bob_routes_25_percent_to_carol`).

## Stage 5 — payout rules

`consensus/payouts.py` — `PayoutBook`: one payout rule pays up to 8
declared recipients under ONE Tau clause. The clause is evaluated in an
isolated `payout` policy pool (registered in `tau_policy.POOL_NAMES`
alongside `apply` and `admission`, with its own worker — a payout clause
can never see or touch another pool's state). Its outputs o1..o8 are the
per-recipient amounts: o1 pays `recipients[0]`, o2 pays `recipients[1]`,
and so on. A missing or zero output pays nothing to that recipient; a
non-integer or negative output blocks the whole execution (fail-closed).

Caps: `max_per_execution` bounds one execution's total, `max_per_period`
bounds the total paid inside one period (calendar month / ISO week / day /
fixed — `consensus/periods.py`). A skipped execution pays nothing and does
not consume the period cap — only an `executed` call marks the period.

All legs are atomic or none: every check runs before any write is staged;
the payer is debited once for the total (+ fee), each recipient is credited
its leg in the same staged-write step, and zero legs are skipped (a zero
credit is not a record). Legs are recorded as `CREDIT_PAYOUT_LEG`, which is
not routable — a payout leg never triggers a receive route. `payout_create`
and `payout_execute` are fee-bearing and carry `chain_id`; `payout_remove`
is fee-exempt, like a retract.

Removal is #33-aware: only the payer may remove a rule, and `locked_until`
is the binding lock — while it is in the future the rule cannot be removed
at all. A rule-change guard (#33) only has to set the lock; the removal
path already consults it.

Demo: Alice splits 1,000 to Bob and Carol by clause
(`tests/test_payouts.py::test_demo_alice_pays_bob_and_carol_by_clause`).

Valid clause shape: the clause is stored as one `always ( ... ).` unit,
and `clause_outputs_for` strips that wrapper before stepping (the policy
worker wraps every body in `always ( ... ).` itself, so stepping the
stored text verbatim would double-wrap and never build). The body must
be a valid Tau expression that READS an input stream — amounts are
bit-vector literals joined with `&&`, never bare decimals or
comma-separated assignments, and a constant-only clause cannot be
stepped at all (the engine refuses a clause that reads no input). The
shape that works, verified against the real payout-pool evaluator:

```
always ((i1[t]:bv[24] > { #x000000 }:bv[24])
  ? (o1[t]:bv[24] = { 300 }:bv[24] && o2[t]:bv[24] = { 700 }:bv[24])
  : (o1[t]:bv[24] = { 0 }:bv[24] && o2[t]:bv[24] = { 0 }:bv[24])).
```

`i1` is the payer balance, so the guard is true whenever the payer is
funded (the real funds check is `apply_payout`'s payer-balance guard).
Caveat: the `i1[t]:bv[24]` guard caps at 16,777,215 — fine for ordinary
balances, but a payer holding more than ~16.7M needs a wider guard (or
an `i5`-timestamp guard, `i5[t]:bv[32] > { #x000000 }:bv[32]`, which has
no balance ceiling). A clause that cannot be built or stepped fails
closed at execute time: the execute is rejected, pays nothing, and the
rule stays open — `payout_create` does not validate buildability
(admission has no evaluator access).
