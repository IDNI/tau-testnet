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
