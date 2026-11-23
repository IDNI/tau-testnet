# Payout rules

A payout rule lets an account's money be paid out by a Tau rule the account
installed, without the account signing each payment. The account installs one
rule; from then on **anyone** may send `payout_execute` naming the account. The
node steps the rule once, reads one amount per recipient slot, and pays all of
them or none, inside caps the account signed.

Typical uses: a reviewer's key releases bounty or milestone money to a
contributor; a treasury pays out a fixed share whenever someone triggers it,
at most so much per period; an allowance anyone can trigger for a named
recipient, at most once a week; a royalty of 5% on every sale, paid once per
sale ([Per sale](#per-sale-royalties)).

The rule is a second, separate authorization for the account's money, chosen by
the account. The `o5` policy governs transfers the account signs; the payout
rule governs executions. To lock money to the payout rule (escrow), combine
three things: the payout rule, an `o5` clause that blocks signed transfers, and
a rule-change guard that needs co-signers for any change (see
[Escrow](#escrow)).

Short reference: [README](../README.md#payout-rules). CLI summary:
[developer_cli.md](developer_cli.md#payout-rules). This guide is the long form.

## Lifecycle

```
payout_rule_set ──► installed ──► payout_execute (anyone) ──► paid (all slots) or refused
                       │   ▲            ...repeat within the caps...
                       │   └── payout_rule_set again: replaced (new id, new period count)
                       ├──► payout_rule_revoke: revoked
                       └──► expires_at reached: expired
```

Every change is recorded in the node's history: `installed`, `executed` (with
its legs), `revoked`, `expired`, and on a replacement the new install names the
rule it `replaced`.

## Installing

```bash
tau-testnet payout set --key treasury --file payout.tau \
    --slot <bob_pubkey> --slot open \
    --cap-per-execution 500 --cap-per-period 2000 \
    --period-blocks 1000 --ends-in 100000
```

| Field | Meaning |
|---|---|
| `rule_text` | One `always ( ... ).` clause on the payout ABI below, at most 4096 bytes. |
| `slots` | 1 to 8 entries: a recipient's public key (fixed) or `""` (open: the executor names the recipient). |
| `cap_per_execution` | The most one execution may pay in total, 1 .. 16,777,215. |
| `cap_per_period` | The most all executions in one period may pay, `cap_per_execution` .. 16,777,215. |
| `period_blocks` or `period_seconds` | Exactly one. The period clock: block height (1 .. 1,000,000) or block time (1 .. 366 days). |
| `expires_at` | The end, on the period's clock (a height, or a unix time), at most 10,000,000 blocks or four years ahead. |
| `per_sale` | Optional, `true` or left out. The rule pays only against sales the chain recorded, once per sale ([Per sale](#per-sale-royalties)). |
| `periods_from` | Optional, a number or left out. The periods count from this point on the period's clock instead of the install ([Optional terms](#optional-terms)). |
| `due_at` | Optional, a number or left out. At this point on the period's clock the node runs the rule itself, once ([Optional terms](#optional-terms)). |
| `due_every` | Optional, a number or left out, with `due_at`. The node runs the rule again every so many blocks or seconds ([Three ways a rule is started](#three-ways-a-rule-is-started)). |
| `due_months` | Optional, 1 to 12, with `due_at` and `period_seconds`. The node runs the rule again every so many calendar months, UTC. |
| `on_arrival` | Optional, `true` or left out, with `per_sale`. The node runs the rule itself for each payment that arrives. |
| `sealed` | Optional, `true` or left out. Until the rule ends the account signs nothing and the rule cannot be changed. |
| `rule_index` | Optional, 1 to 7 or left out. The rule's place on the account; left out, the first ([Several rules per account](#several-rules-per-account)). |
| `due_retry` | Optional, a number or left out, with `due_at`. A due point that found the account short is run again until this much later ([A due point tried again](#a-due-point-tried-again)). |

Admission and apply refuse a rule that pays the account itself in a fixed slot,
names one fixed recipient in two slots, or does not fit the ABI. The rule is
built (compiled) in the payout pool at admission and again at apply; a rule that
does not build is not installed.

Installing costs one fee, paid by the account. Installing again in the same
place replaces the rule there: the old one is removed (outcome `replaced`) and
the new one starts its own period count where it is installed. There is no edit.

### The id

`rule_id` is a BLAKE3 hash over the account, the install's sequence number, the
hash of the normalized rule body, the slots, both caps, the period clock and
length, and `expires_at` (`compute_payout_rule_id`), followed by the optional
terms when the rule carries one (the place included). Every execution names the id, so an
execution signed against a rule the account has since replaced is refused
instead of running the new rule.

## The payout ABI (v1)

A payout rule is stepped in its own policy pool (`payout_apply` at apply,
`payout_admission` at admission), never beside `o5` clauses. Every stream it
mentions must be written with its type, `iN[t]:bv[W]`, at exactly the width
below: stream typing is process-global in an interpreter, and fixed widths are
what let any number of payout rules share one worker.

| Stream | Width | Value |
|---|---|---|
| `i2` | `bv[24]` | The account's balance at the parent block (capped at bv[24]). |
| `i5` | `bv[64]` | Block timestamp. |
| `i6` | `bv[64]` | Block height. |
| `i13` | `bv[384]` | The executor's public key. |
| `i26` | `bv[24]` | Paid out of this account by the rule in the current period. |
| `i30+k` | `bv[384]` | Recipient of slot k: the fixed key, the key the executor named, or 0. |
| `i40+k` | `bv[24]` | Executor data k, k in 0..7 (0 when not given). |
| `o30+k` | `bv[24]` | Amount for slot k (0 when the rule does not write it). |
| `i27` | `bv[24]` | Only with `per_sale`: the amount of the sale the execution names. |
| `i28` | `bv[384]` | Only with `per_sale`: who paid it. |
| `i48` | `bv[64]` | The clock at which the rule was installed, on the rule's own clock (a height with `period_blocks`, a unix time with `period_seconds`). |
| `i49` | `bv[64]` | The clock of the rule's last paid execution, on the same clock; the install clock until one has paid. |

A rule reads `[t]` only, reads at least one input, writes at least one slot
amount, and mentions no slot it does not have. Anything else is refused at
install.

### Every amount is fixed by the rule

Every node must pay the same amounts, whatever it evaluated before, and the
amounts must be the rule's decision, not the engine's. So a payout rule has a
narrow shape, checked at install:

- **Each amount is a definition:** `oN[t]:bv[24] = <expression of inputs>`.
  Definitions are joined with `&&` or chosen by `(condition) ? (...) : (...)`,
  where the condition reads inputs only and both sides fix the same amounts.
  A rule such as `o30[t]:bv[24] <= i40[t]:bv[24]` is refused: it allows many
  amounts, and which one an engine picks is the engine's choice, not the
  account's (an equation fixes its unknown only in this definitional form; see
  Rudeanu, *Boolean Functions and Equations*, Thm 6.6).
- **A condition chooses; it does not stand alone.** A rule has to answer every
  input. A bare condition beside a definition, such as
  `(i40[t]:bv[24] > { 100 }:bv[24]) && (o30[t]:bv[24] = i40[t]:bv[24])`, has no
  answer where the condition fails; the engine does not build such a clause, so
  it is refused at install with that reason. Write the choice and pay nothing on
  the other side:
  `(i40[t]:bv[24] > { 100 }:bv[24]) ? (o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24])`.
  An execution for which the rule pays nothing is refused and costs nothing.
- **Nothing that reads earlier steps:** no temporal operator in any spelling
  (`always`/`G`/`[]`, `sometimes`/`F`/`<>`, `until`/`U`, `release`/`R`,
  `weak_until`/`W`, `since`/`S`, `trigger`/`T`, `A`, `E`), no step constraint
  such as `[t > 3]`, no quantifier, variable, named constant or function. Policy
  interpreters are kept and stepped again, so any of these would make an amount
  depend on what that node stepped before.
- **Parentheses where joins mix:** a part with `||`, `->`, `!` or `? :` is put in
  its own parentheses before it is joined with `&&`, so the amounts never depend
  on how a parser groups them.

Only typed streams at `[t]`, typed constants (`{ #x.. }`, `{ #b.. }`,
`{ 123 }` with `:bv[W]`), `min`/`max`, and the comparison, Boolean and
bit-vector operators are accepted; anything else is refused by name.

### Examples

Pay slot 0 what the executor asks, inside the caps:

```
always ( o30[t]:bv[24] = i40[t]:bv[24] ).
```

Only a named reviewer releases money; anyone else gets nothing:

```
always ( (i13[t]:bv[384] = { #x<reviewer_pubkey> }:bv[384]) ?
         (o30[t]:bv[24] = i40[t]:bv[24]) : (o30[t]:bv[24] = { #x000000 }:bv[24]) ).
```

Pay a fixed and an open slot the same amount together:

```
always ( (o30[t]:bv[24] = i40[t]:bv[24]) && (o31[t]:bv[24] = i40[t]:bv[24]) ).
```

A 5% royalty on each sale (a rule installed with `per_sale`, below):

```
always ( o30[t]:bv[24] = i27[t]:bv[24] / { 20 }:bv[24] ).
```

Amounts are `bv[24]` and arithmetic wraps there, so divide rather than multiply
first: `i27 * 5 / 100` would wrap for a sale above 3,355,443.

`tests/test_payout_native.py` builds and steps these four on the real engine
(skipped where the native module is not built).

## Executing

```bash
tau-testnet payout execute --key carol --account <treasury_pubkey> \
    --recipient 1=<dave_pubkey> --data 0=300
```

The CLI reads the installed `rule_id` from the node unless `--rule-id` pins one.

One execution:

1. The rule must be installed, be the one named, and its end not reached
   (`clock < expires_at`).
2. Named recipients must be open slots of the rule, and none may be the account.
3. The rule is stepped once with the ABI inputs.
4. Every slot with a positive amount is a leg. An open slot with an amount needs
   a named recipient. Then, all or nothing:
   - `1 <= total <= cap_per_execution`,
   - paid in this period + `total <= cap_per_period`,
   - `total <=` the account's balance at that point in the block.
5. The account is debited, the recipients credited, and the executor pays its fee
   **after** the legs, from what it then holds (an executor that is also a
   recipient may pay from what it receives).

A refused execution moves nothing and is not included in the block, so its
executor pays nothing either. At most 16 executions are included per block.

### Periods

Period `n` covers clock values `anchor + n * period .. anchor + (n+1) * period - 1`,
where `anchor` is the height (or block time) the rule was installed at, or the
signed `periods_from` when the rule carries one. What was paid in an earlier
period does not count against the current one, and nothing carries over.

### Per sale (royalties)

A royalty is owed once per sale, and the amount it is computed from must not be
the word of whoever claims it. A rule installed with `"per_sale": true`
(`payout set --per-sale`) therefore pays only against sales the chain recorded
itself:

- **The chain records the sale.** Every signed transfer (`user_tx`) into the
  account while the rule is installed is an open sale: its id is the
  transaction's hash, its amount what that transaction paid the account (all
  its legs to the account together, capped at 16,777,215), its payer the
  sender. A transfer from the account itself is not a sale. Transfers before
  the rule was installed are not sales of it.
- **An execution names one open sale** (`sale_id`, `payout execute --sale
  <tx_hash>`). The rule reads its amount as `i27` and its payer as `i28`, so the
  executor cannot choose the amount. An execution without a sale, with a sale
  that is not open, or with a `sale_id` for a rule without `per_sale` is refused.
- **Paid once.** A paid execution closes the sale; a second execution naming it
  is refused (`the sale named is not an open sale of this rule`). A refused
  execution, for example over a cap, leaves the sale open for a later attempt.
- **Bounded.** At most 64 sales are open per rule. A sale that arrives while 64
  are open is not recorded, and `sales_missed` counts it. Replacing, revoking or
  expiring the rule drops its open sales.

`getpayoutrule` lists the open sales (`open_sales`: id, payer, amount, height)
and `sales_missed`; the `executed` event names the `sale_id` it paid. The open
sales are part of the rule's entry in `payout_rules_root`, so every node agrees
on which sales are still payable.

The caps still apply: a royalty rule can pay no more per execution and per
period than the account signed, whatever the sale.

### Policy at execution time

The account's `o5` clause is **not** consulted: the payout rule is the account's
own authorization for these payments. The rule-change guard is not consulted for
executions either; it governs installing and revoking (below).

## Revoking

```bash
tau-testnet payout revoke --key treasury
tau-testnet payout revoke --key treasury --rule-index 2     # the rule in place 2
```

Account only, fee-free, effective in its own block: an execution later in that
block finds no rule. A revoke names the place (`rule_index`, signed; left out,
the first) and removes only the rule there. A rule also ends on its own when its block (or block time)
reaches `expires_at`; the money stays where it is.

## The rule-change guard

Installing, replacing and revoking a payout rule are rule changes. An account
with a rule-change guard (see [approvals.md](approvals.md)) has them judged with
`i1` = 6 (set payout rule) or 7 (revoke payout rule). If the guard blocks, the
direct transaction is refused, and the account files a rule-change request
instead:

```bash
tau-testnet payout set --key treasury --file payout.tau --slot <bob> \
    --cap-per-execution 500 --cap-per-period 2000 --period-blocks 1000 --ends-in 100000 \
    --request --approver 18=<cosigner_pubkey>
tau-testnet payout revoke --key treasury --request --approver 18=<cosigner_pubkey>
```

A guard that blocks every change without its co-signers covers kinds 6 and 7
with no edit. A guard that names the kinds it blocks (like the weaker wallet
template, which names 2 and 5) does not block 6 and 7.

The request carries the rule's canonical spec text (`payout_spec_text`: sorted
keys, no spaces) and releases on co-signatures or after the time escape, like
every rule-change request. At release the rule is screened and built again; a
rule that no longer fits (for example its end has passed) fails the request and
installs nothing. The installed rule's id uses the request's sequence number.

## Escrow

A payout rule plus a blocking `o5` plus a guard is an escrow without a third
party holding the money:

1. The escrow account installs a payout rule that pays the seller only when a
   named arbiter executes it (the reviewer example above).
2. It installs an `o5` clause that blocks every signed transfer.
3. It installs a guard that needs the buyer's and the seller's co-signature for
   any rule change.

From then on the money can leave only through the payout rule, the arbiter can
release no more than the caps allow, and neither party alone can swap the rules.

A work escrow with several recipients is `work_escrow` in
`tests/test_payout_native.py`: the arbiter settles the review (the worker, two
reviewers, the finder of each confirmed defect, the rest back to the poster)
and a tenth is held for a warranty window, released later to the worker or,
after a late defect, to its finder and the poster. The rule reads what it has
already paid (`i26`) to tell the two executions apart. On the real engine every
settlement path pays exactly the locked price, and nothing after it.

## Money with conditions

The same three pieces carry the conditions of money given to someone. Alice
gives Bob 5,000 he may spend at most 500 a week, not before 1 December, and what
he has not spent by 29 December goes back to her. The money sits in an account
of its own, a grant account, and ONE rule on that account is all of the
conditions:

```
always ( ( (i13[t]:bv[384] = { #x<bob_pubkey> }:bv[384])
           && (i5[t]:bv[64] >= { 1796083200 }:bv[64])
           && (i5[t]:bv[64] <  { 1798502400 }:bv[64])
           && (i40[t]:bv[24] <= { 500 }:bv[24]) && (i26[t]:bv[24] <= { 500 }:bv[24])
           && (i40[t]:bv[24] <= ({ 500 }:bv[24] - i26[t]:bv[24])) )
         ? ((o30[t]:bv[24] = i40[t]:bv[24]) && (o31[t]:bv[24] = { 0 }:bv[24]))
         : ( (i5[t]:bv[64] >= { 1798502400 }:bv[64])
             ? ((o30[t]:bv[24] = { 0 }:bv[24]) && (o31[t]:bv[24] = i2[t]:bv[24]))
             : ((o30[t]:bv[24] = { 0 }:bv[24]) && (o31[t]:bv[24] = { 0 }:bv[24])) ) ).
```

Slot 0 is open and slot 1 is Alice; the rule is installed with a period of one
week. Reading it top to bottom:

- **Who spends.** Only an execution Bob signs pays slot 0, to the payee he names.
- **When.** From 1 December until the deadline, on the block's time (`i5`).
  A weekday or an hour is arithmetic on the same input:
  `((i5 / 86400) + 3) % 7` is the weekday (0 = Monday) and `(i5 % 86400) / 3600`
  the hour, both UTC.
- **How much.** What he asks (`i40`) plus what the rule has paid this period
  (`i26`) stays inside 500. The count starts again with every period and nothing
  carries over.
- **What is left.** From the deadline on, whoever sends the execution, the
  account's whole balance (`i2`) goes to Alice. Bob's own late execution does
  the same.

The account is set up like an escrow: the rule, an `o5` clause that blocks every
transfer the account could sign, and a guard that needs Alice's and Bob's
co-signature for any rule change. `cap_per_execution` and `cap_per_period` only
have to be large enough for the return; the rule holds Bob to his cap.

What follows from the form:

- **A cap shared by several payments.** A second payment of Alice to Bob under
  the same cap is a second transfer into the same account: one account, one
  rule, one count.
- **A cap per recipient or per payment.** Another account with another rule.
- **Another condition** is another line of the rule. The node has no code for
  any of the conditions above.

`tests/test_payout_conditions_native.py` runs this rule on the real engine: each
condition alone, the example (Bob spends 500 in each of three weeks, 3,500 go
back), every history of two spends under a shared cap, and random histories
against a model. `scripts/e2e_payout_grant.py` runs it on two live nodes,
with the lock and the guard in place.

Know the limits before relying on it:

- The periods count from the block that installed the rule, not from the start
  date, unless the rule is installed with `periods_from`
  ([Optional terms](#optional-terms)).
- The return needs one execution. Anyone may send it and it can pay only Alice,
  but the node does not send it by itself, unless the rule is installed with a
  due point (`due_at`, same section).
- The guard has a time escape (see [approvals.md](approvals.md#the-time-escape)):
  whoever holds the grant account's key can file a rule change and wait
  1,000 blocks. Until wallet rules can be made tamper-proof, the conditions are
  as strong as that delay and the co-signers' attention.
- Whoever holds that key can also spend the account's balance on the fees of
  transactions it signs.
- Give the rule an end (`expires_at`) well after the deadline. Once the rule
  itself has expired, what is still in the account moves only by a co-signed
  rule change.
- Amounts are `bv[24]`: one account carries at most 16,777,215.

## Optional terms

Two more numbers a rule may be signed with, and two clocks it may read. None of
them belongs to one kind of payment: they are open to every rule. A rule that
uses none of them has the id, the book entry and the stored row it always had.

```bash
tau-testnet payout set --key grant --file conditions.tau \
    --slot open --slot <alice_pubkey> \
    --cap-per-execution 20000 --cap-per-period 40000 \
    --period-seconds 604800 --ends-at 1829952000 \
    --periods-from 1796083200 --due-at 1798502400
```

**`periods_from`: where the periods count from.** A point on the period's clock.
With it "500 a week from 1 December" counts its weeks from 1 December, whatever
block installed the rule. It may lie in the past, which lines the periods up
with a fixed day or hour. Everything before the point belongs to the first
period. It must be before `expires_at`.

**`due_at`: the node runs the rule itself.** A point on the period's clock, in
the future and before `expires_at`. In the first block whose clock reaches it,
the node steps the rule once, with nobody sending a transaction:

- It runs after the block's transactions and before expiries.
- There is no executor (`i13` is 0), no named recipient and no executor data
  (`i40+k` are 0). So only fixed slots can be paid, and a rule whose first line
  asks for a certain executor does not pay on that line.
- `i2` is the balance the block has reached, not the parent block's. A rule
  that pays "everything that is left" pays exactly what is there, also after a
  spend in the same block.
- Everything else is an execution like any other: all slots are paid or none,
  both caps and the balance hold, the paid total counts in the period, and the
  account's cooldown clock is stamped.
- It runs once, whether it paid or not (`due_done` in `getpayoutrule`; the
  history shows `executed` with `executor_pubkey: null`, or `due_not_paid` with
  the reason).
- It costs nothing beyond the fee of the transaction that installed the rule.
- At most 16 rules are run this way per block, earliest due point first; the
  rest follow in the next blocks, and a rule whose due point has not run yet is
  kept past its end until it has. An idle chain seals a block for a due point.

A rule that pays per sale cannot carry a due point (the node names no sale),
nor can a rule with only open slots. A node that takes the installing
transaction steps the rule once on the inputs of that run before it queues it,
so a rule its evaluator cannot answer in time is stopped there, the way an
execution that times out is.

For the grant of the section above, `--periods-from` the start and `--due-at`
the deadline are all it takes: the rule text stays the same, its weeks count
from 1 December, and at the deadline what Bob has not spent is back with Alice
in the first block after it, with no transaction from anyone.

**`i48` and `i49`: two clocks the node keeps for the rule.** Both are on the
rule's own clock. `i48` is the clock of the install. `i49` is the clock of the
rule's last paid execution, and the install clock until one has paid; a refused
execution does not move it. Two conditions they make possible:

```
# nothing may be spent for six hours after the money was set up
(i5[t]:bv[64] >= (i48[t]:bv[64] + { 21600 }:bv[64]))

# what has not been touched for 30 days goes back
(i5[t]:bv[64] >= (i49[t]:bv[64] + { 2592000 }:bv[64]))
```

The node hands them only to a rule that mentions them, and keeps the last paid
clock only for such a rule.

`tests/test_payout_options.py` pins the arithmetic and the block apply without
an engine, including that a rule without any of this is byte for byte the rule
it was. `tests/test_payout_options_native.py` runs the grant with both terms
and both clock conditions on the real engine, and `scripts/e2e_payout_due.py`
runs them on two live nodes: the deadline arrives in an empty block and the
money is back.

## Three ways a rule is started

A payout rule decides what is paid, to whom and under which condition. Something
has to ask it. There are three ways, and a rule is signed for the ones it wants:

| What starts the rule | Signed term | Who pays a fee |
|---|---|---|
| A transaction someone sends | none: every rule | the executor |
| The clock | `due_at`, repeated by `due_every` or `due_months` | nobody |
| A payment that arrives | `on_arrival` (with `per_sale`) | the payer, for its own payment only |

None of the three knows what the rule is for. The node only decides when it asks
and with which inputs; the answer is the rule's. So a recurring payment and a
share routed from every incoming payment are payout rules like any other.

### The clock, again and again

`due_at` alone runs the rule once. With `due_every` or `due_months` the node
runs it at every due point from `due_at` on.

```bash
# 100 to Bob on the 31st of each month, from 31 January 2027
tau-testnet payout set --key alice --file rent.tau --slot <bob_pubkey> \
    --cap-per-execution 100 --cap-per-period 100 \
    --period-seconds 86400 --ends-at 1830297600 \
    --due-at 1801353600 --due-months 1
```

```
# rent.tau: 100 to slot 0 when the node itself runs the rule, nothing for anyone else
always ( (i13[t]:bv[384] = { 0 }:bv[384])
         ? (o30[t]:bv[24] = { 100 }:bv[24]) : (o30[t]:bv[24] = { 0 }:bv[24]) ).
```

- `due_every` is on the rule's clock: 256 to 1,000,000 blocks with
  `period_blocks`, 3,600 seconds to 366 days with `period_seconds`. Due point
  number k is `due_at + k * due_every`.
- `due_months` is 1 to 12 calendar months in UTC and needs the time clock. Due
  point number k is `due_at` moved by k times that many months, with the day and
  the time of day kept. A day the month does not have becomes its last day, and
  each point is derived from `due_at`, never from the one before: a rule signed
  for the 31st runs on 28 or 29 February and on the 31st again in March.
- Each due point runs once, in the first block whose clock reaches it, exactly
  as a single due point does (see [Optional terms](#optional-terms)): no
  executor, fixed slots only, the balance the block has reached, all slots or
  none, the rule's caps.
- A due point the chain passed while another was still waiting is not caught
  up. After a run the node queues the first due point that lies after the
  block's clock. So a run never pays twice for one point, and a chain that
  stood still does not pay several at once.
- A run that pays nothing (the account does not hold the amount, a cap is
  reached, the rule answers 0) is recorded as `due_not_paid` with the reason.
  Nothing is owed for it later, unless the rule carries `due_retry` and the
  account was short ([A due point tried again](#a-due-point-tried-again)). A
  rule can also make up for it itself: it reads the clock of its last paid
  execution on `i49`.
- The last due point is the last one before `expires_at`. The rule is kept
  until that one has run, then it ends like any rule.
- Revoking the rule stops every later run. A revoke in the block of a due point
  wins: the transactions of a block come before its runs.
- The floor of 256 blocks is what lets a full book be served: 4,096 rules at 16
  runs a block take 256 blocks.

`getpayoutrule` shows `due_every` or `due_months`, `next_due` and the number of
the next due point; the history shows `due_index` with each run.

### A due point tried again

A due point can find the account short: the rule pays 100 and the account holds
60. Without more, that point is lost. `due_retry` (signed, with `due_at`) makes
the node run it again:

```bash
# the rent again; if the 31st finds the account short, try until a week later
tau-testnet payout set --key alice --file rent.tau --slot <bob_pubkey> \
    --cap-per-execution 100 --cap-per-period 100 \
    --period-seconds 86400 --ends-at 1830297600 \
    --due-at 1801353600 --due-months 1 --due-retry 604800
```

- Only a run refused because the account holds less than the rule pays is
  tried again. A run the rule answers with 0, or one a cap refuses, is not.
- The retry is a run like the one at the due point: no executor, fixed slots
  only, the balance the block has reached, all slots or none, the rule's caps.
- It runs in each later block, after the block's due points, at most 4 a block,
  longest waiting first, so a retry never takes a run from another rule's due
  point. Found short again, it waits for the next block.
- It is owed until the rule's clock reaches the due point plus `due_retry`, the
  rule's next due point or its end, whichever comes first. Then it ends unpaid
  (`due_retry_ended` in the history, when no block tried it in time) and
  nothing more is owed.
- A retry does not make the miner produce a block. The money that lets it pay
  reaches the account in a block, and the retry runs at the end of that block.
- `due_retry` is on the rule's clock: 1 to 1,000,000 blocks with
  `period_blocks`, 1 second to 366 days with `period_seconds`.

`getpayoutrule` shows `due_retry`, and `retry_at` and `retry_until` while a
retry is owed; the history marks each retry with `retry: true`, and a run that
leaves one owed with `retry_at`.

### A payment that arrives

A rule with `per_sale` pays against sales the chain recorded: signed transfers
into the account. With `on_arrival` nobody has to execute it. The node runs the
rule for each sale at the end of the block that recorded it.

```bash
# a fifth of every payment the shop receives goes to the creator
tau-testnet payout set --key shop --file route.tau --slot <creator_pubkey> \
    --per-sale --on-arrival \
    --cap-per-execution 100000 --cap-per-period 1000000 \
    --period-seconds 86400 --ends-in 31536000
```

```
# route.tau
always ( o30[t]:bv[24] = i27[t]:bv[24] / { 5 }:bv[24] ).
```

A payment of 101 leaves 81 with the shop and 20 with the creator. The payer
paid 101 and the fee of its own transaction. The shop need not be online.

- The run has no executor (`i13` is 0), so only fixed slots are paid. `i27` is
  the amount of the sale, `i28` who paid it. Everything else is an execution
  like any other: all slots or none, both caps, the balance.
- Each sale is run once and then closed, paid or not. A sale the rule pays
  nothing for is recorded as `arrival_not_paid` with the reason. The history
  in `getpayoutrule` shows each run with the sale, its amount, who paid it and
  what went to which slot: the gross, the shares and so the net.
- A sale is a transfer someone signs to the account, as for every rule that
  pays per sale. A retractable transfer released to the account, a transfer
  released by approvers and a payment the node makes by a rule are not sales.
- Money the node moves is never a sale: a payout leg, a released transfer. So a share one rule pays out is not shared again by the
  rule of the account that receives it. Only a payment someone signs is.
- At most 16 runs a block. More than that wait in the rule's open sales for the
  next blocks, and an idle chain seals a block for them. No sale is turned
  away: the limit of 64 open sales is for rules someone has to execute. What
  waits is bounded by what was paid for: every waiting sale is a signed
  transaction that paid its fee. Each account's longest-waiting sale comes
  first, so an account with many sales waiting does not hold up the one sale
  of another.
- A payment in the block that reaches `expires_at` is not a sale of the rule
  any more. A rule with a sale still waiting is kept until that sale has run.
- The condition is the rule's: a floor (`i27 >= 50`), a payer that is exempt
  (`i28`), a date after which the share stops (`i5`), two shares to two slots.
  `tests/test_payout_triggers_native.py` runs each of these on the real engine;
  none of them has a line of node code.

A node that takes the installing transaction steps the rule once on a trial
sale before it accepts it, for the same reason as with a due point.

### A sealed account

By default the key of an account stays above its payout rule: it can spend the
money itself, and it can replace or revoke the rule (after the guard's wait, if
the account has a guard). `sealed: true` gives that up until the rule ends.

While a sealed rule is installed:

- the node takes no transaction the account signs, of any type. It is refused
  at admission (`ACCOUNT_SEALED`) and in a block (`account_sealed`): no fee is
  charged and no sequence number is used;
- the rule cannot be replaced or revoked, by a transaction or by a rule-change
  request that was already waiting;
- transfers the account had parked for approval end as failed;
- money still comes in, and money leaves by the rule: executions others send,
  and the runs the node makes.

The seal ends when the rule ends: at `expires_at`, or after the last run the
node owes it. Then the key holds the account again. So a sealed rule should pay
out or return everything before its end, as the grant below does at its due
point, and whoever relies on it checks `sealed`, `due_at` and `expires_at` in
`getpayoutrule` before sending money.

```bash
# the 5,000 for Bob, in an account nobody's key can touch until 1 March
tau-testnet payout set --key grant --file conditions.tau \
    --slot open --slot <alice_pubkey> --sealed \
    --cap-per-execution 20000 --cap-per-period 40000 \
    --period-seconds 604800 --ends-at 1803859200 \
    --periods-from 1796083200 --due-at 1798502400
```

Use an account made for the purpose: a sealed account cannot do anything else
with its key, votes and approvals included.

## Several rules per account

An account holds up to eight payout rules, one per place: the first place, and
places 1 to 7 named by `rule_index`. A payer with a rent, a salary and a
royalty split keeps three rules, each with its own text, slots, caps, clock and
end.

```bash
tau-testnet payout set --key alice --file rent.tau --slot <bob_pubkey> ... --due-at ...
tau-testnet payout set --key alice --file salary.tau --slot <carol_pubkey> ... --rule-index 1
tau-testnet payout execute --key dave --account <alice_pubkey> --rule-index 1 --data 0=300
tau-testnet payout revoke --key alice --rule-index 1
```

- A set installs or replaces the rule in its own place only. The place is part
  of the signed terms and of the id.
- A revoke names the place; a guarded account's revoke request (kind 7) names
  it in its `rule_text` ("" for the first rule, as before, or "1" to "7").
- An execution names the rule by its id, as always; the CLI looks the id up by
  `--rule-index`.
- Each rule has its own period count, due points, open sales and runs. A
  payment that arrives is a sale of every per-sale rule of the account, and each
  pays its own share of it under its own caps.
- A sealed rule in any place seals the account: until it ends, the account
  signs nothing, so no rule of it can be set or revoked.
- The 4,096 rules of the book count rules, not accounts.

`tests/test_payout_triggers.py` pins all of this without an engine, including
that every rule from before is byte for byte the rule it was;
`tests/test_payout_triggers_native.py` runs the rules above on the real engine;
`scripts/e2e_payout_triggers.py` runs a recurring payment, a route and a sealed
account on two live nodes. `tests/test_payout_places.py` and
`tests/test_payout_places_guard.py` pin the places and the retry without an
engine, `tests/test_payout_places_native.py` runs them on the real engine, and
`scripts/e2e_payout_places.py` on two live nodes.

## Inspecting

```bash
tau-testnet payout show <address>
tau-testnet getpayoutrule <address>       # raw RPC
```

`getpayoutrule` answers `installed`, `rules` (every place, first place first),
the rule in the first place (`rule`) with its terms and where it
stands (`spent_this_period`, `left_this_period`, `executions`, `paid_total`,
`last_height`), its history on this node (newest first, canonical blocks only),
and `semantics`: the node's own constants, so a wallet can explain the feature
before offering it. `gettxstatus` names what a confirmed payout transaction did
(`payout`: the outcome, legs and, for an install, whether the rule is still the
account's).

## Limits

| Limit | Value |
|---|---|
| Rules per account | 8 (the first place and places 1 to 7) |
| Rules in total | 4,096 |
| Slots per rule | 8 |
| Executor data inputs | 8 |
| Executions per block | 16 |
| Due points run per block | 16 |
| Runs on arrival per block | 16 |
| Retries of a short due point per block | 4 |
| Shortest repeat (`due_every`) | 256 blocks, or 3,600 seconds |
| Rule text | 4,096 bytes |
| Open sales per rule (`per_sale`) | 64 |

## Error codes

| Code | When |
|---|---|
| `INVALID_PAYOUT_RULE` | The rule is malformed, does not fit the ABI, or breaks a limit. |
| `DUPLICATE_PAYOUT_RULE` | This exact rule is already installed. |
| `PAYOUT_BOOK_FULL` | 4,096 rules are installed (replacing one of your own is still possible). |
| `PAYOUT_RULE_DOES_NOT_BUILD` | The rule does not compile. |
| `NO_PAYOUT_RULE` | Revoke without an installed rule in the place named. |
| `INVALID_PAYOUT_EXECUTION` | The execution is malformed. |
| `PAYOUT_REFUSED` | The execution would be refused (reason in the message). |
| `RULE_CHANGE_NEEDS_APPROVAL` | The account's guard blocks the change; use `--request`. |
| `WRONG_NETWORK` | `genesis_hash` is missing, malformed, or names another network. |
| `ACCOUNT_SEALED` | The sender's payout rule is sealed: the account signs nothing until the rule ends. |

Apply reasons in receipts: `payout_rule_not_set`, `payout_rule_not_revoked`,
`payout_not_executed`, `wrong_network`.

## Raw transactions

```json
{"tx_type": "payout_rule_set", "genesis_hash": "<block 0>", "sender_pubkey": "<account>",
 "sequence_number": 7,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "20",
 "rule_text": "always ( o30[t]:bv[24] = i40[t]:bv[24] ).", "slots": ["<bob>", ""],
 "cap_per_execution": 500, "cap_per_period": 2000, "period_blocks": 1000,
 "expires_at": 104000, "signature": "..."}

{"tx_type": "payout_execute", "genesis_hash": "<block 0>", "sender_pubkey": "<executor>",
 "sequence_number": 3,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "20",
 "account_pubkey": "<account>", "rule_id": "<64 hex>", "recipients": {"1": "<dave>"},
 "data": {"0": 300}, "signature": "..."}

{"tx_type": "payout_execute", "...": "as above, for a rule installed with per_sale",
 "sale_id": "<64 hex: the hash of the transfer that paid the account>"}

{"tx_type": "payout_rule_revoke", "genesis_hash": "<block 0>", "sender_pubkey": "<account>",
 "sequence_number": 8,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "0",
 "signature": "..."}
```

Every field above is in the signed bytes (`per_sale`, `periods_from`, `due_at` and `sale_id` when present). `recipients` keys are slot numbers,
`data` keys are k for input `i40+k`. `genesis_hash` is the hash of block 0 of the
network (`getsequence` returns it, the CLI fills it in): all three types are bound to
one network (`consensus/network_binding.py`), so a rule or an
execution signed for another network is refused here.

## Consensus notes

- The book (one row per rule: the id, the terms, and where it stands) plus a
  running commitment of every removal (`replaced`, `revoked`, `expired`) is
  folded into the consensus metadata as `payout_rules_root` **only once the book
  has held a rule**. Until then the metadata is unchanged, so **no regenesis** is
  needed; nodes must upgrade before the first install.
- `i2` is read from the parent block's balances, as for transfers, so proposer
  and verifier feed the rule the same value.
- Replay without a policy evaluator cannot re-run a rule: such an execution moves
  nothing, and the state hash shows it.
- Expiry runs after the block's transactions, before rule-change releases; an
  execution in the expiry block is refused by its clock check.
- Due points run after the block's transactions and the runs on arrival,
  before expiries, in the order (due point, account) with rules on the block
  clock first. Such a run reads the balance the block has reached, which every
  node has computed the same way by then.
- A rule with an optional term, or one that reads `i48` or `i49`, carries a
  second part in its book entry (the terms, the last paid clock, whether the
  due point has run). Every other rule hashes exactly as before.
- Runs on arrival come after the block's transactions and before the due
  points, in the order (position among the account's waiting sales, block that
  recorded the sale, account). A rule with `due_every`, `due_months`, `on_arrival` or
  `sealed` adds those terms and the number of its next due point to the second
  part of its entry; a rule without them hashes exactly as before.
- A rule in another place than the first, or one with `due_retry`, adds its
  place, `due_retry`, and where a retry stands (`retry_at`, `retry_until`) to
  the second part of its entry. Retries run after the due points, in the order
  (retry point, key), at most 4 a block. A rule without these terms hashes
  exactly as before.
- The seal is checked in the block against the book as the block has built it,
  so a transaction of the account later in the block that installed the sealed
  rule is refused too.

## Operator notes

**Upgrading.** No regenesis and no activation height. Until the first
`payout_rule_set` is mined, blocks and state hashes are byte-identical to a
node without this feature, so mixed versions agree. That block adds
`payout_rules_root` to the consensus metadata, and a node that has not upgraded
refuses it. Upgrade every node before anyone sends the first one.

| Table | Written | Read by |
|---|---|---|
| `payout_rules_v1 (account_pubkey, rule_id, …)`; `account_pubkey` is the rule's key: the account for the first place, `account/k` for place k | with the accounts, in the block's state commit | restore at start, `getpayoutrule` |
| `payout_events (account_pubkey, block_hash, …)`, indexed by account | per block, every node, apply and replay | `getpayoutrule`, `gettxstatus` |

Tables and columns are created on start; there is no manual migration.
Events are keyed per block, like `retractable_events`, so a reorg needs no
cleanup. At start a node rebuilds the book from its table and refuses to
start on a row that does not recompute its id or holds an impossible state
(`corrupt payout rule state`): restore the database or resync the node.

**Policy workers.** An execute runs the installed rule in the policy
evaluator's apply pool, never in the main interpreter, within the same time
budget as a transfer's policy step. A block carries at most 16 executes; the
block builder leaves the rest in the mempool for the next block.

Each payout pool keeps one built rule at a time (`tau_policy.pool_options`).
On the pinned engine (tau-lang `c3ea334`) a rule that is stepped after another
rule was built in the same worker sometimes refuses the step, and in a few
runs answered 0: about 5 steps in 100 for `o30 = i27 / 5` after a second rule
was validated (21 of 400), and never on tau-lang 0.8.5. Two nodes could then
disagree about a payout. With one rule at a time a rule is always stepped on
an interpreter built after every other build; 6,000 steps of six rules in
turn, with 1,807 validations mixed in, all answered right. The price is one
build of about 10 ms each time the rule changes. Once the pin moves to an
engine without the fault the pools can keep the default cache again.

**Network.** `payout_rule_set`, `payout_rule_revoke` and `payout_execute` gossip on
`tau/payout/1.0.0`; a mempool snapshot carries at most 32 of them.

**Logs.** `Replay without a policy evaluator: payout … not re-run` means a
replay could not run the rule; nothing moves, and the state hash says so.

## Security notes

- An open slot lets the executor choose the recipient. A rule with open slots
  must decide from its inputs (`i13`, `i30+k`, `i40+k`) what each may receive;
  the caps bound the damage of a rule that decides badly.
- Anyone can send executions. A rule that pays on any input pays whoever asks
  first, up to the caps.
- A payout rule bypasses the account's `o5` clause by design. An account that
  relies on `o5` limits should not install one, or should use the guard so that
  a stolen key cannot install one.
- Executions are bounded per block (16), and refused ones cost the executor
  nothing but are not included either, so they cannot fill blocks.
- Runs the node makes are bounded per block too (16 at due points, 16 on
  arrival, 4 retries), and each run on arrival was paid for by the fee of the
  payment that caused it.
- A seal binds the key holder for the life of the rule and nobody can lift it,
  the key holder included. Check the rule text and `expires_at` before signing.

## Not in this release

- A run on arrival for money the node itself moved (a payout leg, a released
  transfer): only a signed payment is a sale.
- Executor data wider than `bv[24]`.
