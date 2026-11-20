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

Admission and apply refuse a rule that pays the account itself in a fixed slot,
names one fixed recipient in two slots, or does not fit the ABI. The rule is
built (compiled) in the payout pool at admission and again at apply; a rule that
does not build is not installed.

Installing costs one fee, paid by the account. Installing again replaces the
current rule: the old one is removed (outcome `replaced`) and the new one starts
its own period count where it is installed. There is no edit.

### The id

`rule_id` is a BLAKE3 hash over the account, the install's sequence number, the
hash of the normalized rule body, the slots, both caps, the period clock and
length, and `expires_at` (`compute_payout_rule_id`). Every execution names the
id, so an execution signed against a rule the account has since replaced is
refused instead of running the new rule.

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
where `anchor` is the height (or block time) the rule was installed at. What was
paid in an earlier period does not count against the current one, and nothing
carries over.

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
```

Account only, fee-free, effective in its own block: an execution later in that
block finds no rule. A rule also ends on its own when its block (or block time)
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

## Inspecting

```bash
tau-testnet payout show <address>
tau-testnet getpayoutrule <address>       # raw RPC
```

`getpayoutrule` answers `installed`, the rule with its terms and where it
stands (`spent_this_period`, `left_this_period`, `executions`, `paid_total`,
`last_height`), its history on this node (newest first, canonical blocks only),
and `semantics`: the node's own constants, so a wallet can explain the feature
before offering it. `gettxstatus` names what a confirmed payout transaction did
(`payout`: the outcome, legs and, for an install, whether the rule is still the
account's).

## Limits

| Limit | Value |
|---|---|
| Rules per account | 1 |
| Rules in total | 4,096 |
| Slots per rule | 8 |
| Executor data inputs | 8 |
| Executions per block | 16 |
| Rule text | 4,096 bytes |
| Open sales per rule (`per_sale`) | 64 |

## Error codes

| Code | When |
|---|---|
| `INVALID_PAYOUT_RULE` | The rule is malformed, does not fit the ABI, or breaks a limit. |
| `DUPLICATE_PAYOUT_RULE` | This exact rule is already installed. |
| `PAYOUT_BOOK_FULL` | 4,096 accounts already have a rule (replacing your own is still possible). |
| `PAYOUT_RULE_DOES_NOT_BUILD` | The rule does not compile. |
| `NO_PAYOUT_RULE` | Revoke without an installed rule. |
| `INVALID_PAYOUT_EXECUTION` | The execution is malformed. |
| `PAYOUT_REFUSED` | The execution would be refused (reason in the message). |
| `RULE_CHANGE_NEEDS_APPROVAL` | The account's guard blocks the change; use `--request`. |
| `WRONG_NETWORK` | `genesis_hash` is missing, malformed, or names another network. |

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

Every field above is in the signed bytes (`per_sale` and `sale_id` when present). `recipients` keys are slot numbers,
`data` keys are k for input `i40+k`. `genesis_hash` is the hash of block 0 of the
network (`getsequence` returns it, the CLI fills it in): all three types are bound to
one network like standing payments (`consensus/network_binding.py`), so a rule or an
execution signed for another network is refused here.

## Consensus notes

- The book (one row per account: the id, the terms, and where it stands) plus a
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

## Operator notes

**Upgrading.** No regenesis and no activation height. Until the first
`payout_rule_set` is mined, blocks and state hashes are byte-identical to a
node without this feature, so mixed versions agree. That block adds
`payout_rules_root` to the consensus metadata, and a node that has not upgraded
refuses it. Upgrade every node before anyone sends the first one.

| Table | Written | Read by |
|---|---|---|
| `payout_rules_v1 (account_pubkey, rule_id, …)` | with the accounts, in the block's state commit | restore at start, `getpayoutrule` |
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

## Not in this release

- More than one rule per account.
- Paying a rule's amounts in the end-of-block sweep without an execution (that
  is what standing payments are for).
- Executor data wider than `bv[24]`.
