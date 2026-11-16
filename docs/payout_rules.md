# Payout rules

A payout rule lets an account's money be paid out by a Tau rule the account
installed, without the account signing each payment. The account installs one
rule; from then on **anyone** may send `payout_execute` naming the account. The
node steps the rule once, reads one amount per recipient slot, and pays all of
them or none, inside caps the account signed.

Typical uses: a reviewer's key releases bounty or milestone money to a
contributor; a treasury pays out a fixed share whenever someone triggers it,
at most so much per period; an allowance anyone can trigger for a named
recipient, at most once a week.

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

A rule reads `[t]` only, reads at least one input, writes at least one slot
amount, and mentions no slot it does not have. Anything else is refused at
install.

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

`tests/test_payout_native.py` builds and steps these three on the real engine
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

{"tx_type": "payout_rule_revoke", "genesis_hash": "<block 0>", "sender_pubkey": "<account>",
 "sequence_number": 8,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "0",
 "signature": "..."}
```

Every field above is in the signed bytes. `recipients` keys are slot numbers,
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
