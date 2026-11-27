# Which rules are in force, and what a transaction did

Two questions a wallet has to answer before it can tell a user "your protection
is on":

1. **Did my rule transaction take effect?** A transaction in a block is not the
   same as a transaction that did something. `gettxstatus` used to answer
   `confirmed` for both.
2. **What is in force for this account right now?** The `o5` clause, the
   rule-change guard, open rule-change requests and application rules that name
   the account lived behind four different reads.
3. **What does the engine actually run?** A later rule can revise part of an
   earlier one, so the stored rule units say what was sent, not what is in
   force.
4. **What was in force when an earlier payment was made?** Both sides of a
   payment may have to show later which conditions held in its block.

`gettxstatus` now carries the transaction's **outcome**, `getaccountrules`
answers the second question from one tip, `running_spec` (in
`getaccountrules` and `getgovernance`) answers the third, and
`getaccountrules <address> <block>` the fourth. All are read-only, need no restart,
no regenesis and no change to the state hash. Issue: #42.

Short reference: [README](../README.md#pending-aware-wallet-queries). CLI:
[developer_cli.md](developer_cli.md#policy-guard). This guide is the long form.

## Outcome of a confirmed transaction

```bash
tau-testnet rpc gettxstatus <tx_hash>
```

A `confirmed` answer adds `outcome`:

```json
{"tx_hash": "…", "status": "confirmed", "block_number": 41, "confirmations": 3,
 "outcome": {
   "status": "applied", "index": 0, "fee_charged": 10,
   "logs": ["o5 clause registered for 8e7bb4c3e3", "Fee charged: 10 -> proposer 1a2b…"],
   "rule_effects": [{"account": "8e7b…", "kind": "clause", "stream": 5,
                     "action": "registered", "sha256": "…"}]}}
```

| Field | Meaning |
|---|---|
| `status` | `applied`: the transaction did what it carried. `skipped`: it is in the block and valid, but it changed nothing (the receipt logged an ignored offer, decision, request, vote or update). `rejected`: the block carries a transaction its apply step refused (an honest proposer leaves those out; see below). `not_recorded`: this node applied the block before it began recording outcomes. |
| `index` | Position in the block. |
| `reason` | The receipt's machine reason, when it has one (`rule_not_applied`, `rule_change_needs_approval`, …). |
| `fee_charged` | What the sender paid. `0` for an included transaction that paid nothing. A skipped transaction can still have paid: that is the case a wallet must show. |
| `logs` | The apply receipt, at most 16 lines of at most 400 characters each, then a `... N more line(s)` marker. |
| `rule_effects` | What the transaction changed in anyone's rules, only on `applied`. |

A transaction that changed a rule is never `skipped`, even when another of its
operations logged "ignored".

### Rule effects

| `kind` | `action` | `stream` | `sha256` of |
|---|---|---|---|
| `clause` | `registered`, `replaced` | `5` for the `o5` policy, `4294967295` (`0xFFFFFFFF`) for the rule-change guard | the clause body as the registry stores it |
| `clause` | `revoked` | as above | none |
| `application_rule` | `accumulated` | none | the unit as the application-rules accumulation stores it |

`account` is the account whose rules changed (the sender, or the acceptor of an
offer). The hash is over the exact stored text, which is also what
`getaccountrules` hashes, so the two can be compared byte for byte.

An `accumulated` effect also says what the engine did with the unit, read off
the engine's own revision receipt when the block was applied:

```json
{"account": "8e7b…", "kind": "application_rule", "action": "accumulated", "sha256": "…",
 "revision": {"taken": true, "engine_outcome": "ACCEPTED_CHANGED", "spec_revision": 12}}
```

| `revision` field | Meaning |
|---|---|
| `taken` | `true` when the engine took the unit as a revision and its revision counter advanced (`ACCEPTED_CHANGED`). `false` when the engine consumed the unit and its counter stayed (`ACCEPTED_NOOP`): the rule is stored, nothing new is in force. A unit the engine refuses is never included, so it has no effect at all. `taken` says the engine revised, not that the text it runs differs: the unit already in force, sent once more, counts as a revision and leaves the text the same (checked on the real engine). Whether the text differs is what `running_spec.sha256` of the block and of the block before it say, see [The rules at an earlier block](#the-rules-at-an-earlier-block). |
| `engine_outcome` | The engine's outcome as it reported it. |
| `spec_revision` | The engine's revision counter after the unit. It grows with every revision taken, so a wallet can order its rules. Nodes that applied the same blocks give the same number, and a restarted node, whose engine is rebuilt from the journal, continues it (both checked on two live nodes, scenario 7). |

`revision` is absent when the evaluator gave no receipt (the mock engine of
`TAU_FORCE_TEST`).

### The rule's outcome from the block's journal (`rule_outcome`)

The outcome above is this node's own record, written when it applied the
block. A node that was upgraded in place has none for older blocks. For a
transaction that carried a rule for the engine, `outcome` therefore also
carries `rule_outcome`, read from the journal the block committed with:

```json
"outcome": {"status": "applied", "…": "…",
            "rule_outcome": {"source": "committed_journal",
                             "engine_outcome": "ACCEPTED_CHANGED",
                             "accepted": true, "taken": true, "spec_revision": 12}}
```

Every revision the engine was asked for in a block is a row of the committed
journal, in block order, with the rule text and the engine's outcome. The k-th
transaction of the block that carries a given text is the k-th row with that
text. `spec_revision` is the counter in the block's commit record minus the
revisions the engine took later in the same block, so it is the counter after
this rule. The journal is hash-chained and committed with the block, a
restarted node keeps it and a follower rebuilds the same rows, so the answer
needs no record of the node's own: it is there for a block whose `status` is
`not_recorded`, next to that status.

- A transaction without a rule, and a rule that is a clause (`o5`, the guard),
  have no `rule_outcome`: a clause is kept in the registry, not in the
  engine's specification.
- Where the block's transactions and its journal rows do not pair up (the
  block carries the text 2 times and the journal 1), the answer is
  `{"source": "committed_journal", "unavailable": "…"}`. It is never guessed.
- On the real engine the two sources agree for every rule transaction, the
  counter included (`tests/test_running_spec_native.py`, and scenario 8 on two
  live nodes, one of them restarted in between).

### What is recorded where

Every node records the outcome of every block it applies, live or in a replay,
during the same apply that computes the state, so two nodes record the same
status, fee and rule effects for the same block. The logs can differ where a node
hit a node-local error (a width conflict in its own interpreter, a Tau process
that was not ready). The record is node-local, like the retractable events:
it is not part of the state hash, a fork needs no cleanup, and canonicality is
resolved when it is read.

- A node that **synced from genesis** after this change has the outcome of every
  block. A node that was **upgraded in place** has it from the upgrade on and
  answers `not_recorded` before that; resyncing from an empty data directory
  fills the gap.
- A transaction that **apply rejects** is left out of the block by the node that
  builds it. That node keeps the reason in `mempool_dropped`, and its
  `gettxstatus` answers `rejected` with `reason` and `detail`. Other nodes never
  see the transaction in a block and report it `queued` until it expires.
  Outcomes do not change this: they describe transactions that reached a block.

## Everything in force for one account

```bash
tau-testnet policy show <address>          # human summary
tau-testnet --json policy show --key alice # the raw answer
tau-testnet rpc getaccountrules <address>
```

```json
{"address": "8e7b…", "block_number": 41, "block_hash": "…",
 "rule_clauses_root": "…",
 "clauses": [{"stream": 5, "name": "o5", "body": "…", "sha256": "…",
              "since": {"block_number": 40, "tx_hash": "…"}}],
 "rule_change_guard": {"body": "…", "sha256": "…",
                       "since": {"block_number": 12, "request_id": "…"}},
 "application_rules": [],
 "fee_rules": [{"unit": "always ( … -> (o8[t]:bv[24] = { #x000064 }:bv[24]) ).", "sha256": "…",
                "names_this_account": false, "sent_by": ["c41d…"],
                "since": {"block_number": 33, "tx_hash": "…"}}],
 "running_spec": {"text": "always (…) && o27[t]:bv[24] = { 9 }:bv[24] && o26[t]:bv[24] = { 3 }:bv[24]",
                  "sha256": "…", "block_hash": "…"},
 "open_rule_changes": [{"request_id": "…", "kind": "set_policy", "body_sha256": "…",
                        "offer_id": null, "approvers": {"18": "…"}, "voted": {},
                        "declined": [], "ready": false,
                        "created_height": 39, "expire_at_height": 2039}],
 "awaiting_my_vote": [],
 "pending_offers": 1,
 "mempool": [{"tx_hash": "…", "tx_type": "rule_change_request"}],
 "history": [{"block_number": 40, "kind": "clause", "stream": 5,
              "action": "registered", "tx_hash": "…", "sha256": "…"}]}
```

| Field | Meaning |
|---|---|
| `block_number`, `block_hash` | The tip every chain field below was read at. |
| `rule_clauses_root` | The registry root folded into the state hash (`""` while the rule book is empty, as in the state hash itself). |
| `clauses` | The account's registry clauses except the guard, with the sha256 of each stored body. |
| `rule_change_guard` | The guard clause, same shape, or `null`. |
| `since` | The block, and the transaction or released request, that put this exact text in place, from this node's records; `null` when that happened before the node began recording. |
| `application_rules` | Units of the application-rules accumulation whose text names the account's key (`#x<address>`), each with its sha256. |
| `fee_rules` | Every unit of the accumulation that writes the fee stream `o8`, whoever sent it, in the order the units joined. The engine works out `o8` from the whole specification for every transaction, and the node admits a fee rule only when it is fenced to its sender's own key (`UNSCOPED_USER_RULE`), so the list shows which unit sets which sender's fee (#183); `application_rules` shows only the units that name the account. `names_this_account` says whether its text names the account's key. `sent_by` lists the accounts whose rule transaction brought it, from this node's record: the sender of the transaction, never a key the text names. `null` when the node has no record of it (a genesis unit, or one from before it began recording). The same list for every account that asks. |
| `running_spec` | The specification the engine runs at `running_spec.block_hash`, as the engine revised it, in canonical (full-width) form, with the sha256 of that text. See [What the engine runs](#what-the-engine-runs-running_spec). |
| `open_rule_changes` | The account's own rule-change requests that are still open: kind, hash of the requested body, approvers by slot, votes, declines, whether the guard already allows it (`ready`), and the expiry height. |
| `awaiting_my_vote` | Open rule-change requests from other accounts that name this account as an approver, with their `sender_pubkey`. |
| `pending_offers` | Rule offers addressed to the account that are still undecided. |
| `mempool` | Rule-bearing transactions from the account not yet in a block (an `o5`/rule op `0`, offer decisions, rule-change requests and cancels). |
| `history` | The latest 20 rule effects that named the account, newest first. |

All chain fields come from **one** tip: the node reads its in-memory state under
the same locks a block swap holds, so a block landing during the call cannot mix
two tips. `history`, `since` and `mempool` are this node's own view.
`running_spec` names its own head (`block_hash`), read in one database read with
the rules it was built from; the call reads it again, at most three times, until
that head is the tip above.

### Checking that the rule in force is the one the user meant

A wallet that sent a rule knows its text. It can hash the text the way the node
stores it and compare:

1. Send the rule and remember the `tx_hash`.
2. Poll `gettxstatus` until `confirmed`; read `outcome.rule_effects`.
3. Read `getaccountrules`; the clause on that stream must carry the same
   `sha256`, and `since.tx_hash` must be the transaction from step 1.

Only then should a wallet say "protection on". A `skipped` outcome, a different
hash, or a `null` clause means it is not.

For an application rule, step 2 already answers whether it took effect, without
running the engine: the `accumulated` effect carries the hash of the stored unit
and `revision.taken`. `taken: false` means the engine already ran something that
implies it. Whether a later rule has since revised part of it is what
`running_spec` below answers.

### What the engine runs (`running_spec`)

A rule unit can revise part of an earlier one. The probe of Sep 27 on #42:

1. `always ( o26[t]:bv[24] = { 7 }:bv[24] && o27[t]:bv[24] = { 9 }:bv[24] ).`
2. `always ( o26[t]:bv[24] = { 3 }:bv[24] ).`

After the second, `getgovernance.application_rules` still holds both units, the
`7` included, while the engine runs `o26 = 3` and `o27 = 9`. `running_spec.text`
is that second answer:

```text
always (i0[t]:tau = 0 || …) && … && o27[t]:bv[24] = { 9 }:bv[24] && o26[t]:bv[24] = { 3 }:bv[24]
```

Stored units stay listed as what was sent and are never labelled "in force";
`running_spec` is what a wallet reads to know what is in force.

How it is built. The authoritative evaluator runs in a worker whose rule text
feeds some streams shrunk (an address stream as `bv[8]` instead of `bv[384]`),
so its own text is not one two nodes can compare. The node gives the same engine
the committed rule history in canonical form, in a worker of its own: the units
of the last journal reset, then every revision the engine accepted, in order.
It reads back the engine's own `current_spec()`. The steps between the
revisions are not replayed: the revised text depends on the revisions and their
order, not on the inputs or the time point at which they arrived (the same text
and hash with no steps and with steps between).

What to compare. At the same `block_hash`, every node gives the same `text` and
`sha256`: the history it is built from is the committed journal, which a
restarted node and a follower replaying from block 0 rebuild the same way. A
wallet that wants to know whether a rule it sent is in force can look for its
terms in `running_spec.text` and check `sha256` across nodes it uses.

When it is missing. `text` and `sha256` are `null`, with `unavailable` naming
why, on a node that runs without the authoritative engine (the mock engine of
`TAU_FORCE_TEST`) or when the engine could not rebuild the text (a unit not
accepted again is reported, never a partial text).

`tests/test_running_spec_native.py` runs the probe through real blocks on the
real engine, and checks that each of the two transactions says its revision was
taken, in order; `scripts/e2e_rules_in_force.py` (scenarios 6 and 7) on two live
nodes, across a restart (a third rule, `o27 = {4}`, applied by the engine as
rebuilt after it) and a follower's replay.

### The rule-change release

A guarded rule change is parked as a request and written later by the release
at the end of a block, not by a transaction. The release records what it wrote
in the same history, with `request_id` in place of `tx_hash`. A request that
fails at release (the policy it would revoke is already gone, the offer
expired, the body no longer builds) appears as:

```json
{"block_number": 38, "kind": "rule_change_request", "action": "release_failed",
 "request_id": "…", "detail": "no policy to revoke"}
```

Before this, the reason was only in the node's log.

## The rules at an earlier block

```bash
tau-testnet policy show <address> --block 40         # human summary
tau-testnet rpc getaccountrules <address> 40          # a block number
tau-testnet rpc getaccountrules <address> <64-hex>    # or a block hash
```

The answer describes the account when that block of the canonical chain
committed:

```json
{"address": "8e7b…", "block_number": 40, "block_hash": "…",
 "at_block": true, "head_block_number": 57,
 "complete": true, "recorded_from": 1,
 "clauses": [{"stream": 5, "name": "o5", "body": "…", "sha256": "…",
              "since": {"block_number": 40, "tx_hash": "…"}}],
 "rule_change_guard": null,
 "application_rules": [],
 "fee_rules": [],
 "running_spec": {"text": "…", "sha256": "…", "block_hash": "…", "spec_revision": 11},
 "history": [{"block_number": 40, "kind": "clause", "stream": 5,
              "action": "registered", "tx_hash": "…", "sha256": "…"}]}
```

| Field | Meaning |
|---|---|
| `at_block`, `head_block_number` | The answer is for an earlier block, read while this was the head. |
| `clauses`, `rule_change_guard` | What the registry held for the account when the block committed, with the text and where it was set. |
| `application_rules` | The units naming the account that were accumulated up to the block, each with the block and transaction that brought it. |
| `fee_rules` | The units writing `o8` accumulated up to the block, as at the tip. |
| `running_spec` | What the engine ran when the block committed, with the engine's revision counter of that block. |
| `history` | The latest 20 rule effects up to the block, newest first. |
| `complete` | `true` when every part of the answer is certain. |
| `recorded_from` | The block at which this node's unbroken record that reaches the block begins (`1` on a node that synced from genesis), `null` when the block itself is not recorded. |

The fields that exist only at the tip are left out: open requests, offers, the
mempool and the registry root.

Where it comes from.

- **The running spec** comes from the committed journal alone. Every block's
  commit record names the journal head it committed with, so the rule history
  of a block is the journal up to that head. The hash chain of that stretch is
  verified first, then the engine rebuilds the text from it the way it does for
  the tip. A journal that does not verify, a missing commit record and a unit
  the engine does not accept again are each reported in `unavailable`, never
  answered from. The text of a block is cached by its journal head.
- **The clauses and the guard** come from this node's record of rule effects
  and the texts it keeps with them (below). The registry itself holds only the
  present state.
- **The application rules** are the genesis units and every unit accumulated up
  to the block, in order.

What a node cannot know, it says. A node that synced from genesis with this
change records every block and answers `complete: true` for all of them. A
node that was upgraded in place did not record its earlier blocks:

- A clause that was set in a block the node did not record is listed with
  `unavailable` and without a text. If nothing touched the stream since, the
  text is what the registry holds now, and it is given.
- `application_rules` and `fee_rules` are `null`, with
  `application_rules_unavailable`, when the record does not reach back to
  block 1.
- If the record's newest word on a stream is not what the registry holds, the
  node answers `unavailable: "this node's record does not match its registry"`
  and nothing from the record.
- The running spec does not depend on the record, so it is there for every
  block that has a commit record.

A block that is not on the canonical chain, a number above the head and a
fourth word are refused with `INVALID_PARAMS`. Effects recorded for a block
that a reorg left behind are ignored: canonicality is resolved at read time.

Why the journal and not the stored units. Sent `o26 = {7} && o27 = {9}`, then
`o26 = {3}`, then the first unit once more: the engine runs `o26 = 7` again,
because a unit revises what is there in the order it arrives. The stored units
hold each text once and are the same before and after the third transaction.
Only the rule history in order, which the journal keeps, gives each block's
text (`tests/test_running_spec_native.py::test_each_block_of_the_probe_reads_what_the_engine_ran_then`).

What to compare. Two nodes give the same answer for the same block, a node
gives the same answer before and after a restart, and an earlier block answers
with what the tip said while it was the tip. `scripts/e2e_rules_in_force.py`
(scenarios 7 and 8) checks all three on two live nodes for eight remembered
blocks: clauses set, replaced and revoked, an accepted offer, a guard, a
release, and the two blocks of the probe.

## No fee for a unit the network drops

The third point of #42: an account sent an `o5` unit behind `i12 = <its key>`,
the specification already held another account's `o5` unit in total form, the
engine found nothing new, and the account paid for a rule that never took
effect.

On this node that cannot happen, and `tests/test_no_fee_for_a_dropped_unit.py`
pins why:

- An `o5` unit never joins the shared specification. It is the sender's own
  clause, kept per account. No account's `o5` rule can make another's a no-op:
  two accounts each keep their own, in one block or in later ones, with the
  same text or different ones.
- The reported unit itself is refused at admission with `CLAUSE_SHAPE` and the
  way to fix it (submit the body without the `i12` guard), before any fee, the
  same way `UNSCOPED_USER_RULE` refuses an unscoped rule. `checktx` gives the
  same verdict before signing.
- A block that carries it anyway rejects it at apply: `rejected`,
  `rule_not_applied`, `fee_charged: 0`, no rule effect, nothing registered,
  the specification untouched.
- The same policy without the guard is `applied` and `registered` as the
  sender's clause.

What is left of "accepted, nothing new" is an application rule whose text the
engine already runs. The transaction is valid and pays, and the reads say what
happened: the outcome names the engine's verdict, and the block's
`running_spec.sha256` equals that of the block before it. Refusing such a unit
at admission would be wrong, because the same text sent again is not always a
no-op (see the example above).

## Operator notes

| Table | Written | Read by |
|---|---|---|
| `tx_outcomes (tx_hash, block_hash, …)` | per block, every node, apply and replay | `gettxstatus` |
| `rule_effects (account, block_hash, …)`, indexed by account | per block, every node | `getaccountrules` |
| `rule_bodies (sha256, body)` | with the effects: each rule text once, by its hash | `getaccountrules <address> <block>` |
| `outcome_blocks (block_hash, block_number)` | one row per block whose outcomes were recorded, also a block without transactions | `getaccountrules <address> <block>`, to know where the record is unbroken |

All writes are best effort: a failure is logged and never reaches block commit.
The tables are created on start (`CREATE TABLE IF NOT EXISTS`); there is no
migration. They grow with the chain; a full replay rewrites them idempotently.
`rule_bodies` grows with the number of distinct rule texts, not with the number
of blocks. None of them is part of the state hash.

A read for an earlier block walks the canonical chain from the head and reads
the account's effects; its running spec starts one engine worker for a journal
head it has not built yet (the newest 16 are kept), outside the state locks.

`getaccountrules` is in the expensive rate-limit tier: it takes the state locks
and scans the mempool and the history.

`running_spec` is cached per committed rule history. The first read after a
journal reset or an accepted revision starts one engine worker, replays the rule
units in canonical form and closes it (measured: about 0.3 s for the 8 rule
units of the test chain; it grows with the number of units); every later read
until the next rule change is a database read (0.1 ms). It is never built under the state locks, so a block never waits
for it.

## What this does not do

- It does not prove anything to a wallet that does not trust its node. A light
  wallet that wants proof needs a receipts root committed by the block, which
  changes the header or the state hash and therefore needs a coordinated
  restart.
- An earlier block's clauses are this node's record, not a proof. They are
  certain on a node that recorded every block (`complete: true`) and named as
  unknown elsewhere. The running spec of a block needs no such record: it is
  rebuilt from the committed journal.
- It does not change which transactions are valid or what they cost. Soft no-ops
  (an offer that lost a race, a duplicate request) still sit in the block and
  pay their fee; they are now visible as `skipped` with their `fee_charged`.
