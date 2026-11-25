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

`gettxstatus` now carries the transaction's **outcome**, `getaccountrules`
answers the second question from one tip, and `running_spec` (in
`getaccountrules` and `getgovernance`) answers the third. `getrulesinforce`
answers the third question at any committed block, not just the head. All are
read-only, need no restart, no regenesis and no change to the state hash.
Issue: #42.

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
| `taken` | `true` when the engine's specification changed (`ACCEPTED_CHANGED`). `false` when the engine accepted the unit without a change (`ACCEPTED_NOOP`, a unit the specification already implies): the rule is stored, nothing new is in force. A unit the engine refuses is never included, so it has no effect at all. |
| `engine_outcome` | The engine's outcome as it reported it. |
| `spec_revision` | The engine's revision counter after the unit. It grows with every revision taken, so a wallet can order its rules. Nodes that applied the same blocks give the same number, and a restarted node, whose engine is rebuilt from the journal, continues it (both checked on two live nodes, scenario 7). |
| `spec_revision_before` / `spec_revision_after` | The counter on both sides of the unit, when the receipt carries them. A taken unit moves it by exactly one; a no-op leaves it unchanged. |

`revision` is absent when the evaluator gave no receipt (the mock engine of
`TAU_FORCE_TEST`).

### `rule_outcome` and the positive registry check

A confirmed transaction's `outcome` also carries `rule_outcome`, so a wallet
does not have to infer what a rule transaction did from the absence of an
effect:

| `rule_outcome` | Meaning |
|---|---|
| `{"engine_outcome": "ACCEPTED_CHANGED", "taken": true, "spec_revision_before": 4, "spec_revision_after": 5}` | The transaction's application rule, and what the engine did with it. `ACCEPTED_NOOP` with `taken: false` is a unit the engine accepted without changing anything. |
| `{"status": "clause", "registry_confirmed": true}` | A clause-only transaction, with every clause effect confirmed against the registry (below). |
| `{"status": "unmatched", "detail": "…"}` | The transaction carries a rule payload but no rule effect was recorded for it in this block. It is reported as unmatched, in its own words -- never labelled a clause-registry rule. Clause-ness is never inferred from absence. |

A clause effect is annotated with `registry_confirmed`, a POSITIVE check
against `rule_clauses_v1`: true only when the registry actually holds that
account's clause on that stream with the stored body matching the effect's
sha256 (for a revoke, true when the registry no longer holds it). A false
says only "not in the registry now" -- a clause revoked since reads false
too -- and is never evidence the effect did not happen. A plain transaction
gets no `rule_outcome` at all.

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
| `fee_rules` | Every accumulated unit that writes the fee stream `o8`, whoever sent it, in the order the units joined — a fee rule of one account can change what another pays (#183). Each row carries the unit, its sha256, `sent_by` (the accounts whose rule transaction accumulated it, from this node's record of rule effects, or `null` where the node has none — a genesis unit, or one from before it began recording), `since` (the block and transaction that first brought it, or `null`), and `names_this_account`. `getrulesinforce` serves the same list from the current-tip accumulation. |
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

### At one block (`getrulesinforce`)

```bash
tau-testnet policy rules-in-force [<block>|<height>] [<address>]
tau-testnet rpc getrulesinforce [<block>|<height>] [<address>]
```

With no argument, the spec at the canonical head. With a block hash or a
height, the spec that was in force at that block: the journal is replayed
only up to the journal head the block's commit record names
(`block_commits_v1.journal_head`), and `spec_revision` comes from the same
record. The commit record is the anchor: a block with no commit record never
existed here (or this node has not synced it) and answers `code "NOT_FOUND"`;
a block whose record exists but whose journal rows are gone, or do not chain
to its head, was altered after commit and answers `code "TAMPERED"`. A
deletion is reported as tamper, never as "no commit record".

Two further guarantees, both tested in
`tests/test_rules_in_force_at_block.py`:

- **The cache is re-verified before it is served.** A cached text is served
  only after the journal rows behind its head are re-read and their hash
  chain re-verified on that read. A node that cached a head refuses the next
  read after the database is tampered, instead of serving the old text until
  a restart or a new head.
- **The replay is fingerprint-checked.** Each replayed revision is compared
  with the semantic fingerprint the original execution recorded
  (`tau_journal.compare`); a replay that computes something else diverges
  and the read reports unavailable instead of serving a text nobody
  committed. The same comparison the authoritative reconstruction runs with
  `verify=True`.

**Preview isolation.** The view is rebuilt in a fresh worker per rebuild and
disposed after the read. It never reads the node's warm evaluator and never
shares an evaluator with another read: the repo's own discriminator test
proves one shared evaluator contaminates across requests, so a shared
evaluator is not a permitted source for this view.

**Step rows.** The view replays rule rows only, never steps. A step row
forged without relinking its chain is caught by the chain verification
(`TAMPERED`, nothing shown). A step row forged with the chain relinked cannot
change the text this read answers, because steps are not inputs to it; the
divergence check that catches a relinked step forgery is the full
reconstruction's (`WorkerSession.reconstruct(..., verify=True)`, which
replays steps), run by the authoritative path at restart -- not by this read.

With an address, the account's registry clauses are added -- a positive
registry read only: a clause is listed because `rule_clauses_v1` holds it.
The registry and the application-rule units are current-tip state; at a
historical block they are labelled `registry_as_of: "current tip"`, because
no per-block registry snapshot exists. An `o5` clause names no revision.

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

## Operator notes

| Table | Written | Read by |
|---|---|---|
| `tx_outcomes (tx_hash, block_hash, …)` | per block, every node, apply and replay | `gettxstatus` |
| `rule_effects (account, block_hash, …)`, indexed by account | per block, every node | `getaccountrules` |

Both writes are best effort: a failure is logged and never reaches block commit.
Both tables are created on start (`CREATE TABLE IF NOT EXISTS`); there is no
migration. They grow with the chain; a full replay rewrites them idempotently.

`getaccountrules` and `getrulesinforce` are in the expensive rate-limit
tier: they take the state locks and scan the mempool and the history, and a
`getrulesinforce` read that rebuilds the spec starts one engine worker.

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
  restart. Light-client provability of the running-spec text is a documented
  follow-up (its own gated change), not part of this change.
- It does not verify step fingerprints in this read. See "Step rows" above:
  the view replays rule rows only; step verification belongs to the full
  reconstruction.
- It does not change which transactions are valid or what they cost. Soft no-ops
  (an offer that lost a race, a duplicate request) still sit in the block and
  pay their fee; they are now visible as `skipped` with their `fee_charged`.
