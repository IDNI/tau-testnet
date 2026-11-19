# Recipient controls

Until now a transfer was judged by exactly one account's `o5` policy: the
**sender's**. Recipient controls add the second evaluation — the **recipient's
own policy**, checked when a transfer is admitted and again when its block is
applied — so an account can refuse money arriving, and can cap how long a
payment to it may be held. Issues #47 (inbound allow-list) and #76 (maximum
hold time).

Two things follow from that one mechanism:

- **Inbound allow-list.** "Only let approved accounts pay me." A vendor lists
  its counterparties; anyone else is refused with a reason that names the
  recipient's policy, not the sender's.
- **Maximum hold time.** "Only accept payments I get straight away", or "held
  for up to ten minutes". A [retractable transfer](retractable.md) parks funds
  the sender can take back until a release point; a recipient at the point of
  sale needs "paid" to mean final, and a cap of 0 makes every park to it
  refused while plain transfers still pass.

Both live in the **same policy clause** as the account's outbound rules — one
`always ( ... ).` unit per account, judging both directions. An account that
deploys nothing is paid by everyone, as before (the neutral default).

Short reference: [README](../README.md#recipient-controls). Registration flow:
[developer_cli.md](developer_cli.md#transactions) and
[Policy guard](developer_cli.md#policy-guard). Activation mirrors the
co-signature slots: [approvals.md](approvals.md#activation).

## The stream contract

The recipient pass is fed the same per-transfer inputs as the sender pass, plus
two host-computed hold streams. `i3` carries the **sender's** full public key in
both passes: on your own outgoing transfers `i3` is you; on an incoming payment
`i3` is the counterparty. That is what makes an inbound allow-list a plain
comparison.

| Stream | Width | Meaning in the recipient pass |
|---|---|---|
| `i1` | `bv[24]` | transfer amount |
| `i3` | `bv[384]` | sender (counterparty) pubkey — the payer |
| `i4` | `bv[384]` | recipient pubkey — your own key here |
| `i17` | `bv[64]` | hold in **seconds** |
| `i27` | `bv[64]` | hold in **blocks** |
| `o5` | `bv[24]` | verdict: `0` blocks, `1` or absent allows |

The hold streams are fed from the payment itself, never from the sender:

| Payment | `i17` (seconds) | `i27` (blocks) |
|---|---|---|
| Plain transfer | `0` | `0` |
| Time park (`release_at_time`) | `max(0, release_at_time − block timestamp)` | `0` |
| Height park (`release_at_height`) | `0` | `max(0, release_at_height − block height)` |

Consequences worth internalizing:

- **A cap of 0 means instant only.** A plain transfer feeds 0 on both streams
  and passes; every park feeds a positive hold on one stream and is refused.
- **A cap rule bounds whichever stream it reads.** A seconds cap alone does not
  bound height parks (they feed `i17 = 0`); to refuse both park kinds, bound
  both streams. "Instant only" is `--max-hold-seconds 0 --max-hold-blocks 0`.
- **The node forces the hold values.** A sender-supplied `operations["17"]` or
  `operations["27"]` never reaches the recipient's clause. Once the chain is
  active, `i17`/`i27` join the reserved operation keys (write-reserved, like the
  approval slots), and every mention of them in a clause must be typed
  `bv[64]` — the same reject-unless-annotated width screen the slots use.

## Opt-in: which clauses are asked about incoming payments

A clause is evaluated on incoming payments **only when its comment-stripped
body reads `i3`, `i17` or `i27`**. A clause that reads none of them — a pure
outbound whitelist on `i4`, say — keeps its exact current meaning and is never
asked about money arriving. Deploying recipient controls therefore changes
nothing for pre-existing outbound policies, and an account with no clause (or
one that never writes `o5`) allows everything.

Reading `i3` opts you in even if you meant it for an outbound condition: the
screen is textual, and `i3` is the counterparty stream on the incoming pass.
Scope inbound conditions deliberately (see the combined unit below).

## Rule shapes

Every example is one `always ( ... ).` unit writing `o5` at `bv[24]`
(`{ #x000001 }` = allow, `{ #x000000 }` = block), with pubkeys as
`{ #x<96-hex> }:bv[384]` literals and holds as decimal `{ N }:bv[64]` literals.
The usual clause screens apply: no `i12`, `[t]` only, explicit widths, at most
32 comparisons and 8 KiB. The `policy receive` CLI composes these for you
([below](#composing-rules-with-the-cli)).

**Inbound allow-list — only A and B may pay me.** Because the same clause also
judges your own outgoing transfers (where `i3` is you), list your own key too
if you want to keep sending; the CLI adds it automatically when you pass
`--key`/`--privkey`.

```tau
always ( ( (i3[t]:bv[384] = { #x<OWNER> }:bv[384])
        || (i3[t]:bv[384] = { #x<A> }:bv[384])
        || (i3[t]:bv[384] = { #x<B> }:bv[384]) )
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

More senders are more `|| (i3[t]:bv[384] = { #x<KEY> }:bv[384])` terms, up to
the 32-comparison limit. An allow-list that omits your own key blocks your own
spending as well — that is the clause judging your outbound pass, not a bug.

**Instant only — no recall window on payments to me** (cap 0 on both streams):

```tau
always ( ( (i17[t]:bv[64] <= { 0 }:bv[64]) && (i27[t]:bv[64] <= { 0 }:bv[64]) )
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Held for at most 600 seconds** (bounds time parks; add the `i27` term to bound
height parks too):

```tau
always ( (i17[t]:bv[64] <= { 600 }:bv[64])
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Held for at most 10 blocks** (bounds height parks):

```tau
always ( (i27[t]:bv[64] <= { 10 }:bv[64])
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

The canonical `i17[t]:bv[64] <= { N }:bv[64]` comparison is what the node reads
to report your cap in a refusal (`max_hold_seconds=N`). A cap written in another
shape still **enforces** — the Tau verdict decides — but its refusal reports the
measured hold without a numeric cap.

**One unit for everything.** You pay only the shop, are paid only by A and B,
and take no payment held longer than 600 seconds or 10 blocks. Each conjunct
reads "if this is my own send (`i3` = me), skip; otherwise enforce", so the
inbound rules never touch your outgoing transfers:

```tau
always ( ( ( !(i3[t]:bv[384] = { #x<OWNER> }:bv[384]) || (i4[t]:bv[384] = { #x<SHOP> }:bv[384]) )
        && ( (i3[t]:bv[384] = { #x<OWNER> }:bv[384])
          || (i3[t]:bv[384] = { #x<A> }:bv[384])
          || (i3[t]:bv[384] = { #x<B> }:bv[384]) )
        && ( (i3[t]:bv[384] = { #x<OWNER> }:bv[384]) || (i17[t]:bv[64] <= { 600 }:bv[64]) )
        && ( (i3[t]:bv[384] = { #x<OWNER> }:bv[384]) || (i27[t]:bv[64] <= { 10 }:bv[64]) ) )
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

The first conjunct is the outbound whitelist (when you send, the recipient
`i4` must be the shop); the second is the inbound allow-list; the last two are
the hold caps, scoped to incoming payments. A payment from an account to itself
is judged on the sender pass only — the recipient pass skips self-transfers.

## How the hold is measured

Admission and apply measure the hold against **different clocks**, on purpose:

- **Admission** (`sendtx`, `checktx estimate`) measures against the tip view's
  `next_block_height` / `next_block_timestamp` — the same clock that already
  refuses a park which could be mined at or after its own release.
- **Apply** measures against the height and timestamp of the **block being
  applied** (the block that carries the park).

Both judge the cap on equal numbers for the block that decides. Admission is a
pre-check: a park sent at the edge of a cap can pass admission and be refused at
apply, or the reverse, by the seconds (or blocks) between the two clocks. The
block decides, and a refused park costs nothing (see [Fees](#fees)). Block
timestamps are proposer-chosen within the clock tolerance, so a time-based hold
can land up to about two minutes early — the same caveat as any time-based
release ([retractable.md](retractable.md#timing-caveats)).

## When the recipient is asked

| Payment | Asked? |
|---|---|
| Plain transfer (`user_tx`, operation `"1"`) | Yes — each output of a batch by its own recipient. One refused output fails the whole transaction; nothing applies in part. |
| Retractable transfer, when it parks | Yes, with the hold on `i17`/`i27`. |
| Co-signed transfer, when the last vote executes it | Yes, as a final payment (hold 0). If the recipient refuses, the request fails and nothing moves. |
| Creating an approval request | No — the request only parks an intent. |
| Retract of an open park | Never — the sender always gets the funds back. |
| Release of a matured park | No — it was judged when it parked; a later, tighter rule does not strand it. |
| Rule offers, rule changes, votes, faucet grants | No — not transfers. |

The recipient's clause is asked **after** every sender-side check (the consensus
rules and the sender's own clause), so a payment the sender may not make is
refused for the sender's reason. It is asked at mempool admission and again at
block apply, through one shared gate, so the two paths cannot drift and a replay
reaches the same verdicts.

## Refusals

At admission nothing is queued and nothing is charged. The error names the side
that refused, so a wallet can explain which policy said no:

| Code / reason | Raised when | `details` |
|---|---|---|
| `TX_REJECTED`, message `Transaction rejected by recipient policy (o5) for transfer #N (...)` | The recipient's clause blocks the payment (allow-list, amount, …). Receipt reason `recipient_policy_block`. | `transfer_index`, `recipient` |
| `RECIPIENT_MAX_HOLD` (receipt reason `recipient_max_hold`) | A park with hold > 0 is blocked by a clause reading a hold stream. | `transfer_index`, `recipient`, `max_hold_seconds` / `max_hold_blocks`, `hold_seconds` / `hold_blocks` |
| `RECIPIENT_POLICY_INACTIVE` | A clause reading `i17`/`i27` is deployed on a chain where the feature is not active — it would register and never be asked about incoming payments. | — |

`max_hold_seconds` / `max_hold_blocks` are read from the clause's canonical
comparisons (the most restrictive per stream wins; a strict `< N` reports
`N − 1`). A cap in a non-canonical shape still enforces, but the refusal then
carries the measured hold without a numeric cap.

**What a payer wallet should print.** On `recipient_policy_block`, say the
recipient's policy refused the payment (not yours). On `RECIPIENT_MAX_HOLD`,
print the cap and offer the fix, e.g. *"This recipient accepts payments held for
up to 600 seconds. Send it now instead."* — a cap of 0 means send a plain
transfer, not a park. The refusal carries the numbers; the wallet supplies the
sentence.

At block apply a refused transaction is a **hard reject**: it is excluded from
the block, no amount moves, **no fee is charged**, no sequence number is used,
and its staged writes never commit — exactly like a block by the sender's own
policy. The whole `user_tx` fails; a batch is never applied in part.

## Fees

- **Admission refusal costs nothing.** The transaction is not queued.
- **Apply refusal charges no fee.** The proposer filters the transaction out;
  the sender pays nothing, the same as a sender-side `o5` block. (This is the
  documented fee model for recipient blocks; a park refused at the cap is free
  to retry as a plain transfer.)
- A park that is **admitted and mined** pays its fee once at park time, as
  usual; the recipient gate does not change that. A later retract does not
  refund it ([retractable.md](retractable.md#money-flow)).

## Exemptions

- **Retract is never gated.** The sender can always take an open park back,
  whatever the recipient's cap.
- **A matured release is never re-checked.** The release sweep is a direct
  credit from the escrow book with no Tau evaluation, so a recipient who
  tightens its allow-list after a park was admitted cannot strand the payment.
- **Rule offers, rule-change requests, approval requests and votes are not
  transfers** and are not gated by the recipient's `o5`.
- **Approval-vote release is the exception that proves the rule:** when the last
  vote executes a co-signed transfer, the payment becomes final *now*, so the
  gate re-runs with hold 0 through the same shared closure. A recipient that
  refuses incoming payments can therefore still refuse a co-signed payment at
  the moment it executes; the request is marked failed and nothing moves.

## Composing rules with the CLI

`tau-testnet policy receive` composes the unit text and prints the command to
register it. It is pure text composition — no node connection, no signing — so
it works on any build. The clause goes to stdout (redirect it to a file); the
registration guide goes to stderr. `--json` emits both as one object.

```bash
# Inbound allow-list: only these senders may pay you. --key adds your own
# pubkey to the list so your outgoing transfers keep working.
tau-testnet policy receive allow-list --key bob <A_pubkey> <B_pubkey> > receive.tau

# Hold cap: at most 600 seconds and/or 10 blocks. 0 on a stream = instant only
# for that park kind; use both at 0 for "instant only" outright.
tau-testnet policy receive max-hold --max-hold-seconds 600 > receive.tau
tau-testnet policy receive max-hold --max-hold-seconds 0 --max-hold-blocks 0 > receive.tau

# One unit: outbound whitelist + inbound allow-list + caps, scoped by your key.
tau-testnet policy receive combined --key bob \
    --send-to <SHOP_pubkey> --allow-from <A_pubkey> --allow-from <B_pubkey> \
    --max-hold-seconds 600 --max-hold-blocks 10 > receive.tau
```

Register the clause like any `o5` policy rule — it **replaces** your current
clause, and an `o5` rule cannot share a transaction with transfers
(`RULE_WITH_TRANSFERS`):

```bash
tau-testnet tx send --key bob --rule-file receive.tau
```

If your policy is guarded, request the change through the co-signers instead:

```bash
tau-testnet policy change request --key bob --kind set --file receive.tau --approver 18=<xpub>
```

Revoke with the neutral clause
`always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) ).` (see
[approvals.md](approvals.md#removing-a-policy)). Changing or removing a policy
fails your open approval requests.

## Capability detection

`getgovernance` reports `recipient_policy_active` — the **chain** flag — beside
the existing governance fields, plus host capability flags saying this software
supports the gate. The chain flag is what a wallet must check before offering an
inbound rule:

```bash
tau-testnet --json governance | jq '.recipient_policy_active'
```

On a chain where it is `false`, a clause reading `i17`/`i27` is refused at deploy
with `RECIPIENT_POLICY_INACTIVE` rather than silently admitted to never run. A
clause reading only `i3` is not refused at deploy (statically it is
indistinguishable from a sender-pass clause), but the recipient pass only
enforces it once the chain flag is on — so check the flag, not just the deploy
result.

## Activation (operators)

`recipient_policy_active` is **consensus state, not a module flag**, handled
exactly like `approval_slots_active`: a one-way boolean on the lifecycle
manager, persisted, folded into the consensus metadata hash, exposed on the tip
admission view, and read from the *parent* snapshot — an activation recorded in
block *H* governs *H+1* onward and never changes the meaning of the block that
carried it. Only `True` is a legal patch value; a downgrade is refused.

**Collision audit first.** Before activation is accepted, the node audits the
complete effective spec — consensus rules, application accumulation, builtins
and stored clause bodies — for any mention of `i17`/`i27`. Before activation
those are ordinary custom streams, so a pre-existing rule may already use them;
reinterpreting it as a hold stream would change its meaning. Any collision
blocks activation with a loud reason. Grandfathered clauses already on chain
keep working until then, and **hold activation back until their owner replaces
or revokes them**.

Three ways to turn it on:

1. **Governance patch on a live chain.** Propose a `consensus_rule_update`
   carrying the rules in force unchanged as `rule_revisions` and the patch
   `{"recipient_policy_active": true}`:

   ```bash
   tau-testnet gov propose --key alice --file consensus_update.json
   tau-testnet gov vote --key alice --update-id <update_id>
   ```

   ```json
   {
     "rule_revisions": ["<the consensus rules currently in force>"],
     "activate_at_height": 100,
     "host_contract_patch": {"recipient_policy_active": true}
   }
   ```

   The audit runs at admission against the tip's effective spec and again at
   the activation height; a collision leaves the flag off rather than halting
   the chain. No restart and no regenesis.

2. **Fresh genesis.** `scripts/gen_genesis.py --recipient-policy-active` writes
   the lifecycle flag on from block 0 (the recommended path for a new network,
   mirroring `--approval-slots`).

3. The flag is one-way: once active it cannot be turned off, because clauses and
   reserved operation keys depend on it.

Every node must run a build that knows the flag before the update activates; an
older binary diverges at the first block that feeds the hold streams.

## Backward compatibility

- **Opt-in screen.** Only clauses reading `i3`/`i17`/`i27` are asked about
  incoming payments; outbound-only clauses keep their exact meaning.
- **Neutral default.** No clause, or a clause that never writes `o5`, allows
  everything — parks of any length included.
- **Grandfathering.** Custom `i17`/`i27` rules deployed before activation keep
  working and block activation until replaced; nothing is silently reinterpreted.
- **Same widths and `o5` typing as the sender side**, so one policy unit per
  account carries its outbound clauses, its inbound clauses and its cap.

## Not in this change

- A recipient cannot decline a retractable entry that is **already open** — the
  gate judges the park, not the open entry.
- No amount-based inbound cap helper; `i1` is readable, so "refuse incoming
  above N" is expressible by hand.
- The recipient pass does not read the payer's approval slots as votes for the
  recipient; a co-signed payment is judged final (hold 0) when it executes.
