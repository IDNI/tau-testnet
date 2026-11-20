# Recipient controls

An account's own `o5` policy rule can also judge the payments made **to** it.
Two things follow from that one mechanism:

- **Inbound allow-list.** The account accepts payments only from senders it has
  approved and refuses the rest.
- **Maximum hold time.** The account caps how long a retractable transfer to it
  may stay recallable. A cap of 0 means only payments that are final at once, so
  "paid" means final.

Both live in the same policy clause as the account's outbound rules. An account
that deploys nothing is paid by everyone, as before.

Short reference: [README](../README.md#recipient-controls). CLI summary:
[developer_cli.md](developer_cli.md#recipient-controls).

## The receive stream, `i17`

The node feeds one input, `i17` (`bv[64]`), that tells a clause which side of a
payment it is judging:

| `i17` | The clause is judging |
|---|---|
| `0` | a payment its owner **sends**. Also what any path that does not feed the stream reads. |
| `1` | an incoming payment that is **final in this block**: a transfer, or a co-signed transfer that executes. |
| `1 + N` | an incoming retractable transfer that releases **N seconds** after the block's timestamp. The sender can take it back for those N seconds. |
| `1000000000000000000 + N` | an incoming retractable transfer that releases at a **block height**, **N blocks** after the block that parks it. A length in blocks is not a length in seconds, so it has a range of its own (10^18 and up), above every length in seconds. |

A clause that reads `i17` is evaluated a second time for every payment whose
recipient is its owner. A clause that does not read `i17` is never asked about
incoming payments, so every clause written before the feature keeps its meaning.

Only the node writes `i17`: from activation on, `"17"` is a reserved operation
key, and no rule other than a registered `o5` clause may read the stream. Every
mention in a clause must be written `i17[t]:bv[64]`.

## Writing a rule

Deploy these like any `o5` policy rule (`tau-testnet tx send --key bob
--rule-file policy.tau`); revoke with the neutral clause.

**Only Alice may pay me** (what I send is not restricted):

```
always ( ( (i17[t]:bv[64] = { 0 }:bv[64]) || (i3[t]:bv[384] = { #x<ALICE> }:bv[384]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

More senders are more `|| (i3[t]:bv[384] = { #x<KEY> }:bv[384])` terms. The
clause limits apply (32 comparisons, 8 KiB).

**Instant only** (no recall window):

```
always ( (i17[t]:bv[64] > { 1 }:bv[64])
         ? (o5[t]:bv[24] = { #x000000 }:bv[24])
         : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

**Held for 600 seconds at most:** the same rule with `{ 601 }`. A cap of N
seconds is `i17 > { N + 1 }`. A rule like this, written in seconds alone, takes
no height release at all, because every length in blocks reads above it.

**Held for 600 seconds, or released at most 100 blocks ahead.** A rule that
takes height releases names its cap in blocks as well. The number of blocks is
the end of the second literal:

```
always ( ( ( (i17[t]:bv[64] > { 601 }:bv[64]) && (i17[t]:bv[64] < { 1000000000000000000 }:bv[64]) )
        || (i17[t]:bv[64] > { 1000000000000000100 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000000 }:bv[24])
         : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

Height releases only, 5 blocks at most: the same rule with `{ 1 }` in place of
`{ 601 }` and `{ 1000000000000000005 }` at the end.

**One unit for everything.** Bob pays only the shop, is paid only by Alice, and
takes no payment held longer than 10 minutes:

```
always ( ( ( (i17[t]:bv[64] = { 0 }:bv[64]) && !(i4[t]:bv[384] = { #x<SHOP> }:bv[384]) )
        || ( !(i17[t]:bv[64] = { 0 }:bv[64]) && !(i3[t]:bv[384] = { #x<ALICE> }:bv[384]) )
        || (i17[t]:bv[64] > { 601 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000000 }:bv[24])
         : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

**Only with a reference.** A payment to me must carry a nonzero custom input
`i30`, which the payer sends as `"30": "4711"` beside the transfer in
`operations`:

```
always ( ( !(i17[t]:bv[64] = { 0 }:bv[64]) && (i30[t]:bv[24] = { #x000000 }:bv[24]) )
         ? (o5[t]:bv[24] = { #x000000 }:bv[24])
         : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

The rule can read everything a sender-side clause reads, about the same payment:
`i1` (amount), `i3` (the payer), `i4` (the recipient, its owner here), `i5`
(block timestamp), `i2` (the **payer's** balance at the parent block). The
approval slots `i18`–`i25` read `0` on the recipient's side: the payer's
co-signers did not vote for the recipient. Custom inputs the payer attached to
the transaction arrive on their own streams, so a recipient can ask for one (a
reference number on `i30`, say) and refuse a payment that comes without it.

So scope every outbound condition with `i17 = 0`, as the examples do: a balance
floor written for the owner's own spending would otherwise be judged against the
payer's balance. A payment from an account to itself is judged on both sides
like any other, so an allow-list that does not name its owner refuses it.

## When the recipient is asked

| Payment | Asked? |
|---|---|
| Transfer (`user_tx`, operation `"1"`) | Yes, each transfer of a batch by its own recipient. One refusal fails the whole transaction; nothing is applied in part. |
| Retractable transfer, when it parks | Yes, with the hold on `i17`. |
| Co-signed transfer, when the last vote executes it | Yes, as a final payment. If the recipient refuses, the request is marked failed, the vote stands, and nothing moves. |
| Creating an approval request | No. The request only parks an intent. |
| Retract of an open retractable transfer | Never. The sender always gets the funds back. |
| Release of a retractable transfer | No. It was judged when it parked, and a later, tighter rule does not strand it. |
| Rule offers, fees to the proposer, faucet grants | No. |

The recipient's clause is asked **after** every check on the sender's side (the
consensus rules, the sender's own clause), so a payment the sender may not make
is refused for the sender's reason. It is asked at mempool admission and again
at block apply, on the same inputs the sender's side was judged on.

## Refusal

At admission (`sendtx`, `checktx estimate`) nothing is queued and nothing is
charged:

| Code | Meaning | `details` |
|---|---|---|
| `RECIPIENT_POLICY` | The recipient's rule does not accept this payment. Message: `Transaction rejected by recipient policy (o5) ...`. | `transfer_index`, `recipient` |
| `RECIPIENT_MAX_HOLD` | The recipient would accept the payment with a shorter hold. The message carries the cap in the park's own unit (`max_hold_seconds=N` or `max_hold_blocks=N`). | `transfer_index`, `recipient`, and for a time-based release `max_hold_seconds` and `hold_seconds`, for a height-based one `max_hold_blocks` and `hold_blocks` |
| `RECIPIENT_POLICY_INACTIVE` | A rule that reads `i17` was submitted on a chain where the feature is not active. It would register and never be asked, so the node refuses it at deploy. | |

The cap is found by asking the recipient's clause about shorter holds, at
admission only, by bisection: the reported cap was accepted and the next longer
hold was refused, by the clause itself. `0` means the recipient accepts only
payments that are final at once. A height release sent to a recipient whose rule
takes none is told both: `max_hold_blocks=0` and the cap in seconds a timed
release must respect.

A refusal costs the payer nothing, so the node bounds what one costs it: the
verdict is one evaluation, and working out the cap (about 27 evaluations at
most) gets one more admission budget in total. If that runs out, the park is
still refused, as `RECIPIENT_POLICY`, and the message points to
`getrecipientpolicy` for the cap.

At block apply a refused transaction is **not included** in the block: no
amount moves, **no fee is charged** and no sequence number is used, exactly like
a block by the sender's own policy. The receipt reason is
`recipient_policy_block`.

If the engine cannot evaluate the recipient's clause for a payment, the payment
is refused, as on the sender's side, so every node reaches the same result.

## The hold length

The hold is counted in the park's own unit: **seconds** for `release_at_time`,
**blocks** for `release_at_height`.

- At block apply it is `release_at_time` minus the timestamp of the block that
  carries the park, or `release_at_height` minus that block's height.
- At admission it is `release_at_time` minus the node's estimate of the next
  block's timestamp, or `release_at_height` minus the height of the next block.
  Those are the clock and the height admission already uses for `i5` and to
  refuse a park that could be mined at or after its release.
- The two units are never converted into each other: a chain can stand still
  between blocks, so a number of blocks is not a number of seconds. A rule with
  a cap in seconds alone refuses every height release, and the refusal says to
  use `release_at_time`. A rule that takes height releases says how many blocks.

Admission is a pre-check. A hold in blocks only gets shorter by the time the
park is mined, so a height release admitted under a cap stays under it. A timed
park sent at the edge of a cap can pass admission and be refused at apply, or
the reverse, by the seconds between the two clocks. The block decides, and a
refused park costs nothing.

## Asking a node

```bash
tau-testnet governance                          # "recipient_policy_active": true|false
tau-testnet policy receive <address>
tau-testnet policy receive <address> --from <sender_pubkey> --amount 25
```

`getrecipientpolicy <address> [<sender> <amount>]` returns:

| Field | Meaning |
|---|---|
| `active` | Whether the feature is active at the tip (consensus state). |
| `receive_stream`, `receive_stream_width` | `i17`, `64`. |
| `has_clause` | The address has a registered `o5` clause. |
| `judges_incoming` | The feature is active and the address's clause reads `i17`: payments to it are also judged by its own rule. |
| `clause` | The clause text when it reads `i17`. |
| `probe` | Only with `<sender> <amount>`: `accepts_payment`, `max_hold_seconds` (`null` = no cap inside the 90-day park window), `max_hold_blocks` (`null` = no cap inside the 100,000-block window, `0` = no height release), `accepts_height_release`. |

The probe is advisory: a clause may read the clock and the payer's balance, so
admission and apply decide. It counts as an expensive command for rate limiting,
and everything one probe asks the clause shares one admission budget.

## Activation

`recipient_policy_active` is consensus state, handled like
`approval_slots_active`: a one-way flag on the lifecycle manager, persisted,
folded into the consensus metadata hash only once it is true (a chain that never
activates it hashes exactly as before), and read from the parent snapshot, so an
activation recorded in block *H* governs *H+1* onward.

- **Existing chain:** a governance update with
  `"host_contract_patch": {"recipient_policy_active": true}`. No restart and no
  regenesis. Like every `consensus_rule_update`, it carries the full consensus
  spec, so send the rules in force unchanged as `rule_revisions`
  (`getgovernance` returns them as `consensus_rules`); only the patch is new.
  `scripts/e2e_recipient_controls.py` does exactly this on a running chain.
- **Fresh chain:** `scripts/gen_genesis.py --recipient-policy`.

Before activation `i17` is an ordinary custom stream, so activation is audited
in two phases like the approval slots. The proposal is refused at admission
when any rule in force (consensus rules, built-ins, application rules, a
registered clause) already mentions `i17`, and at the activation height the same
audit leaves the flag off rather than halting the chain. Replace or revoke the
rule and propose again.

Until the flag is set, block apply is unchanged, and admission refuses a clause
that reads `i17` with `RECIPIENT_POLICY_INACTIVE`. So from this release on `i17`
is no longer available as a custom input for a new clause; use any free stream
from `i26` up. A clause registered earlier that uses `i17` keeps working until
the activation, and holds the activation back until its owner replaces it.
Every node must run a build that knows the flag before the update activates.

Between approval and activation, `getgovernance` lists the update under
`scheduled_updates` with a `precheck` field. It turns to `fail` with the reason
when a rule that mentions `i17` arrived after the proposal was admitted, which
is the warning that the activation will leave the flag off.

## Not in this change

- Rule offers and the creation of approval requests are not judged by the
  recipient.
- A recipient cannot decline a retractable transfer that is already open.
- The legacy path for chains without the fee model enforces no clause on either
  side.
