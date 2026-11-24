# Recipient controls

An account's own `o5` policy rule can also judge the payments made **to** it.
The node describes every incoming payment on six node-fed inputs, the *receive
record*, so that each condition of the receiver is one comparison in its rule:

- **Who may pay.** Only senders the account has listed; the rest are refused.
- **How long a payment may be held.** A bound on the time until all of it is
  within the receiver's reach, down to "final at once", so "paid" means final.
- **How long the sender may take it back.** A bound on the recall window.
- **Spending limits.** A limit on a payment must leave the receiver a minimum
  allowance, or there must be none.
- **Refunds.** Nothing may go back to the sender by itself before a given time,
  or ever.

All of them live in the same policy clause as the account's outbound rules, and
`tau-testnet policy receive-rule` writes that clause from the numbers. An
account that deploys nothing is paid by everyone, as before.

Short reference: [README](../README.md#recipient-controls). CLI summary:
[developer_cli.md](developer_cli.md#recipient-controls).

## The receive record

Six inputs, each `bv[64]`:

| Input | What the receiver's clause reads |
|---|---|
| `i17` | The kind of payment. `0`: a payment its owner **sends**. `1`: an incoming payment that is final and spendable at once. `2`: an incoming payment with conditions on block **time**; every length below is in seconds. `3`: the same on block **height**; every length below is in blocks. |
| `i50` | Hold: how long until all of the payment is within the receiver's reach. `0` when final. |
| `i51` | Recall: how long the sender can still take it back. `0` when it cannot. |
| `i52`, `i53` | Spending limit: at most `i52` per period of `i53`. Both `0` without a limit. |
| `i54` | Refund: how long until the earliest moment any of it can go back to the sender by itself. |

The largest value of a stream, `18446744073709551615`, stands for "never"
(`i54`) and "without end" (`i50`, `i51`).

What the node puts there:

| Payment | `i17` | `i50` hold | `i51` recall | `i52` per `i53` | `i54` refund |
|---|---|---|---|---|---|
| A transfer, each transfer of a batch, a co-signed transfer when its last vote executes it | `1` | `0` | `0` | `0`, `0` | never |
| A retractable transfer when it parks, released at a time | `2` | seconds from the block's timestamp to `release_at_time` | the same | `0`, `0` | never |
| A retractable transfer when it parks, released at a height | `3` | blocks from the block's height to `release_at_height` | the same | `0`, `0` | never |

Until its release a retractable transfer is not within the receiver's reach, and
the sender can take it back for exactly that long, so its hold and its recall
window are the same number. No payment carries a spending limit or a refund
today: `i52` to `i54` are part of the record so that a payment type which has
them describes them the same way, and `getrecipientpolicy` already answers for
them.

For a payment its owner sends, a clause reads `0` on all six inputs. That is
also what any path that does not feed the record reads, so the receive part of a
clause never fires by accident.

A clause that reads any input of the record is evaluated a second time for every
payment whose recipient is its owner. A clause that reads none of them is never
asked about incoming payments, so every clause written before the feature keeps
its meaning.

Only the node writes the record: from activation on, `"17"` and `"50"` to `"54"`
are reserved operation keys, and no rule other than a registered `o5` clause may
read the six streams. Every mention in a clause must be typed `bv[64]`, as in
`i50[t]:bv[64]`.

**Ceilings.** A spending limit is at most 16,777,215 per period, and a period at
most 31,622,400 seconds (366 days) or 1,000,000 blocks. A payment whose terms
lie above them is refused before the receiver's clause is asked. So a rule that
rounds a period up to its own, as the allowance rule below does with
`(i53 + 604799) / 604800`, cannot wrap.

## Writing a rule

`tau-testnet policy receive-rule` writes the rule from numbers and prints it
(`--out FILE` writes it to a file). Nothing is sent. Deploy the rule like any
`o5` policy rule (`tau-testnet tx send --key bob --rule-file policy.tau`);
revoke it with the neutral clause.

A length is a number of seconds (`600`), `10m`, `2h`, `30d`, `1w`, or a number
of blocks (`100b`).

**Only Alice may pay me** (what I send is not restricted). More senders are more
`--only-from`:

```
$ tau-testnet policy receive-rule --only-from <ALICE>
always ( ( (i17[t]:bv[64] = { 0 }:bv[64]) || (i3[t]:bv[384] = { #x<ALICE> }:bv[384]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Final at once only** (nothing held, nothing the sender can take back):

```
$ tau-testnet policy receive-rule --final-only
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Held for 30 days at most, open to a recall for an hour at most:**

```
$ tau-testnet policy receive-rule --max-hold 30d --max-recall 1h
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
         || ( (i17[t]:bv[64] = { 2 }:bv[64])
            && (i50[t]:bv[64] <= { 2592000 }:bv[64])
            && (i51[t]:bv[64] <= { 3600 }:bv[64]) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Held for 10 minutes, or released at most 100 blocks ahead.** A number is given
once per clock:

```
$ tau-testnet policy receive-rule --max-hold 10m --max-hold 100b
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
         || ( (i17[t]:bv[64] = { 2 }:bv[64]) && (i50[t]:bv[64] <= { 600 }:bv[64]) )
         || ( (i17[t]:bv[64] = { 3 }:bv[64]) && (i50[t]:bv[64] <= { 100 }:bv[64]) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**A spending limit must leave me 500 a week** (a payment without a limit
passes):

```
$ tau-testnet policy receive-rule --min-allowance 500 --per 1w
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
         || (i53[t]:bv[64] = { 0 }:bv[64])
         || ( (i17[t]:bv[64] = { 2 }:bv[64])
            && (i52[t]:bv[64] >= ({ 500 }:bv[64] * ((i53[t]:bv[64] + { 604799 }:bv[64]) / { 604800 }:bv[64]))) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**No spending limits:**

```
$ tau-testnet policy receive-rule --no-limits
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64]) || (i53[t]:bv[64] = { 0 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Nothing goes back to the sender by itself within 90 days:**

```
$ tau-testnet policy receive-rule --min-refund 90d
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
         || ( (i17[t]:bv[64] = { 2 }:bv[64]) && (i54[t]:bv[64] >= { 7776000 }:bv[64]) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**No refunds:**

```
$ tau-testnet policy receive-rule --no-refunds
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
         || (i54[t]:bv[64] = { 18446744073709551615 }:bv[64]) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**All of it in one rule.** Every condition must hold; one that fails refuses the
payment:

```
$ tau-testnet policy receive-rule --only-from <ALICE> --max-hold 30d --max-recall 1h --min-allowance 500 --per 1w --min-refund 90d
always ( ( (i17[t]:bv[64] = { 0 }:bv[64])
         || ( (i3[t]:bv[384] = { #x<ALICE> }:bv[384])
            && ( (i17[t]:bv[64] = { 1 }:bv[64])
               || ( (i17[t]:bv[64] = { 2 }:bv[64])
                  && (i50[t]:bv[64] <= { 2592000 }:bv[64])
                  && (i51[t]:bv[64] <= { 3600 }:bv[64])
                  && ( (i53[t]:bv[64] = { 0 }:bv[64])
                     || (i52[t]:bv[64] >= ({ 500 }:bv[64] * ((i53[t]:bv[64] + { 604799 }:bv[64]) / { 604800 }:bv[64]))) )
                  && (i54[t]:bv[64] >= { 7776000 }:bv[64]) ) ) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

What the writer holds to:

- **What the owner sends is never restricted** by a rule it writes: `i17 = 0`
  always passes.
- **Seconds and blocks are never converted.** A chain can stand still between
  blocks, so a number of blocks is not a number of seconds. A rule with numbers
  for one clock alone accepts no payment with conditions on the other clock, and
  a retractable transfer released at a height is told to use `release_at_time`.
  A rule with no number on either clock (`--only-from`, `--no-limits`,
  `--no-refunds`) accepts both.
- **A minimum allowance alone** is the one case to know: a payment without a
  spending limit carries nothing the rule could refuse, so it passes on either
  clock. A payment with a limit passes only on the clock the allowance names.
- **Numbers that contradict each other are refused with the reason**
  (`--final-only` with any other condition, `--no-limits` with
  `--min-allowance`, `--no-refunds` with `--min-refund`, an allowance without
  its period), and so is a rule that would not register: the clause limits
  apply (32 comparisons, 8 KiB), which is 29 listed senders for a rule with no
  other condition.

### How a spending limit is compared

A payment may carry a limit of `C` per period `P`. The receiver asks for at
least `X` per stretch `W`. The written rule accepts the limit when

```
C >= X * ceil(P / W)
```

This is the strict reading: a receiver who spends `X` in every stretch `W` is
never stopped by the limit. With 500 a week, a limit over 30 days must be 2,500,
because five weeks begin within 30 days; 2,000 per 30 days is refused. In the
rule the rounding is `(i53 + (W - 1)) / W`.

`--average` compares averages instead, `C * W >= X * P`:

```
$ tau-testnet policy receive-rule --min-allowance 500 --per 1w --average
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
         || (i53[t]:bv[64] = { 0 }:bv[64])
         || ( (i17[t]:bv[64] = { 2 }:bv[64])
            && ((i52[t]:bv[64] * { 604800 }:bv[64]) >= ({ 500 }:bv[64] * i53[t]:bv[64])) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

Then 2,143 per 30 days is enough for 500 a week. Which comparison applies is the
receiver's choice; the record carries `C` and `P` either way.

### By hand

What the writer prints is an ordinary `o5` clause. A receiver is free to write
another, and the node treats both the same.

**One unit for everything.** Bob pays only the shop, is paid only by Alice, and
takes no payment held longer than 10 minutes:

```
always ( ( ( (i17[t]:bv[64] = { 0 }:bv[64]) && (i4[t]:bv[384] = { #x<SHOP> }:bv[384]) )
         || ( (i3[t]:bv[384] = { #x<ALICE> }:bv[384])
            && ( (i17[t]:bv[64] = { 1 }:bv[64])
               || ( (i17[t]:bv[64] = { 2 }:bv[64]) && (i50[t]:bv[64] <= { 600 }:bv[64]) ) ) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Only with a reference.** A payment to me must carry a nonzero custom input
`i30`, which the payer sends as `"30": "4711"` beside the transfer in
`operations`:

```
always ( ( !(i17[t]:bv[64] = { 0 }:bv[64]) && (i30[t]:bv[24] = { #x000000 }:bv[24]) )
         ? (o5[t]:bv[24] = { #x000000 }:bv[24])
         : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

**Two conditions tied together.** The hold and the recall window may add up to
an hour:

```
always ( ( (i17[t]:bv[64] <= { 1 }:bv[64])
         || ( (i17[t]:bv[64] = { 2 }:bv[64])
            && (i50[t]:bv[64] <= { 3600 }:bv[64])
            && (i51[t]:bv[64] <= { 3600 }:bv[64])
            && ((i50[t]:bv[64] + i51[t]:bv[64]) <= { 3600 }:bv[64]) ) )
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
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
like any other, so a sender list that does not name its owner refuses it.

## When the recipient is asked

| Payment | Asked? |
|---|---|
| Transfer (`user_tx`, operation `"1"`) | Yes, each transfer of a batch by its own recipient. One refusal fails the whole transaction; nothing is applied in part. |
| Retractable transfer, when it parks | Yes, with its hold and its recall window on the record. |
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

The verdict is one evaluation of the recipient's clause on the whole record. At
admission (`sendtx`, `checktx estimate`) nothing is queued and nothing is
charged, and the refusal names the condition that failed:

| Code | The recipient's rule does not accept | `details` beside `transfer_index`, `recipient`, `condition` |
|---|---|---|
| `RECIPIENT_SENDER` | a payment from this sender, whatever its terms. Also the code when a rule refuses for something the record does not describe, such as the amount or a missing reference. | |
| `RECIPIENT_HOLD` | the hold of this payment. | The hold asked for (`hold_seconds` or `hold_blocks`) and the longest the rule accepts (`max_hold_seconds` or `max_hold_blocks`). |
| `RECIPIENT_RECALL` | the recall window of this payment. | `recall_seconds` or `recall_blocks`, and `max_recall_seconds` or `max_recall_blocks`. |
| `RECIPIENT_LIMIT` | the spending limit on this payment. Also a payment whose limit lies above the ceilings of the record; then the rule was not asked. | |
| `RECIPIENT_REFUND` | the refund terms of this payment. | |
| `RECIPIENT_COMBINED` | this payment's conditions together, while it accepts each of them alone. | |
| `RECIPIENT_POLICY` | this payment, and the node could not work out which condition in time. `getrecipientpolicy` reports it. | |
| `RECIPIENT_POLICY_INACTIVE` | (at deploy) A rule that reads the record was submitted on a chain where the feature is not active. It would register and never be asked, so the node refuses it. | |

`condition` is `sender`, `hold`, `recall`, `limit`, `refund` or `combined`. The
message starts `Transaction rejected by recipient policy (o5)` and carries the
bound in words a wallet can show, for example `the recipient accepts a payment
held for at most 600 seconds (max_hold_seconds=600); this one would be held for
3599 seconds`.

**How the condition is found.** The node asks the clause again, with every other
condition at its most permissive value: first as a payment that is final at once
(refused even then: the sender), then with the hold alone, the recall window
alone, the limit alone, the refund alone. The first one the clause refuses on
its own is named; when it refuses none of them alone, the combination. That is
five evaluations at most. A sender the recipient does not accept learns that and
nothing of the recipient's other terms.

**How the bound is found.** For a hold or a recall window the node also looks
for the longest one the clause accepts in the payment's own unit, by bisection:
the reported bound was accepted and the next longer one refused, by the clause
itself (24 evaluations at most in seconds, 18 in blocks). `0` means the rule
accepts nothing of the kind on that clock. A height release sent to a recipient
whose rule takes none is told both, `max_hold_blocks=0` and the bound in seconds
a timed release must respect. A clause need not be monotone in a length; then
the bound is one boundary of several, and still true as stated: the length it
names is accepted and the next longer one is refused.

A refusal costs the payer nothing, so the node bounds what one costs it: naming
the condition and the bound together get one more admission budget and no more.
If that runs out the payment is still refused: as `RECIPIENT_POLICY` when the
condition is not known yet, otherwise with the condition's code and without the
bound. The message points to `getrecipientpolicy`.

At block apply a refused transaction is **not included** in the block: no
amount moves, **no fee is charged** and no sequence number is used, exactly like
a block by the sender's own policy. The receipt reason is
`recipient_policy_block`. The verdict stays one evaluation there, so the block
does not name the condition. `gettxstatus` shows the payment's terms as the rule
was asked (`asked as: seconds hold=1800 recall=1800`, or `final at once`), and
`getrecipientpolicy` with those terms names it.

If the engine cannot evaluate the recipient's clause for a payment, the payment
is refused, as on the sender's side, so every node reaches the same result.

## How the lengths are measured

A length is counted on the payment's own clock: **seconds** for
`release_at_time`, **blocks** for `release_at_height`.

- At block apply it is `release_at_time` minus the timestamp of the block that
  carries the park, or `release_at_height` minus that block's height.
- At admission it is `release_at_time` minus the node's estimate of the next
  block's timestamp, or `release_at_height` minus the height of the next block.
  Those are the clock and the height admission already uses for `i5` and to
  refuse a park that could be mined at or after its release.
- The two clocks are never converted into each other. A rule with a bound in
  seconds alone refuses every height release, and the refusal says to use
  `release_at_time`. A rule that takes height releases says how many blocks.

Admission is a pre-check on the node's estimate of the next block. A length in
blocks only gets shorter by the time the park is mined, so a height release
admitted under a bound stays under it. A timed park sent at the edge of a bound
can pass admission and be refused at apply, or the reverse, by the seconds
between the two clocks. The block decides, and a refused park costs nothing.

## Asking a node

```bash
tau-testnet governance                          # "recipient_policy_active": true|false
tau-testnet policy receive <address>
tau-testnet policy receive <address> --from <sender_pubkey> --amount 25
tau-testnet policy receive <address> --from <sender_pubkey> --amount 25 --park 2h
tau-testnet policy receive <address> --from <sender_pubkey> --amount 25 \
    --hold 30d --recall 1h --limit 2000 --period 30d --refund 90d
```

`getrecipientpolicy <address> [<sender> <amount> [<terms>]]` with
`<terms> = seconds|blocks [park=N] [hold=N] [recall=N] [limit=N period=N]
[refund=N|never]`. Without terms it asks about a payment that is final at once.
`park=N` is a retractable transfer released N seconds (or blocks) from now: held
for N and open to a recall for N. It returns:

| Field | Meaning |
|---|---|
| `active` | Whether the feature is active at the tip (consensus state). |
| `receive_record`, `receive_stream_width` | `["i17", "i50", "i51", "i52", "i53", "i54"]`, `64`. `receive_stream` is `i17`. |
| `has_clause` | The address has a registered `o5` clause. |
| `judges_incoming` | The feature is active and the address's clause reads the record: payments to it are also judged by its own rule. |
| `clause` | The clause text when it reads the record. |
| `probe` | Only with `<sender> <amount>`. `record`: the record the clause was asked with (`refund` is `null` for never). `accepts_payment`. `refused_condition` and `code`: what a payment with these terms would be told at admission. `max_hold_seconds`, `max_hold_blocks`, `max_recall_seconds`, `max_recall_blocks`: the longest hold and recall window the rule accepts, each with every other condition at its most permissive value (`null` = no bound inside the 90-day or 100,000-block park window, `0` = nothing of the kind on that clock). `accepts_height_release`. A sender the rule refuses gets no bounds. |

The probe is advisory: a clause may read the clock and the payer's balance, so
admission and apply decide. It counts as an expensive command for rate limiting,
and everything one probe asks the clause shares one admission budget. Terms
above the ceilings of the record are refused as `INVALID_PARAMS`.

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

Before activation `i17` and `i50` to `i54` are ordinary custom streams, so
activation is audited in two phases like the approval slots. The proposal is
refused at admission when any rule in force (consensus rules, built-ins,
application rules, a registered clause) already mentions one of the six, and at
the activation height the same audit leaves the flag off rather than halting the
chain. Replace or revoke the rule and propose again.

Until the flag is set, block apply is unchanged, and admission refuses a clause
that reads the record with `RECIPIENT_POLICY_INACTIVE`. So from this release on
`i17` and `i50` to `i54` are no longer available as custom inputs for a new
clause; use any other free stream from `i26` up. A clause registered earlier
that uses one of them keeps working until the activation, and holds the
activation back until its owner replaces it. Every node must run a build that
knows the flag before the update activates.

Between approval and activation, `getgovernance` lists the update under
`scheduled_updates` with a `precheck` field. It turns to `fail` with the reason
when a rule that mentions the record arrived after the proposal was admitted,
which is the warning that the activation will leave the flag off.

## Not in this change

- No payment type sets a spending limit or a refund on the record yet (see "The
  receive record").
- Rule offers and the creation of approval requests are not judged by the
  recipient.
- A recipient cannot decline a retractable transfer that is already open.
- The legacy path for chains without the fee model enforces no clause on either
  side.
