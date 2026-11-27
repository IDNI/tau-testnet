# Recipient controls

Until now a transfer was judged by exactly one account's `o5` policy: the
sender's. Recipient controls add the second evaluation — the
**recipient's own policy**, checked when a transfer is admitted and again
when its block is applied — so an account can refuse money arriving, and
can cap how long a payment to it may be held. Issues #47 and #76.

The gate lives in `consensus/recipient_policy.py`; admission
(`commands/sendtx.py`) and apply (`consensus/engine.py`) call it with the
same inputs, so the two paths cannot drift apart, and a replay reaches
the same verdicts.

## What a recipient rule can say

A recipient rule is an ordinary `o5` clause (or guarded unit, below). It
is evaluated on the same per-transfer inputs as the sender pass — `i1`
amount, `i2` sender balance, `i3` sender key, `i4` recipient key, `i5`
timestamp, approval slots, custom streams — with the direction visible
from the streams: **`i3` carries the sender's full public key**, so an
inbound allow-list is a plain comparison on `i3`:

```
# allow incoming only from A (anyone else is refused)
always ( (i3[t]:bv[384] = { #x<A> }:bv[384])
  ? (o5[t]:bv[24] = { #x000001 }:bv[24])
  : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

"Refuse incoming above N" is the same shape with a comparison on `i1`.

**Opt-in.** The recipient pass enforces only clauses whose body reads
`i3` or a hold stream (below). A clause that reads neither — a pure
outbound whitelist on `i4`, say — keeps its outbound meaning and never
starts blocking inbound transfers, so deploying recipient controls
changes nothing for pre-existing policies. A recipient with no clause
allows everything: the neutral default, as on the sender side.

**Guarded mode.** The accumulated spec is also stepped a second time
with `i12` — the policy-owner stream every guarded unit scopes on — set
to the recipient's key. The recipient's guarded unit is then the one
that can say no, exactly as the sender's unit does in the first pass;
the counterparty stays readable on `i3`. A missing `o5` in that pass is
the neutral default. The pass steps only when the recipient's key
appears in the current spec text: a guarded unit scopes on its owner's
key as a literal, so absence proves there is no unit to enforce — and
an extra step is not free, since history-reading rules observe every
step the shared session takes.

## Refusals

A recipient block rejects the whole transaction (a batch with one
refused output applies nothing), with a reason that names the side that
refused, so a wallet can explain which policy said no:

| Where | Signal |
|---|---|
| Admission | `TX_REJECTED`, "rejected by recipient policy (o5)" |
| Receipt (`gettxstatus`) | `reason: "recipient_policy_block"`, with the refusal in `logs` |

Fees are unchanged: an admission refusal costs nothing; at apply the
sender pays the transaction fee exactly as for a sender-policy block.

## Hold caps for retractable transfers (#76)

A recipient can also cap how long a payment to it may sit in escrow.
Two host-computed streams carry the park's hold length into the
recipient pass:

| Stream | Meaning |
|---|---|
| `i17` | Hold in **seconds**: `release_at_time` minus the block time |
| `i27` | Hold in **blocks**: `release_at_height` minus the block height |

Both are `bv[64]`. A plain transfer feeds 0 on both, so **a cap of 0
admits plain transfers and refuses every park**; a park of one kind
feeds 0 on the other kind's stream, so a cap rule must bound both
streams to bound both kinds:

```
# never hold a payment to me longer than 600 seconds
always ( (i17[t]:bv[64] <= { #x258 }:bv[64])
  ? (o5[t]:bv[24] = { #x000001 }:bv[24])
  : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

Admission measures the hold against the tip view's next-block
height/timestamp — the same clock that refuses a park which could be
mined at or after its own release — and apply measures it against the
block being applied, so both judge the cap on equal numbers. The values
are forced by the node: a sender-supplied value on `i17`/`i27` never
reaches the recipient's clause.

A park refused by a hold cap carries the distinct reason
**`RECIPIENT_MAX_HOLD`**, at admission in the error text and in the
receipt as `reason: "recipient_max_hold"` with
`recipient_max_hold_seconds` / `recipient_max_hold_blocks` fields, so
the payer's wallet can print "this recipient accepts payments held for
up to N". The cap is read from the clause's canonical comparisons (a
hold stream compared against a literal, `<=`, `<`, or the reversed
forms; the most restrictive wins). A cap written in another shape still
enforces — the Tau verdict decides — but its refusal reports the
measured hold without a numeric cap.

Only parks are capped. A **retract** never passes this gate, and a
**release** is not re-checked: at release the money simply arrives, so
it is evaluated, if at all, with hold 0.

## Capability report

`getgovernance` reports the node's recipient controls beside
`stream_widths`:

```json
"capabilities": {
  "recipient_policy": true,
  "recipient_max_hold": true,
  "recipient_guarded_pass": true
}
```

The flags describe the node software, never chain state. On a node
built without the gate they are `false`, and its clause admission
refuses a hold-cap clause (one reading `i17`/`i27`) at deploy time with
a clear reason, instead of admitting a rule that would never run. A
clause reading only `i3` is not refused at deploy: statically it is
indistinguishable from a sender-pass clause — the capabilities report
is how a wallet learns whether the recipient pass will also enforce it
inbound.
