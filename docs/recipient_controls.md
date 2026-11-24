# Recipient controls

An account's own `o5` clause can judge the payments made **to** it: refuse
senders it has not approved (issue [#47]), and cap how long a payment to it may
be held before it is final (issue [#76]).

Before this change only the **sender's** policy was consulted for any transfer,
so a shop could not say "paid" had to mean final and could not keep unknown keys
from paying it. Both are enforcement, not advice: the network refuses the
transaction, at mempool admission and again at block apply.

## One unit per account, judged twice

An account's policy is a single `o5` clause. The node evaluates it twice per
payment, with one input swapped:

| Pass | `i12` (the injected key) | Who is judged |
|---|---|---|
| sender | the sender | "may I send this?" |
| recipient | the recipient | "may this be paid to me, and how long may it be held?" |

Everything else is fed identically, so one clause can carry outbound rules,
inbound rules and the hold cap at once. Two things keep that from changing what
already-deployed policy means: an account with **no clause** on `o5` is never
consulted on the receiving side, and neither is a clause that never mentions
`i17` — reading it is the opt-in. A policy written for outbound rules (it reads
`i3` or `i1`) must not start refusing inbound payments because a node upgraded.

## The receive stream: `i17`

A clause body may not reference `i12` (it is the node's, and a clause is only
ever evaluated for its owner), so an inbound rule cannot tell itself apart from
an outbound one by reading its own key. `i17` is the node-fed `bv[64]` stream
that says which judgement this is and how long the money would be held:

| `i17` | Meaning |
|---|---|
| `0` | the owner is the **sender** of this payment (outbound judgement) |
| `1` | the owner is the **recipient**; the payment is final in this block (a plain transfer, hold 0) |
| `1 + N`, `N >= 1` | recipient; a retractable transfer released `N` **seconds** after the block's timestamp |
| `2^63 + N`, `N >= 1` | recipient; a retractable transfer released `N` **blocks** ahead |

The two families are ordered on purpose: every seconds value is small, so a cap
in seconds is one comparison, and it also refuses every block-based park,
because a block value always exceeds `2^63`.

`i17` is reserved for writes (a sender cannot pre-fill it) and readable only
from policy rule text, like the approval slots. Every mention must be typed
`bv[64]`: per-stream typing is process-global and sticky, so one clause typing it
at another width would leave the interpreter unable to build anyone's receive
rule.

## Rules

Deploy them the way any `o5` rule is deployed — unguarded, one `always ( … ).`
unit. The bodies below are the shipped templates, and they are **ternaries that
assign `o5` on both branches**. That is not style: an output a rule does not
constrain for a given input still materialises, with `0` as its witness, and for
`o5` that is the block value (README, "How a clause judges a transfer"). An
implication such as `(cond) -> (o5 = 1)` therefore blocks every transfer whose
condition is false — the opposite of what its author meant.

**Only approved senders may pay me.** Every other sender is refused.

```
always ( (i3[t]:bv[384] = { #x<APPROVER> }:bv[384]) ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

**Only take payments that arrive instantly** (cap 0: plain transfers pass, every
park is refused).

```
always ( (i17[t]:bv[64] > { #x0001 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

**Hold at most 600 seconds** (plain transfers pass; a park released within ten
minutes passes; one released in an hour is refused, and so is any block-based
park, whose length is not a number of seconds). `601 = 1 + 600`.

```
always ( (i17[t]:bv[64] > { #x0259 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

**Hold at most 100 blocks** (only block-based parks are capped; `2^63 + 100`).

```
always ( (i17[t]:bv[64] > { #x8000000000000064 }:bv[64]) ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

Combine them with `&&`/`||` in one body, and remember the outbound case: a rule
that must not change how the account *sends* should be conditioned on `i17 = 0`
or left to the sender pass, which is what feeds `0`.

## Where it is enforced

| Path | What happens |
|---|---|
| `sendtx` / `checktx` admission | The recipient's clause is evaluated after the sender's, on the same inputs plus `i12 = recipient` and `i17`; a block rejects the transaction before it enters the mempool. Nothing is charged. |
| block apply | The same call, after the sender's `o5` and clause checks. A refusal is a **hard reject**: the transaction is invalid, no staged write commits, and **no fee is settled** — `hard_reject` short-circuits fee charging, which is the same answer the sender's own clause already gives. |
| replay without Tau | Same concession as the sender path: the verdict is unknown, the existing state-hash invariant catches any divergence. |

The hold is measured against the same clock the park itself uses: at apply, the
block height and timestamp; at admission, the **next** block's height and the
advisory admission timestamp, because that is the earliest block that can carry
the transfer. A park that cannot be mined before its own release point is
refused earlier, by the park screens.

One consequence worth knowing: because admission measures with the *next* block
and apply with the block that actually carries the transfer, the hold shrinks as
a park waits, so a transfer admitted at a cap boundary can only become more
acceptable at apply — except for a block timestamp that lands slightly in the
past (a proposer may choose one up to 120 s behind), which can make a time-based
hold marginally longer than admission measured. A park that close to its own
release point is refused by the park screens anyway.

## The payer's approval slots are not visible to the recipient

The receiving pass zeroes `i18`–`i25`. Those slots carry the approvers who
co-signed **the payer's** request; letting them through would let the payer's
co-signature satisfy the recipient's rule, and the recipient never agreed to it.
Zeroed rather than removed, so every clause sees the same shape of input map.

## If a second hold stream is ever added

`tau_defs.HOLD_STREAM_GROUP` names the streams that together describe the hold.
Today it holds one unit-tagged stream, so the question does not arise: a bound in
seconds refuses block-based parks by construction. If a block-denominated stream
is added, `consensus/approvals.py::screen_hold_mentions` refuses at deploy time
any clause that bounds one hold stream and not the other — the failure mode it
prevents is a rule that caps seconds and silently admits a park of any length.
The screen ships now, inert with a single stream and tested against a two-stream
group, so the layout can change without reopening that hole.

## What is deliberately not gated

- **A retract.** Only the sender may retract, and a retract moves no money to
  the recipient; it is admitted regardless of the recipient's cap.
- **A release.** The release sweep credits the recipient unconditionally and is
  not re-checked, matching the rule that nothing is re-evaluated at release. A
  recipient that accepted the park has accepted its money.
- **A rule offer or an approval request.** Neither moves funds: an offer is a
  proposal, and an approval request only queues a transfer that is judged when it
  actually executes. Both are out of scope in the issues and stay unchanged.
- **An account with no clause**, or one that never mentions `i17`: parks of any
  length pass (neutral default).

## Fee model

A refusal at admission costs nothing — the transaction never reaches the
mempool. A refusal at apply is a hard reject, and the fee is **not** settled for
a hard-rejected transaction (`charge_fee and accepted_in_block and
not hard_reject`), which is exactly what happens today when the sender's own
clause blocks. Admission and apply therefore agree on the price of a
transaction: zero paid either way.

## Capability detection

`getgovernance` reports what the connected node enforces:

```json
"features": {"recipient_policy": true, "receive_stream": "i17", "receive_stream_width": 64},
"stream_widths": { "i17": 64, ... }
```

A wallet must not offer these rules against a node that does not list
`recipient_policy`: on such a node `i17` is an ordinary custom stream, so the
rule is admitted and then never runs. The admission screen refuses to write
`i17` as an operation key on this node, which is the other half of the same
guard.

## Activation is a network-wide break, and it is stated, not hidden

This build feeds `i17` on every transfer, so the index is reserved the moment the
build runs. A chain that upgrades to it changes what an existing clause reading
`i17` means: before, that clause saw a value the *sender* wrote as a custom input
(`operations["17"]`); after, it sees the hold the node computed, and the operation
key is refused outright.

There is no activation height and no per-node switch for this, deliberately — the
same shape as `i16` (cooldown) and `i18`–`i25` (approval slots). A flag would let a
fleet disagree about whether `i17` is a custom input or the receive stream, which is
a consensus split; one build is the safer failure mode. Consequences a wallet or an
operator should know before upgrading:

- a rule text that reads `i17` and was written against sender-supplied values must be
  re-checked (it now reads the node's hold, and `i17 > 1` means "refuse every park");
- a transaction that writes `operations["17"]` is rejected from that build on;
- the refusal happens at admission, so nothing is mined and nothing is charged.

## Tests

`tests/test_recipient_controls.py` covers the helper, the encoding, the reserved
stream, the width screen, and the apply/admission sites with the mock evaluator:
which clause is consulted, with which `i12`/`i17`, the refusal reason
(`recipient_policy_block`, or `RECIPIENT_MAX_HOLD` with the hold and the
recipient's cap in the message), the neutral default, batch atomicity, and the
hold a park is judged on. What a real clause computes from those values is
covered by the native-Tau suite.

[#47]: https://github.com/IDNI/tau-testnet/issues/47
[#76]: https://github.com/IDNI/tau-testnet/issues/76
