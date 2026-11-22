# Recipient policy: inbound allow-lists and hold caps (#47, #76)

Until this change one account's policy judged a transfer: the **sender's**.
A recipient had no say. With recipient policy active, the **recipient's** own
`o5` clause judges every payment it would receive, after the sender's checks,
at mempool admission and again at block apply. That makes two wallet requests
expressible:

- "Only accept money from accounts I approved" (#47, inbound allow-list)
- "Only accept payments I get straight away / held at most N seconds" (#76)

## Activation

Recipient policy is a consensus change, so it ships **off** and is switched on
by a governance update carrying the host contract patch

```json
{"recipient_policy_active": true}
```

exactly like `approval_slots_active`:

- **One-way.** Only `true` is a legal value; there is no way back, because
  turning it off would un-reserve `i17` while clauses rely on it.
- **Audited.** If any rule or registered clause in the effective spec already
  mentions `i17`, the proposal is refused at admission, and at the activation
  height the flag stays off (the chain keeps running) instead of re-purposing a
  stream someone used for something else.
- **Hash-bound.** Once on, `recipient_policy_active: true` is part of the
  consensus meta hash. A chain that never activates it hashes exactly as before.
- **Parent snapshot.** An activation recorded in block H governs H+1 onward.
- **Fresh chains** can start with it on: `scripts/gen_genesis.py
  --recipient-policy-active` (a genesis generated without the flag stays
  byte-identical).

`getgovernance` reports it, so a wallet can check before offering the rule:

```json
"recipient_policy": {
  "supported": true,
  "active": true,
  "receive_stream": "i17",
  "receive_stream_width": 64,
  "hold_seconds_base": 1,
  "hold_blocks_base": "9223372036854775808"
}
```

While it is inactive, an `o5` policy rule that reads `i17` is **refused at
deploy** with `RECIPIENT_POLICY_INACTIVE` (and `checktx` reports the same),
instead of being admitted as a rule that would never run.

## Tools for wallets and users

**Pre-flight** (`getrecipientpolicy`, advisory, rate-limited like `checktx`):

```
getrecipientpolicy <recipient>
  -> recipient_policy_active, has_policy_clause, judges_incoming

getrecipientpolicy <recipient> <sender> <amount> [<hold> <seconds|blocks>]
  -> allowed, and when refused: code RECIPIENT_POLICY or RECIPIENT_MAX_HOLD
     with max_hold_seconds / max_hold_blocks
```

It calls the same helper admission and apply call, on the map admission builds,
so a wallet can show "this shop accepts only instant payments" or explain a
refusal before the payer signs anything.

**Compose a clause** (`tau-testnet policy receive`), instead of writing Tau text
by hand:

```
tau-testnet policy receive --allow <A> --allow <B>            # only A or B may pay me
tau-testnet policy receive --max-hold-seconds 0               # instant payments only
tau-testnet policy receive --max-hold-seconds 600 --max-hold-blocks 10
tau-testnet policy receive --allow <A> --send-only-to <C> --out rule.tau
tau-testnet tx send --key me --rule-file rule.tau             # deploy it
```

Every combination it can produce passes the deploy screens, and its meaning is
pinned against the real engine (`tests/test_recipient_policy_native.py`).

## The receive stream `i17` (bv[64])

The node feeds `i17` into every `o5` clause evaluation once the feature is active:

| `i17` value | meaning |
|---|---|
| `0` | the clause owner is **sending** (the existing sender pass) |
| `1` | the owner is **receiving** a plain transfer (hold 0) |
| `1 + N` | the owner is receiving a time-based retractable transfer held `N` seconds |
| `2^63 + N` | the owner is receiving a height-based retractable transfer held `N` blocks |

The two hold ranges never meet (a park is held at most
`MAX_RELEASE_WINDOW_SECONDS`), so a cap in either unit is one comparison.

`i17` is node-only: once active it is a reserved operation key (a sender cannot
write it) and only an `o5` clause may read it. Every mention must be typed
`i17[t]:bv[64]`.

In the recipient pass the clause sees the payment from its own side:

| stream | sender pass (today) | recipient pass (new) |
|---|---|---|
| `i1` amount | amount | amount |
| `i3` from | sender | sender (the counterparty) |
| `i4` to | recipient (the counterparty) | recipient |
| `i12` owner | sender | **recipient** |
| `i2` owner's balance | sender's balance at the parent block | **recipient's** balance at the parent block |
| `i17` receive | `0` | `1`, `1 + N` (seconds), or `2^63 + N` (blocks) |
| `i5`, custom inputs, approval slots | as today | the same values |

## Opt-in by reading `i17`

A recipient's clause is consulted for an incoming payment **only if it reads
`i17`**. Every clause deployed before this change was written as an outbound
rule; judging money arriving with it would silently turn each outbound whitelist
into an inbound block. Reading `i17` is decided from the clause text alone, so
every node decides it identically.

A recipient with no clause, or with a clause that never reads `i17`, accepts
everything: the neutral default (#47 case 2, #76 case 3).

## Examples

Accept incoming money only from A (outbound rules unaffected):

```
always ( ((i17[t]:bv[64] > { #x0000000000000000 }:bv[64])
          && !(i3[t]:bv[384] = { #x<A> }:bv[384]))
         ? (o5[t]:bv[24] = { #x000000 }:bv[24])
         : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

Accept only instant payments (cap 0): refuse when `i17 > 1`.
Accept payments held at most 600 seconds: refuse when `i17 > 601`. A seconds
cap also refuses every height-based park: a block count has no length in
seconds on a chain that can stand still, and its `i17` lies above the seconds
range.
Accept height-based parks held at most 100 blocks: refuse when
`i17 > 2^63 + 100` (literal `{ #x8000000000000064 }:bv[64]`); time-based parks
and plain transfers are below that value and pass. A recipient may state both
caps in one clause.

One clause, both directions (#47 case 4): send only to C, receive only from A:

```
always ( (((i17[t]:bv[64] = { #x0000000000000000 }:bv[64]) && !(i4[t]:bv[384] = { #x<C> }:bv[384]))
       || ((i17[t]:bv[64] > { #x0000000000000000 }:bv[64]) && !(i3[t]:bv[384] = { #x<A> }:bv[384])))
         ? (o5[t]:bv[24] = { #x000000 }:bv[24])
         : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

## What is gated

| transaction | gated by the recipient's clause? |
|---|---|
| `user_tx` transfers (every output of a batch) | yes, hold 0 |
| `retractable_transfer` (park) | yes, with its hold |
| `retract_transfer` | **no**: a retract is never gated |
| matured release of a park | **no**: authorization happens at park; nothing is re-checked at release |
| an approval request (`approval_request`) | no: a request is not a transfer (#47 scope) and is parked whatever the recipient says |
| the transfer an approval vote releases | **yes**, hold 0: it is money arriving. A refusal fails the request (`STATUS_FAILED`, log "refused by the recipient's policy"); the vote stands, nothing moves |
| `rule_offer` | no: moves no money |

A batch is checked output by output, each against its own recipient; one refusal
fails the whole transaction, as an `o5` block does today (#47 case 3).

## Refusals and fees

At **admission** (`sendtx` / `checktx`) nothing is charged:

- `RECIPIENT_POLICY`: the recipient's clause refused the payment
  ("Transaction rejected by recipient policy (o5) ... transfer #N").
- `RECIPIENT_MAX_HOLD`: a park the recipient would have taken instantly was
  refused because of its hold. The message carries the recipient's cap in the
  park's own unit ("the recipient accepts payments held for at most 600
  seconds" / "... at most 100 blocks"), and the details carry
  `max_hold_seconds` and `hold_seconds` (or `max_hold_blocks` and
  `hold_blocks`), so the payer's wallet can print it. The cap is found by asking the same clause the gate asked (a bounded
  search over holds up to the release window), not by reading the rule text, so
  the number is what the rule enforces.

At **apply** the refused transaction is invalid exactly like a sender `o5`
block: no staged write commits, **no fee is charged**, no sequence number is
used, and the receipt reason is `recipient_policy_block`, or
`recipient_max_hold` for a park the recipient would have taken instantly. The
receipt log states the hold that was judged ("payment held 3600 seconds");
`gettxstatus` returns that log as the rejection `detail`. Telling the two
reasons apart costs one extra evaluation. The numeric cap is deliberately not
searched for at apply, where an attacker-chosen clause would multiply the
block builder's work; `checktx` and `getrecipientpolicy` state it.

**How the cap is found.** Exactly, from the recipient's own clause, never
from reading its text as a rule: for this payment every input but `i17` is
fixed, and a clause compares `i17` only with the `bv[64]` constants written in
it, so its verdict can change only at a constant `c` (between `c - 1`, `c` and
`c + 1`). The node evaluates the clause at those points and at both ends of the
release window, nothing else. The verdict is a cap exactly when it is "admit"
up to some point and "refuse" from the next one to the end of the window; that
point is the cap reported. A number is reported only when every mention of `i17`
sits in a direct comparison with a `bv[64]` literal (`i17 OP { c }` or
`{ c } OP i17`). A clause that is not a cap (it admits 0-100 s and 300-400 s,
say), that compares `i17` with another stream (`i17 > i26`), or that does
arithmetic, still enforces exactly what it says; its refusal simply carries no
number.

The search is bounded at `sendtx`, because a refused payment pays no fee: it
stops at the first verdict that rules a cap out (refuse, then admit again), and
a clause with more than `ADMISSION_CAP_MAX_POINTS` (12) candidate points gets
no number there at all, so a refusal costs at most 12 extra evaluations. A cap
in seconds, in blocks or in both needs at most 8. `getrecipientpolicy`, which
the server already queues as an expensive command, searches without the bound.

## Determinism

Admission and apply build the recipient's inputs with one helper
(`consensus/sender_policy.py`), from the same per-transfer map the sender's
clause sees. The hold of a time-based park is measured against the next block's timestamp
at admission (the clock admission already uses to refuse a park that could be
mined at or after its release) and against the timestamp of the block that
carries the park at apply; a height-based park likewise against the next block
height and the carrying block's height. Apply is authoritative.

## Why there is no second "guarded" pass

Issue #47 was written when an `o5` rule could still be an accumulated, guarded
unit (`always ((i12 = <me>) ? body : o5 = allow)`) and asks for either mode to
work. On the current main every user rule that writes `o5` is registered as the
sender's **clause** (`consensus/admission.py::validate_o5_clause_routing`); the
guarded form is refused at deploy (`CLAUSE_SHAPE`) and ignored at apply. So the
recipient's clause is the only place an inbound rule can live, and this change
gates on it alone. A guarded unit left in the accumulation from before clause
routing keeps judging what its owner sends, as before; to restrict what it
receives, the owner deploys the rule as a clause. Not adding a second
evaluation of the whole spec keeps every transfer at its current cost and avoids
a pre-screen on spec text, which is where guarded-mode recipient gates have had
to fight comment-only keys and non-canonical key literals.

## Not covered by this change

- The feeless legacy transfer path (chains with the fee model off) does not
  enforce `o5` at all today, for the sender either; it is left as it is.
- A self-transfer (A to A) is judged by A's clause in both passes, so an inbound
  allow-list that does not list A refuses it.

## Every path that moves money

| Path | Function | Recipient clause |
|---|---|---|
| `user_tx` transfer outputs (each output of a batch) | `_execute_fee_era_transfer(..., recipient_hold=0)` | gated |
| `retractable_transfer` (park) | `_execute_fee_era_transfer(..., recipient_hold=<hold>, escrow=True)` | gated, with the park's hold |
| matured release of a park | release sweep (book credit, no Tau step) | not re-checked: authorization happened at park |
| `retract_transfer` | refund to the sender | never gated |
| vote-released `approval_request` | `_execute_fee_era_transfer(..., recipient_hold=0)` | gated as an instant payment; the request itself is not |
| `rule_offer` / accept | registers a clause, moves no money | not gated |
| feeless legacy transfer path (fee model off) | transfer loop without `o5` | no `o5` of any kind, as today |

`recipient_hold` is a required keyword of `_execute_fee_era_transfer`, so a new
caller cannot forget to decide, and every caller passes a hold: there is no
ungated path that moves money to an account.

## Timing, failures and cost

- **Clock.** Admission measures a time-based hold against the next block's
  timestamp, the same advisory clock admission already uses for `i5` and for
  refusing a park that could be mined at or after its release; apply measures it
  against the timestamp of the block that carries the park and is
  authoritative. A park admitted near a recipient's exact cap can therefore be
  refused at apply (no fee), exactly as a time-based sender rule can today.
- **Failures.** The recipient's clause is judged by the same evaluator, with the
  same failure mapping, as the sender's: a clause that does not build or that
  the engine refuses to step blocks the payment on every node; loss or timeout
  of the evaluator worker is an operational error (admission answers
  `ADMISSION_UNAVAILABLE` / `ADMISSION_TIMEOUT`, apply does not turn it into a
  verdict).
- **Cost.** A payment to an account without a clause that reads `i17` costs
  nothing extra. Otherwise apply adds one clause evaluation per gated output,
  plus one for a refused park; the cap analysis (about three evaluations per
  constant in the clause) runs only at admission and in the advisory RPC.

