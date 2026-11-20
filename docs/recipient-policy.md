# Recipient-side policy (issues #47, #76)

A transfer to R passes only if the **sender's** o5 policy **and R's** o5
policy allow it. The recipient side adds two things:

- **#47 — inbound allow-list:** R can say who may pay it (and how much).
- **#76 — max-hold cap:** R can say how long a payment to it may be held
  (a retractable park). Cap 0 means "instant only": plain transfers pass,
  every park is refused.

Both are enforced at **mempool admission and block apply**, deterministically.
A recipient with no policy, or a policy with no o5, allows everything
(neutral default).

## How the recipient is evaluated

The recipient is evaluated with the **same inputs** as the sender's
evaluation of the same transfer:

| stream | value |
|---|---|
| i1 | amount |
| i3 | sender pubkey (the counterparty) |
| i4 | recipient pubkey |
| i5 | block timestamp |
| i12 | see below (differs by mode) |
| i17 | hold length (see below) |

Policy runs in two modes, and the recipient gate covers both:

**Guarded mode.** The node runs a second Tau step with **i12 = the
recipient's key**, so the recipient's guard matches as "policy owner".
Everything else is identical: i3 still carries the sender key, i4 the
recipient, i1 the amount, i17 the hold. A rule in one unit can therefore
tell the directions apart: `i4 = <me>` is inbound, `i3 = <me>` is outbound.

The second step runs only when the recipient may have a guarded unit --
detected by a case-insensitive search for the recipient's key in the
evaluated spec text. The common case (a recipient with no guarded unit)
costs no extra step. A false positive (the key named in a comment, or in
another account's whitelist) costs one extra step and cannot change a
verdict. A false negative needs a rule that gates on i12 without naming
the recipient's key literally (e.g. `i12[t] = i4[t]`); such rules are
**not** recipient-evaluated.

A self-transfer needs no second evaluation: the recipient pass would run
on inputs identical to the sender's.

**Clause mode.** The node evaluates `clause_for(recipient, 5)` -- the
recipient's registered o5 clause -- with the same input map. Clauses
cannot reference i12 (they are evaluated only for their owner), so the
counterparty is readable via i3.

The recipient step's o8/o9 fee outputs are ignored: fees come from the
sender's step alone.

## The hold-length stream (i17)

i17 carries the **hold length** of the transfer being evaluated, as a
bv[64]:

- **Plain transfer:** 0.
- **`release_at_time` park:** `release_at_time` minus the block time, in
  **seconds**.
- **`release_at_height` park:** `release_at_height` minus the block
  height, in **blocks**.

The unit follows the park's release kind: there is no deterministic
blocks-to-seconds conversion (future block times are unknown). A rule
that wants a wall-clock bound should cap blocks conservatively.

i17 is **node-fed and write-reserved** (like i12 and the approval slots):
a sender cannot pre-fill it, and a rule that types it at any width other
than bv[64] -- or leaves it untyped -- is refused at deploy. It is fed on
every transfer evaluation (sender pass, recipient pass, both clause
evaluations) and as 0 on fee-query steps.

**Clocks.** Admission measures the hold against the advisory next-block
clock -- the same clocks `validate_park_shape` uses to refuse a park that
could be mined at or after its own release (`next_block_timestamp` /
`next_block_height`). Apply measures it against the block's own clock
(the block header timestamp / the block height). The hold only shrinks
between admission and inclusion, so a monotone cap rule (the documented
forms) gives the same verdict on both paths. A non-monotone i17 rule can
flip between admission and apply, exactly like an i5 time-lock today.

**Fee rules may not read i17.** The hold is advisory at admission and
authoritative at apply, so a fee rule (o8/o9) reading it would be quoted
on one hold and charged on another. Policy (o5) rules may read it.

## Refusals

A recipient block is refused with a **distinct reason**, so a wallet can
tell which side said no:

| cause | admission code | apply receipt reason |
|---|---|---|
| recipient policy blocks (allow-list, amount, ...) | `RECIPIENT_POLICY_BLOCK` | `recipient_policy_block` |
| recipient's hold cap blocks a park | `RECIPIENT_MAX_HOLD` | `recipient_max_hold` |

The admission refusal carries details: `transfer_index`, `recipient`,
`hold`, `hold_unit` (`"seconds"` / `"blocks"`), and -- when the policy
states its cap in a documented form -- `max_hold_seconds` /
`max_hold_blocks`. The message carries the cap too:

```
RECIPIENT_MAX_HOLD: recipient 1a2b3c... accepts payments held for up to
600 seconds (max_hold_seconds=600); this park would be held 3600 seconds
```

**Telling a cap block from an allow-list block.** o5 is one bit, so the
node re-evaluates the recipient's policy with identical inputs except
hold = 0 (the discriminator). If it allows at hold 0, the hold caused the
block, so it is the cap; if it still blocks, it is the allow-list. The
discriminator runs only on the already-blocked path of a park -- never
for a plain transfer, never on allow.

**Cap extraction is best-effort text analysis** of the documented forms:
`i17 > N` (cap N), `i17 >= N` (cap N-1), the flipped `N < i17` / `N <=
i17`, and the allow-ternaries `(i17 <= N) ? allow : block` (cap N) and
`(i17 < N) ? allow : block` (cap N-1). A cap stated another way still gets
the `RECIPIENT_MAX_HOLD` reason (the discriminator proves the hold caused
the block); it just does not get the cap value in the message. In guarded
mode the search is scoped to the recipient's own guarded unit, so another
account's cap is never reported as this recipient's.

**Batch.** Each output is checked against its own recipient; one refusal
fails the whole transaction, like an o5 block today. No partial apply.

## What is not gated

- `rule_offer` / accept / reject: not transfers.
- Approval requests: not transfers. (The vote-completion path **does**
  execute a transfer, and is gated through the shared closure.)
- Rule-change requests.
- **Retracts are never gated** -- a sender can always pull back an open
  park, even under a cap that would have refused it.
- **Releases are not re-checked.** Authorization happens at park
  (see `docs/retractable.md`).

## Fee model

Unchanged. A policy block sets `hard_reject`, so the measured fee
components are discarded: a recipient-policy block at apply -- including
a refused park -- charges **no fee**, exactly like a sender-o5 block
today. An admission refusal charges nothing either (the tx never enters
the mempool).

## Capability reporting

`gettaustate` and `checktx` (success and rejection) report:

```json
"capabilities": {"recipient_policy": true, "recipient_max_hold": true}
```

An old node has no such field, which means inactive. A wallet should
check this before deploying an inbound-only rule: on a node without the
feature, a rule referencing i17 is **refused at deploy** with code
`RECIPIENT_POLICY_INACTIVE` and a clear reason -- never silently admitted
as a rule that would never run.

The feature flag is `tau_defs.RECIPIENT_POLICY_ACTIVE`. Flipping it is a
consensus change (like `COOLDOWN_STREAM_ACTIVE`): with it off, i17 is not
fed, not reserved, and not readable in rule text.

## Examples

### Inbound allow-list (clause)

R allows incoming only from A. Clauses carry no i12 guard; the
counterparty is i3:

```
always (
  ( (i3[t]:bv[384] = { #x< A > }:bv[384])
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) )
).
```

Deploy it as a user rule; the node registers it as R's o5 clause.

### Cap 0: instant only (clause)

R accepts plain transfers and refuses every park:

```
always (
  ( (i17[t]:bv[64] <= { #x0000000000000000 }:bv[64])
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) )
).
```

### Cap 600 seconds (clause)

R accepts parks held up to 10 minutes and refuses longer ones:

```
always (
  ( (i17[t]:bv[64] <= { #x0000000000000258 }:bv[64])
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]) )
).
```

600 is `#x258`. A 10-minute park passes; a 1-hour park is refused with
`RECIPIENT_MAX_HOLD` and `max_hold_seconds=600`.

### Inbound + outbound in one guarded unit

One unit can carry both directions. In the recipient pass i12 is R and
i4 is R (inbound); in the sender pass i12 is R and i3 is R (outbound):

```
always (
  (i12[t]:bv[384] = { #x< R > }:bv[384])
  ? ( (i4[t]:bv[384] = { #x< R > }:bv[384])
      ? ( (i3[t]:bv[384] = { #x< A > }:bv[384])   # inbound: only from A
          ? (o5[t]:bv[24] = { #x000001 }:bv[24])
          : (o5[t]:bv[24] = { #x000000 }:bv[24]) )
      : ( (i4[t]:bv[384] = { #x< S > }:bv[384])   # outbound: only to S
          ? (o5[t]:bv[24] = { #x000001 }:bv[24])
          : (o5[t]:bv[24] = { #x000000 }:bv[24]) ) )
  : (o5[t]:bv[24] = { #x000001 }:bv[24])
).
```

## Stream map

| stream | meaning | fed by |
|---|---|---|
| i1 | amount | transfer |
| i2 | sender balance at parent block | node |
| i3 / i4 | from / to pubkeys | transfer |
| i5 | block timestamp | node |
| i12 | sender pubkey (sender pass) / recipient pubkey (recipient pass) | node |
| i16 | seconds since the sender's previous transfer | node (once the cooldown stream activates) |
| **i17** | **hold length, bv[64]** (0 = plain transfer) | **node** |
| i18–i25 | co-signature approval slots | node |
| i26+ | sender custom inputs | sender |

See `docs/approvals.md` for the full stream map.
