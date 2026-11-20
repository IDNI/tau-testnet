# Recipient-side policy

Issues #47 (inbound allow-list) and #76 (maximum hold time).

By default the node checks only the **sender's** policy on a transfer: an
account can limit what it sends, but it has no say over what it receives. With
recipient-side policy on, an account's own o5 clause can also judge payments
coming **in** to it:

- **Inbound allow-list (#47):** accept payments only from approved senders.
- **Maximum hold time (#76):** accept a retractable transfer only if it releases
  within a cap. A cap of 0 accepts plain transfers only, so "paid" means final.

Both live in the same per-account policy clause as the outbound rules (one
policy unit per account), and both are opt-in: nothing changes for an account
whose clause does not ask for it.

## How a clause tells the sides apart: i17

Once recipient policy is active, the node feeds the input stream **i17** (bv[64])
to every o5 clause evaluation:

| i17 | Meaning |
|---|---|
| `0` | The clause owner's own **outgoing** transfer (the sender pass). |
| `1 + H` | A payment **coming in** to the owner, held `H` seconds before it can be spent: `1` for a plain transfer, `1 + (release_at_time - block time)` for a time-released retractable transfer. |

Every other input is the transfer's own, so the clause reads the counterparty
and the amount the same way on both sides: `i1` amount, `i3` sender, `i4`
recipient, `i5` block time.

A retractable transfer released by **block height** has no wall-clock bound
(block production can stall), so it reports the longest window a park may have,
`1 + 7776000` (90 days), and any finite cap refuses it.

```
# accept payments only from A (outgoing transfers untouched)
always (((i17[t]:bv[64] > { #x0000000000000000 }:bv[64]) && !(i3[t]:bv[384] = { #xA... }:bv[384]))
        ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])).

# instant payments only: refuse any hold
always ((i17[t]:bv[64] > { #x0000000000000001 }:bv[64])
        ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])).

# hold at most 600 seconds: refuse i17 above 601 (#x259)
always ((i17[t]:bv[64] > { #x0000000000000259 }:bv[64])
        ? (o5[t]:bv[24] = { #x000000 }:bv[24]) : (o5[t]:bv[24] = { #x000001 }:bv[24])).
```

To keep an outbound whitelist too, combine the two in one clause, deciding on
`i17 = 0` for outgoing and `i17 > 0` for incoming. The web wallet ships the three
rules above as templates.

**Opt-in by reading i17.** The recipient's clause is evaluated for an incoming
payment only if it reads i17. A clause written before this feature (an outbound
whitelist on `i4`, say) is never consulted for receipts: run on one, it would
see `i4` = its own owner and refuse everything.

## What is checked

| Credit | Recipient's clause consulted? |
|---|---|
| Ordinary transfer, every leg of a batch | Yes, `i17 = 1` |
| Retractable transfer (the park) | Yes, `i17 = 1 + hold` |
| Co-signed transfer, when it executes | Yes, `i17 = 1` |
| Retractable release | No: authorized at park, not re-checked (docs/retractable.md) |
| Retract (refund to the sender) | No: never gated by the recipient |
| Routed share (#35) to a route's destination | No: the route owner's money moving by the owner's rule |
| Faucet and genesis grants, fees | No |
| Rule offers, approval requests | No: not transfers |

The recipient's clause runs after the sender's checks, at admission and at block
apply, on the same inputs. A refusal fails the **whole** transaction, exactly
like a sender-side o5 block: a batch with one refused output applies nothing,
and a transaction refused at apply never enters the block, so no fee is charged.
A clause that does not build or step refuses, as on the sender side.

## Refusals

| Code (`sendtx`, `checktx`) | When | Details |
|---|---|---|
| `RECIPIENT_POLICY_BLOCK` | The recipient's clause refused the payment. | `transfer_index`, `recipient` |
| `RECIPIENT_MAX_HOLD` | A retractable transfer the recipient would accept with no hold. | `max_hold_seconds` (the longest hold the clause accepts), `hold_seconds`, `transfer_index`, `recipient` |
| `RECIPIENT_POLICY_INACTIVE` | `checktx` only: the rule reads i17 but the feature is off, so it would never run. | |

Block receipts carry `reason: recipient_policy_block`. `max_hold_seconds` is found
by bisection over the clause (a cap is monotonic in the hold) and is used only to
word the refusal, never to decide it.

## Activation and reads

Off until activated: a governance patch `{"recipient_policy_active": true}` (or
`gen_genesis.py --recipient-policy` on a fresh chain) turns it on, one way. The
flag enters the consensus meta hash only once set, so no regenesis is needed.
From activation on:

- i17 is **write-reserved**: a sender cannot put `"17"` in `operations` (they
  could otherwise pose as the outgoing side of their own payment).
- i17 is **readable only from an o5 clause**: the node feeds it to clause
  evaluations only, never to the shared Tau program.
- Every i17 mention in a clause must be typed `i17[t]:bv[64]` (stream typing is
  process-global inside a policy worker).

Before activation i17 is an ordinary custom stream, as i16 and the approval
slots were before theirs. Activation is refused (logged, flag left off on every
node) while a rule, guard or consensus revision already reads i17, or a clause
types it at another width; an o5 clause that reads `i17[t]:bv[64]` ahead of
activation is the feature's own use and starts judging receipts from then on.

Wallets check support before offering an inbound rule:

- `getaccountstate <address>` returns `recipient_policy: {active, inbound_rule}`.
- `checktx` returns `recipient_policy_active`, and refuses a rule that reads i17
  with `RECIPIENT_POLICY_INACTIVE` while the feature is off.

## Security notes

- **A sender cannot pose as the outgoing side.** i17 is reserved once active, and
  the node sets it per pass.
- **Height-released parks count as unbounded.** A capped account never waits on
  stalled block production.
- **Routed shares bypass the destination's allow-list on purpose.** A route's
  destination is chosen by the route's owner and receives the owner's money;
  gating it would let a destination's rule fail every payment to the owner.
