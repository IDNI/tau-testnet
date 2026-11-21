# Recipient controls (issues #47/#76)

Until now only the sender's policy was ever consulted: a transfer was
judged by the sender's `o5` rules, and the account being paid had no say.
Recipient controls give the receiving account a veto of its own. An
account can say, in plain language:

- "Only accept payments from senders I approve."
- "Only accept instant, final payments — never a parked (recallable) one."
- "Accept a park only if it is held for at most N seconds / N blocks."

## The model: one clause, two roles

An account still has exactly **one** `o5` policy clause, registered the
usual way. It is now evaluated **twice** for every transfer:

1. in the **sender role**, as before — the owner is the sender (`i3`),
   the counterparty is `i4`;
2. in the **recipient role** — the owner is the recipient (`i4`), the
   counterparty sender is `i3`, and the amount is `i1`.

(Clause bodies may not reference `i12`; the counterparty is always read
from `i3`/`i4`, which is what makes the same unit usable in both roles.)
A transfer lands only when **both** evaluations allow it. Inbound and
outbound conditions therefore live in one unit and both are in force;
the shipped templates guard their recipient conditions with
`(i4 = <your pubkey>)` so they cannot fire on your own sends.

A recipient with **no clause** — or a clause whose conditions do not
fire — allows everything. That is the neutral default: installing
nothing changes nothing.

## What is gated, and what is not

The recipient evaluation sits **inside the shared transfer closure**
(`_execute_fee_era_transfer`), the single code path every payment moves
through, so coverage is structural rather than per-call-site:

- ordinary transfers and **batches** — every output is judged against
  its own recipient, and one refusal rejects the whole transaction
  (no partial execution);
- **approval-request settlements** — when the last co-signature lands,
  the parked transfer executes through the same closure and is judged
  against the recipient then; a refusal fails the request (the votes
  themselves stand);
- **escrow parks** (`retractable_transfer`) — judged at park time, on
  the hold the park carries (see below).

Never gated:

- `rule_offer`s, approval requests and votes themselves — they move no
  money;
- **retracts** — taking your own parked payment back is the sender's
  right, not a new payment to the recipient;
- **due releases** — a release is not re-judged. Authorisation happens
  when the park lands, so a park that was accepted *before* the
  recipient installed a cap still pays out in full when it matures.
  A cap protects you from the moment it is registered, not
  retroactively;
- protocol credits that are not a payment from a sender — the genesis
  faucet grant and the block proposer's fee settlement;
- the legacy feeless replay path, which replays pre-fee-era history
  only and enforces no `o5` policy at all (sender or recipient). The
  fee-era closure above is the consensus-determining path, and replay
  of fee-era blocks runs through it with the same verdicts as live
  apply.

## The hold streams (#76)

A park's hold is fed into **clause evaluations only** (never into the
shared session step, whose inputs are unchanged) on two host-fed
streams, set by the node after every merge so a sender cannot smuggle
in a fake hold:

| Stream | Meaning | Width |
| ------ | ------- | ----- |
| `i17` | hold in **seconds**: `release_at_time - block timestamp` | `bv[64]` |
| `i27` | hold in **blocks**: `release_at_height - block height` | `bv[64]` |

An ordinary transfer and an approval settlement carry `0` on both. A
park is time-based or height-based, never both, so it carries its hold
on exactly one stream. A cap written against one unit sees the other
unit's parks as a positive hold on the other stream: a seconds-only
cap that also refuses `i27 > 0` **fails closed** against height parks
instead of reading them as a 0-second hold.

## Refusal reasons

A recipient refusal is distinguishable from a sender refusal
everywhere a sender refusal is reported today:

- `recipient_policy_block` — the recipient's policy refuses this
  payment (an allow-list miss, or any other condition);
- `recipient_max_hold` — the refusal is about the hold. The receipt
  (and the `checktx`/`sendtx` rejection) carries the cap, measured by
  the node for this transfer: `recipient_max_hold:
  {"max_hold_seconds": 600}`. The cap is **measured, never parsed out
  of rule text**: the node re-evaluates the clause with the hold zeroed
  (to learn the refusal is hold-related) and then binary-searches the
  largest hold the clause still accepts for this transfer. A wallet
  can print the sentence a human understands: "Third only accepts
  payments held up to 10 minutes — send an instant transfer instead."

## Fees

The fee model is unchanged. A recipient refusal at **admission**
means the transaction is never queued and costs nothing. A refusal at
**apply** rejects the whole transaction through exactly the same path
as a sender-policy (`o5`) refusal, with exactly the same fee treatment
— there is no new fee surface, and the recipient never pays for being
paid.

## Capability and deployment

- `getgovernance` reports `features.recipient_policy` (`active`, the
  hold stream names and their width), so a wallet can detect support
  instead of guessing.
- A dry-run (`checktx`) against a refusing recipient returns
  `RECIPIENT_POLICY_BLOCK` or `RECIPIENT_MAX_HOLD` with the measured
  cap in the details.
- Clause bodies that read `i17`/`i27` must type them `bv[64]`; the
  deploy screens enforce it. On a node where recipient controls are
  inactive (`tau_defs.RECIPIENT_POLICY_ACTIVE` — a consensus-class
  switch, like the cooldown stream's), such a clause is **refused at
  deploy with a clear reason**, never silently accepted and never run.
- Admission is the early filter; **apply is authoritative**. A
  transfer admitted before the recipient registered a clause is still
  refused at apply once the clause is in force, and a clause registered
  earlier in the same block judges the transfers that follow it in
  that block.

## Fail-closed rules

- A recipient clause that does not build, or that the engine refuses
  to step, **blocks** — the same mapping the sender's clause has.
- A hold that cannot be determined is a refusal, not a pass.
- The binary search behind `recipient_max_hold` runs only on an
  already-refused transfer and is deterministic: same clause, same
  inputs, same verdict on every node.

## Using it from the CLI

```bash
# Only accept payments from two known senders
tau-testnet policy receive set --key me \
  --sender <pubkeyA> --sender <pubkeyB>

# A shop that needs "paid" to mean "final"
tau-testnet policy receive set --key me --instant

# Accept parks held up to ten minutes (height parks refused)
tau-testnet policy receive set --key me --max-hold-seconds 600

# See the clause text without sending anything
tau-testnet policy receive set --key me --sender <pubkeyA> --print-only

# Inspect or remove what is installed
tau-testnet policy receive show
tau-testnet policy receive clear --key me
```

`set` and `clear` go through the ordinary policy rule-change path, so
a rule-change guard, if you have one, judges them like any other
policy change.
