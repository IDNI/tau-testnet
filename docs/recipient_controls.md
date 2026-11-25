# Recipient controls (issues #47, #76)

A recipient can write an `o5` policy clause that governs payments **to**
them: an allow-list of payers, a cap on how long a retractable transfer may
hold their money, or both. The gate lives inside `consensus/sender_policy.py`,
next to the sender's own clause, and is judged at admission and at block
apply through the same helper, so the two never disagree.

## The two streams

| Stream | Meaning |
| ------ | ------- |
| `i17` | The hold length, in the park's **native unit** |
| `i16` | The context/unit tag: `0` outgoing, `1` incoming final payment, `2` incoming time park (seconds), `3` incoming height park (blocks) |

A plain transfer is a final payment: hold `0`, context `1`. A park's hold is
`release_at_time` minus the block timestamp (seconds) or `release_at_height`
minus the block height (blocks), measured against the block being built at
apply and against `next_block_height` / `next_block_timestamp` at admission.
A hold that is not in the future saturates at `0`.

The indices are the two unassigned slots below the approval-slot block:
`i26` and above are the documented custom-input space for clauses and
parked requests, so the tag cannot live there — the shipped wallet
templates type `i26` at `bv[24]` as a sender custom input. `i16` was
designated for the (inactive, never-fed) cooldown stream at the same
`bv[64]` width; the two activations are mutually exclusive on it, and
each audits the live spec before it may proceed.

Both streams are `bv[64]` and are reserved exactly while the feature is
active. The sender pass always feeds `i17 = 0, i16 = 0`, forced after the
custom-input merge, so a sender-supplied `i17`/`i16` never reaches any step
and an owner's inbound rules can never fire on their own outgoing payments.
Before activation nothing is fed at all, and a pre-activation node evaluates
byte-identical inputs.

## Writing a clause

A clause is inbound-capable **iff it reads `i16` or `i17`**. A clause reading
neither keeps exactly its outbound meaning and is never asked inbound — that
is the neutral default for recipients without a policy.

```tau
# inbound allow-list + 600-second / 10-block hold cap, outbound untouched
always (
  (i16[t] = {0}:bv[64]) ? <existing outbound body, or o5 = allow>
: (i16[t] = {1}:bv[64]) ? (sender ∈ {A, B} on i3 ? o5 = allow : o5 = block)
: (i16[t] = {2}:bv[64]) ? ((sender ∈ {A, B}) && i17[t] ≤ 600 ? allow : block)
:                          ((sender ∈ {A, B}) && i17[t] ≤ 10  ? allow : block) ).
```

A clause that reads `i17` but never reads `i16` is **refused at deploy**:
it would judge seconds and blocks with one number. The same refusal applies
on a node where the feature is not active yet (`RECIPIENT_POLICY_INACTIVE`),
so a rule is never silently admitted that will never run.

## Activation

`recipient_policy_active` is a one-way governance flag, exactly on the
`approval_slots_active` precedent: a host-contract patch sets it to `True`
only, and `build_mechanism_metadata` emits the key only when on, so the
legacy consensus meta-hash is pinned while the flag is off. Activation first
audits the effective spec; if any in-force text already reads `i17`/`i16`
with a meaning of its own, activation is refused and the flag stays off —
the chain keeps running. A fresh chain can activate from block 0 with
`scripts/gen_genesis.py --recipient-policy-active`.

## What a refusal carries

- **Allow-list refusal**: `recipient_policy_block` (receipt) / `TX_REJECTED`
  (admission). A re-judgement at hold `0` distinguishes it from a hold
  refusal.
- **Hold refusal**: `RECIPIENT_MAX_HOLD`, carrying the measured hold and its
  unit always, and the recipient's cap only when the gate verified it
  against this payer's own evaluation (the clause admits `cap` and refuses
  `cap + 1` for this counterparty). A rule whose cap cannot be verified —
  a non-monotonic rule, or one whose cap depends on the payer — is reported
  honestly as `cap_kind: "rule"` with no number, never a fabricated one.
  The cap is per-branch: a seconds cap is never reported for a block park.

A refusal at admission costs nothing. A refusal at apply is a hard-reject
through the identical path as a sender-policy block, so it costs no fee and
no sequence number, and a batch containing a refused leg fails atomically.

## Retracts and releases

Only parks are gated. A retract is never gated by the recipient's cap, and
a release is not re-checked: once a park is admitted, the recipient is paid
at maturity even if their rule changed afterwards.

## Pre-flight

`getrecipientpolicy <address> [sender amount hold unit]` is a read-only
pre-flight: it reports whether the address has an inbound-capable clause
and, with the extra arguments, runs the gate once for that payment and
returns the verified cap when the rule is a threshold rule.
`getgovernance` reports `recipient_policy_active` and a `capabilities`
block with the stream numbers and widths, so a wallet can detect the
feature before asking.

## Command line

`tau-testnet policy receive ...` is the operator surface for the gate:

- `policy receive status` — whether recipient controls are active on the
  connected chain, and which streams they reserve (the readable form of
  the `getgovernance` capability report above).
- `policy receive show <address> [--sender <pubkey> --amount <n> --hold
  <n> --unit seconds|blocks]` — one address's recipient state, and with
  the four extra flags a preflight verdict for a payment you are about to
  make, including the verified cap when the rule is a threshold rule
  (the readable form of `getrecipientpolicy`).
- `policy receive allow-list <pubkey>...` — prints an inbound allow-list
  clause in the canonical form above: the outgoing branch untouched,
  every inbound context restricted to the listed payers.
- `policy receive max-hold [--seconds <n>] [--blocks <n>]` — prints a
  hold-cap clause, one disjunct per unit, so a seconds cap never refuses
  a height park and vice versa. A cap of 0 refuses every park of that
  kind while still admitting plain transfers.
- `policy receive combined --allow <pubkey> [--allow <pubkey>...]
  [--seconds <n>] [--blocks <n>]` — prints a clause that is both an
  allow-list and a hold cap; either cap may be omitted to leave that
  unit uncapped.

The three composition commands are offline: they print clause text and
send nothing. Every clause they print reads `i16` (never unit-blind),
types every `i17`/`i16` mention `bv[64]`, and declares its caps in the
canonical comparisons the node's extractor reads — so the text passes
the same deploy screens a node applies, and the caps `show` reports for
it are the caps it declares. Install the printed text as your `o5`
policy clause to use it; it takes effect only on a chain where
recipient controls are active.
