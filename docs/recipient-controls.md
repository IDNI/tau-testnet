# Recipient controls

An account can refuse payments sent to it — from senders it has not
approved, or held (parked) longer than it accepts. Two capabilities,
both enforced on the recipient's own `o5` policy rule (issues #47 and
#76):

- **Recipient policy (#47)** — refuse incoming transfers from unknown
  senders. The recipient allowlists the senders it accepts; everyone
  else is refused at admission.
- **Recipient max hold (#76)** — cap how long a payment to the account
  may be held. `0` means instant arrival only: any parked payment is
  refused. A cap of 600 admits a 10-minute park and refuses a 1-hour
  park. Only parks are gated; retracts are never gated, and releases
  are not re-checked.

No policy means no restriction: the default is neutral, and a transfer
to an account without a recipient policy is unaffected.

## How it works

Every transfer carries its hold length on a new input stream, `i17`:

- a plain transfer holds for `0`;
- a retractable transfer holds for `release_at_time − block time` in
  seconds (time-kind park) or `release_at_height − block height` in
  blocks (height-kind park).

The recipient's `o5` rule reads `i17` (and `i3`, the sender) and
returns allow (`1`) or block (`0`). The rule is evaluated twice:

1. **At admission** (`sendtx`): the transfer is refused before it is
   queued. A refused transfer is never queued and nothing is charged.
2. **At apply** (block execution): the same gate runs as part of
   consensus. A refused transfer rejects the whole transaction —
   staged writes never commit — and no fee is charged. Apply is
   authoritative: a transfer admitted under an older rule can still be
   refused at apply if the recipient changed their policy in between.

A hold only shrinks as a transaction lands in a later block, so a
transfer accepted at admission on its hold is accepted at apply on
its hold too.

The recipient's rule can be written in either of two modes:

### Guarded mode (application rules)

The recipient's unit lives in the application rules and is inert
unless the policy subject is the recipient: it allows whenever `i12`
is not the recipient, and applies the recipient's verdict when it is.
Admission and apply re-evaluate the transfer with `i12` set to the
recipient — a second pass — but only when the rules text may hold a
guarded unit for them. A transfer to an account with no guarded unit
costs no extra evaluation.

Template — allowlist (only accept from one sender):

```
always ((i12[t]:bv[384] = { #x<YOUR_PUBKEY> }:bv[384])
  ? ((i3[t]:bv[384] = { #x<SENDER_PUBKEY> }:bv[384])
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]))
  : (o5[t]:bv[24] = { #x000001 }:bv[24])).
```

Template — max hold of 600 (seconds for a time park, blocks for a
height park):

```
always ((i12[t]:bv[384] = { #x<YOUR_PUBKEY> }:bv[384])
  ? ((i17[t]:bv[64] <= {600}:bv[64])
    ? (o5[t]:bv[24] = { #x000001 }:bv[24])
    : (o5[t]:bv[24] = { #x000000 }:bv[24]))
  : (o5[t]:bv[24] = { #x000001 }:bv[24])).
```

The two combine by nesting: the allowlist check outside, the hold
check inside. The `i12` guard is what makes the unit guarded — without
it, the unit would judge every transfer in the chain, not just ones
to you. The cap literal must be `bv[64]`, the width `i17` is fed at.

Deploy ONE combined unit per recipient, never two separate units: each
`always` revision of `o5` supersedes the previous one, so the
last-applied unit's verdict wins and the earlier policy is silently
masked. Two guarded units for one recipient do NOT AND-combine
(proven by `test_native_two_separate_guarded_units_last_wins` in
`tests/test_recipient_controls_native.py`).

### Clause mode (your own o5 clause)

Register the rule as your own `o5` policy clause: send a `user_tx`
carrying only the rule (operations `"0"`), with no transfers in it —
the same way any `o5` clause is registered (see "Rule sharing" in
[developer_cli.md](developer_cli.md)). The clause body is the verdict
expression on its own, e.g. for a 600 cap:

```
(i17[t]:bv[64] <= {600}:bv[64])
  ? (o5[t]:bv[24] = { #x000001 }:bv[24])
  : (o5[t]:bv[24] = { #x000000 }:bv[24])
```

A clause is evaluated on the transfer's inputs directly — no second
pass — so it costs nothing extra. Clause mode and guarded mode can
both be in force for one account; either one blocking refuses the
transfer (clause mode is checked first).

## Refusals

A refusal names the reason, so a wallet can tell the sender what to
do instead of just failing:

| Code | Meaning | What the sender should do |
| --- | --- | --- |
| `RECIPIENT_POLICY_BLOCK` | The recipient's policy refused this sender (or amount) | Ask the recipient to allowlist you, or pay from an approved account |
| `RECIPIENT_MAX_HOLD` | The payment would be held longer than the recipient's cap | Send it now (plain transfer) instead of parking it, or shorten the park |

`RECIPIENT_MAX_HOLD` carries the cap and the refused hold in its
details (`max_hold`, `hold`, `hold_unit` — `"seconds"` or `"blocks"`).
The two are distinguished by a probe: the transfer is re-evaluated
with a zero hold, and only a transfer that is allowed at zero hold
but blocked at its real hold is a max-hold refusal. A rule that also
blocks an instant payment is a policy refusal, whatever its hold rule
says. The cap in the message is read out of the rule text
(`i17 <= {N}` in canonical form); a rule whose cap cannot be read
still refuses correctly, with the hold length instead of a cap.

At apply, the same distinction lands in the receipt reason:
`recipient_policy_block` or `recipient_max_hold`.

Check before you send: `checktx estimate` returns the same verdict
`sendtx` would, and `gettaustate` reports the capabilities this node
enforces:

```json
{"status": "ok", "command": "gettaustate",
 "data": {"rules_state": "...",
          "capabilities": ["recipient_policy", "recipient_max_hold"]}}
```

## Verification (real engine, not mock)

Guarded-mode verdicts are proven against the real native Tau engine
(`tests/test_recipient_controls_native.py`, 9 tests, all passing): the
recipient's guarded unit is deployed into a real `WorkerSession` spawned
from the router, and `engine.apply` refuses/allows through the gate's
second pass (`i12` = recipient) plus the zero-hold probe -- an unknown
sender is refused with `recipient_policy_block`, a known sender is
accepted, a 3600 s park against a 600 cap is refused with
`recipient_max_hold`, and a 600 s park is accepted and escrowed. The
same four verdicts are proven for the single COMBINED unit (allowlist
outside, cap inside), and a ninth test pins the composition rule: two
separate guarded units for one recipient do NOT combine -- the
last-applied unit's `o5` verdict wins
(`test_native_two_separate_guarded_units_last_wins`). No
`communicate_with_tau*` patching anywhere in those tests.

Clause mode is proven end to end on TWO LIVE NODES running the native
engine (isolated dev chain, `tau-recipient-e2e`, Direct Bindings Mode):
Bob registers an allowlist clause (only Alice) by rule tx, then a
`RECIPIENT_POLICY_BLOCK` refusal is returned at admission for a
Stranger transfer, while Alice's transfer is accepted; Bob then
registers a 600 cap clause, a 3600 s park is refused with
`RECIPIENT_MAX_HOLD` ("only accepts payments held for up to 600
seconds"), and a 600 s park is accepted and escrowed. Both nodes agree
on every block and balance (7 blocks, Alice 999,720 / Bob 1,000,230 /
Stranger 999,890 at the end of the run).

Guarded mode is also proven end to end on TWO LIVE NODES running the
native engine (same isolated dev chain, `tau-recipient-e2e`, Direct
Bindings Mode), with ONE combined guarded unit (allowlist outside,
600 cap inside) seeded into the genesis `application_rules`: a
Stranger transfer to Bob is refused at admission with
`RECIPIENT_POLICY_BLOCK` ("The recipient only accepts payments from
approved senders"); Alice's 100 transfer is accepted (block 1,
tx `6dd2d0ac…`); Alice's 3600 s park is refused with
`RECIPIENT_MAX_HOLD` ("only accepts payments held for up to 600
seconds"); Alice's 600 s park is accepted and escrowed (block 2,
tx `79bdb137…`, retractable `1d8b1d25…` open on both nodes). Both nodes
agree on all 3 blocks and final balances (Alice 999,780 / Bob
1,000,100 / Stranger 1,000,000).

Root cause of the FIRST live run's failure (Stranger accepted despite
a seeded guarded unit): composition, not deployment. That run seeded
TWO separate guarded units for Bob (allowlist + cap); the cap unit
applied last, so its `o5` verdict -- accept for any sender when the
hold is within cap -- silently masked the allowlist. Genesis seeding
itself works: the unit reaches the evaluator's spec and enforces.
That is why the rule is one combined unit per recipient.

Deployment paths for guarded units, as the code stands: genesis
seeding is the ONLY path. A rule tx cannot deploy one -- operations
`{"0"}` routes `o5` rules to the clause registry, which rejects `i12`
guards -- and a rule offer is screened the same way, so an offer
cannot deploy one either. Governance applies consensus rules only.
If a guarded unit must be added after genesis, it has to be a clause
instead (clause mode above), or the chain needs a new deployment path
-- that is a platform question for Tau/IDNI, not part of this change.

## What is not gated

- **Retracts** (`retract_transfer`): never gated. A sender can always
  take back their own parked payment.
- **Releases**: a parked payment that has matured pays out without
  re-checking the recipient's policy. The gate ran when the payment
  was parked.
- **Approval requests**: creating a request is not a transfer, so the
  gate does not run at request creation. The underlying transfer is
  gated when it executes — if the recipient refuses it then, the
  request is marked failed and the vote stands.
- **Rule-offer and approval-request pricing**: an approval request is
  priced on its parked transfer, which executes on approval as a plain
  transfer, so the fee query feeds a hold of `0`.

## Operator notes

- The feature is `tau_defs.RECIPIENT_CONTROLS_ACTIVE` (on). A node
  without it refuses any rule that reads `i17` at deploy, and never
  runs the gate — the screen and the gate read the same flag, so they
  cannot disagree.
- `i17` is a reserved input stream (bv[64]). It cannot be written as
  a transaction operation or as an approval-request custom input; only
  the node feeds it, at admission and at apply, in the same overlay
  position (after `i12`, before custom inputs and approval slots).
- Admission keeps its one-Tau-roundtrip-per-transfer property for
  unguarded recipients: the guarded second pass runs only when the
  rules text may hold a guarded unit for the recipient, and the
  zero-hold probe runs only on a block. A guarded transfer costs at
  most two extra steps; an unguarded one costs none.
- The guarded scan is a substring scan for the recipient's pubkey in
  the rules text. A false positive (a unit that merely mentions the
  key, e.g. as an allowlisted sender) costs one extra step; a guarded
  unit must contain its owner's key, so there are no false negatives.
- The fee model is unchanged: a recipient-policy block sets
  `hard_reject` exactly like a sender-policy block, so fee settlement
  — which runs only for accepted transactions — never charges for a
  refused transfer. No fee rule needs to read `i17`, but one may: the
  fee-query steps feed it (`0` for transfer-less queries and approval
  requests, the park's hold for a retractable transfer).
