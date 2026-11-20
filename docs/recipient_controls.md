# Recipient controls — issues #47 (inbound allow-list) + #76 (max hold time)

One recipient-side o5 gate, enforced at admission **and** at apply, in
both clause mode and guarded mode, evaluated after the sender check.
A wallet can tell which side said no: an allow-list refusal is
`recipient_policy_block`, a hold refusal is `RECIPIENT_MAX_HOLD` and
carries the cap.

## Streams and contexts

| Stream | Meaning |
| --- | --- |
| i17 (bv[64]) | Hold length, in the park's **native unit**: seconds for a time park, blocks for a height park. 0 for a final payment. |
| i16 (bv[64]) | Context tag: 0 outgoing, 1 incoming final, 2 incoming seconds-park, 3 incoming blocks-park. |

The recipient's clause **is** their o5 clause (`clause_for(recipient, 5)`).
No new registry key: one unit carries the outbound whitelist and the
inbound whitelist side by side, branching on i16 (#47 case 4). A clause
opts into inbound judging by reading i17 or i16
(`clause_is_inbound_capable`); a body reading neither keeps exactly its
outbound meaning and is never invoked inbound — that is the neutral
default. The sender pass always carries i17=0, i16=0 (outgoing), forced
after the custom merge/slot feed, byte-identically at admission and
apply, so inbound rules never fire on the owner's own outgoing payments.
Self-transfers never reach the gate: the transfer shape check refuses
them upstream (`'to' address is the sender`).

A rule that reads i17 but never i16 is **unit-blind** — its cap cannot
say whether it means seconds or blocks — and is refused at deploy
(`_screen_clause_widths_and_structure`). Every i17/i16 mention must be
typed bv[64].

## Caps, verified by evaluation — never by text scan or probing

A candidate cap is extracted from canonical `i17 <op> {literal}`
comparisons, attributed to the i16 branch whose guard most recently
precedes it and to the payer whose `i3 =` guard most recently precedes
it (per-branch minimum; never a global "most restrictive wins", which
would print one counterparty's cap to another). The candidate is only a
hint: it is **verified by evaluation for this payer** — the clause must
admit at hold == cap and refuse at hold == cap+1 (two extra
evaluations, bounded; not a ~25-step probe sweep, and no whole-range
monotonicity assumption). A non-monotonic rule fails verification and is
reported honestly as `cap_kind: "rule"` with no number.

Hold-refusal classification: a block at hold H in a park context is
re-judged at hold 0 in the same context. Still blocked at 0 → allow-list
refusal (`recipient_policy_block`); admits at 0 → hold refusal
(`recipient_max_hold`, code `RECIPIENT_MAX_HOLD`, hold + unit + the
verified cap).

## What is gated, and what is not

- Gated: transfers and retractable parks, at admission (Step 3) and at
  apply (`_execute_fee_era_transfer`), clause mode and guarded mode.
  One refused output fails the whole transaction (batch atomicity); the
  staged writes never commit.
- Guarded mode: a second Tau step with i12 set to the **recipient**, run
  only when their key appears as a literal in the current spec; only o5
  is read from it, so it can never move a fee.
- Not gated: `rule_offer` and approval requests (they are not payments).
  Retract is never gated (it never enters `_execute_fee_era_transfer`);
  release is never re-checked (it credits directly). An approval-release
  via vote goes through `_execute_fee_era_transfer` with park=None, so
  it is judged as a final payment (hold 0, context 1): the recipient
  allow-list judges it, no hold cap applies.

## Fee model

A policy block at apply costs no fee. The fee settlement runs only when
`charge_fee and accepted_in_block and not hard_reject`
(`consensus/engine.py`, fee step); a recipient block sets
`hard_reject=True`, exactly like a sender block. At admission the
transaction never enters the mempool, so nothing is charged either.

## The cap in the receipt

A max-hold refusal carries the cap three ways:

- admission: `RECIPIENT_MAX_HOLD` with `recipient_policy`
  `{hold, unit, cap_kind, max_hold_seconds | max_hold_blocks}`;
- apply receipt: `tx_receipt["recipient_policy"]` (same fields) and the
  receipt log line
  `Transfer rejected by recipient policy (recipient_max_hold, o5=0):
  hold=3600 unit=seconds max_hold_seconds=600`;
- preflight: `getrecipientpolicy <address> <sender> <hold>
  <seconds|blocks> [<amount>]` judges a concrete payment against the
  recipient's clause with the admission evaluator and reports the cap
  verified for that payer.

## Activation and the i16 / cooldown discharge (issue #21)

Recipient controls activate by one-way governance flag
(`recipient_policy_active`, mirroring `approval_slots_active`), with
i17/i16 reserved exactly at activation. The context tag sits on i16,
the inactive cooldown feed's stream — the two activations are mutually
exclusive, and that is enforced with guards, not docs alone:

1. Activation is refused while the cooldown feed is live:
   `tau_defs.recipient_policy_conflicts_with_cooldown()` is consulted
   by `validate_recipient_policy_active` (proposal check) and by
   `audit_recipient_stream_collisions`; `activate_recipient_policy()`
   raises on a live cooldown, and the second phase of governance
   activation declines to flip (logs, flag stays off) rather than
   raising, so a bad patch can never freeze the chain.
2. `reserved_operation_keys()` raises if both flags are ever set at once.
3. While recipient controls are active, the engine's cooldown feed sites
   skip i16 (`cooldown_active and not recipient_policy_on`), so the two
   feeds can never both drive the stream.

No cleaner free stream exists: every other low index is assigned, and
i26+ is wallet-template custom space — a tag there was tried first (by
#140) and broke shipped templates. Activation also runs
`audit_recipient_stream_collisions` over the complete effective spec:
any in-force rule already reading i17/i16 with a meaning of its own
blocks activation until the owner replaces it.

While the gate is off, an inbound-capable clause cannot deploy at all:
`RECIPIENT_POLICY_INACTIVE` at rule-offer, rule-offer-accept,
o5-routing and rule-change-request time, and the same predicate refuses
the body at apply, so a gate-less node never silently admits a rule
that never runs.

## Capability reporting

`getgovernance` reports `recipient_policy_active` and
`capabilities.recipient_controls` (`active`, `hold_stream: 17`,
`context_stream: 16`, `widths: bv[64]`, contexts, preflight command
`getrecipientpolicy`). `getrecipientpolicy <address>` with no sender
reports active / has-clause / inbound-capable / neutral-default /
escrowed-in, and notes when the gate is off (no evaluation).

## Worked example

Recipient R's clause caps time parks at 600s and height parks at 10
blocks. A sends R a 600-second park → admitted. A sends R a 3600-second
park → refused `RECIPIENT_MAX_HOLD`, `max_hold_seconds=600`, no fee.
A sends R a 600-block park → refused `RECIPIENT_MAX_HOLD`,
`max_hold_blocks=10`. B sends R a plain transfer while R's clause
allows only A inbound → refused `recipient_policy_block`, no fee.

## Tests

`tests/test_recipient_controls.py` — 29 tests, one named test per
acceptance case (#47.1–5, #76.1–6) plus guarded mode, sender-pass
overlay, self-transfer, non-monotonic caps, per-payer caps, unit-blind
and wrong-width deploy refusals, fee-on-block, activation audit,
cooldown mutual exclusion, the memorable moment (height park refused
with the cap while a seconds park passes), sabotage (gate off →
acceptance behaviour disappears), `getrecipientpolicy`, and full
`sendtx.queue_transaction` end-to-end tests.
