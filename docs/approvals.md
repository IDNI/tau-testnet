# Co-signature approvals

A user can require that their own high-value transfers be co-signed before they
execute. The sender deploys one ordinary user rule naming an amount threshold and
an approver per tier; a transfer above a threshold is submitted as an
**approval request**, parks on-chain, and executes by itself the moment the
sender's own rule is satisfied. Transfers below the first threshold are
unaffected, and nobody is notified about them.

The mechanism is the existing user-policy stream `o5` plus eight
write-reserved approval slots (`i18`–`i25`) that only the node fills, and only
from a verified vote. Approvals are unavailable unless the chain has them
activated — see [Activation](#activation).

Protocol details and the raw command grammar: [developer_cli.md](developer_cli.md).

## What the sender writes

The policy is an ordinary user rule routed into the clause registry, so it is
automatically scoped to its author. The body carries **no `i12` guard** — the
node supplies the sender guard when composing the per-stream composite, and a
body referencing `i12` is rejected.

```tau
always ( ( (i1[t]:bv[24] > { #x0186a0 }:bv[24] && !(i20[t]:bv[384] = { #x<PARTNER> }:bv[384]))
        || (i1[t]:bv[24] > { #x002710 }:bv[24] && !(i19[t]:bv[384] = { #x<SCANNER> }:bv[384]))
        || (i1[t]:bv[24] > { #x0003e8 }:bv[24] && !(i18[t]:bv[384] = { #x<AUTHBOT> }:bv[384])) )
    ? (o5[t]:bv[24] = { #x000000 }:bv[24])
    : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

Each disjunct reads "this tier applies **and** its approver has not signed". Any
true disjunct blocks, so requirements accumulate: a transfer over the third
threshold must satisfy all three lines. Deploy it as a normal rule-bearing
transaction:

```bash
tau-testnet tx send --key alice --rule-file policy.tau
```

Notes that matter in practice:

- **Flat disjunction, not a nested cascade.** Measured on the native engine, the
  flat form builds ~2.5x faster for identical semantics.
- **Comments use `#`, not `//`.** `#` comments are stripped during clause
  canonicalization (`#x`/`#b` bitvector literals are preserved); `//` is not
  Tau syntax and leaves the rule unparseable as a single `always` unit.
- **The rule must be exactly one `always ( … ).` unit.** `clause_body_v1`
  rejects anything else, including two units smuggled in via unbalanced
  parentheses.
- **Unfilled slots read `0`**, which never equals an approver pubkey, so a rule
  blocks until a real vote lands.

### Removing a policy

Submitting a clause whose canonical body is exactly the neutral expression
**removes** the author's clause rather than registering one, freeing an author
slot:

```tau
always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

This is sound because "always allow" and "no clause" are semantically identical,
and it is the registry's release valve — without it the first `MAX_TIER_AUTHORS`
accounts would occupy every slot permanently.

**Replacing or removing a policy resolves all of that sender's open requests as
`failed`, atomically, in the same block, before the replacement takes effect.**
Signatures already collected were given against the old rule and are not carried
over.

## Sending

Below the first threshold nothing changes:

```bash
tau-testnet tx send --key alice --to <pubkey> --amount 500
```

Above a threshold the sender's own policy rejects an ordinary transfer at
admission. There is no dedicated error code for this — it surfaces as
`TX_REJECTED` with `Transaction rejected by user policy (o5) for transfer #N`.
Submit it as an approval request instead:

```bash
tau-testnet approval request --key alice --to <pubkey> --amount 50000 --auto
```

`--auto` asks the node which approvers this particular amount requires, so a
client with no local knowledge of the sender's tiers does not have to
over-declare. Explicit `--approver <slot>=<pubkey>` flags always win.

The sender may attach data an approver can read:

```bash
tau-testnet approval request --key alice --to <pubkey> --amount 50000 --auto \
    --input 26="Q3 rent, approved by finance" --yes
```

Custom inputs are indices **≥ 26**, above the slot block. They are
**public and permanent** and are covered by the request id, hence the `--yes`
confirmation. A TOTP code does not belong here — six digits on-chain is
brute-forceable for its whole validity window; send it to the auth bot's own
endpoint instead.

### Declaration is routing, not authority

Naming an approver decides whose inbox is filled and which slot their vote lands
in. The **rule** decides what is required. So a decline records a refusal to
fill one slot; it does not resolve the request. A needed approver's refusal
blocks naturally, because the rule requires their slot; an over-declared
approver's refusal does not, and the transfer still executes once whoever *was*
required has signed.

Both error directions land on the sender: under-declaring means the rule never
allows and the request expires with funds intact, and over-declaring means
unnecessary notifications but no veto.

## Voting

```bash
tau-testnet approval list --key bot --role in      # the inbox
tau-testnet approval show <request_id>
tau-testnet approval approve <request_id> --key bot
tau-testnet approval decline <request_id> --key bot --reason "not this quarter"
```

`transfer_vote` is **feeless** — it is absent from `FEE_BEARING_TX_TYPES` — so an
approver bot needs no funded account and no fee strategy. It is bounded instead
by referencing an open request, being one of that request's declared approvers,
and one vote per approver.

`approval approve --code` deliberately refuses rather than submitting anything:
the code is verified by the bot, not the chain, and the flag exists to say so.

## Lifecycle

`open → executed | expired | failed`

| Status | Meaning |
|---|---|
| `open` | At least one required signature outstanding. No balance has moved. |
| `executed` | The rule was satisfied and the parked transfer ran. |
| `failed` | Terminal: a required approver declined, the sender's policy was replaced, `o1` rejected the transfer, or the balance no longer covers it. |
| `expired` | `expire_at_height` passed with the rule still blocking. |

**Nothing is escrowed.** A pending request reserves no balance; if the sender
spends the money elsewhere, execution soft-fails when the last approval arrives
rather than overdrawing. Every failure mode above is a soft no-op — the block
stays valid and replay is deterministic from block bytes. Only a Tau *engine*
failure hard-rejects.

Fees are charged **once, at request time**, from the request's own signed
`fee_limit`; execution charges nothing, so a fee-rule change between request and
approval cannot alter what was authorized.

## Inspecting

```bash
tau-testnet approval slots --key alice                                   # slot -> approver
tau-testnet approval preview --key alice --to <pubkey> --amount 50000    # who would this need?
tau-testnet approval list --key alice --role out                         # requests you sent
tau-testnet approval request-id --from-pubkey … --to … --amount … \
    --sequence … --expire-at-height …                                    # derive an id offline
```

`approval slots` and `approval preview` are backed by `getapprovalslots` and
`getapprovalpreview`, both marked **advisory** like `getruleconflict`: they are
node-local, touch no consensus path, and `getapprovalslots` is the only place
rule text is inspected. An unreadable clause returns an empty map and the client
falls back to explicit flags.

`getapprovalpreview` takes the **complete draft** — recipient, amount, custom
inputs, candidate slots — not just an amount, because an `o5` rule may
legitimately depend on `i2`, `i4`, `i5` or a custom input. It enumerates all
`2^N` subsets of the candidate slots and returns the smallest that allows, ties
broken by lowest slot index; a greedy `1 + N` probe is unsound for a rule that is
not monotone in approvals. Above `MAX_PREVIEW_SLOTS` it returns `unavailable`
rather than a wrong answer.

## Approver bots

Three reference approvers ship in `scripts/`, sharing a poll/sign/submit client
in `approval_bot_common.py`:

| Script | Role |
|---|---|
| `approval_bot_totp.py` | RFC 6238 TOTP, byte-compatible with Google Authenticator, from the standard library only. `--enroll <pubkey>` prints an `otpauth://` URI. |
| `approval_bot_scan.py` | Deterministic risk heuristics (unseen recipient, amount versus trailing average, velocity, tier jump, denylist). `--llm` additionally requires a model verdict. |
| `approval_bot_partner.py` | Watcher daemon for a human approver: surfaces requests naming the partner, shows the attached comment, signs only on explicit confirmation. |

The TOTP bot's code endpoint is loopback-only by default and takes one JSON line:

```bash
printf '{"request_id":"<id>","code":"123456"}\n' | nc 127.0.0.1 65440
```

It replies `{"status": "ok", "detail": "accepted; the vote will be cast on the
next poll"}`. Codes are one-time-use bound to `(sender, time_step)`, so a code
cannot be replayed onto a second request inside its own validity window.
Hardening is default-on: loopback bind (`--bind` widens it, with a startup
warning), a per-source token bucket, and a `0600` secrets file inside a `0700`
directory that the bot refuses to start on looser modes.

The scanner needs confirmed chain history, which no RPC serves today
(`commands/history.py` walks mempool rows only), so it self-indexes by walking
`getblocks` from its last-seen height and caching to disk.

## Stream and slot map

| Stream | Width | Role |
|---|---|---|
| `i1` | `bv[24]` | transfer amount |
| `i3` / `i4` | `bv[384]` | sender / recipient pubkey |
| `i12` | `bv[384]` | sender pubkey — supplied by the composer, never by a clause body |
| `i18`–`i25` | `bv[384]` | approval slots: node-written, clause-readable, `0` = no vote |
| `i26`+ | — | sender custom inputs |
| `o5` | `bv[24]` | user policy: `0` blocks, `1` or absent allows |

The slots are **write-reserved and read-permitted**, which is the whole point: a
sender who could write them would forge their own approvals. Concretely,
`reserved_operation_keys()` governs `operations` keys at every ingest site, while
`rule_text_forbidden_input_streams(context)` governs rule text, and the two
differ:

| Context | Slots |
|---|---|
| `operations` keys, any transaction | never — reserved |
| a registered `o5` clause | readable, every occurrence at exactly `bv[384]` |
| any other user rule text | forbidden |
| consensus revisions | forbidden, permanently |

**Slot width is pinned at `bv[384]` by a strict reject-unless-annotated screen.**
Per-stream bitvector typing is process-global and sticky: if one rule types
`i18` as `bv[384]` and another as `bv[24]`, `get_interpreter` returns `None` for
everyone until the process restarts. An unannotated slot mention is therefore
rejected outright, admission compiles offered rule text in an isolated
subprocess before it can reach the live interpreter, and the engine fails closed
if one ever got through.

## Limits

| Constant | Value | Notes |
|---|---|---|
| `MAX_TIER_AUTHORS` | `2` | Policy authors on `o5`, **network-wide**. A measured ceiling, not a quota — see below. |
| `MAX_APPROVERS_PER_REQUEST` | `8` | Tiers use three; the rest are spare. |
| `MAX_PENDING_REQUESTS_PER_SENDER` | `8` | |
| `MAX_APPROVAL_WINDOW_BLOCKS` | `10_000` | CLI `--expire-in` defaults to `1000`. |
| `MAX_CUSTOM_INPUTS_PER_REQUEST` | `8` | Indices ≥ 26. |
| `MAX_CUSTOM_INPUT_BYTES` | `256` | Per entry. |
| `MAX_VOTE_REASON_BYTES` | `256` | Signed and merkle-covered, but excluded from the approval-state root. |
| `MAX_PREVIEW_SLOTS` | `6` | Above this, `getapprovalpreview` returns `unavailable`. |

`MAX_TIER_AUTHORS = 2` is the load-bearing limit and is measured, not guessed.
Interpreter rebuild time grows roughly eightfold per additional policy author —
about 2.5s at one, 13–22s at two, 110s at four — against a 60s `COMM_TIMEOUT`
with a watchdog SIGKILL past it. Any design carrying per-user policy as rule
text dies at four authors. Width is *not* a lever here: `tau_shrink` interns
pubkey literals to `bv[8]`, so a `bv[384]` slot comparison costs the same as
`bv[24]`. The driver is conditional depth times comparisons per level.

## Error codes

| Code | Cause |
|---|---|
| `FEATURE_INACTIVE` | The chain does not have approval slots activated. |
| `CLAUSE_SHAPE` | The clause body references `i12`, writes more than one output stream, nests a temporal operator, or is not one `always` unit. |
| `UNSCOPED_USER_RULE` | An unguarded `o5` rule on a chain without activation, where the guarded form is still expected. |
| `MIXED_OUTPUT_RULE` | The rule writes `o5` and something else. |
| `RULE_WITH_TRANSFERS` | A routed `o5` rule shares a `user_tx` with transfers. Admission would judge those transfers against the policy being replaced. |
| `CLAUSE_REGISTRY_FULL` | `MAX_TIER_AUTHORS` author slots are taken. An existing author frees one with the neutral clause. |
| `TOO_MANY_REQUESTS` | `MAX_PENDING_REQUESTS_PER_SENDER` reached. |
| `DUPLICATE_REQUEST` | A request with this id already exists. |
| `NOT_AN_APPROVER` | The voter is not one of the request's declared approvers. |
| `ALREADY_VOTED` | One vote per approver, and it is final. |
| `REQUEST_EXPIRED` | `expire_at_height` passed before the vote. |
| `REQUEST_RESOLVED` | Already `executed` or `failed`. |
| `UNKNOWN_REQUEST` | No such request id. |

## Activation

`approval_slots_active` is **consensus state, not a module flag**. It is a
one-way boolean field on `ConsensusLifecycleManager`, persisted, folded into
`consensus_meta_hash()`, exposed on both `ActiveConsensusView` and the tip
admission view, and read from the *parent* snapshot — so an activation recorded
in block *H* governs *H+1* onward and never changes the meaning of the block
that carried it.

A module global would not work: `engine.apply` does
`lm = copy.deepcopy(parent_lm)` so each candidate block simulates against an
isolated manager, and a global sits outside that copy and leaks across candidate
simulation, rollback and reorg.

Before activation the feature is invisible: both transaction types are rejected
at admission and are no-ops at apply, the four state-reading RPCs return
`FEATURE_INACTIVE` (`getrequestid` is exempt — it is a pure function of the
request's content and reads no chain state), slots are neither reserved nor
fed, and `o5` rules are appended exactly as before. State is byte-identical to a node without the feature.

**A fresh genesis is the recommended path** — `scripts/gen_genesis.py` emits the
flag and the slot reservation from block 0. Upgrading a live chain uses a
two-phase protocol that is deliberately non-halting: raising inside
`apply_host_contract_patch` at the activation height would make every block at
and after that height invalid, a permanent freeze. Instead a *reserve* phase
validates against the current effective restore plan at admission, and at the
activation height the audit re-runs; failure records a hash-bound
`activation_failed` outcome and leaves the field `False`. Every node computes the
same outcome, the block stays valid, and the chain continues unactivated.

The audit covers the **complete restore plan** from
`chain_state.get_tau_restore_plan()` — consensus rules, genesis and builtin
rules, application rules, stored clause bodies, and derived composites — because
a stream-typing collision anywhere in the effective spec poisons the whole
process. Legacy raw `o5` writers block activation rather than being
grandfathered: the first derived composite would become a second total-form unit
on `o5` beside them, which either fails to conjoin or silently supersedes.

## Signature verification

Per-transaction signatures were historically verified only at mempool admission;
`_process_new_block_locked` checks the header proof, `verify_block_header` and
the timestamp, and `engine.apply` did not check signatures at all. Verifying
only the two new transaction types would be insufficient — after activation a
malicious proposer could forge a transaction that *sets policy* (a `user_tx`
carrying the victim's `o5` rule, or a `rule_offer_accept` from the victim),
replace their clause, and then let a legitimate vote execute under an
attacker-chosen policy.

`consensus/tx_signing.py` holds the canonical `signing_message_bytes` and
`verify_tx_signature`, imported by both `commands/sendtx.py` and `engine.apply`.
`apply` verifies, before any state mutation and **height-gated on activation** so
historical replay is untouched:

- `approval_request` and `transfer_vote`;
- post-activation `user_tx` routed into the `o5` registry;
- post-activation `rule_offer_accept`.

A failure sets `hard_reject`: the transaction lands in `rejected_transactions`,
its effects are discarded, and the **block stays valid**. Every node reaches that
verdict from the block bytes alone.

## Not in this release

- **Balance locking / escrow.** A pending request reserves nothing.
- **Sender-initiated cancel.** Expiry only, plus policy replacement, which fails
  the sender's own open requests.
- **Weighted or threshold-of-N voting** ("any two of three"). The disjunction
  expresses ordered requirements, not counting; Tau has no cross-step
  accumulation.
- **Approvers attaching data**, beyond the decline reason.
- **Real Google Identity / OAuth.** The bot is Google-Authenticator-compatible
  TOTP, which is the actual mechanism; no Google API is contacted.
- **A confirmed-history RPC** for the scanner, which self-indexes instead.
- **Migrating legacy raw `o5` writers.** The audit reports them and blocks
  activation; clearing them is an operator action.

Nothing here protects a stolen key: an attacker holding it can replace the policy
and then send freely. This raises the bar on a single mistaken or coerced
transfer; it is not a recovery mechanism.
