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

The policy is an ordinary user rule that writes `o5`. The node registers it as
the sender's own policy clause in a per-account clause registry, and a clause is
evaluated only for transfers sent by its author. The body therefore carries **no
`i12` guard**, and a body referencing `i12` is rejected.

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
  parentheses. See [What registration requires](#what-registration-requires)
  for the other screens.
- **Unfilled slots read `0`**, which never equals an approver pubkey, so a rule
  blocks until a real vote lands.

### Removing a policy

Submitting a clause whose canonical body is exactly the neutral expression
**removes** the author's clause rather than registering one:

```tau
always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

This is sound because "always allow" and "no clause" are semantically identical.
Revoking when no clause is registered is refused at block apply with the receipt
reason `rule_not_applied`.

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
`TX_REJECTED` with `Transaction rejected: the sender's own policy clause blocked
transfer #N`.
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
allows and the request expires with the transfer amount intact (the fee is
spent either way), and over-declaring means
unnecessary notifications but no veto.

## Voting

```bash
tau-testnet approval list --key bot --role in      # the inbox
tau-testnet approval show <request_id>
tau-testnet approval approve <request_id> --key bot
tau-testnet approval decline <request_id> --key bot --reason "not this quarter"
```

`transfer_vote` is **feeless** — it is absent from `FEE_BEARING_TX_TYPES` — so an
approver bot needs no funded account and no fee strategy. `approve` and
`decline` therefore have no `--fee` flag. It is bounded instead
by referencing an open request, being one of that request's declared approvers,
and one vote per approver.

`approval approve --code` deliberately refuses rather than submitting anything:
the code is verified by the bot, not the chain, and the flag exists to say so.

## Lifecycle

`open → executed | expired | failed | cancelled`

| Status | Meaning |
|---|---|
| `open` | At least one required signature outstanding. The fee is already paid; the transfer amount has not moved. |
| `executed` | The rule was satisfied and the parked transfer ran. |
| `failed` | Terminal: every declared approver answered and the policy still blocks, the sender's policy was replaced, `o1` rejected the transfer, or the balance no longer covers it. A single decline is not a veto and does not fail a request. |
| `expired` | `expire_at_height` passed with the rule still blocking. |
| `cancelled` | A rule-change request its sender cancelled; see [Guarding policy changes](#guarding-policy-changes). |

**Nothing is escrowed.** A pending request reserves no balance; if the sender
spends the money elsewhere, execution soft-fails when the last approval arrives
rather than overdrawing. Every failure mode above is a soft no-op — the block
stays valid and replay is deterministic from block bytes. Only a Tau *engine*
failure hard-rejects.

Fees are charged **once, at request time**, from the request's own signed
`fee_limit`; execution charges nothing, so a fee-rule change between request and
approval cannot alter what was authorized. That charge is **not returned** if the
request lapses, is failed by a policy replacement, or fails on release: a
refundable park would make request spam free, and the fee pays for Tau
evaluations and block space the network has already spent. A request whose own
tx cannot pay the fee is not parked at all.

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

Each bot treats rule-change requests differently from transfers; see
[Bots and rule changes](#bots-and-rule-changes).

The scanner needs confirmed chain history, which no RPC serves today
(`commands/history.py` walks mempool rows only), so it self-indexes by walking
`getblocks` from its last-seen height and caching to disk.

## Guarding policy changes

A policy protects transfers, but whoever holds the key can replace the policy and
then send freely. A **rule-change guard** closes that: an optional clause that
decides whether a change to the account's own `o5` policy may happen at once, or
must wait for co-signers. With a guard in place, a stolen key alone cannot change
the policy.

The guard is a clause like any other, registered in the same per-account registry
at the reserved index `0xFFFFFFFF` (`RULE_CHANGE_GUARD_INDEX`) beside the account's
`o5` clause, and removed the same way. It is evaluated only for its author. An
account with no guard behaves exactly as before.

### What the guard reads and writes

The guard writes `o5` (`0` blocks the change, `1` allows it) and reads only:

| Stream | Meaning |
|---|---|
| `i1` | The kind of change, `bv[24]`, from the table below. |
| `i5` | The timestamp of the block that carries the change, as for a transfer. |
| `i18`–`i25` | The approval slots, `bv[384]`: the approver's public key once their signed vote is verified, `0` while empty. |

Any other input, any output other than `o5`, a clause that does not write `o5`, or
a step other than `[t]` is refused at admission. The usual clause screens for
widths and shape apply.

| `i1` | Kind | Change |
|---|---|---|
| 1 | set policy | Register an `o5` clause. |
| 2 | revoke policy | Remove the `o5` clause. |
| 3 | accept offer | Accept a rule offer as the `o5` clause. |
| 4 | set guard | Register or replace the guard itself. |
| 5 | revoke guard | Remove the guard. |

Because the guard is judged on kind 4 and 5 as well, it protects itself: with a
guard in force, replacing or removing it needs the same approvals.

### The two direct doors

Two transactions still change the policy immediately: a `user_tx` carrying an `o5`
rule in operation `0`, and `rule_offer_accept`. Each consults the guard with every
slot empty. If the guard blocks, admission returns `RULE_CHANGE_NEEDS_APPROVAL`,
and block apply records a soft reject with the receipt reason
`rule_change_needs_approval`; nothing changes and the block stays valid. If it
allows, the change executes as before. A guard that allows everything with empty
slots, such as the weaker template below, therefore leaves those kinds open.

### Requests

`rule_change_request` is the way to make a change that the guard parks.

| Field | Notes |
|---|---|
| `kind` | `1`–`5`, as above. |
| `rule_text` | Required for kinds 1 and 4. For kind 3, the exact raw text of the offer. Absent for kinds 2 and 5. At most `MAX_RULE_CHANGE_TEXT_BYTES` (8192). |
| `offer_id` | Kind 3 only: the offer being accepted. |
| `approvers` | Slot to public key, up to 8. A request that names approvers needs approval slots active. May be empty, which leaves the time escape as the only way out. |
| `expire_at_height` | The height after which the request expires. |
| `fee_limit` | Charged once, at request time, as for transfer requests. |

It is the only way to set or revoke a guard. The request id is derived from the
signed fields, so it can be computed before sending, and kind 3 binds the offered
text into the id.

`rule_change_cancel` carries a `request_id`, is signed by the request's sender
and is feeless. It ends an open request as `cancelled`; anyone else's cancel, an
unknown id and an already resolved request are refused at admission
(`NOT_REQUEST_SENDER`, `UNKNOWN_REQUEST`, `REQUEST_RESOLVED`).

With **no guard**, or a guard that allows the change with empty slots, a request
executes in the block that carries it. Otherwise it parks as `open`.

### Votes and READY

An approver answers with the same `transfer_vote` as for a transfer request, on
the rule-change request id; the declared approvers and the one-vote rule are
unchanged. A request is **ready** when the guard in force now allows the change
with the slots filled so far. That is evaluated when the request is applied and at
every approving vote. A decline records a refusal and fills nothing.

A ready request is written by the **end-of-block release sweep**, in the block that
made it ready. The sweep releases ready requests in id order, at most
`MAX_RULE_CHANGE_RELEASES_PER_BLOCK` (8) per block; the rest wait for the next
block. Each release re-screens the body, builds the clause, and writes the registry.
The guard that judges a vote is the one in force at that vote, so replacing the
guard changes what an existing request needs.

### The time escape

A request that is still `open` becomes ready on its own `RULE_CHANGE_DELAY_BLOCKS`
(1000) blocks after it was mined, whatever the slots hold, and the sweep then
releases it. This is the way out when an approver is lost or unwilling: without it,
a guard naming a key nobody holds would freeze the policy for good. The cost is
that a thief who cannot get approvals can also wait the delay out, which gives the
owner that long to notice and cancel.

A request that expires before its escape height expires without releasing. The CLI
therefore defaults `--expire-in` to 2000 blocks, twice the delay, so a request it
sends can use the escape, and warns when a shorter window rules it out. The window
is capped by `MAX_APPROVAL_WINDOW_BLOCKS`.

### Cancel and the owner/thief stalemate

The owner and a thief hold the same key, so both can request and both can cancel.
Neither can force a change through: the thief's request parks until an approver
votes or the delay passes, and the owner can cancel it in that time, and the other
way round. An approver is the tie-breaker, and an approval
that arrives for a request the sender has cancelled does nothing. A cancel removes
only the request it names: a thief can request again, and the owner can cancel
again.

### What a release does

A successful release writes the registry and then ends other requests that the
change makes stale:

| Kind released | Also fails (`failed`) |
|---|---|
| 1, 2, 3 | The sender's open transfer requests, as any policy replacement does. Rule-change requests are untouched. |
| 4, 5 | The sender's other open rule-change requests, which were judged by a guard that no longer exists. Transfer requests are untouched. |

A release can also fail: the body no longer passes the screen or does not build, a
revoke finds nothing to revoke, or an offered rule was accepted, rejected or has
expired in the meantime. The request becomes `failed`, nothing is
written, no sibling is failed, and the block stays valid; every node reaches the same
result. Admission builds a request's clause before queueing the request; the release
builds it again, and a failure there fails the request without failing the block.

### Limits

A sender's open transfer requests and open rule-change requests share the cap of
`MAX_PENDING_REQUESTS_PER_SENDER` (8); more is refused with `TOO_MANY_REQUESTS`.
The release sweep writes at most `MAX_RULE_CHANGE_RELEASES_PER_BLOCK` (8) requests
per block, and a request that fails counts toward that cap.

### Inspecting

- `getapprovalrequests <address> [in|out|all]` and `getapprovalrequest <id>` return
  rule-change requests alongside transfer requests. A rule-change row has
  `request_type: "rule_change"`, `kind`, `kind_name`, `body` (for kind 3, the exact
  offered text), `body_hash`, `offer_id`, `approvers` with each slot's state
  (`awaiting`, `approved`, `declined`), `voted`, `declined`, `ready`,
  `created_height`, `escape_height`, `expire_at_height` and `status`
  (`open`, `executed`, `expired`, `failed` or `cancelled`).
- `getapprovalpreview` accepts `"request_type": "rule_change"` with `kind`,
  `rule_text`, `offer_id` and `approvers`, and reports whether the change would
  execute at once, which approvers it needs, the screen result and the escape
  delay. It is advisory and node-local.
- `getruleoffers <address>` and `getapprovalslots <address>` return the account's
  guard as `rule_change_guard`; the guard is not listed with the account's
  `accepted_clauses`.

### CLI

```bash
tau-testnet policy guard set    --key alice --file guard.tau --approver 18=<xpub> [--expire-in N]
tau-testnet policy guard revoke --key alice [--approver SLOT=PUBKEY ...]
tau-testnet policy guard show   [<address>]
tau-testnet policy change request --key alice --kind set    --file policy.tau --approver 18=<xpub>
tau-testnet policy change request --key alice --kind revoke --approver 18=<xpub>
tau-testnet policy change request --key alice --kind accept --offer-id <offer_id> --approver 18=<xpub>
tau-testnet policy change cancel  --key alice --request-id <request_id>
```

`--body` takes the clause text inline instead of `--file`. Each request command
accepts `--preview` (ask the node what it would need and send nothing),
`--dry-run` (sign and print), `--fee`, `--expire-in` (default 2000) and
`--expire-at-height`, and prints the request id. `--kind accept` fetches the offered
text from the node, which keeps it only as node-local data.

### Bots and rule changes

A rule change is never decided by a transfer criterion:

- `approval_bot_totp.py` approves only with a valid code for that request, sent to
  its endpoint. There is no on-chain code path and no amount or recipient test.
- `approval_bot_partner.py` skips rule changes unless started with
  `--allow-rule-changes`, and then asks a human at the terminal. `--yes` never
  applies to them, and with no terminal the request is deferred.
- `approval_bot_scan.py` shows rule changes and never approves one: an automatic
  co-signer would approve whatever a thief submits.

### Wallet templates

The web wallet's Policy Change Request panel and the guard templates in its
editor menu cover three guards. Replace each placeholder key with the co-signer's
96-character public key hex and declare the approvers for the slots shown.

| Template | Slots | Effect |
|---|---|---|
| Any policy change needs co-signer X | `i18` | Every kind is blocked until X has voted. |
| 2 of 3 co-signers for any policy change | `i18`, `i19`, `i20` | Every kind is blocked until any two of the three have voted. |
| Revoking needs a co-signer (weaker) | `i18` | Only revoking a policy (kind 2) or a guard (kind 5) is blocked. Setting a policy, accepting an offer and setting a guard are allowed with no approval. |

The weaker template does **not** stop a thief: they can replace the policy with a
permissive one, or replace the guard itself, and then drain the account. Use it
only to stop accidental or lone revocations.

## Stream and slot map

| Stream | Width | Role |
|---|---|---|
| `i1` | `bv[24]` | transfer amount |
| `i3` / `i4` | `bv[384]` | sender / recipient pubkey |
| `i12` | `bv[384]` | sender pubkey — set by the node; a clause body must not reference it |
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
Per-stream bitvector typing is process-global and sticky, so an inferred width
could make a clause's build depend on what else the process has built. An
unannotated slot mention is therefore rejected outright, and every mention must
carry the same explicit width. Clauses are built in separate policy worker
processes, never in the interpreter that holds the consensus rules.

## What registration requires

The same screens run at admission and at block apply, for a clause submitted as
the sender's own `o5` rule and for an offered or accepted one. A body must:

- be exactly one `always ( … ).` unit in the admitted rule syntax
  (`RULE_FRAGMENT` otherwise: typed bitvector comparisons joined by `!`, `&&`,
  `^^`, `||`, `->`, `<-`, `<->` and `? :`, no quantifiers or
  definitions), and not reference `i12`;
- reference the current step `[t]` only (`TEMPORAL_REFERENCE` otherwise);
- write every stream mention as `xN[t]:bv[W]` with an explicit width and use one
  width per stream within the body; `o5` is `bv[24]` (`WIDTH_MISMATCH`
  otherwise) and the approval slots are `bv[384]`;
- write `o5` and no other output stream, and no consensus-owned stream;
- not reference the reserved input streams `i13`–`i15`;
- stay within `MAX_CLAUSE_COMPARISONS` comparisons, `MAX_CLAUSE_DEPTH` levels of
  parentheses and `MAX_OFFER_RULE_BYTES` bytes.

A clause may read `i1` (amount), `i2` (sender balance at the parent block),
`i3`/`i4` (sender and recipient pubkeys), `i5` (block timestamp), the approval
slots and custom inputs. Custom inputs for a clause start at `i26`.

Registration also requires that the engine can build the clause and step it
once. A clause that does not build, or that reads no input stream (a constant
such as an unconditional block), is refused: `TX_REJECTED` at admission, and a
hard reject with the receipt reason `rule_not_applied` at block apply. To block
everything, write a condition on an input, such as amount above zero:

```tau
always ( (i1[t]:bv[24] > { #x000000 }:bv[24])
    ? (o5[t]:bv[24] = { #x000000 }:bv[24])
    : (o5[t]:bv[24] = { #x000001 }:bv[24]) ).
```

A registered clause judges a transfer together with the consensus rules: the
transfer is blocked when the main interpreter yields `o5 = 0` or the sender's
clause yields `o5 = 0` on the same inputs. An account with no clause adds
nothing. The check runs at admission, at block apply (ordinary and parked
transfers alike) and in the approval preview. If the engine refuses to evaluate
a registered clause for particular inputs, for example a value that does not fit
the width the clause declared for that stream, the transfer is blocked.

## Limits

| Constant | Value | Notes |
|---|---|---|
| `MAX_CLAUSE_COMPARISONS` | `32` | Comparison operators in one clause body. |
| `MAX_CLAUSE_DEPTH` | `32` | Levels of parentheses in one clause body. |
| `MAX_OFFER_RULE_BYTES` | `8192` | Size of a clause's rule text. |
| `MAX_APPROVERS_PER_REQUEST` | `8` | Tiers use three; the rest are spare. |
| `MAX_PENDING_REQUESTS_PER_SENDER` | `8` | Shared by a sender's open transfer requests and open rule-change requests. |
| `MAX_RULE_CHANGE_TEXT_BYTES` | `8192` | Size of a rule-change request's `rule_text`. |
| `RULE_CHANGE_DELAY_BLOCKS` | `1000` | Blocks after which an open rule-change request is ready with no approvals. |
| `MAX_RULE_CHANGE_RELEASES_PER_BLOCK` | `8` | Rule-change requests the end-of-block sweep writes per block. |
| `RULE_CHANGE_GUARD_INDEX` | `0xFFFFFFFF` | Registry index of an account's rule-change guard. |
| `MAX_APPROVAL_WINDOW_BLOCKS` | `10_000` | CLI `--expire-in` defaults to `1000`. |
| `MAX_CUSTOM_INPUTS_PER_REQUEST` | `8` | Indices ≥ 26. |
| `MAX_CUSTOM_INPUT_BYTES` | `256` | Per entry. |
| `MAX_VOTE_REASON_BYTES` | `256` | Signed and merkle-covered, but excluded from the approval-state root. |
| `MAX_PREVIEW_SLOTS` | `6` | Above this, `getapprovalpreview` returns `unavailable`. |

Nothing limits how many accounts hold a clause. The per-block rule budget
(`max_rule_txs_per_block`) counts every rule-offer transaction and every user
transaction carrying a rule in `operations["0"]`, whether it registers an `o5`
clause or joins the shared specification. Clauses are not part of the shared
rule budget (`RULE_BUDGET`, see the README).

### Cost

Measured on the reference engine build, so approximate. A transfer from an
account that has a clause costs one clause evaluation: about 3 ms for a small
clause and about 10 ms at the 32-comparison limit. Building a clause on first use
takes about 0.07 s at 8 comparisons and about 0.4 s at 32. None of these depends
on how many accounts hold clauses.

## Error codes

| Code | Cause |
|---|---|
| `FEATURE_INACTIVE` | The chain does not have approval slots activated. |
| `CLAUSE_SHAPE` | The rule is not exactly one `always ( … ).` unit, nests a temporal operator, or its body references `i12`. |
| `WIDTH_MISMATCH` | `o5` (or an `o8` rule's `o8`) is untyped or typed at a width other than `bv[24]`. Other width violations in a clause are reported as `TX_REJECTED`. |
| `TEMPORAL_REFERENCE` | The rule or clause body reads a step other than the current one (`i1[t-1]`, `i1[0]`). User rules reference `[t]` only. |
| `RULE_FRAGMENT` | The rule or clause body uses syntax outside the admitted rule syntax (see [What registration requires](#what-registration-requires)). |
| `RULE_BUDGET` | A rule that joins the shared specification exceeds one of the shared rule limits (rule size, depth, bytes, width, or the occurrence and node totals). It does not apply to `o5` clauses. |
| `UNSCOPED_USER_RULE` | An `o8` fee rule that is not exactly `always ( (i12[t]:bv[384] = { #x<sender pubkey> }:bv[384]) -> ( ... ) ).` with the submitting account's own key. It does not apply to `o5` rules. |
| `MIXED_OUTPUT_RULE` | The rule writes `o5` and something else. |
| `RULE_WITH_TRANSFERS` | A routed `o5` rule shares a `user_tx` with transfers. Admission would judge those transfers against the policy being replaced. |
| `TOO_MANY_REQUESTS` | `MAX_PENDING_REQUESTS_PER_SENDER` reached. |
| `DUPLICATE_REQUEST` | A request with this id already exists. |
| `NOT_AN_APPROVER` | The voter is not one of the request's declared approvers. |
| `ALREADY_VOTED` | One vote per approver, and it is final. |
| `REQUEST_EXPIRED` | `expire_at_height` passed before the vote. |
| `REQUEST_RESOLVED` | Already `executed` or `failed`. |
| `UNKNOWN_REQUEST` | No such request id. |
| `RULE_CHANGE_NEEDS_APPROVAL` | The sender's rule-change guard blocks a direct `o5` change (op-0 rule or offer accept) with empty slots. Block apply gives the receipt reason `rule_change_needs_approval`. |
| `INVALID_RULE_CHANGE_REQUEST` | A `rule_change_request` is malformed, its body fails the screen or does not build, its precondition fails (nothing to revoke, or the offer is not open, not addressed to the sender, or its text does not match), or it names approvers while approval slots are inactive. |
| `INVALID_RULE_CHANGE_CANCEL` | A `rule_change_cancel` is malformed. |
| `NOT_REQUEST_SENDER` | Only the request's sender may cancel it. |

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
request's content and reads no chain state), and slots are neither reserved nor
fed. `o5` rules register as clauses whether or not the feature is active.

**A fresh genesis is the recommended path** — `scripts/gen_genesis.py` emits the
flag and the slot reservation from block 0. Upgrading a live chain uses a
two-phase protocol that is deliberately non-halting: raising inside
`apply_host_contract_patch` at the activation height would make every block at
and after that height invalid, a permanent freeze. Instead a *reserve* phase
validates against the current effective restore plan at admission, and at the
activation height the audit re-runs; failure records a hash-bound
`activation_failed` outcome and leaves the field `False`. Every node computes the
same outcome, the block stays valid, and the chain continues unactivated.

The audit covers the **complete effective spec** — consensus rules, builtin
rules, application rules and stored clause bodies — because a stream-typing
collision anywhere in it poisons the whole process. An `o5` rule in the
accumulated application rules blocks activation: it would keep writing `o5` on
the main interpreter beside the registered clauses, so a sender could be blocked
by a rule the registry does not show.

## Signature verification

Every transaction signature is verified twice: at mempool admission, and again at
block apply. Without the apply check a malicious proposer could include a
transfer from any account, or a `user_tx` carrying a victim's `o5` rule, a
`rule_offer_accept` from the victim, or a vote in an approver's name, and then let
a legitimate vote execute under an attacker-chosen policy. Splitting one theft
into many small forged transfers in one block would also dodge per-transaction
tier policies, which read balances and history frozen at the parent block.

`consensus/tx_signing.py` holds the canonical `signing_message_bytes` and
`verify_tx_signature`, imported by both `commands/sendtx.py` and `engine.apply`.
`apply` verifies **every** transaction of **every** type at one site, at the top of
the per-transaction loop, before the fee preamble, any Tau step or any state
mutation. The check is not gated on approval-slot activation and it runs in replay
too, because the state hash binds a transaction as rejected.

A failure sets `hard_reject`: the transaction lands in `rejected_transactions`
with the receipt reason `invalid_signature`, its effects are discarded (no fee, no
sequence bump, no lifecycle change) and the **block stays valid**. Every node
reaches that verdict from the block bytes alone.

## Not in this release

- **Balance locking / escrow.** A pending request reserves nothing.
- **Cancelling a transfer request.** Expiry only, plus policy replacement, which
  fails the sender's own open requests. Rule-change requests can be cancelled.
- **Weighted or threshold-of-N voting** ("any two of three") as a shipped
  template. The form itself works — a within-step disjunction of conjunctions
  over the slots expresses it, and does not need cross-step accumulation — but
  it costs `C(M,N)` terms, so the 32-comparison clause limit and the 8192-byte
  `TAU_MAX_USER_TX_BYTES` gossip cap put the practical ceiling near `M<=5` at
  `N=3`. Nothing ships to help you write one.
- **Approvers attaching data**, beyond the decline reason.
- **Real Google Identity / OAuth.** The bot is Google-Authenticator-compatible
  TOTP, which is the actual mechanism; no Google API is contacted.
- **A confirmed-history RPC** for the scanner, which self-indexes instead.
- **Migrating raw `o5` rules.** The audit reports an `o5` rule in the
  accumulated application rules and blocks activation; clearing it is an
  operator action.

Without a rule-change guard, nothing here protects a stolen key: an attacker
holding it can replace the policy and then send freely. A guard changes that for
policy changes, as long as its approvers keep their keys and it blocks every kind
with empty slots; it is not a recovery mechanism for funds already moved.
