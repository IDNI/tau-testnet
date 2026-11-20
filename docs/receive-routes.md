# Receive routes

A receive route sends a fixed share of everything an account receives to
another address. The split happens inside the node, in the same atomic write
as the credit: the recipient does not need to be online, and a sender cannot
avoid it, because the sender still signs "send gross to the recipient" and the
node applies the route when it writes that credit.

Typical uses are a standing savings sweep, a revenue share with a partner, or a
binding payout to a counterparty for a fixed period (a **locked** route).

Short reference: [README](../README.md#receive-routes). CLI summary:
[developer_cli.md](developer_cli.md#receive-routes). This guide is the long
form.

## The split

```
gross  = the amount the sender signed
routed = floor(gross * bps / 10000)
net    = gross - routed
```

`net` goes to the route's owner and `routed` to its destination. The two always
sum to `gross`. A 20% route (2000 bps) on a credit of 101 routes 20 and leaves
81. When `routed` rounds down to 0, or `gross` is below the route's
`min_amount`, the credit is left whole.

Routing is **single-hop**: the routed share is written straight to the
destination and never triggers the destination's own route. Two accounts that
route to each other still route each credit once.

## Which credits are routed

| Credit | Routed |
|---|---|
| Ordinary transfer (every leg of a `user_tx`, from any sender) | yes |
| Co-signed transfer, when its approval executes it | yes |
| Retractable transfer, when it releases (a claimed payment) | yes, by the route in force in the release block |
| Retract refund to the sender | no |
| Faucet grant, genesis allocation | no |
| Fees and proposer rewards | no |
| The routed share itself | no (single hop) |

A route applies to a credit only while it is **active** at the block's
timestamp: from `active_from_time` (if set) up to, but not including,
`expires_at_time` (if set). A locked route also waits out its notice period
(below) before it routes anything.

## Installing, replacing and clearing

Each account has at most one route. `receive_route_set` installs it or replaces
the current one; `receive_route_clear` removes it.

| Action | Who | When |
|---|---|---|
| Install or replace | the owner | unless the current route's lock holds |
| Clear | the owner | unless the route's lock holds |
| Clear (release) | the route's destination | always: it only gives up its own share |
| Removal at expiry | nobody (end-of-block sweep) | the first block at or after `expires_at_time` |

A **locked** route must have `expires_at_time`, more than 7 days and at most 3
years after the block it is installed in. It then has a **notice period**: for 7
days after install it neither routes nor binds, and the owner can still clear or
replace it. From the end of the notice period (or `active_from_time`, if later)
until it expires, the lock holds: the owner can neither replace nor clear it, and
only its destination can release it early. Replacing a route starts a new notice
period.

The notice period is what stops a stolen key from capturing years of future
receipts with one transaction: the owner has 7 days to see the route
(`getaccountstate`, `getreceiveroute`, or the warning the web wallet shows on
the account; the route reports `binds_from_time`) and remove it, and nothing is
routed meanwhile. The chain cannot tell the owner from someone holding the
owner's key, so the owner's own locked routes wait too; a route that is not
locked starts at once, since the owner can always clear it. The node stamps the install time
(`installed_at_time`) from the block that installs the route; for a parked
request that is the block that releases it.

Both transactions pay the ordinary transaction fee. A change that is refused
when the block applies it pays nothing.

## The rule-change guard

An owner with a rule-change guard has the guard consulted for route changes,
with kind **6** (set route) and **7** (owner clears route) on `i1`, exactly as
it is for o5 policy changes. A destination releasing a route is not the owner's
change, so the owner's guard is not consulted for it.

When the guard blocks a direct `receive_route_set` or `receive_route_clear`, the
error is `RULE_CHANGE_NEEDS_APPROVAL`. The owner then **parks** the same change
as a `rule_change_request`, which approvals or the time escape release like any
other kind:

```bash
tau-testnet route set --key bob --to <pk> --percent 20 --request \
    --approver 18=<carol_pk> --approver 19=<dave_pk>
tau-testnet route clear --key bob --request --approver 18=<carol_pk>
```

In the web wallet, the same request is the **Policy change request** panel with
kind 6 (**Set receive route**, with a route spec in the text box and templates to
start from) or kind 7 (**Clear receive route**). The wallet checks the spec
before signing.

| Kind | `rule_text` |
|---|---|
| 6, set receive route | a route spec (below) |
| 7, clear receive route | empty |

The route spec is one line of `key=value` fields after a tag, in canonical
decimal (no leading zeros):

```
receive_route_v1 destination=<96 hex> bps=<1..9000> min_amount=<n> active_from_time=<unix> expires_at_time=<unix> locked=<0|1>
```

`destination` and `bps` are required; the rest default to 0. Leave `version`
out: the route's version is the request's own `sequence_number`. The request's
**body** -- bound into its id, its approvals and the approval state root -- is
the canonical spec with that version appended, so approvers vote on exactly the
route that will be installed.

A parked change is checked twice, with the same book checks the direct
transactions use:

- **When it is parked**: the route must be installable (shape, not locked) or,
  for kind 7, there must be an unlocked route to clear. A change that could not
  be written today is refused instead of parked.
- **When it is released** (end of block, after the expiry sweep): the same checks
  at that block's timestamp. If they fail -- the route got locked, the expiry
  passed meanwhile -- the request is marked failed and nothing changes.

Unlike a policy or guard change, a released route change does not fail the
sender's other open requests: it changes neither the policy nor the guard their
approvals were measured against.

## Inspecting

- `getreceiveroute <address> [limit]` -- the route and its status at the tip,
  the routes that pay **to** this address, the canonical routing history (newest
  first), queued route changes naming the address (direct ones and parked
  kind 6/7 requests), and the capability block.
- `getreceiveroute capability` -- the capability block alone, plus `active`.
- `gettxstatus <tx_hash>` -- `receive_routes` (gross, net, routed, fee per routed
  credit) and `receive_route_change` for a confirmed transaction.
- `checktx` -- previews the split a transfer would make against the tip's routes.
  Apply uses the route in force in the block that carries the transfer, so this is
  a preview, not a promise.
- `getaccountstate` -- the account's `receive_route`. `pending_incoming` stays
  gross.

The routing history is node-local (it is not hashed) and filtered to the
canonical chain at query time, so a reorg needs no cleanup.

## Limits

These are consensus constants, not configuration: a per-node value would let
honest nodes disagree about balances and fork.

| Limit | Value |
|---|---|
| Routes per account | 1 |
| Destinations per route | 1 |
| Share | 1 to 9000 bps (0.01% to 90%) |
| `min_amount` | at most the largest transfer value |
| Lock length | more than 604 800 seconds (7 days) and at most 94 608 000 seconds (3 years) from install |
| Lock notice period | 604 800 seconds (7 days) from install |
| Scheduled start | at most 31 536 000 seconds (1 year) ahead |
| Routes in total | no cap |

There is deliberately no book-wide cap. The book holds at most one route per
account, so it is already bounded by the account set, and a fixed cap would be a
squatting target: on a faucet network fresh keys can pay the install fee from
their grant, and a full book would refuse every later install until a
coordinated upgrade raised the cap.

## Error codes

| Code | Raised when |
|---|---|
| `INVALID_RECEIVE_ROUTE` | The transaction is malformed, or the route's shape is not admissible (self-route, share out of range, expiry not in the future, a locked route with no expiry or too long a lock, a start too far ahead). |
| `RECEIVE_ROUTE_LOCKED` | The owner tries to replace or clear a route whose lock still holds. |
| `UNKNOWN_RECEIVE_ROUTE` | A clear names an account with no route. |
| `NOT_ROUTE_OWNER` | A clear is signed by someone who is neither the owner nor the destination. |
| `RULE_CHANGE_NEEDS_APPROVAL` | The owner's rule-change guard blocks the change; park it with `--request`. |
| `RECEIVE_ROUTE_STATE_UNAVAILABLE` | The node cannot read its persisted route book. Admission fails closed rather than treating the book as empty. |
| `FEATURE_INACTIVE` | Receive routes have not been activated on this chain (see [Activation](#activation)). |

A parked request that fails a route check at admission is rejected as
`INVALID_RULE_CHANGE_REQUEST` with the route reason in the message.

## Raw transactions

Only **root fields** are read and signed. A nested `payload` is unsigned data
and is ignored.

| `tx_type` | Signed fields beyond the envelope |
|---|---|
| `receive_route_set` | `destination_pubkey`, `route_bps`, `min_amount`, `active_from_time`, `expires_at_time`, `locked` |
| `receive_route_clear` | `route_owner_pubkey` |
| `rule_change_request`, kind 6 | `kind`, `rule_text` (route spec), `offer_id` (`""`), `approvers` |
| `rule_change_request`, kind 7 | `kind`, `rule_text` (`""`), `offer_id` (`""`), `approvers` |

Each optional `receive_route_set` field is signed as `null` when absent, and an
explicit `null` parses the same as an absent field. All numbers are unsigned
64-bit integers; `locked` is a boolean.

## Consensus notes

- The route book is consensus state. Its root joins the consensus metadata hash
  as `receive_routes_root` **only while the book is non-empty**, and the
  activation flag as `receive_routes_active` only once set, so a chain that never
  activates the feature keeps a byte-identical metadata hash and needs no
  regenesis. Each route's install time is part of the root.
- Expired routes are swept at the end of the block, after retractable releases
  and before parked rule changes are released.
- A stored route row the node could not have installed (bad key, self-route,
  share out of range, a locked route with no expiry, a number outside u64) stops
  the node at startup rather than misrouting funds.

## Activation

Like co-signature approval slots, receive routes are switched on by a one-way
flag in consensus state, `receive_routes_active`, read from the parent snapshot:
an activation recorded in block *H* governs *H+1* onward.

- **Live chain**: a governance `consensus_rule_update` whose `host_contract_patch`
  carries `{"receive_routes_active": true}`. Validators vote it in once they run
  this build; until it activates, no node accepts a route transaction, so an
  older node is never forked by the first route someone submits.
- **Fresh chain**: `scripts/gen_genesis.py --receive-routes` turns it on from
  block 0.

Before activation, `receive_route_set`, `receive_route_clear` and
`rule_change_request` kinds 6 and 7 are refused at admission (`FEATURE_INACTIVE`,
or `INVALID_RULE_CHANGE_REQUEST` for the parked kinds) and are no-ops at apply.
`false` is not a legal patch value: turning the feature off would strand
installed routes, locked ones included, with no way to clear them.

## Recipient-side policy

A routed share is not gated by the destination's inbound allow-list or hold cap
([recipient-policy.md](recipient-policy.md)): it is the route owner's money moving
by the owner's own rule, and gating it would let a destination's policy fail every
payment to the owner. The payment to the owner is checked against the owner's
policy as usual.

## Security notes

- **A route redirects future income.** Anyone holding the owner's key can
  install one. A **locked** route then binds for up to 3 years at up to 90%, with
  only its destination able to release it -- but only after its 7-day notice
  period, during which it routes nothing and the owner can remove it. An account
  that receives regular payments should also install a rule-change guard that
  covers kinds 6 and 7 (all three wallet guard templates do), so that a route
  change needs approval in the first place.
- Senders pay the gross amount and cannot see the split when they sign.
  `checktx` and `getaccountstate` show a recipient's route before you send.

## Not in this release

- More than one destination per route, or more than one route per account.
- Multi-hop routing.
