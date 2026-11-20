# Receive routes

A receive route sends a share of every payment an account receives to another
account, in the same state transition that credits it. The account installs one
route: a destination, a share, and optionally a minimum, a start, an end and a
lock. From then on every payment to the account splits as it lands:

```
routed = floor(gross * share_bps / 10000)      (0 when gross < min_amount)
net    = gross - routed
```

`net` lands on the account and `routed` on the destination. Nobody has to be
online: not the account, not the destination, not a bot. The payer signed
"gross to the account" and is charged exactly what it would be charged without
the route.

Typical uses: a creator sends 10% of every sale to a collaborator; a shop
puts 5% of every incoming payment into a tax account; a project routes 20% of
its income to a treasury it cannot quietly stop paying for a year (a locked
route).

Short reference: [README](../README.md#receive-routes). CLI summary:
[developer_cli.md](developer_cli.md#receive-routes). This guide is the long form.

## Lifecycle

```
receive_route_set ──► installed (scheduled until active_from) ──► active: every credit splits
                         │   ▲
                         │   └── receive_route_set again: replaced (new id)
                         ├──► receive_route_remove (owner, not while locked): removed
                         ├──► receive_route_release (destination only): released
                         └──► expires_at reached: expired
```

Every change is recorded in the node's history: `installed`, `routed` (one per
split credit, with `gross`, `routed`, `net`, the credit class and the payer),
`removed`, `released`, `expired`.

## Setting a route

```bash
tau-testnet route set --key shop --to <tax_pubkey> --share 5
tau-testnet route set --key creator --to <collaborator_pubkey> --share 12.5 \
    --min-amount 100 --starts-in 3600 --ends-in 2592000
tau-testnet route set --key project --to <treasury_pubkey> --share 20 \
    --ends-in 31536000 --locked
```

| Field | Meaning |
|---|---|
| `destination_pubkey` | The account that receives the share (96 lowercase hex, a valid BLS key). Not the account itself. |
| `share_bps` | The share in basis points, 1 .. 9000 (0.01% .. 90%). The account always keeps at least a tenth of what it is paid. |
| `min_amount` | Optional. A credit smaller than this is not split. Default 0. |
| `active_from` | Optional. Unix seconds (block timestamp) from which the route splits; at most 366 days ahead. Default: from the block that installs it. |
| `expires_at` | Optional. Unix seconds at which the route ends, in the future, after `active_from`, at most four years ahead. Default: no end. |
| `locked` | Optional. Binds the account to the route until `expires_at` (see [Locked routes](#locked-routes)). Needs an end at most 366 days ahead. |

The CLI takes `--share` in percent with up to two decimals, or `--share-bps`.

Setting a route costs one fee, paid by the account, and moves no money. Setting
again replaces the current route (outcome `replaced` in the book's commitment);
there is no edit. A route is refused when the destination's own route points
straight back at the account (A -> B while B -> A): such a pair would only bounce
shares back and forth. Longer chains are allowed; they move money one step at a
time (see [One hop](#one-hop)).

### The id

`route_id` is a BLAKE3 hash over the account, the sequence number of the
transaction that set it, and every term above (`compute_receive_route_id`). A
destination releasing a route names the id, so a release signed against a route
the account has since replaced is refused.

## What is split

Every credit that is a payment someone made to the account is split. The class
of each credit is consensus-frozen and appears on every split:

| Class | Split | The credit |
|---|---|---|
| `transfer` | yes | A transfer inside a `user_tx`. Each transfer of a transaction splits on its own. |
| `approved_transfer` | yes | A transfer request released by its co-signatures. |
| `retractable_release` | yes | A retractable transfer reaching its release point. |
| `standing_payment` | yes | A standing payment made by the end-of-block sweep. |
| `payout` | yes | A leg of a payout rule's execution. |
| `envelope_spend` | yes | A spend from an envelope, credited to its payee (see [envelopes.md](envelopes.md)). |
| `envelope_release` | yes | What an envelope still holds, reaching its recipient at a release or at its end. |
| `retract_refund` | no | A retracted transfer returning to its sender: the sender's own money. |
| `faucet_grant` | no | The grant of a new account. |
| `fee` | no | A fee credited to the proposer or the fee beneficiary. |
| `routed_share` | no | Money that arrives through another account's route. |

There is no other way to credit an account, so there is no payment that bypasses
the route: every path calls the same function in the engine.

### One hop

A routed share is credited to the destination plainly; it is never routed
again. With A -> B and B -> C, a payment of 100 to A at 20% gives A 80 and B 20,
and C nothing from it. A payment to B itself is split by B's route as usual.

### Rounding

The split is computed per credit from its own gross amount, rounding the routed
part down. 101 at 20% routes 20 and leaves 81; 4 at 20% routes 0. Two payments
of 9 each route 1 + 1, not floor(18 * 0.2) = 3.

### What the account and the payer see

- The payer is debited `gross` and pays its own fee, unchanged. Routing has no
  fee of its own.
- The routed part never touches the account's balance. It is not a send of the
  account: no `o5` clause of the account judges it, no cooldown clock is
  stamped, nothing the account's rules count as spent grows.
- `sendtx` and `checktx` answer with `receive_routes`: how the routes in force
  now would split the credits of the transaction (the recipient, gross, routed,
  net, destination and the route's status). Credits that land later, such as a
  retractable release or a standing payment, carry `lands_later: true`: the
  route in force in the block where they land decides them.

## Timing

A route splits a credit when `active_from <= block timestamp < expires_at`. A
route that has not started yet is `scheduled`; it is in the book and visible,
and splits nothing.

Within a block, transactions see the routes as the transactions before them
left them: a route set early in a block splits a payment later in the same
block. Credits that land at the end of the block (retractable releases and
standing payments) use the routes in force after the block's last transaction.

A route whose end the block reaches is removed at the end of that block
(outcome `expired`), after the end-of-block credits, which it does not split
because its end has passed.

## Removing

```bash
tau-testnet route remove --key shop
```

Account only, fee-free, effective in its own block. Refused while the route is
locked.

## Locked routes

A locked route protects the destination. Until it ends, the account can neither
remove it nor replace it with anything weaker. A replacement is allowed only if
it gives the destination at least what the current route promised:

- the same destination, still locked;
- a share at least as large, a minimum at most as large;
- a start no later than the current one (or now, if it has started);
- an end no earlier than the current one.

Only the destination can let go of a locked route early:

```bash
tau-testnet route release --key treasury --owner <project_pubkey>
```

`release` is fee-free and works on any route that pays the signer, locked or
not. It names the route id (the CLI reads it from the node unless `--route-id`
pins one), so a release never removes a route the account installed after the
destination decided.

A lock ends at most 366 days after the transaction that sets it. A locked
route ends on its own at `expires_at`.

## The rule-change guard

A route decides where an account's income goes, so setting, replacing and
removing it are rule changes. An account with a rule-change guard (see
[approvals.md](approvals.md)) has them judged with `i1` = 8 (set receive route)
or 9 (remove receive route). If the guard blocks, the direct transaction is
refused, and the account files a rule-change request instead:

```bash
tau-testnet route set --key shop --to <tax_pubkey> --share 5 \
    --request --approver 18=<cosigner_pubkey>
tau-testnet route remove --key shop --request --approver 18=<cosigner_pubkey>
```

One stolen key therefore cannot silently redirect what a guarded account is
paid. A guard that blocks every change without its co-signers covers kinds 8
and 9 with no edit. A guard that names the kinds it blocks does not block kinds
it does not name.

The request carries the route's canonical spec text (`route_spec_text`: sorted
keys, no spaces, defaults left out) and releases on co-signatures or after the
time escape, like every rule-change request. At release the route is checked
again against the book as it is then: a set whose end has passed, or that would
now point straight back at its destination's route, fails the request; a remove
of a route that has since been locked fails too. The installed route's id uses
the request's sequence number.

A destination's release is not a rule change of the account and is not guarded.

## Inspecting

```bash
tau-testnet route show <address>
tau-testnet rpc "getreceiveroute <address>"   # raw RPC
```

`getreceiveroute` answers:

- `installed` and `route`: the account's route with its terms, `share_percent`,
  `status` (`scheduled`, `active` or `ended`), `removable_by_owner`, and a worked
  `example` (101 split);
- `routes_in`: every route that pays this account;
- `history` (as owner) and `history_in` (as destination): installs, splits with
  `gross`, `routed`, `net`, class and payer, removals, releases and expiries;
  canonical blocks only, newest first;
- `semantics`: the node's own constants (credit classes, rounding, fees, limits,
  fee by transaction type), so a wallet can explain the feature before offering
  it.

`gettxstatus` adds `receive_routes` to a confirmed transaction: the splits it
caused, and for a route change whether the route is still `installed` or was
`replaced`, `removed`, `released` or `expired`.

## Limits

| Limit | Value |
|---|---|
| Routes per account | 1 |
| Destinations per route | 1 |
| Routes in total | 4,096 |
| Share | 0.01% .. 90% (1 .. 9000 bps) |
| Start | at most 366 days ahead |
| End | at most four years ahead |
| Lock | ends at most 366 days ahead |
| Route transactions per mempool snapshot | 32 |

## Error codes

| Code | When |
|---|---|
| `INVALID_RECEIVE_ROUTE` | The route is malformed, breaks a limit, points at the account itself or at an invalid key, or its destination routes straight back. |
| `DUPLICATE_RECEIVE_ROUTE` | This exact route is already installed. |
| `RECEIVE_ROUTE_BOOK_FULL` | 4,096 accounts already have a route (replacing your own is still possible). |
| `RECEIVE_ROUTE_LOCKED` | The current route is locked: it cannot be removed or weakened before its end. |
| `NO_RECEIVE_ROUTE` | Remove or release without an installed route. |
| `STALE_ROUTE_ID` | The release names a route that is no longer the account's. |
| `NOT_ROUTE_DESTINATION` | The release is signed by someone other than the route's destination. |
| `RULE_CHANGE_NEEDS_APPROVAL` | The account's guard blocks the change; use `--request`. |
| `WRONG_NETWORK` | `genesis_hash` is missing, malformed, or names another network. `details.genesis_hash` is this network's. |

Apply reasons in receipts: `receive_route_not_set`, `receive_route_not_removed`,
`receive_route_not_released`, `wrong_network`.

## Raw transactions

```json
{"tx_type": "receive_route_set", "sender_pubkey": "<account>", "sequence_number": 7,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "20",
 "genesis_hash": "<64 hex>", "destination_pubkey": "<treasury>", "share_bps": 2000,
 "expires_at": 1830000000, "locked": true, "signature": "..."}

{"tx_type": "receive_route_remove", "sender_pubkey": "<account>", "sequence_number": 8,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "0",
 "genesis_hash": "<64 hex>", "signature": "..."}

{"tx_type": "receive_route_release", "sender_pubkey": "<destination>", "sequence_number": 3,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "0",
 "genesis_hash": "<64 hex>", "owner_pubkey": "<account>", "route_id": "<64 hex>",
 "signature": "..."}
```

Every field above is in the signed bytes. `min_amount`, `active_from`,
`expires_at` and `locked` may be left out; left out they are 0 (or false).
`genesis_hash` is the hash of block 0 of the network the transaction is for;
`getsequence <address>` returns it, and the CLI fills it in.

## Consensus notes

- The book (one row per account: the id and the terms) plus a running commitment
  of every removal (`replaced`, `removed`, `released`, `expired`) is folded into
  the consensus metadata as `receive_routes_root` **only once the book has held a
  route**. Until then the metadata is unchanged, so **no regenesis** is needed;
  nodes must upgrade before the first route is set.
- The split depends only on the block timestamp and the book, both part of the
  replicated state, so proposer, verifiers and replay compute the same split.
- Total supply is unchanged by routing: the engine checks conservation on every
  block.
- The history (`route_events`) is node-local and not hashed; the block metadata
  carries the same events for receipts.
- Route transactions travel on their own gossip topic, `tau/routes/1.0.0`.

## Operator notes

**Upgrading.** No regenesis and no activation height. Until the first
`receive_route_set` is mined, blocks and state hashes are byte-identical to a
node without this feature, so mixed versions agree. That block adds
`receive_routes_root` to the consensus metadata, and a node that has not upgraded
refuses it. Upgrade every node before anyone sends the first one.

| Table | Written | Read by |
|---|---|---|
| `receive_routes_v1 (owner_pubkey, …)` | with the accounts, in the block's state commit | restore at start, `getreceiveroute` |
| `route_events`, indexed by owner and destination | per block, every node, apply and replay | `getreceiveroute`, `gettxstatus` |

Tables and columns are created on start; there is no manual migration.
Events are keyed per block, like `retractable_events`, so a reorg needs no
cleanup. At start a node rebuilds the book from its table and refuses to
start on a row that does not recompute its id or holds an impossible state
(`corrupt receive route state`): restore the database or resync the node.

**Cost.** A route adds no sweep of its own: the split happens inside the credit
that triggers it, and it is one hop, so a credit causes at most one more credit.

**Network.** `receive_route_set`, `receive_route_remove` and
`receive_route_release` gossip on `tau/routes/1.0.0`; a mempool snapshot carries
at most 32 of them.

## Security notes

- A route redirects future income. An account that cares about a stolen key
  should have a rule-change guard, so that a thief cannot set a route to itself.
- The 90% cap means a route can never leave the account with nothing.
- A locked route is a promise to the destination. The account gives up the
  right to stop paying until the end; choose the end with care. The destination
  can always let go.
- Splitting happens on credit, so it cannot be dodged by a payer or delayed by
  the account. It also cannot be undone: a split payment that is later disputed
  is the parties' matter, not the route's.
- All three types sign the network they are for (`genesis_hash`). One signed on
  a devnet, a fork or an earlier testnet is refused here, at admission
  (`WRONG_NETWORK`) and at block apply (left out, no fee, no sequence number
  used), even where the same key and sequence number exist.

## Not in this release

- More than one destination per route, or more than one route per account.
- Routing only some credit classes, or only payments from some payers.
- Routes that depend on a Tau rule (for example, a share that changes with the
  balance).
