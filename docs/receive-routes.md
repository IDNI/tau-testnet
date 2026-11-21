# Receive routes (issue #35)

A receive route diverts a fixed share of every ordinary incoming
transfer to one destination, atomically with the credit. The owner of
the receiving account installs it; the node applies it; the sender of
a transfer cannot bypass it, because the split happens inside the
transfer-execution seam (`_execute_fee_era_transfer`), the single
gate every ordinary transfer passes, in the same staged write set as
the credit itself.

## Terms

One route per owner:

| field | meaning |
| --- | --- |
| `destination_pubkey` | where the diverted share goes; never the owner |
| `bps` | share in basis points, 1..9999 |
| `min_incoming` | optional: no diversion below this gross amount |
| `activation_timestamp` | optional: the route is inert before it |
| `expiry_timestamp` | optional: the route is inert from it; mandatory for locked routes |
| `locked` | a binding route (below) |

## The split

- Computed on the **gross** credit, rounded **down**: 101 at 20%
  routes 20 and credits 81 net.
- **One fee**: the transfer is charged exactly as the unrouted
  transfer would be, on the whole amount, paid by the sender. The
  routed share is not a second transfer and pays no second fee.
- **Single hop, by credit class**: only ordinary user transfers (and
  approval completions of parked ordinary transfers, which pass the
  same seam) trigger a route. The diverted share is credited directly
  by the seam and never re-enters it, so a routed share can never
  trigger another route — including the destination's own route, and
  including a cycle (A routes to B, B routes to A). Credits that never
  pass the seam — sweep releases, retract refunds, standing-payment
  executions' own class, fee credits — are not routed.
- The recipient's balance check, policy (o5) judgement and sequence
  accounting are the unrouted transfer's: routing changes only where
  the credit lands. Routing never counts as the recipient's outgoing
  spend.

## Binding routes

A locked route cannot be removed or replaced by the owner alone
while the lock runs: removal/replacement requires the destination's
BLS signature over the route's unlock message (domain
`tau.route.unlock.v1`, binding the route id, owner and destination).
A locked route must carry an expiry; once it passes, the owner acts
alone again. An expired route is inert whether or not it is removed.

## Transactions

- `receive_route_install` — signed by the owner; every terms field is
  in the signing preimage. Fee-bearing, like creating any standing
  state. Replaces the owner's current route (subject to its lock).
- `receive_route_remove` — signed by the owner; names the installed
  `route_id`; carries `destination_signature` when the route is
  locked. Fee-exempt, like cancelling a standing payment.

## Reporting

- The transfer receipt records the split (`route`: route id,
  destination, gross, routed, net), and the block's snapshot carries
  `route_splits` and `route_events` (installed/removed) for history.
- `checktx estimate` of a transfer to a routed account returns
  `route_previews` computed with the same `RouteTerms.split` the seam
  uses, so the previewed split is the applied split for the same tip
  state.
- `getroutes <pubkey>` reports the installed route and the semantics:
  credit classes, rounding, and the fee rule.

## State

Routes are a field of the consensus lifecycle manager; the book root
(`receive_routes_root`) enters the consensus meta hash only once a
route is installed, so a chain that never installs one hashes exactly
as before. Rows persist in `receive_routes_v1` and restore refuses a
row that does not recompute to its route id.
