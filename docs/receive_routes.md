# Receive routes

A receive route makes an account split what it receives, atomically and with
no wallet online: *save 20% of everything I receive to address X*.

Capability request: [IDNI/tau-testnet#35](https://github.com/IDNI/tau-testnet/issues/35).

```bash
tau-testnet route set --key bob --to <savings_pubkey> --share 20
tau-testnet route show --key bob
tau-testnet route remove --key bob
```

## How a credit is split

When an ordinary credit reaches an account with an active route, the node
divides the **gross** credit in the same atomic write as the transfer:

```
routed = floor(gross * bps / 10000)   -> destination
net    = gross - routed               -> the account
```

A 20% route (`bps = 2000`) and a gross credit of 101: 20 to the destination,
81 to the account. Gross, net and routed amount appear in the transaction
receipt (`routed`) and its logs. Nothing is burned or duplicated: `net + routed
== gross` always.

The sender signs "send gross to recipient" exactly as before and pays the one
ordinary transfer fee; a route adds no fee. A sender cannot bypass the route,
and it applies the same whether the recipient's wallet is online or not.

## Which credits are routed

| Credit | Routed |
|---|---|
| Ordinary transfers (`user_tx`) | yes |
| Executed co-signature requests (`transfer_vote` completing an `approval_request`) | yes |
| Standing-payment executions | yes |
| Grant draws | yes |
| Faucet / genesis funding, fees and rewards | no |
| Retractable releases, grant refunds and cancellations | no |
| Route outputs | no |

**Single hop.** A routed share is credited directly to the destination and
never triggers the destination's own route, so loops such as A → B → A cannot
happen.

## Terms

| Field | Meaning |
|---|---|
| `destination_pubkey` | Where the share goes. Valid BLS key, not the owner (no self-route). |
| `bps` | Share in basis points, `1..9000` (product limit below 100%). |
| `min_incoming` | Credits below this amount are not routed. |
| `activate_at` / `expires_at` | Optional active window (unix, block timestamp). |
| `locked_until` | Optional binding period: until then the owner can neither replace nor remove the route. A locked route must have `expires_at`, at or after `locked_until`. |

One route per account (v1). `receive_route_set` installs or replaces it
(fee-bearing); `receive_route_remove` removes it (fee-exempt). Expired routes
are dropped from state by the block sweep. The routed share never counts as the
recipient's outgoing spend: it was never credited to their spendable balance.

## RPC and state

`getreceiveroute <address>` returns the route, whether it is active and locked
now, and the capability semantics (rounding rule, routed credit classes,
single hop, no extra fee) so a wallet can show them before a send.

The route book is a field of the consensus lifecycle manager; its root enters
the meta hash only once the first route is installed. It is persisted as
`routes_v1` and validated on load.

## Later extensions (not in v1)

A bounded list of destinations, and removal of a locked route with the
destination's co-signature through protected policy administration (#33).

Every transaction above also signs `chain_id` (the network's genesis hash,
RPC `getchainid`); a node of any other network refuses it. See
[programmable_payments.md](programmable_payments.md#design-decisions).
