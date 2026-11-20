# Envelopes (spending limits)

An envelope is money sent with a spending limit written on it. The sender
sends an amount to a recipient; the money leaves the sender at once and waits
in the envelope. It is the recipient's to spend, to anyone, but never faster
than the limit allows: at most a cap per period, on a block clock or a time
clock. Every node enforces the limit when it applies a block, so no wallet, bot
or server has to be trusted to keep it.

```
period n  = (clock - anchor) // period          anchor = the clock when sent
cap(n)    = caps[n]                  while n < len(caps)
          = caps[-1]                 after the list, when recurring
          = no limit                 after the list, when not recurring
a spend   1 <= amount <= what the envelope holds
          spent in period n + amount <= cap(n)
```

Nothing carries over: what was not spent in one period does not raise the
next period's cap.

Typical uses:

| Envelope | Caps | Recurring | Reads as |
|---|---|---|---|
| A child's pocket money | `[100]`, weekly | yes | at most 100 a week, every week |
| A project budget | `[5000]`, every 30 days | yes | at most 5,000 a month |
| An advance, then instalments | `[1000, 500]`, monthly | yes | 1,000 in the first month, then 500 a month |
| A slow start | `[200]`, monthly | no | at most 200 in the first month, then freely |
| A ramp | `[100, 200, 400]`, weekly | no | 100, 200, 400 in the first three weeks, then freely |

Short reference: [README](../README.md#envelopes-spending-limits). CLI summary:
[developer_cli.md](developer_cli.md#envelopes). This guide is the long form.

## Lifecycle

```
envelope_send ──► open ──► envelope_spend (recipient, within the cap) ... ──► emptied
                    │
                    ├──► envelope_release (sender): the rest goes to the recipient: released
                    └──► expires_at reached: the rest goes to the recipient: ended
```

Every step is recorded in the node's history: `sent`, `spend` (one per spend,
with the payee, the amount, what remains and what the period has used),
`emptied`, `released` and `ended` (each with `paid_out`).

## Sending

```bash
tau-testnet envelope send --key parent --to <child_pubkey> --amount 5200 \
    --cap 100 --recurring --period 7d --ends-in 52w
tau-testnet envelope send --key client --to <contractor_pubkey> --amount 4000 \
    --cap 1000,500 --recurring --period 30d --ends-in 210d
tau-testnet envelope send --key dao --to <team_pubkey> --amount 20000 \
    --cap 2000 --recurring --period-blocks 10000 --ends-in-blocks 100000
```

| Field | Meaning |
|---|---|
| `recipient_pubkey` | Who may spend (96 lowercase hex, a valid BLS key). Not the sender. |
| `amount` | What the envelope holds, 1 .. 16,777,215 (the transfer limit). It leaves the sender when the send is mined. |
| `caps` | 1 .. 12 caps, each 1 .. 16,777,215: the cap of period 0, 1, 2, ... |
| `period_blocks` or `period_seconds` | Exactly one: the period, 1 .. 1,000,000 blocks or 1 .. 31,622,400 seconds (366 days). It also chooses the envelope's clock. |
| `recurring` | Optional. After the list, the last cap repeats every period. Without it, the limit stops after the list. Default false. |
| `expires_at` | The end, on the envelope's clock: a block height or a unix time (block time). In the future, at most 10,000,000 blocks or four years of 366 days ahead. |

The CLI takes `--cap` repeated or comma-separated (first period first),
`--period` as a duration (`3600`, `90s`, `15m`, `12h`, `7d`, `2w`) or
`--period-blocks`, and the end on the same clock: `--ends-in` / `--ends-at` for
a time period, `--ends-in-blocks` / `--ends-at-height` for a block period.
`send` prints the envelope id.

A send costs one transfer fee, paid by the sender, on top of the amount. A
sender may have 16 envelopes open at once; the node holds 4,096 in total.

### The id

`envelope_id` is a BLAKE3 hash over the sender, the sequence number of the
transaction that sent it, and every term above (`compute_envelope_id`). Spends
and releases name it, so they can never touch a different envelope.

## Spending

```bash
tau-testnet envelope spend --key child <envelope_id> --to <shop_pubkey> --amount 40
tau-testnet envelope spend --key child <envelope_id> --to self --amount 60
```

- Only the recipient spends. The payee is anyone, the recipient included
  (`--to self` moves money from the envelope to the recipient's own balance,
  where it is free of the limit; the limit is on the envelope, not on the
  person).
- A spend lands only if the envelope is open and has not reached its end, the
  amount is at most what it holds, and the period's spent amount plus this one
  stays within the period's cap. Spends in the same block count in block
  order, so two spends cannot overrun a cap together. The node checks a spend
  against the tip when it is sent; of two queued spends that together exceed
  the cap, the second is refused when its block applies and is dropped.
- The spend is a transfer the recipient signs and is judged like one: the
  recipient's own `o5` clause sees "recipient pays payee amount" (`i2` is the
  recipient's own balance, as for any transfer it signs). The sender's clause
  does not judge spends: the sender already agreed when it sent.
- The recipient pays one transfer fee from its own balance. The payee is
  credited first, so a spend to oneself can pay its own fee, even from a zero
  balance.
- A spend stamps the recipient's cooldown clock, like any transfer it makes.

An envelope spent to zero closes at once (outcome `emptied`).

## Releasing

```bash
tau-testnet envelope release --key parent <envelope_id>
```

Only the sender releases, fee-free: everything the envelope still holds goes
to the recipient at once (outcome `released`). The sender cannot take money
back. Releasing is the one way it can change its mind, and only in the
recipient's favour.

## The end

At the end of the block whose clock reaches `expires_at`, the rest goes to the
recipient (outcome `ended`). No spend lands in that block: an envelope at its
end is closed to spends. Ends are processed after the block's transactions and
the retractable releases, before the standing-payment sweep.

## Timing

The envelope's clock is the block height (`period_blocks`) or the block
timestamp (`period_seconds`). The anchor is that clock in the block that sent
the envelope, so period 0 starts when the money left the sender. A block
timestamp is chosen by its proposer within the usual bounds (the parent's
timestamp and the local clock + 120 s), so a time period can start up to about
two minutes early. Block periods are exact, but height does not advance on an
idle chain.

## Receive routes

What a spend pays and what reaches the recipient at a release or the end are
payments, and they pass through the receive route of the account they land on
(see [receive_routes.md](receive_routes.md)): credit classes `envelope_spend`
(the payee) and `envelope_release` (the recipient, at a release or the end).
The send itself credits nobody, so it is not split.

## Inspecting

```bash
tau-testnet envelope show <envelope_id>
tau-testnet envelope list --key child --role in      # envelopes the key may spend from
tau-testnet envelope list <address> --role out       # envelopes an address sent
tau-testnet rpc "getenvelope <envelope_id>"          # raw RPC
tau-testnet rpc "getenvelopes <address> in"
```

`getenvelope` answers `open`; for an open envelope `envelope` holds the terms
and where it stands at the next block: `remaining`, `spent_total`,
`period_index`, `cap_this_period`, `spent_this_period`, `left_this_period` (the
most one spend may take now) and `next_reset` (when the next period starts, or
`null` once the limit has lapsed). A closed envelope answers `closed` (how it
closed). `history` lists its events on canonical blocks, newest first, and
`semantics` is the node's own report of the rules and limits, so a wallet can
explain the feature before offering it.

`getenvelopes` answers the open envelopes an address holds (`in`) or sent
(`out`), `held_in_envelopes` (what open envelopes hold for it to spend) and its
history.

`getaccountstate` adds `envelopes_out` (what open envelopes the address sent
still hold) and `envelopes_in` (what open envelopes hold for it to spend);
neither is balance. A queued send counts in the sender's `pending_outgoing`, a
queued spend in the payee's `pending_incoming`.

`gettxstatus` adds `envelopes` to a confirmed transaction: what it sent, spent,
emptied or released, and for a send whether the envelope is still `open` or
how it closed. `sendtx` and `checktx` answer `envelope`: what the envelope
would hold, and what the period would have left, after the transaction.

## Limits

| Limit | Value |
|---|---|
| Caps per envelope | 12 |
| Open envelopes per sender | 16 |
| Open envelopes in total | 4,096 |
| Amount, each cap, each spend | 1 .. 16,777,215 |
| Period | 1 .. 1,000,000 blocks, or 1 .. 31,622,400 s |
| End | at most 10,000,000 blocks, or four years of 366 days, ahead |
| Envelope transactions per mempool snapshot | 64 |

## Error codes

| Code | When |
|---|---|
| `INVALID_ENVELOPE` | The transaction is malformed, breaks a limit, sends to the sender itself or to an invalid key, or its end is not ahead. |
| `DUPLICATE_ENVELOPE` | This exact envelope is already open. |
| `TOO_MANY_ENVELOPES` | The sender already has 16 open envelopes. |
| `ENVELOPE_BOOK_FULL` | 4,096 envelopes are open. |
| `NO_ENVELOPE` | No open envelope has this id. |
| `NOT_ENVELOPE_RECIPIENT` | A spend signed by anyone but the recipient. |
| `NOT_ENVELOPE_SENDER` | A release signed by anyone but the sender. |
| `ENVELOPE_ENDED` | The envelope has reached its end. |
| `ENVELOPE_LIMIT` | The spend is larger than the period's cap leaves. The message says what was spent this period and what is left. |
| `ENVELOPE_INSUFFICIENT` | The spend is larger than what the envelope holds. |
| `INSUFFICIENT_FUNDS` | The sender cannot pay amount plus fee, or the spender cannot pay the fee. |
| `WRONG_NETWORK` | `genesis_hash` is missing, malformed, or names another network. `details.genesis_hash` is this network's. |

Apply reasons in receipts: `envelope_not_sent`, `envelope_not_spent`,
`envelope_not_released`, `user_policy_block` when an `o5` clause refused, and
`wrong_network`.

## Raw transactions

```json
{"tx_type": "envelope_send", "sender_pubkey": "<sender>", "sequence_number": 7,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "20",
 "genesis_hash": "<64 hex>", "recipient_pubkey": "<recipient>", "amount": 5200, "caps": [100],
 "period_seconds": 604800, "recurring": true, "expires_at": 1830000000,
 "signature": "..."}

{"tx_type": "envelope_spend", "sender_pubkey": "<recipient>", "sequence_number": 3,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "20",
 "genesis_hash": "<64 hex>", "envelope_id": "<64 hex>", "to_pubkey": "<payee>", "amount": 40,
 "signature": "..."}

{"tx_type": "envelope_release", "sender_pubkey": "<sender>", "sequence_number": 8,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "0",
 "genesis_hash": "<64 hex>", "envelope_id": "<64 hex>", "signature": "..."}
```

Every field above is in the signed bytes. `recurring` may be left out (false).
`genesis_hash` is the hash of block 0 of the network the transaction is for;
`getsequence <address>` returns it, and the CLI fills it in.

## Consensus notes

- The book (one row per open envelope: the id, the terms and where it stands)
  plus a running commitment of every close (`emptied`, `released`, `ended`, with
  what was paid out) is folded into the consensus metadata as `envelopes_root`
  **only once the book has held an envelope**. Until then the metadata is
  unchanged, so **no regenesis** is needed; nodes must upgrade before the first
  envelope is sent.
- What a spend may take depends only on the block's height or timestamp and
  the book, both replicated, so proposer, verifiers and replay agree.
- Money in envelopes is part of the supply: the engine's conservation check on
  every block counts balances plus every escrow, envelopes included.
- Money in an envelope is not balance, so it does not count as stake.
- The history (`envelope_events`) is node-local and not hashed; the block
  metadata carries the same events for receipts.
- Envelope transactions travel on their own gossip topic,
  `tau/envelopes/1.0.0`.

## Operator notes

**Upgrading.** No regenesis and no activation height. Until the first
`envelope_send` is mined, blocks and state hashes are byte-identical to a
node without this feature, so mixed versions agree. That block adds
`envelopes_root` to the consensus metadata, and a node that has not upgraded
refuses it. Upgrade every node before anyone sends the first one.

| Table | Written | Read by |
|---|---|---|
| `envelopes_v1 (envelope_id, …)` (open envelopes and where each stands) | with the accounts, in the block's state commit | restore at start, `getenvelope`, `getenvelopes` |
| `envelope_events (envelope_id, block_hash, …)`, indexed by id, sender and recipient | per block, every node, apply and replay | `getenvelope` history, `gettxstatus` |

Tables and columns are created on start; there is no manual migration.
Events are keyed per block, like `retractable_events`, so a reorg needs no
cleanup. At start a node rebuilds the book from its table and refuses to
start on a row that does not recompute its id or holds an impossible state
(`corrupt envelope state`): restore the database or resync the node.

**Cost.** Spends and releases are transactions, so the block size bounds them.
Ends are closed at the end of the block with no Tau step (the money left the
sender when it was sent), one credit each; at most 4,096 envelopes are open.

**Network.** `envelope_send`, `envelope_spend` and `envelope_release` gossip on
`tau/envelopes/1.0.0`; a mempool snapshot carries at most 64 of them.

## Security notes

- A stolen recipient key can drain an envelope only at the pace of its limit:
  at most one cap per period. A release does not help (it pays the same key),
  so choose the caps and the end with that in mind.
- A stolen sender key can only release the rest early, to the recipient.
- The recipient's own `o5` clause still applies to every spend, so a recipient
  with co-signers or a guard keeps them.
- Every open envelope holds at least 1 and costs its sender a fee to open, and
  one sender holds at most 16. A sender with many funded keys could still fill
  the 4,096 places; the per-key limit, the fee and the amount locked until the
  end make that costly but not impossible. Retractable transfers share the
  same shape of limit.
- All three types sign the network they are for (`genesis_hash`). One signed on
  a devnet, a fork or an earlier testnet is refused here, at admission
  (`WRONG_NETWORK`) and at block apply (left out, no fee, no sequence number
  used), even where the same key and sequence number exist.

## Design choices to confirm

These are the choices of this build that are easiest to change before release.

- **The money leaves the sender at send.** The alternative, an allowance drawn
  from the sender's balance, could not promise the recipient anything: the
  sender could empty its balance at any time.
- **The sender cannot take money back**, only release it early. At the end the
  rest goes to the recipient: the money was sent to it, the limit only paces it.
- **Every envelope carries its own caps.** So a sender sets a different cap for
  each recipient and for each payment. A schedule of up to 12 caps covers an
  advance or a ramp, and `recurring` repeats the last cap: one cap with
  `recurring` is the classic weekly allowance.
- **Nothing carries over** between periods.
- **The recipient spends to anyone**, itself included.

## Not in this release

- Conditions other than the spending limit (a list of allowed payees, a
  co-signer for spends above a size). The terms leave room for them: `semantics`
  lists the conditions a node supports (`conditions: ["spending_limit"]`).
- Topping up an open envelope, or a standing payment that pays into one.
- Partial releases.
