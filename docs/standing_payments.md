# Standing payments

A standing payment is an authorization the payer signs once: pay a fixed amount
to a fixed recipient every period, for a fixed number of periods. Each payment
then happens in an end-of-block sweep, with no further transaction from anyone.
Typical uses are rent, a subscription, a salary or an allowance.

Nothing is reserved. The money stays in the payer's balance until a payment is
made, and every payment passes the payer's **current** policy at the moment it
is made. An authorization therefore never lets a payment through that the payer
could not make by hand at that moment, and the payer can stop it at any time.

Short reference: [README](../README.md#standing-payments). CLI summary:
[developer_cli.md](developer_cli.md#standing-payments). This guide is the long
form.

## Lifecycle

```
waiting ──► due ──► paid ─────────► waiting (next period) ... ──► ended
              │                                                     ▲
              ├──► unfunded ──► retrying (next block) ──► paid      │
              │                       └──► window closes: missed ───┤
              └──► policy blocks: missed ───────────────────────────┘
any open state ──► cancelled (the payer's cancel is mined)
```

| Status | Meaning |
|---|---|
| `waiting` | Open; the current period's due point has not been reached. |
| `due` | Open; the period is due and waits for its first attempt in this block or the next. |
| `retrying` | Open; an attempt found too little money, and it is tried again in the next block of the same window. |
| `ended` | Every period was settled (paid or missed). Final. |
| `cancelled` | The payer's cancel was mined. Final. |

## Creating

Give the recipient, the amount, how many periods, exactly one interval flag and
exactly one first-due flag:

```bash
tau-testnet standing create --key alice --to <recipient_pubkey> --amount 25 --periods 12 \
    --every-months 1 --first-due-time 1798761600
tau-testnet standing create --key alice --to <recipient_pubkey> --amount 10 --periods 52 \
    --every-seconds 604800 --first-due-after 3600
tau-testnet standing create --key alice --to <recipient_pubkey> --amount 5 --periods 10 \
    --every-blocks 1000 --first-due-in 50
```

| Flag | Meaning |
|---|---|
| `--every-blocks N` | One period every `N` blocks (height schedule). |
| `--every-seconds N` | One period every `N` seconds of block time. |
| `--every-months N` | One period every `N` calendar months, UTC. |
| `--first-due-height HEIGHT` | First payment at this height (height schedule). |
| `--first-due-in BLOCKS` | First payment this many blocks after the next one (height schedule). |
| `--first-due-time UNIX` | First payment at this time (seconds or months schedule). |
| `--first-due-after SECONDS` | First payment this many seconds from now (seconds or months schedule). |
| `--periods N` | How many periods the authorization covers. This is its end; there is no open-ended authorization. |

The CLI refuses a first due point that is not after the next block, or a time
that is already (almost) past, before signing anything. `create` prints the
**standing payment id** (`standing payment id: <64 hex>`); with `--json` the line
goes to stderr. Keep it: it is the handle for cancelling and inspecting. The other
transaction flags (`--fee`, `--expiry`, `--expire-in`, `--expire-at-height`)
behave as for a normal transfer. Without `--fee`, `create` takes the fee limit
from the node's fee estimate (`checktx estimate`).

### Deadline clamping

Admission refuses an authorization that could be mined at or after its own first
due point, so the CLI clamps the transaction's deadline:

- height schedule: `expire_at_height` becomes `min(expire_at_height, first_due)`;
- time schedules: `expiration_time` becomes `min(expiration_time, first_due - 1)`.

A raw transaction with a later deadline is rejected with
`DEADLINE_AFTER_FIRST_DUE`.

### The id

The id is a BLAKE3 hash of the signed terms (payer, recipient, amount, sequence
number, schedule kind, interval, first due point, periods). Two authorizations
with identical terms and sequence number have the same id, so the second is
refused as a duplicate; a new sequence number always gives a new id.

## Schedules

Period `p` (counting from 0) is due at:

| Schedule | Due point of period `p` | Clock |
|---|---|---|
| blocks | `first_due + p * interval` | block height |
| seconds | `first_due + p * interval` | block header timestamp |
| months | `first_due` moved by `p * interval` calendar months | block header timestamp, UTC |

A month schedule keeps the day and the time of day of `first_due`. A day the
target month does not have becomes its last day: a schedule anchored on the 31st
pays on 30 April and on 28 or 29 February. Every due point is derived from
`first_due`, never from the previous due point, so the 31st comes back in May.

The authorization's **end** is the due point of period `periods`. Both the end
and every due point are fixed when it is signed.

## How a period is paid

Period `p` is payable in every block whose clock is at or past its due point and
before the next period's due point. That span is the period's **window**.

- **At most one payment per period.** A paid period is settled; the next attempt
  waits for the next due point.
- **No catch-up.** A period whose window closes unpaid is missed. If no block
  lands in a window at all, that period is missed too, and the next block pays
  only the period it falls in.
- **No funds: retry.** An attempt that finds less than the amount pays nothing
  (never a part), records an `unfunded` event, and is tried once in each later
  block of the same window. Money that reaches the payer in the meantime, even
  earlier in the same block, pays it. If the window closes first, the period is
  missed. The payer never owes anything.
- **Policy blocks: missed.** Each attempt re-checks the payer's current `o5`
  clause as if the payer sent this transfer in this block (see below). A block
  misses the period at once, with no retry: the payer decided against it.
- **Sweep order.** Due entries form a line ordered by the block they joined it
  (fell due, or the next block after an unfunded attempt), then by id. At most
  32 entries are handled per block; the rest stay in line for the next block.

### Policy at payment time

An attempt runs the payer's per-account `o5` clause with the inputs of an
ordinary transfer of `amount` from payer to recipient: the amount, the payer's
balance at the parent block, the cooldown input where it is active, both public
keys, and the block timestamp. The approval slots are empty, so a clause that
needs a co-signature blocks every standing payment. A rule change or a freeze
applies to the very next attempt; an authorization signed under an older, looser
policy gains nothing from it.

### Money flow

| Event | Payer | Recipient | Proposer |
|---|---|---|---|
| Create mined | `- fee` | none | `+ fee` |
| Payment | `- amount` | `+ amount` | none |
| Cancel mined | none | none | none |

The create pays one fee, set by the fee step like any other fee-bearing
transaction; payments and cancels are fee-free. A payment does not use or change
the payer's sequence number. A recipient that has no record yet is credited
exactly as by a transfer. A payment counts as a send for the payer's cooldown
clock, once per payment.

Total supply is conserved: a payment moves money between two balances and
creates none.

## Cancelling

```bash
tau-testnet standing cancel --key alice <standing_id>
```

- Only the **payer** may cancel.
- It is **feeless**.
- It takes effect in the block that carries it. The block's transactions are
  applied before the sweep, so a payment due in that same block is not made.
- A second cancel of the same id in the mempool is refused
  (`DUPLICATE_STANDING_CANCEL`).

There is no edit. To change the amount, recipient or schedule, cancel and create
a new authorization.

## Idle chains

A block is only mined when the mempool has something to carry. The miner also
wakes when a standing payment is due for its first attempt at the next block's
height or the current time, and seals the block that crosses it (at most one
attempt every 2 seconds, as for retractable releases). Retries do not wake an
idle chain: an unfunded payment is tried again when the next block comes.

Money can only reach a payer in a block, and that block's sweep retries the
payment after the block's transactions, so a retry that does not wake the chain
loses nothing. A height schedule on an idle chain still waits until enough
blocks have been mined, and a window in which no block lands is missed. For an
idle chain, prefer a time schedule.

### Why there is no execute transaction

Every block attempts every due payment, so nobody has to submit anything for a
payment to happen, and no executor can pick the moment or the order. An execute
transaction would add a fee question (who pays for someone else's payment) and a
race with the sweep, and could only do what the next block does anyway. Any
transaction makes a block; on an idle chain the miner's wake does.

### Fairness when the book is full

With 32 entries handled per block and at most 4096 open entries, every entry in
line is reached within 128 blocks. The shortest height interval is 128 blocks, so
every period of a height schedule gets at least one attempt, however full the
book is. While first attempts are pending the miner keeps waking, so a full line
drains in about 128 blocks; the shortest time interval is one hour.

## Inspecting

```bash
tau-testnet standing list --key alice --role out     # or --address <pk>; --role in|out|all
tau-testnet standing show <standing_id>
```

| RPC | Returns |
|---|---|
| `getstandingpayments <address> [out\|in\|all]` | `payments` (open authorizations the address pays or receives, default `all`), `block_hash` of the tip they were read at, and `semantics`: the node's own rules and limits for standing payments, so a wallet can show them before offering the feature. |
| `getstandingpayment <id>` | An open entry with its terms and progress (below) and `history`; or `{standing_id, status: "ended"\|"cancelled", resolved_at_height, history}` once resolved on the canonical chain; or `STANDING_PAYMENT_UNKNOWN`. |
| `gettxstatus <hash>` | For a confirmed create, `standing: {id, status}` where status is `waiting`, `due`, `retrying`, `ended`, `cancelled` or `not_recorded`; for a confirmed cancel, `cancels: <id>`. |

An open entry reads:

| Field | Meaning |
|---|---|
| `standing_id`, `payer_pubkey`, `recipient_pubkey`, `amount`, `sequence_number` | The signed terms. |
| `schedule`, `interval`, `first_due`, `periods`, `end` | The schedule: `blocks`, `seconds` or `months`. |
| `period`, `period_due`, `period_closes` | The current period and its window. |
| `status`, `tries` | `waiting`, `due` or `retrying`; unfunded attempts in this period. |
| `paid_count`, `missed_count`, `paid_total`, `last_paid_height` | What it has done so far. |

`history` lists the entry's events on the canonical chain, newest first:
`created`, `paid`, `unfunded`, `missed` (with `reason` `window_closed` or
`policy_block`, and `count`), `ended` (with `paid` and `missed`) and `cancelled`,
each with its block height. Events follow reorganizations.

## Limits

These are consensus constants, not configuration: a per-node value would let
honest nodes disagree about what is due and fork.

| Limit | Value |
|---|---|
| Open authorizations per payer | 16 |
| Open authorizations in total | 4096 |
| Entries handled per block | 32 |
| Interval, blocks | 128 to 1 000 000 |
| Interval, seconds | 3 600 to 31 622 400 (366 days) |
| Interval, months | 1 to 12 |
| Periods | 1 to 1 200 |
| First due point, height | strictly after the block that mines the create, at most 100 000 blocks ahead |
| First due point, time | strictly after that block's timestamp, at most 31 622 400 seconds ahead |
| End of a time schedule | before the year 10000 |
| Amount | 1 to 16 777 215 (`bv[24]`) |
| Recipient | a valid public key other than the payer |

## Error codes

| Code | Raised when |
|---|---|
| `INVALID_SCHEDULE` | An amount, interval, period count or first due point is outside the limits above, or the recipient is the payer. |
| `DUPLICATE_STANDING_PAYMENT` | An open authorization with the same id exists. |
| `TOO_MANY_STANDING_PAYMENTS` | The payer already has 16 open authorizations. |
| `STANDING_BOOK_FULL` | 4096 authorizations are open. |
| `DEADLINE_AFTER_FIRST_DUE` | `expire_at_height` is after `first_due`, or `expiration_time` is not before it. |
| `UNKNOWN_STANDING_PAYMENT` | A cancel names an id that is not open (unknown, ended or cancelled). |
| `NOT_STANDING_PAYER` | A cancel is signed by someone other than the payer. |
| `DUPLICATE_STANDING_CANCEL` | A cancel of the same id is already in the mempool. |
| `WRONG_NETWORK` | `genesis_hash` is missing, malformed, or names another network. `details.genesis_hash` is this network's. |

A malformed transaction is rejected with a descriptive message
(`Malformed standing_payment_create: ...`). At block apply, a create or cancel
that does not pass these checks is rejected with receipt reason
`standing_payment_not_created` or `standing_payment_not_cancelled` (or
`wrong_network`), and the block stays valid.

## Raw transactions

Only **root fields** are read and signed. A nested `payload` or `operations` is
unsigned data and is ignored.

| `tx_type` | Fields beyond the envelope |
|---|---|
| `standing_payment_create` | `genesis_hash`, `recipient_pubkey` (96 lowercase hex), `amount`, exactly one of `interval_blocks` / `interval_seconds` / `interval_months`, `first_due`, `periods` |
| `standing_payment_cancel` | `genesis_hash`, `standing_id` (64 lowercase hex); `fee_limit` `"0"` |

The envelope is the usual `sender_pubkey` (the payer, 96 lowercase hex),
`sequence_number`, `expiration_time`, `expire_at_height`, `fee_limit` and
signature. `genesis_hash` is the hash of block 0 of the network (64 lowercase
hex); `getsequence <address>` returns it with the sequence number and the tip,
so a wallet needs no extra call, and the CLI fills it in. Both types travel in
the fast lane, on their own gossip topic `tau/standing/1.0.0`.

## Consensus notes

- The book is part of consensus state. Its root is folded into the consensus
  metadata as `standing_payments_root`, **only once the book has held an entry**,
  the same gate `rule_offers_root` uses. Genesis stays byte-identical and **no
  regenesis is needed**; an un-upgraded node diverges loudly (state-hash
  mismatch) at the first create, so nodes upgrade before the first one lands.
- The root commits to every open entry's terms and progress (period, counts,
  tries, line position, last paid height), so all nodes agree on what is due and
  in which order.
- Ended and cancelled entries leave memory. The book keeps a **count** and an
  order-dependent **running hash** of them, so the root and the per-block copy
  cost depend on the open set alone.
- The sweep runs after the block's transactions and after the retractable
  release, and before a pending rule change takes effect.
- A node restores the book from its database at start and refuses a row whose id
  does not match its terms, or whose progress is impossible.

## Timing caveats

- **Block timestamps are proposer-chosen**, within the parent's timestamp and
  the proposer's clock plus 120 seconds. A time or month payment can land up to
  about two minutes early, and a window edge is judged by block time.
- **A cancel must be included in a block** to stop a payment due in that block.
  A feeless cancel sorts last in a backed-up mempool, so cancel with margin.
- **Height does not advance on an idle chain** (see [Idle chains](#idle-chains)).

## Security notes

- **No new power for a key.** A payment passes the payer's current `o5` clause
  as a transfer of the same amount to the same recipient in the same block would.
  A stolen key can create an authorization, but every payment of it meets the
  same policy a direct transfer by that key meets, so it moves nothing the thief
  could not move by hand. A co-signature clause blocks every standing payment.
- **Terms are fixed.** The id commits to every signed term; the recipient, a
  relayer or a proposer can change none of them, and there is no execute call to
  choose the moment.
- **Replay.** Every transaction here carries its sender's sequence number like
  any transaction, so a copy of its signed bytes is refused wherever it is
  replayed, and the copy pays nothing.
- **Another network.** Both types sign `genesis_hash`, the hash of block 0 of
  the network they are for. Admission and block apply refuse one that names
  another network (`WRONG_NETWORK`; at apply it is left out of the block, with no
  fee and no sequence number used), and the field cannot be rewritten without
  breaking the signature. So an authorization signed on a devnet, a fork or an
  earlier testnet cannot be replayed here, even where the same key and sequence
  number exist. The older transaction types are not changed by this (the
  README's note on domain separation still applies to them): a type that is new
  can sign its network from its first release without breaking any signature.
  The list of bound types is `consensus/network_binding.py`.
- **Spam.** Each create pays a fee; 16 open per payer and 4096 in total bound the
  book, and 32 actions per block bound the sweep.

## Not in this release

- Editing an open authorization (cancel and create instead).
- Reserved or escrowed funds, partial payments, catching up missed periods.
- Variable amounts, payments decided by a rule, or split payments.
- Recipient refusal: the recipient cannot decline an authorization.
- Open-ended authorizations.
- Running the shared application rules at payment time: a payment checks the
  payer's per-account `o5` clause, not rules accumulated in the global
  specification before the clause registry.
- A wallet UI.
