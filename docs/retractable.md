# Retractable transfers

A retractable transfer parks funds in escrow until a **release point**: a block
height or a Unix time. Until that point the sender can take the funds back; from
it, the first block that reaches it pays the recipient, with no further
transaction from anyone.

It is a transfer with a built-in cooling-off window. Typical uses are a payment
the sender may want to cancel on a mistake (wrong recipient, wrong amount) and a
payment that should only land at a known time.

Short reference: [README](../README.md#retractable-transfers). CLI summary:
[developer_cli.md](developer_cli.md#retractable-transfers). This guide is the
long form.

## Lifecycle

```
open ──► released     (a block reaches the release point; recipient is paid)
  └────► retracted    (the sender's retract is mined before the release point)
```

Both end states are final. A retract and a release can never happen in the same
block: the block's transactions are applied first (a retract needs the block to
be strictly before the release point), and the release sweep runs after them.

| Status | Meaning |
|---|---|
| `open` | In escrow; may still be retracted or released. |
| `released` | Paid to the recipient. |
| `retracted` | Returned to the sender. |

## Sending

Give exactly one release flag:

```bash
tau-testnet retractable send --key alice --to <recipient_pubkey> --amount 10 --release-in 20
tau-testnet retractable send --key alice --to <recipient_pubkey> --amount 10 --release-at-height 5000
tau-testnet retractable send --key alice --to <recipient_pubkey> --amount 10 --release-at-time 1790000000
tau-testnet retractable send --key alice --to <recipient_pubkey> --amount 10 --release-after 3600
```

| Flag | Release point |
|---|---|
| `--release-in BLOCKS` | That many blocks after the next one (height). |
| `--release-at-height HEIGHT` | First block at or past this height. |
| `--release-at-time UNIX` | First block whose header timestamp is at or past this time. |
| `--release-after SECONDS` | That many seconds from now (time). |

The CLI refuses a release height that is not after the next block, and a release
time that is already (almost) past, before signing anything.

`send` prints the **retractable id** (`retractable id: <64 hex>`); with `--json`
the line goes to stderr. Keep it: it is the handle for retracting and inspecting.
The other transaction flags (`--fee`, `--expiry`, `--expire-in`,
`--expire-at-height`) behave as for a normal transfer.

### Deadline clamping

Admission refuses a park that could be mined at or after its own release. The CLI
therefore clamps the transaction's own deadline to the release point:

- height release: `expire_at_height` becomes `min(expire_at_height, release_at_height)`;
- time release: `expiration_time` becomes `min(expiration_time, release_at_time - 1)`.

A raw transaction that sets a later deadline is rejected with
`DEADLINE_AFTER_RELEASE`.

### The id

The id is derived from the sender, recipient, amount, sequence number, release
kind and release point alone, so it can be computed before the park is signed:

```bash
tau-testnet retractable id --from-pubkey <sender_pubkey> --to <recipient_pubkey> \
    --amount 10 --sequence 7 --release-at-height 5000
```

Two parks with identical fields have the same id, so the second is refused as a
duplicate; a different sequence number always gives a new id.

## Retracting

```bash
tau-testnet retractable retract --key alice <retractable_id>
```

- Only the **sender** may retract.
- It is **feeless**.
- It must be **included in a block** strictly before the release point. Sending
  it is not enough: if the release point is reached first, the retract is too
  late.
- The escrowed amount returns to the sender's balance. The park's fee is not
  returned.

A retract that admission accepts can still lose the race. If the block that
carries it is at or past the release point, the retract is ignored at apply
(logged as `retract_not_applied`) and the release sweep pays the recipient. A
feeless transaction sorts last in the mempool when it is backed up, so retract
with margin.

## Release

The sweep runs at the end of every block, after its transactions. It pays every
entry whose release point has been reached:

- height: `block height >= release_at_height`;
- time: `block header timestamp >= release_at_time`.

Entries due in the same block release in ascending id order, and each credit goes
straight to the recipient's balance.

### Idle chains

A block is only mined when the mempool has something to carry, so height does not
advance by itself. To keep a due release from waiting for unrelated traffic, the
miner wakes when the mempool is empty but an entry is due at the next block's
height or the current time, and seals the single block that crosses it. The wake
is throttled to one attempt every 2 seconds. It does not fast-forward height: a
height-based release on an idle chain still waits until enough blocks have been
mined. For an idle chain, prefer a time-based release.

`createblock` decides this under the chain lock against the candidate block's own
height and timestamp; the miner's pre-check is only a hint. An empty block is
otherwise refused unless the caller passes `allow-empty`.

## Money flow

| Event | Sender | Recipient | Escrow |
|---|---|---|---|
| Park mined | `- amount - fee` | none | `+ amount` |
| Retract mined | `+ amount` | none | `- amount` |
| Release | none | `+ amount` | `- amount` |

The fee is charged once, at park time, to the sender and credited to the block's
proposer as for any transfer. It is never refunded, whether the entry is later
retracted or released. A retract costs nothing.

Escrowed funds are not balance, so they do not count as stake. Total supply is
conserved across every block: balances plus the open escrow equal the parent's
total, and a block that breaks this is rejected as a consensus bug.

## Authorization happens at park

A park passes the same gates as an ordinary transfer when it is mined: the
sender's `o5` policy (evaluated with the approval slots empty), the fee step, and
the balance. Scheduling a payment therefore cannot be used to get around a
co-signature policy. Retractable transfers are not co-signable.

Nothing is re-checked at release. The release sweep is a plain credit from the
escrow book, with no Tau evaluation, so a later policy change, a changed fee
model, or the sender's balance dropping to zero does not block it. This is also
why the funds are removed from the sender up front: the recipient is guaranteed
to be paid, and nothing the sender does afterwards can fail the release.

## Inspecting

```bash
tau-testnet retractable list --key alice --role out     # or --address <pk>; --role in|out|all
tau-testnet retractable show <retractable_id>
```

| RPC | Returns |
|---|---|
| `getretractable <id>` | An open entry (`retractable_id`, `sender_pubkey`, `recipient_pubkey`, `amount`, `sequence_number`, `status: "open"`, and one of `release_at_height` / `release_at_time`); or `{retractable_id, status: "released"\|"retracted", resolved_at_height}` once resolved on the canonical chain; or `RETRACTABLE_UNKNOWN`. |
| `getretractables <address> [in\|out\|all]` | `retractables` (open entries for the address, default role `all`) and `mempool` (queued parks and retracts naming the address). |
| `getretractableid <json>` | `retractable_id` and `input_echo` for a park's fields, with `shape_error` when the park would be refused as it stands. `sequence_number` defaults to 0. |
| `gettxstatus <hash>` | For a confirmed park, `retractable: {id, status}` where status is `open`, `released`, `retracted` or `not_recorded`; for a confirmed retract, `retracts: <id>`. |
| `getaccountstate <address>` | Adds `escrowed_out` (escrow the account sent, unresolved) and `escrowed_in` (escrow addressed to it). A queued park counts in `pending_outgoing`. |

A mined retract or release is final only on the canonical chain; resolutions
shown by `getretractable` follow it through reorganizations.

## Limits

These are consensus constants, not configuration: a per-node value would let
honest nodes disagree about admissibility and fork.

| Limit | Value |
|---|---|
| Open entries per sender | 16 |
| Open entries in total | 4096 |
| Release window, height | 100 000 blocks ahead |
| Release window, time | 7 776 000 seconds (90 days) ahead |
| Amount | 1 to 16 777 215 (`bv[24]`) |
| Release point | strictly in the future of the block the park is mined in |

## Error codes

| Code | Raised when |
|---|---|
| `DUPLICATE_RETRACTABLE` | An open entry with the same id exists. |
| `TOO_MANY_RETRACTABLES` | The sender already has 16 open entries. |
| `RETRACTABLE_BOOK_FULL` | 4096 entries are open. |
| `DEADLINE_AFTER_RELEASE` | `expire_at_height` is after `release_at_height`, or `expiration_time` is not before `release_at_time`. |
| `UNKNOWN_RETRACTABLE` | A retract names an id that is not open (unknown, or already resolved). |
| `NOT_RETRACTABLE_SENDER` | A retract is signed by someone other than the entry's sender. |
| `RETRACT_TOO_LATE` | The next block is already at or past the release point. |

A malformed transaction, an out-of-range amount, or a release point that is not
in the future or is outside the window is rejected with a descriptive message
(`Malformed retractable_transfer: ...`, `retractable_transfer rejected: ...`) and
the generic error code. A park that fails the sender's `o5` policy, the fee step
or the balance surfaces as for an ordinary transfer.

## Timing caveats

- **Block timestamps are proposer-chosen**, within the parent's timestamp and the
  proposer's clock plus 120 seconds. A time-based release can land up to about two
  minutes early, and a retract near a time deadline is judged by the block's
  timestamp, not by wall-clock time. Height-based release points are exact.
- **Backlog.** A feeless retract sorts last when the mempool is backed up, so it
  can sit behind fee-paying transactions past the release point. Retract with
  margin, or retract while the chain is quiet.
- **Height does not advance on an idle chain** (see [Idle chains](#idle-chains)).

## Raw transactions

Only **root fields** are read and signed. A nested `payload` or `operations` is
unsigned data and is ignored.

| `tx_type` | Fields beyond the envelope |
|---|---|
| `retractable_transfer` | `recipient_pubkey` (96 lowercase hex), `amount`, exactly one of `release_at_height` / `release_at_time` |
| `retract_transfer` | `retractable_id` (64 lowercase hex); `fee_limit` `"0"` |

The envelope is the usual `sender_pubkey` (96 lowercase hex), `sequence_number`,
`expiration_time`, `expire_at_height`, `fee_limit` and signature. All numeric
fields are unsigned 64-bit integers. `sender_pubkey` must be the signer.

## Consensus notes

- The open-entry book is part of consensus state. Its root is always folded into
  the consensus metadata hash, with no activation flag, so an empty book still
  contributes a defined value.
- Resolved entries leave memory. The book keeps only a **count** and an
  order-dependent **running hash** of what was resolved, so the root and the
  per-block copy cost depend on the open set alone.
- Introducing the field changes the metadata hash of every block, so it needs a
  **regenesis**, and every node must run the same build. An older binary forks at
  the first park block.

## Not in this release

- Custom inputs (`--input`) on a retractable transfer.
- Co-signed retractable transfers.
- Recipient refusal: the recipient cannot decline an open entry.
- Partial retraction or editing an open entry.
- Multi-leg or split payments.
- Heartbeat blocks: the chain does not mine empty blocks on a schedule.
- A wallet UI.
