# Envelopes (spending limits, time conditions, refunds)

An envelope is money sent with conditions written on it. The sender sends an
amount to a recipient; the money leaves the sender at once and waits in the
envelope. It is the recipient's to spend, to anyone, but only as the
conditions allow: so fast (a spending limit), not before a time or for a while
after it arrives (time locks), only on some weekdays or hours (windows), and
what is left may come back to the sender (refunds). Every node enforces the
conditions when it applies a block, so no wallet, bot or server has to be
trusted to keep them.

Every condition is optional; an envelope carries at least one. All of an
envelope's conditions are read on its one clock, blocks or seconds:

```
unlock    = max(sent, not_before, sent + hold)      no spend before it
period n  = (clock - unlock) // period              the limit's periods start at the unlock
cap(n)    = caps[n]                  while n < len(caps)
          = caps[-1]                 after the list, when recurring
          = no limit                 after the list, when not recurring
idle      = (clock of the last spend, or unlock) + refund_idle
due       = min(expires_at, idle)                   the earlier decides; a tie is the end

a spend lands at clock c when
          unlock <= c < due
          the block's weekday is in days, its hour in hours (both read at utc_offset)
          1 <= amount <= what the envelope holds
          spent in period n + amount <= cap(n)

at due    unused for refund_idle (idle came first)  the rest goes back to the sender
          expires_at, at_end refund                 the rest goes back to the sender
          expires_at, at_end release (default)      the rest goes to the recipient
```

Nothing carries over: what was not spent in one period does not raise the
next period's cap.

Typical uses:

| Envelope | Conditions | Reads as |
|---|---|---|
| A child's pocket money | caps `[100]` weekly, recurring | at most 100 a week, every week; the rest is the child's at the end |
| A project budget | caps `[5000]` every 30 days, recurring | at most 5,000 a month |
| An advance, then instalments | caps `[1000, 500]` monthly, recurring | 1,000 in the first month, then 500 a month |
| A day's spending money | hold 6 h, ends at midnight, at_end refund | nothing for six hours; what is not spent by midnight comes back |
| A gift for later | not_before 1 Dec | the recipient's from 1 December |
| Lunch money | days mon..fri, hours 11-14, utc_offset +02:00 | spendable on the sender's weekdays around lunch only |
| Use it or lose it | refund_idle 30 days | unused for 30 days, the rest comes back |
| A cooling-off payment | hold 24 h, at_end refund, end in 30 days | the recipient waits a day; what they do not spend in a month returns |
| A budget with all of it | caps `[500]` weekly, not_before 1 Dec, days mon..fri, at_end refund | 500 a week on working days from 1 December; the rest returns at the end |

Short reference: [README](../README.md#envelopes-spending-limits-time-conditions-refunds). CLI summary:
[developer_cli.md](developer_cli.md#envelopes). This guide is the long form.

## Lifecycle

```
envelope_send ──► locked (until the unlock) ──► open ──► envelope_spend (recipient, inside
                    │                            │       the windows, within the cap) ... ──► emptied
                    │                            │
                    ├──► envelope_release (sender, any time): the rest to the recipient: released
                    └──► due point reached (end of that block):
                           unused for refund_idle .......... the rest to the sender: refunded_idle
                           expires_at, at_end refund ........ the rest to the sender: refunded
                           expires_at, at_end release ....... the rest to the recipient: ended
```

Every step is recorded in the node's history: `sent`, `spend` (one per spend,
with the payee, the amount, what remains and what the period has used),
`emptied`, `released`, `ended`, `refunded` and `refunded_idle` (each with
`paid_out` and `paid_to`: `recipient` or `sender`).

## Sending

```bash
tau-testnet envelope send --key parent --to <child_pubkey> --amount 5200 \
    --cap 100 --recurring --period 7d --ends-in 52w
tau-testnet envelope send --key client --to <contractor_pubkey> --amount 4000 \
    --cap 1000,500 --recurring --period 30d --ends-in 210d
tau-testnet envelope send --key dao --to <team_pubkey> --amount 20000 \
    --cap 2000 --recurring --period-blocks 10000 --ends-in-blocks 100000
# nothing for six hours, and what is not spent by midnight (UTC) comes back
tau-testnet envelope send --key alice --to <bob_pubkey> --amount 100 \
    --hold 6h --ends-at 2026-11-18 --at-end refund
# 500 a week on working days from 1 December; unused for 30 days or left at
# the end, it comes back
tau-testnet envelope send --key alice --to <bob_pubkey> --amount 5000 \
    --cap 500 --recurring --period 7d --not-before 2026-12-01 --days mon-fri \
    --refund-idle 30d --ends-at 2027-03-01 --at-end refund
```

| Field | Meaning |
|---|---|
| `recipient_pubkey` | Who may spend (96 lowercase hex, a valid BLS key). Not the sender. |
| `amount` | What the envelope holds, 1 .. 16,777,215 (the transfer limit). It leaves the sender when the send is mined. |
| `expires_at` | The end, on the envelope's clock: a block height or a unix time (block time). In the future, at most 10,000,000 blocks or four years of 366 days ahead. |
| `caps` | Optional, the spending limit: 1 .. 12 caps, each 1 .. 16,777,215: the cap of period 0, 1, 2, ... |
| `period_blocks` or `period_seconds` | With `caps`, exactly one: the period, 1 .. 1,000,000 blocks or 1 .. 31,622,400 seconds (366 days). It also chooses the envelope's clock. |
| `recurring` | Optional, with `caps`. After the list, the last cap repeats every period. Without it, the limit stops after the list. Default false. |
| `clock` | `blocks` or `seconds`. Required without `caps` (it names the clock); with `caps` optional and must match the period. |
| `not_before` | Optional. No spend before this clock value (a height, or a unix time). |
| `hold` | Optional, 1 .. the lifetime limit. No spend for this long after the envelope arrives. |
| `days` | Optional, seconds clock only. The weekdays a spend may land on: day names `mon` .. `sun`, Monday first, each once, not all seven. |
| `hours` | Optional, seconds clock only. The hours a spend may land in: 0 .. 23, increasing, each once, not all 24. `[9, 10]` is 09:00 to 11:00. |
| `utc_offset` | Optional, only with `days` or `hours`. Where they are read: a whole number of quarter hours east of UTC, -48 .. 56 (UTC-12:00 .. UTC+14:00), never 0. `8` is UTC+02:00, `-14` is UTC-03:30. Left out, they are read in UTC. |
| `refund_idle` | Optional, 1 .. the lifetime limit. Unused this long (from the unlock, then from each spend), the rest goes back to the sender. |
| `at_end` | Optional. `release` (the default): at the end the rest goes to the recipient. `refund`: it goes back to the sender. |

The CLI takes `--cap` repeated or comma-separated (first period first),
`--period` as a duration (`3600`, `90s`, `15m`, `12h`, `7d`, `2w`) or
`--period-blocks`, and the end: `--ends-in` / `--ends-at` (time clock;
`--ends-at` takes unix seconds or `2027-01-01[T08:30]`, UTC) or
`--ends-in-blocks` / `--ends-at-height` (block clock). The end chooses the
clock, and every other flag must be on it: `--not-before` / `--hold` /
`--refund-idle` / `--days` / `--hours` on the time clock, `--not-before-height`
/ `--hold-blocks` / `--refund-idle-blocks` on the block clock. `--days` takes
`mon-fri`, `sat,sun` or `fri-mon`; `--hours` takes `9-17` (09:00 to 17:00, so
hours 9 .. 16), `22-6` (across midnight) or `9,12,13`. `send` prints the
envelope id.

A send the envelope could never be spent from is refused (code
`ENVELOPE_NEVER_SPENDABLE`): one that would unlock only at or after its end, or
whose windows do not open between its unlock and its first due point (its end,
or its idle point when it is not used at all).

A send costs one transfer fee, paid by the sender, on top of the amount. A
sender may have 16 envelopes open at once; the node holds 4,096 in total.

### The id

`envelope_id` is a BLAKE3 hash over the sender, the sequence number of the
transaction that sent it, and every term above (`compute_envelope_id`). Spends
and releases name it, so they can never touch a different envelope. The time
conditions and refunds are encoded only when an envelope carries one, so an
envelope with only a spending limit has the same id it had before they
existed.

## Conditions

### Time locks: `not_before` and `hold`

`not_before` locks the envelope until a clock value: a date on the time clock,
a height on the block clock. `hold` locks it for a while after it arrives,
counted from the block that sent it, so a sender does not need to know when
the send will be mined. With both, the later one wins. A `not_before` already
in the past locks nothing. The unlock also starts the spending limit's periods:
"500 a week from 1 December" counts its weeks from 1 December, not from the day
the money was sent.

### Windows: `days` and `hours`

A spend lands only in a block whose timestamp falls on an allowed weekday and
in an allowed hour (both, when both are given). Windows need the seconds
clock. `getenvelope` shows whether the next block is inside a window
(`in_window`) and when the next window opens (`next_window`). A refused spend
says when the next window opens.

**Whose weekdays and hours.** They are read at the offset from UTC the sender
signed, `utc_offset`, in quarter hours east of UTC; left out, they are UTC. So
"weekdays 9 to 17" can mean the sender's working week and not London's:

```bash
# Monday to Friday, 09:00 to 17:00 in Berlin winter time (UTC+01:00)
tau-testnet envelope send --key alice --to <bob> --amount 2000 \
    --days mon-fri --hours 9-17 --utc-offset +01:00 --ends-in 52w
```

The node computes `local = block time + utc_offset * 900` and takes the
weekday and the hour of `local`. That is all: the offset is a fixed number in
the payment, the chain knows no time zones and no daylight saving time. A
payment that runs across a clock change keeps the offset it was signed with,
so its windows then sit one hour off the wall clock until it ends. With an
offset that is not a whole hour (`+05:45`), a window opens and closes on a
quarter hour of UTC. `getenvelope` returns the signed `utc_offset` and
`windows_read_at` (`UTC+01:00`), and a refusal names the next window in UTC
and at the offset.

### Refunds: `refund_idle` and `at_end`

`refund_idle` returns an envelope nobody uses: when no spend has landed for
that long (counted from the unlock, then from each spend), the rest goes back
to the sender at the end of the block that reaches the point (outcome
`refunded_idle`). With `at_end refund`, what is left at `expires_at` goes back
to the sender (outcome `refunded`); with `at_end release`, the default, it goes
to the recipient (outcome `ended`). When the idle point and the end fall on the
same clock value, the end decides. Combined, `refund_idle` with `at_end
release` reads "use it or lose it, but what is left at the end is yours".

A refund is the sender's own money coming back, not a payment: it lands in the
sender's own balance, is fee-free, needs no signature and passes no `o5`
clause and no receive route. Nobody can change an envelope's conditions after
the send, and the sender still cannot take money back early: it can only
release the rest to the recipient (also on an envelope with `at_end refund`).

## Combining conditions

Every condition on an envelope applies at once: a spend lands only when each
of them allows it, and the earlier of the end and the idle point closes it.
Any mix may be written on one envelope, each condition at most once. A spend is
judged in a fixed order, and the first condition that refuses names itself:
due point reached, locked, outside the windows, more than the envelope holds,
over the cap.

Alice sends Bob 5,000: at most 500 a week from 1 December, only on working
days; unused for two weeks, or left on 29 December, it comes back to her.

```bash
tau-testnet envelope check --to <bob_pubkey> --amount 5000 \
    --cap 500 --recurring --period 7d --not-before 2026-12-01 --days mon-fri \
    --refund-idle 14d --ends-at 2026-12-29 --at-end refund
```

```
The recipient may spend 5,000 from Tue 2026-12-01 00:00 UTC, only on Mon-Fri (UTC),
to anyone. At most 500 per week, every period; the periods count from the unlock,
and nothing carries over. If the recipient spends nothing for 2 weeks, what is left
goes back to the sender. At Tue 2026-12-29 00:00 UTC what is left goes back to the
sender. The sender cannot take it back earlier, only release the rest to the
recipient at once.
  info: The limit lets at most 2,000 of the 5,000 be spent before the end; at least
  3,000 goes back to the sender at Tue 2026-12-29 00:00 UTC, unless it is released
  or refunded earlier.
```

With `--utc-offset +01:00` the same check reads "only on Mon-Fri (UTC+01:00)",
and with hours "only on Mon-Fri and only 09:00-17:00 UTC+01:00": the text always
names where the weekdays and hours are read. The notes follow the offset too
(a weekday or an hour that covers the whole life of the envelope is counted on
the envelope's own days).

`envelope check` reads the conditions offline: no key, no node, nothing sent
(times count from now or `--at-time`; on the block clock give `--at-height`).
`envelope send` prints the same reading before it submits, and refuses locally
what the node would refuse. A node answers the same for a queued send:
`sendtx` and `checktx` add `plan`, `notes` and `text` to `envelope`.

**The grant with three conditions only.** At most 500 a week, only from
1 December, and what is not spent by the deadline goes back to Alice:

```bash
tau-testnet envelope send --key alice --to <bob_pubkey> --amount 5000 \
    --cap 500 --recurring --period 7d --not-before 2026-12-01 \
    --ends-at 2026-12-29 --at-end refund
```

```
The recipient may spend 5,000 from Tue 2026-12-01 00:00 UTC, to anyone. At most 500
per week, every period; the periods count from the unlock, and nothing carries over.
At Tue 2026-12-29 00:00 UTC what is left goes back to the sender. The sender cannot
take it back earlier, only release the rest to the recipient at once.
  info: The limit lets at most 2,000 of the 5,000 be spent before the end; at least
  3,000 goes back to the sender at Tue 2026-12-29 00:00 UTC, unless it is released
  or refunded earlier.
```

Week by week, as a block with that timestamp decides it:

| Block time (UTC) | Bob spends | What happens |
|---|---|---|
| 30 Nov 23:59:59 | 1 | refused: locked until 1 December |
| 1 Dec 00:00 | 500 | lands; week 1 is full |
| 3 Dec, 7 Dec | 1 | refused: the cap 500 leaves 0 |
| 8 Dec | 300 | lands; week 2 started on its own |
| 10 Dec | 201, then 200 | 201 is refused (the cap leaves 200), 200 lands |
| 15 to 21 Dec | nothing | week 3 passes unused |
| 22 Dec | 501, then 500 | 501 is refused: nothing carried over; 500 lands |
| 29 Dec 00:00 | 1 | refused; at the end of that block the remaining 3,500 is back with Alice |

Bob spent 1,500 and Alice has 3,500 back, with no transaction of hers and no
fee.

### What each part says

- **`text`**: the conditions as sentences.
- **`plan`**: the points that matter for an envelope sent now: `unlocks_at` and
  `unlocked_by` (`not_before`, `hold`, or both when they meet), `first_spend_at`
  (the first moment inside the windows), `first_due_at`, `first_due_by` (`end`
  or `refund_idle`) and `first_due_outcome`, and for a limit `limit_periods`
  (how many periods begin before the end), `limit_caps` (the caps that can
  apply), `most_spendable` (what the limit lets through before the end) and
  `limit_lapses_at`.
- **`notes`**, each with a `level`, the `condition` and a `code`:

| Code | Level | Says |
|---|---|---|
| `NOT_BEFORE_PASSED` | never_decides | `not_before` is already past when it arrives. |
| `NOT_BEFORE_COVERED` | never_decides | The hold reaches as far or further. |
| `HOLD_COVERED` | never_decides | `not_before` reaches as far or further. |
| `LIMIT_NEVER_BINDS` | never_decides | Every cap that can apply is at least the amount. |
| `CAPS_UNREACHED` | never_decides | Caps after the first N can never apply: the envelope ends first. |
| `RECURRING_UNUSED` | never_decides | The list covers every period, or the last cap is at least the amount. |
| `DAYS_COVER_LIFE` | never_decides | Every day from the unlock to the end is an allowed weekday. |
| `HOURS_COVER_LIFE` | never_decides | Every hour from the unlock to the end is an allowed hour. |
| `IDLE_NEVER_FIRES` | never_decides | The end comes first (or together, and the end decides a tie). |
| `IDLE_BETWEEN_WINDOWS` | warning | `refund_idle` is not longer than the longest time with no window open: the rest may go back while the recipient cannot spend. |
| `LIMIT_LAPSES` | info | The limit stops after its list; from then on the rest may be spent freely. |
| `LIMIT_LEAVES_REST` | info | The limit lets through less than the amount before the end; the rest goes where `at_end` says. |

A `never_decides` note is **certain**: that one condition could be removed and
every spend, refusal and close would stay exactly the same, for every sequence
of spends. On the block clock and without `refund_idle` the notes are also
**complete**: a `not_before`, `hold`, limit or `recurring` without a note does
change something; a `refund_idle` without a note always does. With windows or
an idle refund a condition may still change nothing without a note saying so.
`tests/test_envelope_combined.py` proves both by exhaustive search (below).

### A send that could never be spent

The node refuses it (`ENVELOPE_NEVER_SPENDABLE`). The CLI names the clash:

```
refused: It would unlock at Thu 2026-11-19 10:00 UTC (the hold of 2 days), but it
ends at Wed 2026-11-18 00:00 UTC: it could never be spent.
refused: No spending window (Sat, Sun) opens between the moment it unlocks at Tue
2026-11-17 10:00 UTC and Wed 2026-11-18 10:00 UTC (the refund after 1 day unused):
it could never be spent.
```

The check is exact: with one clock per envelope and windows that repeat every
week, the node finds the first moment a spend could land (the unlock, or the
first window after it, at most 168 hours on) and compares it with the first
due point.

### How the readings are proved

- **Never spendable is exact.** On every envelope of a block-clock universe
  (48,000 term sets: every mix of `not_before`, `hold`, `refund_idle`, end,
  cap schedules, periods, `recurring`, `at_end` and amount around one sending
  height) and on 6,000 random time-clock envelopes, most with windows, a send
  is refused exactly when no moment exists at which a spend of 1 lands, tried
  through the book's own spend check (weekdays and hours read with Python's
  `datetime`).
- **The notes are certain.** For every `never_decides` note in that universe,
  and on 250 random envelopes with windows, the envelope with and without the
  condition is checked for **bisimilarity**: every sequence of spends at every
  block clock (no spend, or 1 up to what is left) must give the same accepts,
  refusals and closes. The search walks pairs of book states, so it covers all
  sequences without listing them.
- **The notes are complete where this guide says so**, by the same search.
- **The proofs have teeth.** Nine planted bugs in the notes (a lock or idle
  point one tick off, a cap one short, the last period forgotten, the last hour
  unread, a tie missed) are each rejected by them.
- **The walkthrough runs.** The 5,000 envelope above, built with the CLI's own
  flags, goes through the real block apply: locked before 1 December, 500 a
  week, refused on a Saturday, back to Alice 14 days after the last spend; and
  left alone, 3,000 back on 29 December. The grant with three conditions runs
  the table above line by line.

## Spending

```bash
tau-testnet envelope spend --key child <envelope_id> --to <shop_pubkey> --amount 40
tau-testnet envelope spend --key child <envelope_id> --to self --amount 60
```

- Only the recipient spends. The payee is anyone, the recipient included
  (`--to self` moves money from the envelope to the recipient's own balance,
  where it is free of the limit; the limit is on the envelope, not on the
  person).
- A spend lands only if the envelope is open and has not reached its due point
  (its end or its idle point), it is unlocked, the block lies in its windows,
  the amount is at most what it holds, and the period's spent amount plus this
  one stays within the period's cap; refusals come in that order. Spends in
  the same block count in block order, so two spends cannot overrun a cap
  together. The node checks a spend
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

## The end and refunds

At the end of the block whose clock reaches the due point (the end, or the
idle point), the envelope closes: the rest goes to the recipient (`ended`) or
back to the sender (`refunded`, `refunded_idle`), as above. No spend lands in
that block: an envelope at its due point is closed to spends. Due envelopes
close after the block's transactions and the retractable releases, before the
standing-payment sweep, block clock first, then by due point and id. The miner
wakes an idle chain for a due envelope (as for a retractable release or a
standing payment), so a refund does not wait for the next transaction.

## Which clock

Every envelope has exactly one clock, and every condition on it is read on
that clock: the period, the end, `not_before`, `hold` and `refund_idle`. One
clock per envelope means any two conditions can be compared, which is what lets
a node refuse an envelope that could never be spent, exactly, when it is sent.

- **Blocks** (`period_blocks`, or `clock: "blocks"`): the block height. Exact
  and not chosen by anyone; a proposer cannot reach a height early, whatever
  timestamp it writes. Height does not advance on an idle chain, but the miner
  wakes for a due envelope.
- **Seconds** (`period_seconds`, or `clock: "seconds"`): the block timestamp,
  never a node's own clock, so proposer, verifiers and replay agree. The
  proposer chooses it: at least the parent's timestamp, at most 120 s
  (`MAX_BLOCK_FUTURE_DRIFT_SECONDS`) past the clock of every node that
  validates the block. So a time condition can be reached up to about two
  minutes early, and a proposer can hold time back: a lock then opens late, a
  window stays open late and a refund comes late. Time never runs backwards.
  Weekdays and hours need this clock and are read at the envelope's
  `utc_offset` (UTC when it has none).
- Clause-step clocks (a Tau clause counting its own steps, `[t > 3]`) are never
  used: they depend on how often an interpreter was stepped, not on the chain.

The anchor of the periods is the unlock, the clock value at which the first
spend may land.

## Receive routes

What a spend pays and what reaches the recipient at a release or the end are
payments, and they pass through the receive route of the account they land on
(see [receive_routes.md](receive_routes.md)): credit classes `envelope_spend`
(the payee) and `envelope_release` (the recipient, at a release or the end).
The send itself credits nobody, so it is not split. A refund
(`envelope_refund`) is never routed: it is the sender's own money coming back.

## Inspecting

```bash
tau-testnet envelope show <envelope_id>
tau-testnet envelope list --key child --role in      # envelopes the key may spend from
tau-testnet envelope list <address> --role out       # envelopes an address sent
tau-testnet rpc "getenvelope <envelope_id>"          # raw RPC
tau-testnet rpc "getenvelopes <address> in"
```

`getenvelope` answers `open`; for an open envelope `envelope` holds the terms
and where it stands at the next block: `status` (`locked`, `open` or `ended`),
`spendable_now`, `remaining`, `spent_total`, `unlocks_at`, `in_window` and
`next_window`, `idle_refund_at`, `due_at` and `due_outcome` (where the rest
goes then: `ended`, `refunded` or `refunded_idle`), `period_index`,
`cap_this_period`, `spent_this_period`, `left_this_period` (the most one spend
may take under the limit) and `next_reset` (when the next period starts, or
`null` without a limit or once it has lapsed), and `text`, its conditions in
plain words. A closed envelope answers `closed` (how it closed). `history` lists its events on canonical blocks, newest first, and
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
how it closed (`emptied`, `released`, `ended`, `refunded`, `refunded_idle`).
`sendtx` and `checktx` answer `envelope`: what the envelope would hold, and what
the period would have left, after the transaction; for a send also `plan`,
`notes` and `text` (see [Combining conditions](#combining-conditions)).

## Limits

| Limit | Value |
|---|---|
| Caps per envelope | 12 |
| Open envelopes per sender | 16 |
| Open envelopes in total | 4,096 |
| Amount, each cap, each spend | 1 .. 16,777,215 |
| Period | 1 .. 1,000,000 blocks, or 1 .. 31,622,400 s |
| End | at most 10,000,000 blocks, or four years of 366 days, ahead |
| `hold`, `refund_idle` | 1 .. 10,000,000 blocks, or 1 .. four years of 366 days |
| `days`, `hours` | 1 .. 6 weekdays, 1 .. 23 hours (seconds clock) |
| Envelope transactions per mempool snapshot | 64 |

## Error codes

| Code | When |
|---|---|
| `INVALID_ENVELOPE` | The transaction is malformed, breaks a limit, sends to the sender itself or to an invalid key, carries no condition, puts windows on the block clock, or its end is not ahead. |
| `ENVELOPE_NEVER_SPENDABLE` | The envelope would unlock only at or after its end, or no window opens between its unlock and its first due point. |
| `DUPLICATE_ENVELOPE` | This exact envelope is already open. |
| `TOO_MANY_ENVELOPES` | The sender already has 16 open envelopes. |
| `ENVELOPE_BOOK_FULL` | 4,096 envelopes are open. |
| `NO_ENVELOPE` | No open envelope has this id. |
| `NOT_ENVELOPE_RECIPIENT` | A spend signed by anyone but the recipient. |
| `NOT_ENVELOPE_SENDER` | A release signed by anyone but the sender. |
| `ENVELOPE_ENDED` | The envelope has reached its end, or its idle point (it goes back to the sender at the end of this block). |
| `ENVELOPE_LOCKED` | The spend comes before the unlock; the message says until when (a block height, or Unix seconds with the moment in UTC). |
| `ENVELOPE_OUTSIDE_WINDOW` | The block would fall outside the envelope's weekdays or hours; the message says when the next window opens (Unix seconds, UTC, and the envelope's own offset when it has one). |
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

{"tx_type": "envelope_send", "sender_pubkey": "<sender>", "sequence_number": 9,
 "expiration_time": 1799999999, "expire_at_height": 5000, "fee_limit": "20",
 "genesis_hash": "<64 hex>", "recipient_pubkey": "<recipient>", "amount": 100, "clock": "seconds",
 "hold": 21600, "at_end": "refund", "expires_at": 1794960000, "signature": "..."}

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
The optional fields (`clock`, `not_before`, `hold`, `days`, `hours`,
`utc_offset`, `refund_idle`, `at_end`) are signed when present and left out of the signed
bytes when absent, so a spending-limit envelope signed before they existed
keeps its bytes; adding or stripping one breaks the signature.

## Consensus notes

- The book (one row per open envelope: the id, the terms and where it stands)
  plus a running commitment of every close (`emptied`, `released`, `ended`,
  `refunded`, `refunded_idle`, with what was paid out) is folded into the
  consensus metadata as `envelopes_root` **only once the book has held an
  envelope**. An envelope with a time condition or refund also commits the
  clock of its last spend; one without encodes exactly as before, so a node
  upgraded with spending-limit envelopes open computes the same root. Until then the metadata is
  unchanged, so **no regenesis** is needed; nodes must upgrade before the first
  envelope is sent.
- What a spend may take, and when an envelope closes, depend only on the
  block's height or timestamp and the book, both replicated, so proposer,
  verifiers and replay agree.
- Money in envelopes is part of the supply: the engine's conservation check on
  every block counts balances plus every escrow, envelopes included.
- Money in an envelope is not balance, so it does not count as stake.
- The history (`envelope_events`) is node-local and not hashed; the block
  metadata carries the same events for receipts.
- Envelope transactions travel on their own gossip topic,
  `tau/envelopes/1.0.0`.

## The conditions in Tau

The node checks an envelope's conditions itself, in `EnvelopeBook.check_spend`,
and the sender's and recipient's own `o5` rules on the Tau engine, as for any
transfer. The conditions can also be written in Tau:
`tests/test_envelope_tau_form.py` turns the terms of any envelope into the body
of one `always` clause, in the form the policy worker runs, and has the real
engine judge thousands of spends next to every point where a verdict changes
(the unlock, the end, the idle refund, each period boundary, each window edge,
and amounts around what the cap leaves). The engine and the node agree on every
case. The clause is built from the signed terms alone; what changes after the
send reaches it as input streams: the spend's amount, the block's clock and
time, what the envelope holds, the period and amount of the last spends, and
the unlock point.

The node keeps the check for three reasons:

- **The history comes from the book.** What a condition depends on (spent
  this period, the last spend, what is left) reaches the clause as inputs that
  the node computes and stores anyway, so the clause can confirm the node's
  arithmetic on the node's numbers but cannot replace the book.
- **Time comes from the block.** In the Tau form the clock is an input like any
  other; the step counter `t` counts interpreter steps, not blocks or seconds,
  so `[t > n]` cannot express "not before" (see #115).
- **Cost.** One engine call per spend, about 2 ms with the clause cached and
  about 20 ms to build it on a 2-core ARM server, against microseconds for the
  node's check; and every envelope would be its own clause to build and keep
  cached, up to 4,096 of them.

A sender who wants a condition an envelope does not offer can still write it in
their own `o5` rule, which judges the send; the recipient's rule judges each
spend.

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

**Idle chains.** The miner also wakes for an envelope whose end, refund or
idle refund is due at the next block (at most one attempt every 2 seconds), so
a refund lands on time on a quiet chain.

**Network.** `envelope_send`, `envelope_spend` and `envelope_release` gossip on
`tau/envelopes/1.0.0`; a mempool snapshot carries at most 64 of them.

## Security notes

- A stolen recipient key can drain an envelope only at the pace of its limit:
  at most one cap per period, only after the unlock and only inside the
  windows. A release does not help (it pays the same key), so choose the
  conditions and the end with that in mind. With `at_end refund`, what the
  thief could not spend in time comes back to the sender.
- A payment to the wrong person, or one a scammer talked the sender into, can
  be sent with a `hold` and `at_end refund`: if the recipient never spends it,
  it comes back on its own. Once spent, it is gone; a hold only buys time.
- A proposer controls the block timestamp within the bounds above, never the
  height. For conditions where minutes matter, use the block clock.
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
- **One clock per envelope.** Mixing a block-clock hold with a time-clock end
  would make "can this ever be spent" undecidable at the send.
- **The periods start at the unlock**, not at the send.
- **The idle timer starts at the unlock** and restarts at each spend; a spend
  of any size counts as use.
- **A tie between the idle point and the end goes to the end**, so `at_end`
  decides what happens on the last day.
- **Windows are weekdays and whole hours at a fixed offset from UTC.** The
  sender signs the offset (`utc_offset`, quarter hours; UTC when left out). No
  time zone names, no daylight saving, no minutes or dates in the chain; a
  wallet translates.
- **A refund is never routed and never judged by a clause**: it is the sender's
  own money coming back.
- **The readings are advice, not consensus.** `plan`, `notes` and `text` are
  computed from the terms the node already judges and change nothing a node
  accepts; a wallet may show them or not. Only `ENVELOPE_NEVER_SPENDABLE` is a
  refusal, and it is the node's own check.

## Not in this release

- Conditions other than these (a list of allowed payees, a co-signer for spends
  above a size, a refund triggered by an event other than time). `semantics`
  lists the conditions a node supports.
- A refund back to the sender before the end at the sender's request: the
  sender can never take money back early.
- Topping up an open envelope, or a standing payment that pays into one.
- Partial releases.
