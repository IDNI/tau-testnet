# Enhanced Wallet Usage Guide

The `wallet.py` tool now supports sending transactions with multiple operations, including rules and custom operations.

## Basic Commands

### Generate a new keypair
```bash
python wallet.py new
```

### Check balance
```bash
python wallet.py balance --address <public_key_hex>
# or
python wallet.py balance --privkey <private_key>
```

### Check transaction history
```bash
python wallet.py history --address <public_key_hex>
# or
python wallet.py history --privkey <private_key>
```

### Pending-aware account state and tx status

`getbalance` returns only the confirmed chain balance. `balance` is what the
account can spend: for an account with no record on the chain yet, it includes
the faucet grant of the genesis, and `faucet_pending` is `true`. Two additive
node commands give a wallet the mempool view:

- `getaccountstate <address>` — `chain_balance`, `faucet_pending`, `pending_outgoing`,
  `pending_incoming`, `pending_fees`, `available_balance`, and a `pending_txs`
  list. `pending_outgoing` is the transfer total only; the sender's admission fee
  estimate is reported separately in `pending_fees`. `available_balance = max(0,
  chain_balance − pending_outgoing − pending_fees)`; unconfirmed incoming is
  reported but not spendable. All amounts are decimal strings.
  `chain_balance − available_balance` is the authoritative "not currently
  spendable" amount — it stays correct regardless of how the constituent fields
  are split, so prefer it over summing them yourself.
- `gettxstatus <tx_hash>` — `queued` | `confirmed` | `expired` | `evicted` |
  `rejected` | `unknown`. `sendtx` returns the `tx_hash` on success, so a wallet
  can poll status right after queuing.

## Sending Transactions

The `send` command now supports multiple operation types:

### Simple Transfer (Backwards Compatible)
```bash
python wallet.py send --privkey <private_key> --to <recipient_address> --amount <amount>
```

### Rule-Only Transaction
```bash
python wallet.py send --privkey <private_key> --rule "o12[t]=i1[t]"
```

### Rule + Transfer
```bash
python wallet.py send --privkey <private_key> \
  --rule "o12[t]=i1[t]" \
  --transfer "recipient_address:amount"
```

### Multiple Transfers
```bash
python wallet.py send --privkey <private_key> \
  --transfer "recipient1:amount1" \
  --transfer "recipient2:amount2" \
  --transfer "recipient3:amount3"
```

A single transaction can carry up to 64 transfers in `operations["1"]`, applied
atomically (all commit or none). This is the supported way to do **fee-splits,
donations, or fan-out payouts** entirely client-side — no special protocol
primitive is needed. There is no amount-transform / routing output; the credited
amounts are exactly the tuple amounts.

### Custom Operations
```bash
python wallet.py send --privkey <private_key> \
  --operation "13:custom_data" \
  --operation "100:more_data"
```
*Note: Keys 2–12, 14 and 15 are always reserved, and further keys are reserved in some modes (see Operation Types). Use keys 26 and above for custom application data that a policy rule reads.*

### Complex Multi-Operation Transaction
```bash
python wallet.py send --privkey <private_key> \
  --rule "o12[t]=i1[t]" \
  --transfer "recipient_address:5" \
  --operation "13:custom_data" \
  --operation "26:more_data"
```

### Raw JSON Operations (Advanced)
```bash
python wallet.py send --privkey <private_key> \
  --operations-json '{"0": "o12[t]=i1[t]", "1": [["sender", "receiver", "10"]], "13": "custom_op"}'
```

## Command Line Options

### Required
- `--privkey`, `-k`: Private key (hex or decimal format)

### Operation Options (at least one required)
- `--to`, `-t`: Recipient address for simple transfers
- `--amount`, `-m`: Amount for simple transfers  
- `--rule`, `-r`: Rule to add as operation 0 (e.g., 'o12[t]=i1[t]')
- `--transfer`: Transfer in format 'to_address:amount' (can be used multiple times)
- `--operation`, `-o`: Custom operation in format 'op_number:data' (can be used multiple times)
- `--operations-json`: Raw JSON operations object (overrides other operation options)

### Transaction Metadata
- `--fee`, `-f`: Fee limit (default: 0)
- `--expiry`, `-e`: Expiration seconds from now (default: 3600)

### Connection Options
- `--host`: Node host (default: from config)
- `--port`: Node port (default: from config)

## Operation Types

An operation key `N` maps to Tau input stream `iN`. The wallet supports:

- **Operation "0"**: Rules/Logic formulas (sent as-is to Tau)
- **Operation "1"**: Coin transfers — a **list** of `[from, to, amount]` tuples
  (up to 64 per transaction; SBF-encoded by the server)
- **Operations "13" and above**: User custom inputs (normalized to lists of
  strings). Up to 16 custom streams per transaction.

**Reserved streams (cannot be set by a user_tx):**

| Stream | Meaning |
|--------|---------|
| `i2` | sender balance at the **parent block**, frozen for the whole block. Readable by policy (`o5`) rules — e.g. a min-balance floor. Rejected in **fee** (`o8`) rules, since admission estimates against the head and the charge would differ from the quote. |
| `i3` / `i4` | sender / recipient pubkey (`bv[384]`, real at admission and apply) |
| `i5` | block timestamp (consensus clock) |
| `i6`–`i11` | consensus ABI (block height, ts, proposer, parent hash, proof, claims) |
| `i12` | sender pubkey (`bv[384]`, set by the node) |
| `i13` | proposer pubkey, reserved under the `tau_validator_set` eligibility mode |
| `i14` / `i15` | consensus stake / eligibility-mode inputs |
| `i16` | seconds since the sender's previous transfer (`bv[64]`). Reserved **only while the network feeds it**; until then it is an ordinary custom stream. While reserved, a policy clause may not read it. |
| `i18`–`i25` | co-signature approval slots, reserved once the chain has activated approvals; only the node fills them |

So user-controllable custom input streams start at **`i13`**, and the streams
above that are reserved as listed. Attempting to set a reserved stream as an
operation key is rejected at admission (and at block apply), so a crafted
`operations["12"]` cannot spoof the sender pubkey. Custom inputs read by an `o5`
policy rule (see below) start at **`i26`**, above the approval slots.

**Combining custom inputs with the transfer.** Custom streams are evaluated in
the *same* Tau step as the transfer at both admission and apply, so a policy
rule may gate a transfer on a custom input alongside the transfer fields. For
example, a passphrase-confirmation gate on `o5` (block unless `i26` matches and a
non-zero amount is sent):

```
always ( (i26[t]:bv[24] = { #x00002a }:bv[24] && i1[t]:bv[24] != { #x000000 }:bv[24])
         ? (o5[t]:bv[24] = { #x000001 }:bv[24])
         : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).
```

Sending the transfer with `--operation "26:0x2A"` yields `o5=1` (allow); a wrong
or absent `i26` yields `o5=0` and the transfer is rejected at `sendtx`, not just
at apply. The same holds for 2FA flags, escrow conditions, and multi-party
approval keyed on i26+.

**Pubkeys in custom streams.** Write a custom stream (`i13` and up) that holds
a pubkey as `iN[t]:bv[384]` at every reference, for example
`i13[t]:bv[384] = { #x… }:bv[384]`. The node runs pubkey streams at a smaller
internal width. A bare `i13[t]` takes its width from the rule text around it,
so it can conflict with another rule that uses the same stream. The node then
refuses the rule, and the error tells you to write `i13[t]:bv[384]`. The bare
form is correct for `i3`, `i4`, `i12` and the approval slots `i18` to `i25`,
because the node knows their width.

### User Policy Rules (`o5`)

A rule written to operation `"0"` that writes the user-policy stream `o5`
(`0` = block the transfer, `1`/absent = allow) is registered as **your own policy
clause**. **`o5` is consensus-enforced**: it is checked at mempool admission AND
re-checked by every validator at block apply. A policy block on any transfer
rejects the whole transaction (no partial execution); a malformed `o5` fails
closed (treated as block), and so does a registered clause the engine refuses to
evaluate for the transfer's inputs.

A clause is evaluated on its own, and only for transfers you send, so it carries
**no sender guard** and must not reference `i12`. You hold one clause; submitting
another replaces it. A transfer is blocked when the consensus rules or your
clause yield `o5 = 0`. A policy rule cannot share a transaction with transfers
(`RULE_WITH_TRANSFERS`): send the rule first, then the transfers.

A clause may read the amount (`i1`), your balance (`i2`), sender and recipient
(`i3`/`i4`), block time (`i5`), approval slots and custom inputs from `i26` up —
all real at both admission and apply. It must:

- be exactly one `always ( ... ).` unit;
- write every stream mention as `xN[t]:bv[W]` with an explicit width (`o5` and
  `i1` at `bv[24]`, `i5` at `bv[64]`, pubkey streams and approval slots at
  `bv[384]`) and use one width per stream;
- reference `[t]` only: `i1[t-1]` or `i1[0]` is refused with
  `TEMPORAL_REFERENCE`, because one unit that reads another step zeroes every
  output for the steps after each later revision, for all accounts;
- read at least one input stream, and build and step in the engine: a constant
  such as an unconditional block is refused. To block everything, test a
  condition on an input, such as amount above zero;
- stay within 32 comparisons and 32 levels of parentheses.

Examples expressible today:

- **Recipient whitelist:** `always ( (i4[t]:bv[384] = { #x<96-hex recipient pubkey> }:bv[384]) ? (o5[t]:bv[24] = { #x000001 }:bv[24]) : (o5[t]:bv[24] = { #x000000 }:bv[24]) ).`
- **Time-lock:** block transfers while `i5[t]:bv[64]` is below the unlock timestamp.
- **Spending limit:** block when `i1[t]` exceeds a per-tier cap.

To remove your clause, submit the neutral clause
`always ( (o5[t]:bv[24] = { #x000001 }:bv[24]) ).`. Changing or removing it fails
your open approval requests.

Policy clauses **may** read `i2` (balance): it is the sender's balance at the
parent block, frozen for the whole block, so admission and apply agree. A
min-balance floor is expressible:

- **Balance floor:** block when `(i2[t] - i1[t])` falls below your minimum.

Note two transfers from the same sender in one block both see the same pre-block
balance, so a floor does not compound within a block. **Fee** rules (`o8`) still
may not read `i2`: admission estimates it against the current head, so the fee
charged at inclusion could differ from the estimate quoted to the sender. Fee
rules, unlike clauses, accumulate in a shared specification and must reference
`i12` or `i3` to scope themselves to you (`UNSCOPED_USER_RULE`).

## Sharing Rules With Another User

Besides deploying a rule on your own transaction (operation `"0"`), you can
**send a rule to someone else**, who reviews it and either accepts it into their
own policy clause or rejects it.

```bash
# Alice offers Bob a policy rule (expires 1000 blocks from the current tip)
tau-testnet rule offer --key alice --to <bob_pubkey> --rule-file policy.tau

# Bob lists what has been sent to him
tau-testnet rule list --key bob --role in

# Bob reads the full text, then checks conflict status
tau-testnet rule show <offer_id>
tau-testnet rule check <offer_id>

# Bob accepts (the conflict report is printed first; --yes is required if it
# reports warn or conflict) -- or rejects
tau-testnet rule accept --key bob <offer_id>
tau-testnet rule reject --key bob <offer_id>
```

### What an offered rule may contain

An offered rule must be exactly one `always ( ... ).` unit that writes exactly
one permitted output stream — `o5` (user policy) today. It must not:

- reference `i12` — the clause is evaluated only for you, so it needs no sender
  guard;
- write consensus-owned streams (`o0`–`o4`, `o6`–`o9`);
- reference reserved input streams (`i13`–`i15`);
- reference any step but `[t]`;
- nest `always` / `sometimes`, or pack more than one unit.

It must satisfy the clause rules in [User Policy Rules](#user-policy-rules-o5):
explicit stream widths, at least one input read, and the comparison and nesting
limits.

Size and rate bounds are fixed by consensus, not configuration: 8 KiB per rule,
32 pending offers per recipient, 16 per offerer, and a 100 000-block maximum
offer window.

### How acceptance actually works

The node keeps a registry of `(account, target stream) -> clause`. Accepting an
offer registers the offered rule as **your** clause for that stream, exactly as if
you had submitted it yourself, and nobody else's transfers are affected: a clause
is evaluated only for its owner's transfers.

Practical consequences:

- **Accepting replaces your own clause** on that stream. To change it, accept a
  different offer or submit your own rule; to remove it, submit the neutral
  clause.
- An accept transaction repeats the offered `rule_text` **verbatim**. The node
  recomputes the offer id from it, so reformatting the text invalidates the
  accept. The CLI fetches the text from the node rather than retyping it.
- An accepted clause must build and step in the engine; one that does not is
  refused.
- Offers and accepts are fee-bearing.

### Reading the conflict report

`tau-testnet rule check <offer_id>` reports per layer: `shape`,
`reserved_domains`, `registry_collision` (do you already have a clause on this
stream, and who else does), `bv_widths`, and `compile` (does the clause build).

The report is **advisory and node-local** — it never gates a transaction. And
satisfiability is **not** checked: tau-lang exposes `sat`/`unsat`/`valid` in C++
but not through its Python bindings, so a logical contradiction cannot be
detected at all. A clean report means *no conflict was observed*, not that none
exists. Read the rule text before accepting it.

## Examples

### Example 1: User's Transaction with Rule and Transfer
```bash
python wallet.py send \
  --privkey "0x1234567890abcdef..." \
  --rule "o12[t]=i1[t]" \
  --transfer "0000000000000000000000000000000011cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09:1"
```

This creates a transaction with:
- Operation "0": The rule "o12[t]=i1[t]"
- Operation "1": A transfer of 1 unit to the specified address

### Example 2: Multiple Operations Transaction
```bash
python wallet.py send \
  --privkey "0x1234567890abcdef..." \
  --rule "o12[t]=i1[t]" \
  --transfer "recipient1:5" \
  --operation "13:custom_asset_data" \
  --operation "26:extra_input"
```

This creates a transaction with operations 0, 1, 13, and 26. Custom inputs must
not use a reserved key (keys 2–12, 14 and 15, and others in some modes; see
Operation Types). Governance
(rule proposals/votes) is a separate transaction type restricted to active
validators on the public testnet — it is not expressed via operation keys.

## Transaction Structure

The wallet constructs transactions with this JSON structure:

```json
{
  "sender_pubkey": "BLS_PUBLIC_KEY_HEX",
  "sequence_number": 0,
  "expiration_time": 1748526535,
  "operations": {
    "0": "rule_formula",
    "1": [["from_address", "to_address", "amount"]],
    "13": "custom_operation_data"
  },
  "fee_limit": "0",
  "signature": "BLS_SIGNATURE_HEX"
}
```

The server processes these operations and sends them to Tau in the format:
```
rule_formula
sbf_encoded_transfer
custom_operation_encoded_or_F
```

Where missing operations are filled with "F" up to the maximum operation number present. 