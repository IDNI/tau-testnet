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

`getbalance` returns only the confirmed chain balance. Two additive node
commands give a wallet the mempool view:

- `getaccountstate <address>` — `chain_balance`, `pending_outgoing`,
  `pending_incoming`, `pending_fees`, `available_balance`, and a `pending_txs`
  list. `pending_outgoing` includes the node's fee estimate (matching admission),
  and `available_balance = max(0, chain_balance − pending_outgoing −
  pending_fees)`; unconfirmed incoming is reported but not spendable. All amounts
  are decimal strings.
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
python wallet.py send --privkey <private_key> --rule "o2[t]=i1[t]"
```

### Rule + Transfer
```bash
python wallet.py send --privkey <private_key> \
  --rule "o2[t]=i1[t]" \
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
*Note: Keys 2–12 are reserved (see Operation Types). Use keys 13 and above for custom application data.*

### Complex Multi-Operation Transaction
```bash
python wallet.py send --privkey <private_key> \
  --rule "o2[t]=i1[t]" \
  --transfer "recipient_address:5" \
  --operation "13:custom_data" \
  --operation "14:more_data"
```

### Raw JSON Operations (Advanced)
```bash
python wallet.py send --privkey <private_key> \
  --operations-json '{"0": "o2[t]=i1[t]", "1": [["sender", "receiver", "10"]], "13": "custom_op"}'
```

## Command Line Options

### Required
- `--privkey`, `-k`: Private key (hex or decimal format)

### Operation Options (at least one required)
- `--to`, `-t`: Recipient address for simple transfers
- `--amount`, `-m`: Amount for simple transfers  
- `--rule`, `-r`: Rule to add as operation 0 (e.g., 'o2[t]=i1[t]')
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
| `i2` | balance (mocked to "0" at apply — not readable by rules) |
| `i3` / `i4` | sender / recipient pubkey (`bv[384]`, real at admission and apply) |
| `i5` | block timestamp (consensus clock) |
| `i6`–`i11` | consensus ABI (block height, ts, proposer, parent hash, proof, claims) |
| `i12` | sender pubkey (`bv[384]`, set by the node) |

So user-controllable custom input streams start at **`i13`**. Attempting to set
any reserved stream (`2`–`12`) as an operation key is rejected at admission (and
at block apply), so a crafted `operations["12"]` cannot spoof the sender pubkey.

**Combining custom inputs with the transfer.** Custom streams are evaluated in
the *same* Tau step as the transfer at both admission and apply, so a policy
rule may gate a transfer on a custom input alongside the transfer fields. For
example, a passphrase-confirmation gate on `o5` (block unless `i13` matches and a
non-zero amount is sent):

```
always ( (i13[t] = { #x2A }:bv[16] && i1[t] != {0}:bv[16])
         ? o5[t] = {1}:bv[16]
         : o5[t] = {0}:bv[16] ).
```

Sending the transfer with `--operation "13:0x2A"` yields `o5=1` (allow); a wrong
or absent `i13` yields `o5=0` and the transfer is rejected at `sendtx`, not just
at apply. The same holds for 2FA flags, escrow conditions, and multi-party
approval keyed on i13+.

### User Policy Rules (`o5`)

A rule written to operation `"0"` can emit the user-policy stream `o5`
(`0` = block the transfer, `1`/absent = allow). **`o5` is consensus-enforced**:
it is checked at mempool admission AND re-checked by every validator at block
apply. A policy block on any transfer rejects the whole transaction (no partial
execution); a malformed `o5` fails closed (treated as block).

Rules scope on the sender (`i12` pubkey, or `i3`) and may read the recipient
(`i4`), block time (`i5`), and amount (`i1`) — all real at both admission and
apply. Examples expressible today:

- **Recipient whitelist:** `always ( (i4[t] = {#x…}:bv[384]) ? o5[t] = {1}:bv[16] : o5[t] = {0}:bv[16] ).`
- **Time-lock:** block transfers while `i5[t] < {unlock_ts}:bv[64]`.
- **Spending limit:** block when `i1[t]` exceeds a per-tier cap.

Rules must NOT read `i2` (balance): it is mocked at apply, so a rule reading it
would diverge between admission and inclusion — such rule text is rejected.

## Sharing Rules With Another User

Besides deploying a rule on your own transaction (operation `"0"`), you can
**send a rule to someone else**, who reviews it and either accepts it into their
own specification or rejects it.

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

- reference `i12` — the node supplies your sender guard when it composes the
  rule, and a rule that guards itself does not actually isolate you (see below);
- write consensus-owned streams (`o0`–`o4`, `o6`–`o9`);
- read `i2` (balance), which is mocked at apply time;
- reference reserved input streams (`i13`–`i15`);
- nest `always` / `sometimes`, or pack more than one unit.

Size and rate bounds are fixed by consensus, not configuration: 8 KiB per rule,
32 pending offers per recipient, 16 per offerer, and a 100 000-block maximum
offer window.

### How acceptance actually works

Accepted rules do not simply get appended. The node keeps a registry of
`(acceptor, target stream) -> clause` and re-emits **one composite rule per
stream**, with each acceptor's clause behind a guard on their own public key and
a neutral value (for `o5`: allow) for everyone else.

This is not a stylistic choice. On the real engine an output stream that no
clause constrains for a given sender still materializes with an arbitrary value
— observed as `0`, which for `o5` means **block**. So a rule of the form
`always ( (i12 = you) -> (o5 = 1) ).` would grant you your policy and block
every *other* user's transfers. And two independently guarded rules on one
stream do not compose: conjoined they are unsatisfiable, and applied one after
another the later silently supersedes the earlier. The composite is the only
shape that keeps each acceptor's policy in force without affecting anyone else.

Practical consequences:

- **Accepting replaces your own clause** on that stream. There is no separate
  retraction; to change an accepted rule, accept a different offer.
- An accept transaction repeats the offered `rule_text` **verbatim**. The node
  recomputes the offer id from it, so reformatting the text invalidates the
  accept. The CLI fetches the text from the node rather than retyping it.
- Offers and accepts are fee-bearing.

### Reading the conflict report

`tau-testnet rule check <offer_id>` reports per layer: `shape`,
`reserved_domains`, `registry_collision` (do you already have a clause on this
stream, and who else does), `bv_widths`, and `compile` (does the *composed* rule
parse and step).

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
  --rule "o2[t]=i1[t]" \
  --transfer "0000000000000000000000000000000011cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09:1"
```

This creates a transaction with:
- Operation "0": The rule "o2[t]=i1[t]"
- Operation "1": A transfer of 1 unit to the specified address

### Example 2: Multiple Operations Transaction
```bash
python wallet.py send \
  --privkey "0x1234567890abcdef..." \
  --rule "o2[t]=i1[t]" \
  --transfer "recipient1:5" \
  --operation "13:custom_asset_data" \
  --operation "14:extra_input"
```

This creates a transaction with operations 0, 1, 13, and 14. Custom inputs must
use keys ≥ 13 (keys 2–12 are reserved; see Operation Types). Governance
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