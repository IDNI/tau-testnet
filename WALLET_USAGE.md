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

### Custom Operations
```bash
python wallet.py send --privkey <private_key> \
  --operation "2:custom_data" \
  --operation "5:more_data"
```

### Complex Multi-Operation Transaction
```bash
python wallet.py send --privkey <private_key> \
  --rule "o2[t]=i1[t]" \
  --transfer "recipient_address:5" \
  --operation "2:custom_data" \
  --operation "5:more_data"
```

### Raw JSON Operations (Advanced)
```bash
python wallet.py send --privkey <private_key> \
  --operations-json '{"0": "o2[t]=i1[t]", "1": [["sender", "receiver", "10"]], "3": "custom_op"}'
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

The wallet supports the following operation types:

- **Operation "0"**: Rules/Logic formulas (sent as-is to Tau)
- **Operation "1"**: Coin transfers (SBF-encoded by the server)
- **Operation "2", "3", etc.**: Custom operations (encoding depends on server implementation)

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
  --operation "3:custom_asset_data" \
  --operation "7:governance_vote"
```

This creates a transaction with operations 0, 1, 3, and 7, with missing operations 2, 4, 5, 6 filled with "F" when sent to Tau.

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
    "2": "custom_operation_data"
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