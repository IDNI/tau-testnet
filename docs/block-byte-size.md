# Block stored JSON byte size

Consensus limits each block to **18 874 368** UTF-8 bytes (`MAX_BLOCK_BYTES` in
`block.py`). This document defines how to count these bytes.

## What is measured

The size of a received block is:

```text
len(json.dumps(Block.from_dict(payload).to_dict()).encode("utf-8"))
```

`payload` is the received JSON object. `Block.from_dict` normalizes it (see
"Normalization before the count"). The byte count uses the normalized block, not
the received text. The received text can be longer or shorter than the counted
text.

The normalized form is written to SQLite (`db._write_block_rows`) and returned inside
`{"blocks": […]}` from `get_blocks`. `Block.from_dict` of a normalized block gives
the same block again.

`json.dumps` uses Python’s defaults unless stated otherwise:

| Option | Value |
| --- | --- |
| `separators` | `(", ", ": ")` — comma and colon each followed by one space |
| `ensure_ascii` | `True` — non-ASCII via `\uXXXX` or surrogate pairs |
| `sort_keys` | `False` |
| `indent` | `None` |

## Key order and object equality

The byte count of an object depends only on its keys and values. A different key
order gives the same byte count. When a key appears twice in a JSON object,
`json.loads` keeps the last value. The node uses only that value, also for the
number rule.

The normalization keeps only the keys that the next sections name for the block
object and for the header. Each transaction object keeps every received key, with
the key order of the received block body.

## Normalization before the count

`Block.from_dict` (`block.py`) does these steps in this order. A step that cannot
complete makes the block invalid.

1. The number rule (below) applies to the whole received object. It also applies
   to the keys that the next steps drop.
2. The received block must be a JSON object. The value of `header` must be a JSON
   object. A missing `header` is an empty object. `"header": null` makes the block
   invalid.
3. The block object keeps only `header`, `transactions`, `block_hash`,
   `consensus_proof` and `tx_ids`. It drops every other key. A received `hash` is
   read as `block_hash` (step 7).
4. The header keeps only the 7 keys of "Header object key order". It drops every
   other key.
5. Each header key gets a value of a fixed type. In this table, an empty value is a
   missing key, `null`, `false`, `0`, `""`, `[]` or `{}`.

   | Header key | Received value | Value after normalization |
   | --- | --- | --- |
   | `block_number`, `timestamp` | an empty value | integer `0` |
   | | `true` | integer `1` |
   | | an integer | the same integer |
   | | a string | the Python `int()` of the string, see below |
   | | a non-empty array or object | the block is invalid |
   | `previous_hash`, `merkle_root`, `state_hash` | an empty value | 64 times `"0"` |
   | `proposer_pubkey`, `state_locator` | an empty value | `""` |
   | all five string keys | a string | the same string |
   | | `true` | `"True"` |
   | | a non-zero integer | its decimal text as a string, for example `"5"` or `"-5"` |
   | | a non-empty array or object | the Python `str()` text, for example `[1, "a"]` gives `"[1, 'a']"` |

   The Python `int()` of a string removes these characters at the two ends:
   U+0009 to U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028,
   U+2029, U+202F, U+205F and U+3000. U+001C to U+001F are not in this set. It then
   reads an optional `+` or `-` and one or more decimal digits, with no character
   between the sign and the first digit. A single `_` can stand between two digits.
   A digit can be any Unicode decimal digit, for example `"\u0663"` gives `3`.
   Leading zeros are allowed. Any other string makes the block invalid. The list
   `int_header_strings` of the test vectors gives examples.

   `block_number` and `timestamp` must then be in 0 to 2^64 - 1.

   `previous_hash`, `merkle_root`, `state_hash` and a non-empty `proposer_pubkey`
   must be hex text of this form: zero or more pairs of hex digits. A hex digit is
   `0` to `9`, `a` to `f` or `A` to `F`. ASCII whitespace (U+0009 to U+000D and
   U+0020) can stand before each pair and at the end. No character can stand
   inside a pair. Any other text makes the block invalid. The header hash uses the
   bytes of the pairs. The byte count uses the text as received, with its
   whitespace and its case. Past block 0, `merkle_root` must also be equal, as a
   string, to the computed root: 64 lower-case hex digits. No step reads
   `state_locator`.
6. `transactions` stays when it is an array. Any other value, and a missing key,
   gives `[]`.
7. `block_hash` is the first non-empty value of `block_hash`, then of `hash`, as a
   string. When both are empty, it is the header hash. Past block 0, a value that is
   not the header hash makes the block invalid.
8. `consensus_proof` keeps the received value of any type. A missing key gives
   `null`.
9. A missing or `null` `tx_ids` gives the list of the transaction hashes. Past
   block 0, every other value stays as received, and it must be equal to that list.
   In block 0, a value that is not an array of strings gives that list.

## Top-level block object key order

`Block.to_dict()` emits keys in this order:

1. `header`
2. `transactions`
3. `block_hash`
4. `consensus_proof`
5. `tx_ids`

## Header object key order

`BlockHeader.to_dict()` emits:

1. `block_number`
2. `previous_hash`
3. `timestamp`
4. `merkle_root`
5. `proposer_pubkey`
6. `state_hash`
7. `state_locator`

## Transactions

`transactions` is a JSON array. Each element is an object copied from the block
body without re-sorting keys. Key order is therefore:

- For blocks built in Python: insertion order of the transaction `dict`.
- For blocks loaded from JSON: key order preserved by `json.loads` (peer wire or
  DB text).

Nested objects (e.g. `operations`) keep their own insertion order the same way.

Transaction hashes (`compute_tx_hash`) use a **different** canonical form
(`sort_keys=True`, `separators=(",", ":")`). That form is **not** used for the
byte cap.

## Numbers and other literals

Every number in a block is an integer from `-9223372036854775808` (-2^63) to
`18446744073709551615` (2^64 - 1). This rule applies to the whole received block
object: the header, every transaction, every nested value, and the keys that the
normalization drops.
A block with another number is invalid, and mempool admission refuses such a
transaction. The node refuses these numbers:

- a number with a fraction or an exponent, for example `1.5`, `7.0`, `1e5`, `-0.0`,
- `NaN`, `Infinity` and `-Infinity`,
- an integer below -2^63 or above 2^64 - 1.

`json.dumps` writes the other literals in these forms:

| Python value | Form | Examples |
| --- | --- | --- |
| `int` | decimal digits, a minus sign for a negative value | `0`, `42`, `-7` |
| `bool` | literal | `true`, `false` |
| `None` | literal | `null` |

An integer has no leading zeros and no plus sign, so its form is the same on
every node.

## String escaping (`ensure_ascii=True`)

Short escapes (two-character JSON backslash sequences, counted as two UTF-8 bytes
each in the JSON text):

| Character | JSON text |
| --- | --- |
| U+0008 BACKSPACE | `\b` |
| U+0009 TAB | `\t` |
| U+000A LINE FEED | `\n` |
| U+000C FORM FEED | `\f` |
| U+000D CARRIAGE RETURN | `\r` |
| `"` | `\"` |
| `\` | `\\` |

Other controls U+0000–U+001F except the five above → `\u00xx` (lowercase hex,
six UTF-8 bytes in the JSON text). **U+007F DELETE** → `\u007f`.

ASCII printable except `"` and `\` appear literally. Other non-ASCII scalars →
`\uXXXX` (lowercase hex). Code points above U+FFFF → UTF-16 surrogate pair as two
`\uXXXX` escapes.

## Test vectors

Fixed examples with expected byte counts live in
`tests/fixtures/block_byte_size_vectors.json`. Each vector includes the full
`block_json` text; tests assert the UTF-8 length and, for escape cases, that the
text contains the short escapes above (not `\u000a` for newline, etc.).
The list `invalid_number_literals` gives number forms that make a block invalid.
A vector with `received_byte_count` has keys that the normalization drops. Its
`byte_count` is the count after the normalization.
The list `int_header_strings` gives strings in `block_number` with the integer that
Python `int()` reads, or `null` for a string that makes the block invalid.

## Validity rule

1. Every number of the received block object obeys the number rule above.
2. Normalize the block as "Normalization before the count" says.
3. Write the normalized block as JSON text, with the separators, the key order and
   the escapes above.
4. Count the UTF-8 bytes of the text. A block is valid only if the count is at
   most `18874368`.
