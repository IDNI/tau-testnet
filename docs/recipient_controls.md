# Accepting payments

A shop can accept payments only from approved senders, refuse payments that can still be recalled, or combine the two. Check the node's `getgovernance` response first. Offer these options only when `data.recipient_controls_active` is `true`. A missing field means the node predates this feature.

## Require immediate payment

Save this line in `instant.rule` and submit it using the receiving account's key.

```text
recipient_v1 o5[t] {"max_hold_seconds":0}
```

```sh
tau-testnet tx send --key shop --rule-file instant.rule
```

In the bundled web wallet, paste the same line into the transaction’s rule editor after connecting to a node that reports active recipient controls. Leave the transfer and custom-operation fields empty and confirm the rule-only transaction.

Once the installation is confirmed, the shop still accepts ordinary transfers. A sender who tries to park a payment to the shop gets `RECIPIENT_MAX_HOLD` with `max_hold_seconds: 0`. Releasing or retracting a payment parked before the shop changed its rule follows the terms of the original park.

A cap of 600 accepts a time-based park with up to and including 600 seconds left. To accept height-based parks as well, set `max_hold_blocks` explicitly. Each cap applies to its own unit. With just a seconds cap, every height-based park is refused, since the length of a block in seconds is unknown. With neither cap, the recipient imposes no fixed hold limit.

## Allow payments from a particular sender

This example writes a rule file from a payer's 96-digit hexadecimal public key. It also sets a ten-minute cap on time-based parks. The `inbound` field holds one Tau clause. Its `o5` output has the same width as a sender's policy. Zero refuses the transfer.

```python
import json
from pathlib import Path

payer = input("Payer's public key (hex): ").strip().lower()
if len(payer) != 96 or any(c not in "0123456789abcdef" for c in payer):
    raise ValueError("expected a 96-digit BLS public key")
allow = "o5[t]:bv[24] = { #x000001 }:bv[24]"
deny = "o5[t]:bv[24] = { #x000000 }:bv[24]"
rule = f"always ( (i3[t]:bv[384] = {{ #x{payer} }}:bv[384]) ? ({allow}) : ({deny}) )."
policy = {"inbound": rule, "max_hold_seconds": 600}
Path("shop.rule").write_text("recipient_v1 o5[t] " + json.dumps(policy), encoding="utf-8")
```

Deploy with `tau-testnet tx send --key shop --rule-file shop.rule`. Use a rule-only transaction. Each installation replaces the complete inbound policy, including its hold limits. Keep every inbound setting the shop still needs in the new file. To remove all inbound restrictions, submit `recipient_v1 o5[t] {}`. To set an outgoing Tau clause at the same time, include an `outbound` string in the JSON object. Omitting it preserves the current outgoing clause. The account's rule-change guard applies to the update. Replacing an existing inbound clause or relaxing a hold cap also requires the guard to allow revocation. The existing co-signed rule-change request accepts ordinary Tau clauses only. An account whose guard requires co-signatures for this change cannot install this envelope under that guard.

After confirmation, query `getruleoffers <shop_pubkey>`. The `recipient_policy` field contains the stored inbound clause body and any caps. The RPC returns caps as decimal strings so wallets can read the full unsigned 64-bit range. A null value means the account has no registered inbound policy.

| Inbound input | Type | Value |
| --- | --- | --- |
| `i1` | `bv[24]` | Amount of this transfer output |
| `i3`, `i4` | `bv[384]` | Actual sender and recipient public keys, respectively |
| `i12` | `bv[384]` | Policy owner (the recipient) in an inbound clause |
| `i5` | `bv[64]` | Candidate timestamp at admission, header timestamp at apply |
| `i17`, `i27` | `bv[64]` | Seconds or blocks until release, respectively |

The receiving account owns the clause. An owner-guarded inbound rule can match the shop on `i12` and the payer on `i3`. In the global sender pass, `i12` still identifies the sender. The node supplies the hold values in this evaluation. A plain transfer has zero on both streams. A park sets the stream for its release unit and leaves the other at zero.

## Reading a refusal

Use `checktx estimate` with the signed transaction for a full preflight. Plain `checktx` can skip policy evaluation. Admission evaluates time-based parks against the later of the tip timestamp and the node's current Unix time, and height-based parks against the next block height. Block application uses the block's own timestamp and height. A preflight therefore describes the candidate the node checked. A different inclusion time or an intervening policy change can change the result.

If a payment was queued and the recipient changed their policy before mining, use `gettxstatus <tx_hash>` on the node that recorded the rejection to read the reason and detail.

A recipient's Tau clause returns `RECIPIENT_POLICY_BLOCKED` when it refuses a transfer. A declared hold limit returns `RECIPIENT_MAX_HOLD` with the receiving key, the configured cap and the proposed hold. The error identifies the transfer's one-based position in a batch. The sender's policy is also enforced. A recipient refusal rejects the whole transaction before any fee, sequence or output is committed, including an earlier output that passed. Offers, approval requests and retracts do not deliver a new payment. For a co-signed transfer, the request pays its fee up front. If the recipient refuses the transfer at the final vote, the vote is recorded, the request ends as failed, the principal stays with the sender and the original request fee remains paid.

## Activating a network

For a new network, pass `--recipient-controls` to `scripts/gen_genesis.py` when generating the genesis that all nodes will use. For an existing network, upgrade the validators before scheduling a governance update with the following host-contract patch.

```json
{"recipient_controls_active": true}
```

Activation is permanent. If governance activates the update at the end of block H, recipient controls apply to transactions starting in H+1. Older blocks replay under their original rules. Query `getgovernance` after activation before enabling the options in a wallet. A node running this release on an inactive chain refuses an attempted installation with `FEATURE_INACTIVE`.
