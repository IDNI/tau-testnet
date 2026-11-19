# Rule-computed payouts

A payout rule lets an account pay amounts that a **Tau rule computes** from
state and inputs, within caps the owner declares: royalties, escrow release,
warranty holdbacks, profit shares, patronage dividends.

Capability request: [IDNI/tau-testnet#63](https://github.com/IDNI/tau-testnet/issues/63)
(extends [#34](standing_payments.md)).

## Example: a 5% royalty

`royalty.tau` — one clause body; `o1` pays recipient slot 1, `o2` slot 2:

```tau
(o1[t]:bv[24] = i13[t]:bv[24] / { 20 }:bv[24]) && (o2[t]:bv[24] = i13[t]:bv[24] - i13[t]:bv[24] / { 20 }:bv[24])
```

```bash
tau-testnet payout install --key shop --rule-file royalty.tau \
  --recipient <artist_pubkey> --recipient <seller_pubkey> \
  --max-per-execution 2000 --max-per-period 50000 --period month
# payout rule id: <64 hex>

# A sale of 1,000: anyone submits the execution with the price as input i13.
tau-testnet payout execute --key relayer <rule_id> --input 13=1000
# -> 50 to the artist, 950 to the seller, from the shop's balance
```

## How an execution works

1. The node steps the rule once, in an isolated policy worker of its own pool
   (`payout`), so the rule's stream typing can never clash with the chain's
   interpreter or with `o5` policy clauses.
2. Recipient slot *k* is paid the value of output `o<k>` (bv[24]); an
   unwritten output pays 0. **The rule chooses amounts only**: recipients are
   fixed at install time, so a rule can never pay an undeclared account.
3. The total must be positive, at most `max_per_execution`, and fit in what is
   left of `max_per_period` for the current period.
4. Every leg runs through the **owner's** ordinary transfer gates: current
   `o1`/`o5` policy, the fee step and the balance check. Legs are credited
   through receive routes like any transfer.
5. All legs apply atomically, or none do. A rule that does not build or step,
   writes an unreadable amount, pays nothing, breaks a cap, or meets a policy
   block or a shortfall rejects the whole transaction.

### Rule inputs

| Stream | Value |
|---|---|
| `i1` | owner's spendable balance before the execution (bv[24]) |
| `i2` | executions so far in the current period (bv[24]) |
| `i3` | period index (bv[64]) |
| `i13` … `i20` | values supplied by the executor in `inputs` (decimal or Tau bitvector literal) |

Executor inputs are untrusted by design: the rule decides how much weight they
get, and the caps bound the damage of any input. Third-party-attested inputs
(oracles, delivery confirmations) are [#62](https://github.com/IDNI/tau-testnet/issues/62).

## Fees

`payout_rule_install` (owner) and `payout_execute` (executor) are fee-bearing.
The execution is priced like a multi-transfer `user_tx`: one fee step per leg,
paid by the executor. `payout_rule_remove` is fee-exempt.

## Admission

An install must build in the payout pool before it is admitted, so a rule
that can never run is refused up front. Rules are capped at 8 KiB of text,
8 recipients, 4 rules per owner and 4096 in total.

## State and RPC

The `PayoutBook` is a field of the consensus lifecycle manager; its root
enters the meta hash only once the first rule is installed. Persisted as
`payouts_v1`; every rule id is recomputed on load.

`getpayoutrules <address> [in|out|all]` returns each rule's text, recipients,
caps, `paid_this_period`, `left_this_period` and the input conventions above.

## Transactions

`payout_rule_install` (owner): `rule_text`, `recipients`, `max_per_execution`,
`max_per_period`, `period_kind`, `period_seconds`, `start_at`, `expires_at`.

`payout_execute` (anyone): `rule_id`, `inputs`.

`payout_rule_remove` (owner): `rule_id`. Removal follows the account's normal
rules; protected policy administration (#33) can later lock it.
