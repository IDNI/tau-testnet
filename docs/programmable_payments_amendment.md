## Amendment (#145): programmable payments are one Tau rule

Submitted for approval under the rule @andrei-idni stated on PR #146: critical bounties are design first, the first correct design is the one that is approved, and later changes are amendments. The acceptance criterion is that new payment policies and combinations of actions are expressed through Tau rules and configuration, without a new feature-specific execution path in the Python node.

This amendment replaces the shape of PR #145. `consensus/payments.py` and `consensus/periods.py` are that kind of path (standing payments, receive routes, payout expressions, and allowances each have their own transaction types and their own checks). We will not extend them. After this amendment is approved, #145 is reworked onto the runner below, and those two modules come out.

One rule per account is the whole bounty. The rule text decides who is paid, how much, and under which combination of conditions. The node only decides when to ask the rule, feeds it facts, and applies the transfers the rule writes.

### The runner

An account carries one clause and a signed configuration. The configuration is not a policy. It names three things:

- **When the rule is asked.** `execute` (someone submits a transaction; the executor pays the ordinary fee), `clock` (`due_at`, repeated by `due_every` in seconds or by `due_months`), or `on_arrival` (a user transfer credited to the account). A clock or arrival rule requires an end, `until` or `max_fires`, so automation cannot be permanent by accident.
- **The parties.** Up to eight pubkeys. One party may be `executor_dest`, the pubkey on the execution transaction. The rule writes one `bv[24]` amount per party. Zero pays nothing. The amounts apply atomically, or the run pays nothing.
- **The seal.** `rule_only: true` means the node admits no transaction the account signs: no spend, no fee, no rule replacement, including a rule-change request that was already waiting. Money enters by ordinary transfer and leaves only as amounts the rule writes. The seal ends at `until`.

The clause is the policy. A different cap, a different share, a different combination of conditions, or a different order between them is a different clause. Stream numbers are one allocation for this runner, chosen by the maintainers. They are not a stream per feature.

Bounds, shared with the cost model in @jimb000o's amendment of 20 Nov: at most 16 executions, 16 clock runs, and 16 arrival runs in a block. A self-running rule's shortest interval is 256 blocks. A rule the node will run by itself is stepped once at admission on the inputs of such a run, and a rule the evaluator cannot answer does not reach a block. Inside a block the order is fixed: user transactions, then arrival runs for credits those transactions created, then clock runs. A revoke in the block is already in effect when the clock run happens.

### Each capability

**Standing / recurring (#34).** Clock trigger, and the clause writes a constant to party 0 when the executor input is 0 (the node asked).

```
always ( (i_executor[t]:bv[384] = { 0 }:bv[384])
         ? (o_party0[t]:bv[24] = { 100 }:bv[24])
         : (o_party0[t]:bv[24] = { 0 }:bv[24]) ).
```

Signed with `due_at` and `due_months: 1`, this pays 100 on that civil day each month. Each due point is derived from the anchor, so a rule signed for the 31st runs on the last day of a short month and on the 31st again after it. A due point the chain has passed is not caught up: the scheduler opens the latest due whose window contains now, and earlier indexes close unpaid. While the window is open and the run pays nothing (the balance is short, or the clause writes 0), the due index stays open and the next block asks again. At the end of the window the index closes unpaid. There is no debt and no catch-up. Cancelling is revoking the rule; on an unsealed account a revoke in the same block as the due point wins.

On an unsealed account every amount the rule writes is screened by the account's current o5 clause, the same screen a normal transfer gets. A freeze written after the standing payment was signed stops the next run. On a sealed account the clause is the only authorization, which is what the seal is for.

**Receive routes (#35).** Arrival trigger. The clause writes the share. Integer division, which is the same operation the route clause below uses:

```
always ( o_party0[t]:bv[24] = i_gross[t]:bv[24] / { 5 }:bv[24] ).
```

A transfer of 101 pays 20 to party 0 and leaves 81 on the account. The payer pays 101 and the fee of that one transaction. The arrival run takes its amounts from the incoming credit, in the same write as the credit and before any later transaction in the block can spend it. Amounts that sum to more than the credit reject the transfer. A fee, a faucet credit, and any amount this runner wrote are not arrivals, so a routed share is not routed again, including by a route on the account that received the share. A floor, an exempt payer, an end date, and two shares are four different clauses on this same trigger. More than 16 arriving transfers wait for a later block as transactions, not as credits that have already landed unsplit.

**Rule-computed payouts (#63).** Execution trigger. The executor supplies `event_id`, the gross, and the asked amount. The clause writes the legs. The node records `(rule, event_id)` when a non-zero run commits, and a second submission of the same id is refused before the clause is paid again. "Pays 5, once" is that record plus a clause that writes 5. The executor pays the fee. The account that holds the funds is not charged.

**Period spending limits.** The clause keeps the amount it has written this period in its own memory (below) and compares the asked amount with `cap - spent`. A new period is a different value of the period index, and the clause treats the spent memory as 0 when the index changes. A week is `(i5 - anchor) / 604800` inside the clause, so "from 1 December" is the anchor written in the clause. A calendar month is the civil-month input below, because a clause should not reimplement leap years. A different cap per recipient is a different memory slot, or a different account. One cap over several payments is one account and one slot.

**Time locks.** The clause compares `i5` with a constant. Before the constant every party amount is 0.

**Schedules.** `due_at`, `due_every`, `due_months`, plus weekday and hour computed in the clause from `i5`. The hour is `i5 / 3600` with the day-multiple subtracted. The weekday is the remainder of `(i5 / 86400 + 3)` divided by 7, Monday = 0, because the Unix epoch was a Thursday. The clock is UTC. A fixed offset is a constant in the clause. The node carries no timezone table.

**Holds.** The funding arrival writes `i5` into a memory slot. A later draw writes an amount only when `i5` is at least that slot plus the hold length.

**Idle refunds.** A daily clock run writes the whole spendable balance to the funder when `i5` is past the memory of the last draw by the idle length.

**Expiry and refunds.** The first branch of the clause: once `i5` reaches the deadline, write the spendable balance to the funder and write 0 to every other party. A clock trigger at that timestamp runs it with nobody present. The clock run has no fee, so the returned amount is the full remainder.

**Combined conditions.** One clause. Conjunction is Tau `&&`. Which condition wins is the order of the branches in the clause. Expiry is the first branch in the grant below, so a draw submitted in the deadline block writes nothing to the recipient. There is no precedence table in Python.

### The 5,000 payment

Alice funds a fresh account with 5,000. The account is `rule_only` until 1 January 2027. Party 0 is `executor_dest`. Party 1 is Alice. Memory is `period` and `spent`. Clock trigger `due_at = 1798761600` (2027-01-01 00:00 UTC). Anyone may execute.

The clause, in the order it decides:

1. If `i5 >= 1798761600`, write `spendable` to Alice and 0 to party 0.
2. If `i5 < 1796083200` (2026-12-01 00:00 UTC), write 0.
3. Let `week = (i5 - 1796083200) / 604800`. If `week` differs from the `period` memory, the spent figure for this decision is 0; otherwise it is the `spent` memory.
4. If the asked amount is greater than 0, at most `500 - spent`, and at most `spendable`, write that amount to party 0 and write `week` and `spent + asked` back to memory.
5. Otherwise write 0.

One history: 300 and then 200 in week 0 (the second execution sees 300 in memory), 500 in week 1, 200 in week 2, and 3,800 to Alice at the deadline. A draw of 501 in week 0 writes 0 and moves nothing. The same clause with `due_at = 1798502400` (29 December) and three draws of 500 returns 3,500. Both histories sum to 5,000.

Bob never holds a key that can spend the 5,000 or pay a fee with it. He draws by submitting executions. Alice's refund is a clock run, fee-free.

### The histories already named

These are the acceptance cases named on this issue, each as a clause on the runner:

- 101 at 20% leaves 20 and 81, and the payer pays one fee. Clause: `gross / 5`.
- 5% of 101 pays 5 once. Clause writes 5, and the `event_id` record refuses the second execution.
- A routed share does not route again. Amounts the runner writes are not arrivals.
- A monthly rule signed for the 31st runs on the last day of a short month. `due_months` derives that day from the anchor.
- The 5,000 grant returns the remainder above. 1,200 drawn returns 3,800.

### What the node has to grow

Tau clauses are stateless, and `i5` is a single timestamp. Four primitives are the whole addition. Each one is used by any rule the node runs for itself, and none of them knows what the rule is for.

1. **Rule-written transfers.** The node applies the party amounts the clause writes, through the existing balance gate. This is the generic "a rule can move funds" output. Standing payments, routes, royalties, draws, and refunds are clauses on it.
2. **Time.** `i5` stays the block timestamp (non-decreasing, at most 120 seconds ahead of a verifier's clock). Weekday, hour, and fixed-length periods are arithmetic on `i5` inside the clause. Civil year, month, and day are inputs derived from `i5` by one integer UTC calendar, and `due_months` uses that same calendar to choose the next due point, clamping the anchor day to the last day of a short month. A clause cannot do that calendar in a way reviewers can check. This is a clock service. It does not count money.
3. **Memory the clause itself writes, and a consumed-id set.** Up to four `bv[64]` values. The node stores them per `(account, rule version)` and feeds them back. It does not interpret them. After a run commits, later runs in the same block see the new values, in block order. `i2` cannot be this: it is the sender's balance at the parent block for the whole block (issue #20). The runner also feeds `spendable`, the balance at this run after earlier writes in the block, so a refund in the deadline block returns what is still there, and a second draw in one block sees the first draw's memory. The consumed set records `(rule, event_id)`. Clock and arrival ids are derived (the due index, the transfer id). An execution id is supplied by the executor. An id is recorded when a non-zero run commits; a clock window that closes on a zero run records the id as unpaid.
4. **`rule_only`.** While set, the account's key is not an author of transactions. This is the generic form of "this balance moves only when its rule says so." It closes two holes that exist on main today, where #33 is not available: the key can wait out a rule-change guard's 1,000 blocks, and the key can pay fees from the balance. The supply check is unchanged, because the funds are an ordinary balance.

Arrival funding (the amounts come out of the incoming credit, in that credit's write) is part of primitive 1, not a route feature. Screening an unsealed account's outputs with its current o5 clause is the existing transfer screen, not a new one.

The signed configuration commits to the genesis hash. A rule signed for one network is rejected on another.

### What this covers beyond the amendments already posted

@jimb000o's amendment of 20 Nov (one rule path, three triggers, sealed accounts, routes and rent as clauses) is the right shape, and this amendment follows it. Four points in that amendment are still node policy, or still open against the issues:

- A due point that cannot pay is recorded unpaid and is not asked again. Issue #34 says an underfunded occurrence does not advance the marker, and a later block inside the window may still pay it. Here the due index stays open until a non-zero run commits or the window ends.
- "What the rule paid this period" is a node counter fed to the clause (`i26` in the 19 Nov amendment). The period then has a meaning in Python. Here the clause adds what it just wrote into its own memory. The node stores the integer.
- Weeks count from install unless a further node field, `periods_from`, is added. Here the anchor is the constant in `(i5 - anchor) / 604800`, so "from 1 December" does not depend on a new field.
- An unsealed account's payout does not go through o5. A standing payment signed from an ordinary account would then ignore a freeze the owner wrote later. Here an unsealed account's outputs pass the current o5 screen. A sealed account does not need that screen, because its key cannot sign.

@forkproven's amendment keeps the grant decision moving into a clause, keeps weeks anchored at the signed open time, and keeps the refund fee-free so 1,200 drawn returns exactly 3,800. Those three are right, and this amendment keeps them. The book beside the clause still checks the window, the per-period cap, and the shared group cap in Python (`GrantBook`, `consensus/periods.py`), and the route share is still node arithmetic over signed basis points. A clause that authorizes more than the book allows is cut down by the book, so the policy lives in both places. Here the cap, the window, the week index, and the share are the clause. A shared cap across two recipients is two memory slots in one clause (`spent_a + spent_b` against one constant), or one account both draw from. The 108 draw histories are a property of that clause, checked by executing it, not of a group counter in a book.

@kioway-dev's amendment pins a concrete payout encoding and open execution (anyone executes, the executor pays, a settlement id pays once, legs come only from the clause). This amendment keeps all four of those for every run, not only for payouts. The state he lists — schedules, route tables, escrow grants, settlement records, a shared-cap counter — is the feature path the criterion is about. He notes that Tau cannot remember, and offers a single rule-driven ledger if that is what is wanted. Memory, the consumed-id set, and the clock are that ledger. One record of "the integers this clause wrote" replaces a book per feature.

### Migration of #145, after approval

1. Replace the branch. Delete `consensus/payments.py`, `consensus/periods.py`, the payment transaction types, the payment books, and the feature RPC. Do not merge #145 as it stands.
2. Add only the four primitives above, with stream numbers the maintainers assign.
3. Re-express the tests as clauses on the real engine: the five histories in the section above, the intra-block memory case (300 then 200 in one block sees 300), the sealed key being refused, and a restart that replays to the same state hash.
4. The demo installs this clause and this configuration. It does not open an allowance.

No node code changes with this amendment. #145 stays as it is until the amendment is approved.
