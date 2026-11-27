## Interface design (#145): one payment ABI any Tau rule can use

For approval before more code, per @andrei-idni's review of #145 at `a060e5a` and the criteria in https://github.com/IDNI/tau-testnet/issues/34#issuecomment-7215221686. This replaces the symbolic streams in our amendment (https://github.com/IDNI/tau-testnet/issues/34#issuecomment-7057830046). #145's Python books stay until this is approved, then they come out.

One clause, one input map, one output map, one book. Rent, splits, royalties, allowances, time locks and refunds are clause text. A new combination is a new clause. Nothing under `consensus/` grows per feature.

Built on @jimb000o's actions, registers, wake and holdings, plus @forkproven's point that the clause is the decision, @clHODL's transactions-then-sweep order and freeze/manual/retry case, and @nikifers85's fixed map. There is no second ceiling in the node: a cap the clause does not write is not enforced. Clock steps take no fee from the funds: a fee taken first shrinks the offline refund and skips the step when the holding is smaller than the fee. The ABI is a reserved band, so it cannot poison process-global stream typing.

### ABI

Payment clauses are stepped on a cached interpreter per clause text (an uncached pool rebuilds on every switch: about 1.5 s for an allowance-sized clause, measured by @jimb000o on tau-lang `6ea436e8`). User rules, o5 clauses, offers and custom inputs are screened from mentioning `i200`–`i229` and `o200`–`o216`. `i5` is not reused: existing clauses type it at both `bv[24]` and `bv[64]`, and that typing is process-global. `i26` is not reused either: it is the first user custom input (`REQUEST_CUSTOM_INPUT_MIN`). `o1`–`o11` are already protocol streams (`o5` policy, `o8`/`o9` fees).

**Inputs**

| Stream | Width | Fact |
|---|---|---|
| i200 | bv[16] | trigger: 1 arrival, 2 execute, 3 clock, 4 created |
| i201 | bv[24] | event amount (gross, or amount asked) |
| i202 | bv[384] | payer or executor; 0 when the node asked |
| i203 | bv[384] | dest the request names; 0 otherwise |
| i204 | bv[24] | source available at this step |
| i205 | bv[384] | owner of the clause |
| i206 | bv[384] | beneficiary |
| i207 | bv[384] | origin (who paid the coins in) |
| i208 | bv[64] | time the instance was created |
| i209 | bv[64] | block timestamp |
| i210 | bv[16] | UTC year |
| i211 | bv[16] | UTC month, 1–12 |
| i212 | bv[16] | UTC day |
| i213 | bv[16] | days in this month |
| i214 | bv[16] | days in the next month |
| i215 | bv[64] | unix of this month's day 1, 00:00 UTC |
| i216 | bv[64] | unix of next month's day 1, 00:00 UTC |
| i217, i218 | bv[24] | registers r0, r1 as last committed |
| i219, i220 | bv[64] | registers r2, r3 as last committed |
| i221, i222 | bv[24] | amount parameters |
| i223, i224 | bv[64] | time parameters |
| i225–i228 | bv[384] | parties 0–3 |
| i229 | bv[16] | refused clock steps of this instance in a row |

**Outputs** (every one defined on every branch; the existing total-function screen)

| Stream | Width | Fact |
|---|---|---|
| o200–o203 | bv[24] | amount of action 0–3 |
| o204–o207 | bv[384] | recipient of action 0–3 |
| o208–o211 | bv[16] | under: 0 = pay out, n = hold under the owner's clause n |
| o212, o213 | bv[24] | r0, r1 after this step |
| o214, o215 | bv[64] | r2, r3 after this step |
| o216 | bv[64] | next wake; 0 = none |

`*`, `/` and `%` take a constant operand, so a percentage is a literal in the clause, not a parameter. Parameters are for comparisons (`asked <= cap`).

### What the node checks, and nothing else

A step is all or nothing. It is refused, with registers and wake unchanged, if any output is missing or mistyped, if the sum of the amounts overflows `bv[24]` or exceeds the source, if a recipient is not one of parties 0–3, owner, origin, beneficiary or the request dest, if `under` names no clause of the owner, or if a trigger-4 step writes a non-zero amount. A free-balance debit is also screened by the account's current o5 clause. A holding debit is not: the clause is the authorization, so a later freeze of the owner's key cannot trap a refund of coins already under the clause.

The source is the incoming credit on trigger 1 (remainder stays on the account), the free balance on an account instance, and the holding on a holding. `i2` is not the source: it is the parent-block balance for the whole block (issue #20). `i204` is the balance after earlier writes in this block.

A committed step writes registers, wake, debits and credits together. Trigger 4 only initializes registers and wake. An action with `under = n` creates a holding (balance = amount, clause n, origin, beneficiary = that action's recipient) and steps it once with trigger 4. That creation step cannot create holdings. A free credit written by a clause is not an arrival. So one event is one step plus at most four creation steps, and a holding pays later as its own event. Chains end there.

Install (`payment_clause_set`, owner-signed, chain id in the preimage, judged by the existing rule-change guard) carries the text (≤ 4096 bytes), four parties, the four parameters, `on_balance`, `on_arrival` (one per account) and `until` (≤ 4 years). No schedule, cap or refund address is a field. Up to 8 clauses per account. Per block: 16 executes, 16 arrivals, 16 clock steps, 8 cold builds; the rest wait, clock steps in `(wake, id)` order. A refused clock step waits 64 blocks and, after 8 refusals, its wake is cleared until an execute. A skip is a committed step that writes amount 0 and a new wake.

Execute carries `event_nonce`, admitted only when it equals `last_nonce + 1`, and advanced only on commit. A refusal retries that nonce; the next request needs the next one. A replayed transaction still dies on tx-hash uniqueness. A committed clock step must write wake 0 or wake > block time, so one wake pays once. An arrival's identity is the credit write.

The one transfer the node authors: at `until`, a holding that still has funds returns them to origin, fee-free, and is deleted. Same rule for every holding, after the clause's own refund wake. An empty holding is deleted. No catch-up and no debt.

### Clause memory, restart, reorg

The book is the memory. Canonical bytes, little-endian, blake3 as `payments_root` inside `consensus_meta_hash` once the book is non-empty (no regenesis):

- Clauses, sorted by `(owner, index)`: owner (48), index (u8), flags (u8), `until` (u64), params (2×u24, 2×u64), parties (4×48), text length (u16) and text.
- Instances, sorted by id: id (u64) = first 8 bytes of blake3(parent root ‖ event id ‖ action index), clause ref, kind (u8), balance (u24), r0 r1 (u24), r2 r3 (u64), wake (u64), attempt (u8), created (u64), last nonce (u64), beneficiary, origin, owner (48 each).

Registers are uninterpreted. Spent-this-week is r0 because the clause added what it wrote. The week is r2 because the clause stored `(i209 - anchor) / 604800`.

The book is committed in the block's DB transaction. Restart loads the tip bytes and checks blake3 against the header. On a miss, load the latest checkpoint (full book every 256 blocks) whose root matches that block, then replay later blocks with the live function: transactions, then arrivals, then clock. Replay does not trust receipts. A reorg drops the book past the ancestor and replays the winning branch. Losing-branch nonces, registers and holdings are gone. No merge.

A holding is about 300 bytes, removed when empty or at `until`. Clause text is stored once. A block creates at most 64 holdings.

### Policies are clauses

- **Rent.** Trigger 3. When `i209 >= r2` and the source covers the amount, pay party 0 and set r2 and o216 to the next due: `i216 + (min(N, i214) - 1) * 86400`. A short month fires when `i212 == i213` and N is greater than `i213`. The clause stores only the next future due, so nothing is caught up.
- **Split.** Trigger 1. `o200 = i201 / 5` to party 0. 101 leaves 20 and 81, on the payer's one fee.
- **Royalty.** Trigger 1. While r0 is 0, write `i201 / 20` and set r0 = 1. 5% of 101 pays 5 once.
- **Allowance and time lock.** A holding. Draws pay only when `i209 >= open`, and only up to `cap - r0`, with r0 reset when the week in r2 changes.
- **Refund.** Trigger 3 at the deadline. Write `i204` to the owner or the origin, and o216 = 0. Nobody signs. No fee.

Conflicting branches are the clause's order. Expiry is the first branch, so a draw in the deadline block writes 0 to the beneficiary. Inside a block the order is transactions, arrivals, clock, so that draw is already in the registers when the refund runs.

### Composition (owner offline after setup)

Alice installs clause 1 (`on_arrival`) and clause 2 (`until` = 1798848000, one day after the refund), then goes offline. Clause 2's parties are Carol and Alice. Its time parameters are open `1796083200` (2026-12-01) and deadline `1798761600` (2027-01-01). Its amount parameter is 100. Week length 604800 is a literal.

1. Bob pays Alice 1000. Clause 1 writes 200 under clause 2 and leaves 800 on Alice. Holding H is created (origin Bob, beneficiary Carol) and its trigger-4 step sets o216 to the deadline. One fee.
2. 30 Nov: Carol asks for 40. Clause 2 writes 0 (`i209 < open`). Nothing moves.
3. Week 0: Carol asks for 40. H pays 40. She asks for 70. Clause writes 0 because `40 + 70 > 100`. H holds 160.
4. Week 1: Carol asks for 60. r2 changed, so spent is 0. H pays 60 and holds 100.
5. 1 Jan, clock, Alice offline: clause 2's first branch writes 100 to Alice. H is empty and deleted.

Conservation: 800 + 40 + 60 + 100 = 1000. The same clause with three draws of 500 against a 5000 holding returns 3500. A draw of 501 writes 0.

### How the criteria are met

- **General interface.** Any clause that type-checks against the map originates actions, inside the limits above. Composition is `under = n`.
- **Policy through rules.** The six policies are clauses. Two allowances with different caps are two `under` actions. No new handler.
- **Defined execution.** Executor pays an execute; arrival and clock are free. Time is `i209` plus the civil inputs. State updates only on commit. Conflicts follow clause order, then block order. Chains stop at one hop and creation depth 1.
- **Composition.** The trace is a split, a time-locked allowance, a partial draw, a refused over-ask, and a fee-free refund with Alice offline.
- **Issue #34's nine cases.** One firing per due, not before or after: clause plus wake. Anyone executes; only a new install changes terms. A revoke is visible before the clock step. A short source writes 0 or is refused, with no debt. The chain id stops cross-network replay. o5 runs once, on free-balance debits. Admission and apply are one function. `getpayments` returns clause, registers, wake and `until`.
- **Reliable operation.** Tests after approval, real engine, through `sendtx`: this trace; 101 at 20%; 5% of 101 once; a routed share that is not an arrival; the 31st on a short month; 5000 returning the remainder; freeze then manual then clock pays once; restart; checkpoint replay; a reorg that drops the funding block.

### Node work, and what leaves #145

Add the reserved band and its screen, this book and its root, the four triggers, the checks in the validation section, the cached interpreter, and checkpoint/replay. Delete, once this is approved: `consensus/payments.py`, `consensus/periods.py`, the per-feature transaction types, and the feature RPC. #145 is not merged as it stands. No code changes with this post.

### Stages

1. Book, ABI, account-instance triggers, persistence and replay. Rent, split, royalty.
2. Holdings and the composition trace.
3. `getpayments` and the two-node tests, including reorg.

Stage 2 is unfinished until it lands. A change to the map or the book encoding comes back here as an amendment first.
