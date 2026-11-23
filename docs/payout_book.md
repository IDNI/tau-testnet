# The payout book: many rules per account, updated in place

Stage 2 of the Bounty 01 payout work (issues #34, #35, #63), on
top of the stage-1 rules form described in
`docs/payouts-and-grants.md`. Stage 1 gave an account ONE standing
payout rule whose legs are computed by a Tau clause the account
registered -- the policy lives in Tau rules and configuration, and
no Python code decides who gets paid. Stage 2 keeps that shape
exactly and grows the book around it:

- **F1 -- a book, not a slot.** Rules are keyed `(owner, rule_id)`;
  an account holds up to 8 standing rules (`MAX_RULES_PER_OWNER`),
  each with its own caps, period, trigger and history. An
  execution that does not name its rule resolves only when the
  owner holds exactly one; with several, an unnamed execution is
  refused (`PAYOUT_RULE_AMBIGUOUS` at admission, the same refusal
  at apply) rather than guessed at.
- **F2 -- updates that keep history.** `payout_rule_update`
  supersedes a rule's terms in place. The new version carries the
  lineage (version counter plus the superseded rule ids, oldest
  first) AND the accounting state: settlement history, current
  period spend, clock totals and fire count, all-time paid total
  and execution count. Nothing resets. An update is refused when
  it would move the schedule (anchor or period kind) the settled
  history was recorded against, when the new period cap is below
  what the current period already spent, when the new lifetime
  cap is at or below what the clock already paid, or when the new
  terms collide with a sibling rule. A settled settlement id can
  never settle again under the new version. Guarded accounts have
  the same update through rule-change request **kind 6**, screened
  by the same validator and applied by the same book method --
  parity, not a revoke-and-reinstall fallback (which would lose
  the lineage and the history by construction).
- **F3 -- eight legs.** `MAX_LEGS` is 8 (leg streams o21..o36).
  The shipped `TEMPLATE_WORK_ESCROW_CLAUSE` settles the #63 work
  escrow as ONE execution with six legs: worker 50%, two
  reviewers 10% each, defect bounty 10%, poster remainder 15%,
  warranty holdback 5%. On a price divisible by 100 the legs sum
  to the price exactly; on any other price each leg floors and
  the dust (under 6 units) stays with the poster.
- **F4 -- sealed terms.** A rule installed `sealed` cannot be
  replaced, removed or updated until it ends, and while it is
  sealed and unended its owner's ordinary transfers are refused
  (admission and apply agree): the account is locked to the
  rule's own settlements. A sealed rule must declare an end
  condition; a sealed non-clock rule can only end on its final
  period index.
- **F5 -- a fee cap in the rule.** `max_fee_per_execution` caps
  the fee a single execution of the rule may cost. At apply, an
  execution whose measured fee exceeds its rule's cap is rejected
  (`payout_fee_cap_exceeded`) and settles nothing.
- **F6 -- due accounting and introspection.** The block-end clock
  sweep settles at most 16 due rules per block
  (`MAX_CLOCK_SETTLEMENTS_PER_BLOCK`), earliest-due first; due
  rules must be spaced at least an hour apart at install
  (`MIN_DUE_SPACING_SECONDS`). Periods that close unsettled are
  counted per rule as `missed_periods` -- observed once, never
  caught up, never double-counted. `getpayouts` returns the whole
  book per owner: every rule's caps, trigger, end condition,
  sealed flag, fee cap, period spend, clock total, fires, paid
  total, executions, missed periods, version and lineage.
- **Persistence.** Stage 1's single table keyed by owner could
  not hold a book -- and, as stage 2's rewrite surfaced, it also
  dropped trigger fields on the way to disk, so a triggered rule
  did not survive a restart (its row no longer recomputed its
  id). Stage 2 writes the complete row per rule to
  `payout_rules_v2` and keeps the stage-1 table written for the
  owner's first rule, so stage-1 readers keep working and a
  disagreement between the two is treated as corruption, as
  before.

## Proof pack (F7)

Two reproducible measurements ship as scripts and tests:

- `scripts/payout_interleave_probe.py` -- one evaluator session
  stepped **25,000 steps**, the shipped payout clauses
  interleaved with unrelated rules, the session answering by
  parsing the clause texts against an independent share table:
  **0 wrong answers**.
- `scripts/payout_differential_probe.py` -- an independent
  reference model of the settlement bookkeeping against
  `PayoutBook` over 4 templates x 25 grosses x 6 cap profiles x
  7 prior-spend states x 29 operation sequences =
  **121,800 settlement paths, 0 divergences**.

## Named cases and where they are tested

| Behavior | Test |
| --- | --- |
| Two rules independent; unnamed execution refused | `test_payout_stage2_book.py::test_two_rules_on_one_account_are_independent`, `test_payout_stage2_apply.py::test_two_rules_on_one_account_pay_independently` |
| Ninth rule refused; replace is not a ninth | `test_payout_stage2_book.py::test_a_full_owner_book_refuses_a_ninth_rule` |
| Update preserves settlements and period spend | `test_payout_stage2_book.py::test_an_update_preserves_settlements_and_period_spend`, `test_payout_stage2_apply.py::test_an_update_through_the_update_kind`, `test_payout_stage2_native.py::test_an_update_preserves_settlements_and_period_spend_native` |
| Settled id cannot resurrect after update | `test_payout_stage2_book.py::test_an_update_cannot_resurrect_a_settled_settlement_id` |
| Update below spent period cap refused | `test_payout_stage2_book.py::test_an_update_below_spent_period_cap_is_refused` |
| Schedule-moving update refused | `test_payout_stage2_book.py::test_an_update_cannot_move_the_schedule` |
| Guarded account updates through kind 6 | `test_payout_stage2_book.py::test_guarded_update_admission_parity`, `test_payout_stage2_apply.py::test_a_guarded_account_updates_through_the_update_kind`, `..._only_when_the_guard_allows` |
| Six-leg #63 escrow pays exactly | `test_payout_stage2_apply.py::test_the_work_escrow_pays_exactly_the_locked_price`, `test_payout_stage2_native.py::test_the_work_escrow_pays_exactly_the_locked_price_on_every_path` |
| Sealed rule refuses replace/remove/update and locks transfers | `test_payout_stage2_book.py::test_sealed_admission_screens`, `test_payout_stage2_apply.py::test_a_sealed_rule_locks_the_account_until_it_ends` |
| Fee over the rule's cap refused | `test_payout_stage2_apply.py::test_an_execution_over_the_rules_fee_cap_is_refused` |
| Sweep cap 16 per block, earliest-due first | `test_payout_stage2_apply.py::test_clock_sweep_settles_at_most_sixteen_due_rules` |
| Missed periods counted once, stop at end | `test_payout_stage2_book.py::test_missed_periods_are_counted_when_periods_close_unsettled`, `test_payout_stage2_apply.py::test_missed_periods_are_counted_by_the_sweep` |
| Triggered rule and multi-rule book survive the DB round trip | `test_payout_stage2_book.py::test_triggered_rule_survives_the_db_round_trip`, `test_multi_rule_book_survives_the_db_round_trip` |
| Interleave 25,000 / differential 121,800 | `test_payout_stage2_proofs.py` |

The maintainer's five named cases from stage 1 are unchanged and
still covered by the stage-1 suites (`test_payouts.py`,
`test_payout_triggers.py`, `test_payout_triggers_native.py`,
`test_payouts_grants_*.py`).
