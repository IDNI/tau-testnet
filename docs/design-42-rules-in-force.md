# Bounty 02 (#42) — Design: rules in force, pinned to a block

Status: built and measured on branch `bounty-02-rules-in-force` (HEAD
`700949e`). Awaiting maintainer plan approval before opening a PR.

## The two gaps (measured on `main`)

1. A confirmed rule transaction does not expose its apply outcome.
   `gettxstatus` returns only block/confirmations, while the receipt
   (outcome, `spec_revision` before/after, fee) is computed at apply and
   then dropped: `ApplyBlockResult` has no receipts field and there is no
   receipts table.
2. `gettaustate` / `getgovernance` show the append-only submitted text,
   not what the engine runs. After `o26 = 7` then `o26 = 3`, the engine
   runs `o26 = 3` while the text still shows `o26 = 7`.

## Design (two read views, zero apply-time change)

1. `getrulesinforce [block] [account]` — a new read-only command. It
   replays the committed journal to that block in a disposable worker
   (`WorkerSession.reconstruct(verify=True)` — the node's own restart
   reconstruction, every stream plain so two nodes produce byte-identical
   text and sha256), cross-checks the replayed `spec_revision` against
   the one already stored per block in `block_commits_v1`, and returns
   the interpreter's `current_spec()` with its sha256. Every answer
   carries `available` plus a reason; a diverged, tampered or timed-out
   replay answers `unavailable` and never returns unchecked text. With
   an account, it also lists that account's clauses from the effective
   spec, so a wallet can read both sides of a payment at the same block.
2. `gettxstatus` on a confirmed rule transaction now includes
   `rule_outcome`, read from that block's journal rows: the k-th rule
   with a given canonical text maps to the k-th revision with that
   text, so every node answers the same, not only the proposer. No new
   table, no apply-time write, no state-hash change.

## Why journal rows, not a new receipts table

The receipt is derived from data every node already commits (the
journal + the commit records). A new table written at commit time
would need its own rebuild and reproducibility story: a node rebuilt
from genesis must reproduce it byte-identically, and anything that
enters the commit path raises the question of whether it is consensus
data. The journal lookup also works for blocks applied before an
upgrade, with no migration.

## Invariants the tests pin

- **Source of truth.** The view comes from the committed journal
  (`tau_journal_v1`, hash-linked), not from `get_canonical_spec()`:
  that call returns `last_known_tau_spec`, reset to `None` at every
  process start, tracking only the in-process interpreter — on a fresh
  node it returns the genesis spec with no user rule in it (measured).
- **Equivalence guard.** The snapshotted canonical text is reloaded
  into a fresh interpreter and stepped against the live engine on the
  same inputs; any divergence fails. `WorkerSession.reconstruct(...,
  verify=True)` already replays every revision and step and checks each
  against the fingerprint recorded at apply, so a replay that does not
  reproduce the committed execution raises `DivergenceError` and
  yields no text at all. Replay uses every stream plain: the
  authoritative worker shrinks address streams to a node-local width,
  and plain streams are what keep text and sha256 byte-identical
  across nodes.
- **Reorg away-and-back.** A reorg goes through
  `reset_committed_journal()` and rebuilds from genesis, so the journal
  only ever holds the canonical chain; an orphaned block has no commit
  record and the query answers `NOT_FOUND`. Tests compare
  `spec_revision` per block before and after.
- **Preview isolation.** Scoped to worker-backed authority only. The
  in-process shared-evaluator fallback is known-contaminating (repo
  test `test_the_same_requests_through_one_shared_evaluator_do_contaminate`
  proves a valid tx refused when routed through one shared context), so
  the isolation probe does not cover that config.
- **Receipts root: dropped.** Folding a receipts root into
  `compute_consensus_state_hash` (BLAKE3 over four inputs) changes
  every historical state hash — ungated it reads as an unconditional
  hash-formula hard fork. Light-client provability stays deferred as
  its own gated change.
- **No protection verdicts in v1.** A rule can constrain an output the
  transfer code never reads, so verdicts need the payment-decision
  wiring first.

## Acceptance (measured at `700949e`)

- Full mock suite: **4936 passed / 0 failed** (pristine main `a54a346`:
  4864 passed / 0 failed). Delta +72 = new tests for these views; no
  test present on main is missing.
- E2E on the real engine (two live nodes, native Tau engine): **98/0**
  across 7 scenarios, including node restart agreement and follower
  replay agreement.
- Forge (live-node, two layers): a tampered journal (one row's result
  rewritten, hash chain relinked so it still verifies) is refused from
  the forged block on; earlier blocks still answer. Revision forgery:
  blocks 0–23 answer, 24–28 refuse (`UNAVAILABLE`, replay diverged).
  Step forgery: the views stay correct (a step forgery changes no
  rule), and a node started on the step-forged copy refuses to start
  ("the committed journal does not reconstruct: replay diverged at
  entry 26").
- Three read-audit gaps, each measured (`tests/test_gap_ours.py`):
  deleting the head journal row while the commit record exists answers
  `TAMPERED`, not `NOT_FOUND`.
- Two rules in one block:
  `test_two_rules_in_one_block_each_advance_spec_revision`.
- In-place upgrade on a main database: a DB written by plain main
  answers through the new views (`tests/test_rules_in_force_at_block.py`,
  "in-place upgrade" section).
- `gettaustate` / `getgovernance` byte-identical to main.

## Files (26 files, +4768/−5 vs main)

- New commands: `commands/getrulesinforce.py`,
  `commands/getaccountrules.py`; extended `commands/gettxstatus.py`,
  `commands/getgovernance.py`.
- Engine/journal read path: `tau_running_spec.py` (new),
  `consensus/engine.py`, `db.py`, `chain_state.py`,
  `tau_speculation.py`, `tau_speculation_worker.py`, `server.py`.
- CLI: `tau_testnet_cli/cli.py`; docs: `docs/rules_in_force.md`
  (new), `docs/developer_cli.md`.
- E2E rig: `scripts/e2e_rules_in_force.py`, `scripts/e2e_rig.py`.
- Tests: `tests/test_rules_in_force_at_block.py`,
  `tests/test_tx_outcomes.py`, `tests/test_gap_ours.py`,
  `tests/test_running_spec.py`, `tests/test_running_spec_native.py`,
  `tests/test_cli_policy.py`, `tests/test_worker_lost.py`.
