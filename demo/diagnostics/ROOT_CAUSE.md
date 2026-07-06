# Phase 8 — Root cause of Finding 1 (reverse encore blocked)

## Verdict

**Confirmed: H2 (rebuild abort), compounded by a `reorg_to` masking bug.**

Follower nodes cannot rebuild their state past the **first post-activation
block**. The state-hash invariant check inside the rebuild replay fires a
mismatch at that block and aborts the rebuild; `reorg_to` then commits the *new
head number* anyway, so the node advertises an advancing head while its applied
consensus state is frozen at the activation block. Every consensus governance
update carried in a block after activation (the reverse-to-PoA update, and any
other) is therefore never applied on followers — it registers only on the node
that mined it. This is NOT the mechanism the iteration-1 implementer guessed
("pull-synced blocks bypass the apply path"): pulled blocks DO go through
`reorg_to` → full rebuild → `engine.apply_block` (which registers governance).
The rebuild simply dies before it reaches the governance block.

It is also more serious than the demo encore: the divergence is a **mine-vs-replay
state-hash nondeterminism at post-activation blocks**, i.e. a latent fork /
replay-determinism bug independent of the demo.

## Evidence (compose network, stake mode already active)

Instrumented `propose-reverse` (submit reverse `eligibility_mode=validator_set`
update to node4, mine one block on node4, snapshot every node's RPC + sqlite):

```
AFTER node4 mines reverse block 64:
  node4 (miner): head 64, tip 64, consensus_updates_v2=[7d9c6bd7], lifecycle 7d9c6bd7=pending   ✓ registered
  node1        : head 64, tip 64, consensus_updates_v2=[],          lifecycle: update ABSENT    ✗ head advanced, governance NOT registered
  node3        : head 64, tip 64, consensus_updates_v2=[],          lifecycle: update ABSENT    ✗ same
  node2        : head 63,          lifecycle 7d9c6bd7=mempool (tx gossiped, not yet mined in its view)
```

node1/node3 have block 64 in their DB and report head 64, yet the governance
update inside it is not registered — proving the block was "accepted" (head
number committed) without its consensus effect being applied.

node1 rebuild log (deterministic, every reorg):

```
[db] Added block #64 to database
[ERROR][chain_state] Block #8 state_hash invariant mismatch!
  Computed: e545bfad3c8a3404d5e9dfdbdbdd310545205d6846e22d57179d6ea94764bd08
  Block:    b69295ff02028af6da6d736a138d9edcea981029c693ecaa8770d18a0d6f8543
```

Stored per-block state hashes on the canonical (node4) chain:

```
block 5  12361fffac4bbfe8...  txs 0  proposer node1     # empty
block 6  12361fffac4bbfe8...  txs 0  proposer node1     # empty -> SAME hash as 5 (empty blocks preserve state)
block 7  e545bfad3c8a3404...  txs 0  proposer node1     # ACTIVATION (mode -> stake): state changes
block 8  b69295ff02028af6...  txs 0  proposer node4     # empty, yet state changes again (7 -> 8)
block 9  c253fcebc072f7ca...  txs 1  proposer node4
```

The computed hash at the abort (`e545bf…`) is **exactly block 7's stored hash**.
So node1's replay of block 8 reproduces block-7 state (no advance), while the
miner stored a *different* hash for block 8. Blocks 5→6 (both empty) share a
hash, confirming empty blocks normally preserve the state hash — so block 8's
state change is anomalous and, critically, **only the miner produces it; replay
does not.**

## The two compounding bugs

1. **Mine-vs-replay state-hash divergence at the first post-activation block.**
   An empty block mined immediately after a governance activation changes the
   miner's consensus state hash (block 7 `e545bf…` → block 8 `b69295…`), but
   `_rebuild_state_from_blockchain_internal`'s replay of that same empty block
   reproduces the *pre*-block-8 (block-7) state. The non-reproduced state change
   at block 8 is not caused by transactions (block 8 is empty) — it is a
   post-activation consensus-metadata transition that the live mining path
   computes but the rebuild/replay path does not. Candidate fields (to pin in
   Phase 9 with a one-line component dump of `compute_consensus_state_hash`
   inputs at block 8, mine-time vs replay-time): `active_consensus_id` /
   `consensus_rules_state` provenance, vote-clearing on activation, or an
   archival transition applied at H+1 on the miner but at H on replay.

2. **`reorg_to` commits the new head *number* even when the rebuild aborted.**
   `chain_state.reorg_to` (chain_state.py:1655) calls
   `_rebuild_state_from_blockchain_internal(0, new_path)`, which on a state-hash
   mismatch prints an error and `return`s early (chain_state.py:816-820) —
   leaving in-memory state at the last good block (7). Control returns to
   `reorg_to`, which unconditionally commits
   `head_num = db.get_block_by_hash(new_head_hash)[...]['block_number']`
   (chain_state.py:1669) = 64. The abort is swallowed into a single ERROR log
   (also `network/service.py:1616` swallows the reorg failure), so the head
   silently advances past un-applied state. This masks bug (1) and turns a
   replay divergence into a silent head/state inconsistency.

## Why forward flow appeared to work

The PoA→stake switch activates at block 7 (mined by node1, the hub). Followers
rebuild cleanly through block 7 (its hash matches) and reach `eligibility_mode =
stake` — so Scene 6's assertions pass. The money-shot block 8 is the FIRST block
where the divergence bites: followers store it and bump their head label, but
their applied state is frozen at block 7. Because block-7 state is already
`stake`, `getgovernance` still reports stake, so Scene 7's proposer/head checks
(which read the block DB, not applied state) also pass. The break only becomes
visible when a *later* governance update (the reverse) must register on
followers and never does.

## Fix direction (Phase 9)

- **9A:** (a) Make `reorg_to` fail loudly and NOT advance the head when
  `_rebuild_state_from_blockchain_internal` aborts (return a status; keep the old
  head; error-log with block number and both hashes). (b) Eliminate the
  mine-vs-replay divergence at post-activation blocks so replay reproduces the
  miner's state hash bit-for-bit — first pinpoint the diverging
  `compute_consensus_state_hash` component at block 8 (instrument mine-time vs
  replay-time), then make that transition deterministic across both paths. Pin
  it with the cross-path equivalence test (same block sequence via
  `process_new_block` vs `ingest_block`+`maybe_update_canonical_head` → identical
  lifecycle state + state hash).
- Findings 2 (scheduled-payload persistence) and 3 (commit-path parity) are
  independent and proceed per the plan.

## Reproduction

`demo/diagnostics/<ts>/` holds the per-node snapshot, node1 block-8 mismatch log,
and node4 per-block hashes captured for this verdict.
