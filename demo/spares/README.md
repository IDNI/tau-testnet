# Demo spares — rehearsed recovery moves

Pre-scripted moves for the live stake-switch demo. Each is a scene of
`scripts/demo_stake_switch.py`; nothing here hard-codes a block height (heights
depend on the live head, so each scene computes it). Fire them by name.

| Spare | Command | When to use |
|-------|---------|-------------|
| Late-activation | `venv/bin/python scripts/demo_stake_switch.py --scene propose-spare` | A vote missed the activation height (the pending update auto-expired to archival). Re-proposes the stake switch at `current_height + 20` — plenty of runway to gather votes. A new activation height yields a new `update_id`, so duplicate-rejection does not bite. |
| Reverse (encore) — **blocked, see note** | `--scene propose-reverse` → `--scene vote-reverse` → `--scene activate-reverse` | Vote the network back to `validator_set` (PoA). The revision compiles/admits fine (not a one-way door at consensus level), but the beat cannot complete yet: reverse-governance blocks are minted by node4 (the only stake-mode proposer, a leaf) and reach followers via header-sync pull, and governance updates register only on block *apply* / pubsub-broadcast paths — so the vote never reaches quorum network-wide. Node-side fix required; see the "Encore" section of `docs/demo_stake_switch.md`. |
| Checkpoint | `--scene checkpoint` | Snapshot the current chain state as a rollback point (stops the nodes, rsyncs `node*/data`, restarts). |
| Restore | `--scene restore` | Roll back to the last checkpoint. |

## Drills (rehearse before the demo)

| Drill | Command | Proves |
|-------|---------|--------|
| Abort | `--scene drill-abort` | Run to a scheduled update, checkpoint, then RESTORE instead of activating; asserts the network is back at the scheduled/`validator_set` state. Muscle memory for the live abort path. |
| Node restart | `--scene drill-node-restart` | Restart node3; asserts it reconverges to node1's head, `eligibility_mode`, and `consensus_rules` from persisted state. |

## Notes

- In **stake mode only node4 (funded) may propose**, so the reverse scenes mine
  their blocks on node4 (the sole eligible proposer) up to the activation
  height, where the revert to `validator_set` takes effect.
- A checkpoint taken while an update is merely *scheduled* is a valid rollback
  point for showing state (drill-abort), but do **not** rely on restoring it and
  then activating: scheduled-but-not-activated update payloads are not persisted
  across the restart a snapshot performs (see the "Known limitation" section of
  `docs/demo_stake_switch.md`). To retry a missed activation, re-propose with
  `propose-spare`, or full-reset.
