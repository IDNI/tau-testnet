# Stake-switch demo runbook

Live demonstration: a 4-node Tau network starts in **validator_set** (PoA) mode
where only the 3 genesis validators may propose blocks. Governance then votes in
a consensus revision that flips proposer eligibility to **stake** mode. After
activation, a funded *non-validator* (node4) can propose blocks — and a
validator holding zero stake can no longer propose.

The whole switch runs on the real network with **background mining disabled**:
blocks are produced only by the operator's `createblock` RPC, so the stage never
races a mining loop.

## Topology

| Node  | Role at genesis | RPC (loopback) | Container IP   |
|-------|-----------------|----------------|----------------|
| node1 | validator       | 127.0.0.1:65441 | 172.28.0.11   |
| node2 | validator       | 127.0.0.1:65442 | 172.28.0.12   |
| node3 | validator       | 127.0.0.1:65443 | 172.28.0.13   |
| node4 | outsider        | 127.0.0.1:65444 | 172.28.0.14   |

Genesis: validators = node1/2/3, treasury pre-funded 1,000,000, base fee 0,
consensus rule = `demo/genesis_consensus_demo.tau` (mode-guarded), network id
`tau-demo-stake`. Auto-faucet is **off** on every node (a faucet would mint
phantom stake).

## Setup (one-time)

```bash
# 1. Build image + generate keys/identities/genesis/.env (idempotent)
bash demo/setup.sh
docker compose -f demo/docker-compose.yml --env-file demo/.env up -d --build   # ~minutes (image build)

# 2. Smoke check: all four respond and agree on genesis
venv/bin/python scripts/demo_stake_switch.py --scene 1
```

Timing: image build is the slow one-time cost (several minutes). Each scene is
seconds; `e2e` is ~1 minute (dominated by block-gossip sleeps and the
empty-block march to the activation height).

## Scenes

Run everything: `venv/bin/python scripts/demo_stake_switch.py e2e` (scenes 1-7).

| # | Command | Expected on screen | Talking point |
|---|---------|--------------------|---------------|
| 1 | `--scene 1` | all 4 share head hash; node1 shows 3 validators, `mode=validator_set` | The network boots in classic PoA. |
| 2 | `--scene 2` | node4 createblock → "not in the active validator set" | Outsiders cannot propose under PoA. |
| 3 | `--scene 3` | node4 balance == 150000 on all 4 nodes | Treasury stakes the outsider; state gossips network-wide. |
| 4 | (in `e2e`) | update `pending` on all 4; prints activation height H | Governance proposes the stake rule + `eligibility_mode=stake` patch. |
| 5 | (in `e2e`) | update `approved-and-scheduled` on all 4 | 2-of-3 supermajority schedules it for height H. |
| 6 | (in `e2e`) | mode flips to `stake`; `consensus_rules` == revision on all 4; a checkpoint is taken | The patch applies at block H; first stake-verified block is H+1. |
| 7 | (in `e2e`) | node4 createblock SUCCESS; all 4 accept node4 as proposer | **The money shot:** a non-validator with stake produces a canonical block. |
| 8 | `--scene 8` | node1 createblock → "Not our turn" | Encore: a validator with 0 stake is now ineligible (o7=0). |

Each scene prints a banner, the raw RPC replies, and an `OK:` line on success;
any mismatch prints `[FATAL] ...` and exits non-zero.

### Checkpoint timing

The `e2e` checkpoint is taken **after** activation (end of Scene 6). A consistent
snapshot requires stopping the nodes (you cannot safely rsync a live sqlite DB),
so `checkpoint.sh snapshot` inherently restarts them; the activated consensus
params reload cleanly.

Phase 9C removed the original reason this had to be post-activation:
scheduled-but-not-yet-activated update payloads (`rule_revisions` +
`host_contract_patch`) are now persisted alongside the schedule entry, so a node
that restarts while an update is merely `approved-and-scheduled` still activates
it at height H (proven by `--scene drill-abort` — checkpoint-while-scheduled →
restore → still `approved-and-scheduled` — and by
`tests/test_scheduled_payload_persistence.py`). The e2e nonetheless keeps the
checkpoint post-activation for demo robustness: the eligible proposer flips at
height H (genesis validators hold 0 stake and become ineligible), so a restart
placed right before the mine-to-H step can leave a freshly-rebooted leaf follower
one block short of the activation block with no eligible proposer left to
re-announce it.

After a governance switch the node's Tau engine reloads the heavier stake spec
at boot, so the demo raises `TAU_CLIENT_WAIT_TIMEOUT`/`TAU_PROCESS_TIMEOUT` in
`docker-compose.yml` to give startup enough headroom.

## Restart determinism

The mode and the active rule are meta-hash-bound consensus state, not local
config. Prove it survives a restart:

```bash
docker compose -f demo/docker-compose.yml down
docker compose -f demo/docker-compose.yml --env-file demo/.env up -d
# after boot, every node reloads eligibility_mode=stake from disk:
for p in 65441 65442 65443 65444; do
  printf 'getgovernance\r\n' | nc -w3 127.0.0.1 $p \
    | venv/bin/python -c "import sys,json;d=json.load(sys.stdin)['data'];print(p:=d['eligibility_mode'])"
done
venv/bin/python scripts/demo_stake_switch.py --scene 7   # node4 still mines -> mode survived restart
```

(`--scene 1` is the *genesis*-state check and asserts `validator_set`; do not
run it after the switch. The Tau engine reloads the heavier stake spec at boot,
so give the nodes ~30-60s to become ready before driving Scene 7.)

## Pre-flight checklist (run before the audience arrives)

- [ ] Image built: `docker images tau-testnet-standalone:demo` shows a recent build.
- [ ] `bash demo/setup.sh` run; `demo/.env` present with 4 privkeys/pubkeys/peer-ids + 4 bootstrap lists.
- [ ] Stack up: `docker compose -f demo/docker-compose.yml --env-file demo/.env up -d`.
- [ ] All 4 nodes share the genesis hash: `venv/bin/python scripts/demo_stake_switch.py --scene 1` prints OK.
- [ ] Native tests green on this machine: `PYTHONPATH=<tau-lang nanobind> venv/bin/python -m pytest tests/test_stake_switch_spike_native.py tests/test_stake_switch_e2e_native.py -q`.
- [ ] Checkpoint dir clean: `bash demo/checkpoint.sh status` reports no snapshot (or an intentional one).
- [ ] **Rehearse the drills:** `--scene drill-abort` and `--scene drill-node-restart` both green.
- [ ] **Recorded backup:** capture a screen recording of a full clean `e2e` run during rehearsal and keep it offline. Path: `___________` (fill in). This is the final fallback if the live network misbehaves.

## Abort ladder

| Symptom | Diagnosis | Operator command | Recovery time |
|---|---|---|---|
| A scene prints `[FATAL] ... sync` | Gossip lag under host load (a follower trails by a block) | Re-run that single scene (`--scene N`); scenes poll + re-announce to reconverge | seconds–1 min |
| Proposal never reaches `pending` | Bad rule rejected at admission (isolated compile) | Read the `sendtx` reply for the reject reason; fix the rule text; re-propose | 1 min |
| Vote short of quorum near the height | Update auto-expired to `archival` when its `activate_at` passed | Re-propose with a far-future height: `--scene propose-spare` (uses current+20) | 1 min |
| Chain stalls at H-1; `FeeRuleError` in a node's logs | Activation revision was rejected by the live interpreter (would mean the composed spec is UNSAT) | `bash demo/checkpoint.sh restore` (post-activation snapshot) **or** full reset; do NOT improvise a rule live | 1–2 min |
| One node diverges / wedges | Node lost sync or crashed | `docker compose -f demo/docker-compose.yml restart nodeN`; it reloads mode+rules from disk (see `--scene drill-node-restart`) | ~30–60s |
| Total loss | Anything unrecoverable | Full reset (below) | < 2 min |

**Full reset:**
```bash
docker compose -f demo/docker-compose.yml down
rm -rf demo/node*/data demo/.checkpoint demo/.env   # wipe chain state (keys/identities regenerate)
bash demo/setup.sh
docker compose -f demo/docker-compose.yml --env-file demo/.env up -d
# wait ~30-60s for boot, then: venv/bin/python scripts/demo_stake_switch.py e2e
```

> Host load matters: the demo runs 4 native Tau engines on one machine. Under
> heavy load a follower can trail the miner by a block, so the convergence
> scenes poll and re-announce. On a constrained laptop, close other heavy apps
> before the live run, and prefer a freshly-restarted stack (clears accumulated
> load) over one that has been mining for a long rehearsal.

## Encore — vote the network back to PoA

Intended closing beat: nothing here is a one-way door. With the network in stake
mode, the validator electorate (still node1/2/3) votes proposer-eligibility back
to `validator_set`:

```bash
venv/bin/python scripts/demo_stake_switch.py --scene propose-reverse    # genesis-guarded rule + eligibility_mode=validator_set
venv/bin/python scripts/demo_stake_switch.py --scene vote-reverse        # node2 + node3 approve
venv/bin/python scripts/demo_stake_switch.py --scene activate-reverse    # mine to H on node4 -> back to PoA
```

The reverse encore is a **scripted, green beat** — the door swings both ways:
`propose-reverse` → `vote-reverse` → `activate-reverse` restores `validator_set`
on all four nodes, node4 (the stake outsider) is refused again, and a genesis
validator resumes proposing. The eligible proposer hands off at the activation
boundary (node4 mines up to H, then a validator takes over to pull followers
through the activation block), which `scene_activate_reverse` now drives
automatically.

> **Previously blocked — now fixed.** The iteration-1 note here guessed the
> reverse was blocked by header-synced blocks bypassing the apply path. Phase 8
> (`demo/diagnostics/ROOT_CAUSE.md`) refuted that: pulled blocks DO go through
> `reorg_to → rebuild → engine.apply_block`. The real cause was a **mine-vs-replay
> state-hash divergence** at the first block a node mined after a restart — a node
> reloaded a state missing "sequence-only" accounts (validators who voted/proposed
> but hold no funds), because `save_canonical_state_atomically` persisted accounts
> keyed on balances only. Followers then rejected that block's hash and their
> rebuild aborted, freezing the head. Fixed by persisting the union of balance and
> sequence keys (Phase 9B); reorg aborts are now loud and non-destructive
> (Phase 9A); scheduled-update payloads persist across restart (Phase 9C).

The spares and drills are catalogued in `demo/spares/README.md`.
