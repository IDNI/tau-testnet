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
| 5 | (in `e2e`) | update `approved-and-scheduled` on all 4 | 2-of-3 supermajority schedules it; a checkpoint is taken. |
| 6 | (in `e2e`) | mode flips to `stake`; `consensus_rules` == revision on all 4 | The patch applies at block H; first stake-verified block is H+1. |
| 7 | (in `e2e`) | node4 createblock SUCCESS; all 4 accept node4 as proposer | **The money shot:** a non-validator with stake produces a canonical block. |
| 8 | `--scene 8` | node1 createblock → "Not our turn" | Encore: a validator with 0 stake is now ineligible (o7=0). |

Each scene prints a banner, the raw RPC replies, and an `OK:` line on success;
any mismatch prints `[FATAL] ...` and exits non-zero.

## Restart determinism

The mode and the active rule are meta-hash-bound consensus state, not local
config. Prove it survives a restart:

```bash
docker compose -f demo/docker-compose.yml down
docker compose -f demo/docker-compose.yml --env-file demo/.env up -d
venv/bin/python scripts/demo_stake_switch.py --scene 1   # mode still stake, heads agree
venv/bin/python scripts/demo_stake_switch.py --scene 7   # node4 still mines
```

## Abort ladder

1. **A scene fails a soft assertion** (e.g. gossip lag): re-run that scene; the
   sleeps allow a couple of seconds for propagation.
2. **State got dirty mid-rehearsal:** roll back to the Scene-5 checkpoint:
   ```bash
   bash demo/checkpoint.sh restore
   ```
   (`demo/checkpoint.sh snapshot` was taken automatically at the end of Scene 5
   during `e2e`; `demo/checkpoint.sh status` shows whether one exists.)
3. **A node is wedged:** `docker compose -f demo/docker-compose.yml restart nodeN`.
4. **Full reset:** `docker compose ... down` then re-run `bash demo/setup.sh`
   (existing keys/identities/genesis are reused; delete `demo/node*/data` to wipe
   chain state) and bring the stack back up.

> The detailed operator abort procedures live in
> `plans/stake-switch/phase-7.md` (rehearsal + failure drills).
