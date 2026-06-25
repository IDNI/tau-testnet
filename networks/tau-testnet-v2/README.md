# tau-testnet-v2 — network join profile

Canonical artifacts + config to join the public `tau-testnet-v2` network.
The three genesis artifacts and `TAU_NETWORK_ID` must be **identical on every
node** or the P2P handshake rejects the peer (fork protection).

| File | Purpose |
|---|---|
| `genesis.json` | pre-funded accounts, validator set, vote-quorum policy, base fee, block 0. `block_0.hash` = `4bf5ee70…fbce`. |
| `env` | `TAU_NETWORK_ID` + bootnode multiaddr + listen address. Source it before running. |
| `join.sh` | copies `genesis.json` into `data/`, loads `env`, starts the node. |

> `genesis.tau` and `genesis_consensus.tau` ship at the repo root and are
> already correct for this network — no copy needed.

## Join (one command)

```bash
pip install -e .                     # once; build tau-lang too for the real engine
./networks/tau-testnet-v2/join.sh
```

## Join (manual)

```bash
cp networks/tau-testnet-v2/genesis.json data/genesis.json
set -a; . networks/tau-testnet-v2/env; set +a
tau-testnet node run --no-isolated
```

`tau-testnet status` — head number climbing means you are syncing. A
genesis-hash or network-id mismatch is rejected at the handshake (the node
logs the reason and will not sync).
