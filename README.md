![The TauNet logo](/docs/images/TauNet_banner.png)

# Tau Testnet Alpha Blockchain

A live, working blockchain whose state transitions and consensus rules are governed by **Tau formal logic**. A Python host handles networking, storage, and cryptography (BLS12-381 signatures); a separate Tau logic program — run via native bindings or the bundled Docker image — is the ultimate arbiter of block validity, proposer eligibility, transfers, and fees.

- **Tau-driven consensus** — block validity (`o6`) and proposer eligibility (`o7`) come from living, governance-votable Tau rules.
- **On-chain PoA validator set** — proposers must be in the active validator set; the set changes only through governance with a configurable vote quorum.
- **Native fee model** — fees are emitted by the consensus rules (`o9` + optional user `o8`), charged on inclusion, credited to the block proposer.
- **Multi-node ready** — libp2p P2P, header/block sync, fork choice + reorgs, genesis-hash handshake gate, NAT-friendly announce addresses.

> **Status: Alpha.** Under active development, for testing and experimentation.
>
> ⚠️ **This alpha network has no economic finality, no slashing, and limited DoS protection, and it may reorg. Do not use it with real funds.** Specifically: tokens have **no real value**; there is **no finality** (PoA with possible deep reorgs); **no validator slashing**; the cryptography and consensus are **not audited**; sustained Tau use can hit a **native segfault** that stops the node process; and a **bad governance update can halt the chain** until corrected. See [Security & risk model](#security--risk-model).

> **Platforms:** Linux and macOS run the node natively. **Windows is supported via Docker Desktop or WSL2** — the node is not supported on *native* Windows (it relies on Unix-only process control and a bash/cmake Tau build). See [Windows](#windows).

---

## Quickstart (Docker, ~2 commands)

The standalone Docker image bundles the node **and** the Tau engine — no separate Tau install needed.

```bash
# 1. Build (compiles tau-lang inside the image; one-time, slow)
docker build -f Dockerfile.standalone -t tau-testnet-standalone .

# 2. Run a local node (isolated, no mining) with persistent data in ./data
docker run --rm -it \
  -p 65432:65432 -p 65433:65433 -p 4001:4001 \
  -v "$(pwd)/data:/data" \
  tau-testnet-standalone
```

The node exposes three ports: **65432** (RPC/TCP + CLI), **65433** (WebSocket, for the web wallet), **4001** (libp2p P2P). The `-v` mount keeps the database, identity, and keys across restarts.

> ⚠️ **Bind RPC/WS to localhost, not all interfaces.** `-p 65432:65432` publishes the port on **every** host interface (`0.0.0.0`). The RPC/WS API has no authentication beyond a loopback gate on `createblock`; anyone who can reach the port can read chain state, submit transactions, and (over plaintext WS) interact with the wallet. P2P (`4001`) is meant to be public; **RPC (`65432`) and WS (`65433`) are not.** For local use, bind them to loopback:
>
> ```bash
> docker run --rm -it \
>   -p 127.0.0.1:65432:65432 -p 127.0.0.1:65433:65433 -p 4001:4001 \
>   -v "$(pwd)/data:/data" tau-testnet-standalone
> ```
>
> To expose RPC/WS deliberately, put them behind a TLS-terminating reverse proxy and set `TAU_WS_ALLOWED_ORIGINS`. See [RPC / WebSocket exposure](#rpc--websocket-exposure).

Talk to it from another terminal:

```bash
pip install -e .                       # installs the `tau-testnet` CLI
tau-testnet status                     # node health + chain tip
tau-testnet keys new                   # generate a BLS keypair
```

To **join a network** instead of running isolated, jump to [Join the Tau Testnet](#join-the-tau-testnet). To run **without Docker**, see [Run from source](#run-from-source).

---

## Ways to run a node

| Path | Best for | Tau engine |
| --- | --- | --- |
| **Docker standalone** (above) | Fastest start, operators | Bundled (compiled in image) |
| **From source + native bindings** | Development, contributors | You build `tau-lang` locally |
| **`tau-testnet node run`** | Either of the above, ergonomic flags | Whatever the env provides |

### Node roles

- **Read / RPC node** — syncs the chain, serves queries, relays gossip. No keys, mining off. Anyone can run one.
- **Validator** — additionally proposes blocks. Needs a BLS keypair **and** membership in the on-chain active validator set (granted at genesis or via governance).

### Windows

The node does **not** run on native Windows: the watchdog uses `SIGKILL`/`pgrep`, the Tau engine reads `/proc` and loads a `.so`, and tau-lang builds with bash/cmake/clang. Use one of:

- **Docker Desktop (recommended).** Run the exact same image as everyone else. The only difference from the Linux/macOS commands is the volume-mount path. In **PowerShell**:

  ```powershell
  docker build -f Dockerfile.standalone -t tau-testnet-standalone .
  docker run --rm -it -p 65432:65432 -p 65433:65433 -p 4001:4001 -v "${PWD}/data:/data" tau-testnet-standalone
  ```

  In **cmd.exe** use `-v "%cd%/data:/data"`. PowerShell has no `\` line continuation — keep `docker run` on one line, or use a backtick `` ` `` to continue.

- **WSL2 (for development / from source).** Install WSL2 with a Linux distro (Ubuntu), open the Linux shell, and follow the [Run from source](#run-from-source) steps verbatim — inside WSL it is Linux, so every bash command works as written.

The `tau-testnet` CLI is pure Python and runs under native Windows Python to query a remote node (`tau-testnet --host <ip> --port 65432 status`); only *running a node* needs Docker/WSL2.

---

## Run from source

> On Windows, run these inside **WSL2** (see [Windows](#windows)). On Linux/macOS, run them directly.

**Prerequisites:** Python **3.10+** (3.10 / 3.11 / 3.12).

```bash
python3 -m venv venv && source venv/bin/activate
pip install -e .                       # installs deps + the `tau-testnet` CLI
```

**Option A — quick mock node (no Tau build).** `--test` sets `TAU_ENV=test` + `TAU_FORCE_TEST=1` and implies `--miner --isolated`: a self-mining single node using the deterministic mock validator path. Great for trying the CLI/API without compiling tau-lang.

```bash
tau-testnet node run --test
```

**Option B — real Tau engine.** Build the `tau-lang` native bindings once, then run **without** `--test` (real evaluation is the default — see [Tau execution mode](#tau-execution-mode)):

```bash
# clone tau-lang as a SIBLING of this repo (../tau-lang is auto-discovered)
git clone https://github.com/IDNI/tau-lang.git ../tau-lang
( cd ../tau-lang && ./dev dep-cvc5 && ./dev dep-boost \
  && ./dev build Release -DTAU_BUILD_BINDING_PYTHON=ON )   # → build-Release/bindings/python/nanobind/tau*.so

# only needed if auto-discovery of ../tau-lang fails:
export PYTHONPATH=../tau-lang/build-Release/bindings/python/nanobind

tau-testnet node run --miner --isolated        # real-Tau isolated dev chain
```

`tau-testnet node run` wraps `server.py` (you can also run `python server.py` directly with the same `TAU_*` env vars). Useful flags: `--miner/--no-miner`, `--isolated/--no-isolated`, `--listen <multiaddr|host:port>`, `--ephemeral-identity`, `--fresh`, `--open-governance` (isolated dev only), `--port`, `--host`.

---

## Join the Tau Testnet

The public network is **`tau-testnet-v2`**. Everything needed to join is **already committed to this repo** under [`networks/tau-testnet-v2/`](networks/tau-testnet-v2/) (`genesis.json`, the bootnode address, and the network id); `genesis.tau` and `genesis_consensus.tau` sit at the repo root. You do **not** need to obtain anything from the operator.

> Every node must advertise the **same `genesis_hash` and `TAU_NETWORK_ID`** or it is rejected at the P2P handshake (fork protection). Using the committed profile guarantees a match.

Pick the path for your machine. **Docker is the quickest** and works the same on all three OSes; **from source** is for development.

### Option 1 — Docker · Windows / macOS / Linux (no toolchain to build)

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows, macOS) or Docker Engine (Linux). The image compiles `tau-lang` for you — nothing else to set up.

```bash
# 1. clone, then build the image once (slow: compiles tau-lang inside the image)
git clone https://github.com/IDNI/tau-testnet.git && cd tau-testnet
docker build -f Dockerfile.standalone -t tau-testnet-standalone .

# 2. join — loads the committed genesis profile; chain data persists in the `tau_data` volume
docker run --rm -it -p 65432:65432 -p 65433:65433 -p 4001:4001 \
  -v tau_data:/data \
  -e TAU_NETWORK_ID=tau-testnet-v2 \
  -e TAU_BOOTSTRAP_PEERS='[{"peer_id":"12D3KooWDpWEYxBy8y84AssrPSLaq9DxC7Lncmn5wERJnAWZFnYC","addrs":["/ip4/34.251.82.246/tcp/4001"]}]' \
  -e TAU_MINING_ENABLED=false \
  tau-testnet-standalone \
  bash -c 'mkdir -p data && cp networks/tau-testnet-v2/genesis.json data/genesis.json && python server.py'
```

> **Windows:** run the above in **PowerShell** or **Git Bash**. In PowerShell, put the `docker run` on one line (or break lines with a backtick `` ` `` instead of `\`); keep the single quotes around the `TAU_BOOTSTRAP_PEERS` and `bash -c` values.

RPC is exposed on `localhost:65432`, WebSocket on `65433`.

### Option 2 — From source · macOS / Linux / Windows-WSL2

For development, or to run without Docker. **On Windows, run these inside [WSL2](#windows)** — the node is Unix-only.

```bash
# 1. clone + install the CLI (Python 3.10+)
git clone https://github.com/IDNI/tau-testnet.git && cd tau-testnet
python3 -m venv venv && source venv/bin/activate
pip install -e .

# 2. build the tau-lang native engine once (prerequisites: see "Run from source")
git clone https://github.com/IDNI/tau-lang.git ../tau-lang
( cd ../tau-lang && ./dev dep-cvc5 && ./dev dep-boost \
  && ./dev build Release -DTAU_BUILD_BINDING_PYTHON=ON )
# only if auto-discovery of ../tau-lang fails:
# export PYTHONPATH=../tau-lang/build-Release/bindings/python/nanobind

# 3. join — copies the genesis profile into data/, loads the network env, starts the node
./networks/tau-testnet-v2/join.sh
```

`join.sh` simply does:

```bash
cp networks/tau-testnet-v2/genesis.json data/genesis.json
set -a; . networks/tau-testnet-v2/env; set +a   # TAU_NETWORK_ID + bootnode + listen addr
tau-testnet node run --no-isolated
```

The node dials the bootnode (with retry/backoff), handshakes, syncs headers + block bodies, and rebuilds state by replaying from genesis. Known peers persist across restarts. Remote clients cannot trigger block production (`createblock` is loopback-only unless `TAU_ALLOW_REMOTE_CREATEBLOCK=true`).

### Verify you joined

Both join commands run the node in the **foreground**, so sync progress (`Header sync …`, `Added block #N …`) streams live in your terminal. To query state, use the CLI from **another terminal** (it talks to the node's TCP port `65432`):

```bash
tau-testnet status                       # node started from source
tau-testnet --host localhost status      # node started via Docker (CLI installed on the host)
```

> The Docker image ships only the node, not the `tau-testnet` CLI. To query a Docker node, install the client on the host with `pip install -e .` (no `tau-lang` build needed — the CLI is a thin RPC client), or just read the container's foreground logs.

A rising `head_number` means you are syncing. If it stays at 0, the handshake was rejected — confirm `TAU_NETWORK_ID=tau-testnet-v2` and that `data/genesis.json` matches the committed profile (`block_0.hash` = `4bf5ee70…fbce`). The node logs the exact reason for any mismatch.

### Run as a validator

A validator additionally **proposes** blocks and must already be in the active set (granted at genesis or via governance — see [Operating a network](#operating-a-network-genesis-keys-validators)). Add a BLS keypair on top of either path above:

```bash
export TAU_MINING_ENABLED=true
export TAU_MINER_PUBKEY=<96-hex-pubkey>
export TAU_MINER_PRIVKEY=<64-hex-privkey>     # or TAU_MINER_PRIVKEY_PATH=/path/to/key
tau-testnet node run --no-isolated
```

For a **Docker** node, pass the same as `-e` flags (and mount the key, e.g. `-v "$(pwd)/test_miner.key:/data/test_miner.key:ro"` with `-e TAU_MINER_PRIVKEY_PATH=/data/test_miner.key`).

A validator whose key is removed from the active set stops proposing, and its blocks are rejected by peers.

### Behind NAT / on a public host

Advertise a reachable address (the node still binds `TAU_NETWORK_LISTEN` locally):

```bash
export TAU_ANNOUNCE_ADDRS='/ip4/<YOUR_PUBLIC_IP>/tcp/4001'   # Docker: -e TAU_ANNOUNCE_ADDRS=...
```

> **Must be identical on every node, or the network forks:** `TAU_NETWORK_ID` and the three genesis artifacts (which pin the validator set, the `vote_quorum` policy, and the base fee). Keep `TAU_GOVERNANCE_OPEN_ADMISSION=false` on a public network. The `vote_quorum` policy is read from **genesis, not per-node config**, and is bound into the state hash — a misconfigured node surfaces as a hash mismatch, not a silent fork.

### Rebuilding the Docker image against a specific tau-lang

```bash
TAU_LANG_REF=$(git ls-remote https://github.com/IDNI/tau-lang.git refs/heads/main | awk '{print $1}')
docker build --pull -f Dockerfile.standalone \
  --build-arg TAU_LANG_REF="$TAU_LANG_REF" --build-arg TAU_BUILD_JOBS=4 \
  -t tau-testnet-standalone:latest .
```

`TAU_LANG_REF` accepts a branch, tag, or commit SHA. Keep `TAU_BUILD_JOBS` ≥ 1.

---

## Using the node

The `tau-testnet` CLI is the primary interface; it speaks the RPC over TCP (default `127.0.0.1:65432`). Use `--host`/`--port` to target a remote node and `--json` for machine-readable output.

```bash
# keys (stored under ~/.tau-testnet/keys, chmod 0600)
tau-testnet keys new                              # print a fresh keypair
tau-testnet keys save --name alice                # generate + save under a name
tau-testnet keys list

# query chain state
tau-testnet status
tau-testnet balance <pubkey>
tau-testnet sequence <pubkey>
tau-testnet history <pubkey>
tau-testnet blocks --limit 10
tau-testnet mempool
tau-testnet governance

# send a transfer (default fee 10, expiry 600s)
tau-testnet tx send --key alice --to <recipient_pubkey> --amount 10
tau-testnet tx send --key alice --transfer <pk1>:5 --transfer <pk2>:3 --fee 10

# governance (sender must be an active validator; default fee 0)
tau-testnet gov propose --key alice --file consensus_update.json
tau-testnet gov vote --key alice --update-id <update_id_hex>

# target a remote node
tau-testnet --host testnet.tau.net --port 65432 status
```

Full CLI reference, validator-setup recipe, and the governance update lifecycle: [docs/developer_cli.md](docs/developer_cli.md). Raw TCP/WebSocket command grammar and JSON envelopes: [docs/blockchain_api.md](docs/blockchain_api.md).

### Web wallet

A browser wallet lives in [`web-wallet/`](web-wallet/) (static client; connects to the node's **WebSocket** port, 65433 by default). It is not auto-served — open it with a static server:

```bash
cd web-wallet && python3 -m http.server 8000
# then browse http://localhost:8000 and point the wallet at ws://<node-host>:65433
```

### Console wallet (legacy)

`python wallet.py` provides the original command-line wallet (`new`, `balance`, `history`, `send`); see [WALLET_USAGE.md](WALLET_USAGE.md). The `tau-testnet` CLI above is the preferred path.

---

## Operating a network (genesis, keys, validators)

A network is defined by its genesis artifacts. Generate them once and distribute the **identical** files to every node.

```bash
# 1. validator keypair (writes test_miner.key + test_miner.pub)
python scripts/generate_miner_keys.py        # or: tau-testnet keys new

# 2. genesis (pre-funds accounts, pins validator set + vote quorum + base fee)
python scripts/gen_genesis.py \
  --validator-key <96-hex-pubkey> \
  --account <addr1>:1000000 --account <addr2>:500000 \
  --network-id tau-testnet-v2 \
  --base-fee 10 \
  --genesis-rules-path genesis.tau \
  --genesis-consensus-path genesis_consensus.tau \
  --out data/genesis.json
```

- Validator and account addresses are **96 lowercase hex chars** (48-byte BLS pubkeys, no `0x`). Private keys are 64 hex chars (32 bytes). Use `--validator-privkey` to derive the pubkey automatically.
- **No auto-faucet** — unknown accounts have balance 0. Fund accounts at genesis with repeatable `--account ADDR:BALANCE`, or by transfer afterward.
- Transfer amounts are `bv[24]` → capped at **16,777,215** per step; `--base-fee` likewise (0–16777215).
- **Adding a validator after launch:** an existing validator proposes a `consensus_rule_update` with `host_contract_patch.validator_additions`; once it reaches the vote quorum (`supermajority` = ⌈2N/3⌉ by default, or `majority`) it activates. Removal works symmetrically.

---

## Configuration reference (`TAU_*` env vars)

Defaults shown; set via environment or `tau-testnet node run` flags. **Bold** vars must match across all peers on a network.

**Core**

| Var | Default | Meaning |
| --- | --- | --- |
| `TAU_ENV` | `development` | Profile: `development` / `test` / `production`. |
| **`TAU_NETWORK_ID`** | `tau-local` | Consensus network identifier. |
| `TAU_HOST` | `127.0.0.1` | TCP API bind address. |
| `TAU_PORT` | `65432` | TCP API port (WebSocket = `+1` = 65433). |
| `TAU_DB_PATH` | `node.db` | SQLite database path. |
| `TAU_PROGRAM_FILE` | `genesis.tau` | Application Tau rules program. |
| `TAU_FORCE_TEST` | `0` | `1` = mock Tau (test only; refused in `production`). |
| `TAU_USE_DIRECT_BINDINGS` | — | `1` = use native tau-lang bindings (default in Docker). |

**Networking**

| Var | Default | Meaning |
| --- | --- | --- |
| `TAU_NETWORK_LISTEN` | `/ip4/0.0.0.0/tcp/0` | libp2p bind multiaddr(s); use a fixed port (e.g. `/ip4/0.0.0.0/tcp/4001`) to be reachable. |
| `TAU_ANNOUNCE_ADDRS` | _(empty)_ | Multiaddrs advertised to peers (set to your public addr behind NAT). |
| `TAU_BOOTSTRAP_PEERS` | `[]` | JSON `[{"peer_id":…,"addrs":[…]}]` for discovery. |
| `TAU_IDENTITY_KEY_PATH` | `data/identity.key` | Persistent libp2p identity (`--ephemeral-identity` to skip). |
| `TAU_PEERSTORE_PATH` | `data/peerstore` | Persisted known-peer store. |

**Mining / validator**

| Var | Default | Meaning |
| --- | --- | --- |
| `TAU_MINING_ENABLED` | `true` | Run the internal block proposer. Set `false` for read nodes. **The standalone Docker image overrides this to `false`**, so the quickstart node does not mine; pass `-e TAU_MINING_ENABLED=true` to mine. |
| `TAU_MINER_PUBKEY` | _(test key)_ | 96-hex validator public key. |
| `TAU_MINER_PRIVKEY` / `_PATH` | — / `data/test_miner.key` | 64-hex signing key (direct value wins over path). |
| `TAU_ALLOW_REMOTE_CREATEBLOCK` | `false` | Allow non-loopback `createblock` RPC (leave off). |

**Governance / consensus** (network-wide)

| Var | Default | Meaning |
| --- | --- | --- |
| `TAU_VALIDATOR_VOTE_QUORUM` | `supermajority` | Default `vote_quorum` baked into genesis by `gen_genesis.py` (`supermajority` = ⌈2N/3⌉, or `majority` = N/2+1). **Runtime nodes read the policy from genesis, not this var.** Set it at genesis with `gen_genesis.py --vote-quorum`. |
| **`TAU_BLOCK_SIGNATURE_SCHEME`** | `bls_g2` | Block signature algorithm. |
| `TAU_GOVERNANCE_OPEN_ADMISSION` | `false` | Allow non-validators into governance (keep off in public). |

Operational extras: `TAU_MAX_MEMPOOL_TXS` (5000), `TAU_MAX_CONNECTIONS` (200), `TAU_RATE_LIMIT_PER_PEER` (2.0/s), `TAU_COMM_TIMEOUT` (60s; watchdog kills a stalled Tau), `TAU_WS_ALLOWED_ORIGINS`, `TAU_WS_CERT_PATH`/`TAU_WS_KEY_PATH` (WSS), `TAU_FORCE_FRESH_START` (crash recovery). See `config.py` for the full list.

---

## Tau execution mode

Real Tau evaluation is **enabled by default**. Setting `TAU_FORCE_TEST=1` bypasses the real engine and uses a deterministic mock validator path — for development/CI only (the test suite sets it automatically). Booting with `TAU_FORCE_TEST=1` **and** `TAU_ENV=production` is refused.

When native bindings are active (`TAU_USE_DIRECT_BINDINGS=1`, default in Docker), the node holds a single `tau::interpreter` instance and reads state updates from its output streams. The interpreter is process-global and Tau calls are serialized; a watchdog (`TAU_COMM_TIMEOUT`) kills a stalled evaluation. A native segfault under sustained use is a known alpha risk and is **not** isolated — it can stop the node process (see [Security & risk model](#security--risk-model)).

---

## Consensus boundary

"Tau-driven" means the Tau program is the **arbiter of the consensus verdict**, but the Python host performs all the cryptography, encoding, and state mechanics the verdict depends on. The split is fixed:

**Tau decides** (verdict output streams):
- `o6` — block validity. The genesis rule is `o6 = i10` — "valid iff the host's cryptographic proof check passed" (see below).
- `o7` — proposer eligibility.
- `o9` — consensus base fee (strict); `o8` — optional user fee (lenient).

**Python host enforces _before_ Tau** (the inputs Tau trusts):
- Transaction BLS signature verification + canonical decoding (`commands/sendtx.py`).
- **Block proposer signature** — `Block.verify_consensus_proof()` verifies the proposer's BLS signature over the canonical header and feeds the result to Tau as `i10`; the `o6 = i10` rule then rejects an unsigned/forged block. Validator-set membership alone proves only that the named proposer is _listed_, not that the sender holds its key — the signature check is what binds them.
- Proposer ∈ active validator set (`consensus/engine.py`).
- Per-account sequence, expiration, `fee_limit` admission estimate, and DoS size bounds (`consensus/admission.py`).
- Canonical Tau input-stream construction (heights, timestamps, ids).

**Python host enforces _after_ Tau** (applying the verdict):
- Account balance/sequence updates and fee charging as a single staged overlay, committed only if the tx stays accepted (all-or-nothing).
- Supply-conservation invariant (no mint/burn) — a mismatch raises, it does not silently continue.
- Governance lifecycle: quorum tally, **activation-delay floor**, and height transitions.
- `state_hash` computation and **exact-match** comparison against the block header.

**If Tau and Python disagree:**
- The host **may reject a Tau-valid block** — a wrong `state_hash`, a supply violation, a proposer not in the set, or a failed signature reject the block regardless of the Tau verdict.
- The host does **not** accept anything the Tau verdict failed: `o6 == 0` (with no `require_bls_sig` escape clause) ⇒ rejected.
- An invalid consensus fee (`o9`) raises `FeeRuleError`: the proposer aborts the round and validators **defer** the block — it is simply not committed and can be re-offered later (there is no negative cache; a persistently-bad voted-in rule can therefore halt progress at that height until governance corrects it).

**Non-consensus local policy** (may differ per node without forking): mempool size/eviction, rate limits, gossip/DHT discovery, log verbosity, RPC bind address.

---

## State hash & canonical encoding

Every block commits to its full post-state via `state_hash` and to its body via `merkle_root`. Both must be reproduced bit-for-bit by every node, so the encodings are fixed.

**State hash** (`consensus/state.py::compute_consensus_state_hash`):

```
state_hash = BLAKE3(
    consensus_rules_text  ||   # active consensus Tau program (UTF-8)
    application_rules_text ||   # active application Tau program (UTF-8)
    accounts_hash         ||   # SHA-256(canonical_json({"balances":…,"sequences":…}))
    consensus_meta_hash        # BLAKE3(encode_consensus_meta(…))
)
```

`consensus_meta_hash` binds the **active validator set, pending governance updates, votes, the activation schedule (with heights), and the resolved `vote_quorum` policy**. So `state_hash` commits to: account balances, sequence numbers, both rule programs (hence the fee policy, which the rules emit), the validator set, all in-flight governance, and the quorum policy. All collections are canonically sorted before hashing.

**Deliberately _not_ in `state_hash`:**
- `network_id` / `genesis_hash` — bound separately: the genesis hash is fixed by the `previous_hash` chain back to block 0, and both are enforced at the P2P handshake.
- `state_locator` — a DHT lookup hint, not consensus data.
- `consensus_proof` (the block signature) and the mempool — not state.

> **Breaking change:** the `vote_quorum` policy is now folded into `state_hash` (previously it was not, which allowed two nodes with different quorum config to agree on the hash while computing different governance outcomes). Genesis artifacts and chains created before this change are incompatible — regenerate with `scripts/gen_genesis.py`.

**Canonical identifiers:**

| Identifier | Function → hash | Encoding |
| --- | --- | --- |
| Block hash | `BlockHeader.canonical_bytes` → SHA-256 | Fixed big-endian binary: `block_number`(8B) ‖ `previous_hash`(32B) ‖ `timestamp`(8B) ‖ `merkle_root`(32B) ‖ `proposer_pubkey`(48B, omitted if empty) ‖ `state_hash`(32B). Excludes `state_locator`, `consensus_proof`. |
| `tx_id` | `compute_tx_hash` → SHA-256 | Compact sorted-key JSON of the **whole transaction, including `signature`**. |
| `merkle_root` | `compute_merkle_root` → SHA-256 | Leaves = `tx_id`s; odd levels duplicate the last node; empty tree = `SHA-256("")`. |
| `update_id` | `compute_update_id` → BLAKE3 | Length-prefixed binary over `(rule_revisions, activate_at_height, host_contract_patch)`; excludes signature/sequence/fee. |

**Determinism caveats — clients must match the host byte-for-byte:**
- Token amounts and `fee_limit` travel as **decimal strings**, and `tx_id`/signatures are computed over the raw JSON **without type-normalization**. A client that sends `100` instead of `"100"`, or uppercase hex, produces a different `tx_id` and signature. **Always send amounts as strings and pubkeys/hashes as lowercase hex.**
- Hashed JSON is always `sort_keys=True, separators=(",",":")`. Timestamps are integer seconds (no timezone, no float). No floats appear in any hashed payload.

---

## Cryptography & signatures

- **Scheme:** BLS12-381 via `py_ecc` **`G2Basic`** (IETF basic scheme, DST `…G2_XMD:SHA-256_SSWU_RO_NUL_`). Public keys are **G1, 48 bytes / 96 lowercase hex**; signatures are **G2, 96 bytes**; private keys are 32 bytes / 64 hex. `TAU_BLOCK_SIGNATURE_SCHEME=bls_g2` is descriptive metadata — the scheme is fixed in code.
- **Validation:** `Verify` runs public-key and signature **subgroup checks** and rejects the **point at infinity**; transaction ingest additionally runs `KeyValidate` on `sender_pubkey` and both transfer addresses. Malformed keys/signatures fail closed (`INVALID_SIGNATURE`); if `py_ecc` is unavailable, ingest is **refused** (`BLS_UNAVAILABLE`), never skipped.
- **Signed payloads:**
  - Transaction → `SHA-256` of canonical JSON of `{sender_pubkey, sequence_number, expiration_time, fee_limit, tx_type, …type-specific}`. `tx_type` **is** signed, so a `user_tx` signature cannot be replayed as a governance vote.
  - Block header → `SHA-256` of `BlockHeader.canonical_bytes()`, verified by `Block.verify_consensus_proof()`.

> ⚠️ **No cross-network / version domain separation (replay risk).** Signed payloads do **not** include `network_id`, `genesis_hash`, or a protocol version, and there is no explicit `tx`-vs-`block` domain tag (they are separated only implicitly by incompatible encodings). A transaction signed for one Tau network is cryptographically valid on any other network where the same keypair is funded. **Do not reuse account/validator keys across networks.** Adding explicit domain tags (e.g. `TAU_TESTNET_TX_V1 | network_id | genesis_hash | tx_type | body`) is planned and will be a breaking signature-format change.

---

## Transaction fees

Fees are sourced from the Tau consensus rules and votable by validators — no separate fee machinery.

- **Consensus fee (`o9`, strict).** Active consensus rules emit the base fee on stream `o9` (genesis default `always (o9[t]:bv[24] = { #x00000a }:bv[24]).` → 10/step). Change it via a `consensus_rule_update` carrying the full new consensus spec, voted to its activation height. Absent `o9` → fee model inactive (0). A present-but-invalid `o9` is a consensus failure: proposers abort the round and validators defer the block rather than guess.
- **User custom fee (`o8`, lenient).** User application rules may add a per-transfer fee on `o8`. Absent → 0 silently; invalid → 0 with a node-side warning.
- **Total:** `total_fee = Σ over the tx's Tau steps of (o9 + o8)` — one step per transfer; a transfer-less `user_tx` is charged one fee-query step. Multi-transfer txs pay N× by design.
- **`fee_limit` is a cap.** Rejected (at admission and in-block) if `total_fee > fee_limit`; the sender pays `total_fee`, not the cap. Every tx carries a valid `fee_limit`; **only `user_tx` is charged** (validators never need funds to govern).
- **Credited to** `block.header.proposer_pubkey`. **Charge-on-inclusion:** a fee-rejected tx pays nothing (no writes, no nonce bump). Sender must cover `Σ transfers + total_fee`.
- **Determinism note:** during block application only `i1` (amount), `i5` (block timestamp), `i12` (sender pubkey) and the tx's custom inputs carry real values; `i2`/`i3`/`i4` are mocked to `"0"`. A fee rule reading a mocked stream would charge a different fee at admission than at inclusion, so rule text referencing `i2`/`i3`/`i4` is **rejected at admission** (both user `o8` rules and consensus `o9` revisions). Scope on `i12` and tier on `i1` instead. Admission error `FEE_LIMIT_TOO_LOW` returns the computed `required_fee`.
- **Mempool priority** is by admission-time estimate (`estimated_fee DESC, fee_limit DESC, received_at ASC`); inflating `fee_limit` does not buy priority.
- **Limitations:** multiplication isn't verified in the deployed tau-lang usage, so percentage fees aren't expressible yet — flat fees and comparison-ladder tiers only. User rule text referencing `o6`/`o7`/`o9`, or any rule text reading the apply-time-mocked streams `i2`/`i3`/`i4`, is rejected at admission.

---

## Governance

Consensus rules and the validator set change **only** through on-chain governance. A `consensus_rule_update` carries the full new consensus spec (plus an optional `host_contract_patch` for validator add/remove); `consensus_rule_vote`s approve it. Update identity is `update_id = BLAKE3(rule_revisions, activate_at_height, host_contract_patch)` (signature / sequence / fee excluded), so the id is canonical and collision-resistant.

**Lifecycle:**

```
submitted ──(quorum reached)──> scheduled ──(height ≥ activate_at_height)──> active ──> archived
    │
    └──(activate_at_height passes while still pending)──> expired (archived)
```

- **Quorum** — promotion to `scheduled` needs votes ≥ `approval_threshold` = ⌈2N/3⌉ (`supermajority`) or N/2+1 (`majority`), where N is the **current** active validator set and the policy comes from genesis (bound into the state hash). A validator cannot vote twice (votes are a set); only active validators count — a forged or non-validator vote inside a block is a deterministic no-op.
- **Activation delay** — enforced at admission **and** at block application: `activate_at_height ≥ inclusion_height + N`. A crafted block cannot reach quorum and activate in the same block.
- **Expiry** — a pending update whose `activate_at_height` arrives before quorum is archived, not activated.
- **Safety** — a revision that fails to compile is rejected at admission (isolated staging compile) and again at activation; an activated rule emitting an invalid `o9` halts progress until further governance (see [Security & risk model](#security--risk-model)). Governance txs still require a valid signature, sequence, and expiration; they carry fee 0 and therefore sort **below** any paid user tx.

## Mempool policy

- **Selection order** — `estimated_fee DESC, fee_limit DESC, received_at ASC`. Inflating `fee_limit` does not outrank a higher estimate.
- **Sequences** — admission checks projected (confirmed + pending) state; a sender may stack contiguous sequences, but a **gap is rejected**. There is **no replacement / RBF** — a stuck low-fee tx must expire or be evicted, not be replaced.
- **Duplicates** — a repeat `tx_id` is idempotently ignored.
- **Capacity & eviction** — at the cap the **oldest pending** tx is evicted (FIFO, fee-blind; reserved txs are never evicted). The cap is `TAU_MAX_MEMPOOL_TXS` (default 5000), enforced consistently on both the soft admission pre-check and the DB-layer eviction, each counting pending rows only.
- **Expiry** — expired txs are pruned opportunistically on insert (no background reaper).
- **Persistence** — the mempool survives restart (same SQLite file) and is not re-validated on boot.
- **Re-validation** — the proposer fully re-executes and re-validates every tx at block-build time, so admission is best-effort, not authoritative.

## Features

- **Tau-driven pluggable consensus** — block validity (`o6`) and proposer eligibility (`o7`) decided by living `consensus_rules`; fully on-chain governance via `consensus_rule_update` / `consensus_rule_vote` with activation delays and a vote quorum.
- **On-chain PoA validator set** — proposers are gated against the active validator set; set membership changes only through governance.
- **Persistent blockchain & fork choice** — SQLite-backed chain, multiple competing tips, heaviest-valid-branch fork choice with deterministic tie-break, seamless reorgs (revert/re-apply state).
- **P2P networking (libp2p)** — protocols: `handshake`, `ping`, `sync`, `blocks`, `tx`, `gossip`; gossip topics `tau/blocks/1.0.0` and `tau/transactions/1.0.0`; genesis-hash handshake gate; bootstrap retry/backoff; NAT announce addresses; DHT-backed state/provider records. Block numbers are **0-indexed**; sync decisions use `head_hash`, not just `head_number`.
- **Authenticated transactions & blocks** — BLS12-381 signatures over canonical payloads ([details](#cryptography--signatures)); transactions carry per-account sequence numbers (replay protection) and expiration; blocks carry a proposer signature verified before they affect the head. Signatures are **not yet domain-separated across networks** — see the replay-risk note in [Cryptography & signatures](#cryptography--signatures).
- **Typed transactions** — `user_tx`, `consensus_rule_update`, `consensus_rule_vote`; common fields `sender_pubkey`, `sequence_number`, `expiration_time`, `fee_limit`, `signature`.
- **Hardening** — block proposer-signature verification, governance vote-quorum bound into the state hash, consensus-enforced activation delay, genesis-hash handshake gate; SQLite WAL + busy timeout, refuse-to-start on schema drift (no silent data loss), mempool size cap + expiry pruning, admission size limits, production guards on dev/test flags.

### DHT configuration & gossip health

The libp2p DHT layer exposes runtime knobs through `NetworkConfig`:

| Option | Default | Purpose |
| --- | --- | --- |
| `dht_refresh_interval` | `60.0` | Seconds between routing-table refreshes. |
| `dht_bucket_refresh_interval` | `dht_refresh_interval` | Stale-peer refresh/eviction interval. |
| `dht_bucket_refresh_limit` | `8` | Max stale peers revalidated per cycle. |
| `dht_stale_peer_threshold` | `3600.0` | Age before a peer is considered stale. |
| `dht_opportunistic_cooldown` | `120.0` | Min time between reseeding the same gossip/handshake-discovered peer. |
| `gossip_health_window` | `120.0` | Sliding window for `get_metrics_snapshot()` gossip health. |

`NetworkService.get_metrics_snapshot()` (or the periodic `[metrics]` log line) reports gossip activity, routing-table counts, and bucket refresh results.

---

## Response envelope

Node commands reply with a single-line JSON envelope (TCP appends `\r\n`; WebSocket emits it raw):

```json
{"status":"ok","command":"getbalance","data":{"address":"a63b...ea73","balance":"1000"}}
{"status":"error","command":"sendtx","error":{"code":"INVALID_SEQUENCE","message":"Invalid sequence number: expected 5, got 4.","details":{"expected":5,"received":4}}}
```

- `status` is `"ok"` or `"error"`; `command` echoes the request; `data` on success, `error.code`/`error.message`(+`details`) on failure.
- Types: addresses/hashes/IDs and token amounts are **strings** (overflow-safe); counts/heights/sequence numbers are integers; timestamps are ISO 8601 strings.
- Error codes: `INVALID_PARAMS`, `PARSE_ERROR`, `INVALID_SIGNATURE`, `INVALID_SEQUENCE`, `TX_EXPIRED`, `TX_REJECTED`, `TX_INVALID`, `BLS_UNAVAILABLE`, `FEE_LIMIT_TOO_LOW`, `FEE_RULE_ERROR`, `MINING_NOT_ELIGIBLE`, `MEMPOOL_EMPTY`, `MEMPOOL_FULL`, `MINING_CONFIG_ERROR`, `MINING_FAILED`, `BLOCK_NOT_CREATED`, `GOVERNANCE_ERROR`, `FORBIDDEN`, `COMM_TIMEOUT`, `TIMEOUT`, `UNKNOWN_COMMAND`, `RATE_LIMITED`, `INTERNAL_ERROR`.
- The `hello version=N` handshake stays plain text (versions 1 and 2).

## Block structure

A block header carries `block_number` (0-indexed height), `previous_hash`, `timestamp`, `merkle_root`, `state_hash` (the full post-state commitment — see [State hash & canonical encoding](#state-hash--canonical-encoding)), and `state_locator` (a DHT lookup hint, **not** consensus data). The body carries the ordered `transactions` and their `tx_ids`. Consensus is attested by `consensus_proof` — the proposer's BLS signature over the canonical header, verified by `Block.verify_consensus_proof()` and gated by the `o6 = i10` rule. There is **no proof-of-work**; validity and proposer eligibility are decided by the Tau consensus program at each height. See `block.py` (`Block`, `BlockHeader`, `compute_tx_hash`, `compute_merkle_root`).

---

## Development

```bash
# fast unit suite (Trio; disable the asyncio plugin)
./venv/bin/python3 -m pytest -p no:asyncio

# with the real Tau engine, point at the native bindings
PYTHONPATH=../tau-lang/build-Release/bindings/python/nanobind \
  ./venv/bin/python3 -m pytest -p no:asyncio
```

CI builds tau-lang and runs the consensus suite against the real engine ([.github/workflows/ci.yml](.github/workflows/ci.yml)). The full suite in a single process can hit a known pre-existing native segfault under sustained Tau use; run per-file if you see it.

**Key components:** `server.py` (TCP/WS server), `tau_manager.py` + `tau_native.py` (Tau engine lifecycle/IPC), `commands/` (RPC handlers incl. `sendtx`, `createblock`), `consensus/` (engine, governance, fees, admission), `chain_state.py` (balances/sequences/rebuild), `network/` (libp2p service, DHT, gossip), `db.py` (SQLite), `block.py`, `config.py`, `rules/` (built-in transfer-validation Tau rules), `scripts/gen_genesis.py`, `tests/`.

## Submitting issues

[Tau Testnet issues](https://github.com/IDNI/tau-testnet/issues).

## Production safety checklist

`TAU_ENV=production` enforces exactly one thing in code: it **refuses to boot with `TAU_FORCE_TEST=1`** (no mock Tau in production). Every other safe default below is global, not production-gated, and several can be overridden by env vars with no guard — so verify them yourself before exposing a node:

- [ ] **Network id** — set a unique `TAU_NETWORK_ID` (the `tau-local` default is not rejected).
- [ ] **Validator key** — supply your own `TAU_MINER_PRIVKEY(_PATH)` / `TAU_MINER_PUBKEY`; the shipped `data/test_miner.key` is **not** refused.
- [ ] **RPC/WS bind** — keep `TAU_HOST=127.0.0.1` (default) or firewall it; `0.0.0.0` is accepted with no warning. In Docker, publish RPC/WS only on `127.0.0.1` (see quickstart).
- [ ] **WS origins** — set `TAU_WS_ALLOWED_ORIGINS` explicitly. The check is **substring-based** and **always allows no-Origin clients and any `localhost`/`127.0.0.1` origin**.
- [ ] **WSS** — set **both** `TAU_WS_CERT_PATH` and `TAU_WS_KEY_PATH`; a partial/invalid TLS config **silently downgrades to plaintext** WS.
- [ ] **Governance** — keep `TAU_GOVERNANCE_OPEN_ADMISSION=false` (production only warns if it is on alongside bootstrap peers).
- [ ] **Remote createblock** — leave `TAU_ALLOW_REMOTE_CREATEBLOCK=false`; the loopback gate is the only protection.
- [ ] **Identity & DB** — set/back up `TAU_IDENTITY_KEY_PATH` and `TAU_DB_PATH`; both default into `data/` and are auto-created.
- [ ] **Rate limiting** — the plain TCP RPC path has **none**; the WS limiter is a fixed 5 req/s **per connection** (reset on reconnect). Front it with a proxy if exposed.

---

## Security & risk model

This is **alpha, non-finalized PoA**. Tokens have no value; the cryptography and consensus are unaudited.

**Fork choice & finality.** The "heaviest-valid-branch" weight is simply **block height**, with ties broken on the lexicographically smallest block hash (`fork_choice_scheme: height_then_hash`). There is **no finality and no checkpoints** — a reorg can run as deep as the common ancestor (bounded only by a 2000-block path cap in `get_chain_path`, beyond which the switch is refused). A validator controlling enough proposer slots can build a competing branch; honest nodes switch to a longer valid one. Reorgs revert and re-apply full state by replaying from genesis along the new path and commit it in a single DB transaction; the fast extend path writes the block and the head pointer in two transactions and relies on replay-on-restart for crash consistency.

**P2P threat model.**
- **Authentication** — transport is libp2p (Ed25519 peer identity). The application handshake gates peers on matching `network_id` **and** `genesis_hash`; a peer presenting an empty/missing or mismatching genesis is rejected once this node has a genesis (fork protection).
- **Block/tx relay** — gossiped transactions pass through the same admission path as RPC submissions; blocks are fully validated (proposer signature, validator-set membership, `state_hash`, fees) before they can affect the canonical head. Invalid blocks are rejected and never committed, but there is **no peer scoring/banning yet** — a peer can keep re-sending junk (throttled only at the libp2p connection level, `TAU_RATE_LIMIT_PER_PEER`).
- **DHT records are discovery hints, not trusted consensus data** — advertised state is re-validated against the local chain before use; provider/peer records are capped and truncated on intake to bound poisoning.
- **Not yet addressed** — eclipse/Sybil resistance (bootstrap peers are trusted for discovery), per-peer block/header quarantine, and a per-object Tau-evaluation budget beyond the global watchdog.

### RPC / WebSocket exposure

RPC (TCP, default `127.0.0.1:65432`) and WebSocket (`+1` → `65433`) bind to `TAU_HOST`. There is **no per-call authentication**; the only network gate is that `createblock` is refused from non-loopback clients (and always over WS) unless `TAU_ALLOW_REMOTE_CREATEBLOCK=true`, decided from the real socket peer address (not header-spoofable). The web wallet keeps private keys client-side and signs locally — keys are never sent to the node. Treat RPC/WS as a loopback / trusted-LAN surface; front it with TLS and an origin allowlist if you must expose it.

**Known alpha risks:** no economic finality; no slashing; possible deep reorgs; unaudited cryptography and consensus; **no cross-network signature domain separation** (do not reuse keys across networks); a sustained Tau run can hit a **native segfault that stops the node process** (no process isolation yet); and a voted-in consensus rule that emits an invalid `o9` (or otherwise fails at runtime) can **halt progress at a height** until governance corrects it.

---

## Project status

**Alpha** — active development, for testing and experimentation. In place: Tau-driven consensus, on-chain PoA validator set with governance quorum, native fee model, BLS-authenticated transactions, persistent chain with fork choice/reorgs, multi-node P2P sync.

## Future work

- Richer Tau logic (verified multiplication → percentage fees; finality/checkpoints).
- Validator rotation policies and stronger fork-choice/finality rules.
- Metrics/observability endpoints and operator runbooks.
- Broader integration-test coverage.
