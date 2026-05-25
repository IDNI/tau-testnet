# Tau Testnet developer CLI

The `tau-testnet` CLI is the developer-facing wrapper around node RPC, key
management, transactions, and Docker workflows. It is installable from a clone
of this repository and wraps the same TCP protocol used by `wallet.py`.

## Install (from a clone)

```bash
python -m venv venv
source venv/bin/activate
pip install -e .
tau-testnet --help
```

`python -m tau_testnet_cli --help` is equivalent.

`pip install -e .` is recommended during development. Wheel/sdist builds and
the GHCR release workflow are documented in [packaging.md](packaging.md).

## Global options

| Flag | Default | Notes |
|---|---|---|
| `--host` | `127.0.0.1` (or `config.HOST` if set to a non-bind-all value) | Node TCP RPC host. |
| `--port` | `65432` | Node TCP RPC port. |
| `--timeout` | `10` (seconds) | Network read/connect timeout. |
| `--json` | off | Emit machine-readable JSON where possible. |
| `--verbose` / `-v` | off | Show Python tracebacks on error (default: a single-line error). |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Success — node returned `{"status":"ok",...}` JSON envelope. |
| `1` | Application error — node returned `{"status":"error",...}` envelope, or `error …` plain-text from the handshake. |
| `2` | argparse misuse |
| `3` | Connection / timeout / response too large |
| `4` | Local file, key, or config error |

## Response envelope

Every node command (everything except the `hello` handshake) replies with a
single-line JSON envelope:

Protocol details (transports, handshake, full command list): [blockchain_api.md](blockchain_api.md).

```json
{"status":"ok","command":"<name>","data":{...}}
{"status":"error","command":"<name>","error":{"code":"<CODE>","message":"<text>","details":{...}?}}
```

The TCP transport adds `\r\n` framing at the wire; WebSocket emits the raw
envelope without `\r\n`. The handshake (`hello version=1` / `hello version=2`
→ `ok version=N env=… node=…`) stays plain text — it is session-level, not a
data API. `tau-testnet ping` and `tau-testnet --json status` consume the
plain-text handshake reply directly.

Error codes emitted by the node: `INVALID_PARAMS`, `PARSE_ERROR`,
`INVALID_SIGNATURE`, `INVALID_SEQUENCE`, `TX_EXPIRED`, `TX_REJECTED`,
`TX_INVALID`, `BLS_UNAVAILABLE`, `MINING_NOT_ELIGIBLE`, `MEMPOOL_EMPTY`,
`MINING_CONFIG_ERROR`, `MINING_FAILED`, `BLOCK_NOT_CREATED`,
`GOVERNANCE_ERROR`, `NOT_FOUND`, `TAU_NOT_READY`, `TIMEOUT`,
`UNKNOWN_COMMAND`, `RATE_LIMITED`, `INTERNAL_ERROR`. Structured context (e.g.
`{"expected":5,"received":4}` on `INVALID_SEQUENCE`) lives under
`error.details`.

## Commands

### `tau-testnet version`

Print the installed CLI version.

```bash
tau-testnet version
tau-testnet --json version
```

### `tau-testnet ping`

TCP handshake with the node. Sends `hello version=1`, prints the response
(expected: `ok version=1 env=… node=tau-node`).

```bash
tau-testnet ping
tau-testnet --host testnet.example.com --port 65432 ping
```

### `tau-testnet status`

Best-effort node status. Runs the handshake plus `gettimestamp` and
`getmempool`; if any sub-RPC fails the rest still execute and the failed
piece is reported as an error string.

```bash
tau-testnet status
tau-testnet --json status
```

### `tau-testnet rpc <command>`

Send a raw command string to the node and print its response verbatim.
Exits `1` if the JSON envelope has `"status":"error"` (or if the handshake
reply starts with `error `).

```bash
tau-testnet rpc "getbalance 0xabc..."
tau-testnet rpc gettimestamp
```

### Account state

```bash
tau-testnet balance <pubkey-hex>
tau-testnet sequence <pubkey-hex>
tau-testnet history <pubkey-hex>
tau-testnet accounts
```

### Chain state

```bash
tau-testnet mempool
tau-testnet blocks
tau-testnet blocks --limit 10
tau-testnet tau-state
```

### Governance introspection

```bash
tau-testnet governance
tau-testnet --json governance | jq '.pending_updates'
```

### Compute an update-id

```bash
tau-testnet update-id --file consensus_update.json
tau-testnet update-id --inline '{"rule_revisions":["always."],"activate_at_height":100}'
```

The input must be a JSON object with `rule_revisions`, `activate_at_height`,
and optionally `host_contract_patch` (object or `null`/omitted).

> The inline payload flag is named `--inline` (not `--json`) to avoid
> colliding with the global `--json` output-mode flag.

## Keys (Phase 2)

Keys are stored under `~/.tau-testnet/keys/<name>.json`. On POSIX the files are
chmod `0600`. `keys list` and `keys show <name>` (without `--private`) never
print private material.

```bash
# Generate a fresh keypair, print only (no file written)
tau-testnet keys new
tau-testnet keys new --json

# Generate a key and save it to ~/.tau-testnet/keys/alice.json
tau-testnet keys save --name alice

# Import an existing private key under a logical name (the private key is
# saved but never echoed back to the terminal)
tau-testnet keys save --name alice --privkey 0xabc...

# Public-only operations
tau-testnet keys pub --privkey 0xabc...
tau-testnet keys list
tau-testnet keys show alice

# Reveal the private key (explicit opt-in)
tau-testnet keys show alice --private

# Delete a key. Requires --yes in non-interactive contexts.
tau-testnet keys delete alice --yes
```

## Transactions

```bash
# Single-recipient transfer
tau-testnet tx send --key alice --to <recipient_pubkey> --amount 10

# Multiple recipients (combine flags freely; matches wallet.py semantics)
tau-testnet tx send --key alice \
    --transfer <pk1>:5 \
    --transfer <pk2>:7 \
    --rule-file my_rule.tau

# Use a private key directly instead of a saved key
tau-testnet tx send --privkey 0xabc... --to <pk> --amount 1

# Build the operations dict yourself
tau-testnet tx send --key alice --operations-json ops.json

# Sign without submitting (useful for offline workflows)
tau-testnet tx raw-sign --privkey 0xabc... --payload tx.json > signed_tx.json

# Submit a pre-signed payload
tau-testnet tx raw-submit --file signed_tx.json
```

`tx send` exits `1` when the node returns a `{"status":"error",...}`
envelope (any `error.code`, e.g. `INVALID_SIGNATURE`, `INVALID_SEQUENCE`,
`TX_REJECTED`), `4` for bad amounts/empty operations/missing inputs, `3` on
connection/timeout errors.

## Governance

```bash
# Inspect governance state (alias for `tau-testnet governance`)
tau-testnet gov list
tau-testnet --json gov list | jq '.pending_updates'

# Compute the update-id for a candidate update
tau-testnet gov update-id --file consensus_update.json

# Submit a consensus_rule_update transaction
tau-testnet gov propose --key alice --file consensus_update.json

# Vote on a pending update (approve=true is implicit; approve=false is rejected
# by the node)
tau-testnet gov vote --key alice --update-id <update_id_hex>
```

`consensus_update.json` shape:
```json
{
  "rule_revisions": ["always."],
  "activate_at_height": 100,
  "host_contract_patch": null
}
```

`host_contract_patch` may be omitted, set to `null`, or be an object such as
`{"proof_scheme": "bls_header_sig", "fork_choice_scheme": "height_then_hash", "input_contract_version": 1}`.

The CLI wraps this with `tx_type`, `sender_pubkey`, `sequence_number`,
`expiration_time`, `fee_limit`, and the BLS `signature` — all flat at the top
level (matching `tests/test_gov_integration.py`).

### Prerequisite: the proposer/voter must be an active validator

Both `gov propose` and `gov vote` are admission-checked by `consensus/admission.py`:
the sender pubkey must appear in `active_validators` (visible via `tau-testnet
governance` / `gov list`). Otherwise the node returns
`{"status":"error","command":"sendtx","error":{"code":"TX_REJECTED","message":"Proposer <pk> is not an active validator."}}`
(exit code 1).

The validator set is populated from two sources:

1. **Genesis** — `consensus_meta.active_validators` in `data/genesis.json`. Use
   `scripts/gen_genesis.py --validator-key <96-hex-pubkey>` to write a genesis
   that seeds your test pubkey as a validator.
2. **Per-block override** — on every block, `chain_state.tick_governance()`
   resets `active_validators` to the value of `TAU_MINER_PUBKEY` (or
   `TAU_MINER_PUBKEYS`). So the *running* validator set is whatever the node
   was started with.

Recipe to wire up a fresh local validator from scratch:

```bash
# 1. Generate (or import) a key and save it to the keystore.
tau-testnet keys save --name alice
ALICE_PK=$(tau-testnet keys show alice)

# 2. Write a genesis that lists alice as the validator and funds her account.
scripts/gen_genesis.py \
    --validator-key "$ALICE_PK" \
    --genesis-address "$ALICE_PK" \
    --genesis-balance 1000000 \
    --out data/genesis.json

# 3. Start the node fresh with TAU_MINER_PUBKEY=<alice> so tick_governance keeps
#    her in the active set, plus TAU_FORCE_FRESH_START=1 so the new genesis is
#    actually loaded.
rm -f node.db
TAU_ENV=test \
TAU_MINING_ENABLED=true \
TAU_MINER_PUBKEY="$ALICE_PK" \
TAU_FORCE_FRESH_START=1 \
    python server.py

# 4. Sanity-check the validator set.
tau-testnet --json governance | jq '.active_validators'
# → ["<ALICE_PK>"]

# 5. Propose, vote, observe.
tau-testnet gov propose --key alice --file consensus_update.json
tau-testnet --json gov list | jq '.lifecycle, .pending_updates'
# … wait for one block, then …
tau-testnet gov vote --key alice --update-id <update_id>
```

### Update lifecycle states

`gov list` exposes a per-update `lifecycle` map alongside `pending_updates`,
`scheduled_updates`, `archival_updates`, and `votes[]`. The states an update
moves through:

| State | When |
|---|---|
| `mempool` | Proposal tx accepted by mempool admission, not yet in a block. |
| `pending` | Proposal landed in a block; awaiting votes. Visible in `pending_updates`. |
| `approved-and-scheduled` | Votes for the update reached `approval_threshold`. Moves to `scheduled_updates` with its `activation_height`. |
| `activated` | Block height reached `activation_height`. Update id appears in `archival_updates` and `active_consensus_id` matches it. |
| `archived` | Update was superseded (in archival but not active). |

## Node lifecycle and Docker

`tau-testnet node …` wraps the existing entrypoints — running `python
server.py` directly and the legacy scripts under `scripts/` keep working
unchanged, so this CLI group is purely additive.

### Run the node in-process

```bash
# Equivalent to `python server.py` with conventional env defaults.
tau-testnet node run

# Standalone test miner — mining + isolated (no public testnet bootstrap)
# are implied by --test. Pair with --listen if you want to bind to localhost
# only.
tau-testnet node run --test --listen 127.0.0.1:4001

# Mine without isolating (use the configured bootstrap list):
tau-testnet node run --test --no-isolated

# Stay isolated but don't run the miner:
tau-testnet node run --test --no-miner

# Other flags
tau-testnet node run --fresh              # TAU_FORCE_FRESH_START=1 (ignore persisted DB)
tau-testnet node run --ephemeral-identity # forwarded to server.py argparse
```

| Flag | Env var(s) set | Notes |
|---|---|---|
| `--test` | `TAU_ENV=test`, `TAU_FORCE_TEST=1` | Also implies `--miner` and `--isolated` (shell env still wins for both). Override with `--no-miner` / `--no-isolated`. |
| `--miner` / `--no-miner` | `TAU_MINING_ENABLED=true` / `=false` | Explicit form unconditionally overrides shell env. Default: implied true under `--test`, otherwise unset. |
| `--isolated` / `--no-isolated` | `TAU_BOOTSTRAP_PEERS=[]` / unset | `--no-isolated` defers to shell or `config.bootstrap_peers`. |
| `--fresh` | `TAU_FORCE_FRESH_START=1` | |
| `--listen ADDR` | `TAU_NETWORK_LISTEN=ADDR` | Accepts `/ip4/host/tcp/port` or the `host:port` IPv4 shorthand (auto-rewritten). |
| `--ephemeral-identity` | (none — appended to `sys.argv`) | Forwarded to `server.py`'s argparse: regenerate the libp2p identity for this run. |

`node run` lazily imports `server` and calls `server.main()`, so the env
variables you set on the CLI are visible to `config` at module-import time.

> **Equivalence check**: a fully isolated single-validator test miner that
> previously required this shell command:
>
> ```bash
> TAU_LOG_LEVEL=DEBUG \
> TAU_NETWORK_LISTEN=/ip4/127.0.0.1/tcp/4001 \
> TAU_ENV=test TAU_BOOTSTRAP_PEERS="[]" TAU_MINING_ENABLED=true \
>     ./venv/bin/python server.py
> ```
>
> is now:
>
> ```bash
> TAU_LOG_LEVEL=DEBUG tau-testnet node run --test --listen 127.0.0.1:4001
> ```
>
> (`TAU_LOG_LEVEL` is not a CLI flag — it's still a shell prefix.)

### Build the standalone Docker image

```bash
tau-testnet node docker-build                       # default tag: tau-testnet-standalone:latest
tau-testnet node docker-build --jobs 8              # propagate to TAU_BUILD_JOBS
tau-testnet node docker-build --tau-lang-ref my-fork
tau-testnet node docker-build --image foo:dev --pull
```

This is a thin wrapper around
`docker build -f Dockerfile.standalone -t <image> [--build-arg …] .`

### Run the container

```bash
# Always publishes 65432, 65433, 4001 and mounts <data-dir>:/data.
tau-testnet node docker-run --data-dir ./data

# Local mining only, no public testnet bootstrap:
tau-testnet node docker-run --miner --isolated

# Background detach, named container, extra env:
tau-testnet node docker-run --detach --name tau-test --env TAU_LOG_LEVEL=DEBUG
```

Maps to:

```
docker run [--rm] [-it] [-d] [--name <n>]
    -p 65432:65432 -p 65433:65433 -p 4001:4001
    -v <data-dir>:/data
    [-e TAU_MINING_ENABLED=true] [-e TAU_BOOTSTRAP_PEERS=[]] [-e ...]
    <image>
```

### `docker compose` shortcut

```bash
tau-testnet node docker-compose-up                 # docker compose up --build
tau-testnet node docker-compose-up --no-build -d   # detached, skip rebuild
```

## Connecting to a remote node

```bash
tau-testnet --host testnet.tau.net --port 65432 status
tau-testnet --host 10.0.0.5 --port 65432 governance
```

## See also

- [`README.md`](../README.md) — high-level overview, standalone Docker node, follower mode.
- [`WALLET_USAGE.md`](../WALLET_USAGE.md) — original `wallet.py` usage (still supported).
- `packaging.md` — wheel/sdist builds, GHCR releases, tag workflow.
