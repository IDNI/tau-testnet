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

```json
{"status":"ok","command":"<name>","data":{...}}
{"status":"error","command":"<name>","error":{"code":"<CODE>","message":"<text>","details":{...}?}}
```

The TCP transport adds `\r\n` framing at the wire; WebSocket emits the raw
envelope without `\r\n`. The handshake (`hello version=1` / `hello version=2`
→ `ok version=N env=… node=…`) stays plain text — it is session-level, not a
data API. `tau-testnet ping` and `tau-testnet --json status` consume the
plain-text handshake reply directly.

Structured context (e.g. `{"expected":5,"received":4}` on `INVALID_SEQUENCE`)
lives under `error.details`.

Error codes emitted by the node, by origin:

| Origin | Codes |
|---|---|
| Server dispatch (`server.py`) | `UNKNOWN_COMMAND`, `RATE_LIMITED`, `FORBIDDEN`, `TIMEOUT`, `INTERNAL_ERROR` |
| Argument / payload parsing (every command) | `INVALID_PARAMS`, `PARSE_ERROR` |
| `sendtx` / `checktx` structural | `TX_INVALID`, `TX_EXPIRED`, `INVALID_SIGNATURE`, `INVALID_SEQUENCE`, `BLS_UNAVAILABLE`, `TX_REJECTED` |
| `sendtx` fees & capacity | `FEE_LIMIT_TOO_LOW`, `FEE_RULE_ERROR`, `INSUFFICIENT_FUNDS`, `MEMPOOL_FULL` |
| Admission (`consensus/admission.py`) | `ADMISSION_TIMEOUT`, `ADMISSION_UNAVAILABLE`, `DUPLICATE_UPDATE`, `ALREADY_VOTED`, `UNSCOPED_USER_RULE`, `WIDTH_MISMATCH`, `RULE_WITH_TRANSFERS`, `MIXED_OUTPUT_RULE`, `CLAUSE_SHAPE`, `CLAUSE_REGISTRY_FULL`, `DUPLICATE_REQUEST`, `TOO_MANY_REQUESTS`, `NOT_AN_APPROVER`, `UNKNOWN_REQUEST`, `REQUEST_EXPIRED`, `REQUEST_RESOLVED` |
| `createblock` | `MEMPOOL_EMPTY`, `MINING_NOT_ELIGIBLE`, `MINING_BUSY`, `MINING_CONFIG_ERROR`, `MINING_FAILED`, `BLOCK_NOT_CREATED` |
| Governance / rule / approval reads | `GOVERNANCE_ERROR`, `OFFER_UNKNOWN`, `REQUEST_UNKNOWN`, `FEATURE_INACTIVE`, `TAU_UNAVAILABLE`, `TAU_ERROR` |

> Earlier revisions of this table listed `NOT_FOUND` and `TAU_NOT_READY`. Neither
> string exists anywhere in the node; the real codes are `OFFER_UNKNOWN` /
> `REQUEST_UNKNOWN` and `TAU_UNAVAILABLE`. Do not match on the retired names.

`rpc createblock` accepts one optional argument, `allow-empty`. By default an
empty mempool is refused with `MEMPOOL_EMPTY`; pass the flag when the point is
to advance height (e.g. reaching a governance activation). Rounds are
serialized node-wide, so a caller racing the miner gets `MINING_BUSY`.

## Raw protocol

What the CLI, `wallet.py`, and `web-wallet/` all speak underneath. There is no
authentication layer: reachability *is* authorization, so a node bound to
anything other than loopback is world-writable for every command below.

### Transports

| | TCP | WebSocket |
|---|---|---|
| Address | `config.HOST` : `config.PORT` (`127.0.0.1:65432`) | `config.HOST` : `PORT + 1` (`65433`) |
| Scheme | raw socket | `ws://`, or `wss://` when `TAU_WS_CERT_PATH` **and** `TAU_WS_KEY_PATH` are both set |
| Request framing | one command per line, `\n` (an optional preceding `\r` is stripped) | one command per WebSocket text message, unframed |
| Response framing | envelope + `\r\n` | envelope, raw, no `\r\n` |
| Max request | `MAX_RPC_COMMAND_BYTES`, default 4 MiB | 1 MiB (`trio_websocket`'s `max_message_size` default — not configured by the node) |

Both transports run the same `process_command` dispatcher, so the command
grammar and envelopes are identical; only framing, size caps, and the
locality rule below differ.

The WebSocket listener scans `65433`–`65442` for the first free port, so on a
host already running a node the browser wallet may need a port other than the
default. The node binds its libp2p listener first, and both scans (the TCP
one from `65432`) skip its ports: a p2p port inside either range moves the
WebSocket or TCP listener, never the p2p one. It also enforces an `Origin` allowlist: missing/`null` origins and
anything containing `localhost` or `127.0.0.1` pass, otherwise the origin must
match an entry in the comma-separated `TAU_WS_ALLOWED_ORIGINS` (`*` allows
all). A rejected connection gets the plain-text `error disallowed_origin` and
is then closed.

### Connection lifecycle

The TCP handler is a request loop: it reassembles across `recv()` boundaries,
dispatches every complete line, ignores blank lines, and on EOF flushes an
unterminated remainder as one final command. It closes the connection only on
peer disconnect or after an over-size request.

Because the server keeps the connection open, a client that wants a large
response cannot simply read once. `tau_testnet_cli/rpc.py` sends one command,
half-closes the write side with `shutdown(SHUT_WR)`, then reads until the
server closes — which is why the CLI is one-command-per-connection, and why
its own 4 MiB read ceiling surfaces as exit code `3` rather than an envelope.

### Handshake

```
hello version=1                    → ok version=1 env=<env> node=tau-node
hello version=2                    → ok version=2 env=<env> node=tau-node
hello version=9                    → error unsupported_version expected=1|2 got=9
hello version=                     → error malformed_handshake
```

Plain text, not an envelope, and **stateless**: the dispatcher holds no
per-connection session, so the handshake is optional and every command below
works without it. Only the exact prefix `hello version=` is treated as a
handshake — bare `hello` falls through to command dispatch and comes back as
an `UNKNOWN_COMMAND` envelope.

### Command grammar

Whitespace-split, case-insensitive in the verb only (`parts[0].lower()`);
arguments keep their case except where a handler lowercases a hex id. Payload
commands take the rest of the line verbatim as one JSON argument, and tolerate
it being wrapped in matching single or double quotes.

The full registry (25 names, `app/container.py`):

| Command | Grammar |
|---|---|
| `sendtx` | `sendtx <json_payload>` |
| `checktx` | `checktx <json_payload>` — admission dry-run, no mempool write |
| `createblock` | `createblock [allow-empty]` — **local-only**, see below |
| `getmempool` | `getmempool` |
| `gettimestamp` | `gettimestamp` |
| `getcurrenttimestamp` | alias of `gettimestamp` |
| `getbalance` | `getbalance <address>` |
| `getaccountstate` | `getaccountstate <address>` — pending-aware |
| `getsequence` | `getsequence <address>` |
| `history` | `history <address>` — mempool only, not chain history |
| `gettxstatus` | `gettxstatus <tx_hash>` — 64 hex chars |
| `getblocks` | `getblocks [limit]` — bare form returns the whole chain |
| `getallaccounts` | `getallaccounts` |
| `gettaustate` | `gettaustate` |
| `getgovernance` | `getgovernance` |
| `getupdateid` | `getupdateid <json_payload>` |
| `getofferid` | `getofferid <json_payload>` |
| `getruleoffers` | `getruleoffers <address> [in\|out\|all]` (default `all`) |
| `getruleoffer` | `getruleoffer <offer_id>` — 64 hex chars |
| `getruleconflict` | `getruleconflict <offer_id>` — advisory, node-local |
| `getapprovalrequests` | `getapprovalrequests <address> [in\|out\|all]` (default `all`) |
| `getapprovalrequest` | `getapprovalrequest <request_id>` |
| `getrequestid` | `getrequestid <json_payload>` |
| `getapprovalslots` | `getapprovalslots <address>` — advisory, node-local |
| `getapprovalpreview` | `getapprovalpreview <json_draft>` — advisory, node-local |

`gettimestamp` and `getcurrenttimestamp` share one handler, and it hardcodes
its own name: a `getcurrenttimestamp` request comes back with
`"command":"gettimestamp"`. Match on `status`, not on the echoed name.

The five approval commands return `FEATURE_INACTIVE` unless the co-signature
slots are reserved at the tip.

### Locality: `createblock`

`createblock` is refused with `FORBIDDEN` unless the peer address is
`127.0.0.1` or `::1`, because it signs with the node's own `MINER_PRIVKEY`.
The WebSocket path never passes locality through, so `createblock` is
**always** refused over WebSocket, loopback included. Set
`TAU_ALLOW_REMOTE_CREATEBLOCK=true` (config key
`authority.allow_remote_createblock`) to lift the check. Validators mine
through the internal `SoleMiner` loop, not this command.

### Rate limiting

Two token buckets per connection, on both transports, keyed to nothing but the
connection — reconnecting resets them.

| Bucket | Burst | Refill | Applies to |
|---|---|---|---|
| general | 10 | 5/s | every command |
| expensive | 2 | 0.5/s | `checktx`, `getapprovalpreview`, `getapprovalslots` |

An expensive command is charged to *both* buckets, so it cannot be used to
dodge the general rate. `sendtx` is deliberately not in the expensive tier: it
burns a sequence number, is capped by the mempool limit, and carries a
`fee_limit`, so it is already self-deterring.

Over budget returns `RATE_LIMITED` and drops that one command, keeping the
connection open. The envelope's `command` field is the literal string
`rate_limit`, **not** the command you sent — this is the one response whose
`command` does not round-trip.

### Envelope edge cases

These carry an empty `command` field, because the dispatcher rejected the
request before it had a name:

| Condition | Response |
|---|---|
| Empty or whitespace-only request | `INVALID_PARAMS`, `command: ""` |
| Invalid UTF-8 in a TCP line | `INVALID_PARAMS`, `command: ""` |
| Buffered request over `MAX_RPC_COMMAND_BYTES` | `PARSE_ERROR`, `command: ""`, then the connection closes |

A handler that raises is caught per-command and reported as `INTERNAL_ERROR`
(or `TIMEOUT` for a `TimeoutError`); the connection survives either way.

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
tau-testnet blocks --limit 10   # the 10 most recent blocks
tau-testnet tau-state
```

`--limit N` sends `getblocks N` and returns the N highest-numbered blocks,
still ordered oldest → newest. Prefer it on a long chain: the unlimited form
can exceed the CLI's 4 MiB read ceiling and fail with exit code `3`. The
response also carries `total` (the full chain length) and `truncated`, so a
short window is distinguishable from a short chain.

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

## Keys

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

## Rule sharing

Send a Tau rule to another user; they check its conflict status and then accept
it into their own specification or reject it.

```bash
# Offer a rule. --expire-in N gives it N blocks to land, counted from the next
# block (expire_at_height = tip + 1 + N);
# --expire-at-height sets an absolute height instead.
tau-testnet rule offer --key alice --to <bob_pubkey> --rule-file policy.tau
tau-testnet rule offer --key alice --to <bob_pubkey> --rule 'always ( o5[t]:bv[24] = { #x000000 }:bv[24] ).' \
    --expire-at-height 5000

# Inspect. `list` defaults to the --key owner's address; --role filters direction.
tau-testnet rule list --key bob --role in
tau-testnet --json rule list <pubkey> | jq '.data.incoming'
tau-testnet rule show <offer_id>          # full rule text
tau-testnet rule check <offer_id>         # layered conflict report

# Decide. `accept` prints the conflict report first and refuses on a
# warn/conflict verdict unless --yes is given.
tau-testnet rule accept --key bob <offer_id>
tau-testnet rule accept --key bob <offer_id> --yes
tau-testnet rule reject --key bob <offer_id>

# Derive an offer id without submitting anything
tau-testnet rule offer-id --rule-file policy.tau \
    --from-pubkey <alice_pubkey> --to <bob_pubkey> --expire-at-height 5000
```

`accept` fetches the offered text from the node rather than having you retype
it: the node recomputes `offer_id` from the accept's own copy of the text, so
any reformatting makes the accept unapplicable. `--rule-file` on `accept` is an
escape hatch for the case where the node no longer has the text (it is
node-local durability, not consensus state).

Underlying RPCs: `getruleoffers <address> [in|out|all]`, `getruleoffer <offer_id>`,
`getruleconflict <offer_id>`, `getofferid '<json>'`.

The conflict report is **advisory and node-local** and never gates a
transaction. It does not check satisfiability — tau-lang exposes
`sat`/`unsat`/`valid`/`unrealizable` in C++ but not through its Python
bindings — so a clean result means no conflict was *observed*. See the
[Rule sharing](../README.md#rule-sharing) section for the composite-rule model
and why an accepted rule is composed rather than appended.

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
`expiration_time`, `expire_at_height`, `fee_limit`, and the BLS `signature` —
all flat at the top level (matching `tests/test_gov_integration.py`). The CLI
fills `expire_at_height` from the node's tip (`tip + 1 + 1000`: 1000 blocks
to land in, counted from the next one); every transaction must carry one.

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
