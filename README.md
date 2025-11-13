![The TauNet logo](/docs/images/TauNet_banner.png)

# Tau Testnet Alpha Blockchain

This project is the codebase for the Tau Testnet Alpha Blockchain. Its primary goal is to provide a live, working demonstration of a blockchain where core state transitions and rules are governed by Tau's formal logic.
The architecture is designed around the principle of extralogical processing. The core engine, written in Python, handles networking, storage, and any operations not yet implemented in pure Tau logic, such as cryptographic signature verification. This engine prepares transactions and validates them against a separate Tau logic program (executed via Docker), which serves as the ultimate arbiter of the chain's rules. This hybrid model allows us to build a robust and feature-complete testnet today, showcasing the power of Tau's logical core while providing all the necessary functions for a working blockchain.

## Features

*   **TCP Server**: Handles client connections and commands.
*   **P2P Networking (libp2p shim)**:
    *   Protocols (all implemented on the libp2p shim):
        - `TAU_PROTOCOL_HANDSHAKE` (`/tau/handshake/1.0.0`): Exchange node info and current tip.
        - `TAU_PROTOCOL_PING` (`/tau/ping/1.0.0`): Latency/keepalive round-trip with a nonce.
        - `TAU_PROTOCOL_SYNC` (`/tau/sync/1.0.0`): Header/tip synchronization with locator/stop/limit semantics.
        - `TAU_PROTOCOL_BLOCKS` (`/tau/blocks/1.0.0`): Serve block bodies by hash list or by range (`from`/`from_number` + `limit`).
        - `TAU_PROTOCOL_STATE` (`/tau/state/1.0.0`): Fetch the latest known block metadata alongside requested account/receipt data.
        - `TAU_PROTOCOL_TX` (`/tau/tx/1.0.0`): Compatibility channel for submitting transactions, which queues locally and re-broadcasts over gossipsub.
        - `TAU_PROTOCOL_GOSSIP` (`/tau/gossip/1.0.0`): Gossipsub-style transport used for topic-based dissemination.
    *   Gossip topics:
        - `tau/blocks/1.0.0`: Propagates new headers/tip summaries prior to full sync.
        - `tau/transactions/1.0.0`: Propagates canonical, signed transactions across the mesh.
    *   Bootstrapping connects to peers, performs handshake + sync, fetches missing blocks, rebuilds state, and replays gossip subscriptions so the node immediately participates in block/transaction mesh traffic.
    *   Verbose debug logging traces requests/responses and bootstrap progress for easier development.
*   **Persistent Blockchain**:
    *   Creates blocks from transactions stored in the mempool.
    *   Links blocks together in a chain by referencing the previous block's hash.
    *   Persists the entire chain of blocks to a SQLite database.
*   **Authenticated Transactions via BLS Signatures**:
    *   Transactions are cryptographically signed using BLS12-381 signatures.
    *   The server verifies the signature against the `sender_pubkey` and a canonical representation of the transaction data.
    *   Requires `py_ecc.bls` for signature verification.
*   **Replay Protection with Sequence Numbers**:
    *   Each account (`sender_pubkey`) has a sequence number managed by `chain_state.py`.
    *   Transactions must include the correct sequence number, which is incremented upon successful validation.
*   **Transaction Expiration**:
    *   Transactions include an `expiration_time` (Unix timestamp) after which they are considered invalid.
*   **New JSON Transaction Structure**:
    *   The `sendtx` command now expects a JSON object with the following top-level fields:
        *   `sender_pubkey` (string): BLS12-381 public key of the transaction authorizer.
        *   `sequence_number` (integer): Nonce for replay protection.
        *   `expiration_time` (integer): Unix timestamp for transaction validity.
        *   `operations` (object): Contains the actual operations to perform (e.g., `"0": <rules_data>`, `"1": <transfers_list>`).
            *   For transfers in `operations["1"]`, the `from_pubkey` of each transfer must match the top-level `sender_pubkey`.
        *   `fee_limit` (string/integer): Placeholder for future fee models.
        *   `signature` (string): Hex-encoded BLS signature over a canonical form of the other fields.
*   **Tau Integration for Operation Validation**: The `genesis.tau` program validates the logic of operations within a transaction (e.g., coin transfers via SBF). This now includes robust structural validation to ensure transfer data is complete and well-formed.
*   **String-to-ID Mapping**: Dynamically assigns `y<ID>` identifiers for Tau SBF.
*   **In-Memory Balances & Sequence Numbers**: Tracks account balances and sequence numbers for rapid validation.
*   **SQLite Mempool**: Persists transactions awaiting inclusion in a block.
*   **BLS12-381 Public Key Validation**: Format and optional cryptographic checks for public keys.

### DHT Configuration & Gossip Health

The libp2p-based DHT layer now exposes several runtime knobs through `NetworkConfig`:

| Option | Default | Purpose |
| --- | --- | --- |
| `dht_refresh_interval` | `60.0` | Seconds between background calls to `KadDHT.refresh_routing_table`. |
| `dht_bucket_refresh_interval` | `dht_refresh_interval` | Interval for opportunistic stale peer refresh/eviction. |
| `dht_bucket_refresh_limit` | `8` | Maximum stale peers revalidated per cycle. |
| `dht_stale_peer_threshold` | `3600.0` | Age (seconds) before a peer is considered stale. |
| `dht_opportunistic_cooldown` | `120.0` | Minimum time between reseeding the same peer discovered via gossip/handshake. |
| `gossip_health_window` | `120.0` | Sliding window used by `get_metrics_snapshot()` to flag gossip as healthy/stale. |

Call `NetworkService.get_metrics_snapshot()` (or read the periodic `[metrics]` log line) to monitor gossip activity, routing table counts, and bucket refresh results.

## Setup and Running

### Prerequisites

*   Python 3.8+
*   Docker
*   A Tau Docker image (default: `tau`, configurable in `config.py`).
*   `py_ecc` (specifically `py_ecc.bls`): **Required** for BLS public key validation and transaction signature verification.

### Setup Steps

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
2.  **Set up Python Environment (Recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate 
    pip install py_ecc
    ```
3.  **Ensure `genesis.tau` is Present:**
    Place your `genesis.tau` file in the location specified by `config.TAU_PROGRAM_FILE` (defaults to the project root).

4.  **Ensure Tau Docker Image:**
    Make sure the Docker image specified in `config.TAU_DOCKER_IMAGE` (default: `tau`) is available.

5.  **Run the Server:**
    ```bash
    python server.py 
    ```
    The server will initialize the database and manage the Tau Docker process.

6.  **Optional: Configure Bootstrap Peers**
    Edit `config.py` to point at one or more peers to sync from:
    ```py
    BOOTSTRAP_PEERS = [
        {
            "peer_id": "<REMOTE_NODE_ID>",
            "addrs": ["/ip4/127.0.0.1/tcp/12345"]
        },
    ]
    ```
    On start, the node will connect, handshake, sync headers, request missing block bodies, and rebuild its state.

### Connecting to the Server

Use any TCP client, e.g., `netcat`:
```bash
netcat 127.0.0.1 65432
```

## Core Components

*   **`server.py`**: The main TCP server application.
*   **`tau_manager.py`**: Manages the Tau Docker process lifecycle and communication.
*   **`commands/`**: Modules for handling client commands:
    *   `sendtx.py`: Handles submission and validation of complex transactions (including signature checks, sequence numbers, and Tau logic for operations).
    *   `getmempool.py`: Retrieves mempool content.
    *   `createblock.py`: Creates new blocks from mempool transactions.
*   **`db.py`**: SQLite database interface, managing the mempool, string-to-ID mappings, and persistent block storage.
*   **`network/`**: P2P protocols and service implementation (`handshake`, `ping`, `sync`, `blocks`, `tx`).
*   **`chain_state.py`**: Manages in-memory state (account balances, sequence numbers).
*   **`sbf_defs.py`**: Symbolic Boolean Formula (SBF) constants for Tau communication.
*   **`utils.py`**: Utilities for SBF, data conversions, and transaction message canonicalization.
*   **`config.py`**: Centralized configuration.
*   **`block.py`**: Defines block data structures (block header, transactions list) and merkle root computation.
*   **`genesis.tau`**: The Tau logic program for validating operations, including structural checks on transaction data and logic for applying new rules via pointwise revision.
*   **`wallet.py`**: Command-line wallet interface for interacting with the Tau node (see `WALLET_USAGE.md` for comprehensive usage guide).
*   **`rules/`**: Directory containing Tau rule files:
    *   `01_handle_insufficient_funds.tau`: Logic for handling insufficient fund scenarios.
*   **`tests/`**: Directory containing unit tests:
    - `test_sendtx_basic.py`: Basic transaction functionality tests.
    - `test_sendtx_validation.py`: Transaction validation logic tests.
    - `test_sendtx_tx_meta.py`: Transaction metadata handling tests.
    - `test_sendtx_crypto.py`: Cryptographic signature verification tests.
    - `test_sendtx_sequential.py`: Sequential multi-operation transaction tests.
    - `test_tau_logic.py`: Tests all logic paths and validation rules directly within `genesis.tau`.
    - `test_chain_state.py`: Tests balance and sequence number management.
    - `test_block.py`: Tests the block data structure and the persistent block creation/chaining logic.
    - `test_persistent_chain_state.py`: Tests for persistent chain state management (currently skipped).
    - `test_state_reconstruction.py`: Tests for state reconstruction from blockchain data.
    - `test_p2p.py`: Connectivity and custom protocol round-trip using libp2p shim.
    - `test_network_protocols.py`: End-to-end tests for Tau protocols (handshake, ping, sync, blocks, state, tx, gossip). Coverage includes header sync, transaction gossip, subscription handling, DHT routing-table refresh, gossip health metrics, opportunistic peer seeding, and multi-hop gossip propagation driven solely by KadDHT lookups.

## Console Wallet

A comprehensive command-line wallet `wallet.py` is provided to interact with the Tau node. It supports generating a new keypair, sending complex multi-operation transactions (including rules, transfers, and custom operations), querying balances, and listing transaction history. For detailed usage instructions, see `WALLET_USAGE.md`.

### Prerequisites

Requires `py_ecc` for BLS operations (install with `pip install py_ecc`).

### Usage

```bash
# Generate a new keypair
python wallet.py new

# Query balance (by private key or address)
python wallet.py balance --privkey <hex_privkey>
python wallet.py balance --address <pubkey_hex>

# List transaction history
python wallet.py history --privkey <hex_privkey>
python wallet.py history --address <pubkey_hex>

# Send a simple transaction
python wallet.py send --privkey <hex_privkey> --to <recipient_pubkey_hex> --amount <amount> [--fee <fee_limit>] [--expiry <seconds>]

# Send a transaction with rules
python wallet.py send --privkey <hex_privkey> --rule "o2[t]=i1[t]" --transfer "recipient:amount"

# Send multi-operation transaction  
python wallet.py send --privkey <hex_privkey> --rule "rule_formula" --transfer "addr:amt" --operation "2:custom_data"
```

## Available Commands and Block Structure

### Available Commands

*   **Send Transaction (New Structure):**
    ```
    sendtx '{
      "sender_pubkey": "a63b...ea73", 
      "sequence_number": 0, 
      "expiration_time": 1700000000, 
      "operations": {
        "1": [["a63b...ea73", "000a...000a", "10"]]
      },
      "fee_limit": "0",
      "signature": "HEX_SIGNATURE_OVER_OTHER_FIELDS"
    }'
    ```
    *   Replace placeholders with actual values.
    *   The client is responsible for creating the canonical message, hashing it, signing the hash, and providing the hex-encoded signature.

*   **Get Mempool:**
    ```
    getmempool
    ```
*   **Create Block:**
    ```
    createblock
    ```

### Block Structure

A block is a fundamental data structure that organizes transactions into an atomic unit for chain progression. Each block consists of:

- A **block header** containing:
  - `block_number` (integer): Height of the block in the chain.
  - `previous_hash` (string): Hex-encoded SHA256 hash of the previous block's header.
  - `timestamp` (integer): Unix timestamp when the block was created.
  - `merkle_root` (string): Hex-encoded Merkle root of the included transactions.
- A **block body** containing:
  - `transactions` (list): Ordered list of transactions (each is the JSON object accepted by `sendtx`).

Blocks do **not** include proof-of-work or signatures at this alpha stage.

The `block.py` module provides the `Block` and `BlockHeader` classes, along with utility functions for computing transaction hashes (`compute_tx_hash`), Merkle roots (`compute_merkle_root`), and block hashes.

## Known Issues / Notes

*   The fee model (`fee_limit`) is a placeholder and not yet enforced.
*   Gossipsub topics (`tau/blocks/1.0.0`, `tau/transactions/1.0.0`) must be subscribed to by peers that expect block or transaction updates.

## Project Status

**Alpha:** This is an early alpha version. It's under active development and is intended for testing and experimentation. The core engine for a functional blockchain is in place, including transaction validation, mempool management, and persistent block creation.

## Future Work

*   Fork choice mechanism.
*   Expansion of Tau logic.
*   Full consensus mechanism implementation.
*   More robust error handling and reporting.
*   More comprehensive unit and integration tests.
