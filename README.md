![The TauNet logo](/docs/images/TauNet_banner.png)

# Tau Testnet Alpha Blockchain

This project is the codebase for the Tau Testnet Alpha Blockchain. Its primary goal is to provide a live, working demonstration of a blockchain where core state transitions and rules are governed by Tau's formal logic.
The architecture is designed around the principle of extralogical processing. The core engine, written in Python, handles networking, storage, and any operations not yet implemented in pure Tau logic, such as cryptographic signature verification. This engine prepares transactions and validates them against a separate Tau logic program (executed via Docker), which serves as the ultimate arbiter of the chain's rules. This hybrid model allows us to build a robust and feature-complete testnet today, showcasing the power of Tau's logical core while providing all the necessary functions for a working blockchain.

## Features

*   **TCP Server**: Handles client connections and commands.
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
*   **Tau Integration for Operation Validation**: The `tool_code.tau` program validates the logic of operations within a transaction (e.g., coin transfers via SBF). This now includes robust structural validation to ensure transfer data is complete and well-formed.
*   **String-to-ID Mapping**: Dynamically assigns `y<ID>` identifiers for Tau SBF.
*   **In-Memory Balances & Sequence Numbers**: Tracks account balances and sequence numbers for rapid validation.
*   **SQLite Mempool**: Persists transactions awaiting inclusion in a block.
*   **BLS12-381 Public Key Validation**: Format and optional cryptographic checks for public keys.

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
3.  **Ensure `tool_code.tau` is Present:**
    Place your `tool_code.tau` file in the location specified by `config.TAU_PROGRAM_FILE` (defaults to the project root).

4.  **Ensure Tau Docker Image:**
    Make sure the Docker image specified in `config.TAU_DOCKER_IMAGE` (default: `tau`) is available.

5.  **Run the Server:**
    ```bash
    python server.py 
    ```
    The server will initialize the database and manage the Tau Docker process.

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
*   **`chain_state.py`**: Manages in-memory state (account balances, sequence numbers).
*   **`sbf_defs.py`**: Symbolic Boolean Formula (SBF) constants for Tau communication.
*   **`utils.py`**: Utilities for SBF, data conversions, and transaction message canonicalization.
*   **`config.py`**: Centralized configuration.
*   **`block.py`**: Defines block data structures (block header, transactions list) and merkle root computation.
*   **`tool_code.tau`**: The Tau logic program for validating operations, including structural checks on transaction data and logic for applying new rules via pointwise revision.
*   **`wallet.py`**: Command-line wallet interface for interacting with the Tau node (see `WALLET_USAGE.md` for comprehensive usage guide).
*   **`rules/`**: Directory containing Tau rule files:
    *   `01_handle_insufficient_funds.tau`: Logic for handling insufficient fund scenarios.
*   **`tests/`**: Directory containing unit tests:
    - `test_sendtx_basic.py`: Basic transaction functionality tests.
    - `test_sendtx_validation.py`: Transaction validation logic tests.
    - `test_sendtx_tx_meta.py`: Transaction metadata handling tests.
    - `test_sendtx_crypto.py`: Cryptographic signature verification tests.
    - `test_sendtx_sequential.py`: Sequential multi-operation transaction tests.
    - `test_tau_logic.py`: Tests all logic paths and validation rules directly within `tool_code.tau`.
    - `test_chain_state.py`: Tests balance and sequence number management.
    - `test_block.py`: Tests the block data structure and the persistent block creation/chaining logic.
    - `test_persistent_chain_state.py`: Tests for persistent chain state management (currently skipped).
    - `test_state_reconstruction.py`: Tests for state reconstruction from blockchain data.

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
*   The chain state (balances, sequence numbers) is updated in memory *before* a transaction is included in a block. A server crash between transaction validation and block creation could lead to a state inconsistency.

## Project Status

**Alpha:** This is an early alpha version. It's under active development and is intended for testing and experimentation. The core engine for a functional blockchain is in place, including transaction validation, mempool management, and persistent block creation.

## Future Work

*   Implement a fee model.
*   Reconcile in-memory chain state with the persistent block data to enhance fault tolerance.
*   More robust error handling and reporting.
*   Expansion of Tau-validated logic and commands.
*   Implementation of a simple P2P networking layer for node synchronization.
*   More comprehensive unit and integration tests.
