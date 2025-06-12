![The TauNet logo](/docs/images/TauNet_banner.png)

# Tau Testnet Alpha Blockchain

This project is the codebase for the Tau Testnet Alpha Blockchain. It implements a server that interacts with a Tau logic program (executed via Docker) to manage a simple blockchain with a focus on transaction processing and mempool management.

## Core Components

*   **`server.py`**: The main TCP server application.
*   **`tau_manager.py`**: Manages the Tau Docker process lifecycle and communication.
*   **`commands/`**: Modules for handling client commands:
    *   `sendtx.py`: Handles submission and validation of complex transactions (including signature checks, sequence numbers, and Tau logic for operations).
    *   `getmempool.py`: Retrieves mempool content.
    *   `gettimestamp.py`: Handles timestamp requests.
*   **`db.py`**: SQLite database interface (string-to-ID mapping, mempool).
*   **`chain_state.py`**: Manages in-memory state (account balances, sequence numbers).
*   **`sbf_defs.py`**: Symbolic Boolean Formula (SBF) constants for Tau communication.
*   **`utils.py`**: Utilities for SBF, data conversions, and transaction message canonicalization.
*   **`config.py`**: Centralized configuration.
*   **`tool_code.tau`**: The Tau logic program for validating operations.
*   **`tests/`**: Directory containing unit tests:
    - `test_sendtx_basic.py`
    - `test_sendtx_validation.py`
    - `test_sendtx_tx_meta.py`
    - `test_sendtx_crypto.py`
    - `test_tau_logic.py`: Tests direct SBF interaction with `tool_code.tau`.
    - `test_chain_state.py`: Tests balance and sequence number management.

## Features

*   **TCP Server**: Handles client connections and commands.
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
*   **Tau Integration for Operation Validation**: The `tool_code.tau` program validates the logic of operations within a transaction (e.g., coin transfers via SBF).
*   **String-to-ID Mapping**: Dynamically assigns `y<ID>` identifiers for Tau SBF.
*   **In-Memory Balances & Sequence Numbers**: Tracks account balances and sequence numbers.
*   **SQLite Mempool**: Persists transactions awaiting processing.
*   **BLS12-381 Public Key Validation**: Format and optional cryptographic checks for public keys.

## Prerequisites

*   Python 3.8+
*   Docker
*   A Tau Docker image (default: `tau`, configurable in `config.py`).
*   `py_ecc` (specifically `py_ecc.bls`): **Required** for BLS public key validation and transaction signature verification.

## Setup and Running

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

## Connecting to the Server

Use any TCP client, e.g., `netcat`:
```bash
netcat 127.0.0.1 65432
```

## Console Wallet

A simple command-line wallet `wallet.py` is provided to interact with the Tau node. It supports generating a new keypair, sending signed transactions, querying balances, and listing transaction history.

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

# Send a transaction
python wallet.py send --privkey <hex_privkey> --to <recipient_pubkey_hex> --amount <amount> [--fee <fee_limit>] [--expiry <seconds>]
```

## Available Commands

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
*   **GetCurrentTimestamp:**
    ```
    getcurrenttimestamp
    ```

## Testing

Unit tests are located in the `tests/` directory. To run all tests:
```bash
python -m unittest discover tests
```
Or run a specific test file:
```
*   To run sendtx tests: `python -m unittest tests/test_sendtx_basic.py tests/test_sendtx_validation.py tests/test_sendtx_tx_meta.py tests/test_sendtx_crypto.py`
```
Tests for `sendtx` now cover the new transaction structure, including cryptographic signature generation (within the test environment) and verification.

## Known Issues / Notes
*   The fee model (`fee_limit`) is a placeholder and not yet enforced.

## Project Status

**Alpha:** This is an early alpha version. It's under active development and is intended for testing and experimentation. Expect changes and potential bugs.

## Future Work

*   Implement a fee model.
*   Persistent chain state (blocks, not just balances and sequence numbers).
*   More robust error handling and reporting.
*   Expansion of Tau-validated logic and commands.
*   Implementation of a simple P2P networking layer.
*   More comprehensive unit and integration tests.
*   Block creation and processing from mempool.
