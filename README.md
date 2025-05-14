# Tau Testnet Alpha Blockchain

This project is the codebase for the Tau Testnet Alpha Blockchain. It implements a server that interacts with a Tau logic program (executed via Docker) to manage a simple blockchain with a focus on transaction processing and mempool management.

## Core Components

*   **`server.py`**: The main TCP server application. It handles client connections, parses commands, and dispatches them to appropriate handlers.
*   **`tau_manager.py`**: Manages the lifecycle of the Tau Docker process, including starting, stopping, monitoring, and facilitating communication (sending SBF input, receiving SBF output).
*   **`commands/`**: Directory containing modules for handling specific client commands:
    *   `sendtx.py`: Handles transaction submission. It parses JSON-formatted transactions, validates individual transfers against Tau logic, updates balances, and adds valid transactions to the mempool.
    *   `getmempool.py`: Handles requests to retrieve the current content of the mempool. It currently interacts with Tau but primarily fetches from the DB.
    *   `gettimestamp.py`: Intended for Tau-based timestamp (currently `getcurrenttimestamp` is handled directly by `server.py`).
*   **`db.py`**: Provides an interface for SQLite database interactions. It manages:
    *   `tau_strings` table: Maps arbitrary text strings (like public keys) to unique `y<ID>` identifiers for use with Tau.
    *   `mempool` table: Stores transactions waiting to be processed.
*   **`chain_state.py`**: Manages the in-memory state of account balances. Includes a genesis account and functions to update balances upon successful transfers.
*   **`sbf_defs.py`**: Contains definitions for Symbolic Boolean Formula (SBF) constants used in communication with the Tau program (e.g., failure codes, success acknowledgments).
*   **`utils.py`**: A collection of utility functions, primarily for converting between bit strings, SBF atom strings, and decimal values.
*   **`config.py`**: Centralized configuration for server settings (host, port), Tau program details (file path, Docker image), timeouts, and database paths.
*   **`test_sendtx.py`**: Unit tests for the `sendtx` command functionality, including mocking Tau interactions.
*   **`tool_code.tau`**: The initial Tau logic file

## Features

*   **TCP Server**: Listens for client connections and handles commands concurrently.
*   **Tau Integration**: Interacts with a `tool_code.tau` program (run in Docker) for validating business logic, particularly for `sendtx` operations.
*   **Command Handling**:
    *   `sendtx '{ "1": [["<from_pubkey_hex>", "<to_pubkey_hex>", "<amount_str>"], ...] }'`: Submits a transaction.
        *   Each transfer within the transaction is individually validated with Tau.
        *   `<pubkey_hex>` must be a 96-character hexadecimal BLS12-381 public key.
        *   `<amount_str>` is a decimal string representing the amount (0-255 for Tau validation).
    *   `getmempool`: Retrieves all transactions currently in the mempool.
    *   `getcurrenttimestamp`: Returns the server's current UTC timestamp (handled directly by the server, not via Tau currently).
*   **String-to-ID Mapping**: Dynamically assigns unique `y<ID>` identifiers to strings (e.g., public keys) for compact representation in Tau SBF.
*   **In-Memory Balances**: Tracks account balances for a native coin (AGRS), with an initial Genesis balance.
*   **SQLite Mempool**: Persists the mempool in an SQLite database.
*   **BLS12-381 Public Key Validation**:
    *   Performs format checks (96-char hex).
    *   Optionally performs cryptographic validation if the `py_ecc.bls` library is installed.
*   **Unit Testing**: Includes tests for `sendtx` command.

## Prerequisites

*   Python 3.8+
*   Docker
*   A Tau Docker image (default: `tau`, configurable in `config.py`). This image should be capable of running `.tau` files.
*   `py_ecc` (specifically `py_ecc.bls`): for full BLS public key cryptographic validation.

## Setup and Running

1.  **Clone the Repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
2.  **Ensure `tool_code.tau` is Present:**
    Place your `tool_code.tau` file in the location specified by `config.TAU_PROGRAM_FILE` (defaults to the project root) or update the path in `config.py`.

3.  **Ensure Tau Docker Image:**
    Make sure the Docker image specified in `config.TAU_DOCKER_IMAGE` (default: `tau`) is available locally (e.g., `docker pull tau` or `docker build -t tau .` if you have a Dockerfile for it).

4.  **Install Dependencies:**
    ```bash
    pip install py_ecc
    ```

5.  **Run the Server:**
    ```bash
    python server.py
    ```
    The server will start, initialize the database (default: `strings.db` or `test_tau_string_db.sqlite` for tests, path configurable via `TAU_DB_PATH` environment variable), and attempt to start and manage the Tau Docker process.

## Connecting to the Server

You can connect to the server using any TCP client, such as `netcat` or `telnet`:

```bash
netcat 127.0.0.1 65432
```

Once connected, you can issue commands as described in the "Features" section.

## Available Commands

*   **Send Transaction:**
    ```
    sendtx '{"1": [["a63b...ea73", "000a...000a", "10"], ["a63b...ea73", "000b...000b", "20"]]}'
    ```
    (Replace pubkeys with actual 96-char hex keys and amounts with 0-255 values.)

*   **Get Mempool:**
    ```
    getmempool
    ```

## Testing

Unit tests are provided (e.g., `test_sendtx.py`). To run tests:

```bash
python -m unittest discover
# or specifically
# python test_sendtx.py
```
The tests will use a separate database file (`test_tau_string_db.sqlite`) which is cleaned up before each test run.

## Known Issues / Notes

## Project Status

**Alpha:** This is an early alpha version. It's under active development and is intended for testing and experimentation. Expect changes and potential bugs.

## Future Work

*   Persistent chain state (blocks, not just balances).
*   More robust error handling and reporting.
*   Expansion of Tau-validated logic and commands.
*   Implementation of a simple P2P networking layer.
*   More comprehensive unit and integration tests.
*   Block creation and processing from mempool.
