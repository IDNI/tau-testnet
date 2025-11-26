"""
createblock.py

Command handler for creating a new block from the current mempool.
"""

import json
import time
from typing import List, Dict
import db
import block
import chain_state
import config
from poa.state import compute_state_hash


def create_block_from_mempool() -> Dict:
    """
    Creates a new block from all transactions currently in the mempool,
    saves it to the database, and clears the mempool.
    """
    print(f"[INFO][createblock] Starting block creation process...")
    
    # Get all transactions from mempool
    mempool_txs = db.get_mempool_txs()
    print(f"[INFO][createblock] Found {len(mempool_txs)} entries in mempool")

    if not mempool_txs:
        print("[INFO][createblock] Mempool is empty. No block created.")
        return {"message": "Mempool is empty. No block created."}
    
    # Parse transactions (filter out invalid JSON)
    transactions = []
    skipped_count = 0
    for i, tx_data in enumerate(mempool_txs):
        if tx_data.startswith("json:"):
            try:
                tx = json.loads(tx_data[5:])  # Remove "json:" prefix
                transactions.append(tx)
                sender = tx.get("sender_pubkey", "unknown")[:10] + "..."
                ops_count = len(tx.get("operations", {}))
                print(f"[INFO][createblock] TX #{i+1}: From {sender}, {ops_count} operations")
            except json.JSONDecodeError as e:
                print(f"[WARN][createblock] Skipping invalid JSON transaction #{i+1}: {e}")
                skipped_count += 1
        else:
            print(f"[WARN][createblock] Skipping non-JSON transaction #{i+1}: {tx_data[:50]}...")
            skipped_count += 1
    
    if skipped_count > 0:
        print(f"[WARN][createblock] Skipped {skipped_count} invalid transactions")
    
    print(f"[INFO][createblock] Successfully parsed {len(transactions)} valid transactions")
    
    # Get latest block to determine new block number and previous hash
    latest_block = db.get_latest_block()
    if latest_block:
        block_number = latest_block['header']['block_number'] + 1
        previous_hash = latest_block['block_hash']
        print(f"[INFO][createblock] Latest block is #{latest_block['header']['block_number']}. New block will be #{block_number}.")
    else:
        # Genesis block
        block_number = 0
        previous_hash = "0" * 64
        print(f"[INFO][createblock] No existing blocks. Creating Genesis Block #{block_number}.")
    
    print(f"[INFO][createblock] Creating block #{block_number} with previous hash: {previous_hash[:16]}...")
    
    # Create the block
    print(f"[INFO][createblock] Computing transaction hashes and Merkle root...")
    rules_blob = chain_state.get_rules_state().encode("utf-8")
    state_hash = compute_state_hash(rules_blob)
    state_locator = f"{config.STATE_LOCATOR_NAMESPACE}:{state_hash}"
    new_block = block.Block.create(
        block_number=block_number,
        previous_hash=previous_hash,
        transactions=transactions,
        state_hash=state_hash,
        state_locator=state_locator,
        signing_key_hex=config.MINER_PRIVKEY,
    )
    
    print(f"[INFO][createblock] Block created successfully!")
    print(f"[INFO][createblock] Block Details:")
    print(f"[INFO][createblock]   - Block Number: {new_block.header.block_number}")
    print(f"[INFO][createblock]   - Timestamp: {new_block.header.timestamp}")
    print(f"[INFO][createblock]   - Transaction Count: {len(transactions)}")
    print(f"[INFO][createblock]   - Merkle Root: {new_block.header.merkle_root}")
    print(f"[INFO][createblock]   - State Hash: {new_block.header.state_hash}")
    print(f"[INFO][createblock]   - Block Hash: {new_block.block_hash}")
    
    # Show transaction summary
    if transactions:
        print(f"[INFO][createblock] Transaction Summary:")
        for i, tx in enumerate(transactions):
            sender = tx.get("sender_pubkey", "unknown")[:10] + "..."
            seq = tx.get("sequence_number", "?")
            ops = tx.get("operations", {})
            transfers = ops.get("1", [])
            transfer_count = len(transfers) if isinstance(transfers, list) else 0
            rule = "Yes" if ops.get("0") else "No"
            print(f"[INFO][createblock]   TX #{i+1}: {sender} (seq:{seq}) - {transfer_count} transfers, rule:{rule}")
    
    # Atomically save the new block, commit state, and clear mempool
    print(f"[INFO][createblock] Committing block #{new_block.header.block_number}, state, and clearing mempool in a single transaction...")
    import chain_state as _cs, db as _db
    # Inline block insertion and state commit to ensure atomicity
    with _db._db_lock, _db._db_conn:
        conn = _db._db_conn
        # Insert block
        block_dict = new_block.to_dict()
        block_data_json = json.dumps(block_dict)
        conn.execute(
            'INSERT INTO blocks (block_number, block_hash, previous_hash, timestamp, block_data) VALUES (?, ?, ?, ?, ?)',
            (
                new_block.header.block_number,
                new_block.block_hash,
                new_block.header.previous_hash,
                new_block.header.timestamp,
                block_data_json,
            )
        )
        # Commit in-memory state to database
        conn.execute(
            'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
            ('current_rules', _cs.get_rules_state())
        )
        conn.execute(
            'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
            ('last_processed_block_hash', new_block.block_hash)
        )
        for addr, bal in _cs._balances.items():
            seq = _cs._sequence_numbers.get(addr, 0)
            conn.execute(
                'INSERT OR REPLACE INTO accounts (address, balance, sequence_number) VALUES (?, ?, ?)',
                (addr, bal, seq)
            )
        # Clear mempool
        conn.execute('DELETE FROM mempool')
    print(f"[INFO][createblock] Block, state committed; mempool cleared.")
    
    print(f"[INFO][createblock] Block creation process completed!")
    
    return new_block.to_dict()


def encode_command(parts: List[str]) -> str:
    """
    Encode the createblock command. No parameters needed.
    """
    if len(parts) != 1:
        raise ValueError("createblock command takes no parameters")
    return "createblock"


def decode_output(tau_output: str, tau_input: str) -> str:
    """
    Decode output - not applicable for createblock as it doesn't use Tau.
    """
    return block_data


def execute(raw_command: str, container):
    """
    Executes the createblock command.
    """
    logger.info("Create block requested")
    try:
        block_data = create_block_from_mempool()
        if not block_data or "block_hash" not in block_data:
            message = block_data.get("message") if isinstance(block_data, dict) else None
            resp = (message or "Mempool is empty. No block created.") + "\r\n"
            logger.info("Create block skipped: %s", message or "empty mempool")
        else:
            tx_count = len(block_data.get("transactions", []))
            block_hash = block_data["block_hash"]
            block_number = block_data["header"]["block_number"]
            merkle_root = block_data["header"]["merkle_root"]
            timestamp = block_data["header"]["timestamp"]

            resp_lines = [
                f"SUCCESS: Block #{block_number} created successfully!",
                f"  - Transactions: {tx_count}",
                f"  - Block Hash: {block_hash}",
                f"  - Merkle Root: {merkle_root}",
                f"  - Timestamp: {timestamp}",
            ]
            for idx, tx in enumerate(block_data.get("transactions", []), start=1):
                tx_json = json.dumps(tx, sort_keys=True)
                resp_lines.append(f"  - TX#{idx}: {tx_json}")
            resp_lines.append("  - Mempool cleared\r\n")
            resp = "\n".join(resp_lines)
            logger.info("Block #%s created", block_number)
    except Exception:
        logger.exception("Block creation failed")
        resp = "ERROR: Failed to create block\r\n"
    return resp


def handle_result(decoded: str, tau_input: str, mempool_state: Dict) -> str:
    """
    Handle the result of block creation.
    """
    try:
        block_data = create_block_from_mempool()
        if not block_data or "block_hash" not in block_data:
            message = block_data.get("message") if isinstance(block_data, dict) else "Mempool is empty. No block created."
            return message

        # Return a detailed summary of the created block
        tx_count = len(block_data["transactions"])
        block_hash = block_data["block_hash"]
        block_number = block_data["header"]["block_number"]
        merkle_root = block_data["header"]["merkle_root"]
        state_hash = block_data["header"].get("state_hash")
        timestamp = block_data["header"]["timestamp"]

        result = f"SUCCESS: Block #{block_number} created successfully!\n"
        result += f"  - Transactions: {tx_count}\n"
        result += f"  - Block Hash: {block_hash}\n"
        result += f"  - Merkle Root: {merkle_root}\n"
        result += f"  - Timestamp: {timestamp}\n"
        if state_hash:
            result += f"  - State Hash: {state_hash}\n"
        result += f"  - Mempool cleared"

        return result

    except Exception as e:
        print(f"[ERROR][createblock] Block creation failed: {e}")
        return f"ERROR: Failed to create block: {e}" 
