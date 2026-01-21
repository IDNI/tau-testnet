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


import tau_manager
from tau_manager import parse_tau_output
import logging

logger = logging.getLogger(__name__)

# Try import optional crypto dependencies
try:
    from py_ecc.bls import G2Basic
    _BLS_AVAILABLE = True
except ImportError:
    _BLS_AVAILABLE = False


def _validate_signature(payload: Dict) -> bool:
    """
    Validates the BLS signature of the transaction.
    """
    # Strict BLS: if library missing, cannot validate -> fail.
    # We expect _BLS_AVAILABLE to be checked by caller too, but good to be safe.
    if not _BLS_AVAILABLE:
        return False 
        
    sender_pubkey = payload.get('sender_pubkey')
    signature = payload.get('signature')
    
    if not sender_pubkey or not signature:
        return False
        
    try:
        # Reconstruct signing message
        signing_dict = {
            "sender_pubkey": sender_pubkey,
            "sequence_number": payload.get('sequence_number'),
            "expiration_time": payload.get('expiration_time'),
            "operations": payload.get('operations'),
            "fee_limit": payload.get('fee_limit'),
        }
        msg_bytes = json.dumps(signing_dict, sort_keys=True, separators=(",", ":")).encode()
        msg_hash = import_hashlib().sha256(msg_bytes).digest()
        
        pubkey_bytes = bytes.fromhex(sender_pubkey)
        sig_bytes = bytes.fromhex(signature)
        
        return G2Basic.Verify(pubkey_bytes, msg_hash, sig_bytes)
    except Exception:
        return False

def import_hashlib():
    import hashlib
    return hashlib

def execute_batch(transactions: List[Dict], tx_ids: List[int]):
    """
    Executes a batch of transactions against a SNAPSHOT of the chain state.
    Returns (final_txs, final_reserved_ids, final_rules, final_balances, final_sequences)
    """
    # 1. Capture Consistent State Snapshot
    with chain_state.get_all_state_locks():
        temp_balances = chain_state._balances.copy()
        temp_sequences = chain_state._sequence_numbers.copy()
        temp_rules = chain_state._current_rules_state
        
    final_txs = []
    final_reserved_ids = []
    
    # Ensure Tau is ready
    if not tau_manager.tau_ready.is_set():
        tau_manager.tau_ready.wait(timeout=5)
        
    # Tau Baseline Reset
    # Ensure local Tau process state matches our snapshot before we begin.
    # Even if temp_rules is empty, we must reset Tau to "clean".
    try:
        if logger.isEnabledFor(logging.DEBUG):
            try:
                logger.debug(
                    "Mining with Tau state len=%s hash=%s preview=%r",
                    len(temp_rules or ""),
                    import_hashlib().sha256((temp_rules or "").encode("utf-8")).hexdigest(),
                    (temp_rules or "")[:200],
                )
            except Exception:
                logger.debug("Mining with Tau state (debug logging failed)")
        tau_manager.reset_tau_state(temp_rules or "", source="createblock-reset")
    except Exception as e:
        logger.error("Failed to reset Tau baseline: %s", e)
        # Fail batch so we can unreserve
        raise RuntimeError(f"Failed to reset Tau baseline: {e}")

    for i, tx in enumerate(transactions):
        tx_id_db = tx_ids[i]
        sender = tx.get('sender_pubkey')
        seq = tx.get('sequence_number')
        
        # --- 1. Validation ---
        
        # A. Signature
        if not _BLS_AVAILABLE:
            print(f"[ERROR][miner] BLS library missing. Cannot validate signature.")
            continue

        if not _validate_signature(tx):
            print(f"[WARN][miner] TX {i} rejected: Invalid signature")
            continue
            
        # B. Expiry
        if tx.get('expiration_time') and int(tx.get('expiration_time', 0)) < int(time.time()):
            print(f"[WARN][miner] TX {i} rejected: Expired")
            continue
            
        # C. Sequence Number
        expected_seq = temp_sequences.get(sender, 0)
        if seq != expected_seq:
            print(f"[WARN][miner] TX {i} rejected: Sequence mismatch (got {seq}, expected {expected_seq})")
            continue
            
        # --- 2. Execution & Rollback Prep ---
        checkpoint_rules = temp_rules
        # We don't rollback balances/sequences explicitly; we just don't apply changes to `temp_*` until success.
        
        tx_success = True
        
        ops = tx.get('operations', {})
        rule_op = ops.get("0")
        transfer_op = ops.get("1")
        
        # D. Rule Injection
        if rule_op:
            try:
                res = tau_manager.communicate_with_tau(rule_text=rule_op, target_output_stream_index=0)
                if "error" in res.lower():
                    print(f"[WARN][miner] TX {i} rejected: Tau rule error: {res}")
                    tx_success = False
                else:
                    # Tentatively accepted
                    try:
                        # Capture the updated specification emitted by Tau.
                        temp_rules = chain_state.get_rules_state()
                    except Exception:
                        # If we can't read it, keep the prior snapshot.
                        pass
            except Exception as e:
                print(f"[WARN][miner] TX {i} rejected: Tau rule exception: {e}")
                tx_success = False

        # Intra-Transaction Balance Tracking & Tau Validation
        pending_balance_deductions = {} # local tracking for this tx
        
        if tx_success and transfer_op:
            # E. Transfers
            pending_transfers_list = [] # Store validated transfers for commit: (f_addr, t_addr, amt)
            
            for t_entry in transfer_op:
                # Safe Validation (Structure)
                if not isinstance(t_entry, list) or len(t_entry) < 3:
                    print(f"[WARN][miner] TX {i} rejected: Invalid transfer entry format")
                    tx_success = False; break
                    
                try:
                    f_addr, t_addr, amt_str = t_entry[:3] # take first 3 if more
                except ValueError:
                    tx_success = False; break
                
                # Enforce Anti-Theft
                if f_addr != sender:
                    print(f"[WARN][miner] TX {i} rejected: Theft attempt (From {f_addr} != Sender {sender})")
                    tx_success = False; break

                try:
                    amt = int(amt_str)
                    if amt <= 0: raise ValueError
                except:
                    logger.warning("TX %s rejected: Invalid amount %s", i, amt_str)
                    tx_success = False; break
            
                # Faucet Logic Check (Pre-calculation)
                if f_addr not in temp_balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
                     current_bal = 100000
                else:
                     current_bal = temp_balances.get(f_addr, 0)
                
                deducted = pending_balance_deductions.get(f_addr, 0)
                remaining = current_bal - deducted
                
                if remaining < amt:
                     logger.warning("TX %s rejected: Insufficient funds (Intra-TX overspend)", i)
                     tx_success = False; break
                
                # Tau Validation (Transfer)
                try:
                     # Fix ID Conversion (expect int, strip 'y')
                     sender_id_str = db.get_string_id(f_addr)
                     receiver_id_str = db.get_string_id(t_addr)
                     
                     # Strict Tau ID (No 0 fallback)
                     if not sender_id_str:
                        logger.warning("TX %s rejected: Sender Tau ID missing", i)
                        tx_success = False; break
                        
                     try: 
                        s_id = int(sender_id_str[1:])
                     except: 
                        logger.warning("TX %s rejected: Invalid sender Tau ID '%s'", i, sender_id_str)
                        tx_success = False; break
                        
                     if not receiver_id_str:
                        logger.warning("TX %s rejected: Receiver Tau ID missing", i)
                        tx_success = False; break

                     try: 
                        r_id = int(receiver_id_str[1:])
                     except: 
                        logger.warning("TX %s rejected: Invalid receiver Tau ID '%s'", i, receiver_id_str)
                        tx_success = False; break
                     
                     tau_input_stream_values = {
                        1: str(amt),
                        2: str(remaining), 
                        3: str(s_id),
                        4: str(r_id),
                     }
                     # Communicate with Tau stream 1 (validator)
                     tau_output_transfer = tau_manager.communicate_with_tau(
                        target_output_stream_index=1,
                        input_stream_values=tau_input_stream_values,
                        apply_rules_update=False,
                     )
                     
                     # Output Parsing (Unified)
                     converted_val = parse_tau_output(tau_output_transfer)
                         
                     # Validation: output must equal amount
                     if converted_val != amt:
                         logger.warning("TX %s rejected: Tau validation failed. Expected %s, got %s (parsed: %s)", i, amt, tau_output_transfer, converted_val)
                         tx_success = False; break
                     
                except Exception as e:
                     logger.warning("TX %s rejected: Tau validation error: %s", i, e)
                     tx_success = False; break

                # Track deduction
                pending_balance_deductions[f_addr] = deducted + amt
                
                # Validated! Add to pending list for commit
                pending_transfers_list.append((f_addr, t_addr, amt))

        if tx_success:
            # Apply changes to temp state (Commit)

            if transfer_op:
                for f_addr, t_addr, amt in pending_transfers_list:
                    # Safe Commit (Apply validated transfers)
                    
                    # Faucet Logic Safety (Commit)
                    if f_addr not in temp_balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
                        temp_balances[f_addr] = 100000
                    
                    # Deduct from temp_balances
                    temp_balances[f_addr] = temp_balances.get(f_addr, 0) - amt
                    # Credit to temp_balances
                    temp_balances[t_addr] = temp_balances.get(t_addr, 0) + amt
            
            # Increment sequence
            temp_sequences[sender] = expected_seq + 1
            
            final_txs.append(tx)
            final_reserved_ids.append(tx_id_db)
            print(f"[INFO][miner] TX {i} accepted.")
            
        else:
            # ROLLBACK
            # 1. Restore Tau State (if rule was applied)
            if rule_op:
                try:
                    tau_manager.communicate_with_tau(rule_text=checkpoint_rules, target_output_stream_index=0)
                    print(f"[INFO][miner] Rolled back Tau state for TX {i}")
                except Exception as e:
                    print(f"[CRITICAL][miner] Failed to rollback Tau state: {e}. State may be corrupt.")
            
            # temp_rules is reset
            temp_rules = checkpoint_rules
            # temp_balances/sequences not touched
            
    return final_txs, final_reserved_ids, temp_rules, temp_balances, temp_sequences


def create_block_from_mempool() -> Dict:
    """
    Creates a new block from all transactions currently in the mempool,
    saves it to the database, and clears the mempool.
    """
    print(f"[INFO][createblock] Starting block creation process...")

    if not config.MINER_PRIVKEY:
        print("[ERROR][createblock] PoA mining requires MINER_PRIVKEY to be configured.")
        return {"error": "PoA mining requires a configured miner key."}

    if not block.bls_signing_available():
        print("[ERROR][createblock] BLS signing not available; cannot sign PoA block.")
        return {"error": "BLS signing is required for PoA blocks."}
    
    # Get batch of reserved transactions from mempool
    reserved_txs = db.reserve_mempool_txs(limit=1000)
    print(f"[INFO][createblock] Reserved {len(reserved_txs)} entries from mempool")

    if not reserved_txs:
        # Check if there were any pending at all (for logging purposes)
        # But we are done if no reserved txs
        print("[INFO][createblock] Mempool is empty (no pending txs). No block created.")
        return {"message": "Mempool is empty. No block created."}
    
    # Extract data
    mempool_txs = [rtx['payload'] for rtx in reserved_txs]
    reserved_ids = [rtx['id'] for rtx in reserved_txs]
    
    # Fix JSON alignment
    # We must filter reserved_ids and transactions in lockstep
    transactions = []
    filtered_reserved_ids = []
    skipped_count = 0
    
    for i, tx_data in enumerate(mempool_txs):
        r_id = reserved_ids[i]
        try:
            clean_data = tx_data
            if clean_data.startswith("json:"):
                clean_data = clean_data[5:]
            
            tx = json.loads(clean_data)
            transactions.append(tx)
            filtered_reserved_ids.append(r_id)
        except json.JSONDecodeError as e:
            print(f"[WARN][createblock] Skipping invalid JSON transaction #{i+1}: {e}")
            skipped_count += 1
            # We do NOT add to filtered lists, so align remains correct
            # But we might want to delete this invalid row? 
            # For now, just skip inclusion. It will be deleted if we delete all reserved_ids?
            # Yes, `reserved_ids` (original list) is used for cleanup.
            
    if skipped_count > 0:
        print(f"[WARN][createblock] Skipped {skipped_count} invalid transactions")
    
    if not transactions:
        print("[INFO][createblock] No valid transactions parsed. Cleared reserved.")
        if reserved_ids:
             import db as _db
             _db.remove_transactions(reserved_ids)
        return {"message": "No valid transactions parsed."}
    
    print(f"[INFO][createblock] Validating and Executing Batch...")
    # Use filtered IDs so index matches
    try:
        final_txs, final_reserved_ids, final_rules, final_balances, final_sequences = execute_batch(transactions, filtered_reserved_ids)
    except Exception as e:
        print(f"[ERROR][createblock] Block creation failed during batch execution: {e}")
        # Liveness Fix - Unreserve so they can be retried immediately
        import db as _db
        _db.unreserve_mempool_txs(reserved_ids)
        return {"error": str(e)}
    
    print(f"[INFO][createblock] Execution Result: {len(final_txs)}/{len(transactions)} accepted")
    
    if not final_txs:
        print("[INFO][createblock] All transactions rejected. No block created.")
        # We should still delete the rejected txs!
        if reserved_ids:
            import db as _db
            _db.remove_transactions(reserved_ids)
        return {"message": "All transactions rejected. Mempool cleared."}

    # Use final_txs for the block
    transactions = final_txs
    
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
    # Use FINAL RULES from execution, not global state
    rules_blob = final_rules.encode("utf-8")
    
    # Consensus State Commitment (Rules + Accounts)
    accounts_hash = chain_state.compute_accounts_hash(final_balances, final_sequences)
    state_hash = chain_state.compute_consensus_state_hash(rules_blob, accounts_hash)
    
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
            ('current_rules', final_rules)
        )
        conn.execute(
            'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
            ('last_processed_block_hash', new_block.block_hash)
        )
        for addr, bal in final_balances.items():
            seq = final_sequences.get(addr, 0)
            conn.execute(
                'INSERT OR REPLACE INTO accounts (address, balance, sequence_number) VALUES (?, ?, ?)',
                (addr, bal, seq)
            )
        # Clear ONLY the reserved transactions from mempool (safe cleanup)
        # We delete ALL reserved IDs (both accepted and rejected)
        if reserved_ids:
            placeholders = ','.join(['?'] * len(reserved_ids))
            conn.execute(f'DELETE FROM mempool WHERE id IN ({placeholders})', tuple(reserved_ids))
        
    # In-Memory Swap Correctness
    # We acquire ALL locks to ensure no readers see partial state during update
    print(f"[INFO][createblock] Block committed. Updating in-memory state...")
    try:
        with chain_state.get_all_state_locks():
            chain_state._balances.clear()
            chain_state._balances.update(final_balances)
            
            chain_state._sequence_numbers.clear()
            chain_state._sequence_numbers.update(final_sequences)
            
            chain_state._current_rules_state = final_rules
            chain_state._tau_engine_state_hash = state_hash
            chain_state._last_processed_block_hash = new_block.block_hash
    except Exception as e:
        print(f"[CRITICAL][createblock] Failed to update in-memory state after DB commit: {e}. Node restart recommended.")
            
    print(f"[INFO][createblock] Block, state committed; {len(reserved_ids)} mempool txs cleared.")

    # Publish the Tau/rules snapshot tied to this block so peers can fetch it by
    # (state_hash/state_locator) and apply it to their Tau engine.
    try:
        published = False
        if hasattr(chain_state, "publish_tau_state_snapshot"):
            # Compute accounts hash for consensus integrity
            accounts_hash = chain_state.compute_accounts_hash(final_balances, final_sequences)
            if logger.isEnabledFor(logging.DEBUG):
                try:
                    rules_text = rules_blob.decode("utf-8")
                    logger.debug(
                        "Publishing Tau state snapshot: state_hash=%s accounts_hash=%s rules_len=%s rules_hash=%s preview=%r",
                        state_hash,
                        accounts_hash.hex(),
                        len(rules_text),
                        import_hashlib().sha256(rules_text.encode("utf-8")).hexdigest(),
                        rules_text[:200],
                    )
                except Exception:
                    logger.debug("Publishing Tau state snapshot (debug logging failed)")
            published = bool(chain_state.publish_tau_state_snapshot(state_hash, rules_blob, accounts_hash))
        if published:
            print(f"[INFO][createblock] Published Tau state snapshot to DHT: {state_locator}")
        else:
            print(f"[DEBUG][createblock] Tau state snapshot not published to DHT (no DHT client?)")
    except Exception as e:
        print(f"[WARN][createblock] Failed to publish Tau state snapshot to DHT: {e}")

    # Publish the resulting accounts table so secondary nodes can update balances
    # without re-executing transactions.
    try:
        published_accounts = False
        if hasattr(chain_state, "publish_accounts_snapshot"):
            published_accounts = bool(chain_state.publish_accounts_snapshot(new_block.block_hash))
        if published_accounts:
            print(f"[INFO][createblock] Published accounts snapshot to DHT: {config.STATE_LOCATOR_NAMESPACE}:{new_block.block_hash}")
        else:
            print(f"[DEBUG][createblock] Accounts snapshot not published to DHT (no DHT client?)")
    except Exception as e:
        print(f"[WARN][createblock] Failed to publish accounts snapshot to DHT: {e}")
    
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
    # This function is not expected to be called for createblock,
    # as the result is handled directly by the execute function.
    # Returning an empty string or raising an error might be more appropriate
    # depending on how this is used elsewhere.
    return ""


import logging
logger = logging.getLogger(__name__)

def execute(raw_command: str, container):
    """
    Executes the createblock command.
    """
    logger.info("Create block requested")
    try:
        block_data = create_block_from_mempool()
        if not block_data or "block_hash" not in block_data:
            message = None
            if isinstance(block_data, dict):
                message = block_data.get("message") or block_data.get("error")
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
            
            # Broadcast the new block to the network
            try:
                from network import bus
                service = bus.get()
                if service:
                    service.broadcast_block(block_data)
                    logger.info("Block #%s broadcasted to network", block_number)
                else:
                    logger.warning("Network service not available, block not broadcasted")
            except Exception:
                logger.exception("Failed to broadcast block")

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
            if isinstance(block_data, dict):
                message = block_data.get("message") or block_data.get("error")
            else:
                message = None
            if not message:
                message = "Mempool is empty. No block created."
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
