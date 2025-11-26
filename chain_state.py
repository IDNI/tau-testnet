import threading
import json
from typing import Dict, List, Optional
import db
import tau_manager

# Lock for thread-safe access to balances
_balance_lock = threading.Lock()

# In-memory balance table
# Maps full BLS public key hex strings to integer amounts
_balances = {}

# Lock for thread-safe access to sequence numbers
_sequence_lock = threading.Lock()

# In-memory sequence numbers table: maps address to sequence number
_sequence_numbers = {}

# Lock for thread-safe access to rules state
_rules_lock = threading.Lock()

# In-memory rules state storage
_current_rules_state = ""
_last_processed_block_hash = ""

# Genesis address and balance used across tests and reconstruction
GENESIS_ADDRESS = "91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6"
GENESIS_BALANCE = 65535
# Alice
# Private Key (hex, 32 bytes): 11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09
# Public Key (hex, 48 bytes, G1 compressed): 91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6

def rebuild_state_from_blockchain(start_block=0):
    """
    Rebuilds or updates the chain state by replaying transactions from the database.
    If start_block is 0, it clears existing state.
    """
    
    
    print(f"[INFO][chain_state] Starting blockchain state reconstruction from block {start_block}...")
    global _last_processed_block_hash
    
    if start_block == 0:
        # Clear current state for a full rebuild
        with _balance_lock, _sequence_lock, _rules_lock:
            _balances.clear()
            _sequence_numbers.clear()
            _current_rules_state = ""
            _last_processed_block_hash = ''
        print("[INFO][chain_state] Cleared existing in-memory state for full rebuild.")
        # Initialize genesis state
        with _balance_lock:
            _balances[GENESIS_ADDRESS] = GENESIS_BALANCE
        print(f"[INFO][chain_state] Initialized genesis balance: {GENESIS_ADDRESS[:10]}... = {GENESIS_BALANCE}")
    
    # Get all blocks from database, ordered by block number
    # Get all blocks from database, ordered by block number
    block_rows = db.get_blocks_after(start_block)
    
    if not block_rows:
        print(f"[INFO][chain_state] No new blocks found since block {start_block -1}. State is up to date.")
        return
    
    print(f"[INFO][chain_state] Found {len(block_rows)} blocks to replay.")
    
    total_transactions_processed = 0
    
    # Process each block in chronological order
    # Process each block in chronological order
    for block_idx, block_data in enumerate(block_rows):
        try:
            # block_data is already a dict from db.get_blocks_after
            block_number = block_data['header']['block_number']
            block_hash = block_data['block_hash'][:16] + "..."
            transactions = block_data.get('transactions', [])
            
            print(f"[INFO][chain_state] Processing block #{block_number} ({block_hash}) with {len(transactions)} transactions")
            
            # Process each transaction in the block
            for tx_idx, transaction in enumerate(transactions):
                print(f"[DEBUG][chain_state]   Processing TX #{tx_idx + 1} in block #{block_number}")
                
                # Extract transaction details
                sender_pubkey = transaction.get('sender_pubkey')
                sequence_number = transaction.get('sequence_number')
                operations = transaction.get('operations', {})
                
                if not sender_pubkey:
                    print(f"[WARN][chain_state]   TX #{tx_idx + 1}: Missing sender_pubkey, skipping")
                    continue
                
                # Update sequence number first (this happens for all valid transactions)
                if sequence_number is not None:
                    with _sequence_lock:
                        current_seq = _sequence_numbers.get(sender_pubkey, 0)
                        expected_seq = sequence_number
                        if expected_seq == current_seq:
                            _sequence_numbers[sender_pubkey] = expected_seq + 1
                            print(f"[DEBUG][chain_state]     Updated sequence for {sender_pubkey[:10]}...: {current_seq} -> {expected_seq + 1}")
                        else:
                            print(f"[WARN][chain_state]     Sequence mismatch for {sender_pubkey[:10]}...: expected {expected_seq}, had {current_seq}")
                
                # Process all operations in the transaction
                print(f"[DEBUG][chain_state]     Processing {len(operations)} operations: {list(operations.keys())}")
                
                for op_key, op_data in operations.items():
                    print(f"[DEBUG][chain_state]       Processing operation '{op_key}'")
                    
                    if op_key == "0":
                        # Handle rules (operation "0")
                        if isinstance(op_data, str) and op_data.strip():
                            print(f"[DEBUG][chain_state]         Rule operation: '{op_data[:50]}{'...' if len(op_data) > 50 else ''}'")
                            # Rules must be sent to Tau core to recreate the exact Tau state
                            try:
                                
                                
                                # Wait for Tau to be ready
                                if not tau_manager.tau_ready.wait(timeout=10):
                                    print(f"[ERROR][chain_state]         Tau not ready for rule processing, skipping rule")
                                    continue
                                
                                # Send rule to Tau (same as live processing)
                                print(f"[DEBUG][chain_state]         Sending rule to Tau core...")
                                tau_output = tau_manager.communicate_with_tau(rule_text=op_data.strip(), target_output_stream_index=0)
                                
                                if tau_output.strip().lower() == "x1001":
                                    print(f"[DEBUG][chain_state]         Rule successfully applied to Tau core")
                                else:
                                    print(f"[ERROR][chain_state]         Tau rejected rule during reconstruction. Output: {tau_output}")
                                    # In reconstruction, we might want to be more lenient since this was historically valid
                                    print(f"[WARN][chain_state]         Continuing reconstruction despite Tau rejection (historical inconsistency)")
                                
                            except Exception as e:
                                print(f"[ERROR][chain_state]         Failed to send rule to Tau during reconstruction: {e}")
                                print(f"[WARN][chain_state]         Continuing reconstruction without rule application")
                        else:
                            print(f"[DEBUG][chain_state]         Empty or invalid rule data, skipping")
                    
                    elif op_key == "1":
                        # Handle transfers (operation "1") 
                        if not (isinstance(op_data, list)):
                            print(f"[WARN][chain_state]         Transfer operation must be a list, got {type(op_data).__name__}")
                            continue
                        
                        if not op_data:  # Empty transfer list
                            print(f"[DEBUG][chain_state]         Empty transfer list")
                            continue
                        
                        print(f"[DEBUG][chain_state]         Processing {len(op_data)} transfers")
                        
                        for transfer_idx, transfer in enumerate(op_data):
                            if not (isinstance(transfer, (list, tuple)) and len(transfer) == 3):
                                print(f"[WARN][chain_state]           Transfer #{transfer_idx + 1}: Invalid format, skipping")
                                continue
                            
                            from_addr, to_addr, amount_str = transfer
                            try:
                                amount = int(amount_str)
                            except (ValueError, TypeError):
                                print(f"[WARN][chain_state]           Transfer #{transfer_idx + 1}: Invalid amount '{amount_str}', skipping")
                                continue
                            
                            if amount <= 0:
                                print(f"[WARN][chain_state]           Transfer #{transfer_idx + 1}: Non-positive amount {amount}, skipping")
                                continue
                            
                            # Use the same function as live transaction processing
                            success = update_balances_after_transfer(from_addr, to_addr, amount)
                            if not success:
                                print(f"[ERROR][chain_state]           Transfer #{transfer_idx + 1}: Failed to apply transfer")
                            else:
                                print(f"[DEBUG][chain_state]           Transfer #{transfer_idx + 1}: Successfully applied {from_addr[:10]}... -> {to_addr[:10]}... amount={amount}")
                    
                    else:
                        # Handle unknown operation types
                        print(f"[WARN][chain_state]         Unknown operation type '{op_key}', skipping")
                        print(f"[DEBUG][chain_state]         Operation data: {str(op_data)[:100]}{'...' if len(str(op_data)) > 100 else ''}")
                
                total_transactions_processed += 1
            
        except json.JSONDecodeError as e:
            print(f"[ERROR][chain_state] Failed to parse block #{block_idx}: {e}")
        except KeyError as e:
            print(f"[ERROR][chain_state] Missing required field in block #{block_idx}: {e}")
        except Exception as e:
            print(f"[ERROR][chain_state] Unexpected error processing block #{block_idx}: {e}")
        
        # Update the last processed block hash after successfully processing a block
        _last_processed_block_hash = block_data['block_hash']
    
    # Print final state summary
    print(f"[INFO][chain_state] Blockchain state reconstruction completed!")
    print(f"[INFO][chain_state] - Processed {len(block_rows)} blocks")
    print(f"[INFO][chain_state] - Processed {total_transactions_processed} transactions")
    
    with _balance_lock:
        non_zero_balances = {addr: bal for addr, bal in _balances.items() if bal > 0}
        print(f"[INFO][chain_state] - Final state: {len(non_zero_balances)} accounts with non-zero balances")
        for addr, balance in non_zero_balances.items():
            print(f"[INFO][chain_state]   {addr[:10]}... = {balance}")
    
    with _sequence_lock:
        active_sequences = {addr: seq for addr, seq in _sequence_numbers.items() if seq > 0}
        print(f"[INFO][chain_state] - Final state: {len(active_sequences)} accounts with sequence numbers")
        for addr, seq in active_sequences.items():
            print(f"[INFO][chain_state]   {addr[:10]}... seq = {seq}")

def init_chain_state():
    """Initializes the chain state with genesis balance."""
    with _balance_lock:
        _balances[GENESIS_ADDRESS] = GENESIS_BALANCE
    print(f"[INFO][chain_state] Chain state initialized. Genesis address {GENESIS_ADDRESS[:10]}... funded with {GENESIS_BALANCE} AGRS.")

def get_balance(address_hex: str) -> int:
    """Returns the balance of the given address. Returns 0 if address not found."""
    with _balance_lock:
        return _balances.get(address_hex, 0)

def update_balances_after_transfer(from_address_hex: str, to_address_hex: str, amount: int) -> bool:
    """
    Updates balances for a transfer. Assumes validation (including sufficient funds)
    has already occurred.
    Returns True if update was successful, False otherwise (e.g., an unexpected issue).
    """
    if amount <= 0:
        print(f"[WARN][chain_state] Attempted to update balance with non-positive amount: {amount}")
        return False # Should have been caught by Tau

    with _balance_lock:
        current_from_balance = _balances.get(from_address_hex, 0)

        # Enforce sufficient funds during balance updates to avoid negative balances
        if current_from_balance < amount:
            print(f"[ERROR][chain_state] Insufficient funds for {from_address_hex[:10]}... to send {amount}. Has: {current_from_balance}.")
            return False

        current_to_balance = _balances.get(to_address_hex, 0)
        
        _balances[from_address_hex] = current_from_balance - amount
        _balances[to_address_hex] = current_to_balance + amount
        
        print(f"[INFO][chain_state] Balances updated: {from_address_hex[:10]}... now {_balances[from_address_hex]}, {to_address_hex[:10]}... now {_balances[to_address_hex]}")
        return True

def get_sequence_number(address_hex: str) -> int:
    """Returns the current sequence number for the given address (defaults to 0)."""
    with _sequence_lock:
        return _sequence_numbers.get(address_hex, 0)

def increment_sequence_number(address_hex: str):
    """Increments the sequence number for the given address."""
    with _sequence_lock:
        _sequence_numbers[address_hex] = _sequence_numbers.get(address_hex, 0) + 1

def save_rules_state(rules_content: str):
    """
    Saves the rules state from Tau's o000 output stream.
    This represents the current rules state that should be persisted for chain state reconstruction.
    """
    global _current_rules_state
    with _rules_lock:
        _current_rules_state = rules_content.strip()
        print(f"[INFO][chain_state] Rules state updated. Length: {len(_current_rules_state)} characters")
        

def get_rules_state() -> str:
    """Returns the current rules state."""
    with _rules_lock:
        return _current_rules_state


def load_state_from_db() -> bool:
    """
    Loads chain state from the database into the in-memory caches.
    Returns True if accounts were found in the database, False if no state exists.
    """
    import db
    
    balances, sequences, current_rules, last_processed_block_hash = db.load_chain_state()
    
    if not balances:
        return False
        
    with _balance_lock, _sequence_lock, _rules_lock:
        _balances.clear()
        _sequence_numbers.clear()
        _balances.update(balances)
        _sequence_numbers.update(sequences)
        
        global _current_rules_state
        _current_rules_state = current_rules
        
        global _last_processed_block_hash
        _last_processed_block_hash = last_processed_block_hash
        
    return True

def commit_state_to_db(block_hash: str):
    """
    Commits the in-memory state (balances, sequence numbers, rules) to the database atomically,
    associating it with the provided block_hash.
    """
    # Snapshot state under locks
    with _balance_lock, _sequence_lock, _rules_lock:
        balances_snapshot = _balances.copy()
        sequences_snapshot = _sequence_numbers.copy()
        rules_snapshot = _current_rules_state
        
    db.save_chain_state(balances_snapshot, sequences_snapshot, rules_snapshot, block_hash)

def initialize_persistent_state():
    """
    Initializes persistent chain state from the database and verifies it against the blockchain.
    On first startup (no state and no blocks), initializes genesis state.
    On mismatch between stored state and blockchain, rebuilds and commits state.
    """
    print("[DEBUG][chain_state] > initialize_persistent_state started")
    db.init_db()

    print("[DEBUG][chain_state] Attempting to load state from database...")
    loaded = load_state_from_db()
    if loaded:
        print(f"[DEBUG][chain_state] State loaded successfully. Last known block hash: '{_last_processed_block_hash[:16]}...'")
    else:
        print("[DEBUG][chain_state] No persistent state found in database.")

    print("[DEBUG][chain_state] Fetching latest block from database...")
    latest = db.get_latest_block()
    latest_hash = latest['block_hash'] if latest else ''
    if latest_hash:
         print(f"[DEBUG][chain_state] Latest block hash from DB: '{latest_hash[:16]}...'")
    else:
        print("[DEBUG][chain_state] No blocks found in database.")

    if not latest_hash:
        # No existing state: full rebuild (or genesis)
        print("[INFO][chain_state] Triggering full state rebuild because no persistent state was found.")
        rebuild_state_from_blockchain(start_block=0)
        print(f"[DEBUG][chain_state] Rebuild complete. Committing state with latest block hash: '{latest_hash[:16]}...'")
        commit_state_to_db(latest_hash)
        # Load built-in rules into Tau from rules directory
        try:
            import os

            rules_dir = os.path.join(os.path.dirname(__file__), 'rules')
            if os.path.isdir(rules_dir):
                print(f"[DEBUG][chain_state] Found rules directory at: {rules_dir}")
                for fname in sorted(os.listdir(rules_dir)):
                    path = os.path.join(rules_dir, fname)
                    if os.path.isfile(path) and fname and fname[0].isdigit():
                        with open(path, 'r', encoding='utf-8') as f:
                            # Read all lines, filter out comments (lines starting with #), and join them.
                            rule_text = " ".join([line.strip() for line in f if not line.strip().startswith('#')]).strip()
                        
                        if rule_text:
                            print(f"[INFO][chain_state] Injecting built-in rule '{fname}' into Tau i0")
                            print(f"[DEBUG][chain_state] Rule content: {rule_text}")
                            tau_manager.communicate_with_tau(rule_text=rule_text,
                                                             target_output_stream_index=0)
            else:
                print(f"[DEBUG][chain_state] Rules directory not found at: {rules_dir}")
        except Exception as e:
            print(f"[ERROR][chain_state] Failed to inject built-in rules into Tau: {e}")
    else:
        # Verify consistency with blockchain head
        print("[DEBUG][chain_state] Verifying consistency between loaded state and blockchain head...")
        if _last_processed_block_hash != latest_hash:
            print(f"[WARN][chain_state] State-DB mismatch! State hash: '{_last_processed_block_hash[:16]}...', DB hash: '{latest_hash[:16]}...'.")
            print("[INFO][chain_state] Triggering full state rebuild due to mismatch.")
            rebuild_state_from_blockchain(start_block=0)
            print(f"[DEBUG][chain_state] Rebuild complete. Committing state with latest block hash: '{latest_hash[:16]}...'")
            commit_state_to_db(latest_hash)
        else:
            print(f"[INFO][chain_state] Persistent state is consistent and up-to-date with the blockchain.")

    print("[DEBUG][chain_state] > initialize_persistent_state finished")
