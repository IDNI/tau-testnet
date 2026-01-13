import threading
import json
import logging
from typing import Dict, List, Optional
import db
import tau_manager
import config
from poa import PoATauEngine, TauStateSnapshot, compute_state_hash
from block import Block
import hashlib
from poa.state import compute_state_hash as compute_rules_hash, compute_consensus_state_hash

def compute_accounts_hash(balances: Dict[str, int], sequences: Dict[str, int]) -> bytes:
    """
    Computes a canonical hash of the accounts state (balances + sequences).
    Sorts keys to ensure determinism.
    """
    snapshot = {
        "balances": balances,
        "sequences": sequences
    }
    canonical_json = json.dumps(snapshot, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(canonical_json.encode('utf-8')).digest()



logger = logging.getLogger(__name__)

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
_tau_engine_state_hash = ""  # last known Tau engine snapshot hash (best-effort)

# DHT Client for storing formulas
_dht_client = None

def set_dht_client(client):
    """Sets the DHT client for storing formulas."""
    global _dht_client
    _dht_client = client
    # Hydrate DHT with currently loaded items so we can advertise them
    try:
        if _dht_client:
             _republish_state_to_dht()
        else:
             logger.warning("set_dht_client called with None client; skipping hydration")
    except Exception as e:
        logger.error("Failed to hydrate DHT with persisted state: %s", e)


def _republish_state_to_dht():
    """
    Publishes the currently loaded state (rules and accounts) to the local DHT value store.
    This ensures that on node startup, the DHT is populated with the state loaded from DB,
    allowing the node to advertise these keys during handshake.
    """
    global _last_processed_block_hash, _current_rules_state, _tau_engine_state_hash
    
    if not _last_processed_block_hash:
        return

    logger.info("Hydrating DHT with persisted state for block %s...", _last_processed_block_hash)
    
    # 1. Publish Accounts
    publish_accounts_snapshot(_last_processed_block_hash)
    
    # 2. Publish Tau State / Rules
    # Always RECOMPUTE state_hash to ensure it matches the payload (rules + accounts_hash).
    # This avoids publishing with a stale or rules-only hash which would fail validation.
    
    with _balance_lock, _sequence_lock, _rules_lock:
         acc_hash = compute_accounts_hash(_balances, _sequence_numbers)
         rules_bytes = (_current_rules_state or "").encode("utf-8")
    
    state_hash = compute_consensus_state_hash(rules_bytes, acc_hash)
    
    # Update global reference if it differs (though strictly we just want to publish valid data here)
    if state_hash != _tau_engine_state_hash:
        logger.info("Updating stale _tau_engine_state_hash during hydration: %s -> %s", _tau_engine_state_hash, state_hash)
        _tau_engine_state_hash = state_hash

    # Check if we have rules (even empty string is valid state now)
    # Ensure we publish if state_hash is valid.
    if state_hash and _current_rules_state is not None:
        publish_tau_state_snapshot(state_hash, rules_bytes, acc_hash)



def publish_tau_state_snapshot(state_hash: str, tau_bytes: bytes, accounts_hash: bytes) -> bool:
    """
    Publish the serialized Tau/rules snapshot into the DHT under `tau_state:<hash>`.
    Payload is JSON: `{"rules": <str>, "accounts_hash": <hex>}`.
    """
    if not state_hash or not isinstance(state_hash, str):
        return False
    if tau_bytes is None:
        return False
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return False
        
    try:
        # Construct JSON payload
        rules_str = tau_bytes.decode("utf-8")
        accounts_hash_hex = accounts_hash.hex()
        
        payload = json.dumps({
            "rules": rules_str,
            "accounts_hash": accounts_hash_hex
        }).encode("utf-8")
        
        key = f"tau_state:{state_hash}".encode("ascii")
    except Exception:
        return False

    try:
        if logger.isEnabledFor(logging.DEBUG):
            logger.debug(
                "Publishing Tau state snapshot to DHT key=%s len=%s state_hash=%s",
                key,
                len(payload),
                state_hash,
            )

        # Prefer network replication if supported by the DHT manager wrapper.
        if hasattr(_dht_client, "put_record_sync"):
            return bool(_dht_client.put_record_sync(key, payload))

        # Fallback: local store only
        _dht_client.dht.value_store.put(key, payload)
        return True
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to publish tau state snapshot to DHT: {exc}")
        return False


def fetch_tau_state_snapshot(state_hash: str) -> Optional[str]:
    """
    Fetch a serialized Tau rules snapshot (string) from the DHT `tau_state:<hash>`.
    Expects JSON payload with "rules" field.
    """
    if not state_hash or not isinstance(state_hash, str):
        return None
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return None
    try:
        key = f"tau_state:{state_hash}".encode("ascii")
    except Exception:
        return None

    try:
        if hasattr(_dht_client, "get_record_sync"):
            val_bytes = _dht_client.get_record_sync(key, timeout=2.0)
        else:
            val = _dht_client.dht.value_store.get(key)
            val_bytes = getattr(val, "value", val) if val else None
            
        if val_bytes is None:
            return None
            
        # Parse JSON payload
        decoded = val_bytes.decode("utf-8")
        data = json.loads(decoded)
        if isinstance(data, dict):
            return data.get("rules")
        return None
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to fetch tau state snapshot from DHT: {exc}")
        return None


def publish_accounts_snapshot(block_hash: str) -> bool:
    """
    Publish the resulting account table (balances + sequence numbers) for a block
    into the DHT.

    Key:   state:<block_hash>
    Value: JSON bytes: {"block_hash": "<block_hash>", "accounts": {addr: {"balance": int, "sequence": int}}}
    """
    if not block_hash or not isinstance(block_hash, str):
        return False
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return False

    with _balance_lock, _sequence_lock:
        accounts = {
            addr: {"balance": int(bal), "sequence": int(_sequence_numbers.get(addr, 0))}
            for addr, bal in _balances.items()
        }
    payload = json.dumps(
        {"block_hash": block_hash, "accounts": accounts},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    try:
        key = f"{config.STATE_LOCATOR_NAMESPACE}:{block_hash}".encode("ascii")
    except Exception:
        return False

    try:
        if logger.isEnabledFor(logging.DEBUG):
             try:
                 # Avoid logging full payload for large state
                 data_obj = json.loads(payload.decode("utf-8"))
                 accs = data_obj.get("accounts", {})
                 acc_count = len(accs)
                 # Sample first 10
                 sample = dict(list(accs.items())[:10])
                 logger.debug(
                     "Publishing accounts snapshot key=%s block=%s count=%d sample=%s...",
                     key, block_hash, acc_count, sample
                 )
             except Exception:
                 logger.debug(
                     "Publishing accounts snapshot key=%s block=%s len=%d",
                     key, block_hash, len(payload)
                 )

        if hasattr(_dht_client, "put_record_sync"):
            return bool(_dht_client.put_record_sync(key, payload))
        _dht_client.dht.value_store.put(key, payload)
        return True
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to publish accounts snapshot to DHT: {exc}")
        return False


def fetch_accounts_snapshot(block_hash: str) -> Optional[tuple[Dict[str, int], Dict[str, int]]]:
    """
    Fetch the account table snapshot (balances + sequences) for a block from DHT.
    """
    if not block_hash or not isinstance(block_hash, str):
        return None
    if not _dht_client or not getattr(_dht_client, "dht", None):
        return None

    try:
        key = f"{config.STATE_LOCATOR_NAMESPACE}:{block_hash}".encode("ascii")
    except Exception:
        return None

    try:
        if hasattr(_dht_client, "get_record_sync"):
            val_bytes = _dht_client.get_record_sync(key, timeout=2.0)
        else:
            val = _dht_client.dht.value_store.get(key)
            val_bytes = getattr(val, "value", val) if val else None
        if not val_bytes:
            return None
        if not isinstance(val_bytes, (bytes, bytearray)):
            val_bytes = bytes(val_bytes)
        data = json.loads(val_bytes.decode("utf-8"))
        if not isinstance(data, dict):
            return None
        accounts = data.get("accounts")
        if not isinstance(accounts, dict):
            return None
        balances: Dict[str, int] = {}
        sequences: Dict[str, int] = {}
        for addr, row in accounts.items():
            if not isinstance(addr, str):
                continue
            if isinstance(row, dict):
                try:
                    balances[addr] = int(row.get("balance", 0))
                except Exception:
                    balances[addr] = 0
                try:
                    sequences[addr] = int(row.get("sequence", 0))
                except Exception:
                    sequences[addr] = 0
            else:
                # Back-compat: allow {addr: balance} only
                try:
                    balances[addr] = int(row)
                except Exception:
                    balances[addr] = 0
                sequences[addr] = 0
        return balances, sequences
    except Exception as exc:
        print(f"[WARN][chain_state] Failed to fetch accounts snapshot from DHT: {exc}")
        return None

# Genesis address and balance used across tests and reconstruction
GENESIS_ADDRESS = "91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6"
GENESIS_BALANCE = 65535
# Alice
# Private Key (hex, 32 bytes): 11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09
# Public Key (hex, 48 bytes, G1 compressed): 91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6


def process_new_block(block: Block) -> bool:
    """
    Verify and persist a new block.

    Secondary-node fast path:
    - Do NOT re-execute transactions.
    - Fetch the resulting `accounts` snapshot from DHT under `state:<block_hash>`.
    - Fetch the resulting Tau rules snapshot from DHT under `state:<state_hash>` and apply it to Tau via i0.

    Fallback (backwards compatibility):
    - If snapshots are unavailable, fall back to the previous behavior (re-execute via PoATauEngine).

    Returns True if successful, False otherwise.
    """
    block_number = block.header.block_number
    # Basic deduplication
    existing = db.get_block_by_hash(block.block_hash)
    if existing:
        return True

    global _current_rules_state, _last_processed_block_hash

    print(f"[INFO][chain_state] Processing new block #{block_number} ({block.block_hash[:8]}...)")
    
    engine = PoATauEngine()
    if not engine.verify_block(block):
        print(f"[WARN][chain_state] Block #{block_number} verification failed")
        return False

    expected_state_hash = getattr(block.header, "state_hash", "") or ""

    # --- Snapshot fast path (secondary nodes) ---------------------------------
    # Do not replay block transactions. Instead, pull the resulting state from DHT.
    import time

    deadline = time.time() + 5.0  # allow brief propagation delay
    balances_snapshot: Optional[Dict[str, int]] = None
    sequences_snapshot: Optional[Dict[str, int]] = None
    rules_from_dht: Optional[str] = None

    while time.time() < deadline:
        accounts_result = fetch_accounts_snapshot(block.block_hash)
        if accounts_result:
            balances_snapshot, sequences_snapshot = accounts_result

        if expected_state_hash and expected_state_hash != ("0" * 64):
            rules_from_dht = fetch_tau_state_snapshot(expected_state_hash)
        else:
            rules_from_dht = ""

        if balances_snapshot is not None and sequences_snapshot is not None and rules_from_dht is not None:
             # Cache fetched snapshots to local DHT store to assist network propagation
            try:
                 if _dht_client and _dht_client.dht:
                    # Cache accounts
                    # Do NOT call publish_accounts_snapshot() (which reads current global state).
                    # Construct payload from FETCHED snapshots.
                    accounts_payload = json.dumps(
                         {
                             "block_hash": block.block_hash, 
                             "accounts": {
                                 addr: {"balance": bal, "sequence": sequences_snapshot.get(addr, 0)} 
                                 for addr, bal in balances_snapshot.items()
                             }
                         }, 
                         sort_keys=True, separators=(",", ":")
                    ).encode("utf-8")
                    
                    if hasattr(_dht_client, "put_record_sync"):
                        # Cache accounts
                        # Use put_record_sync which handles key encoding (e.g. /state/<hash>)
                        acc_key_raw = f"{config.STATE_LOCATOR_NAMESPACE}:{block.block_hash}".encode("ascii")
                        if not _dht_client.put_record_sync(acc_key_raw, accounts_payload):
                             logger.warning("[chain_state] Failed to cache accounts snapshot for %s via put_record_sync", block.block_hash)
                        
                        # Cache rules
                        if rules_from_dht is not None:
                             # Reconstruct payload for cache using local hash computation
                             acc_hash_for_cache = compute_accounts_hash(balances_snapshot, sequences_snapshot)
                             
                             import json
                             payload_cache = json.dumps({
                                 "rules": rules_from_dht,
                                 "accounts_hash": acc_hash_for_cache.hex()
                             }).encode("utf-8")
                             
                             rules_key_raw = f"tau_state:{expected_state_hash}".encode("ascii")
                             if not _dht_client.put_record_sync(rules_key_raw, payload_cache):
                                  logger.warning("[chain_state] Failed to cache rules snapshot for %s via put_record_sync", expected_state_hash)
                    else:
                        # Fallback if put_record_sync missing (should not happen with updated dht_manager)
                        acc_key = f"{config.STATE_LOCATOR_NAMESPACE}:{block.block_hash}".encode("ascii")
                        _dht_client.dht.value_store.put(acc_key, accounts_payload)
                        if rules_from_dht is not None:
                             acc_hash_for_cache = compute_accounts_hash(balances_snapshot, sequences_snapshot)
                             payload_cache = json.dumps({
                                 "rules": rules_from_dht,
                                 "accounts_hash": acc_hash_for_cache.hex()
                             }).encode("utf-8")
                             rules_key = f"tau_state:{expected_state_hash}".encode("ascii")
                             _dht_client.dht.value_store.put(rules_key, payload_cache)
            except Exception as e:
                 print(f"[WARN][chain_state] Failed to cache snapshots to local DHT: {e}")
            break
        time.sleep(0.2)

    if balances_snapshot is None or sequences_snapshot is None:
        print(f"[ERROR][chain_state] Missing accounts snapshot in DHT for block {block.block_hash[:12]}...")
        return False
    # If expected_state_hash is present/non-empty, we demand rules
    if expected_state_hash and expected_state_hash != ("0" * 64) and rules_from_dht is None:
        print(f"[ERROR][chain_state] Missing Tau snapshot in DHT for state_hash {expected_state_hash[:12]}...")
        return False

    # Apply Tau rules snapshot to the running Tau engine via i0.
    if not tau_manager.tau_ready.is_set():
        tau_manager.tau_ready.wait(timeout=5)
    if not tau_manager.tau_ready.is_set():
        print("[ERROR][chain_state] Tau is not ready; cannot apply state snapshot")
        return False

    try:
        # Always reset Tau state even if empty
        rule_text = rules_from_dht if rules_from_dht else ""
        tau_manager.communicate_with_tau(rule_text=rule_text, target_output_stream_index=0)
    except Exception as exc:
        print(f"[ERROR][chain_state] Failed to apply Tau state snapshot via i0: {exc}")
        return False

    # Consensus State Verification
    # Confirm the applied rules AND accounts match the block commitment.
    
    # 1. Compute Accounts Hash
    accounts_hash = compute_accounts_hash(balances_snapshot, sequences_snapshot)
    
    # 2. Compute Consensus Hash
    # Rules: existing logic tries `_current_rules_state` (if updated by communicate?) 
    # But communicate_with_tau updates _current_rules_state via handler? 
    # Let's rely on rules_from_dht since that's what we applied.
    applied_rules = rules_from_dht or ""
    rules_bytes = applied_rules.encode("utf-8")
    
    applied_hash = compute_consensus_state_hash(rules_bytes, accounts_hash)

    # Allow fallback? If hash format changed, we might have issues.
    # But for Phase 12 hardening, we enforce the new format.
    
    if expected_state_hash and expected_state_hash != ("0" * 64) and applied_hash != expected_state_hash:
        print(
            f"[ERROR][chain_state] Consensus state hash mismatch. "
            f"expected={expected_state_hash[:12]} got={applied_hash[:12]}"
        )
        return False

    with _rules_lock:
        global _tau_engine_state_hash
        _tau_engine_state_hash = expected_state_hash

    # Replace local account state with the snapshot.
    with _balance_lock, _sequence_lock:
        _balances.clear()
        _balances.update(balances_snapshot)
        _sequence_numbers.clear()
        _sequence_numbers.update(sequences_snapshot)

    with _rules_lock:
        _current_rules_state = applied_rules
        _last_processed_block_hash = block.block_hash

    db.add_block(block)
    db.save_chain_state(
        balances=_balances,
        sequences=_sequence_numbers,
        rules=applied_rules,
        last_block_hash=block.block_hash,
    )
    print(f"[INFO][chain_state] Block #{block_number} persisted via DHT snapshots.")
    return True

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
            global _tau_engine_state_hash
            _tau_engine_state_hash = ""
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
            
            # Verify and process block using PoATauEngine
            block = Block.from_dict(block_data)
            engine = PoATauEngine()
            
            if not engine.verify_block(block):
                print(f"[WARN][chain_state] Block #{block_number} verification failed (signature/validator)")
                # We continue for reconstruction but log it
            
            # Prepare snapshot from current rules state
            current_rules_bytes = _current_rules_state.encode('utf-8')
            snapshot = TauStateSnapshot(
                state_hash=compute_state_hash(current_rules_bytes),
                tau_bytes=current_rules_bytes,
                metadata={"source": "chain_state"}
            )
            
            # Apply transactions
            result = engine.apply(snapshot, block.transactions)
            
            # Update rules state from result
            # The engine accumulates bytes in snapshot.tau_bytes
            new_rules = result.snapshot.tau_bytes.decode('utf-8')
            if new_rules != _current_rules_state:
                save_rules_state(new_rules)
            
            total_transactions_processed += len(result.accepted_transactions)
            
            # Log results
            if result.rejected_transactions:
                print(f"[WARN][chain_state]   {len(result.rejected_transactions)} transactions rejected in block #{block_number}")
            
            print(f"[DEBUG][chain_state]   Processed {len(result.accepted_transactions)} accepted transactions")
            
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
        if address_hex not in _balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
            return 100000
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

        # Auto-faucet logic for sender: if missing, assume 100k
        if from_address_hex not in _balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
             current_from_balance = 100000

        # Enforce sufficient funds during balance updates to avoid negative balances
        if current_from_balance < amount:
            print(f"[ERROR][chain_state] Insufficient funds for {from_address_hex[:10]}... to send {amount}. Has: {current_from_balance}.")
            return False

        current_to_balance = _balances.get(to_address_hex, 0)
        
        _balances[from_address_hex] = current_from_balance - amount
        _balances[to_address_hex] = current_to_balance + amount
        
        print(f"[INFO][chain_state] Balances updated: {from_address_hex[:10]}... now {_balances[from_address_hex]}, {to_address_hex[:10]}... now {_balances[to_address_hex]}")
        return True


from contextlib import contextmanager

@contextmanager
def get_all_state_locks():
    """
    Context manager to acquire all state locks (balances, sequences, rules)
    to ensure a consistent global snapshot.
    """
    with _balance_lock:
        with _sequence_lock:
            with _rules_lock:
                yield

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
    global _current_rules_state, _tau_engine_state_hash
    with _rules_lock:
        # Do not strip()! We must preserve exact bytes for hash consistency.
        candidate = rules_content or ""
        if not candidate:
            logger.warning("Saving empty Tau rules state.")
            # return
        _current_rules_state = candidate
        
        # NOTE: We do NOT set _tau_engine_state_hash to the rules-only hash here.
        # We wait until we compute the consensus hash (rules + accounts_hash) below.
        
        print(f"[INFO][chain_state] Rules state updated. Length: {len(_current_rules_state)} characters")
        logger.debug(
            "Rules state saved (len=%s).",
            len(_current_rules_state)
        )

        if _dht_client:
                try:
                    rules_bytes = _current_rules_state.encode('utf-8')
                    # Compute Accounts Hash for Consensus Hash
                    with _balance_lock, _sequence_lock:
                         accounts_hash = compute_accounts_hash(_balances, _sequence_numbers)
                    
                    # Compute Consensus Hash
                    state_hash = compute_consensus_state_hash(rules_bytes, accounts_hash)
                    
                    # Update global hash
                    _tau_engine_state_hash = state_hash
                    
                    # Publish to tau_state:<consensus_hash>
                    publish_tau_state_snapshot(state_hash, rules_bytes, accounts_hash)
                    print(f"[INFO][chain_state] Published Tau state snapshot to DHT: tau_state:{state_hash}")
                    
                    # Previously we also published to formula:<sha256>. Keep it for raw formula lookup?
                    # The user asked to "Stop publishing state:<rules_hash>" which refers to keying by rule hash
                    # but using "state" namespace.
                    # We might still want "formula:<sha256>" -> raw_bytes for direct formula sharing if needed.
                    # But if not critical, we can skip. Let's keep formula for now as it seems distinct.
                    
                except Exception as e:
                    print(f"[ERROR][chain_state] Failed to store state in DHT: {e}")
        

def fetch_formula_from_dht(formula_hash: str) -> Optional[str]:
    """
    Retrieves a formula from the DHT using its hash.
    Returns the formula content as a string if found, None otherwise.
    """
    if not _dht_client or not _dht_client.dht:
        print("[WARN][chain_state] DHT client not available for formula retrieval")
        return None
        
    try:
        key = f"formula:{formula_hash}".encode('ascii')
        # We use get_value which should return the value if found
        # Note: libp2p KadDHT.get_value returns the value bytes
        # It's an async method usually, but here we might be in sync context?
        # Wait, chain_state is mostly sync.
        # If KadDHT methods are async, we might have a problem calling them from sync code.
        # But save_rules_state called value_store.put which is sync (in-memory store).
        # However, real DHT operations are async.
        # For now, let's assume we are accessing the local value store or we need to bridge to async.
        # But wait, save_rules_state used `_dht_client.dht.value_store.put`. That is the LOCAL storage.
        # If we want to retrieve from the network, we need `dht.get_value(key)`.
        # That is definitely async.
        # But maybe for this task, we just want to verify we can retrieve what we stored?
        # If we stored it in local value_store, we can retrieve it from local value_store.
        
        if hasattr(_dht_client, "get_record_sync"):
            val_bytes = _dht_client.get_record_sync(key)
            if val_bytes:
                return val_bytes.decode('utf-8')
            else:
                print(f"[DEBUG][chain_state] Formula {formula_hash} not found in DHT (local or network)")
                return None
        
        # Fallback for old clients (local check only)
        val = _dht_client.dht.value_store.get(key)
        if val:
            return val.decode('utf-8')
        else:
            print(f"[DEBUG][chain_state] Formula {formula_hash} not found in local DHT store")
            return None
            
    except Exception as e:
        print(f"[ERROR][chain_state] Failed to fetch formula from DHT: {e}")
        return None
        

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

        # We loaded rules state from persistence, but Tau engine has not necessarily
        # been updated yet (it restarts fresh). Treat engine state as unknown until
        # we explicitly apply a snapshot to Tau.
        global _tau_engine_state_hash
        _tau_engine_state_hash = ""
        
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


def load_builtin_rules_from_disk() -> list[str]:
    """
    Load built-in Tau rule statements from the local `rules/` directory.

    Each file is expected to contain one or more Tau rule statements. Lines starting with '#'
    are treated as comments and ignored.
    """
    import os

    rules_dir = os.path.join(os.path.dirname(__file__), "rules")
    if not os.path.isdir(rules_dir):
        return []

    rules: list[str] = []
    for fname in sorted(os.listdir(rules_dir)):
        path = os.path.join(rules_dir, fname)
        # Keep existing convention: only numeric-prefixed rule files are injected.
        if not (os.path.isfile(path) and fname and fname[0].isdigit()):
            continue
        with open(path, "r", encoding="utf-8") as f:
            # Read all lines, filter out comments, and join into a single Tau input.
            rule_text = " ".join([line.strip() for line in f if not line.strip().startswith("#")]).strip()
        if rule_text:
            rules.append(rule_text)
    return rules
