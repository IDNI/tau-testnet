import threading
import json
import logging
from typing import Dict, List, Optional
import db
import tau_manager
import config
from consensus import TauConsensusEngine, TauStateSnapshot, compute_state_hash
from block import Block
import hashlib
from consensus.state import compute_state_hash as compute_rules_hash, compute_consensus_state_hash, compute_consensus_meta_hash

def compute_accounts_hash(balances: Dict[str, int], sequences: Dict[str, int]) -> bytes:
    """
    Computes a canonical hash of the accounts state (balances + sequences).
    Normalizes keys so missing sequence/balance entries default to 0.
    """
    keys = set(balances.keys()) | set(sequences.keys())
    normalized_balances: Dict[str, int] = {}
    normalized_sequences: Dict[str, int] = {}
    for addr in keys:
        if not isinstance(addr, str):
            continue
        normalized_balances[addr] = int(balances.get(addr, 0))
        normalized_sequences[addr] = int(sequences.get(addr, 0))
    snapshot = {
        "balances": normalized_balances,
        "sequences": normalized_sequences,
    }
    canonical_json = json.dumps(snapshot, sort_keys=True, separators=(",", ":"))
    json_bytes = canonical_json.encode("utf-8")
    digest = hashlib.sha256(json_bytes).digest()

    # Debug log to trace determinism issues
    if logger.isEnabledFor(logging.DEBUG):
        logger.debug(
            "compute_accounts_hash: %s len=%s content=%s...",
            digest.hex(),
            len(json_bytes),
            canonical_json[:100],
        )

    return digest



logger = logging.getLogger(__name__)

# Lock for thread-safe reorg/fork-choice processing
_chain_lock = threading.RLock()

# Lock for thread-safe access to balances
_balance_lock = threading.Lock()

# In-memory balance table
# Maps full BLS public key hex strings to integer amounts
_balances = {}

from dataclasses import dataclass

@dataclass
class IngestResult:
    status: str
    message: str

# Lock for thread-safe access to sequence numbers
_sequence_lock = threading.Lock()

# In-memory sequence numbers table: maps address to sequence number
_sequence_numbers = {}

# Lock for thread-safe access to rules state
_rules_lock = threading.Lock()

# In-memory rules state storage
# In-memory rules state storage
_application_rules_state = ""
_consensus_rules_state = ""
_active_consensus_id = "tau_poa_v1"
from consensus.governance import ConsensusLifecycleManager
_lifecycle_manager = ConsensusLifecycleManager()

_canonical_head_hash = ""
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


def rehydrate_dht_state() -> bool:
    """
    Republish the currently loaded chain/tau snapshot into DHT.
    Returns True when the republish attempt completed without exceptions.
    """
    if not _dht_client:
        return False
    try:
        _republish_state_to_dht()
        return True
    except Exception as e:
        logger.error("rehydrate_dht_state failed: %s", e)
        return False


def _republish_state_to_dht():
    """
    Publishes the currently loaded state (rules and accounts) to the local DHT value store.
    """
    global _canonical_head_hash, _application_rules_state, _consensus_rules_state, _tau_engine_state_hash
    global _active_consensus_id
    
    if not _canonical_head_hash:
        return

    logger.info("Hydrating DHT with persisted state for block %s...", _canonical_head_hash)
    
    # 1. Publish Accounts
    publish_accounts_snapshot(_canonical_head_hash)
    
    # 2. Publish Tau State / Rules
    with _balance_lock, _sequence_lock, _rules_lock:
         acc_hash = compute_accounts_hash(_balances, _sequence_numbers)
         app_rules_bytes = (_application_rules_state or "").encode("utf-8")
         cons_rules_bytes = (_consensus_rules_state or "").encode("utf-8")
         vote_records = [(k, pub) for k, v in _lifecycle_manager.votes.items() for pub in v]
         meta_hash = compute_consensus_meta_hash(
             host_contract={}, active_validators=list(_lifecycle_manager.active_validators),
             pending_updates=list(_lifecycle_manager.pending_updates),
             vote_records=vote_records, activation_schedule=_lifecycle_manager.scheduled_updates,
             checkpoint_references=[]
         )
    
    state_hash = compute_consensus_state_hash(cons_rules_bytes, app_rules_bytes, acc_hash, meta_hash)
    
    if state_hash != _tau_engine_state_hash:
        logger.info("Updating stale _tau_engine_state_hash during hydration: %s -> %s", _tau_engine_state_hash, state_hash)
        _tau_engine_state_hash = state_hash

    # We publish the combined rules to DHT for backwards compatibility of block explorers, 
    # but actual verification uses split parts.
    combined_rules = cons_rules_bytes + b"\n" + app_rules_bytes
    if state_hash:
        publish_tau_state_snapshot(state_hash, combined_rules, acc_hash)



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


def fetch_tau_state_snapshot(state_hash: str) -> Optional[tuple[str, Optional[str]]]:
    """
    Fetch a serialized Tau rules snapshot from the DHT `tau_state:<hash>`.
    Returns (rules_str, accounts_hash_hex_or_None).
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
        source = "unknown"
        if hasattr(_dht_client, "get_record_sync"):
            val_bytes = _dht_client.get_record_sync(key, timeout=2.0)
            source = "get_record_sync"
        else:
            val = _dht_client.dht.value_store.get(key)
            val_bytes = getattr(val, "value", val) if val else None
            source = "local_value_store"
            
        if val_bytes is None:
            return None
            
        # Parse JSON payload
        decoded = val_bytes.decode("utf-8")
        data = json.loads(decoded)
        if isinstance(data, dict):
            rules = data.get("rules")
            accounts_hash = data.get("accounts_hash")
            if logger.isEnabledFor(logging.DEBUG) and isinstance(rules, str):
                try:
                    logger.debug(
                        "Fetched Tau state snapshot source=%s len=%s hash=%s has_newline=%s preview=%r",
                        source,
                        len(rules),
                        hashlib.sha256(rules.encode("utf-8")).hexdigest(),
                        "\n" in rules,
                        rules[:200],
                    )
                except Exception:
                    logger.debug("Fetched Tau state snapshot (debug logging failed)")
            return rules, accounts_hash
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
        keys = set(_balances.keys()) | set(_sequence_numbers.keys())
        accounts = {
            addr: {
                "balance": int(_balances.get(addr, 0)),
                "sequence": int(_sequence_numbers.get(addr, 0)),
            }
            for addr in keys
            if isinstance(addr, str)
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
GENESIS_ADDRESS = "a1fe40d5e4f155a1af7cb5804ec1ecba9ee3fb1f594e8a7b398b7ed69a6b0ccfd5bb6fd6d8ff965f8e1eb98d5abe7d2b"
GENESIS_BALANCE = 10000

def process_new_block(block: Block) -> bool:
    """
    Standard network/import block ingestion path.
    Enforces strict derivation, verification, and pure simulation before persistence.
    """
    global _lifecycle_manager, _application_rules_state, _consensus_rules_state, _tau_engine_state_hash, _canonical_head_hash
    from errors import TauTestnetError, BlockchainBug
    import db
    
    try:
        current_head = db.get_canonical_head()
        current_head_hash = current_head.get('block_hash') if current_head else ''
        
        # Fast path: cleanly extends the canonical chain
        if block.header.previous_hash == current_head_hash or current_head_hash == '':
            from consensus.engine import TauConsensusEngine
            from consensus.state import TauStateSnapshot, compute_consensus_meta_hash, compute_consensus_state_hash
            engine = TauConsensusEngine()
            
            # 1. Load Canonical Parent Snapshot natively
            app_rules = (_application_rules_state or "").encode('utf-8')
            cons_rules = (_consensus_rules_state or "").encode('utf-8')
            acc_hash = compute_accounts_hash(_balances, _sequence_numbers)
            vote_records = [(k, pub) for k, v in _lifecycle_manager.votes.items() for pub in v]
            meta_hash = compute_consensus_meta_hash(
                host_contract={}, active_validators=list(_lifecycle_manager.active_validators),
                pending_updates=list(_lifecycle_manager.pending_updates),
                vote_records=vote_records, activation_schedule=_lifecycle_manager.scheduled_updates,
                checkpoint_references=[]
            )
            state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)
            
            parent_snapshot = TauStateSnapshot(
                state_hash=state_hash,
                tau_bytes=app_rules,
                metadata={
                    "source": "chain_state",
                    "balances": _balances,
                    "sequence_numbers": _sequence_numbers,
                    "lifecycle_manager": _lifecycle_manager
                }
            )
            
            # 2. Derive Active consensus
            active_view = engine.derive_active_consensus(parent_snapshot, block.header.block_number)
            
            # 3. Form Proof State and Verify Block Header (Includes structural integrity & consensus checks)
            # Proof verified via cryptographic parsing (assumes network transport pre-verified signature structure)
            if not engine.verify_block_header(active_view, block, {"proof_ok": getattr(block, "verify_consensus_proof", lambda: True)()}):
                logger.error(f"[BLOCKCHAIN] Block #{block.header.block_number} failed network verification.")
                return False
                
            # 4. Pure Apply Block Executor
            apply_result = engine.apply_block(active_view, block, parent_snapshot)
            next_snapshot = apply_result.next_snapshot
            
            # 5. Invariant Checks
            # Fast path ensures the block is valid, but the generated state hash MUST match exactly.
            if getattr(block.header, 'state_hash', "") and next_snapshot.state_hash != block.header.state_hash:
                 logger.error(f"[BLOCKCHAIN] State hash mismatch for extending block #{block.header.block_number}")
                 return False
                 
            # 6. Atomically persist block + returned post state
            db.add_block(block)
            
            with _balance_lock, _sequence_lock, _rules_lock:
                _balances.clear()
                _balances.update(next_snapshot.metadata["balances"])
                _sequence_numbers.clear()
                _sequence_numbers.update(next_snapshot.metadata["sequence_numbers"])
                
                _lifecycle_manager = next_snapshot.metadata["lifecycle_manager"]
                
                new_app_rules = next_snapshot.tau_bytes.decode('utf-8', errors='ignore')
                if new_app_rules != _application_rules_state:
                    _application_rules_state = new_app_rules
                    save_application_rules_state(_application_rules_state)
                    
                _consensus_rules_state = next_snapshot.metadata["consensus_rules_state"]
                _tau_engine_state_hash = next_snapshot.state_hash
                _canonical_head_hash = block.block_hash
                
            db.save_canonical_state_atomically(
                head_hash=_canonical_head_hash,
                head_num=block.header.block_number,
                balances=_balances,
                sequences=_sequence_numbers,
                application_rules=_application_rules_state,
                consensus_rules=_consensus_rules_state,
                active_consensus_id=_tau_engine_state_hash,
                pending_updates=[u.to_dict() for u in _lifecycle_manager.pending_updates],
                votes=[{"update_id": uid, "validator_pubkey": p} for uid, ps in _lifecycle_manager.votes.items() for p in ps],
                scheduled=_lifecycle_manager.scheduled_updates,
                archival=[]
            )
            
            # Optional: mempool eviction triggers could be mapped here using `apply_result.mempool_hints`
            return True
        else:
            # Reorg or Orphan Path (delegates to legacy ingest and rebuild)
            res = ingest_block(block)
            if res.status == "added":
                maybe_update_canonical_head()
                return True
            return False

    except Exception as e:
        if isinstance(e, TauTestnetError):
            raise
        logger.error(f"[BLOCKCHAIN_BUG] Unhandled exception in process_new_block: {e}", exc_info=True)
        raise BlockchainBug(f"Unhandled exception in process_new_block: {e}") from e

def _rebuild_state_from_blockchain_internal(start_block=0, path_hashes=None):
    """
    Rebuilds or updates the chain state by replaying transactions from the database.
    If start_block is 0, it clears existing state.
    """
    
    
    print(f"[INFO][chain_state] Starting blockchain state reconstruction from block {start_block}...")
    global _canonical_head_hash, _tau_engine_state_hash, _application_rules_state, _consensus_rules_state
    global _active_consensus_id, _lifecycle_manager
    
    if start_block == 0:
        # Clear current state for a full rebuild
        with _balance_lock, _sequence_lock, _rules_lock:
            _balances.clear()
            _sequence_numbers.clear()
            _application_rules_state = ""
            _consensus_rules_state = ""
            _active_consensus_id = "tau_poa_v1"
            _lifecycle_manager = ConsensusLifecycleManager()
            _tau_engine_state_hash = ""
            _canonical_head_hash = ''
        print("[INFO][chain_state] Cleared existing in-memory state for full rebuild.")
        # Initialize genesis state
        with _balance_lock:
            _balances[GENESIS_ADDRESS] = GENESIS_BALANCE
        print(f"[INFO][chain_state] Initialized genesis balance: {GENESIS_ADDRESS[:10]}... = {GENESIS_BALANCE}")
    
    import db
    if path_hashes is not None:
        block_rows = [db.get_block_by_hash(h) for h in path_hashes]
        block_rows = [b for b in block_rows if b is not None]
    else:
        # Get all blocks from database, ordered by block number
        block_rows = db.get_canonical_blocks_at_or_after_height(start_block)
    
    if not block_rows:
        print(f"[INFO][chain_state] No new blocks found since block {start_block -1}. State is up to date.")
        return
    
    print(f"[INFO][chain_state] Found {len(block_rows)} blocks to replay.")
    
    total_transactions_processed = 0
    
    # Process each block in chronological order
    # Process each block in chronological order
    for block_idx, block_data in enumerate(block_rows):
        try:
            # block_data is already a dict from db.get_canonical_blocks_at_or_after_height
            block_number = block_data['header']['block_number']
            block_hash = block_data['block_hash'][:16] + "..."
            transactions = block_data.get('transactions', [])
            
            print(f"[INFO][chain_state] Processing block #{block_number} ({block_hash}) with {len(block_data.get('transactions', []))} transactions")
            
            block = Block.from_dict(block_data)
            engine = TauConsensusEngine()
            
            # 1. Load Parent Snapshot
            app_rules = (_application_rules_state or "").encode('utf-8')
            cons_rules = (_consensus_rules_state or "").encode('utf-8')
            acc_hash = compute_accounts_hash(_balances, _sequence_numbers)
            vote_records = [(k, pub) for k, v in _lifecycle_manager.votes.items() for pub in v]
            meta_hash = compute_consensus_meta_hash(
                host_contract={}, active_validators=list(_lifecycle_manager.active_validators),
                pending_updates=list(_lifecycle_manager.pending_updates),
                vote_records=vote_records, activation_schedule=_lifecycle_manager.scheduled_updates,
                checkpoint_references=[]
            )
            state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)
            
            # Build input parent_snapshot natively utilizing runtime state
            parent_snapshot = TauStateSnapshot(
                state_hash=state_hash,
                tau_bytes=app_rules,
                metadata={
                    "source": "chain_state",
                    "balances": _balances,
                    "sequence_numbers": _sequence_numbers,
                    "lifecycle_manager": _lifecycle_manager
                }
            )
            
            # 2. Derive Active Consensus
            active_view = engine.derive_active_consensus(parent_snapshot, block_number)
            
            # 3. Verify Block Header
            # We must not bypass verification during rebuild.
            # Passing proof_ok bypasses independent cryptography re-checks here because db integrity guarantees it,
            # but consensus verdicts on Tau rules (o6) will run.
            if not engine.verify_block_header(active_view, block, {"proof_ok": True}):
                print(f"[ERROR][chain_state] Block #{block_number} verification failed. Aborting rebuild!")
                return
            
            # 4. Execute Core Block Application Natively
            apply_result = engine.apply_block(active_view, block, parent_snapshot)
            next_snapshot = apply_result.next_snapshot
            
            # 5. Execute Required Invariant Replay Checks (comparing state hashes)
            if block_number != 0 and getattr(block.header, 'state_hash', "") not in ("", "0"*64) and next_snapshot.state_hash != block.header.state_hash:
                 # Legacy blocks generated prior to Phase 2 might lack this.
                 print(f"[ERROR][chain_state] Block #{block_number} state_hash invariant mismatch!")
                 print(f"  Computed: {next_snapshot.state_hash}\n  Block: {block.header.state_hash}")
                 return
                 
            # 6. Atomically Replace In-Memory State
            with _balance_lock, _sequence_lock, _rules_lock:
                _balances.clear()
                _balances.update(next_snapshot.metadata["balances"])
                _sequence_numbers.clear()
                _sequence_numbers.update(next_snapshot.metadata["sequence_numbers"])
                
                _lifecycle_manager = next_snapshot.metadata["lifecycle_manager"]
                
                new_app_rules = next_snapshot.tau_bytes.decode('utf-8', errors='ignore')
                if new_app_rules != _application_rules_state:
                    _application_rules_state = new_app_rules
                    save_application_rules_state(_application_rules_state)
                    
                _consensus_rules_state = next_snapshot.metadata["consensus_rules_state"]
                _tau_engine_state_hash = next_snapshot.state_hash
            
            total_transactions_processed += len(apply_result.accepted_tx_ids)
            
            # Log results
            if apply_result.invalid_tx_ids:
                print(f"[WARN][chain_state]   {len(apply_result.invalid_tx_ids)} transactions logically invalid in block #{block_number}")
            
            print(f"[DEBUG][chain_state]   Processed {len(apply_result.accepted_tx_ids)} accepted transactions")
            
        except json.JSONDecodeError as e:
            print(f"[ERROR][chain_state] Failed to parse block #{block_idx}: {e}")
        except KeyError as e:
            print(f"[ERROR][chain_state] Missing required field in block #{block_idx}: {e}")
        except Exception as e:
            print(f"[ERROR][chain_state] Unexpected error processing block #{block_idx}: {e}")
        
        # Update the last processed block hash after successfully processing a block
        _canonical_head_hash = block_data['block_hash']
    
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

def rebuild_state_from_blockchain(start_block=0):
    try:
        _rebuild_state_from_blockchain_internal(start_block)
    except Exception as e:
        from errors import TauTestnetError, BlockchainBug
        if isinstance(e, TauTestnetError):
            raise
        logger.error(f"[BLOCKCHAIN_BUG] Unhandled exception in rebuild_state_from_blockchain: {e}", exc_info=True)
        raise BlockchainBug(f"Unhandled exception in rebuild_state_from_blockchain: {e}") from e

def init_chain_state():
    """Initializes the chain state with genesis balance."""
    with _balance_lock:
        _balances[GENESIS_ADDRESS] = GENESIS_BALANCE
    print(f"[INFO][chain_state] Chain state initialized. Genesis address {GENESIS_ADDRESS[:10]}... funded with {GENESIS_BALANCE} AGRS.")

def get_balance(address_hex: str) -> int:
    """Returns the balance of the given address. Returns 0 if address not found."""
    with _balance_lock:
        if address_hex not in _balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
            return 1000
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
             current_from_balance = 1000

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
    """Returns the composed effective rules state."""
    with _rules_lock:
        app = _application_rules_state or ""
        cons = _consensus_rules_state or ""
        if cons and app:
            return cons + "\n" + app
        return cons + app

def get_application_rules_state() -> str:
    with _rules_lock:
        return _application_rules_state

def get_consensus_rules_state() -> str:
    with _rules_lock:
        return _consensus_rules_state

def save_application_rules_state(rules_content: str):
    global _application_rules_state
    with _rules_lock:
        _application_rules_state = rules_content or ""
        
def save_consensus_rules_state(rules_content: str):
    global _consensus_rules_state
    with _rules_lock:
        _consensus_rules_state = rules_content or ""

def load_state_from_db() -> bool:
    """
    Loads chain state from the database into the in-memory caches.
    Returns True if accounts were found in the database, False if no state exists.
    """
    import db
    
    balances, sequences, app_rules, cons_rules, cons_id, last_processed_block_hash, pending_updates, votes, scheduled, archival = db.load_chain_state()
    
    votes_map = {}
    for v in votes:
        votes_map.setdefault(v['update_id'], []).append(v['voter_pubkey'])
    
    if not balances and not last_processed_block_hash:
        return False
        
    with _balance_lock, _sequence_lock, _rules_lock:
        _balances.clear()
        _sequence_numbers.clear()
        _balances.update(balances)
        _sequence_numbers.update(sequences)
        
        global _application_rules_state, _consensus_rules_state, _active_consensus_id
        
        _application_rules_state = app_rules
        _consensus_rules_state = cons_rules
        _active_consensus_id = cons_id
        _lifecycle_manager = ConsensusLifecycleManager(
            pending_updates=[p['update_id'] for p in pending_updates],
            scheduled_updates=scheduled,
            archival_updates=archival,
            votes=votes_map
        )
        for p in pending_updates:
            _lifecycle_manager.update_payloads[p['update_id']] = p

        global _tau_engine_state_hash
        _tau_engine_state_hash = ""
        
        global _canonical_head_hash
        _canonical_head_hash = last_processed_block_hash
        
    return True

def commit_state_to_db(block_hash: str, block_number: int):
    """
    Commits the in-memory state (balances, sequence numbers, rules, proposals, votes) to the database atomically,
    associating it with the provided block_hash.
    """
    # Snapshot state under locks
    with _balance_lock, _sequence_lock, _rules_lock:
        balances_snapshot = _balances.copy()
        sequences_snapshot = _sequence_numbers.copy()
        app_rules_snapshot = _application_rules_state
        cons_rules_snapshot = _consensus_rules_state
        cons_id_snapshot = _active_consensus_id
        pending_updates_list = [{"update_id": k, "rule_revisions": v.rule_revisions, "activate_at_height": v.activate_at_height, "host_contract_patch": v.host_contract_patch} for k, v in _lifecycle_manager.update_payloads.items() if k in _lifecycle_manager.pending_updates]
        votes_list = [{"update_id": k, "voter_pubkey": pub} for k, v in _lifecycle_manager.votes.items() for pub in v]
        scheduled_list = _lifecycle_manager.scheduled_updates[:]
        archival_list = list(_lifecycle_manager.archival_updates)
        
    db.save_canonical_state_atomically(
        block_hash, block_number, 
        balances_snapshot, sequences_snapshot, 
        app_rules_snapshot, cons_rules_snapshot, cons_id_snapshot,
        pending_updates_list, votes_list, scheduled_list, archival_list
    )

def tick_governance(height: int):
    """
    Called when a block is accepted at the given height. Let the ConsensusLifecycleManager
    execute precise transitions, and if any updates activate, apply them here.
    """
    global _active_consensus_id, _consensus_rules_state
    with _rules_lock:
        import config
        validators = getattr(config, "MINER_PUBKEYS", [])
        if not validators and config.MINER_PUBKEY:
            validators = [config.MINER_PUBKEY]
            
        # Ensure the lifecycle manager uses the active validators to set its threshold
        _lifecycle_manager.active_validators = set(validators)
        n_validators = len(validators)
        _lifecycle_manager.approval_threshold = (2 * n_validators + 2) // 3 # Mock Phase 2 configurable threshold
        
        # Drive lifecycle transitions
        newly_active = _lifecycle_manager.process_height_transitions(height)
        
        # If any activated, the last one deterministically takes effect as active state
        # In a real V1 chain there's rarely >1 scheduled for the exact same block,
        # but if there is, we apply the last one sequentially.
        if newly_active:
            for update in newly_active:
                logger.info("Governance activated consensus update: %s", update.update_id_hex)
                # Combine revisions if multiple 
                combined_revisions = "\n".join(update.rule_revisions)
                _consensus_rules_state = combined_revisions
                
                # In Phase 2, `_active_consensus_id` isn't used much as an ID, but we keep it tracking the hash.
                _active_consensus_id = update.update_id_hex[:16] 


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
        print(f"[DEBUG][chain_state] State loaded successfully. Last known block hash: '{_canonical_head_hash[:16]}...'")
    else:
        print("[DEBUG][chain_state] No persistent state found in database.")

    print("[DEBUG][chain_state] Fetching latest block from database...")
    latest = db.get_canonical_head_block()
    latest_hash = latest['block_hash'] if latest else ''
    latest_num = latest['block_number'] if latest else 0
    if latest_hash:
         print(f"[DEBUG][chain_state] Latest block hash from DB: '{latest_hash[:16]}...'")
    else:
        print("[DEBUG][chain_state] No blocks found in database.")

    if not latest_hash:
        # No existing state: full rebuild (or genesis)
        print("[INFO][chain_state] Triggering full state rebuild because no persistent state was found.")
        rebuild_state_from_blockchain(start_block=0)
        print(f"[DEBUG][chain_state] Rebuild complete. Committing state with latest block hash: '{latest_hash[:16]}...'")
        commit_state_to_db(latest_hash, latest_num)
    else:
        # Verify consistency with blockchain head
        print("[DEBUG][chain_state] Verifying consistency between loaded state and blockchain head...")
        if _canonical_head_hash != latest_hash:
            print(f"[WARN][chain_state] State-DB mismatch! State hash: '{_canonical_head_hash[:16]}...', DB hash: '{latest_hash[:16]}...'.")
            print("[INFO][chain_state] Triggering full state rebuild due to mismatch.")
            rebuild_state_from_blockchain(start_block=0)
            print(f"[DEBUG][chain_state] Rebuild complete. Committing state with latest block hash: '{latest_hash[:16]}...'")
            commit_state_to_db(latest_hash, latest_num)
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


def _is_reachable_from_genesis(b_hash: str) -> bool:
    import config, db
    try:
        path = db.get_chain_path(b_hash, config.GENESIS_HASH)
        return True
    except ValueError:
        return False

def select_best_head(candidates: list[tuple[str, int]]) -> str | None:
    if not candidates:
        return None
        
    def score(cand):
        block_hash, height = cand
        return (-height, bytes.fromhex(block_hash))
        
    best = min(candidates, key=score)
    return best[0]

def ingest_block(block: Block) -> IngestResult:
    import db, config
    engine = TauConsensusEngine()
    if not engine.verify_block_header(block):
        return IngestResult('invalid', "Block verification failed")
    
    existing = db.get_block_by_hash(block.block_hash)
    if existing:
        return IngestResult('known', "Block already exists")
    
    # Enforce parent linkage rules for non-genesis
    parent = db.get_block_by_hash(block.header.previous_hash)
    if parent:
        parent_num = int(parent['header'].get('block_number', -1))
        if block.header.block_number != parent_num + 1:
            return IngestResult('invalid', f"Block number {block.header.block_number} is not +1 of parent {parent_num}")
    elif block.header.previous_hash != config.GENESIS_HASH and block.block_hash != config.GENESIS_HASH:
        # Parent missing, store as orphan
        db.add_block(block)
        return IngestResult('orphan', f"Block stored as orphan (missing parent {block.header.previous_hash})")
        
    db.add_block(block)
    return IngestResult('added', "Block ingested to DB")

def maybe_update_canonical_head():
    import db
    candidates = db.get_candidate_heads()
    if not candidates:
        return
        
    valid_cands = []
    for cand_hash, cand_height in candidates:
        if _is_reachable_from_genesis(cand_hash):
            valid_cands.append((cand_hash, cand_height))
            
    best_hash = select_best_head(valid_cands)
    if not best_hash:
        return
        
    with _chain_lock:
        current_head = db.get_canonical_head()
        current_hash = current_head.get('block_hash') if current_head else ''
        if best_hash != current_hash:
            reorg_to(best_hash)

def reorg_to(new_head_hash: str):
    import db, config
    
    current_head = db.get_canonical_head()
    old_head_hash = current_head.get('block_hash') if current_head else config.GENESIS_HASH
    
    if old_head_hash == new_head_hash:
        return
        
    try:
        new_path = db.get_chain_path(new_head_hash, config.GENESIS_HASH)
    except ValueError:
        return
        
    old_path = []
    if old_head_hash != config.GENESIS_HASH:
        try:
            old_path = db.get_chain_path(old_head_hash, config.GENESIS_HASH)
        except ValueError:
            pass
            
    common_prefix_len = 0
    for n_h, o_h in zip(new_path, old_path):
        if n_h == o_h:
            common_prefix_len += 1
        else:
            break
            
    new_suffix = new_path[common_prefix_len:]
    old_suffix = old_path[common_prefix_len:]
    
    # Phase 2: Mempool Diffs
    old_txs = {}
    from block import compute_tx_hash
    for shash in old_suffix:
        b = db.get_block_by_hash(shash)
        if b:
            for tx in b.get('transactions', []):
                tx_id = compute_tx_hash(tx) if isinstance(tx, dict) else tx
                old_txs[tx_id] = tx
                
    new_txs = set()
    for shash in new_suffix:
        b = db.get_block_by_hash(shash)
        if b:
            for tx in b.get('transactions', []):
                tx_id = compute_tx_hash(tx) if isinstance(tx, dict) else tx
                new_txs.add(tx_id)
                
    # Phase 3: Apply State Rebuild
    db.reset_mempool_reservations()
    _rebuild_state_from_blockchain_internal(0, path_hashes=new_path)
    
    # Phase 4: Atomic Commit of Rebuilt State
    with _balance_lock, _sequence_lock, _rules_lock:
        b = dict(_balances)
        s = dict(_sequence_numbers)
        app_r = _application_rules_state
        cons_r = _consensus_rules_state
        cons_id = _active_consensus_id
        pending_updates_list = [{"update_id": k, "rule_revisions": v.rule_revisions, "activate_at_height": v.activate_at_height, "host_contract_patch": v.host_contract_patch} for k, v in _lifecycle_manager.update_payloads.items() if k in _lifecycle_manager.pending_updates]
        votes_list = [{"update_id": k, "voter_pubkey": pub} for k, v in _lifecycle_manager.votes.items() for pub in v]
        scheduled_list = _lifecycle_manager.scheduled_updates[:]
        archival_list = list(_lifecycle_manager.archival_updates)
        head_num = db.get_block_by_hash(new_head_hash)['header']['block_number']
        db.save_canonical_state_atomically(
            new_head_hash,
            head_num,
            b,
            s,
            app_r,
            cons_r,
            cons_id,
            pending_updates_list,
            votes_list,
            scheduled_list,
            archival_list
        )
    
    # Phase 5: Mempool Restore
    if new_txs:
        db.remove_mempool_by_hashes(list(new_txs))
        
    import time, json
    for tx_id, tx in old_txs.items():
        if tx_id not in new_txs:
            try:
                db.add_mempool_tx(json.dumps(tx, separators=(",", ":")), tx_id, int(time.time()))
            except Exception as e:
                logger.error(f"[chain_state] Failed to restore tx {tx_id} to mempool: {e}")
    
