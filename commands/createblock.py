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
from consensus.state import compute_state_hash


import tau_manager
from tau_manager import parse_tau_output
import tau_defs
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




def execute_batch(transactions: List[Dict], reserved_ids: List[int], block_timestamp: int):
    """
    Compatibility helper used by tests to simulate a batch over the current
    in-memory chain state without persisting a block.
    """
    from copy import deepcopy
    from consensus.engine import TauConsensusEngine
    from consensus.state import TauStateSnapshot, compute_consensus_meta_hash, compute_consensus_state_hash
    from chain_state import compute_accounts_hash

    latest_block = db.get_canonical_head_block()
    block_number = (latest_block['header']['block_number'] + 1) if latest_block else 0

    app_rules = (chain_state._application_rules_state or "").encode('utf-8')
    cons_rules = (chain_state._consensus_rules_state or "").encode('utf-8')
    acc_hash = compute_accounts_hash(chain_state._balances, chain_state._sequence_numbers)
    vote_records = [(k, pub) for k, v in chain_state._lifecycle_manager.votes.items() for pub in v]
    meta_hash = compute_consensus_meta_hash(
        host_contract={}, active_validators=list(chain_state._lifecycle_manager.active_validators),
        pending_updates=list(chain_state._lifecycle_manager.pending_updates),
        vote_records=vote_records, activation_schedule=chain_state._lifecycle_manager.scheduled_updates,
        checkpoint_references=[]
    )
    state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)

    parent_snapshot = TauStateSnapshot(
        state_hash=state_hash,
        tau_bytes=app_rules,
        metadata={
            "source": "chain_state",
            "balances": chain_state._balances,
            "sequence_numbers": chain_state._sequence_numbers,
            "lifecycle_manager": chain_state._lifecycle_manager,
        }
    )

    working_balances = deepcopy(chain_state._balances)
    working_sequences = deepcopy(chain_state._sequence_numbers)
    working_lifecycle = deepcopy(chain_state._lifecycle_manager)

    for tx in transactions:
        operations = tx.get("operations", {}) if isinstance(tx, dict) else {}
        transfers = operations.get("1") if isinstance(operations, dict) else None
        if not isinstance(transfers, list) or not transfers:
            continue
        custom_inputs: dict[int, list[str]] = {}
        for key, value in operations.items():
            if not isinstance(key, str) or not key.isdigit():
                continue
            idx = int(key)
            if idx in (0, 1):
                continue
            if isinstance(value, (str, int)):
                custom_inputs[idx] = [str(value)]
            elif isinstance(value, (list, tuple)):
                custom_inputs[idx] = [str(item) for item in value]
        try:
            from_addr, to_addr, amount = transfers[0]
            tau_input_stream_values = {
                1: str(amount),
                2: str(working_balances.get(str(from_addr), chain_state.get_balance(str(from_addr)))),
                3: "0",
                4: "0",
                5: str(block_timestamp),
            }
            tau_input_stream_values.update(custom_inputs)
            tau_manager.communicate_with_tau_multi(
                input_stream_values=tau_input_stream_values,
                apply_rules_update=False,
            )
        except Exception:
            pass

    engine = TauConsensusEngine()
    exec_result = engine.apply(
        parent_snapshot,
        transactions,
        block_timestamp,
        target_balances=working_balances,
        target_sequences=working_sequences,
        target_lifecycle=working_lifecycle,
    )

    accepted = {id(tx) for tx in exec_result.accepted_transactions}
    final_txs = []
    final_reserved_ids = []
    for tx, reserved_id in zip(transactions, reserved_ids):
        if id(tx) in accepted:
            final_txs.append(tx)
            final_reserved_ids.append(reserved_id)

    final_rules = exec_result.snapshot.tau_bytes.decode('utf-8', errors='ignore')
    return final_txs, final_reserved_ids, final_rules, working_balances, working_sequences


def create_block_from_mempool() -> Dict:
    """
    Creates a new block from all transactions currently in the mempool,
    saves it to the database, and clears the mempool.
    """
    print(f"[INFO][createblock] Starting block creation process...")

    if not config.MINER_PRIVKEY:
        print("[ERROR][createblock] PoA mining requires MINER_PRIVKEY to be configured.")
        return {"error": "PoA mining requires a configured miner key."}

    if not _BLS_AVAILABLE:
        print("[ERROR][createblock] BLS signing not available; cannot sign PoA block.")
        return {"error": "BLS signing is required for PoA blocks."}
    
    # Ensure early turn-check and block number logic happens BEFORE reserving mempool
    latest_block = db.get_canonical_head_block()
    if latest_block:
        block_number = latest_block['header']['block_number'] + 1
        previous_hash = latest_block['block_hash']
    else:
        # Genesis block
        block_number = 0
        previous_hash = "0" * 64

    from consensus.engine import TauConsensusEngine
    engine = TauConsensusEngine()
    
    current_time = int(time.time())
    if not engine.query_eligibility(config.MINER_PUBKEY, block_number, current_time, previous_hash):
        msg = f"Not our turn to mine block #{block_number} according to Tau consensus."
        print(f"[INFO][createblock] {msg}")
        return {"message": msg}

    from chain_state import _chain_lock
    with _chain_lock:
        # Get batch of reserved transactions from mempool
        reserved_txs = db.reserve_mempool_txs(limit=1000)
        print(f"[INFO][createblock] Reserved {len(reserved_txs)} entries from mempool")

        if not reserved_txs:
            print("[INFO][createblock] Mempool is empty (no pending txs). Proceeding to create an empty block.")
    
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
    
    if reserved_ids and not transactions:
        print("[INFO][createblock] No valid transactions parsed. Cleared reserved.")
        import db as _db
        _db.remove_transactions(reserved_ids)
    
    print(f"[INFO][createblock] Validating and Executing Batch Natively...")
    block_timestamp = int(time.time())
    
    try:
        from consensus.engine import TauConsensusEngine
        from consensus.state import TauStateSnapshot, compute_consensus_meta_hash, compute_consensus_state_hash
        from chain_state import compute_accounts_hash
        
        # 1. Load canonical parent snapshot
        app_rules = (chain_state._application_rules_state or "").encode('utf-8')
        cons_rules = (chain_state._consensus_rules_state or "").encode('utf-8')
        acc_hash = compute_accounts_hash(chain_state._balances, chain_state._sequence_numbers)
        vote_records = [(k, pub) for k, v in chain_state._lifecycle_manager.votes.items() for pub in v]
        meta_hash = compute_consensus_meta_hash(
            host_contract={}, active_validators=list(chain_state._lifecycle_manager.active_validators),
            pending_updates=list(chain_state._lifecycle_manager.pending_updates),
            vote_records=vote_records, activation_schedule=chain_state._lifecycle_manager.scheduled_updates,
            checkpoint_references=[]
        )
        state_hash = compute_consensus_state_hash(cons_rules, app_rules, acc_hash, meta_hash)
        
        parent_snapshot = TauStateSnapshot(
            state_hash=state_hash,
            tau_bytes=app_rules,
            metadata={
                "source": "chain_state",
                "balances": chain_state._balances,
                "sequence_numbers": chain_state._sequence_numbers,
                "lifecycle_manager": chain_state._lifecycle_manager,
                "active_consensus_id": chain_state._active_consensus_id
            }
        )
        
        engine = TauConsensusEngine()
        
        # 2. Derive active_view for next height
        active_view = engine.derive_active_consensus(parent_snapshot, block_number)
        
        # 3. Simulate Candidate using apply_block() natively
        # We need a candidate block body structure.
        candidate_block = block.Block.create(
            block_number=block_number,
            previous_hash=previous_hash,
            transactions=transactions,
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=block_timestamp,
            state_hash=''
        )
        
        # Call the unified path
        apply_result = engine.apply_block(active_view, candidate_block, parent_snapshot)
        
        # Extract accepted/skipped outcomes
        final_txs = []
        final_reserved_ids = []
        
        for i, tx in enumerate(transactions):
             tx_id = tx.get('tx_id')
             if tx_id in apply_result.accepted_tx_ids or tx_id in apply_result.skipped_tx_ids:
                 final_txs.append(tx)
             # Whether applied, skipped, or structurally invalid, we dispose of them from mempool!
             if tx_id in apply_result.accepted_tx_ids or tx_id in apply_result.skipped_tx_ids or tx_id in apply_result.invalid_tx_ids:
                 final_reserved_ids.append(filtered_reserved_ids[i])
                 
        print(f"[INFO][createblock] Execution Result: {len(final_txs)}/{len(transactions)} logically valid")
        # Removed check to allow creation of empty block
        # 4. Form Complete Valid Block Header
        candidate_block.transactions = final_txs
        # Update IDs
        candidate_block.tx_ids = [block.compute_tx_hash(tx) for tx in final_txs]
        candidate_block.header.merkle_root = block.compute_merkle_root(candidate_block.tx_ids)
        candidate_block.header.state_hash = apply_result.next_snapshot.state_hash
        candidate_block.header.state_locator = f"{config.STATE_LOCATOR_NAMESPACE}:{apply_result.next_snapshot.state_hash}"
        candidate_block.block_hash = block.sha256_hex(candidate_block.header.canonical_bytes())
        
        # Generate Consensus Proof (PoA)
        try:
            from py_ecc.bls import G2Basic
            import hashlib
            msg_hash = hashlib.sha256(candidate_block.header.canonical_bytes()).digest()
            if not getattr(config, "MINER_PRIVKEY", None):
                raise ValueError("MINER_PRIVKEY not configured")
            sig_bytes = G2Basic.Sign(int(config.MINER_PRIVKEY, 16), msg_hash)
            candidate_block.consensus_proof = sig_bytes.hex()
        except Exception as e:
            print(f"[ERROR][createblock] Failed to generate consensus proof: {e}")
            import db as _db
            _db.unreserve_mempool_txs(reserved_ids)
            return {"error": f"Failed to sign block: {e}"}

        # 5. Full Final Acceptance Path
        # The node runs standard process_new_block ingestion as if we imported it over network.
        # This guarantees path equivalence.
        if not chain_state.process_new_block(candidate_block):
             import db as _db
             _db.unreserve_mempool_txs(reserved_ids)
             return {"error": "Failed to persist new canonical block"}
             
        # 6. Mempool Disposition
        if final_reserved_ids:
             import db as _db
             _db.remove_transactions(final_reserved_ids)
             
        new_block = candidate_block # map for existing return variable
    except Exception as e:
        print(f"[ERROR][createblock] Block creation failed during native simulation: {e}")
        import db as _db
        _db.unreserve_mempool_txs(reserved_ids)
        return {"error": str(e)}
        
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
