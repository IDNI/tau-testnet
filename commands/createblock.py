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
import api_response

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
        msg = "PoA mining requires a configured miner key."
        return {"error": msg, "message": msg}

    if not _BLS_AVAILABLE:
        print("[ERROR][createblock] BLS signing not available; cannot sign PoA block.")
        msg = "BLS signing is required for PoA blocks."
        return {"error": msg, "message": msg}
    
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
    reserved_hashes = [rtx.get('tx_hash') for rtx in reserved_txs]
    
    # Fix JSON alignment
    # We must filter reserved_ids and transactions in lockstep
    transactions = []
    execution_transactions = []
    filtered_reserved_ids = []
    skipped_count = 0
    
    for i, tx_data in enumerate(mempool_txs):
        r_id = reserved_ids[i]
        tx_hash = reserved_hashes[i]
        try:
            clean_data = tx_data
            if clean_data.startswith("json:"):
                clean_data = clean_data[5:]
            
            tx = json.loads(clean_data)
            # Ensure every tx has a stable identifier so the consensus engine can
            # report acceptance/rejection. Keep this synthetic ID out of the
            # persisted block body so tx_ids remains the canonical ID surface.
            execution_tx = dict(tx) if isinstance(tx, dict) else tx
            if isinstance(execution_tx, dict) and not execution_tx.get("tx_id") and tx_hash:
                execution_tx["tx_id"] = tx_hash
            transactions.append(tx)
            execution_transactions.append(execution_tx)
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
            transactions=execution_transactions,
            proposer_pubkey=config.MINER_PUBKEY,
            timestamp=block_timestamp,
            state_hash=''
        )
        
        # Call the unified path
        apply_result = engine.apply_block(active_view, candidate_block, parent_snapshot)
        
        # Extract accepted/skipped outcomes
        final_txs = []
        final_reserved_ids = []
        
        for i, tx in enumerate(execution_transactions):
             tx_id = tx.get('tx_id')
             if tx_id in apply_result.accepted_tx_ids or tx_id in apply_result.skipped_tx_ids:
                 final_txs.append(transactions[i])
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
            msg = f"Failed to sign block: {e}"
            return {"error": msg, "message": msg}

        # 5. Full Final Acceptance Path
        # The node runs standard process_new_block ingestion as if we imported it over network.
        # This guarantees path equivalence.
        if not chain_state.process_new_block(candidate_block):
             import db as _db
             # Return the full reserved batch to pending first, then drop any txs
             # we determined are safe to dispose (invalid/skipped/accepted) to avoid
             # poisoning the mempool with permanently-invalid transactions.
             _db.unreserve_mempool_txs(reserved_ids)
             if final_reserved_ids:
                 _db.remove_transactions(final_reserved_ids)
             msg = "Failed to persist new canonical block"
             return {"error": msg, "message": msg}
             
        # 6. Mempool Disposition
        if final_reserved_ids:
             import db as _db
             _db.remove_transactions(final_reserved_ids)
             
        new_block = candidate_block # map for existing return variable
    except Exception as e:
        print(f"[ERROR][createblock] Block creation failed during native simulation: {e}")
        import db as _db
        _db.unreserve_mempool_txs(reserved_ids)
        msg = str(e)
        return {"error": msg, "message": msg}
        
    print(f"[INFO][createblock] Block creation process completed!")
    return new_block.to_dict()


_CONFIG_ERROR_PREFIXES = ("PoA mining requires", "BLS signing is required")
_MINING_FAILED_PREFIXES = ("Failed to sign block", "Failed to persist")


def _classify_createblock_error(block_data: Dict) -> tuple[str, str]:
    err = block_data.get("error") or ""
    msg = block_data.get("message") or err or "Block creation failed."
    if err.startswith(_CONFIG_ERROR_PREFIXES) or msg.startswith(_CONFIG_ERROR_PREFIXES):
        return "MINING_CONFIG_ERROR", msg
    if err.startswith(_MINING_FAILED_PREFIXES) or msg.startswith(_MINING_FAILED_PREFIXES):
        return "MINING_FAILED", msg
    if msg.startswith("Not our turn"):
        return "MINING_NOT_ELIGIBLE", msg
    if "Mempool is empty" in msg:
        return "MEMPOOL_EMPTY", msg
    if err:
        return "MINING_FAILED", msg
    return "BLOCK_NOT_CREATED", msg


def execute(raw_command: str, container):
    """
    Executes the createblock command.
    """
    logger.info("Create block requested")
    try:
        block_data = create_block_from_mempool()
    except Exception as exc:
        logger.exception("Block creation failed")
        return api_response.error_response(
            "createblock", f"Failed to create block: {exc}", "MINING_FAILED"
        )

    if isinstance(block_data, dict) and "block_hash" in block_data:
        header = block_data.get("header", {})
        transactions = block_data.get("transactions", [])
        data = {
            "block_number": header.get("block_number"),
            "block_hash": block_data["block_hash"],
            "merkle_root": header.get("merkle_root"),
            "timestamp": header.get("timestamp"),
            "tx_count": len(transactions),
            "transactions": transactions,
        }
        logger.info("Block #%s created", header.get("block_number"))

        try:
            from network import bus
            service = bus.get()
            if service:
                service.broadcast_block(block_data)
                logger.info("Block #%s broadcasted to network", header.get("block_number"))
            else:
                logger.warning("Network service not available, block not broadcasted")
        except Exception:
            logger.exception("Failed to broadcast block")

        return api_response.success_response("createblock", data)

    if not isinstance(block_data, dict):
        return api_response.error_response(
            "createblock", "Block creation returned no data.", "BLOCK_NOT_CREATED"
        )

    code, message = _classify_createblock_error(block_data)
    logger.info("Create block skipped: %s (%s)", message, code)
    return api_response.error_response("createblock", message, code)
