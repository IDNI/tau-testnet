from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import config
from .tau_engine import TauEngine, TauExecutionResult, TauStateSnapshot
from .state import StateStore, compute_state_hash

# We need to import chain_state and tau_manager, but we must be careful about circular imports.
# We'll import them inside methods or use a lazy import pattern if needed.
import tau_manager
# chain_state will be imported inside methods to avoid circular dependency if chain_state imports this module.

logger = logging.getLogger(__name__)

class PoATauEngine(TauEngine):
    """
    Proof-of-Authority implementation of the Tau Engine.
    
    Handles:
    1. Block signature verification (PoA consensus).
    2. Transaction execution (delegating to Tau process and chain state).
    """

    def __init__(self, state_store: Optional[StateStore] = None) -> None:
        self._state_store = state_store or StateStore()
        # Validator set: strictly ordered list of public keys representing the round robin schedule
        self._validators: List[str] = list(getattr(config, "MINER_PUBKEYS", []) or [])
        if not self._validators and config.MINER_PUBKEY:
             self._validators = [config.MINER_PUBKEY]

    def is_validator(self, pubkey: str) -> bool:
        """Check if a public key belongs to an authorized validator."""
        return pubkey in self._validators

    def verify_block(self, block: Any) -> bool:
        """
        Verify that the block is signed by a valid validator.
        
        Args:
            block: A Block object (duck-typed, expected to have verify_signature and block_signature).
        """
        if not block.block_signature:
            logger.warning("PoA: Block #%s has no signature", block.header.block_number)
            return False

        # Determine expected miner for this block height (Round Robin)
        if not self._validators:
            logger.warning("PoA: No validators configured.")
            return False
            
        expected_miner_index = block.header.block_number % len(self._validators)
        expected_miner = self._validators[expected_miner_index]

        # Verify the signature against the expected round-robin miner
        if not block.verify_signature(miner_pubkey=expected_miner):
            logger.warning("PoA: Block #%s signature verification failed. Expected miner: %s", block.header.block_number, expected_miner[:10])
            return False

        return True

    def apply(
        self,
        snapshot: TauStateSnapshot,
        transactions: Sequence[Dict[str, Any]],
        block_timestamp: int | None = None,
        target_balances: Optional[Dict[str, int]] = None,
        target_sequences: Optional[Dict[str, int]] = None,
    ) -> TauExecutionResult:
        """
        Apply transactions to the current state.
        
        This executes operations:
        - '0' (Rules): Sent to Tau process.
        - '1' (Transfers): Applied to chain_state balances.
        """
        import chain_state  # Import here to avoid circular dependency

        if block_timestamp is None:
            block_timestamp = 0

        accepted_txs = []
        rejected_txs = []
        receipts = {}

        # Track the serialized Tau/rules snapshot bytes.
        # In production, `tau_manager` prints the normalized updated specification
        # after successful pointwise revision; `chain_state.save_rules_state(...)`
        # persists that string. When that is available, we use it to build the
        # snapshot. In tests/mocks (no rules handler), fall back to concatenating
        # rule payloads for determinism.
        current_tau_bytes = snapshot.tau_bytes

        for i, tx in enumerate(transactions):
            tx_id = tx.get('tx_id', str(i)) # Fallback if no ID
            operations = tx.get('operations', {})
            sender = tx.get('sender_pubkey')
            
            # By default, we consider the transaction valid for inclusion unless strictly malformed
            # (e.g. signature issues are handled in verify_block, here we might assume validity).
            # However, historically we used tx_success to mean "execution successful".
            # We now split this:
            # - accepted_in_block: True (unless we decide it's total garbage)
            # - execution_success: True/False
            
            accepted_in_block = True
            execution_success = True
            tx_receipt = {"logs": []}

            # Sequence number handling: only increment if the tx is included/accepted.
            sequence_number = tx.get('sequence_number')
            should_increment_seq = False
            if sequence_number is not None and sender:
                if target_sequences is not None:
                    current_seq = target_sequences.get(sender, 0)
                else:
                    current_seq = chain_state.get_sequence_number(sender)
                    
                if sequence_number == current_seq:
                    should_increment_seq = True
                else:
                    logger.warning(
                        "Sequence mismatch for %s: expected %s, got %s",
                        sender,
                        current_seq,
                        sequence_number,
                    )
                    # Keep legacy behavior: do not hard-fail here, but also do not increment.

            # Process operations
            # Parse operations first to establish deterministic order:
            # 1. Rule update (key "0")
            # 2. Custom inputs (keys >= 5)
            # 3. Transfers (key "1") - applied last to state, though input validation happened upstream

            rule_op_data = operations.get("0")
            transfers_op_data = operations.get("1")
            
            custom_tau_inputs: dict[int, list[str]] = {}
            reserved_error = None
            
            for k, v in operations.items():
                if k.isdigit():
                    idx = int(k)
                    import tau_defs
                    if idx in (0, 1):
                        continue
                    if idx in tau_defs.RESERVED_STREAMS:
                         reserved_error = f"Operation key '{k}' matches reserved stream {idx}."
                         break
                    
                    # Normalize value
                    normalized_val = []
                    valid_type = True
                    if isinstance(v, (str, int)):
                        normalized_val.append(str(v))
                    elif isinstance(v, (list, tuple)):
                        for item in v:
                            if isinstance(item, (str, int)):
                                normalized_val.append(str(item))
                            else:
                                valid_type = False
                                break
                    else:
                        valid_type = False
                    
                    if not valid_type:
                        reserved_error = f"Invalid value type for stream {idx}."
                        break
                    
                    custom_tau_inputs[idx] = normalized_val

            if reserved_error:
                logger.error("Transaction invalid: %s", reserved_error)
                execution_success = False
                tx_receipt["logs"].append(f"Error: {reserved_error}")
            else:
                # --- Step 1: Rule Execution ---
                if rule_op_data is not None:
                     if isinstance(rule_op_data, str) and rule_op_data.strip():
                        try:
                            # Wait for Tau availability logic
                            if not tau_manager.tau_ready.is_set():
                                tau_manager.tau_ready.wait(timeout=5)
                            
                            if not tau_manager.tau_ready.is_set():
                                logger.error("Tau process not ready for rule execution")
                                execution_success = False
                                tx_receipt["logs"].append("Tau not ready")
                                # Skip further processing if Tau is down
                            else:
                                output = tau_manager.communicate_with_tau(
                                    rule_text=rule_op_data.strip(), 
                                    target_output_stream_index=0,
                                    apply_rules_update=True # Apply update for consensus
                                )
                                
                                tx_receipt["logs"].append(f"Tau(rule) o0: {output}")

                                if "error" in output.lower() and "x1001" not in output.lower():
                                    logger.warning("Tau rejected rule: %s", output)
                                    execution_success = False
                                    tx_receipt["logs"].append(f"Error: Tau rejected rule output: {output}")

                                # Persist updated rules state
                                rules_text = None
                                try:
                                    # Try to fetch authoritative state from global tracker (updated by handler)
                                    val = chain_state.get_rules_state() if hasattr(chain_state, "get_rules_state") else None
                                    if isinstance(val, str):
                                        rules_text = val
                                except Exception:
                                    pass

                                if rules_text is not None:
                                    current_tau_bytes = rules_text.encode("utf-8")
                                else:
                                    # Fallback
                                    current_tau_bytes += rule_op_data.encode("utf-8")
                                tx_receipt["logs"].append("Rule applied")

                        except Exception as e:
                            logger.error("Error applying rule: %s", e)
                            execution_success = False
                            tx_receipt["logs"].append(f"Error: {e}")

                # --- Step 2 & 3: Unified Custom Inputs & Transfers ---
                if execution_success and transfers_op_data is not None:
                    if isinstance(transfers_op_data, list):
                        for transfer in transfers_op_data:
                            if isinstance(transfer, (list, tuple)) and len(transfer) == 3:
                                from_addr, to_addr, amount_val = transfer
                                try:
                                    amount = int(amount_val)
                                    
                                    # Simulate miner unified execution parity
                                    # We don't need 'remaining' balance or 'IDs' accurately in replay
                                    # because the transaction was already accepted. But to ensure
                                    # perfect semantic parity as requested, we construct the input map.
                                    # Replay strictly mirrors mining execution logic without actually 
                                    # failing if Tau fails it (as block was already valid), but we run it
                                    # to ensure identical side-effects (if any) and identical log output.
                                    
                                    tau_input_stream_values = {
                                        1: str(amount),
                                        2: "0",  # Mock balance for replay
                                        3: "0",  # Mock IDs for replay
                                        4: "0",
                                    }
                                    for k, v in custom_tau_inputs.items():
                                        tau_input_stream_values[k] = v
                                    tau_input_stream_values[5] = str(block_timestamp)

                                    if tau_manager.tau_ready.is_set():
                                        tau_output_transfer = tau_manager.communicate_with_tau(
                                            target_output_stream_index=1,
                                            input_stream_values=tau_input_stream_values,
                                            apply_rules_update=False,
                                        )
                                        tx_receipt["logs"].append(f"Tau(transfer) o1: {tau_output_transfer}")
                                    
                                    if target_balances is not None:
                                        # Use isolated balance tracking
                                        current_from = target_balances.get(from_addr, 0)
                                        if from_addr not in target_balances and getattr(config, "TESTNET_AUTO_FAUCET", False):
                                            current_from = 1000
                                            
                                        if current_from < amount:
                                            logger.error("Insufficient funds for %s to send %s. Has: %s.", from_addr[:10], amount, current_from)
                                            execution_success = False
                                            tx_receipt["logs"].append("Transfer balance state failed (insufficient)")
                                            break
                                            
                                        current_to = target_balances.get(to_addr, 0)
                                        target_balances[from_addr] = current_from - amount
                                        target_balances[to_addr] = current_to + amount
                                    else:
                                        if not chain_state.update_balances_after_transfer(from_addr, to_addr, amount):
                                            execution_success = False
                                            tx_receipt["logs"].append("Transfer balance state failed")
                                            break
                                except Exception as e:
                                    logger.error("Error applying transfer: %s", e)
                                    execution_success = False
                                    break
                        # Loop finishes, check if we broke out
                    else:
                        # logical error in tx format (should be caught by verify usually)
                        pass
                
                # --- Step 4: Unified Custom Execution (if no transfers were present) ---
                if execution_success and not transfers_op_data and (custom_tau_inputs or rule_op_data is not None):
                    try:
                         unified_inputs = {}
                         for k, v in custom_tau_inputs.items():
                             unified_inputs[k] = v
                         unified_inputs[5] = str(block_timestamp)
                         
                         if tau_manager.tau_ready.is_set():
                             res_eval = tau_manager.communicate_with_tau(
                                 target_output_stream_index=0,
                                 input_stream_values=unified_inputs,
                                 apply_rules_update=False
                             )
                             tx_receipt["logs"].append(f"Tau(custom_unified) o0: {res_eval}")
                             if "error" in res_eval.lower():
                                 tx_receipt["logs"].append(f"Custom logic error: {res_eval}")
                                 execution_success = False
                    except Exception as e:
                         logger.error("Error applying unified custom log: %s", e)
                         execution_success = False
                         tx_receipt["logs"].append(f"Error (unified custom): {e}")

            if accepted_in_block:
                if should_increment_seq and sender:
                    try:
                        if target_sequences is not None:
                            target_sequences[sender] = target_sequences.get(sender, 0) + 1
                        else:
                            chain_state.increment_sequence_number(sender)
                    except Exception:
                        logger.error("Failed to increment sequence number for %s", sender, exc_info=True)
                        tx_receipt["logs"].append("Error: failed to increment sequence number")
                        # execution_success = False ? No, sequence failure is bad but processed.

            if accepted_in_block:
                accepted_txs.append(tx)
                status = "success" if execution_success else "failed"
                tx_receipt["status"] = status
                receipts[tx_id] = tx_receipt
            else:
                rejected_txs.append(tx)
                receipts[tx_id] = {"status": "failed", "logs": tx_receipt["logs"]}

        # Create new snapshot
        new_snapshot = TauStateSnapshot(
            state_hash=compute_state_hash(current_tau_bytes),
            tau_bytes=current_tau_bytes,
            metadata={**snapshot.metadata, "poa": True, "last_tx_count": len(accepted_txs)},
        )
        
        return TauExecutionResult(
            snapshot=self._state_store.commit(new_snapshot),
            accepted_transactions=accepted_txs,
            rejected_transactions=rejected_txs,
            receipts=receipts,
        )
