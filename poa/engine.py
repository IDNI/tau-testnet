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
        # Validator set: currently just the configured miner public key
        self._validators: Set[str] = {config.MINER_PUBKEY} if config.MINER_PUBKEY else set()

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

        # Verify the signature itself
        # Block.verify_signature() checks against config.MINER_PUBKEY by default.
        # If we had multiple validators, we would need to recover the signer or check against each.
        # For now, we assume the block class handles the crypto check against the configured miner.
        if not block.verify_signature():
            logger.warning("PoA: Block #%s signature verification failed", block.header.block_number)
            return False

        # If we had dynamic validators, we would check if the signer is in self._validators here.
        # Since verify_signature uses MINER_PUBKEY and self._validators contains MINER_PUBKEY,
        # it is implicitly checked.

        return True

    def apply(
        self,
        snapshot: TauStateSnapshot,
        transactions: Sequence[Dict[str, Any]],
    ) -> TauExecutionResult:
        """
        Apply transactions to the current state.
        
        This executes operations:
        - '0' (Rules): Sent to Tau process.
        - '1' (Transfers): Applied to chain_state balances.
        """
        import chain_state  # Import here to avoid circular dependency

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
            
            tx_success = True
            tx_receipt = {"logs": []}

            # Update sequence number
            sequence_number = tx.get('sequence_number')
            if sequence_number is not None and sender:
                # We need to check and update sequence number in chain_state
                # This is a bit tight coupling, but necessary for now.
                current_seq = chain_state.get_sequence_number(sender)
                if sequence_number == current_seq:
                    chain_state.increment_sequence_number(sender)
                else:
                    logger.warning("Sequence mismatch for %s: expected %s, got %s", sender, current_seq, sequence_number)
                    # Should we fail the tx? 
                    # Original code just warned but proceeded? 
                    # "Sequence mismatch ...: expected ..., had ..."
                    # It didn't seem to stop processing.
                    # But usually sequence mismatch invalidates tx.
                    # Let's fail it to be safe, or follow original behavior?
                    # Original code: print warning, then continue to process operations.
                    # So it didn't fail. We'll replicate that but maybe we should fail?
                    # For now, replicate.
                    pass

            # Process operations
            for op_key, op_data in operations.items():
                if op_key == "0": # Rule
                    if isinstance(op_data, str) and op_data.strip():
                        try:
                            # Send to Tau
                            # We assume tau_manager is ready or we wait?
                            # chain_state.rebuild_state_from_blockchain waits.
                            if not tau_manager.tau_ready.is_set():
                                # Try to wait a bit?
                                tau_manager.tau_ready.wait(timeout=5)
                            
                            if not tau_manager.tau_ready.is_set():
                                logger.error("Tau process not ready for rule execution")
                                tx_success = False
                                tx_receipt["logs"].append("Tau not ready")
                                break

                            output = tau_manager.communicate_with_tau(
                                rule_text=op_data.strip(), 
                                target_output_stream_index=0
                            )
                            
                            # Check output (simplified check)
                            if "error" in output.lower() and "x1001" not in output.lower():
                                # Basic error check, though Tau output format varies
                                # x1001 is success (ACK_RULE_PROCESSED)
                                logger.warning("Tau rejected rule: %s", output)
                                # For now, we might not fail the TX if Tau rejects, 
                                # or we might. Let's assume strictness.
                                # But historical blocks might have invalid rules?
                                # We'll log it.
                                tx_receipt["logs"].append(f"Tau output: {output}")
                            else:
                                # Prefer the persisted "updated specification" snapshot if available.
                                rules_text = None
                                try:
                                    candidate = getattr(chain_state, "get_rules_state", None)
                                    if callable(candidate):
                                        val = candidate()
                                        if isinstance(val, str):
                                            rules_text = val
                                except Exception:
                                    rules_text = None

                                if rules_text is not None:
                                    current_tau_bytes = rules_text.encode("utf-8")
                                else:
                                    # Fallback for tests/mocks: deterministic accumulation.
                                    current_tau_bytes += op_data.encode("utf-8")
                                tx_receipt["logs"].append("Rule applied")

                        except Exception as e:
                            logger.error("Error applying rule: %s", e)
                            tx_success = False
                            tx_receipt["logs"].append(f"Error: {e}")
                            break
                
                elif op_key == "1": # Transfer
                    if isinstance(op_data, list):
                        for transfer in op_data:
                            if isinstance(transfer, (list, tuple)) and len(transfer) == 3:
                                from_addr, to_addr, amount_val = transfer
                                try:
                                    amount = int(amount_val)
                                    # Use chain_state to update balances
                                    # Note: This modifies global state!
                                    # Ideally we should work on a copy or transactional state,
                                    # but for now we follow the existing pattern.
                                    if not chain_state.update_balances_after_transfer(from_addr, to_addr, amount):
                                        tx_success = False
                                        tx_receipt["logs"].append("Transfer failed")
                                        break
                                except Exception as e:
                                    logger.error("Error applying transfer: %s", e)
                                    tx_success = False
                                    break
                        if not tx_success:
                            break

            if tx_success:
                accepted_txs.append(tx)
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
