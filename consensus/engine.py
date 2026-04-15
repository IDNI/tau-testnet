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

from dataclasses import dataclass
from abc import ABC, abstractmethod

@dataclass
class ActiveConsensusView:
    """
    Represents the active consensus policy to be used for block validation.
    Derived purely from a parent snapshot state.
    """
    target_height: int
    consensus_rules: str
    active_validators: List[bytes]
    mechanism_specific_metadata: Optional[Dict[str, Any]] = None

@dataclass
class TransactionOutcome:
    tx_id: str
    status: str # "applied", "skipped", "invalid"
    reason: Optional[str] = None
    receipt_logs: List[str] = None

@dataclass
class ApplyBlockResult:
    next_snapshot: TauStateSnapshot
    outcomes: List[TransactionOutcome]
    accepted_tx_ids: List[str]
    skipped_tx_ids: List[str]
    invalid_tx_ids: List[str]
    governance_changes: Dict[str, Any]
    mempool_hints: Dict[str, Any]


class ConsensusEngine(ABC):
    """
    Defines the contract for the Tau-driven consensus processing paths.
    Unifies mining, import, replay, and reorg behind a single interface.
    """
    
    @abstractmethod
    def derive_active_consensus(self, parent_snapshot: TauStateSnapshot, target_height: int) -> ActiveConsensusView:
        """
        Pure, read-only derivation of the active consensus view for the target height.
        MUST NOT mutate any state objects or perform archival transitions.
        """
        pass
        
    @abstractmethod
    def verify_block_header(self, active_view: ActiveConsensusView, block: Any, proof_result: Dict[str, Any]) -> bool:
        """
        Complete consensus-verdict step. Encompasses proof result consumption and 
        Tau policy evaluation yielding the final block validity (o6).
        Returns True if the block is accepted.
        """
        pass
        
    @abstractmethod
    def apply_block(
        self,
        active_view: ActiveConsensusView,
        block: Any,
        parent_snapshot: TauStateSnapshot,
        *,
        replay_mode: bool = False,
    ) -> ApplyBlockResult:
        """
        Apply the valid block payload over the active view to produce the next 
        committed snapshot. This includes archival transitions.
        """
        pass
        
    @abstractmethod
    def query_eligibility(self, active_view: ActiveConsensusView, local_pubkey: str, target_height: int, now_ts: int) -> bool:
        """
        Query whether the given identity is eligible to propose the block at the target height 
        and time, according to Tau policy (o7).
        """
        pass

class TauConsensusEngine(TauEngine, ConsensusEngine):
    """
    Legacy and transition implementation of the Tau Engine and new Consensus Engine contract.
    
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

    # --- ConsensusEngine Interface Implementation ---

    def derive_active_consensus(self, parent_snapshot: TauStateSnapshot, target_height: int) -> ActiveConsensusView:
        # Skeleton implementation for Phase 1
        # In Phase 2, this will traverse the consensus_meta to build the view. 
        # For now, it delegates to PoA parameters.
        return ActiveConsensusView(
            target_height=target_height,
            consensus_rules=parent_snapshot.tau_bytes.decode('utf-8', errors='ignore'),
            active_validators=[bytes.fromhex(v) for v in self._validators],
            mechanism_specific_metadata={"poa": True}
        )

    def verify_block_header(self, *args, **kwargs) -> bool:
        """
        Verify that the block header meets the consensus proof requirements.
        Supports both Phase 1 legacy signature and new ConsensusEngine signature.
        """
        if len(args) > 0 and isinstance(args[0], ActiveConsensusView) or "active_view" in kwargs:
            # Phase 2+ new signature: (active_view, block, proof_result)
            proof_result = kwargs.get("proof_result") if "proof_result" in kwargs else (args[2] if len(args) > 2 else {})
            if proof_result.get("proof_ok", False) is False:
                return False
            block = kwargs.get("block") if "block" in kwargs else (args[1] if len(args) > 1 else None)
        else:
            # Phase 1 Legacy Signature: (block)
            block = args[0] if len(args) > 0 else kwargs.get("block")

        if block and not block.consensus_proof:
            logger.warning("Consensus: Block #%s has no consensus proof", block.header.block_number)
            return False

        if not tau_manager.tau_ready.is_set():
            logger.error("Consensus: Tau not ready for block verification.")
            return False
            
        i2_inputs = [
            block.header.proposer_pubkey,
            str(block.header.block_number),
            str(block.header.timestamp),
            block.header.previous_hash
        ]
        try:
            output = tau_manager.communicate_with_tau(
                target_output_stream_index=7,
                input_stream_values={2: i2_inputs},
                apply_rules_update=False
            )
            if "require_bls_sig" in output:
                try:
                    from py_ecc.bls import G2Basic
                    import hashlib
                    block_sig = block.consensus_proof
                    if isinstance(block_sig, dict):
                        block_sig = block_sig.get("signature")
                    if not block_sig:
                        logger.warning("Consensus: Block #%s missing cryptographic proof", block.header.block_number)
                        return False
                    msg_hash = hashlib.sha256(block.header.canonical_bytes()).digest()
                    pubkey_bytes = bytes.fromhex(block.header.proposer_pubkey)
                    sig_bytes = bytes.fromhex(block_sig)
                    if not G2Basic.Verify(pubkey_bytes, msg_hash, sig_bytes):
                        logger.warning("Consensus: Block #%s cryptographic proof failed", block.header.block_number)
                        return False
                except Exception as e:
                    logger.warning("Consensus: Block #%s cryptographic proof error: %s", block.header.block_number, e)
                    return False
                return True
            
            logger.warning("Consensus: Block #%s rejected by Tau rules (o7: %s)", block.header.block_number, output)
            return False
        except Exception as e:
            logger.error("Header verification failed: %s", e)
            return False

    def apply_block(
        self,
        active_view: ActiveConsensusView,
        block: Any,
        parent_snapshot: TauStateSnapshot,
        *,
        replay_mode: bool = False,
    ) -> ApplyBlockResult:
        """
        Executes a full block over the consensus boundaries.
        Unifies Rebuild, Process Block, and Mining paths.
        Pure Implementation: Operates on state passed implicitly through parent_snapshot.metadata and returns ApplyBlockResult.
        """
        import copy
        from consensus.state import compute_consensus_meta_hash, compute_consensus_state_hash
        from chain_state import compute_accounts_hash
        import chain_state

        # 1. State Extraction
        metadata = parent_snapshot.metadata
        t_bals = copy.deepcopy(metadata.get('balances', {}))
        t_seqs = copy.deepcopy(metadata.get('sequence_numbers', {}))
        
        # Make a deep copy of the lifecycle manager or instantiate a snapshot equivalent
        parent_lm = metadata.get('lifecycle_manager')
        if parent_lm:
            # Reconstruct an isolated instance 
            lm = copy.deepcopy(parent_lm)
        else:
            # Fallback if somehow not provided (tests, legacy)
            from consensus.governance import ConsensusLifecycleManager
            lm = ConsensusLifecycleManager(active_validators=[bytes.fromhex(v) for v in self._validators])
        
        # 2. Pure Transaction Simulation (Internal Layer)
        # We pass target_balances and target_sequences to self.apply which mutates them internally.
        # This acts as our pure executor since t_bals/t_seqs are local copies.
        exec_result = self.apply(
            parent_snapshot,
            block.transactions,
            block.header.timestamp,
            target_balances=t_bals,
            target_sequences=t_seqs,
            target_lifecycle=lm,
            replay_mode=replay_mode,
        )
        
        # Convert internal apply result into structural outcomes
        outcomes = []
        accepted_ids = []
        skipped_ids = []
        
        for tx in block.transactions:
            tx_id = tx.get('tx_id')
            if tx in exec_result.accepted_transactions:
                # We consider all accepted ones as "applied" or "skipped/no-op"
                # Internal execution logs tell us if it was essentially a no-op 
                status = "applied"
                receipt = exec_result.receipts.get(tx_id, {})
                logs = receipt.get("logs", [])
                if any("valid no-op" in log.lower() or "ignored" in log.lower() for log in logs):
                    status = "skipped/no-op"
                    skipped_ids.append(tx_id)
                else:
                    accepted_ids.append(tx_id)
                    
                outcomes.append(TransactionOutcome(tx_id=tx_id, status=status, receipt_logs=logs))
            elif tx in exec_result.rejected_transactions:
                status = "invalid"
                receipt = exec_result.receipts.get(tx_id, {})
                outcomes.append(TransactionOutcome(tx_id=tx_id, status=status, reason=receipt.get("error"), receipt_logs=receipt.get("logs", [])))

        # 3. Post-State Materialization Layer
        
        # The rules are updated by self.apply (it returns a generic snapshot with tau_bytes).
        next_app_rules = exec_result.snapshot.tau_bytes.decode('utf-8', errors='ignore')
        
        # Governance Height Transitions
        newly_active = lm.process_height_transitions(block.header.block_number)
        next_cons_rules = active_view.consensus_rules
        if newly_active:
             last_update = newly_active[-1]
             # Update consensus rules string based on combined revisions
             next_cons_rules = "\\n".join(last_update.rule_revisions)
        
        # Finalize Hashes
        acc_hash = compute_accounts_hash(t_bals, t_seqs)
        vote_records = [(k, pub) for k, v in lm.votes.items() for pub in v]
        meta_hash = compute_consensus_meta_hash(
            host_contract={}, active_validators=list(lm.active_validators),
            pending_updates=list(lm.pending_updates),
            vote_records=vote_records, activation_schedule=lm.scheduled_updates,
            checkpoint_references=[]
        )
        state_hash = compute_consensus_state_hash(next_cons_rules.encode('utf-8'), next_app_rules.encode('utf-8'), acc_hash, meta_hash)
        
        # 4. Construct Next Snapshot
        next_snapshot = TauStateSnapshot(
            state_hash=state_hash,
            tau_bytes=next_app_rules.encode('utf-8'),
            metadata={
                "source": "engine_apply_block",
                "balances": t_bals,
                "sequence_numbers": t_seqs,
                "lifecycle_manager": lm,
                "consensus_rules_state": next_cons_rules
            }
        )
        
        return ApplyBlockResult(
            next_snapshot=next_snapshot,
            outcomes=outcomes,
            accepted_tx_ids=accepted_ids,
            skipped_tx_ids=skipped_ids,
            invalid_tx_ids=[tx.get('tx_id') for tx in exec_result.rejected_transactions],
            governance_changes={"activated_updates": [u.update_id_hex for u in newly_active]},
            mempool_hints={"safe_to_drop": accepted_ids + skipped_ids}
        )

    def query_eligibility(self, *args, **kwargs) -> bool:
        """
        Check if we are eligible to propose the next block by dry-running consensus logic.
        Supports both Phase 1 legacy signature and new ConsensusEngine signature.
        """
        if len(args) > 0 and isinstance(args[0], ActiveConsensusView) or "active_view" in kwargs:
            # new signature: (active_view, local_pubkey, target_height, now_ts)
            my_pubkey = kwargs.get("local_pubkey") if "local_pubkey" in kwargs else (args[1] if len(args) > 1 else "")
            block_number = kwargs.get("target_height") if "target_height" in kwargs else (args[2] if len(args) > 2 else 0)
            timestamp = kwargs.get("now_ts") if "now_ts" in kwargs else (args[3] if len(args) > 3 else 0)
            previous_hash = "0" * 64
        else:
            # legacy signature: (my_pubkey, block_number, timestamp, previous_hash)
            my_pubkey = args[0] if len(args) > 0 else kwargs.get("my_pubkey")
            block_number = args[1] if len(args) > 1 else kwargs.get("block_number")
            timestamp = args[2] if len(args) > 2 else kwargs.get("timestamp")
            previous_hash = args[3] if len(args) > 3 else kwargs.get("previous_hash")

        if not tau_manager.tau_ready.is_set():
            return False
            
        i2_inputs = [my_pubkey, str(block_number), str(timestamp), previous_hash]
        try:
            output = tau_manager.communicate_with_tau(
                target_output_stream_index=7,
                input_stream_values={2: i2_inputs},
                apply_rules_update=False
            )
            if "require_bls_sig" in output:
                return True
            return False
        except Exception as e:
            logger.error("Eligibility query failed: %s", e)
            return False

    def apply(
        self,
        snapshot: TauStateSnapshot,
        transactions: Sequence[Dict[str, Any]],
        block_timestamp: int | None = None,
        target_balances: Optional[Dict[str, int]] = None,
        target_sequences: Optional[Dict[str, int]] = None,
        target_lifecycle: Optional[Any] = None,
        replay_mode: bool = False,
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
            
        lifecycle_mgr = target_lifecycle if target_lifecycle is not None else chain_state._lifecycle_manager

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
            hard_reject = False
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
                    accepted_in_block = False
                    hard_reject = True
                    execution_success = False
                    tx_receipt["logs"].append(
                        f"Invalid sequence number: expected {current_seq}, got {sequence_number}"
                    )

            # Process operations
            # Parse operations first to establish deterministic order:
            # 1. Rule update (key "0")
            # 2. Custom inputs (keys >= 5)
            # 3. Transfers (key "1") - applied last to state, though input validation happened upstream

            tx_type = tx.get('tx_type', 'user_tx')
            
            rule_op_data = None
            transfers_op_data = None
            custom_tau_inputs: dict[int, list[str]] = {}
            reserved_error = None

            from consensus.governance import parse_consensus_rule_update, parse_consensus_rule_vote
            
            if tx_type == 'consensus_rule_update':
                update = parse_consensus_rule_update(tx)
                if update:
                    if lifecycle_mgr.can_admit_update(update, is_mempool=False):
                        if lifecycle_mgr.submit_update(update):
                            tx_receipt["logs"].append("Update submitted: " + update.update_id_hex)
                        else:
                            tx_receipt["logs"].append("Duplicate update ignored: " + update.update_id_hex)
                    else:
                        tx_receipt["logs"].append("Update rejected by strict admission")
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                else:
                    tx_receipt["logs"].append("Invalid update format")
                    accepted_in_block = False # Structural invalidity rejects entirely in most chains

            elif tx_type == 'consensus_rule_vote':
                vote = parse_consensus_rule_vote(tx)
                if vote and sender:
                    if lifecycle_mgr.can_admit_vote(vote, sender, is_mempool=False):
                        if lifecycle_mgr.submit_vote(vote, sender):
                            tx_receipt["logs"].append(f"Vote accepted for update {vote.update_id.hex()}")
                        else:
                            tx_receipt["logs"].append("Vote ignored (valid no-op)")
                    else:
                        tx_receipt["logs"].append("Vote rejected by strict admission")
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                else:
                    tx_receipt["logs"].append("Invalid vote format")
                    accepted_in_block = False
            else:
                # user_tx
                rule_op_data = operations.get("0")
                transfers_op_data = operations.get("1")
                
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
                accepted_in_block = False
                hard_reject = True
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
                                        if from_addr in target_balances:
                                            current_from = target_balances[from_addr]
                                        else:
                                            current_from = chain_state.get_balance(from_addr)
                                        
                                        if current_from == 0 and getattr(config, "TESTNET_AUTO_FAUCET", False):
                                            current_from = 1000
                                            
                                        if current_from < amount:
                                            logger.error("Insufficient funds for %s to send %s. Has: %s.", from_addr[:10], amount, current_from)
                                            if not replay_mode:
                                                accepted_in_block = False
                                                hard_reject = True
                                            execution_success = False
                                            tx_receipt["logs"].append("Transfer balance state failed (insufficient)")
                                            break
                                            
                                        current_to = target_balances.get(to_addr, chain_state.get_balance(to_addr))
                                        target_balances[from_addr] = current_from - amount
                                        target_balances[to_addr] = current_to + amount
                                    else:
                                        if not chain_state.update_balances_after_transfer(from_addr, to_addr, amount):
                                            if not replay_mode:
                                                accepted_in_block = False
                                                hard_reject = True
                                            execution_success = False
                                            tx_receipt["logs"].append("Transfer balance state failed")
                                            break
                                except Exception as e:
                                    logger.error("Error applying transfer: %s", e)
                                    if not replay_mode:
                                        accepted_in_block = False
                                        hard_reject = True
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

            if accepted_in_block and not hard_reject:
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

            if accepted_in_block and not hard_reject:
                accepted_txs.append(tx)
                tx_receipt["status"] = "success" if execution_success else "failed"
                receipts[tx_id] = tx_receipt
            else:
                rejected_txs.append(tx)
                receipts[tx_id] = {"status": "failed", "logs": tx_receipt["logs"]}
                logger.error("TX REJECTED during apply: %s", tx_receipt["logs"])

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
