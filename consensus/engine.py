from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import config
import db
import tau_defs
from .tau_engine import TauEngine, TauExecutionResult, TauStateSnapshot
from .serialization import canonical_json, canonicalize_parent_hash_yid, canonicalize_proposer_yid
from .state import StateStore, compute_state_hash
from .governance import normalize_validator_set
from . import fees
from .fees import FeeRuleError
from errors import BlockchainBug, TauCommunicationError, TauEngineBug, TauEngineCrash

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

    def _active_validator_hexes_from_snapshot(self, parent_snapshot: TauStateSnapshot) -> List[str]:
        metadata = parent_snapshot.metadata or {}
        lifecycle_manager = metadata.get("lifecycle_manager")
        if lifecycle_manager is not None and getattr(lifecycle_manager, "active_validators", None):
            return sorted(normalize_validator_set(lifecycle_manager.active_validators))
        return sorted(normalize_validator_set(self._validators))

    @staticmethod
    def _encode_bv_uint(value: Any, *, width_bits: int, field_name: str) -> str:
        parsed = int(value)
        if parsed < 0 or parsed >= (1 << width_bits):
            raise ValueError(f"{field_name} must fit within bv[{width_bits}]")
        return str(parsed)

    @staticmethod
    def _encode_yid(text: str) -> str:
        return db.get_string_id(text)

    def _build_consensus_input_streams(
        self,
        *,
        proposer_pubkey: str,
        block_number: Any,
        timestamp: Any,
        previous_hash: str,
        proof_ok: bool,
        claims: Any = None,
    ) -> Dict[int, str]:
        canonical_proposer = canonicalize_proposer_yid(proposer_pubkey)
        canonical_parent_hash = canonicalize_parent_hash_yid(previous_hash)
        claims_json = canonical_json(claims if claims is not None else {}).decode("utf-8")

        return {
            6: self._encode_bv_uint(block_number, width_bits=64, field_name="block_number"),
            7: self._encode_bv_uint(timestamp, width_bits=64, field_name="timestamp"),
            8: self._encode_yid(canonical_proposer),
            9: self._encode_yid(canonical_parent_hash),
            10: self._encode_bv_uint(1 if proof_ok else 0, width_bits=16, field_name="proof_ok"),
            11: self._encode_yid(claims_json),
        }

    # --- ConsensusEngine Interface Implementation ---

    def derive_active_consensus(self, parent_snapshot: TauStateSnapshot, target_height: int) -> ActiveConsensusView:
        # Skeleton implementation for Phase 1
        # In Phase 2, this will traverse the consensus_meta to build the view. 
        # For now, it delegates to PoA parameters.
        validator_hexes = self._active_validator_hexes_from_snapshot(parent_snapshot)
        # consensus_rules is the CONSENSUS spec (o6/o7), carried in the parent
        # snapshot metadata -- NOT parent_snapshot.tau_bytes, which is the
        # APPLICATION accumulation. Using tau_bytes here meant every non-governance
        # block wrote the application spec into consensus_rules_state, which then
        # failed to parse when replayed via i0 on restart ("Unexpected 'a'").
        return ActiveConsensusView(
            target_height=target_height,
            consensus_rules=str(parent_snapshot.metadata.get("consensus_rules_state", "") or ""),
            active_validators=[bytes.fromhex(v) for v in validator_hexes],
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
            # PoA: the proposer must be in the active validator set (skip for
            # genesis, whose proposer is the all-zero sentinel).
            active_view = args[0] if (args and isinstance(args[0], ActiveConsensusView)) else kwargs.get("active_view")
            if (
                block is not None
                and getattr(block.header, "block_number", None) != 0
                and active_view is not None
                and not getattr(config.settings.authority, "open_governance_admission", False)
            ):
                try:
                    allowed = normalize_validator_set(active_view.active_validators)
                    proposer_hex = (block.header.proposer_pubkey or "").lower()
                except (ValueError, AttributeError):
                    return False
                if allowed and proposer_hex not in allowed:
                    logger.warning(
                        "Consensus: proposer %s not in active validator set for block #%s",
                        proposer_hex[:10], block.header.block_number,
                    )
                    return False
        else:
            # Phase 1 Legacy Signature: (block)
            block = args[0] if len(args) > 0 else kwargs.get("block")
            proof_result = args[1] if len(args) > 1 and isinstance(args[1], dict) else kwargs.get("proof_result", {"proof_ok": True})

        if block and not block.consensus_proof:
            logger.warning("Consensus: Block #%s has no consensus proof", block.header.block_number)
            return False

        if not tau_manager.tau_ready.is_set():
            logger.error("Consensus: Tau not ready for block verification.")
            return False
            
        try:
            tau_inputs = self._build_consensus_input_streams(
                proposer_pubkey=block.header.proposer_pubkey,
                block_number=block.header.block_number,
                timestamp=block.header.timestamp,
                previous_hash=block.header.previous_hash,
                proof_ok=bool(proof_result.get("proof_ok", False)),
                claims=proof_result.get("claims"),
            )
            output = tau_manager.communicate_with_tau(
                target_output_stream_index=6,
                input_stream_values=tau_inputs,
                apply_rules_update=False
            )
            verdict = tau_manager.parse_tau_output(str(output))
            if verdict != 0:
                return True
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
            
            logger.warning("Consensus: Block #%s rejected by Tau rules (o6: %s)", block.header.block_number, output)
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
        from consensus.state import compute_consensus_state_hash
        from chain_state import compute_accounts_hash
        import chain_state

        # 1. State Extraction
        metadata = parent_snapshot.metadata
        t_bals = copy.deepcopy(metadata.get('balances', {}))
        t_seqs = copy.deepcopy(metadata.get('sequence_numbers', {}))
        # Pre-block total supply, captured before apply mutates t_bals.
        parent_total = sum(int(v) for v in t_bals.values())

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
            proposer_pubkey=block.header.proposer_pubkey,
            block_height=block.header.block_number,
        )

        # Conservation invariant: the native fee model debits the sender and
        # credits the proposer through the same staged_writes pass, so total
        # supply is preserved across a block (no mint, no burn). A mismatch is
        # a consensus bug, not a recoverable error.
        post_total = sum(int(v) for v in t_bals.values())
        if post_total != parent_total and not getattr(config, "TESTNET_AUTO_FAUCET", False):
            raise BlockchainBug(
                f"Supply not conserved applying block #{block.header.block_number}: "
                f"parent_total={parent_total} post_total={post_total}"
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
        next_active_consensus_id = parent_snapshot.metadata.get("active_consensus_id", "")
        if newly_active:
            # Route every activated revision through `i0` in declaration order.
            # The genesis `i0 -> u` routing emits an `Updated specification:`
            # marker on stdout and tau_native rebuilds the interpreter from
            # that output, so the live spec advances exactly the same way it
            # does for user_tx ops['0'] application-rule changes.
            #
            # Activation revisions intentionally do NOT trigger the
            # rules-handler (`apply_rules_update=False`): consensus provenance
            # is updated via the deterministic `"\n".join(rule_revisions)` tag
            # written into `next_snapshot.metadata["consensus_rules_state"]`
            # below, not via the live spec extracted from stdout. Letting the
            # handler fire here would briefly write a partially-stripped
            # intermediate into `_application_rules_state` (the old consensus
            # prefix no longer matches the post-revision spec) and persist a
            # polluted `full_tau_spec` to the DB before the snapshot commit
            # overwrites it.
            for update in newly_active:
                tag = f"governance_activation:{update.update_id_hex[:16]}"
                for rev in update.rule_revisions:
                    if not isinstance(rev, str) or not rev.strip():
                        continue
                    try:
                        output = tau_manager.communicate_with_tau(
                            rule_text=rev,
                            target_output_stream_index=0,
                            source=tag,
                            apply_rules_update=False,
                        )
                        if output and "error" in output.lower() and "x1001" not in output.lower():
                            raise FeeRuleError(
                                f"Governance rule activation revision rejected by live Tau interpreter: {output}"
                            )
                    except (TauCommunicationError, TauEngineBug, TauEngineCrash) as e:
                        # Triggers round abort (proposer) or block deferral (validator),
                        # preventing state divergence.
                        raise FeeRuleError(
                            f"Governance rule activation rejected by live Tau interpreter "
                            f"at height {block.header.block_number}: {e}"
                        )
            last_update = newly_active[-1]
            # Provenance tag used by `compute_consensus_state_hash`. Every node
            # derives this string deterministically from `last_update.rule_revisions`,
            # so the resulting state hash is independent of the live interpreter.
            next_cons_rules = "\n".join(last_update.rule_revisions)
            next_active_consensus_id = last_update.update_id_hex[:16]
        
        # Finalize Hashes
        acc_hash = compute_accounts_hash(t_bals, t_seqs)
        meta_hash = lm.consensus_meta_hash()
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
                "consensus_rules_state": next_cons_rules,
                "active_consensus_id": next_active_consensus_id
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
            
        try:
            tau_inputs = self._build_consensus_input_streams(
                proposer_pubkey=my_pubkey,
                block_number=block_number,
                timestamp=timestamp,
                previous_hash=previous_hash,
                proof_ok=True,
                claims={},
            )
            output = tau_manager.communicate_with_tau(
                target_output_stream_index=7,
                input_stream_values=tau_inputs,
                apply_rules_update=False
            )
            verdict = tau_manager.parse_tau_output(str(output))
            if verdict != 0:
                return True
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
        proposer_pubkey: Optional[str] = None,
        block_height: Optional[int] = None,
    ) -> TauExecutionResult:
        """
        Apply transactions to the current state.

        This executes operations:
        - '0' (Rules): Sent to Tau process.
        - '1' (Transfers): Applied to chain_state balances.

        Fee model: when `proposer_pubkey` is supplied together with a
        `target_balances` overlay, every accepted user_tx is charged
        total_fee = sum over its Tau steps of (o9 consensus fee + o8 user
        custom fee), capped by the signed `fee_limit` field, and the fee is
        credited to the proposer. o9 absent -> fee 0 (model inactive).
        A FeeRuleError (invalid o9 from the voted consensus rules) is
        strict and propagates: callers must abort the proposal / defer the
        block rather than guess a fee.
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

        # Fee charging requires the isolated balance overlay: there is no
        # proposer-credit primitive on the direct chain_state mutation path
        # (only legacy tests use it), and staged commit-on-accept semantics
        # depend on the overlay.
        fees_enabled = bool(proposer_pubkey) and target_balances is not None
        if bool(proposer_pubkey) and target_balances is None:
            logger.error(
                "Fee charging requested without target_balances overlay; fees skipped (legacy path)."
            )

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

            # Expiration recheck against the deterministic block timestamp
            # (admission checks wall clock; this is the consensus-side gate).
            expiration_time = tx.get('expiration_time')
            if block_timestamp and isinstance(expiration_time, int) and block_timestamp > expiration_time:
                if not replay_mode:
                    accepted_in_block = False
                    hard_reject = True
                execution_success = False
                tx_receipt["logs"].append("Transaction expired at block timestamp")

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

            # --- Fee preamble (user_tx only; governance txs are exempt by
            # design so validators never need funds to govern) ---
            charge_fee = fees_enabled and tx_type == 'user_tx'
            fee_limit_int: Optional[int] = None
            fee_components: List[int] = []
            staged_writes: Dict[str, int] = {}

            def _read_bal(addr: str) -> int:
                """Balance as seen through this tx's staged writes."""
                if addr in staged_writes:
                    return staged_writes[addr]
                if target_balances is not None and addr in target_balances:
                    return target_balances[addr]
                return chain_state.get_balance(addr)

            if charge_fee:
                # Absent field -> cap 0: legacy/feeless txs stay valid while
                # the fee model is inactive (total fee 0) and are rejected
                # by the cap check once it is active. Only a PRESENT but
                # malformed value is structurally invalid.
                raw_fee_limit = tx.get('fee_limit')
                fee_limit_int = 0 if raw_fee_limit is None else fees.parse_fee_limit(raw_fee_limit)
                if fee_limit_int is None:
                    if replay_mode:
                        # Stored blocks are canonical; never re-litigate.
                        logger.error(
                            "Replay: tx %s has malformed fee_limit %r; fee skipped.",
                            tx_id, tx.get('fee_limit'),
                        )
                        tx_receipt["logs"].append("Replay: malformed fee_limit; fee skipped")
                        charge_fee = False
                    else:
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                        tx_receipt["reason"] = "invalid_fee_limit"
                        tx_receipt["logs"].append(
                            f"Invalid fee_limit: {tx.get('fee_limit')!r}"
                        )

            rule_op_data = None
            transfers_op_data = None
            custom_tau_inputs: dict[int, list[str]] = {}
            reserved_error = None

            from consensus.governance import parse_consensus_rule_update, parse_consensus_rule_vote
            
            if tx_type == 'consensus_rule_update':
                update = parse_consensus_rule_update(tx)
                if update:
                    # Consensus-enforced activation delay. Mirrors the mempool
                    # admission floor (admission.validate_consensus_rule_update_payload)
                    # so a crafted block — which never passed admission — cannot
                    # submit a governance update that activates before the
                    # validator set has had time to react; in the limit, reaching
                    # quorum and activating in the same block. The reference
                    # height is the inclusion height, so the floor is identical
                    # on every node applying this block. Breach is a soft no-op
                    # (block stays valid, update is simply not recorded), matching
                    # forged-vote / unknown-update handling and keeping replay
                    # deterministic.
                    min_activation = (
                        block_height + len(lifecycle_mgr.active_validators)
                        if block_height is not None else None
                    )
                    if min_activation is not None and update.activate_at_height < min_activation:
                        tx_receipt["logs"].append(
                            "Update ignored (activation delay breached): "
                            f"{update.activate_at_height} < {min_activation}"
                        )
                    elif lifecycle_mgr.can_admit_update(update, is_mempool=False):
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
                    if idx in (0, 1):
                        continue
                    # i12 is the sender pubkey the node sets below; a custom
                    # operations["12"] would override it in the merge at
                    # tau_input_stream_values[12] and spoof the sender-scoped
                    # o5/o8 policy stream. Reject it here (it is not in
                    # RESERVED_STREAMS, a consensus-shared constant) so apply
                    # agrees with the sendtx/admission gate. Consensus change.
                    if idx in tau_defs.RESERVED_STREAMS or idx == 12:
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
                                    # A rule Tau cannot parse/compile is
                                    # structurally invalid and must not be
                                    # embedded in the block. Hard-reject it,
                                    # mirroring reserved-stream/bad-format paths,
                                    # so the "logically valid" count excludes it.
                                    accepted_in_block = False
                                    hard_reject = True
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
                            # A deterministic Tau parse/compile failure (the
                            # native engine emits "(Error)" lines, which bubble
                            # up in the exception text) means the rule is
                            # unparseable — hard-reject so it cannot enter the
                            # block. Other failures (e.g. transient Tau outage)
                            # stay soft.
                            if "(error)" in str(e).lower():
                                accepted_in_block = False
                                hard_reject = True

                # --- Step 2 & 3: Unified Custom Inputs & Transfers ---
                if execution_success and transfers_op_data is not None:
                    if isinstance(transfers_op_data, list) and charge_fee:
                        # Fee-era path: o1+o8+o9 in one roundtrip per
                        # transfer, tx-atomic balance staging (writes commit
                        # only if the whole tx is accepted — a mid-tx
                        # failure must not pollute the overlay/state hash).
                        for transfer in transfers_op_data:
                            if not (isinstance(transfer, (list, tuple)) and len(transfer) == 3):
                                continue
                            from_addr, to_addr, amount_val = transfer
                            try:
                                amount = int(amount_val)

                                tau_input_stream_values = {
                                    1: str(amount),
                                    # i2 (balance) is the ONLY stream that genuinely
                                    # diverges queue-time vs apply-time (other txs in
                                    # the block may debit the account); it stays mocked
                                    # and rule text reading it is rejected at admission.
                                    2: "0",
                                    # i3/i4 are the real from/to pubkeys (immutable in
                                    # the transfer tuple -> identical at admission and
                                    # apply), so recipient-aware policy/fee rules are
                                    # deterministic across the two.
                                    3: "{ #x" + str(from_addr) + " }:bv[384]",
                                    4: "{ #x" + str(to_addr) + " }:bv[384]",
                                }
                                tau_input_stream_values[12] = "{ #x" + str(from_addr) + " }:bv[384]"
                                for k, v in custom_tau_inputs.items():
                                    tau_input_stream_values[k] = v
                                tau_input_stream_values[5] = str(block_timestamp)

                                if not tau_manager.tau_ready.is_set():
                                    tau_manager.tau_ready.wait(timeout=5)
                                if not tau_manager.tau_ready.is_set():
                                    if replay_mode:
                                        # Tau-less replay is supported for
                                        # pre-fee chains (fee 0 matches).
                                        # For fee-era chains the state-hash
                                        # invariant catches the divergence.
                                        logger.warning(
                                            "Replay without Tau: fee step assumed 0 for tx %s.",
                                            tx_id,
                                        )
                                        fee_components.append(0)
                                    else:
                                        # The fee value is unknowable without
                                        # Tau; "pretend 0" would be a locally-
                                        # valid divergent transition. Strict.
                                        raise FeeRuleError(
                                            f"Tau unavailable during fee-era transfer execution (tx {tx_id})"
                                        )
                                else:
                                    with tau_manager.tau_comm_lock:
                                        tau_outputs = tau_manager.communicate_with_tau_multi(
                                            input_stream_values=tau_input_stream_values,
                                            apply_rules_update=False,
                                        )
                                    tx_receipt["logs"].append(
                                        f"Tau(transfer) o1: {tau_outputs.get(1)}"
                                    )
                                    step_fee = fees.parse_consensus_fee(
                                        tau_outputs.get(tau_defs.CONSENSUS_FEE_STREAM_INDEX),
                                        context=f"tx {tx_id}",
                                    ) + fees.parse_custom_fee(
                                        tau_outputs.get(tau_defs.CUSTOM_FEE_STREAM_INDEX),
                                        context=f"tx {tx_id}",
                                    )
                                    fee_components.append(step_fee)
                                    if step_fee:
                                        tx_receipt["logs"].append(f"Tau fee step: {step_fee}")

                                    # --- User policy (o5) — consensus-enforced ---
                                    # Read from the SAME multi result (no extra
                                    # roundtrip, no perturbation), mirroring admission
                                    # (commands/sendtx.py). Semantics: o5 absent -> allow;
                                    # present and == BLOCK (0) -> reject the WHOLE tx
                                    # (a policy block on any transfer invalidates the
                                    # user_tx — staged writes never commit, so no partial
                                    # execution). parse_tau_output maps unparseable -> 0,
                                    # so a malformed policy output fails closed (reject).
                                    o5_raw = tau_outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
                                    if o5_raw is not None and \
                                            tau_manager.parse_tau_output(o5_raw) == tau_defs.USER_POLICY_BLOCK_VALUE:
                                        logger.info(
                                            "Transfer rejected by user policy (o5) for %s->%s (o5=%s)",
                                            str(from_addr)[:10], str(to_addr)[:10], o5_raw,
                                        )
                                        if not replay_mode:
                                            accepted_in_block = False
                                            hard_reject = True
                                        execution_success = False
                                        tx_receipt["reason"] = "user_policy_block"
                                        tx_receipt["logs"].append(
                                            f"Transfer rejected by user policy (o5={o5_raw})"
                                        )
                                        break

                                current_from = _read_bal(from_addr)
                                if current_from == 0 and getattr(config, "TESTNET_AUTO_FAUCET", False):
                                    current_from = int(getattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000))
                                if current_from < amount:
                                    logger.error(
                                        "Insufficient funds for %s to send %s. Has: %s.",
                                        from_addr[:10], amount, current_from,
                                    )
                                    if not replay_mode:
                                        accepted_in_block = False
                                        hard_reject = True
                                    execution_success = False
                                    tx_receipt["logs"].append("Transfer balance state failed (insufficient)")
                                    break
                                staged_writes[from_addr] = current_from - amount
                                staged_writes[to_addr] = _read_bal(to_addr) + amount
                            except FeeRuleError:
                                raise
                            except Exception as e:
                                logger.error("Error applying transfer: %s", e)
                                if not replay_mode:
                                    accepted_in_block = False
                                    hard_reject = True
                                execution_success = False
                                break
                    elif isinstance(transfers_op_data, list):
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
                                        # Real from/to pubkeys for eval/width parity
                                        # with the fee-era path.
                                        3: "{ #x" + str(from_addr) + " }:bv[384]",
                                        4: "{ #x" + str(to_addr) + " }:bv[384]",
                                    }
                                    # i12: full 384-bit sender pubkey (bv[384]),
                                    # mirrors the submit path so any rule that
                                    # references i12[t] replays deterministically.
                                    tau_input_stream_values[12] = "{ #x" + str(from_addr) + " }:bv[384]"
                                    # NOTE: o5 user policy is consensus-enforced in the
                                    # fee-era loop above (the live path when fees are on,
                                    # which is the release config). This feeless legacy
                                    # path mutates balances non-atomically and is not the
                                    # consensus-determining path, so it does not enforce o5.
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
                                            current_from = int(getattr(config, "TESTNET_AUTO_FAUCET_AMOUNT", 100000))

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

            # --- Step 5: Fee settlement (charged only on inclusion) ---
            # A transfer-less user_tx is charged via one dedicated fee-query
            # step with the canonical mocked transfer inputs so governance
            # fees apply uniformly to all user transactions.
            if charge_fee and accepted_in_block and not hard_reject and not transfers_op_data:
                try:
                    fee_query_inputs = {
                        1: "0", 2: "0", 3: "0", 4: "0",
                        5: str(block_timestamp),
                        12: "{ #x" + str(sender) + " }:bv[384]",
                    }
                    for k, v in custom_tau_inputs.items():
                        fee_query_inputs[k] = v
                    if not tau_manager.tau_ready.is_set():
                        tau_manager.tau_ready.wait(timeout=5)
                    if not tau_manager.tau_ready.is_set():
                        if replay_mode:
                            logger.warning(
                                "Replay without Tau: fee-query step assumed 0 for tx %s.", tx_id
                            )
                        else:
                            raise FeeRuleError(
                                f"Tau unavailable during fee-query step (tx {tx_id})"
                            )
                    else:
                        with tau_manager.tau_comm_lock:
                            fee_outputs = tau_manager.communicate_with_tau_multi(
                                input_stream_values=fee_query_inputs,
                                apply_rules_update=False,
                            )
                        fee_components.append(
                            fees.parse_consensus_fee(
                                fee_outputs.get(tau_defs.CONSENSUS_FEE_STREAM_INDEX),
                                context=f"tx {tx_id} fee-query",
                            ) + fees.parse_custom_fee(
                                fee_outputs.get(tau_defs.CUSTOM_FEE_STREAM_INDEX),
                                context=f"tx {tx_id} fee-query",
                            )
                        )
                except FeeRuleError:
                    raise
                except Exception as e:
                    logger.error("Error during fee-query step for tx %s: %s", tx_id, e)
                    if not replay_mode:
                        accepted_in_block = False
                        hard_reject = True
                    execution_success = False
                    tx_receipt["logs"].append(f"Error (fee query): {e}")

            if charge_fee and accepted_in_block and not hard_reject:
                total_fee = sum(fee_components)
                if total_fee == 0:
                    pass  # fee model inactive (no o9/o8): zero writes, legacy-identical
                elif total_fee > fee_limit_int:
                    if replay_mode:
                        logger.error(
                            "Replay: tx %s total fee %s exceeds fee_limit %s; fee skipped.",
                            tx_id, total_fee, fee_limit_int,
                        )
                        tx_receipt["logs"].append("Replay: fee exceeds fee_limit; fee skipped")
                    else:
                        accepted_in_block = False
                        hard_reject = True
                        execution_success = False
                        tx_receipt["reason"] = "fee_limit_exceeded"
                        tx_receipt["logs"].append(
                            f"Fee {total_fee} exceeds fee_limit {fee_limit_int}"
                        )
                else:
                    # No faucet shim here: fee settlement reads plain
                    # balances; a 0-balance faucet sender cannot pay fees.
                    sender_bal = _read_bal(sender) if sender else 0
                    if sender is None or sender_bal < total_fee:
                        if replay_mode:
                            logger.error(
                                "Replay: tx %s sender cannot cover fee %s (has %s); fee skipped.",
                                tx_id, total_fee, sender_bal,
                            )
                            tx_receipt["logs"].append("Replay: insufficient balance for fee; fee skipped")
                        else:
                            accepted_in_block = False
                            hard_reject = True
                            execution_success = False
                            tx_receipt["reason"] = "insufficient_funds_for_fee"
                            tx_receipt["logs"].append(
                                f"Insufficient balance for fee: need {total_fee}, have {sender_bal}"
                            )
                    else:
                        # Aliasing-safe ordering: deduct the sender first,
                        # then credit the proposer THROUGH the staged view —
                        # sender == proposer nets to zero because the credit
                        # reads the already-deducted value.
                        staged_writes[sender] = sender_bal - total_fee
                        staged_writes[proposer_pubkey] = _read_bal(proposer_pubkey) + total_fee
                        tx_receipt["fee_charged"] = total_fee
                        tx_receipt["logs"].append(
                            f"Fee charged: {total_fee} -> proposer {str(proposer_pubkey)[:10]}..."
                        )

            # Commit staged balance writes only for txs that stay accepted.
            # (Replay soft-fails intentionally commit partial stages — same
            # observable behavior as the legacy immediate-write loop.)
            if charge_fee and accepted_in_block and not hard_reject and staged_writes:
                target_balances.update(staged_writes)

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
                rejected_receipt = {"status": "failed", "logs": tx_receipt["logs"]}
                if "reason" in tx_receipt:
                    # Machine-readable fee rejection cause; a rejected tx
                    # never pays anything.
                    rejected_receipt["reason"] = tx_receipt["reason"]
                    rejected_receipt["fee_charged"] = 0
                receipts[tx_id] = rejected_receipt
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
