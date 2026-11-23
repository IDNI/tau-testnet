from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

import config
import db
import tau_defs
from .tau_engine import TauEngine, TauExecutionResult, TauStateSnapshot
from .serialization import canonical_json, canonicalize_parent_hash_yid, canonicalize_proposer_yid
from .state import StateStore, compute_state_hash
from .governance import (
    DEFAULT_MAX_RULE_TXS_PER_BLOCK,
    normalize_validator_set,
    is_tau_authoritative_eligibility_mode,
)
from . import faucet, fees
from . import sender_policy
from .fees import FeeRuleError
from .approvals import (
    APPROVAL_TX_TYPES,
    RULE_CHANGE_TX_TYPES,
    STATUS_EXECUTED,
    STATUS_FAILED,
    STATUS_CANCELLED,
    STATUS_OPEN,
    TX_TYPE_APPROVAL_REQUEST,
    TX_TYPE_RULE_CHANGE_REQUEST,
    TX_TYPE_TRANSFER_VOTE,
    parse_approval_request,
    parse_rule_change_cancel,
    parse_rule_change_request_checked,
    parse_transfer_vote,
)
from .retractable import (
    RETRACTABLE_TX_TYPES,
    RetractableBook,
    TX_TYPE_RETRACTABLE_TRANSFER,
    RetractableShapeError,
    parse_retract_transfer,
    parse_retractable_transfer,
)
from .rule_offers import (
    RULE_OFFER_TX_TYPES,
    RuleOfferDecision,
    RuleOfferShapeError,
    clause_body_v1,
    is_neutral_clause_body,
    TX_TYPE_RULE_OFFER,
    TX_TYPE_RULE_OFFER_ACCEPT,
    parse_rule_offer,
    parse_rule_offer_accept,
    parse_rule_offer_reject,
    clause_output_streams,
)

# Transaction types that pay a fee. Governance types are exempt so validators
# never need funds to govern; rule sharing is user-initiated and expensive, so
# exempting it would make rule spam free.
#
# `approval_request` pays because it is the ONLY charge for a parked transfer:
# executing it later is free, so there is no second fee to drift against a fee
# rule that changed while the request sat open. `transfer_vote` is exempt like a
# governance vote, so approver bots need no funding.
#
# MUST stay in step with commands.sendtx.FEE_BEARING_TX_TYPES -- the same
# constant is deliberately duplicated there to keep the admission path free of
# an engine import, and a divergence charges a different fee at admission than
# at inclusion.
FEE_BEARING_TX_TYPES = frozenset(
    {"user_tx", TX_TYPE_APPROVAL_REQUEST, TX_TYPE_RETRACTABLE_TRANSFER,
     TX_TYPE_RULE_CHANGE_REQUEST}
    | set(RULE_OFFER_TX_TYPES)
)


def _receipt_lookup_key(tx: Dict[str, Any], index: int) -> str:
    """Receipt dict key; only used for receipts and ApplyBlockResult id lists."""
    return tx.get("tx_id") or str(index)

# Branches that mutate the lifecycle manager in place. They write only to the
# fork of the tx, which both apply paths drop on a rejection. A tx that is
# already rejected skips them, so it never reaches the evaluator.
_LIFECYCLE_TX_TYPES = frozenset(
    {"consensus_rule_update", "consensus_rule_vote"}
    | set(RULE_OFFER_TX_TYPES)
    | set(APPROVAL_TX_TYPES)
    | set(RULE_CHANGE_TX_TYPES)
)
from consensus.tx_checks import apply_tx_error
from consensus import bls
from consensus.tx_signing import verify_tx_signature
import tau_native
import tau_advisory
import tau_guard
import tau_journal
import tau_session
import tau_shrink

from errors import (
    BlockchainBug,
    TauCommunicationError,
    TauEngineBug,
    TauEngineCrash,
    TauSpecIntegrationError,
    TauSpecRejected,
)

# We need to import chain_state and tau_manager, but we must be careful about circular imports.
# We'll import them inside methods or use a lazy import pattern if needed.
import tau_manager
# chain_state will be imported inside methods to avoid circular dependency if chain_state imports this module.

logger = logging.getLogger(__name__)


def _application_rule_landed(rule_text: str) -> bool:
    """True when the preprocessed unit is in the hashed application-rules state.

    `communicate_with_tau(..., apply_rules_update=True)` is supposed to persist
    via `save_effective_tau_spec`. If the handler did not run, a success string
    from Tau is a no-op: the spec is unchanged, but a soft fail would still
    include the tx and charge a fee. Membership here is the honesty check.
    """
    import chain_state

    raw = (rule_text or "").strip()
    if not raw:
        return False
    try:
        unit = chain_state._preprocess_tau_spec_text(raw) or raw
    except Exception:
        unit = raw
    try:
        app = chain_state.get_application_rules_state() or ""
    except Exception:
        return False
    units = [u.strip() for u in app.split("\n") if u.strip()]
    if unit in units or raw in units:
        return True
    return unit in app or raw in app


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
    parent_balances: Optional[Dict[str, int]] = None

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
        and time, according to the active view.
        """
        pass


class DefaultConsensusEngine(ConsensusEngine):
    """
    Standard Python-Tau implementation of the ConsensusEngine.
    Delegates block and transaction execution to TauEngine and associated modules.
    """

    def __init__(self, tau_engine: Optional[TauEngine] = None):
        self.tau_engine = tau_engine or TauEngine()

    def derive_active_consensus(self, parent_snapshot: TauStateSnapshot, target_height: int) -> ActiveConsensusView:
        """
        Derives the consensus view from the parent snapshot.
        Extracts rules, validators, balances, etc.
        """
        consensus_rules = parent_snapshot.consensus_rules or ""
        active_validators = list(parent_snapshot.validators) if parent_snapshot.validators else []
        parent_balances = dict(parent_snapshot.balances) if parent_snapshot.balances else {}

        return ActiveConsensusView(
            target_height=target_height,
            consensus_rules=consensus_rules,
            active_validators=active_validators,
            parent_balances=parent_balances,
        )

    def verify_block_header(self, active_view: ActiveConsensusView, block: Any, proof_result: Dict[str, Any]) -> bool:
        """
        Verifies block header using TauEngine or proof results.
        """
        # Typically, TauEngine verifies the block via its internal logic or proof validation.
        # Here we delegate to tau_engine if needed or do standard checks.
        return self.tau_engine.verify_header(active_view, block, proof_result)

    def apply_block(
        self,
        active_view: ActiveConsensusView,
        block: Any,
        parent_snapshot: TauStateSnapshot,
        *,
        replay_mode: bool = False,
    ) -> ApplyBlockResult:
        """
        Applies a block, executing all transactions and updating state.
        """
        import chain_state

        outcomes: List[TransactionOutcome] = []
        accepted_tx_ids: List[str] = []
        skipped_tx_ids: List[str] = []
        invalid_tx_ids: List[str] = []
        governance_changes: Dict[str, Any] = {}
        mempool_hints: Dict[str, Any] = {}

        balances = dict(parent_snapshot.balances) if parent_snapshot.balances else {}
        nonces = dict(parent_snapshot.nonces) if parent_snapshot.nonces else {}
        
        txs = getattr(block, "transactions", []) or []
        
        # Process transactions through TauEngine and state updates
        for idx, tx in enumerate(txs):
            tx_id = tx.get("tx_id") or str(idx)
            tx_type = tx.get("type") or "user_tx"
            
            # Check fee payment if applicable
            sender = tx.get("sender")
            fee = tx.get("fee", 0)
            
            if sender and fee > 0 and sender in balances:
                if balances[sender] < fee:
                    invalid_tx_ids.append(tx_id)
                    outcomes.append(TransactionOutcome(tx_id=tx_id, status="invalid", reason="insufficient_balance_for_fee"))
                    continue
                balances[sender] -= fee

            # Execute transaction operations via Tau engine
            operations = tx.get("operations", {})
            
            # Handle op-0 policy rules explicitly if present
            rule_landed = False
            if "0" in operations:
                rule_text = operations["0"]
                if isinstance(rule_text, dict):
                    rule_text = rule_text.get("rule", "") or str(rule_text)
                
                # Apply rules update through chain_state / tau_manager if applicable
                try:
                    success, err = tau_manager.apply_rules_update(str(rule_text))
                    if success:
                        rule_landed = _application_rule_landed(str(rule_text))
                    else:
                        logger.warning(f"Rule update failed for tx {tx_id}: {err}")
                except Exception as e:
                    logger.exception(f"Exception applying rule update for tx {tx_id}: {e}")

            accepted_tx_ids.append(tx_id)
            outcomes.append(TransactionOutcome(tx_id=tx_id, status="applied", receipt_logs=[]))

        next_snapshot = TauStateSnapshot(
            height=active_view.target_height,
            parent_hash=getattr(block, "parent_hash", ""),
            state_hash=compute_state_hash(balances, nonces),
            balances=balances,
            nonces=nonces,
            validators=active_view.active_validators,
            consensus_rules=active_view.consensus_rules,
        )

        return ApplyBlockResult(
            next_snapshot=next_snapshot,
            outcomes=outcomes,
            accepted_tx_ids=accepted_tx_ids,
            skipped_tx_ids=skipped_tx_ids,
            invalid_tx_ids=invalid_tx_ids,
            governance_changes=governance_changes,
            mempool_hints=mempool_hints,
        )

    def query_eligibility(self, active_view: ActiveConsensusView, local_pubkey: str, target_height: int, now_ts: int) -> bool:
        """
        Queries whether the node is eligible to propose a block.
        """
        if is_tau_authoritative_eligibility_mode():
            return self.tau_engine.query_eligibility(active_view, local_pubkey, target_height, now_ts)
        
        validators = active_view.active_validators
        if not validators:
            return True
        # Simple round-robin or pubkey presence check if validators are defined
        return local_pubkey.encode() in validators or local_pubkey in [v.decode() if isinstance(v, bytes) else v for v in validators]