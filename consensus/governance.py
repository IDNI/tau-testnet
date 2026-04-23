from typing import Any, Dict, List, Optional, Union
import json
import logging
from dataclasses import dataclass

from consensus.serialization import compute_update_id

logger = logging.getLogger(__name__)

@dataclass
class ConsensusRuleUpdate:
    rule_revisions: List[str]
    activate_at_height: int
    host_contract_patch: Optional[Dict[str, Union[int, str, bool]]] = None

    @property
    def update_id(self) -> bytes:
        return compute_update_id(
            revisions=self.rule_revisions,
            activate_at_height=self.activate_at_height,
            patch=self.host_contract_patch
        )
        
    @property
    def update_id_hex(self) -> str:
        return self.update_id.hex()

@dataclass
class ConsensusRuleVote:
    update_id: bytes
    approve: bool

def parse_consensus_rule_update(tx: Dict[str, Any]) -> Optional[ConsensusRuleUpdate]:
    """
    Parse a transaction dictionary into a ConsensusRuleUpdate if it matches the schema.
    Normally we check tx_type == "consensus_rule_update".
    """
    if tx.get("tx_type") != "consensus_rule_update":
        return None
        
    # Fields like rule_revisions could be in a nested "payload" dict, or at the root of `tx`.
    root_val = tx.get("payload")
    if isinstance(root_val, dict):
        payload = root_val
    elif isinstance(root_val, str):
        try:
            payload = json.loads(root_val)
        except Exception:
            payload = tx
    else:
        payload = tx

    revisions = payload.get("rule_revisions")
    if not isinstance(revisions, list):
         # Legacy fallback to single tau_source
         tau_source = payload.get("tau_source")
         if isinstance(tau_source, str):
             revisions = [tau_source]
         else:
             return None
             
    activate_at = payload.get("activate_at_height")
    if not isinstance(activate_at, int):
         # Try convert
         try:
             activate_at = int(activate_at)
         except Exception:
             return None

    patch = payload.get("host_contract_patch")
    if patch is not None and not isinstance(patch, dict):
        return None
        
    return ConsensusRuleUpdate(
        rule_revisions=revisions,
        activate_at_height=activate_at,
        host_contract_patch=patch
    )

def parse_consensus_rule_vote(tx: Dict[str, Any]) -> Optional[ConsensusRuleVote]:
    """
    Parse a transaction dictionary into a ConsensusRuleVote if it matches the schema.
    """
    if tx.get("tx_type") != "consensus_rule_vote":
        return None
        
    root_val = tx.get("payload")
    if isinstance(root_val, dict):
        payload = root_val
    elif isinstance(root_val, str):
        try:
            payload = json.loads(root_val)
        except Exception:
            payload = tx
    else:
        payload = tx

    update_id_str = payload.get("update_id")
    if not isinstance(update_id_str, str):
         return None
         
    try:
        update_id = bytes.fromhex(update_id_str)
        if len(update_id) != 32:
            return None
    except ValueError:
        return None
        
    approve = payload.get("approve", True) # Default to true for approvals
    if not isinstance(approve, bool):
         if str(approve).lower() == "false" or approve == 0:
             approve = False
         else:
             approve = True

    return ConsensusRuleVote(
        update_id=update_id,
        approve=approve
    )

class ConsensusLifecycleManager:
    """
    Manages the lifecycle of Governance consensus updates: 
    Pending -> Scheduled -> Active -> Archival.
    Also handles duplicate rejection according to Phase 2 rules.
    """
    def __init__(self, 
                 pending_updates: Optional[List[bytes]] = None,
                 scheduled_updates: Optional[List[tuple[int, bytes]]] = None,
                 archival_updates: Optional[List[bytes]] = None,
                 votes: Optional[Dict[bytes, List[bytes]]] = None, # update_id -> list of voter_pubkey bytes
                 active_validators: Optional[List[bytes]] = None):
        
        self.pending_updates = set(pending_updates) if pending_updates else set()
        # Scheduled is list of (activation_height, update_id)
        self.scheduled_updates = scheduled_updates if scheduled_updates else []
        self.archival_updates = set(archival_updates) if archival_updates else set()
        
        # In-memory tracking of full payload for pending/scheduled items
        self.update_payloads: Dict[bytes, ConsensusRuleUpdate] = {}
        
        self.votes: Dict[bytes, set[bytes]] = {
            k: set(v) for k, v in (votes or {}).items()
        }
        self.active_validators = set(active_validators) if active_validators else set()
        
        # A simple >50% threshold for Phase 2 PoA mock, logic could be configurable via patch
        self.approval_threshold = (len(self.active_validators) // 2) + 1 if self.active_validators else 1

    def knows_update(self, update_id: bytes) -> bool:
        """Check if an update is currently known in any state."""
        if update_id in self.pending_updates:
            return True
        if update_id in self.archival_updates:
            return True
        for _, u_id in self.scheduled_updates:
            if u_id == update_id:
                return True
        return False

    def can_admit_update(self, update: ConsensusRuleUpdate, is_mempool: bool = False) -> bool:
        """
        Enforce Strict Admission Handling:
        Mempool and block admission drop unrecognized updates implicitly, but here we just check
        if it's a completely new update payload. Duplicate updates are skipped silently but mempool drops them.
        """
        uid = update.update_id
        if self.knows_update(uid):
            # Duplicate update handling:
            # - Mempool rejects known entirely.
            # - Block processing skips silently (valid no-op)
            if is_mempool:
                return False
        return True

    def submit_update(self, update: ConsensusRuleUpdate) -> bool:
        """
        Apply a consensus update proposal to the state.
        Returns True if it was a new update, False if it was duplicate (no-op).
        """
        uid = update.update_id
        if self.knows_update(uid):
            return False
            
        self.pending_updates.add(uid)
        self.update_payloads[uid] = update
        self.votes[uid] = set()
        return True

    def can_admit_vote(self, vote: ConsensusRuleVote, voter_pubkey: bytes, is_mempool: bool = False) -> bool:
        """
        Strict Admission handling for votes.
        - Mempool drops unrecognized updates.
        - Mempool drops post-approval duplicates.
        - Mempool drops already-voted same-validator duplicates.
        - Mempool drops approve=False in v1.
        """
        uid = vote.update_id
        
        if vote.approve is False:
            if is_mempool:
                return False # approve=false unsupported in v1 mempool
        
        if uid not in self.pending_updates:
            # Unknown update_id -> reject from mempool
            # Known non-pending (already approved/archival) -> reject from mempool
            if is_mempool:
                return False
                
        # Already voted duplicate check
        if uid in self.votes and voter_pubkey in self.votes[uid]:
            if is_mempool:
                return False

        return True

    def submit_vote(self, vote: ConsensusRuleVote, voter_pubkey: bytes) -> bool:
        """
        Process a vote from a validator.
        Returns True if the vote contributed to the tally, False if duplicate no-op or invalid state.
        """
        uid = vote.update_id
        if uid not in self.pending_updates:
            # Non-duplicate vote targeting an update that is already approved-and-scheduled is invalid in context
            # "duplicate vote by the same validator for the same update_id in the same block is always a valid no-op"
            # Here we follow the block processing rule: if not pending anymore, we reject unless it's a safe duplicate.
            # However, the top-level block application normally checks this. We return False to signify no tally change.
            return False

        # if voter_pubkey not in self.active_validators:
        #     return False # Only validators can vote
            
        if uid not in self.votes:
            self.votes[uid] = set()
            
        if voter_pubkey in self.votes[uid]:
            # Duplicate vote by the same validator for the same update_id is a valid no-op.
            return False
            
        self.votes[uid].add(voter_pubkey)
        
        # Check for promotion
        self._check_approval_promotion(uid)
        return True

    def _check_approval_promotion(self, update_id: bytes):
        """Evaluate threshold and promote to scheduled if approved."""
        if update_id in self.pending_updates:
            if len(self.votes.get(update_id, set())) >= self.approval_threshold:
                # Promote to Scheduled
                self.pending_updates.remove(update_id)
                activation_height = self.update_payloads[update_id].activate_at_height
                self.scheduled_updates.append((activation_height, update_id))
                # Keep sorted by activation height ensuring deterministic order
                self.scheduled_updates.sort(key=lambda x: (x[0], x[1]))

    def process_height_transitions(self, current_height: int) -> List[ConsensusRuleUpdate]:
        """
        Perform precise lifecycles evaluations at a block boundary.
        Pending -> Expired
        Scheduled -> Active -> Archival
        Returns the list of updates that just activated (to apply to Tau).
        """
        newly_active = []
        
        # 1. Expire pending updates that missed their activation height
        expired_uids = []
        for uid in self.pending_updates:
            if uid in self.update_payloads:
                if self.update_payloads[uid].activate_at_height <= current_height:
                    expired_uids.append(uid)
                    
        for uid in expired_uids:
            self.pending_updates.remove(uid)
            self.archival_updates.add(uid)
            # Cleanup votes
            if uid in self.votes:
                del self.votes[uid]
                
        # 2. Activate scheduled updates
        still_scheduled = []
        for activation_height, uid in self.scheduled_updates:
            if activation_height <= current_height:
                # Activate
                if uid in self.update_payloads:
                    newly_active.append(self.update_payloads[uid])
                self.archival_updates.add(uid)
                if uid in self.votes:
                    del self.votes[uid]
            else:
                still_scheduled.append((activation_height, uid))
                
        self.scheduled_updates = still_scheduled
        
        return newly_active
