from typing import Any, Dict, List, Optional, Iterable, Union
import json
import logging
from dataclasses import dataclass

from consensus.serialization import compute_update_id

logger = logging.getLogger(__name__)

VALIDATOR_DELTA_FIELDS = ("validator_additions", "validator_removals")


def _open_governance_admission() -> bool:
    """Lazy config read; must match network-wide (same fork caveat as quorum policy)."""
    try:
        import config as _config
        return bool(getattr(_config.settings.authority, "open_governance_admission", False))
    except Exception:
        return False


def normalize_validator_pubkey(pubkey: Any) -> str:
    """Return a canonical 96-character lowercase validator pubkey hex string."""
    if isinstance(pubkey, (bytes, bytearray)):
        pubkey = bytes(pubkey).hex()
    if not isinstance(pubkey, str):
        raise ValueError("validator pubkey must be a string")
    if pubkey.startswith("0x"):
        raise ValueError("validator pubkey must not have 0x prefix")
    if len(pubkey) != 96:
        raise ValueError(f"validator pubkey must be exactly 96 hex chars, got {len(pubkey)}")
    if pubkey != pubkey.lower():
        raise ValueError("validator pubkey must be lowercase hex")
    try:
        bytes.fromhex(pubkey)
    except ValueError as exc:
        raise ValueError("validator pubkey must be valid hex") from exc
    return pubkey


def normalize_validator_set(validators: Optional[Iterable[Any]]) -> set[str]:
    if not validators:
        return set()
    return {normalize_validator_pubkey(validator) for validator in validators}


def normalize_validator_delta(values: Any, field_name: str) -> List[str]:
    if values is None:
        return []
    if not isinstance(values, list):
        raise ValueError(f"{field_name} must be a list")
    try:
        return sorted({normalize_validator_pubkey(value) for value in values})
    except ValueError as exc:
        raise ValueError(f"{field_name}: {exc}") from exc

@dataclass
class ConsensusRuleUpdate:
    rule_revisions: List[str]
    activate_at_height: int
    host_contract_patch: Optional[Dict[str, Union[int, str, bool, List[str]]]] = None
    proposer_pubkey: Optional[str] = None

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

    proposer_pubkey = tx.get("sender_pubkey")
    if not isinstance(proposer_pubkey, str):
        proposer_pubkey = payload.get("sender_pubkey")
    if not isinstance(proposer_pubkey, str):
        proposer_pubkey = None
        
    return ConsensusRuleUpdate(
        rule_revisions=revisions,
        activate_at_height=activate_at,
        host_contract_patch=patch,
        proposer_pubkey=proposer_pubkey
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
                 active_validators: Optional[Iterable[Any]] = None):
        
        self.pending_updates = set(pending_updates) if pending_updates else set()
        # Scheduled is list of (activation_height, update_id)
        self.scheduled_updates = scheduled_updates if scheduled_updates else []
        self.archival_updates = set(archival_updates) if archival_updates else set()
        
        # In-memory tracking of full payload for pending/scheduled items
        self.update_payloads: Dict[bytes, ConsensusRuleUpdate] = {}
        
        self.votes: Dict[bytes, set[bytes]] = {
            k: set(v) for k, v in (votes or {}).items()
        }
        self.active_validators = normalize_validator_set(active_validators)
        # Quorum policy: "" defers to config (TAU_VALIDATOR_VOTE_QUORUM); genesis
        # consensus_meta.mechanism_specific_metadata.vote_quorum overrides when present.
        # Must be identical across all nodes or the network forks.
        self.quorum_policy: str = ""
        self.recompute_approval_threshold()

    def recompute_approval_threshold(self) -> int:
        policy = self.quorum_policy
        if not policy:
            try:
                import config as _config
                policy = getattr(_config.settings.authority, "validator_vote_quorum", "supermajority")
            except Exception:
                policy = "supermajority"
        n_validators = len(self.active_validators)
        if not n_validators:
            self.approval_threshold = 1
        elif policy == "majority":
            self.approval_threshold = (n_validators // 2) + 1
        else:
            self.approval_threshold = max(1, (2 * n_validators + 2) // 3)
        return self.approval_threshold

    def preview_validator_patch(self, patch: Optional[Dict[str, Any]]) -> set[str]:
        """Return the validator set that would result if this host patch activated."""
        next_validators = set(self.active_validators)
        if not patch:
            return next_validators
        additions = normalize_validator_delta(patch.get("validator_additions"), "validator_additions")
        removals = normalize_validator_delta(patch.get("validator_removals"), "validator_removals")
        next_validators.difference_update(removals)
        next_validators.update(additions)
        return next_validators

    def apply_host_contract_patch(self, patch: Optional[Dict[str, Any]]) -> None:
        """Apply activation-time host metadata changes governed by consensus."""
        if not patch:
            return
        next_validators = self.preview_validator_patch(patch)
        if not next_validators:
            raise ValueError("validator delta would leave no active validators")
        self.active_validators = next_validators
        self.recompute_approval_threshold()

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

        # Non-validator voters are dropped at the mempool only. The block path
        # must NOT hard-reject here: submit_vote ignores them as a soft no-op,
        # which keeps block validity deterministic across replays.
        if is_mempool and not _open_governance_admission():
            try:
                voter_hex = normalize_validator_pubkey(voter_pubkey)
            except ValueError:
                return False
            if voter_hex not in self.active_validators:
                return False

        # Already voted duplicate check
        if uid in self.votes and self._normalize_voter(voter_pubkey) in self.votes[uid]:
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

        # Only active validators may contribute to the tally. A forged vote
        # inside a block is a deterministic soft no-op, never a hard reject.
        try:
            voter_hex = normalize_validator_pubkey(voter_pubkey)
        except ValueError:
            return False
        if not _open_governance_admission() and voter_hex not in self.active_validators:
            return False

        if uid not in self.votes:
            self.votes[uid] = set()

        if voter_hex in self.votes[uid]:
            # Duplicate vote by the same validator for the same update_id is a valid no-op.
            return False

        self.votes[uid].add(voter_hex)

        # Check for promotion
        self._check_approval_promotion(uid)
        return True

    @staticmethod
    def _normalize_voter(voter_pubkey) -> str:
        try:
            return normalize_validator_pubkey(voter_pubkey)
        except ValueError:
            return ""

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
                    update = self.update_payloads[uid]
                    self.apply_host_contract_patch(update.host_contract_patch)
                    newly_active.append(update)
                self.archival_updates.add(uid)
                if uid in self.votes:
                    del self.votes[uid]
            else:
                still_scheduled.append((activation_height, uid))
                
        self.scheduled_updates = still_scheduled
        
        return newly_active
