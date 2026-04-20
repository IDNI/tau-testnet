import json
import logging
from typing import Optional, Set

import config
import db
import chain_state

logger = logging.getLogger(__name__)

class TipAdmissionView:
    """
    Shared read facade for mempool admission representing the canonical-tip context.
    Encapsulates all governance lookups so sendtx.py is thin and purely dispatch-driven.
    """

    @property
    def active_validators(self) -> Set[str]:
        """Provides the active validator set at canonical tip."""
        validators = getattr(config, "MINER_PUBKEYS", [])
        if not validators and config.MINER_PUBKEY:
            validators = [config.MINER_PUBKEY]
        
        # If there's a dynamic validator set managed by the host contract, fetch it from chain_state
        # For v1, falling back to config for boot:
        if getattr(chain_state, "_lifecycle_manager", None):
            state_vals = chain_state._lifecycle_manager.active_validators
            if state_vals:
                if len(state_vals) == 1 and "00000000000000000000000000000000" in list(state_vals)[0]:
                    return set(validators)
                return set(state_vals)
        return set(validators)

    @property
    def next_block_height(self) -> int:
        """Returns the height that the next block would receive (tip + 1)."""
        latest_block = db.get_canonical_head_block()
        if latest_block:
            return latest_block['header']['block_number'] + 1
        return 1

    @property
    def current_consensus_rules(self) -> str:
        """Returns the exact UTF-8 bytes of current live consensus_rules at canonical tip."""
        return chain_state.get_rules_state() or ""

    @property
    def host_contract(self) -> dict:
        """Returns the active host contract configuration at canonical tip."""
        # For this version, defaults from config where undefined
        return {
            "proof_scheme": "bls_header_sig",
            "fork_choice_scheme": "height_then_hash",
            "input_contract_version": 1
        }

    def get_update_lifecycle_state(self, update_id: str) -> Optional[str]:
        """
        Lookup update_id across all lifecycle states.
        Returns one of: 'pending', 'approved-and-scheduled', 'archived' (covers activated/expired),
        or None if completely unknown.
        """
        # 1. Check archival
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute("SELECT 1 FROM consensus_archival WHERE update_id = ?", (update_id,))
            if cur.fetchone():
                return "archived"
            
            # 2. Check scheduled
            cur.execute("SELECT 1 FROM consensus_scheduled WHERE update_id = ?", (update_id,))
            if cur.fetchone():
                return "approved-and-scheduled"
            
            # 3. Check pending (exists in updates but not scheduled or archived)
            cur.execute("SELECT 1 FROM consensus_updates_v2 WHERE update_id = ?", (update_id,))
            if cur.fetchone():
                return "pending"
                
        return None

    def is_update_pending(self, update_id: str) -> bool:
        """Fast-path lookup exclusively for pending status."""
        return self.get_update_lifecycle_state(update_id) == "pending"

    def has_duplicate_vote(self, update_id: str, voter_pubkey: str) -> bool:
        """Checks if the same-validator vote is already recorded."""
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT 1 FROM consensus_votes_v2 WHERE update_id = ? AND voter_pubkey = ?",
                (update_id, voter_pubkey)
            )
            return cur.fetchone() is not None
