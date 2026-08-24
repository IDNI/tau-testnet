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
    def eligibility_mode(self) -> str:
        """Proposer-eligibility regime in force at canonical tip.

        Admission needs it because i13 is a reserved consensus stream only under
        tau_validator_set (the sole mode that feeds it) and an ordinary custom
        stream otherwise."""
        lm = getattr(chain_state, "_lifecycle_manager", None)
        if lm is None:
            return ""
        return getattr(lm, "effective_eligibility_mode", lambda: "")()

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

    # --- Rule sharing -----------------------------------------------------
    #
    # Read from the persisted tables rather than the in-memory lifecycle
    # manager: admission runs on RPC/gossip threads while block apply mutates
    # the manager, and the tip tables are the same view every node has.

    def get_offer_lifecycle_state(self, offer_id: str) -> Optional[str]:
        """'offered', a terminal status, or None when the offer is unknown."""
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT status FROM rule_offers_v1 WHERE offer_id = ?", (offer_id,)
            )
            row = cur.fetchone()
        return row[0] if row else None

    def get_offer(self, offer_id: str) -> Optional[dict]:
        """The full offer row, or None. Includes the node-local rule text."""
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT offer_id, offerer_pubkey, recipient_pubkey, rule_text, "
                "expire_at_height, status FROM rule_offers_v1 WHERE offer_id = ?",
                (offer_id,),
            )
            row = cur.fetchone()
        if not row:
            return None
        return {
            "offer_id": row[0],
            "offerer_pubkey": row[1],
            "recipient_pubkey": row[2],
            "rule_text": row[3],
            "expire_at_height": int(row[4] or 0),
            "status": row[5],
        }

    def pending_offers_for_recipient(self, recipient_pubkey: str) -> int:
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM rule_offers_v1 "
                "WHERE recipient_pubkey = ? AND status = 'offered'",
                (recipient_pubkey.lower(),),
            )
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def pending_offers_for_offerer(self, offerer_pubkey: str) -> int:
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM rule_offers_v1 "
                "WHERE offerer_pubkey = ? AND status = 'offered'",
                (offerer_pubkey.lower(),),
            )
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def clause_for(self, acceptor_pubkey: str, target_stream: int) -> Optional[str]:
        """The acceptor's currently registered clause body for a stream."""
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT clause_body FROM rule_clauses_v1 "
                "WHERE acceptor_pubkey = ? AND target_stream = ?",
                (acceptor_pubkey.lower(), int(target_stream)),
            )
            row = cur.fetchone()
        return row[0] if row else None

    def clauses_for_stream(self, target_stream: int) -> dict:
        """acceptor pubkey -> clause body, for composing a stream's rule."""
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT acceptor_pubkey, clause_body FROM rule_clauses_v1 "
                "WHERE target_stream = ?",
                (int(target_stream),),
            )
            return {row[0]: row[1] for row in cur.fetchall()}
