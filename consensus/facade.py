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

    # --- Co-signature approvals -------------------------------------------
    #
    # Read from the persisted tables and chain_state values rather than the
    # in-memory lifecycle manager, for the same reason rule sharing does:
    # admission runs on RPC/gossip threads while block apply mutates the
    # manager, and the tip tables are the same view every node has.

    @property
    def approval_slots_active(self) -> bool:
        """Whether i18..i25 are reserved and fed at the canonical tip.

        Consensus state, never a module global: block apply deep-copies the
        lifecycle manager per candidate block, so a global would leak across
        candidate simulation, rollback and reorg.
        """
        try:
            value = db.get_chain_state_value("approval_slots_active", "0")
        except Exception:
            return False
        return str(value) == "1"

    def get_approval_request(self, request_id: str) -> Optional[dict]:
        """The full request row, or None. Includes the recorded votes."""
        import json as _json

        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT request_id, sender_pubkey, recipient_pubkey, amount, "
                "expire_at_height, approvers_json, custom_inputs_json, "
                "voted_json, declined_json, status FROM approval_requests_v1 "
                "WHERE request_id = ?",
                (request_id,),
            )
            row = cur.fetchone()
        if not row:
            return None

        def _imap(raw):
            try:
                parsed = _json.loads(raw or "{}")
            except (TypeError, ValueError):
                return {}
            if not isinstance(parsed, dict):
                return {}
            out = {}
            for k, v in parsed.items():
                try:
                    out[int(k)] = v
                except (TypeError, ValueError):
                    continue
            return out

        try:
            declined = _json.loads(row[8] or "[]")
            declined = [int(d) for d in declined] if isinstance(declined, list) else []
        except (TypeError, ValueError):
            declined = []

        return {
            "request_id": row[0],
            "sender_pubkey": row[1],
            "recipient_pubkey": row[2],
            "amount": int(row[3] or 0),
            "expire_at_height": int(row[4] or 0),
            "approvers": _imap(row[5]),
            "custom_inputs": _imap(row[6]),
            "voted": _imap(row[7]),
            "declined": declined,
            "status": int(row[9] or 0),
        }

    def open_requests_for_sender(self, sender_pubkey: str) -> int:
        from consensus.approvals import STATUS_OPEN

        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM approval_requests_v1 "
                "WHERE sender_pubkey = ? AND status = ?",
                (sender_pubkey.lower(), STATUS_OPEN),
            )
            row = cur.fetchone()
        return int(row[0]) if row else 0

    def open_requests_for_approver(self, approver_pubkey: str) -> int:
        """Open requests naming this account as an approver.

        No indexed column for it -- the approver set is a JSON map -- so this
        scans the open rows. Bounded by MAX_PENDING_REQUESTS_PER_SENDER times the
        number of senders, and the open book is small by construction.
        """
        from consensus.approvals import STATUS_OPEN

        target = approver_pubkey.lower()
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT approvers_json FROM approval_requests_v1 WHERE status = ?",
                (STATUS_OPEN,),
            )
            rows = cur.fetchall()
        count = 0
        for (blob,) in rows:
            if target in (blob or "").lower():
                count += 1
        return count

    def open_requests_naming(self, approver_pubkey: str) -> list:
        """Open request rows naming this account as an approver.

        This is the inbox, and it IS the tier scoping: a request declares only
        the approvers its amount needs, so an approver whose vote is not needed
        never sees it.
        """
        import json as _json
        from consensus.approvals import STATUS_OPEN

        target = approver_pubkey.lower()
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT request_id, approvers_json FROM approval_requests_v1 "
                "WHERE status = ? ORDER BY request_id",
                (STATUS_OPEN,),
            )
            rows = cur.fetchall()
        out = []
        for request_id, blob in rows:
            try:
                approvers = _json.loads(blob or "{}")
            except (TypeError, ValueError):
                continue
            if not isinstance(approvers, dict):
                continue
            if target in {str(v).lower() for v in approvers.values()}:
                row = self.get_approval_request(request_id)
                if row:
                    out.append(row)
        return out

    def clause_author_count(self, target_stream: int) -> int:
        """How many principals hold a registered clause on this stream.

        Bounds the derived composite, and with it interpreter rebuild cost: every
        additional author multiplies it by roughly eight.
        """
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT COUNT(*) FROM rule_clauses_v1 WHERE target_stream = ?",
                (int(target_stream),),
            )
            row = cur.fetchone()
        return int(row[0]) if row else 0
