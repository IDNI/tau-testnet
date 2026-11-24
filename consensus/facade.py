import json
import logging
import time
from typing import List, Optional, Set

import config
import db
import chain_state
from consensus.grants import GrantBook
from consensus.payout_rules import PayoutRuleBook
from consensus.standing_payments import StandingPaymentBook

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

    # --- Co-signature approvals -------------------------------------------
    #
    # Request and vote rows come from the persisted tables, as rule sharing
    # does: the tip tables are the same view every node has.

    @property
    def approval_slots_active(self) -> bool:
        """Whether i18..i25 are reserved and fed at the canonical tip.

        Read from the canonical lifecycle manager, the source block apply reads,
        so admission refuses what apply refuses. Apply mutates only a copy and
        publishes it by swapping the reference, so this read sees one tip.
        """
        lm = getattr(chain_state, "_lifecycle_manager", None)
        return getattr(lm, "approval_slots_active", False) is True

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
            cur.execute(
                "SELECT COUNT(*) FROM rule_change_requests_v1 "
                "WHERE sender_pubkey = ? AND status = ?",
                (sender_pubkey.lower(), STATUS_OPEN),
            )
            rule_row = cur.fetchone()
        return (int(row[0]) if row else 0) + (int(rule_row[0]) if rule_row else 0)

    def get_rule_change_request(self, request_id: str) -> Optional[dict]:
        """The rule-change request row, or None. Any status."""
        import json as _json

        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT request_id, sender_pubkey, kind, body, offer_id, "
                "approvers_json, voted_json, declined_json, ready, created_height, "
                "expire_at_height, status FROM rule_change_requests_v1 "
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
            out = {}
            for k, v in (parsed.items() if isinstance(parsed, dict) else ()):
                try:
                    out[int(k)] = v
                except (TypeError, ValueError):
                    continue
            return out

        def _slots(raw):
            try:
                parsed = _json.loads(raw or "[]")
            except (TypeError, ValueError):
                return []
            return sorted(s for s in parsed if isinstance(s, int)) if isinstance(parsed, list) else []

        return {
            "request_id": row[0],
            "sender_pubkey": row[1],
            "kind": int(row[2]),
            "body": row[3],
            "offer_id": row[4],
            "approvers": _imap(row[5]),
            "voted": _imap(row[6]),
            "declined": _slots(row[7]),
            "ready": bool(row[8]),
            "created_height": int(row[9] or 0),
            "expire_at_height": int(row[10] or 0),
            "status": int(row[11] or 0),
        }

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
            cur.execute(
                "SELECT approvers_json FROM rule_change_requests_v1 WHERE status = ?",
                (STATUS_OPEN,),
            )
            rows += cur.fetchall()
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

    def open_rule_changes_naming(self, approver_pubkey: str) -> list:
        """Open rule-change request rows naming this account as an approver."""
        import json as _json
        from consensus.approvals import STATUS_OPEN

        target = approver_pubkey.lower()
        with db._db_lock:
            cur = db._db_conn.cursor()
            cur.execute(
                "SELECT request_id, approvers_json FROM rule_change_requests_v1 "
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
            if isinstance(approvers, dict) and target in {
                str(v).lower() for v in approvers.values()
            }:
                row = self.get_rule_change_request(request_id)
                if row:
                    out.append(row)
        return out

    # --- Retractable transfers ---------------------------------------------
    #
    # Persisted rows, not the in-memory manager, for the same reason as the
    # approval accessors. Absent tables read as an empty book.

    @property
    def tip_timestamp(self) -> int:
        """Header timestamp of the canonical tip; 0 when there is none."""
        try:
            head = db.get_canonical_head_block()
            return int(head["header"]["timestamp"]) if head else 0
        except Exception:
            return 0

    @property
    def next_block_timestamp(self) -> int:
        """Best guess of the next block's timestamp, for admission checks only."""
        # The tip lags the next block, and the genesis tip has timestamp 0.
        # Apply judges on the real block timestamp, so the clock cannot split nodes.
        return max(self.tip_timestamp, int(time.time()))

    def _retractable_scalar(self, sql: str, params: tuple = ()) -> int:
        try:
            with db._db_lock:
                row = db._db_conn.execute(sql, params).fetchone()
        except Exception:
            return 0
        return int(row[0] or 0) if row else 0

    def get_retractable(self, retractable_id: bytes) -> Optional[dict]:
        """The open entry with this id, or None (unknown or already resolved)."""
        try:
            with db._db_lock:
                row = db._db_conn.execute(
                    "SELECT sender_pubkey, recipient_pubkey, amount, sequence_number, "
                    "release_kind, release_at FROM retractable_transfers_v1 "
                    "WHERE retractable_id = ?",
                    (bytes(retractable_id).hex(),),
                ).fetchone()
        except Exception:
            return None
        if not row:
            return None
        return {
            "retractable_id": bytes(retractable_id).hex(),
            "sender_pubkey": row[0],
            "recipient_pubkey": row[1],
            "amount": int(row[2]),
            "sequence_number": int(row[3]),
            "release_kind": int(row[4]),
            "release_at": int(row[5]),
        }

    def get_receive_route(self, owner_pubkey: str) -> Optional[dict]:
        """The owner's installed receive route (#35), or None.

        Read from the canonical tip's lifecycle manager — the same in-memory
        source the eligibility and validator views above use. (Retractable
        entries are read from their db table because that book is persisted;
        the route book's persistence is a follow-up, so the manager is the
        only honest source today.)
        """
        lm = getattr(chain_state, "_lifecycle_manager", None)
        book = getattr(lm, "receive_routes", None)
        if book is None:
            return None
        entry = book.get(owner_pubkey)
        if entry is None:
            return None
        return {
            "route_id": entry.route_id.hex(),
            "owner_pubkey": entry.owner_pubkey,
            "destination_pubkey": entry.destination_pubkey,
            "bps": entry.bps,
            "min_amount": entry.min_amount,
            "activation_ts": entry.activation_ts,
            "expiry_ts": entry.expiry_ts,
            "locked_until_ts": entry.locked_until_ts,
            "version": entry.version,
            "form": entry.form,
            "clause_text": entry.clause_text,
        }

    def _tip_standing_book(self) -> Optional[StandingPaymentBook]:
        lm = getattr(chain_state, "_lifecycle_manager", None)
        book = getattr(lm, "standing_payments", None)
        return book if isinstance(book, StandingPaymentBook) else None

    def _standing_payment_view(self, book: StandingPaymentBook, entry) -> dict:
        """The full view of one standing-payment authorization (#34).

        Terms and progress come from the book's own rows — the exact tuples
        `StandingPaymentBook.restore` consumes, so admission can rebuild the
        book from this dict and call its can_* verbs verbatim — and the
        computed fields (status, next due, totals, paid-period facts) are
        the book's own answers at the next block's timestamp. One source
        for the getstandingpayment command, admission and tests.
        """
        row = next(r for r in book.rows() if r[0] == entry.auth_id)
        (auth_id, payer, recipient, amount, kind, day, anchor, window,
         final_ts, max_occ, max_total, fee_limit, policy_ref, catch_up,
         version, settled, total_paid, last_exec, cancelled,
         cancelled_ts, form, clause_text, due_retry_seconds) = row
        ts = self.next_block_timestamp
        occurrences, total = book.total_executed(entry.auth_id)
        return {
            "auth_id": entry.auth_id.hex(),
            "payer_pubkey": payer,
            "recipient_pubkey": recipient,
            "amount": amount,
            "schedule_kind": kind,
            "signed_day": day,
            "anchor_ts": anchor,
            "window_seconds": window,
            "final_ts": final_ts,
            "max_occurrences": max_occ,
            "max_total": max_total,
            "fee_limit": fee_limit,
            "policy_version_ref": policy_ref,
            "allow_catch_up": catch_up,
            "version": version,
            "form": form,
            "clause_text": clause_text,
            "due_retry_seconds": due_retry_seconds,
            "retries_owed": [
                {
                    "period_index": retry.period_index,
                    "due_ts": retry.due_ts,
                    "retry_until": retry.retry_until,
                    "recorded_height": retry.recorded_height,
                }
                for retry in book.owed_retries()
                if retry.auth_id == entry.auth_id
            ],
            "settled_periods": list(settled),
            "total_paid": total_paid,
            "last_execution_ts": last_exec,
            "cancelled": cancelled,
            "cancelled_ts": cancelled_ts,
            "status": book.status(entry.auth_id, ts),
            "next_due_ts": book.next_due_ts(entry.auth_id, ts),
            "occurrences_executed": occurrences,
            "total_executed": total,
            "paid_facts": [
                {
                    "period_index": fact.period_index,
                    "period_start_ts": fact.period_start_ts,
                    "period_end_ts": fact.period_end_ts,
                    "amount": fact.amount,
                    "execution_ts": fact.execution_ts,
                }
                for fact in book.facts_for(entry.auth_id)
            ],
        }

    def get_standing_payment(self, auth_id: bytes) -> Optional[dict]:
        """One standing-payment authorization (#34) by id, or None.

        Read from the canonical tip's lifecycle manager — the same
        in-memory source get_receive_route uses (the standing book's db
        persistence is the same follow-up as the route book's).
        """
        book = self._tip_standing_book()
        if book is None:
            return None
        entry = book.get(bytes(auth_id))
        if entry is None:
            return None
        return self._standing_payment_view(book, entry)

    def get_standing_payment_for_series(
        self, payer_pubkey: str, recipient_pubkey: str,
        schedule_kind: int, anchor_ts: int,
    ) -> Optional[dict]:
        """The current version of one authorization series, or None.

        Create admission needs the series' current entry so it can call
        the book's can_create verbatim — the next-version rule lives in
        the book, not here.
        """
        book = self._tip_standing_book()
        if book is None:
            return None
        for row in book.rows():
            if (row[1], row[2], row[4], row[6]) == (
                payer_pubkey, recipient_pubkey, schedule_kind, anchor_ts
            ):
                entry = book.get(row[0])
                if entry is not None:
                    return self._standing_payment_view(book, entry)
        return None

    def _tip_payout_book(self) -> Optional[PayoutRuleBook]:
        lm = getattr(chain_state, "_lifecycle_manager", None)
        book = getattr(lm, "payout_rules", None)
        return book if isinstance(book, PayoutRuleBook) else None

    def _payout_rule_view(self, book: PayoutRuleBook, entry) -> dict:
        """The full view of one payout rule (#63).

        Terms and progress come from the book's own rows — the exact tuples
        `PayoutRuleBook.restore` consumes, so admission can rebuild the
        book from this dict and call its can_* verbs verbatim — and the
        computed fields (current period, its paid total, the settlement
        records) are the book's own answers at the next block's timestamp.
        One source for the getpayoutrule command, admission and tests.
        """
        from consensus.payout_rules import period_index_at

        row = next(r for r in book.rows() if r[0] == entry.rule_id)
        (rule_id, owner, recipients, legs, max_exec, max_period,
         period_seconds, anchor, version, period_totals,
         form, clause_text) = row[:12]
        rule_index = int(row[12]) if len(row) > 12 else 0
        shared_cap_id = str(row[13]) if len(row) > 13 else ""
        shared_cap_amount = int(row[14]) if len(row) > 14 else 0
        ts = self.next_block_timestamp
        period = period_index_at(entry, ts)
        return {
            "rule_id": entry.rule_id.hex(),
            "rule_index": rule_index,
            "shared_cap_id": shared_cap_id,
            "shared_cap_amount": shared_cap_amount,
            "owner_pubkey": owner,
            "recipients": list(recipients),
            "legs": [
                {"recipient_pubkey": r, "mode": m, "value": v}
                for r, m, v in legs
            ],
            "form": form,
            "clause_text": clause_text,
            "max_per_execution": max_exec,
            "max_per_period": max_period,
            "period_seconds": period_seconds,
            "period_anchor_ts": anchor,
            "version": version,
            "period_totals": [
                {"period_index": i, "total": t} for i, t in period_totals
            ],
            "current_period_index": period,
            "current_period_total": (
                book.period_total(entry.rule_id, period) if period >= 0 else 0
            ),
            # Never below 0: a carried total may stand over a lowered cap
            # (FIX 5C); None when the rule names no per-period cap.
            "left_this_period": (
                None
                if max_period == 0
                else max(
                    0,
                    max_period
                    - (
                        book.period_total(entry.rule_id, period)
                        if period >= 0
                        else 0
                    ),
                )
            ),
            # The shared cap's group accounting at the same instant
            # (FIX 8): what the group has paid in its current periods and
            # the room left under THIS rule's declared amount. None when
            # the rule names no shared cap.
            "shared_cap_used": (
                None
                if not shared_cap_id
                else book.shared_cap_usage(owner, shared_cap_id, ts)
            ),
            "shared_cap_left": (
                book.shared_cap_left(entry, ts)
            ),
            "settlements": [
                {
                    "settlement_id": s.settlement_id.hex(),
                    "base_amount": s.base_amount,
                    "total": s.total,
                    "execution_ts": s.execution_ts,
                }
                for s in book.settlements_for(entry.rule_id)
            ],
        }

    def get_payout_rule(self, rule_id: bytes) -> Optional[dict]:
        """One payout rule (#63) by id, or None.

        Read from the canonical tip's lifecycle manager — the same
        in-memory source get_receive_route uses (the payout book's db
        persistence is the same follow-up as the other books').
        """
        book = self._tip_payout_book()
        if book is None:
            return None
        entry = book.get_by_id(bytes(rule_id))
        if entry is None:
            return None
        return self._payout_rule_view(book, entry)

    def get_payout_rule_for_owner(self, owner_pubkey: str) -> Optional[dict]:
        """The payout rule at one owner's slot 0, or None.

        Slot 0 is the rule every pre-multi-rule caller means: the owner's
        first rule. Callers that need the whole book use
        get_payout_rules_for_owner.
        """
        return self.get_payout_rule_for_owner_index(owner_pubkey, 0)

    def get_payout_rule_for_owner_index(
        self, owner_pubkey: str, rule_index: int
    ) -> Optional[dict]:
        """The payout rule at one owner's one slot (FIX 7), or None."""
        book = self._tip_payout_book()
        if book is None:
            return None
        entry = book.get(owner_pubkey, int(rule_index))
        if entry is None:
            return None
        return self._payout_rule_view(book, entry)

    def get_payout_rules_for_owner(self, owner_pubkey: str) -> List[dict]:
        """Every payout rule one owner holds, in slot order (FIX 7).

        Install admission needs the owner's whole book so it can call the
        book's can_install verbatim — the per-slot version chain and the
        slot bound live in the book, not here.
        """
        book = self._tip_payout_book()
        if book is None:
            return []
        return [
            self._payout_rule_view(book, entry)
            for entry in book.get_all(owner_pubkey)
        ]

    def _tip_grant_book(self) -> Optional[GrantBook]:
        lm = getattr(chain_state, "_lifecycle_manager", None)
        book = getattr(lm, "grants", None)
        return book if isinstance(book, GrantBook) else None

    def _shared_cap_view(self, book: GrantBook, funder_pubkey: str) -> Optional[dict]:
        """One funder's shared cap as a restore-shaped dict, or None."""
        for row in book.shared_cap_rows():
            if row[1] == funder_pubkey:
                (cap_id, funder, amount, period_seconds, anchor,
                 version, totals) = row
                return {
                    "cap_id": cap_id.hex(),
                    "funder_pubkey": funder,
                    "cap_amount": amount,
                    "period_seconds": period_seconds,
                    "period_anchor_ts": anchor,
                    "version": version,
                    "period_totals": [
                        {"period_index": i, "total": t} for i, t in totals
                    ],
                }
        return None

    def _grant_view(self, book: GrantBook, entry) -> dict:
        """The full view of one grant (stages 2-5).

        Terms and progress come from the book's own rows — the exact
        tuples `GrantBook.restore` consumes, so admission can rebuild the
        book from this dict and call its verbs verbatim — and the computed
        fields (status, effective deadline, released/spendable/held) are
        the book's own answers at the next block's timestamp. The funder's
        shared cap rides along because a draw's verdict depends on it:
        without it the rebuilt book could not answer evaluate_draw the way
        the full book does. One source for the getgrant command, admission
        and tests.
        """
        from consensus.grants import released_by

        row = next(r for r in book.rows() if r[0] == entry.grant_id)
        (grant_id, funder, beneficiary, total, release, kind, day, start,
         deadline, locked, win_start, win_end, inactivity, version,
         spent, last_draw, refunded, refunded_amount, refunded_ts,
         form, clause_text, periods_from_ts) = row
        ts = self.next_block_timestamp
        return {
            "grant_id": entry.grant_id.hex(),
            "funder_pubkey": funder,
            "beneficiary_pubkey": beneficiary,
            "total_amount": total,
            "release_per_period": release,
            "schedule_kind": kind,
            "signed_day": day,
            "start_ts": start,
            "deadline_ts": deadline,
            "locked_until_ts": locked,
            "window_start_ts": win_start,
            "window_end_ts": win_end,
            "inactivity_seconds": inactivity,
            "version": version,
            "form": form,
            "clause_text": clause_text,
            "periods_from_ts": periods_from_ts,
            "total_spent": spent,
            "last_draw_ts": last_draw,
            "refunded": bool(refunded),
            "refunded_amount": refunded_amount,
            "refunded_ts": refunded_ts,
            "status": book.status(entry.grant_id, ts),
            "effective_deadline_ts": book.deadline_of(entry.grant_id),
            "released": released_by(entry, ts),
            "spendable": book.spendable(entry.grant_id, ts),
            "held": book.held(entry.grant_id),
            "shared_cap": self._shared_cap_view(book, funder),
        }

    def get_grant(self, grant_id: bytes) -> Optional[dict]:
        """One grant (stages 2-5) by id, or None.

        Read from the canonical tip's lifecycle manager — the same
        in-memory source get_payout_rule uses (the grant book's db
        persistence is the same follow-up as the other books').
        """
        book = self._tip_grant_book()
        if book is None:
            return None
        entry = book.get(bytes(grant_id))
        if entry is None:
            return None
        return self._grant_view(book, entry)

    def get_shared_cap(self, funder_pubkey: str) -> Optional[dict]:
        """One funder's shared cap (stages 2-5), or None.

        Shared-cap admission needs the funder's current cap so it can call
        the book's can_set_shared_cap verbatim — the next-version rule
        lives in the book, not here.
        """
        book = self._tip_grant_book()
        if book is None:
            return None
        return self._shared_cap_view(book, funder_pubkey)

    def get_balance(self, pubkey: str) -> int:
        """The spendable balance at the canonical tip (chain_state's read)."""
        try:
            return int(chain_state.get_balance(pubkey))
        except Exception:
            return 0

    def open_retractable_count_for_sender(self, sender_pubkey: str) -> int:
        return self._retractable_scalar(
            "SELECT COUNT(*) FROM retractable_transfers_v1 WHERE sender_pubkey = ?",
            (sender_pubkey,),
        )

    def open_retractable_count(self) -> int:
        return self._retractable_scalar("SELECT COUNT(*) FROM retractable_transfers_v1")

    def escrowed_out(self, pubkey: str) -> int:
        return self._retractable_scalar(
            "SELECT COALESCE(SUM(amount), 0) FROM retractable_transfers_v1 "
            "WHERE sender_pubkey = ?",
            (pubkey,),
        )

    def escrowed_in(self, pubkey: str) -> int:
        return self._retractable_scalar(
            "SELECT COALESCE(SUM(amount), 0) FROM retractable_transfers_v1 "
            "WHERE recipient_pubkey = ?",
            (pubkey,),
        )
