import json

import api_response
from consensus.admission import precheck_scheduled_update


def _normalize_hexish(value):
    if isinstance(value, bytes):
        return value.hex()
    return value


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return api_response.error_response(
            "getgovernance", "Usage: getgovernance", "INVALID_PARAMS"
        )

    chain_state = container.chain_state
    db = container.db

    with chain_state._balance_lock, chain_state._sequence_lock, chain_state._rules_lock:
        head = db.get_canonical_head_block() or {}
        header = head.get("header") or {}
        head_hash = head.get("block_hash", "")
        head_number = int(header.get("block_number", 0))

        active_validators = sorted(_normalize_hexish(v) for v in chain_state._lifecycle_manager.active_validators)
        validator_count = len(active_validators)
        next_block_height = head_number + 1
        min_activation_height = next_block_height + validator_count

        pending_updates = []
        scheduled_updates = []
        archival_updates = sorted(_normalize_hexish(uid) for uid in chain_state._lifecycle_manager.archival_updates)
        votes = []
        lifecycle = {}

        for uid, update in chain_state._lifecycle_manager.update_payloads.items():
            uid_hex = _normalize_hexish(uid)
            lifecycle[uid_hex] = "unknown"
            if uid in chain_state._lifecycle_manager.pending_updates:
                lifecycle[uid_hex] = "pending"
                pending_updates.append(
                    {
                        "update_id": uid_hex,
                        "rule_revisions": list(update.rule_revisions),
                        "activate_at_height": int(update.activate_at_height),
                        "host_contract_patch": update.host_contract_patch,
                        "proposer_pubkey": update.proposer_pubkey,
                    }
                )

        try:
            from consensus.governance import parse_consensus_rule_update
            mempool_tx_payloads = db.get_mempool_txs()
            for tx_payload_str in mempool_tx_payloads:
                try:
                    tx_data = json.loads(tx_payload_str)
                    update_obj = parse_consensus_rule_update(tx_data)
                    if update_obj:
                        uid_hex = _normalize_hexish(update_obj.update_id)
                        if uid_hex not in lifecycle:
                            lifecycle[uid_hex] = "mempool"
                            pending_updates.append(
                                {
                                    "update_id": uid_hex,
                                    "rule_revisions": list(update_obj.rule_revisions),
                                    "activate_at_height": int(update_obj.activate_at_height),
                                    "host_contract_patch": update_obj.host_contract_patch,
                                    "proposer_pubkey": update_obj.proposer_pubkey,
                                }
                            )
                except Exception:
                    continue
        except Exception:
            pass


        for activation_height, uid in chain_state._lifecycle_manager.scheduled_updates:
            uid_hex = _normalize_hexish(uid)
            lifecycle[uid_hex] = "approved-and-scheduled"
            entry = {
                "activation_height": int(activation_height),
                "update_id": uid_hex,
            }
            # The full payload is retained in update_payloads for the whole
            # scheduled lifetime (read at promotion and again at activation), so
            # surface it here too. Without this, clients can show the rule text of
            # PENDING proposals but not of approved/scheduled ones, even though the
            # node already holds it. Mirrors the pending serialization above.
            payload_obj = chain_state._lifecycle_manager.update_payloads.get(uid)
            if payload_obj is not None:
                entry["rule_revisions"] = list(payload_obj.rule_revisions)
                entry["activate_at_height"] = int(payload_obj.activate_at_height)
                entry["host_contract_patch"] = payload_obj.host_contract_patch
                entry["proposer_pubkey"] = payload_obj.proposer_pubkey
            # Advisory re-validation against the CURRENT validator set: an update
            # is checked when submitted, but activates later, and the tip moves in
            # between (issue #24 ask 4). Informational only — consensus never
            # reads it, so an operator gets a warning window while the terminal
            # behaviour of a bad activation is unchanged.
            precheck = precheck_scheduled_update(
                payload_obj, chain_state._lifecycle_manager.active_validators
            )
            entry["precheck"] = precheck["status"]
            if precheck["error"]:
                entry["precheck_error"] = precheck["error"]
            scheduled_updates.append(entry)

        for uid, voter_set in chain_state._lifecycle_manager.votes.items():
            uid_hex = _normalize_hexish(uid)
            for voter in voter_set:
                votes.append(
                    {
                        "update_id": uid_hex,
                        "voter_pubkey": _normalize_hexish(voter),
                    }
                )

        active_consensus_id = chain_state._active_consensus_id
        for uid_hex in archival_updates:
            if active_consensus_id and uid_hex.startswith(active_consensus_id):
                lifecycle[uid_hex] = "activated"
            elif lifecycle.get(uid_hex) not in ("pending", "approved-and-scheduled"):
                lifecycle[uid_hex] = "archived"

        # Payload of updates that already activated/archived. `archival_updates`
        # stays a list of bare hex strings — it is documented that way and the
        # CLI's `gov list` consumes it — so this is a parallel field rather than
        # a shape change (issue #23).
        #
        # `payload_available` is honest about a real limitation: activation does
        # not delete from update_payloads, but only pending|scheduled payloads are
        # persisted, so a node restart loses the text of everything already
        # activated. Widening the persistence set would grow without bound.
        archival_update_details = []
        for uid_hex in archival_updates:
            payload_obj = None
            for uid, obj in chain_state._lifecycle_manager.update_payloads.items():
                if _normalize_hexish(uid) == uid_hex:
                    payload_obj = obj
                    break
            entry = {
                "update_id": uid_hex,
                "lifecycle": lifecycle.get(uid_hex, "archived"),
                "payload_available": payload_obj is not None,
            }
            if payload_obj is not None:
                entry["rule_revisions"] = list(payload_obj.rule_revisions)
                entry["activate_at_height"] = int(payload_obj.activate_at_height)
                entry["host_contract_patch"] = payload_obj.host_contract_patch
                entry["proposer_pubkey"] = payload_obj.proposer_pubkey
            archival_update_details.append(entry)

        payload = {
            "head_hash": head_hash,
            "head_number": head_number,
            "next_block_height": next_block_height,
            "active_validator_count": validator_count,
            "approval_threshold": chain_state._lifecycle_manager.approval_threshold,
            # The resolved policy string, not just the integer it derives: at
            # N=4 validators, 'count:3' and 'supermajority' both yield 3, so the
            # threshold alone cannot tell a client which policy is active, nor
            # confirm that an activated vote_quorum patch took effect (#23).
            "vote_quorum": chain_state._lifecycle_manager.effective_quorum_policy(),
            "eligibility_mode": chain_state._lifecycle_manager.effective_eligibility_mode(),
            "active_validators": active_validators,
            "min_activation_height_for_next_update": min_activation_height,
            "active_consensus_id": active_consensus_id,
            "consensus_rules": chain_state._consensus_rules_state,
            "application_rules": chain_state._application_rules_state,
            "pending_updates": pending_updates,
            "scheduled_updates": scheduled_updates,
            "archival_updates": archival_updates,
            "archival_update_details": archival_update_details,
            "votes": sorted(votes, key=lambda entry: (entry["update_id"], entry["voter_pubkey"])),
            "lifecycle": lifecycle,
        }

    return api_response.success_response("getgovernance", payload)
