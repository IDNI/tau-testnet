import json


def _normalize_hexish(value):
    if isinstance(value, bytes):
        return value.hex()
    return value


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return "ERROR: Usage: getgovernance\r\n"

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
                    }
                )

        for activation_height, uid in chain_state._lifecycle_manager.scheduled_updates:
            uid_hex = _normalize_hexish(uid)
            lifecycle[uid_hex] = "approved-and-scheduled"
            scheduled_updates.append(
                {
                    "activation_height": int(activation_height),
                    "update_id": uid_hex,
                }
            )

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

        payload = {
            "head_hash": head_hash,
            "head_number": head_number,
            "next_block_height": next_block_height,
            "active_validator_count": validator_count,
            "approval_threshold": chain_state._lifecycle_manager.approval_threshold,
            "active_validators": active_validators,
            "min_activation_height_for_next_update": min_activation_height,
            "active_consensus_id": active_consensus_id,
            "consensus_rules": chain_state._consensus_rules_state,
            "application_rules": chain_state._application_rules_state,
            "pending_updates": pending_updates,
            "scheduled_updates": scheduled_updates,
            "archival_updates": archival_updates,
            "votes": sorted(votes, key=lambda entry: (entry["update_id"], entry["voter_pubkey"])),
            "lifecycle": lifecycle,
        }

    return json.dumps(payload, sort_keys=True) + "\r\n"
