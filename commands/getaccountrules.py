"""Everything in force for one account's rules, at one tip (issue #42).

A wallet used to piece "is my protection on?" together from several places:
the o5 clause and the rule-change guard (getruleoffers / getapprovalslots), open
rule-change requests (getapprovalrequests, by approver), units in the
application-rules accumulation (gettaustate, the whole text), and nothing at all
for "did my last rule transaction change anything". This answers it in one call:

  clauses              the account's registry clauses, guard excluded, each with
                       the sha256 of the stored body and, where this node
                       recorded it, the block and transaction that set it
  rule_change_guard    the guard clause, same shape, or null
  application_rules    accumulated units that name the account's key, as stored
  fee_rules            every accumulated unit that writes the fee stream o8,
                       whoever sent it, in the order the units joined. The
                       engine works out o8 from the whole specification for
                       every transaction, so a unit that never names this
                       account can still change what it pays (#183). Each
                       carries `names_this_account` and `sent_by`: the
                       accounts whose rule transaction accumulated it, from
                       this node's record, or null where the node has none
                       (a genesis unit, or one from before it began recording)
  running_spec         the specification the engine runs at this head, as the
                       engine revised it (canonical form), with its sha256. A
                       later unit can revise part of an earlier one, so the
                       stored units above are what was sent and this is what is
                       in force. Null text with `unavailable` on a node without
                       the authoritative engine
  open_rule_changes    the account's own rule-change requests still open
  awaiting_my_vote     open rule-change requests naming the account as approver
  pending_offers       rule offers addressed to the account, not yet decided
  mempool              rule transactions from the account not yet in a block
  history              the latest rule effects naming the account (newest first)

All chain fields come from ONE tip: the in-memory state is read under the
locks the block swap holds, so a block landing mid-call cannot mix two tips.
`history` and `since` are node-local records of blocks this node applied or
replayed (see gettxstatus `outcome`); they are absent, not empty, for older
blocks. Comparing `sha256` with the hash of the text a wallet sent is the
check that the rule in force is the one the user meant.
"""
import hashlib
import json
import logging

import api_response
import tau_defs

logger = logging.getLogger(__name__)

_CMD = "getaccountrules"

_HISTORY_LIMIT = 20

_KIND_NAMES = {
    tau_defs.RULE_CHANGE_KIND_SET_POLICY: "set_policy",
    tau_defs.RULE_CHANGE_KIND_REVOKE_POLICY: "revoke_policy",
    tau_defs.RULE_CHANGE_KIND_ACCEPT_OFFER: "accept_offer",
    tau_defs.RULE_CHANGE_KIND_SET_GUARD: "set_guard",
    tau_defs.RULE_CHANGE_KIND_REVOKE_GUARD: "revoke_guard",
}

_RULE_TX_TYPES = (
    "rule_offer_accept", "rule_offer_reject",
    "rule_change_request", "rule_change_cancel",
)


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


_FEE_STREAM = "o%d" % tau_defs.CUSTOM_FEE_STREAM_INDEX


def _writes_fee(unit: str) -> bool:
    from consensus.admission import _streams_referenced

    return bool(_streams_referenced(unit, (_FEE_STREAM,)))


def _fee_rules(units, accumulated, address: str) -> list:
    """The units among `units` that write o8, with who sent each one.

    `accumulated` are this node's records of units joining the accumulation on
    the canonical chain, oldest first; a unit without one gets `sent_by` null.
    """
    needle = "#x" + address
    senders, first = {}, {}
    for effect in accumulated:
        sha = effect.get("sha256")
        senders.setdefault(sha, set()).add(effect["account"])
        first.setdefault(sha, effect)
    rows, seen = [], set()
    for unit in units:
        if not unit or unit in seen or not _writes_fee(unit):
            continue
        seen.add(unit)
        sha = _sha256(unit)
        rows.append({
            "unit": unit,
            "sha256": sha,
            "names_this_account": needle in unit.lower(),
            "sent_by": sorted(senders[sha]) if sha in senders else None,
            "since": _since_of(first[sha]) if sha in first else None,
        })
    return rows


def _since_of(effect) -> dict:
    since = {"block_number": int(effect["block_number"])}
    for key in ("tx_hash", "request_id"):
        if effect.get(key):
            since[key] = effect[key]
    return since


def _canonical_accumulated(database) -> list:
    """`accumulated` application-rule effects on the canonical chain, oldest first."""
    try:
        rows = database.get_rule_effect_rows(kind="application_rule")
    except Exception:
        logger.exception("Failed to read who sent the accumulated units")
        return []
    canonical = {}
    out = []
    for effect in rows:
        if effect.get("action") != "accumulated":
            continue
        block_hash = effect.get("block_hash")
        if block_hash not in canonical:
            try:
                canonical[block_hash] = database.get_canonical_confirmation(
                    block_hash, int(effect["block_number"]))[0]
            except Exception:
                canonical[block_hash] = False
        if canonical[block_hash]:
            out.append(effect)
    return out


def fee_rules_for(database, address: str, app_rules: str) -> list:
    """Every accumulated unit that writes o8, with who sent it (see `_fee_rules`).

    Read-only view over the node-local rule-effects record and the current
    accumulation; no state-hash change, no new consensus behaviour.
    """
    return _fee_rules(
        [u.strip() for u in (app_rules or "").split("\n")],
        _canonical_accumulated(database), address)


def _tip_view(chain_state):
    """(head hash, lifecycle manager, application rules) as one consistent read."""
    with chain_state._balance_lock, chain_state._sequence_lock, chain_state._rules_lock:
        return (
            getattr(chain_state, "_canonical_head_hash", None),
            chain_state._lifecycle_manager,
            chain_state._application_rules_state or "",
        )


def tip_and_running_spec(chain_state, store=None):
    """`_tip_view` plus the running spec at the same head.

    The running spec carries the head it was read with. A block that commits
    between the two reads moves one of them; read again (at most three times) so
    the answer names one block.
    """
    import tau_running_spec

    for _ in range(3):
        view = _tip_view(chain_state)
        running = tau_running_spec.at_head(store)
        if running.get("block_hash") in (None, view[0]):
            break
    return view, running


def _request_row(rid: bytes, entry) -> dict:
    return {
        "request_id": rid.hex(),
        "kind": _KIND_NAMES.get(entry.kind, str(entry.kind)),
        "body_sha256": _sha256(entry.body) if entry.body else None,
        "offer_id": entry.offer_id or None,
        "approvers": {str(k): v for k, v in sorted(entry.approvers.items())},
        "voted": {str(k): v for k, v in sorted(entry.voted.items())},
        "declined": sorted(entry.declined),
        "ready": bool(entry.ready),
        "created_height": int(entry.created_height),
        "expire_at_height": int(entry.expire_at_height),
    }


def _mempool_rule_txs(database, address: str) -> list:
    """Rule-bearing transactions from this address still waiting for a block."""
    out = []
    try:
        entries = database.get_mempool_entries()
    except Exception:
        return out
    for entry in entries:
        raw = entry.get("payload")
        text = raw[5:] if isinstance(raw, str) and raw.startswith("json:") else raw
        try:
            tx = json.loads(text)
        except Exception:
            continue
        if (tx.get("sender_pubkey") or "").lower() != address:
            continue
        tx_type = tx.get("tx_type") or "user_tx"
        ops = tx.get("operations") if isinstance(tx.get("operations"), dict) else {}
        if tx_type in _RULE_TX_TYPES or (tx_type == "user_tx" and str(ops.get("0") or "").strip()):
            out.append({"tx_hash": entry.get("tx_hash"), "tx_type": tx_type})
    return out


def _since(history: list, stream=None, sha=None, kind="clause"):
    """The latest recorded effect that put this exact text in place, if any."""
    for effect in history:
        if effect.get("kind") != kind or effect.get("sha256") != sha:
            continue
        if stream is not None and effect.get("stream") != stream:
            continue
        if effect.get("action") in ("registered", "replaced", "accumulated"):
            since = {"block_number": effect["block_number"]}
            for key in ("tx_hash", "request_id"):
                if effect.get(key):
                    since[key] = effect[key]
            return since
    return None


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address>", "INVALID_PARAMS"
        )
    from consensus.approvals import ApprovalShapeError, _normalize_pubkey

    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    chain_state = container.chain_state
    database = container.db
    try:
        (head_hash, lm, app_rules), running = tip_and_running_spec(chain_state)
        head = database.get_block_by_hash(head_hash) if head_hash else None
        if head is None:
            head = database.get_canonical_head_block()
        header = (head or {}).get("header") or {}

        offers = lm.rule_offers
        own = sorted(
            (stream, body) for (who, stream), body in offers.accepted_clauses.items()
            if who == address
        )
        try:
            history = database.get_canonical_rule_effects(address, limit=_HISTORY_LIMIT)
        except Exception:
            logger.exception("Failed to read rule history for %s", address)
            history = []

        guard_index = tau_defs.RULE_CHANGE_GUARD_INDEX
        clauses, guard = [], None
        for stream, body in own:
            sha = _sha256(body)
            item = {"body": body, "sha256": sha,
                    "since": _since(history, stream=stream, sha=sha)}
            if stream == guard_index:
                guard = item
            else:
                clauses.append({"stream": stream, "name": f"o{stream}", **item})

        needle = "#x" + address
        units = []
        for unit in (u.strip() for u in app_rules.split("\n")):
            if unit and needle in unit.lower():
                sha = _sha256(unit)
                units.append({"unit": unit, "sha256": sha,
                              "since": _since(history, sha=sha, kind="application_rule")})

        fee_rules = fee_rules_for(database, address, app_rules)

        approvals = lm.approval_requests
        open_changes = [
            _request_row(rid, entry)
            for rid, entry in sorted(approvals.open_rule_changes().items())
            if entry.sender_pubkey == address
        ]
        to_vote = [
            {**_request_row(rid, entry), "sender_pubkey": entry.sender_pubkey}
            for rid, entry in approvals.rule_change_inbox_for(address)
        ]

        data = {
            "address": address,
            "block_number": int(header.get("block_number", 0)) if header else None,
            "block_hash": (head or {}).get("block_hash") or head_hash,
            "rule_clauses_root": "" if offers.is_empty() else offers.clauses_root().hex(),
            "clauses": clauses,
            "rule_change_guard": guard,
            "application_rules": units,
            "fee_rules": fee_rules,
            "running_spec": running,
            "open_rule_changes": open_changes,
            "awaiting_my_vote": to_vote,
            "pending_offers": offers.pending_count_for_recipient(address),
            "mempool": _mempool_rule_txs(database, address),
            "history": history,
        }
    except Exception as exc:
        logger.exception("Failed to build account rules for %s", address)
        return api_response.error_response(
            _CMD, f"Failed to read account rules: {exc}", "INTERNAL_ERROR"
        )
    return api_response.success_response(_CMD, data)
