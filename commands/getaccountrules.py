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
                       every transaction, and a fee rule is admitted only
                       when it is fenced to its sender's own key (#183). Each
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

`getaccountrules <address> <block>` answers for an earlier block of the
canonical chain (a number or a hash): the clauses and the guard the account
had when that block committed, the application rules naming it, the running
spec of that block and the history up to it. The clauses come from this node's
record of rule effects and the texts it kept with them; the running spec comes
from the committed journal up to that block's journal head. What this node
cannot know (a block it did not record) is named, never guessed: `complete`
says whether every part of the answer is certain, `recorded_from` where the
unbroken record that reaches the block begins. The fields that exist only at
the tip (open requests, offers, the mempool, the registry root) are left out.
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


def _canonical(rows, chain):
    return [e for e in rows
            if e["block_number"] < len(chain) and chain[e["block_number"]] == e["block_hash"]]


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


_NOT_RECORDED = "this node did not record the block that set it"
_HEX = "0123456789abcdef"


class _BadBlock(ValueError):
    """The block asked for is not one this node can answer for."""


def _resolve_block(chain: list, wanted: str) -> int:
    """The height on the canonical chain that `wanted` (a number or a hash) names."""
    text = wanted.strip().lower()
    if text.isdigit() and len(text) < 20:
        number = int(text)
        if number >= len(chain):
            raise _BadBlock(f"block {number} is above the head ({len(chain) - 1})")
        return number
    if len(text) == 64 and all(c in _HEX for c in text):
        if text in chain:
            return chain.index(text)
        raise _BadBlock("that block is not on the canonical chain")
    raise _BadBlock("the block is a block number or a 64-character block hash")


def _state_at(effects: list, number: int, first: int, through_tip: bool, live):
    """What one clause stream held when block `number` committed.

    `effects` are the stream's canonical effects, oldest first; `first` the
    height at which the unbroken record that reaches `number` begins (`number
    + 1` when the block itself is not recorded); `live` the body in the
    registry now. Returns (effect or None, body or None, why not known or None).
    """
    if through_tip and effects:
        # The whole record after this block is there, so its last word has to
        # be what the registry holds now. If it is not, do not answer from it.
        newest = effects[-1]
        if (live is None) != (newest["action"] == "revoked") or (
                live is not None and _sha256(live) != newest.get("sha256")):
            return None, None, "this node's record does not match its registry"
    known = [e for e in effects if first <= e["block_number"] <= number]
    if known:
        last = known[-1]
        if last["action"] == "revoked":
            return last, None, None
        body = last.get("body")
        if body is None and live is not None and _sha256(live) == last.get("sha256"):
            body = live
        return last, body, None if body is not None else "this node did not keep the text"
    if first <= 1:
        return None, None, None
    if not through_tip:
        return None, None, _NOT_RECORDED
    later = [e for e in effects if e["block_number"] > number]
    if not later:
        return None, live, None            # untouched since: what the registry holds now
    if later[0]["action"] == "registered":
        return None, None, None            # the first clause came after this block
    return None, None, _NOT_RECORDED


def _since_of(effect) -> dict:
    since = {"block_number": int(effect["block_number"])}
    for key in ("tx_hash", "request_id"):
        if effect.get(key):
            since[key] = effect[key]
    return since


def _history_row(effect) -> dict:
    row = {"block_number": int(effect["block_number"]), "kind": effect["kind"],
           "action": effect["action"]}
    for key in ("tx_hash", "request_id", "sha256", "detail"):
        if effect.get(key):
            row[key] = effect[key]
    if effect.get("stream") is not None:
        row["stream"] = int(effect["stream"])
    return row


def at_block(chain_state, database, address: str, wanted: str) -> dict:
    """The account's rules when an earlier block committed (see the module text)."""
    import tau_running_spec

    for _ in range(3):
        head_hash, lm, _app_rules = _tip_view(chain_state)
        chain = database.canonical_chain()
        if chain and chain[-1] == head_hash:
            break
    else:
        raise _BadBlock("the chain moved during the read; ask again")
    number = _resolve_block(chain, wanted)
    block_hash = chain[number]

    recorded = database.recorded_outcome_blocks(chain[1:])
    first = number + 1
    while first > 1 and chain[first - 1] in recorded:
        first -= 1
    through_tip = all(h in recorded for h in chain[number + 1:])

    def canonical(rows):
        return _canonical(rows, chain)

    own = canonical(database.get_rule_effect_rows(account=address))
    live = {stream: body for (who, stream), body in lm.rule_offers.accepted_clauses.items()
            if who == address}
    by_stream = {}
    for effect in own:
        if effect["kind"] == "clause" and effect.get("stream") is not None:
            by_stream.setdefault(int(effect["stream"]), []).append(effect)

    guard_index = tau_defs.RULE_CHANGE_GUARD_INDEX
    clauses, guard, complete = [], None, True
    for stream in sorted(set(by_stream) | set(live)):
        effect, body, unknown = _state_at(
            by_stream.get(stream, []), number, first, through_tip, live.get(stream))
        if body is None and not unknown:
            continue
        item = {"body": body,
                "sha256": _sha256(body) if body is not None else (effect or {}).get("sha256"),
                "since": _since_of(effect) if effect is not None else None}
        if unknown:
            item["unavailable"] = unknown
            complete = False
        if stream == guard_index:
            guard = item
        else:
            clauses.append({"stream": stream, "name": f"o{stream}", **item})

    # The accumulation only grows, so the units of a block are the genesis
    # units and every unit accumulated up to it. Certain only on a node that
    # recorded every block up to this one, with the texts.
    units, fee_rules, units_unknown = None, None, None
    if first <= 1:
        needle = "#x" + address
        accumulated = [e for e in canonical(database.get_rule_effect_rows(kind="application_rule"))
                       if e["action"] == "accumulated" and e["block_number"] <= number]
        if any(e.get("body") is None for e in accumulated):
            units_unknown = "this node did not keep the text of every unit"
        else:
            units, seen = [], set()
            genesis = getattr(chain_state, "_genesis_application_rules", "") or ""
            genesis_units = [u.strip() for u in genesis.split("\n")]
            for unit in genesis_units:
                if unit and needle in unit.lower() and unit not in seen:
                    seen.add(unit)
                    units.append({"unit": unit, "sha256": _sha256(unit), "since": None})
            for effect in accumulated:
                unit = effect["body"]
                if needle in unit.lower() and unit not in seen:
                    seen.add(unit)
                    units.append({"unit": unit, "sha256": effect["sha256"],
                                  "since": _since_of(effect)})
            fee_rules = _fee_rules(
                genesis_units + [e["body"] for e in accumulated], accumulated, address)
    else:
        units_unknown = "this node did not record every block up to this one"
    if units_unknown:
        complete = False

    running = tau_running_spec.at_block(block_hash, database)
    history = [_history_row(e) for e in reversed(own) if e["block_number"] <= number]
    data = {
        "address": address,
        "block_number": number,
        "block_hash": block_hash,
        "at_block": True,
        "head_block_number": len(chain) - 1,
        "complete": complete,
        "recorded_from": first if first <= number else None,
        "clauses": clauses,
        "rule_change_guard": guard,
        "application_rules": units,
        "fee_rules": fee_rules,
        "running_spec": running,
        "history": history[:_HISTORY_LIMIT],
    }
    if units_unknown:
        data["application_rules_unavailable"] = units_unknown
    return data


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (2, 3):
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [block number or hash]", "INVALID_PARAMS"
        )
    from consensus.approvals import ApprovalShapeError, _normalize_pubkey

    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")

    chain_state = container.chain_state
    database = container.db
    if len(parts) == 3:
        try:
            return api_response.success_response(
                _CMD, at_block(chain_state, database, address, parts[2]))
        except _BadBlock as exc:
            return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
        except Exception as exc:
            logger.exception("Failed to build account rules at %s for %s", parts[2], address)
            return api_response.error_response(
                _CMD, f"Failed to read account rules: {exc}", "INTERNAL_ERROR"
            )
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

        try:
            accumulated = [
                e for e in _canonical(
                    database.get_rule_effect_rows(kind="application_rule"),
                    database.canonical_chain())
                if e["action"] == "accumulated"]
        except Exception:
            logger.exception("Failed to read who sent the accumulated units")
            accumulated = []
        fee_rules = _fee_rules(
            [u.strip() for u in app_rules.split("\n")], accumulated, address)

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
