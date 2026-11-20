"""What rules are in force for an account (issue #42).

Answers the wallet's question -- "what is actually protecting me right
now?" -- from engine-produced state only, per apply path:

* Registry half: the account's accepted clauses from the persisted
  rule-clause tables (the same source `getruleoffers` reads), plus the
  clause-registry root at the tip.
* Shared-spec half: the normalized spec from the node's shadow replay
  (consensus/shadow_spec.py), served from the persisted per-block
  snapshots (db.spec_snapshots) -- NEVER from the append-only accumulation
  that `gettaustate` returns (submitted text: a later unit can displace
  part of an earlier one while both stay in the text) and never from the
  live interpreter's composed spec (eval-only, possibly shrunk, and never
  hashed or persisted by design).

Every answer carries the snapshot it was derived from -- height, block
hash, shadow revision and sha256 of the normalized text -- so two nodes'
answers can be compared byte-for-byte. An optional height serves the
newest snapshot at or before it; a height the node has no snapshot for is
answered `not_recorded`, never reconstructed from submitted text.
"""
import api_response
import db
import tau_defs
from consensus.rule_offers import RuleOfferShapeError, normalize_acceptor_pubkey

_CMD = "getaccountrules"


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (2, 3):
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [height]", "INVALID_PARAMS"
        )

    try:
        address = normalize_acceptor_pubkey(parts[1])
    except RuleOfferShapeError as exc:
        return api_response.error_response(
            _CMD, f"Invalid address: {exc}", "INVALID_PARAMS"
        )

    height = None
    if len(parts) == 3:
        try:
            height = int(parts[2])
        except ValueError:
            return api_response.error_response(
                _CMD, "Height must be a non-negative integer.", "INVALID_PARAMS"
            )
        if height < 0:
            return api_response.error_response(
                _CMD, "Height must be a non-negative integer.", "INVALID_PARAMS"
            )

    database = getattr(container, "db", db) or db
    chain_state = getattr(container, "chain_state", None)

    # --- registry half: persisted clause tables, as in getruleoffers ---
    try:
        clauses = database.load_rule_clauses()
    except Exception as exc:
        return api_response.error_response(
            _CMD, f"Failed to read rule clauses: {exc}", "INTERNAL_ERROR"
        )
    own = [
        clause for clause in clauses
        if (clause.get("acceptor_pubkey") or "").lower() == address
    ]
    guard_index = tau_defs.RULE_CHANGE_GUARD_INDEX
    accepted = [
        {
            "target_stream": clause["target_stream"],
            "clause_body": clause["clause_body"],
        }
        for clause in own
        if int(clause["target_stream"]) != guard_index
    ]
    guard = next(
        (c["clause_body"] for c in own if int(c["target_stream"]) == guard_index),
        None,
    )
    clauses_root = None
    if chain_state is not None and hasattr(chain_state, "get_clauses_root"):
        try:
            clauses_root = chain_state.get_clauses_root()
        except Exception:
            clauses_root = None

    # --- shared-spec half: the shadow snapshot --------------------------
    try:
        snap = database.get_spec_snapshot_at(height)
    except Exception as exc:
        return api_response.error_response(
            _CMD, f"Failed to read spec snapshot: {exc}", "INTERNAL_ERROR"
        )

    data = {
        "address": address,
        "registry": {
            "accepted_clauses": accepted,
            "rule_change_guard": guard,
            "rule_clauses_root": clauses_root,
        },
    }
    if snap is None:
        # No snapshot can serve this height (or any height yet): say so,
        # in the vocabulary gettxstatus already uses for pre-feature
        # transactions, instead of falling back to the submitted text.
        data["status"] = "not_recorded"
        data["height"] = height
        data["snapshot"] = None
        data["shared_spec"] = None
        return api_response.success_response(_CMD, data)

    text = snap["normalized_text"] or ""
    data["status"] = "recorded"
    data["height"] = snap["height"]
    data["snapshot"] = {
        "height": snap["height"],
        "block_hash": snap["block_hash"],
        "shadow_revision": snap["shadow_revision"],
        "sha256": snap["sha256"],
    }
    data["shared_spec"] = {
        # The normalized spec the engine runs, from the shadow -- this is
        # the in-force text; the units are its top-level lines.
        "normalized_text": text,
        "units": [line for line in text.split("\n") if line.strip()],
    }
    return api_response.success_response(_CMD, data)
