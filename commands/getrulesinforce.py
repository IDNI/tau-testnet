"""Rules in force at one block, for the chain or one account (issue #42).

    getrulesinforce [<block>|<height>] [<account>]

With no argument, the running spec at the canonical head. With a block hash
or a height, the spec that was in force at that block: the journal is replayed
only up to the journal head the block's commit record names, and
`spec_revision` comes from the same record. A block with no commit record
answers `code "NOT_FOUND"`; a block whose record exists but whose journal rows
do not verify answers `code "TAMPERED"` -- a deletion is tamper, never "no
commit record". A node without the authoritative engine answers the spec as
unavailable instead of a text.

With an account, the account's registry clauses and the application-rule units
naming it are added. The clauses are a POSITIVE registry read only: a clause
is listed because `rule_clauses_v1` holds it, with the sha256 of the stored
body. The registry and the application rules are current-tip state; at a
historical block they are labelled as such, because no per-block registry
snapshot exists. An o5 clause names no revision: the registry is not the
engine, and a clause body is not a revision of the specification.
"""
import hashlib
import logging

import api_response
import tau_defs
import tau_running_spec

logger = logging.getLogger(__name__)

_CMD = "getrulesinforce"


def _sha256(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8")).hexdigest()


def _resolve_block(database, arg):
    """(block_hash, block_number) for a hash, a height, or None (the head)."""
    if arg is None:
        head = database.get_canonical_head_block() or {}
        return (head.get("block_hash"),
                (head.get("header") or {}).get("block_number"))
    text = str(arg)
    if len(text) == 64 and all(c in "0123456789abcdefABCDEF" for c in text):
        block_hash = text.lower()
        block = database.get_block_by_hash(block_hash) or {}
        return block_hash, (block.get("header") or {}).get("block_number")
    if text.isdigit():
        block_hash = database.get_block_hash_by_number(int(text))
        if block_hash is None:
            return None, int(text)
        block = database.get_block_by_hash(block_hash) or {}
        return block_hash, (block.get("header") or {}).get("block_number")
    return None, None


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (1, 2, 3):
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} [<block>|<height>] [<account>]", "INVALID_PARAMS"
        )
    block_arg, account_arg = None, None
    for arg in parts[1:]:
        if len(arg) == 64 and all(c in "0123456789abcdefABCDEF" for c in arg):
            if block_arg is not None:
                return api_response.error_response(
                    _CMD, f"Usage: {_CMD} [<block>|<height>] [<account>]",
                    "INVALID_PARAMS")
            block_arg = arg
        elif arg.isdigit():
            if block_arg is not None:
                return api_response.error_response(
                    _CMD, f"Usage: {_CMD} [<block>|<height>] [<account>]",
                    "INVALID_PARAMS")
            block_arg = arg
        else:
            if account_arg is not None:
                return api_response.error_response(
                    _CMD, f"Usage: {_CMD} [<block>|<height>] [<account>]",
                    "INVALID_PARAMS")
            account_arg = arg

    database = container.db
    block_hash, block_number = _resolve_block(database, block_arg)
    if block_arg is not None and block_hash is None and block_number is None:
        return api_response.error_response(
            _CMD, f"no block {block_arg}", "INVALID_PARAMS"
        )

    import tau_authority

    if block_hash is None:
        # A height with no canonical block: the block never existed here.
        running = {"text": None, "sha256": None, "block_hash": None,
                   "unavailable": f"no canonical block at height {block_number}",
                   "code": "NOT_FOUND"}
        spec_revision = None
    else:
        commit = None
        try:
            commit = database.get_block_commit(block_hash)
        except Exception:
            logger.exception("Failed to read the commit record for %s", block_hash)
        spec_revision = (commit or {}).get("spec_revision")
        if not tau_authority.owner().enabled:
            running = {"text": None, "sha256": None, "block_hash": block_hash,
                       "unavailable": "this node runs without the authoritative engine",
                       "code": "UNAVAILABLE"}
        elif block_arg is None:
            running = tau_running_spec.at_head(database)
            if running.get("block_hash") is not None:
                block_hash = running["block_hash"]
        else:
            running = tau_running_spec.running_spec_at(database, block_hash)

    data = {
        "block_number": int(block_number) if block_number is not None else None,
        "block_hash": block_hash,
        "spec_revision": (int(spec_revision) if spec_revision is not None else None),
        "running_spec": running,
    }

    if account_arg is not None:
        from commands import getaccountrules
        from consensus.approvals import ApprovalShapeError, _normalize_pubkey

        try:
            address = _normalize_pubkey(account_arg)
        except ApprovalShapeError as exc:
            return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
        try:
            rows = database.load_rule_clauses()
        except Exception:
            logger.exception("Failed to read the clause registry")
            rows = []
        guard_index = tau_defs.RULE_CHANGE_GUARD_INDEX
        clauses, guard = [], None
        for row in rows:
            if str(row.get("acceptor_pubkey") or "").lower() != address:
                continue
            stream = int(row["target_stream"])
            body = row.get("clause_body") or ""
            item = {"body": body, "sha256": _sha256(body)}
            if stream == guard_index:
                guard = item
            else:
                clauses.append({"stream": stream, "name": f"o{stream}", **item})
        data["account"] = {
            "address": address,
            "clauses": sorted(clauses, key=lambda c: c["stream"]),
            "rule_change_guard": guard,
            # Registry and accumulation are current-tip state; at a historical
            # block they describe now, not that block.
            "registry_as_of": "this block" if block_arg is None else "current tip",
        }
        try:
            (_head_hash, _lm, app_rules) = getaccountrules._tip_view(
                container.chain_state)
            try:
                history = database.get_canonical_rule_effects(address, limit=20)
            except Exception:
                history = []
            needle = "#x" + address
            units = []
            for unit in (u.strip() for u in app_rules.split("\n")):
                if unit and needle in unit.lower():
                    sha = _sha256(unit)
                    units.append({"unit": unit, "sha256": sha,
                                  "since": getaccountrules._since(
                                      history, sha=sha, kind="application_rule")})
            data["account"]["application_rules"] = units
        except Exception:
            logger.exception("Failed to read application rules for %s", address)
            data["account"]["application_rules"] = []
    return api_response.success_response(_CMD, data)
