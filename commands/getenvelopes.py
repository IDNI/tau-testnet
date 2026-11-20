"""The envelopes an account sent or holds (spending limits).

    getenvelopes <address> [in|out|all]

`in`: envelopes the account holds and may spend from; `out`: envelopes it sent
and may release; `all` (the default): both. Each open envelope is described at
the next block (see getenvelope). `held_in_envelopes` is what open envelopes
hold for the account to spend; `history` is the account's envelope events on
canonical blocks, newest first.
"""
import api_response
from commands import getenvelope as _one

_CMD = "getenvelopes"
_ROLES = ("in", "out", "all")


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) not in (2, 3) or (len(parts) == 3 and parts[2] not in _ROLES):
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <address> [in|out|all]", "INVALID_PARAMS")
    from consensus.approvals import ApprovalShapeError, _normalize_pubkey

    try:
        address = _normalize_pubkey(parts[1])
    except ApprovalShapeError as exc:
        return api_response.error_response(_CMD, str(exc), "INVALID_PARAMS")
    role = parts[2] if len(parts) == 3 else "all"
    import db

    try:
        history = db.get_canonical_envelope_events(pubkey=address, role=role)
    except Exception:
        history = []
    head, book, height, ts = _one.tip()
    data = {
        "address": address,
        "role": role,
        "block_hash": head,
        "held_in_envelopes": book.held_for(address),
        "envelopes": [_one.describe_open(book, eid, height, ts)
                      for eid in book.of(address, role)],
        "history": history,
        "semantics": _one.semantics(),
    }
    return api_response.success_response(_CMD, data)
