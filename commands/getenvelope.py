"""One envelope: its terms, where it stands, and its history.

    getenvelope <envelope_id>

An open envelope answers `open: true` with its terms and progress at the next
block: whether it is locked (and until when), whether the next block is inside
its spending window (and when the next one opens), the period it is in, that
period's cap, what was spent in it, what one spend may still take, when the next
period starts, and its due point (`due_at`, `due_outcome`: where the rest goes
then). A closed one answers `open: false`; its history (newest first, canonical
blocks only) says how it closed: `emptied`, `released`, `ended` (rest to the
recipient), `refunded` or `refunded_idle` (rest back to the sender), with what
was paid out and to whom.

`semantics` is the capability report a wallet reads before offering envelopes.
"""
import re

import api_response
import chain_state
import consensus.envelope as envelope
from consensus.envelope import EnvelopeBook, describe

_CMD = "getenvelope"
_ID_RE = re.compile(r"^[0-9a-f]{64}$")


def semantics() -> dict:
    out = dict(envelope.SEMANTICS)
    out.update({
        "tx_types": sorted(envelope.ENVELOPE_TX_TYPES),
        "fee_by_tx_type": {
            "envelope_send": "one transfer fee, paid by the sender",
            "envelope_spend": "one transfer fee, paid by the recipient who spends",
            "envelope_release": "fee-free",
            "end_and_refunds": "fee-free, started by the network at the end of a block",
        },
        "preview": "sendtx and checktx answer `envelope` with what the envelope would "
                   "hold or have left after the transaction",
    })
    return out


def tip():
    """(head hash, envelope book, next height, next timestamp) as one read."""
    from consensus.facade import TipAdmissionView

    with chain_state._balance_lock, chain_state._sequence_lock, chain_state._rules_lock:
        lm = chain_state._lifecycle_manager
        head = getattr(chain_state, "_canonical_head_hash", None)
    book = getattr(lm, "envelopes", None)
    view = TipAdmissionView()
    return (head, book if isinstance(book, EnvelopeBook) else EnvelopeBook(),
            view.next_block_height, view.next_block_timestamp)


def describe_open(book: EnvelopeBook, eid: bytes, height: int, ts: int) -> dict:
    return describe(book.get(eid), book.state_of(eid), height=height, ts=ts)


def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2 or not _ID_RE.match(parts[1].lower()):
        return api_response.error_response(
            _CMD, f"Usage: {_CMD} <envelope_id (64 hex)>", "INVALID_PARAMS")
    eid_hex = parts[1].lower()
    import db

    try:
        history = db.get_canonical_envelope_events(envelope_id=eid_hex)
    except Exception:
        history = []
    head, book, height, ts = tip()
    eid = bytes.fromhex(eid_hex)
    data = {"envelope_id": eid_hex, "block_hash": head, "open": book.get(eid) is not None}
    if data["open"]:
        data["envelope"] = describe_open(book, eid, height, ts)
    elif not history:
        return api_response.error_response(
            _CMD, "No envelope with this id on the canonical chain.", "NOT_FOUND")
    else:
        data["closed"] = history[0].get("outcome")
    data["history"] = history
    data["semantics"] = semantics()
    return api_response.success_response(_CMD, data)
