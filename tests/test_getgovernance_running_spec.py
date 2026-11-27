"""getgovernance: the running spec in the answer must be the spec at the head
the answer names (issue #42 sibling of the AtticKnight getrulesinforce review,
PR #180).

getgovernance reads the spec with at_head() and the head afterwards; a block
that commits between the two reads makes them disagree, and the old single
re-read can itself be beaten by a second commit landing in the retry window.
The spec must be pinned to the named head instead.
"""
from __future__ import annotations

import hashlib
import json
import threading
import types
from unittest.mock import patch

import tau_running_spec as rs
from commands import getgovernance


def _spec(block_hash, text):
    return {"text": text, "sha256": hashlib.sha256(text.encode()).hexdigest(),
            "block_hash": block_hash}


def _container(head_hash="H2", head_number=5):
    lm = types.SimpleNamespace(
        active_validators=[],
        archival_updates=[],
        update_payloads={},
        pending_updates=set(),
        scheduled_updates=[],
        votes={},
        approval_threshold=1,
        effective_quorum_policy=lambda: "count:1",
        effective_eligibility_mode=lambda: "open",
        effective_fee_beneficiary=lambda: "",
    )
    chain_state = types.SimpleNamespace(
        _balance_lock=threading.Lock(),
        _sequence_lock=threading.Lock(),
        _rules_lock=threading.Lock(),
        _lifecycle_manager=lm,
        _active_consensus_id=None,
        _consensus_rules_state="",
        _application_rules_state="",
    )

    class FakeDB:
        def get_canonical_head_block(self):
            return {"block_hash": head_hash,
                    "header": {"block_number": head_number}}

        def get_mempool_txs(self):
            return []

    return types.SimpleNamespace(db=FakeDB(), chain_state=chain_state)


def test_getgovernance_spec_is_pinned_to_the_named_head():
    """Two commits defeat the old single re-read: first at_head H1, head H2,
    retry at_head H3 -- the answer must still carry H2's spec."""
    container = _container()
    with patch.object(rs, "at_head", side_effect=[
                _spec("H1", "spec at H1"), _spec("H3", "spec at H3")]), \
            patch.object(rs, "running_spec_at",
                         return_value=_spec("H2", "spec at H2")) as pinned:
        resp = json.loads(getgovernance.execute("getgovernance", container))
    assert resp["status"] == "ok", resp
    data = resp["data"]
    assert data["head_hash"] == "H2"
    assert data["running_spec"]["block_hash"] == "H2"
    assert data["running_spec"]["text"] == "spec at H2"
    pinned.assert_called_once()
    assert pinned.call_args.args[1] == "H2"


def test_getgovernance_falls_back_when_the_store_cannot_answer_history():
    """A store without historical reads keeps the old best-effort re-read."""
    container = _container()
    unavailable = {"text": None, "sha256": None, "block_hash": "H2",
                   "unavailable": "this store cannot answer historical blocks",
                   "code": "UNAVAILABLE"}
    with patch.object(rs, "at_head", side_effect=[
                _spec("H1", "spec at H1"), _spec("H3", "spec at H3")]), \
            patch.object(rs, "running_spec_at", return_value=unavailable):
        resp = json.loads(getgovernance.execute("getgovernance", container))
    assert resp["status"] == "ok", resp
    assert resp["data"]["running_spec"]["block_hash"] == "H3"
