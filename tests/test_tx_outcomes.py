"""Issue #42: what a transaction did, and what is in force for an account.

Engine: every applied block carries one outcome per transaction (applied /
skipped / rejected, reason, fee, bounded logs, rule effects) and one record per
rule-change request its release sweep processed. DB: both are kept per block and
read back with canonicality resolved at query time. RPC: `gettxstatus` adds
`outcome`; `getaccountrules` answers "what is in force" from one tip.
"""
import hashlib
import json
import threading
import types

import pytest

import chain_state
import db
import tau_defs
from block import Block
from commands import getaccountrules, gettxstatus
from consensus import engine as engine_module
from consensus.governance import ConsensusLifecycleManager
from consensus.rule_offers import RuleOffer, clause_body_v1

import test_approval_apply as ap
import test_rule_change_release as rel
from test_rule_change_requests import (
    ALICE,
    BOB,
    GUARD_BODY,
    KIND_REVOKE,
    KIND_SET,
    POLICY_KEY,
    SET_TEXT,
    _lm as rc_lm,
    _request,
)

STREAM = tau_defs.USER_POLICY_STREAM_INDEX
GUARD = tau_defs.RULE_CHANGE_GUARD_INDEX
SET_BODY = clause_body_v1(SET_TEXT)
BLOCK_RULE = "always ( (o5[t]:bv[24] = { #x000000 }:bv[24]) )."


def _sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _rows(meta):
    return meta["tx_outcomes"]


def _row(meta, tx):
    """Outcomes are in block order, and the helpers keep the order given."""
    return _rows(meta)[meta["_order"].index(tx["tx_id"])]


def _apply_ap(txs, lm=None):
    result, post, _ = ap._apply(txs, lm=lm)
    meta = dict(result.next_snapshot.metadata)
    meta["_order"] = [tx["tx_id"] for tx in txs]
    return result, post, meta


# --- engine: one outcome per transaction ----------------------------------------

def test_registering_an_o5_rule_records_the_clause_hash():
    tx = ap.rule_tx(ap.UNGUARDED_RULE)
    _, post, meta = _apply_ap([tx])
    row = _row(meta, tx)
    body = post.rule_offers.clause_for(ap.ALICE, STREAM)
    assert body is not None
    assert row["status"] == "applied"
    assert row["rule_effects"] == [{
        "account": ap.ALICE, "kind": "clause", "stream": STREAM,
        "action": "registered", "sha256": _sha(body),
    }]
    assert any("o5 clause registered" in line for line in row["logs"])
    assert row["fee_charged"] == 0  # the test fee model charges nothing
    assert len(row["tx_hash"]) == 64


def test_replacing_and_revoking_are_named_as_such():
    first = ap.rule_tx(ap.UNGUARDED_RULE)
    again = ap.rule_tx(BLOCK_RULE, seq=1)
    gone = ap.rule_tx(ap.NEUTRAL_RULE, seq=2)
    _, post, meta = _apply_ap([first, again, gone])
    actions = [r["rule_effects"][0]["action"] for r in _rows(meta)]
    assert actions == ["registered", "replaced", "revoked"]
    assert _rows(meta)[1]["rule_effects"][0]["sha256"] == _sha(clause_body_v1(BLOCK_RULE))
    assert "sha256" not in _rows(meta)[2]["rule_effects"][0]
    assert post.rule_offers.clause_for(ap.ALICE, STREAM) is None


def test_a_rule_that_does_not_land_is_rejected_with_its_reason_and_no_effect():
    tx = ap.rule_tx(ap.NEUTRAL_RULE)  # revoking with nothing registered
    _, _, meta = _apply_ap([tx])
    row = _row(meta, tx)
    assert row["status"] == "rejected"
    assert row["reason"] == "rule_not_applied"
    assert "rule_effects" not in row
    assert any("nothing registered" in line for line in row["logs"])


def test_a_soft_no_op_is_skipped_not_applied():
    """An offer to oneself is ignored at apply but stays in the block and pays."""
    tx = ap._sign({
        "tx_id": "self-offer", "tx_type": "rule_offer", "sender_pubkey": ap.ALICE,
        "recipient_pubkey": ap.ALICE, "rule_text": ap.UNGUARDED_RULE,
        "sequence_number": 0, "expiration_time": 9999999999, "expire_at_height": 5000,
        "fee_limit": "100",
    }, ap.SK_ALICE)
    result, _, meta = _apply_ap([tx])
    (row,) = _rows(meta)
    assert tx["tx_id"] in result.skipped_tx_ids
    assert row["status"] == "skipped"
    assert "rule_effects" not in row
    assert any("Offer ignored" in line for line in row["logs"])


def test_accepting_an_offer_records_the_accepted_body():
    lm = ConsensusLifecycleManager(active_validators=[ap.ALICE])
    lm.activate_approval_slots()
    offer = RuleOffer(offerer_pubkey=ap.STRANGER, recipient_pubkey=ap.ALICE,
                      rule_text=ap.UNGUARDED_RULE, expire_at_height=5000)
    assert lm.rule_offers.submit_offer(offer)
    tx = ap._sign({
        "tx_id": "accept-1", "tx_type": "rule_offer_accept", "sender_pubkey": ap.ALICE,
        "sequence_number": 0, "expiration_time": 9999999999, "expire_at_height": 5000,
        "fee_limit": "100", "offer_id": offer.offer_id_hex, "rule_text": offer.rule_text,
    }, ap.SK_ALICE)
    _, post, meta = _apply_ap([tx], lm=lm)
    (row,) = _rows(meta)
    assert row["status"] == "applied", row
    assert row["rule_effects"] == [{
        "account": ap.ALICE, "kind": "clause", "stream": STREAM, "action": "registered",
        "sha256": _sha(post.rule_offers.clause_for(ap.ALICE, STREAM)),
    }]


def test_outcomes_are_the_same_on_every_apply_of_the_same_block():
    txs = [ap.rule_tx(ap.UNGUARDED_RULE), ap.rule_tx(ap.NEUTRAL_RULE, seq=1),
           ap.rule_tx(ap.NEUTRAL_RULE, seq=2)]
    _, _, one = _apply_ap(txs)
    _, _, two = _apply_ap(txs)
    assert _rows(one) == _rows(two)
    assert [r["status"] for r in _rows(one)] == ["applied", "applied", "rejected"]


def test_logs_are_bounded():
    many = ["x" * 1000] * 40
    kept = engine_module._bounded_logs(many)
    assert len(kept) == engine_module.OUTCOME_MAX_LOG_LINES + 1
    assert all(len(line) <= engine_module.OUTCOME_MAX_LOG_CHARS + 3 for line in kept[:-1])
    assert kept[-1].startswith("... 24 more")


# --- engine: the rule-change release sweep --------------------------------------

@pytest.fixture
def guard_needs_slot():
    """As in test_rule_change_release: the guard allows a change once i18 is set."""
    from consensus import sender_policy
    from consensus.policy_mock import MockPolicyEvaluator

    for pool in ("apply", "admission"):
        ev = MockPolicyEvaluator(pool=pool)
        ev.set_verdict(GUARD_BODY, lambda inputs: "0" if inputs.get("i18", "0") == "0" else "1")
        sender_policy.set_evaluator(pool, ev)
    yield
    for pool in ("apply", "admission"):
        sender_policy.set_evaluator(pool, None)


def test_an_approved_rule_change_records_what_the_release_wrote(guard_needs_slot):
    chain, req = rel._parked()
    result = chain.block(rel._vote(req.request_id))
    assert chain.clause(POLICY_KEY) == SET_BODY
    meta = result.next_snapshot.metadata
    assert meta["rule_change_releases"] == [{
        "request_id": req.request_id.hex(), "account": ALICE, "status": "executed",
        "rule_effects": [{"kind": "clause", "stream": STREAM, "action": "registered",
                          "sha256": _sha(SET_BODY)}],
        "rule_bodies": {_sha(SET_BODY): SET_BODY},
    }]


def test_a_failed_release_records_why(guard_needs_slot):
    chain, req = rel._parked(KIND_REVOKE, setup={"policy": True})
    chain.lm.rule_offers.accepted_clauses.pop(POLICY_KEY)
    result = chain.block(rel._vote(req.request_id))
    (release,) = result.next_snapshot.metadata["rule_change_releases"]
    assert release["status"] == "failed"
    assert release["detail"] == "no policy to revoke"


def test_the_clause_diff_names_each_change():
    effects = engine_module._clause_diff_effects(
        {5: "a", GUARD: "g"}, {5: "b", 7: "c"})
    assert [(e["stream"], e["action"]) for e in effects] == [
        (5, "replaced"), (7, "registered"), (GUARD, "revoked")]


# --- db: per block, canonicality at query time -----------------------------------

def _chain_of(n):
    blocks, prev = [], "00" * 32
    for i in range(n):
        blk = Block.create(block_number=i, previous_hash=prev, transactions=[],
                           proposer_pubkey="a" * 96, timestamp=1_700_000_000 + i)
        db.add_block(blk)
        blocks.append(blk)
        prev = blk.block_hash
    return blocks


def _set_head(blk):
    with db._db_lock:
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_hash', ?)",
            (blk.block_hash,))
        db._db_conn.execute(
            "INSERT OR REPLACE INTO chain_state (key, value) VALUES ('canonical_head_number', ?)",
            (str(blk.header.block_number),))
        db._db_conn.commit()


def _effect(action, sha=None, stream=STREAM, account=ALICE):
    e = {"account": account, "kind": "clause", "stream": stream, "action": action}
    if sha:
        e["sha256"] = sha
    return e


def test_an_outcome_round_trips(temp_database):
    (blk,) = _chain_of(1)
    db.record_tx_outcomes(blk.block_hash, 0, [{
        "tx_hash": "ab" * 32, "index": 0, "status": "applied", "fee_charged": 10,
        "logs": ["o5 clause registered for 1a1a"], "rule_effects": [_effect("registered", "11" * 32)],
    }])
    assert db.get_tx_outcome("ab" * 32, blk.block_hash) == {
        "status": "applied", "index": 0, "fee_charged": 10,
        "logs": ["o5 clause registered for 1a1a"],
        "rule_effects": [_effect("registered", "11" * 32)],
    }
    assert db.get_tx_outcome("ab" * 32, "cd" * 32) is None


def test_history_is_canonical_newest_first_and_includes_releases(temp_database):
    blocks = _chain_of(3)
    fork = Block.create(block_number=2, previous_hash=blocks[1].block_hash, transactions=[],
                        proposer_pubkey="b" * 96, timestamp=1_700_000_099)
    db.add_block(fork)
    _set_head(blocks[2])
    db.record_tx_outcomes(blocks[1].block_hash, 1, [{
        "tx_hash": "01" * 32, "index": 0, "status": "applied",
        "rule_effects": [_effect("registered", "aa" * 32)]}])
    db.record_tx_outcomes(blocks[2].block_hash, 2, [{
        "tx_hash": "02" * 32, "index": 0, "status": "applied",
        "rule_effects": [_effect("replaced", "bb" * 32)]}],
        [{"request_id": "rr" * 16, "account": ALICE, "status": "failed",
          "detail": "no policy to revoke"}])
    db.record_tx_outcomes(fork.block_hash, 2, [{
        "tx_hash": "03" * 32, "index": 0, "status": "applied",
        "rule_effects": [_effect("revoked")]}])

    history = db.get_canonical_rule_effects(ALICE.upper())
    assert [(h["block_number"], h["action"]) for h in history] == [
        (2, "release_failed"), (2, "replaced"), (1, "registered")]
    assert history[0]["request_id"] == "rr" * 16
    assert history[0]["detail"] == "no policy to revoke"
    assert history[1]["tx_hash"] == "02" * 32
    assert db.get_canonical_rule_effects(ALICE, limit=1) == history[:1]
    assert db.get_canonical_rule_effects(BOB) == []


def test_chain_state_records_from_the_snapshot(temp_database):
    tx = {"sender_pubkey": "a" * 96, "sequence_number": 0, "operations": {"1": []}}
    blk = Block.create(block_number=0, previous_hash="00" * 32, transactions=[tx],
                       proposer_pubkey="a" * 96, timestamp=1_700_000_000)
    db.add_block(blk)
    snap = types.SimpleNamespace(metadata={
        "tx_outcomes": [{"tx_hash": blk.tx_ids[0], "index": 0, "status": "skipped"},
                        {"tx_hash": "ef" * 32, "index": 1, "status": "applied"}],
        "rule_change_releases": [],
    })
    chain_state._record_tx_outcomes(blk, snap)
    assert db.get_tx_outcome(blk.tx_ids[0], blk.block_hash)["status"] == "skipped"
    assert db.get_tx_outcome("ef" * 32, blk.block_hash) is None, "not in this block"


# --- gettxstatus ------------------------------------------------------------------

def _confirmed_block():
    tx = {"tx_id": "t", "operations": {"1": [["a" * 96, "b" * 96, "1"]]}}
    genesis = Block.create(block_number=0, previous_hash="00" * 32, transactions=[],
                           proposer_pubkey="a" * 96, timestamp=1_700_000_000)
    blk = Block.create(block_number=1, previous_hash=genesis.block_hash, transactions=[tx],
                       proposer_pubkey="a" * 96, timestamp=1_700_000_001)
    db.add_block(genesis)
    db.add_block(blk)
    _set_head(blk)
    return blk


def _txstatus(tx_hash):
    resp = json.loads(gettxstatus.execute(
        f"gettxstatus {tx_hash}", types.SimpleNamespace(db=db)))
    assert resp["status"] == "ok", resp
    return resp["data"]


def test_gettxstatus_reports_the_recorded_outcome(temp_database):
    blk = _confirmed_block()
    db.record_tx_outcomes(blk.block_hash, 1, [{
        "tx_hash": blk.tx_ids[0], "index": 0, "status": "skipped",
        "fee_charged": 10, "logs": ["Vote ignored (valid no-op)"]}])
    data = _txstatus(blk.tx_ids[0])
    assert data["status"] == "confirmed"
    assert data["outcome"] == {"status": "skipped", "index": 0, "fee_charged": 10,
                               "logs": ["Vote ignored (valid no-op)"]}


def test_gettxstatus_says_when_nothing_was_recorded(temp_database):
    blk = _confirmed_block()
    assert _txstatus(blk.tx_ids[0])["outcome"] == {"status": "not_recorded"}


# --- getaccountrules -----------------------------------------------------------------

APP_UNIT = ("always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) ? "
            "(o12[t]:bv[24] = i1[t]:bv[24]) : (o12[t]:bv[24] = { #x000000 }:bv[24]) ).")
OTHER_UNIT = "always ( o13[t]:bv[24] = i1[t]:bv[24] )."


def _state(lm, head):
    return types.SimpleNamespace(
        _balance_lock=threading.Lock(), _sequence_lock=threading.Lock(),
        _rules_lock=threading.Lock(), _lifecycle_manager=lm,
        _application_rules_state=APP_UNIT + "\n" + OTHER_UNIT,
        _canonical_head_hash=head.block_hash,
    )


def _account_rules(lm, head, address=ALICE):
    resp = json.loads(getaccountrules.execute(
        f"getaccountrules {address}", types.SimpleNamespace(db=db, chain_state=_state(lm, head))))
    return resp


def test_getaccountrules_answers_from_one_tip(temp_database):
    blocks = _chain_of(2)
    _set_head(blocks[1])
    lm = rc_lm(guard=True)
    lm.rule_offers.accepted_clauses[POLICY_KEY] = SET_BODY
    parked = _request(KIND_SET, approvers={18: BOB})
    lm.approval_requests.submit_rule_change(parked, created_height=1)
    db.record_tx_outcomes(blocks[1].block_hash, 1, [{
        "tx_hash": "09" * 32, "index": 0, "status": "applied",
        "rule_effects": [_effect("registered", _sha(SET_BODY))]}])

    data = _account_rules(lm, blocks[1])["data"]
    assert data["address"] == ALICE
    assert data["block_number"] == 1 and data["block_hash"] == blocks[1].block_hash
    assert data["rule_clauses_root"] == lm.rule_offers.clauses_root().hex()
    assert data["clauses"] == [{
        "stream": STREAM, "name": "o5", "body": SET_BODY, "sha256": _sha(SET_BODY),
        "since": {"block_number": 1, "tx_hash": "09" * 32},
    }]
    assert data["rule_change_guard"] == {
        "body": GUARD_BODY, "sha256": _sha(GUARD_BODY), "since": None}
    assert [u["unit"] for u in data["application_rules"]] == [APP_UNIT]
    (change,) = data["open_rule_changes"]
    assert change["request_id"] == parked.request_id.hex()
    assert change["kind"] == "set_policy" and change["approvers"] == {"18": BOB}
    assert data["awaiting_my_vote"] == []
    assert data["history"][0]["tx_hash"] == "09" * 32

    bob = _account_rules(lm, blocks[1], address=BOB)["data"]
    assert bob["clauses"] == [] and bob["rule_change_guard"] is None
    assert [c["sender_pubkey"] for c in bob["awaiting_my_vote"]] == [ALICE]


def test_getaccountrules_lists_queued_rule_transactions(temp_database):
    (blk,) = _chain_of(1)
    _set_head(blk)
    tx = ap.rule_tx(ap.UNGUARDED_RULE, sender=ALICE)
    db.add_mempool_tx(json.dumps(tx), "77" * 32, 1)
    transfer = {"tx_type": "user_tx", "sender_pubkey": ALICE, "sequence_number": 1,
                "operations": {"1": [[ALICE, BOB, "1"]]}}
    db.add_mempool_tx(json.dumps(transfer), "88" * 32, 2)
    data = _account_rules(rc_lm(), blk)["data"]
    assert data["mempool"] == [{"tx_hash": "77" * 32, "tx_type": "user_tx"}]


def test_getaccountrules_refuses_a_bad_address(temp_database):
    (blk,) = _chain_of(1)
    resp = _account_rules(rc_lm(), blk, address="nothex")
    assert resp["status"] == "error"
    assert resp["error"]["code"] == "INVALID_PARAMS"


# --- fee rules: every unit that writes o8, whoever sent it (#183) ---------------------

FEE_OWN = ("always ( (i12[t]:bv[384] = { #x" + ALICE + " }:bv[384]) -> "
           "(o8[t]:bv[24] = { #x00000a }:bv[24]) ).")
FEE_OTHER = ("always ( ((i12[t]:bv[384] = { #x" + BOB + " }:bv[384]) || "
             "(i1[t]:bv[24] > { #x000000 }:bv[24])) -> (o8[t]:bv[24] = { #x000064 }:bv[24]) ).")
FEE_GENESIS = "always ( (i3[t]:bv[384] = i3[t]:bv[384]) -> (o8[t]:bv[24] = { #x000001 }:bv[24]) )."


def _app_effect(text, sender):
    return {"account": sender, "kind": "application_rule", "action": "accumulated",
            "sha256": _sha(text)}


def _fee_view(address=ALICE):
    blocks = _chain_of(3)
    fork = Block.create(block_number=2, previous_hash=blocks[1].block_hash, transactions=[],
                        proposer_pubkey="b" * 96, timestamp=1_700_000_099)
    db.add_block(fork)
    _set_head(blocks[2])
    db.record_tx_outcomes(blocks[1].block_hash, 1, [{
        "tx_hash": "01" * 32, "index": 0, "status": "applied",
        "rule_effects": [_app_effect(FEE_OWN, ALICE)]}])
    db.record_tx_outcomes(blocks[2].block_hash, 2, [{
        "tx_hash": "02" * 32, "index": 0, "status": "applied",
        "rule_effects": [_app_effect(FEE_OTHER, BOB)]}])
    db.record_tx_outcomes(fork.block_hash, 2, [{                  # off the canonical chain
        "tx_hash": "0f" * 32, "index": 0, "status": "applied",
        "rule_effects": [_app_effect(FEE_OTHER, ALICE)]}])
    state = _state(rc_lm(), blocks[2])
    state._application_rules_state = "\n".join(
        [FEE_GENESIS, APP_UNIT, FEE_OWN, OTHER_UNIT, FEE_OTHER])
    resp = json.loads(getaccountrules.execute(
        f"getaccountrules {address}", types.SimpleNamespace(db=db, chain_state=state)))
    assert resp["status"] == "ok", resp
    return resp["data"]


def test_every_fee_rule_is_listed_with_who_sent_it_in_the_order_they_joined(temp_database):
    data = _fee_view()
    assert data["fee_rules"] == [
        {"unit": FEE_GENESIS, "sha256": _sha(FEE_GENESIS), "names_this_account": False,
         "sent_by": None, "since": None},
        {"unit": FEE_OWN, "sha256": _sha(FEE_OWN), "names_this_account": True,
         "sent_by": [ALICE], "since": {"block_number": 1, "tx_hash": "01" * 32}},
        {"unit": FEE_OTHER, "sha256": _sha(FEE_OTHER), "names_this_account": False,
         "sent_by": [BOB], "since": {"block_number": 2, "tx_hash": "02" * 32}},
    ]


def test_a_fee_rule_that_never_names_the_account_is_shown_only_among_the_fee_rules(temp_database):
    """The case of #183: another account's fee rule can charge this one, and the
    units naming the account do not show it."""
    data = _fee_view()
    assert FEE_OTHER not in [u["unit"] for u in data["application_rules"]]
    assert FEE_OTHER in [u["unit"] for u in data["fee_rules"]]


def test_the_fee_rules_are_the_same_whichever_account_asks(temp_database):
    alice, bob = _fee_view(ALICE), _fee_view(BOB)
    strip = lambda rows: [{k: v for k, v in r.items() if k != "names_this_account"} for r in rows]
    assert strip(alice["fee_rules"]) == strip(bob["fee_rules"])
    assert [r["names_this_account"] for r in bob["fee_rules"]] == [False, False, True]


def test_a_unit_that_writes_no_fee_is_not_a_fee_rule(temp_database):
    units = [r["unit"] for r in _fee_view()["fee_rules"]]
    assert APP_UNIT not in units and OTHER_UNIT not in units


def test_the_sender_of_a_fee_rule_is_the_account_that_sent_it_not_the_key_it_names():
    """A unit sent by one account can name another key: `sent_by` comes from the
    transaction, never from the text."""
    text = ("always ( (i12[t]:bv[384] = { #x" + ap.BOB + " }:bv[384]) -> "
            "(o8[t]:bv[24] = { #x000005 }:bv[24]) ).")
    result, _, _ = ap._apply([ap.rule_tx(text)])
    (row,) = result.next_snapshot.metadata["tx_outcomes"]
    assert row["status"] == "applied", row
    unit = (chain_state._preprocess_tau_spec_text(text) or text).strip()
    assert row["rule_effects"] == [{
        "account": ap.ALICE, "kind": "application_rule", "action": "accumulated",
        "sha256": _sha(unit),
    }]


def test_the_fee_actually_charged_is_reported():
    tx = ap.rule_tx(ap.UNGUARDED_RULE)
    result, _, _ = ap._apply([tx], fee=7)
    (row,) = result.next_snapshot.metadata["tx_outcomes"]
    assert row["status"] == "applied"
    assert row["fee_charged"] == 7


SCOPED_APP_RULE = (
    "always ( (i12[t]:bv[384] = { #x" + ap.ALICE + " }:bv[384]) ? "
    "(o12[t]:bv[24] = i1[t]:bv[24]) : (o12[t]:bv[24] = { #x000000 }:bv[24]) )."
)


def test_an_accumulated_rule_records_the_stored_unit_hash():
    tx = ap.rule_tx(SCOPED_APP_RULE)
    result, _, _ = ap._apply([tx])
    (row,) = result.next_snapshot.metadata["tx_outcomes"]
    assert row["status"] == "applied", row
    unit = (chain_state._preprocess_tau_spec_text(SCOPED_APP_RULE) or SCOPED_APP_RULE).strip()
    assert row["rule_effects"] == [{
        "account": ap.ALICE, "kind": "application_rule", "action": "accumulated",
        "sha256": _sha(unit),
    }]


def _apply_with_engine_receipt(tx, receipt):
    from unittest.mock import patch
    with patch("tau_manager.get_last_revision_receipt", return_value=receipt):
        result, _, _ = ap._apply([tx])
    (row,) = result.next_snapshot.metadata["tx_outcomes"]
    assert row["status"] == "applied", row
    return row["rule_effects"]


def test_an_accumulated_rule_says_whether_the_engine_took_the_revision():
    """#42: a wallet reads from the confirmed transaction whether the rule took
    effect, without running the engine itself."""
    (effect,) = _apply_with_engine_receipt(ap.rule_tx(SCOPED_APP_RULE), {
        "outcome": "ACCEPTED_CHANGED", "accepted": True, "changed": True,
        "spec_revision_before": 4, "spec_revision_after": 5})
    assert effect["action"] == "accumulated"
    assert effect["revision"] == {"taken": True, "engine_outcome": "ACCEPTED_CHANGED",
                                  "spec_revision": 5}


def test_a_rule_the_engine_already_implied_is_accepted_but_not_taken():
    (effect,) = _apply_with_engine_receipt(ap.rule_tx(SCOPED_APP_RULE), {
        "outcome": "ACCEPTED_NOOP", "accepted": True, "changed": False,
        "spec_revision_before": 5, "spec_revision_after": 5})
    assert effect["revision"] == {"taken": False, "engine_outcome": "ACCEPTED_NOOP",
                                  "spec_revision": 5}


def test_a_clause_names_no_revision_even_beside_an_engine_receipt():
    """An o5 clause goes to the clause registry, not into the engine's
    specification, so its effect never claims a revision was taken, even when
    the engine's last receipt (from another step) says one was."""
    (effect,) = _apply_with_engine_receipt(ap.rule_tx(ap.UNGUARDED_RULE), {
        "outcome": "ACCEPTED_CHANGED", "accepted": True, "changed": True,
        "spec_revision_before": 4, "spec_revision_after": 5})
    assert effect["kind"] == "clause" and effect["action"] == "registered"
    assert "revision" not in effect

def test_the_worker_receipt_gives_the_revision_after_the_unit():
    # the authoritative worker reports its counter once, after the revision
    assert engine_module._engine_revision({"outcome": "ACCEPTED_CHANGED", "accepted": True,
                                           "spec_revision": 9, "time_point": 31}) == {
        "taken": True, "engine_outcome": "ACCEPTED_CHANGED", "spec_revision": 9}
    assert engine_module._engine_revision(None) is None
    assert engine_module._engine_revision({}) is None


def test_a_built_block_records_only_its_own_transactions_at_their_positions(temp_database):
    """The builder's simulation ran a rejected tx the committed block dropped."""
    kept_a = {"sender_pubkey": "a" * 96, "sequence_number": 0, "operations": {"1": []}}
    dropped = {"sender_pubkey": "b" * 96, "sequence_number": 0, "operations": {"1": []}}
    kept_b = {"sender_pubkey": "c" * 96, "sequence_number": 0, "operations": {"1": []}}
    from block import compute_tx_hash

    sim = [dict(tx, tx_id=compute_tx_hash(tx)) for tx in (kept_a, dropped, kept_b)]
    sim_rows = [
        {"tx_hash": compute_tx_hash(tx), "tx_id": tx["tx_id"], "index": i,
         "status": status}
        for i, (tx, status) in enumerate(zip(sim, ("applied", "rejected", "skipped")))
    ]
    final = Block.create(block_number=0, previous_hash="00" * 32,
                         transactions=[kept_a, kept_b], proposer_pubkey="a" * 96,
                         timestamp=1_700_000_000)
    rows = chain_state._outcomes_for_block(final, sim_rows)
    assert [(r["tx_hash"], r["index"], r["status"]) for r in rows] == [
        (final.tx_ids[0], 0, "applied"), (final.tx_ids[1], 1, "skipped")]
    assert all("tx_id" not in r for r in rows)
