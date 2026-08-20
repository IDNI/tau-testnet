"""The rule-sharing read RPCs: getofferid, getruleoffers, getruleoffer,
getruleconflict.

getruleconflict is advisory and node-local by construction -- it never gates a
transaction -- so these tests assert the report's SHAPE and honesty (notably
that satisfiability is reported as unavailable rather than silently claimed),
not that any particular verdict is authoritative.
"""
import json
import types

import pytest

import db
from commands import getofferid, getruleconflict, getruleoffer, getruleoffers
from consensus.rule_offers import clause_body_v1
from consensus.serialization import compute_offer_id

A = "aa" * 48
B = "bb" * 48
C = "cc" * 48
RULE = "always ( o5[t]:bv[24] = { #x000000 }:bv[24] )."
TARGET = 5
EXPIRE = 500


@pytest.fixture
def container(temp_database):
    return types.SimpleNamespace(db=db)


def _offer_id(offerer=A, recipient=B, text=RULE, expire=EXPIRE):
    return compute_offer_id(
        offerer_pubkey=offerer, recipient_pubkey=recipient,
        rule_text=text, expire_at_height=expire,
    ).hex()


def _seed(offers=None, clauses=None):
    db.save_canonical_state_atomically(
        "head", 1, {}, {}, "", "", "", [], [], [], [],
        rule_offers=offers or [], rule_clauses=clauses or [],
    )


def _offer_row(**over):
    row = {
        "offer_id": _offer_id(),
        "offerer_pubkey": A,
        "recipient_pubkey": B,
        "rule_text": RULE,
        "expire_at_height": EXPIRE,
        "status": "offered",
    }
    row.update(over)
    return row


def _call(handler, command, container):
    return json.loads(handler.execute(command, container))


# --- getofferid -------------------------------------------------------------

def test_getofferid_matches_the_canonical_derivation(container):
    payload = {"sender_pubkey": A, "recipient_pubkey": B,
               "rule_text": RULE, "expire_at_height": EXPIRE}
    res = _call(getofferid, "getofferid " + json.dumps(payload), container)
    assert res["status"] == "ok"
    assert res["data"]["offer_id"] == _offer_id()
    assert res["data"]["target_stream"] == TARGET


def test_getofferid_tolerates_quoted_json(container):
    payload = json.dumps({"sender_pubkey": A, "recipient_pubkey": B,
                          "rule_text": RULE, "expire_at_height": EXPIRE})
    res = _call(getofferid, f"getofferid '{payload}'", container)
    assert res["status"] == "ok"


def test_getofferid_reports_shape_without_failing(container):
    """The id is well defined even for a rule that would be refused, and a
    client may legitimately want it."""
    payload = {"sender_pubkey": A, "recipient_pubkey": B,
               "rule_text": "o5[t] = 1.", "expire_at_height": EXPIRE}
    res = _call(getofferid, "getofferid " + json.dumps(payload), container)
    assert res["status"] == "ok"
    assert res["data"]["offer_id"]
    assert "shape_error" in res["data"]
    assert res["data"]["target_stream"] is None


@pytest.mark.parametrize("payload,code", [
    ({"sender_pubkey": A, "recipient_pubkey": A, "rule_text": RULE,
      "expire_at_height": 5}, "INVALID_PARAMS"),
    ({"sender_pubkey": "short", "recipient_pubkey": B, "rule_text": RULE,
      "expire_at_height": 5}, "INVALID_PARAMS"),
    ({"sender_pubkey": A, "recipient_pubkey": B, "rule_text": "",
      "expire_at_height": 5}, "INVALID_PARAMS"),
    ({"sender_pubkey": A, "recipient_pubkey": B, "rule_text": RULE,
      "expire_at_height": 0}, "INVALID_PARAMS"),
    ({"sender_pubkey": A, "recipient_pubkey": B, "rule_text": RULE,
      "expire_at_height": True}, "INVALID_PARAMS"),
])
def test_getofferid_rejects_bad_payloads(container, payload, code):
    res = _call(getofferid, "getofferid " + json.dumps(payload), container)
    assert res["status"] == "error" and res["error"]["code"] == code


def test_getofferid_usage_and_parse_errors(container):
    assert _call(getofferid, "getofferid", container)["error"]["code"] == "INVALID_PARAMS"
    assert _call(getofferid, "getofferid {nope", container)["error"]["code"] == "PARSE_ERROR"


# --- getruleoffers ----------------------------------------------------------

def test_getruleoffers_splits_incoming_and_outgoing(container):
    _seed(offers=[_offer_row()])
    res = _call(getruleoffers, f"getruleoffers {B}", container)["data"]
    assert res["pending_incoming"] == 1
    assert len(res["incoming"]) == 1
    assert res["outgoing"] == []

    res = _call(getruleoffers, f"getruleoffers {A}", container)["data"]
    assert res["incoming"] == []
    assert len(res["outgoing"]) == 1


def test_getruleoffers_previews_rather_than_dumping_text(container):
    long_rule = RULE + " " + ("#" * 500)
    _seed(offers=[_offer_row(rule_text=long_rule)])
    entry = _call(getruleoffers, f"getruleoffers {B}", container)["data"]["incoming"][0]
    assert entry["rule_text_truncated"] is True
    assert len(entry["rule_text_preview"]) <= 200
    assert entry["rule_text_sha256"]
    assert entry["rule_text_bytes"] == len(long_rule.encode())


def test_getruleoffers_role_filter(container):
    _seed(offers=[_offer_row()])
    data = _call(getruleoffers, f"getruleoffers {B} in", container)["data"]
    assert "incoming" in data and "outgoing" not in data
    data = _call(getruleoffers, f"getruleoffers {A} out", container)["data"]
    assert "outgoing" in data and "incoming" not in data


def test_getruleoffers_lists_accepted_clauses(container):
    _seed(clauses=[{"acceptor_pubkey": B, "target_stream": TARGET,
                    "clause_body": clause_body_v1(RULE)}])
    data = _call(getruleoffers, f"getruleoffers {B}", container)["data"]
    assert data["accepted_clauses"] == [
        {"target_stream": TARGET, "clause_body": clause_body_v1(RULE)}
    ]
    # Another user's clauses are not attributed to this address.
    assert _call(getruleoffers, f"getruleoffers {C}", container)["data"]["accepted_clauses"] == []


def test_getruleoffers_surfaces_unmined_offers_from_the_mempool(container):
    """So a wallet can show a just-submitted offer before it is mined."""
    db.add_mempool_tx(json.dumps({
        "tx_type": "rule_offer", "sender_pubkey": A, "recipient_pubkey": B,
        "rule_text": RULE, "expire_at_height": EXPIRE,
        "expiration_time": 9999999999,
    }), "mp-1", 1000)
    data = _call(getruleoffers, f"getruleoffers {B}", container)["data"]
    assert len(data["mempool"]) == 1
    assert data["mempool"][0]["lifecycle"] == "mempool"
    assert data["mempool"][0]["tx_type"] == "rule_offer"


def test_getruleoffers_validates_input(container):
    assert _call(getruleoffers, "getruleoffers", container)["error"]["code"] == "INVALID_PARAMS"
    assert _call(getruleoffers, "getruleoffers nope", container)["error"]["code"] == "INVALID_PARAMS"
    assert _call(getruleoffers, f"getruleoffers {B} sideways", container)["error"]["code"] == "INVALID_PARAMS"


# --- getruleoffer -----------------------------------------------------------

def test_getruleoffer_returns_full_text_and_clause(container):
    _seed(offers=[_offer_row()])
    data = _call(getruleoffer, f"getruleoffer {_offer_id()}", container)["data"]
    assert data["rule_text"] == RULE
    assert data["clause_body"] == clause_body_v1(RULE)
    assert data["target_stream"] == TARGET


def test_getruleoffer_unknown_and_malformed(container):
    _seed(offers=[])
    res = _call(getruleoffer, f"getruleoffer {'ff' * 32}", container)
    assert res["error"]["code"] == "OFFER_UNKNOWN"
    assert _call(getruleoffer, "getruleoffer zz", container)["error"]["code"] == "INVALID_PARAMS"
    assert _call(getruleoffer, "getruleoffer abcd", container)["error"]["code"] == "INVALID_PARAMS"


def test_getruleoffer_reports_shape_error_for_stored_text(container):
    """A resolved row may have lost its text, and a stored offer can predate a
    shape rule; report rather than fail."""
    _seed(offers=[_offer_row(rule_text="o5[t] = 1.")])
    data = _call(getruleoffer, f"getruleoffer {_offer_id()}", container)["data"]
    assert data["clause_body"] is None
    assert "shape_error" in data


# --- getruleconflict --------------------------------------------------------

def _layers(data):
    return {layer["layer"]: layer for layer in data["layers"]}


def test_conflict_report_is_advisory_and_layered(container):
    _seed(offers=[_offer_row()])
    data = _call(getruleconflict, f"getruleconflict {_offer_id()}", container)["data"]
    assert data["advisory"] is True
    layers = _layers(data)
    assert layers["shape"]["status"] == "ok"
    assert layers["reserved_domains"]["status"] == "ok"
    assert layers["bv_widths"]["status"] == "ok"
    # The composed rule is what would actually enter the specification.
    assert data["composed_rule"] and B in data["composed_rule"]


def test_conflict_report_never_claims_satisfiability(container):
    """tau-lang exposes sat/unsat/valid/unrealizable in C++ but not to Python,
    so a clean result means 'no conflict observed', never 'none exists'. The
    report must say so rather than implying a guarantee."""
    _seed(offers=[_offer_row()])
    data = _call(getruleconflict, f"getruleconflict {_offer_id()}", container)["data"]
    layer = _layers(data)["unrealizable"]
    assert layer["status"] == "unavailable"
    assert "not" in layer["detail"].lower()


def test_conflict_report_flags_a_bad_shape(container):
    _seed(offers=[_offer_row(rule_text="always ( o5[t] = 1 ). always ( o5[t] = 0 ).")])
    oid = _offer_id(text="always ( o5[t] = 1 ). always ( o5[t] = 0 ).")
    _seed(offers=[_offer_row(offer_id=oid,
                             rule_text="always ( o5[t] = 1 ). always ( o5[t] = 0 ).")])
    data = _call(getruleconflict, f"getruleconflict {oid}", container)["data"]
    assert data["verdict"] == "conflict"
    assert _layers(data)["shape"]["status"] == "conflict"


def test_conflict_report_flags_a_reserved_domain(container):
    bad = "always ( o9[t]:bv[24] = { #x000001 }:bv[24] )."
    oid = _offer_id(text=bad)
    _seed(offers=[_offer_row(offer_id=oid, rule_text=bad)])
    data = _call(getruleconflict, f"getruleconflict {oid}", container)["data"]
    assert data["verdict"] == "conflict"
    # o9 is caught by the shape screen (not a permitted target stream).
    assert _layers(data)["shape"]["status"] == "conflict"


def test_conflict_report_warns_about_replacing_your_own_clause(container):
    """Accepting replaces an existing clause on the same stream, and there is no
    separate retraction -- the recipient has to be told."""
    _seed(
        offers=[_offer_row()],
        clauses=[{"acceptor_pubkey": B, "target_stream": TARGET,
                  "clause_body": "o5[t]:bv[24] = { #x000001 }:bv[24]"}],
    )
    data = _call(getruleconflict, f"getruleconflict {_offer_id()}", container)["data"]
    layer = _layers(data)["registry_collision"]
    assert layer["status"] == "warn"
    assert "REPLACES" in layer["detail"]
    assert data["verdict"] in ("warn", "conflict")


def test_conflict_report_lists_other_acceptors(container):
    _seed(
        offers=[_offer_row()],
        clauses=[{"acceptor_pubkey": C, "target_stream": TARGET,
                  "clause_body": "o5[t]:bv[24] = { #x000001 }:bv[24]"}],
    )
    data = _call(getruleconflict, f"getruleconflict {_offer_id()}", container)["data"]
    layer = _layers(data)["registry_collision"]
    assert layer["other_acceptors"] == [C]
    # The composite must retain the other acceptor.
    assert C in data["composed_rule"] and B in data["composed_rule"]


def test_conflict_report_detects_a_width_clash_statically(container):
    """Compared statically on purpose: probing the engine would permanently
    type streams in the live interpreter, which serves consensus."""
    import chain_state

    clashing = "always ( o5[t]:bv[8] = { #x01 }:bv[8] )."
    oid = _offer_id(text=clashing)
    _seed(offers=[_offer_row(offer_id=oid, rule_text=clashing)])
    original = chain_state._application_rules_state
    try:
        chain_state._application_rules_state = (
            "always ( o5[t]:bv[24] = { #x000001 }:bv[24] )."
        )
        data = _call(getruleconflict, f"getruleconflict {oid}", container)["data"]
    finally:
        chain_state._application_rules_state = original

    layer = _layers(data)["bv_widths"]
    assert layer["status"] == "conflict"
    assert layer["findings"][0]["stream"] == "o5"
    assert data["verdict"] == "conflict"


def test_conflict_report_unknown_offer(container):
    _seed(offers=[])
    res = _call(getruleconflict, f"getruleconflict {'ff' * 32}", container)
    assert res["error"]["code"] == "OFFER_UNKNOWN"


def test_conflict_report_validates_the_id(container):
    assert _call(getruleconflict, "getruleconflict", container)["error"]["code"] == "INVALID_PARAMS"
    assert _call(getruleconflict, "getruleconflict abcd", container)["error"]["code"] == "INVALID_PARAMS"
