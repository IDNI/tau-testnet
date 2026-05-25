import json
import pytest
from commands import getupdateid
from consensus.serialization import compute_update_id


def _call(payload):
    return json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))


def test_getupdateid_valid():
    revisions = ["always (o5[t] = {1}:bv)."]
    activate_at_height = 100

    payload = {
        "rule_revisions": revisions,
        "activate_at_height": activate_at_height,
        "host_contract_patch": {
            "proof_scheme": "bls_header_sig",
            "fork_choice_scheme": "height_then_hash",
            "input_contract_version": 1
        }
    }

    response = _call(payload)

    assert response["status"] == "ok"
    data = response["data"]
    assert "update_id" in data
    assert len(data["update_id"]) == 64
    assert data["update_id"].islower()
    assert all(c in "0123456789abcdef" for c in data["update_id"])

    expected_uid = compute_update_id(revisions, activate_at_height, payload["host_contract_patch"])
    assert data["update_id"] == expected_uid.hex()


def test_getupdateid_missing_revisions():
    response = _call({"activate_at_height": 100})
    assert response["status"] == "error"
    assert "rule_revisions" in response["error"]["message"]


def test_getupdateid_invalid_revisions_type():
    response = _call({"rule_revisions": "not a list", "activate_at_height": 100})
    assert response["status"] == "error"
    assert "list" in response["error"]["message"]


def test_getupdateid_empty_revisions():
    response = _call({"rule_revisions": [], "activate_at_height": 100})
    assert response["status"] == "error"
    assert "non-empty" in response["error"]["message"]


def test_getupdateid_invalid_revision_element():
    response = _call({"rule_revisions": [""], "activate_at_height": 100})
    assert response["status"] == "error"
    assert "non-empty string" in response["error"]["message"]


def test_getupdateid_float_height():
    response = _call({"rule_revisions": ["a"], "activate_at_height": 100.0})
    assert response["status"] == "error"
    assert "integer, not float" in response["error"]["message"]


def test_getupdateid_zero_height():
    response = _call({"rule_revisions": ["a"], "activate_at_height": 0})
    assert response["status"] == "error"
    assert "1..2^64-1" in response["error"]["message"]


def test_getupdateid_negative_height():
    response = _call({"rule_revisions": ["a"], "activate_at_height": -1})
    assert response["status"] == "error"
    assert "1..2^64-1" in response["error"]["message"]


def test_getupdateid_string_height():
    response = _call({"rule_revisions": ["a"], "activate_at_height": "100"})
    assert response["status"] == "error"
    assert "integer in range" in response["error"]["message"] or "integer, not float" in response["error"]["message"]


def test_getupdateid_invalid_patch_type():
    response = _call({
        "rule_revisions": ["a"],
        "activate_at_height": 100,
        "host_contract_patch": "string",
    })
    assert response["status"] == "error"
    assert "object if provided" in response["error"]["message"]


def test_getupdateid_invalid_patch_array():
    response = _call({
        "rule_revisions": ["a"],
        "activate_at_height": 100,
        "host_contract_patch": [],
    })
    assert response["status"] == "error"
    assert "object if provided" in response["error"]["message"]


def test_getupdateid_no_patch_omitted():
    response = _call({"rule_revisions": ["always."], "activate_at_height": 1})
    assert response["status"] == "ok"
    assert "host_contract_patch" not in response["data"]["input_echo"]
