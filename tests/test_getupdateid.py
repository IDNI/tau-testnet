import json
import pytest
from commands import getupdateid
from consensus.serialization import compute_update_id

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
    
    raw_cmd = f"getupdateid {json.dumps(payload)}"
    response_json = getupdateid.execute(raw_cmd, None)
    response = json.loads(response_json)
    
    assert response["status"] == "ok"
    assert "update_id" in response
    assert len(response["update_id"]) == 64
    assert response["update_id"].islower()
    assert all(c in "0123456789abcdef" for c in response["update_id"])
    
    # Check it matches direct computation
    expected_uid = compute_update_id(revisions, activate_at_height, payload["host_contract_patch"])
    assert response["update_id"] == expected_uid.hex()

def test_getupdateid_missing_revisions():
    payload = {"activate_at_height": 100}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "rule_revisions" in response["error"]

def test_getupdateid_invalid_revisions_type():
    payload = {"rule_revisions": "not a list", "activate_at_height": 100}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "list" in response["error"]

def test_getupdateid_empty_revisions():
    payload = {"rule_revisions": [], "activate_at_height": 100}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "non-empty" in response["error"]

def test_getupdateid_invalid_revision_element():
    payload = {"rule_revisions": [""], "activate_at_height": 100}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "non-empty string" in response["error"]

def test_getupdateid_float_height():
    payload = {"rule_revisions": ["a"], "activate_at_height": 100.0}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "integer, not float" in response["error"]

def test_getupdateid_zero_height():
    payload = {"rule_revisions": ["a"], "activate_at_height": 0}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "1..2^64-1" in response["error"]

def test_getupdateid_negative_height():
    payload = {"rule_revisions": ["a"], "activate_at_height": -1}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "1..2^64-1" in response["error"]

def test_getupdateid_string_height():
    payload = {"rule_revisions": ["a"], "activate_at_height": "100"}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "integer in range" in response["error"]
    
def test_getupdateid_invalid_patch_type():
    payload = {"rule_revisions": ["a"], "activate_at_height": 100, "host_contract_patch": "string"}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "object if provided" in response["error"]
    
def test_getupdateid_invalid_patch_array():
    payload = {"rule_revisions": ["a"], "activate_at_height": 100, "host_contract_patch": []}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "object if provided" in response["error"]
    
def test_getupdateid_malformed_patch_key_type():
    payload = {
        "rule_revisions": ["a"], 
        "activate_at_height": 100, 
        "host_contract_patch": {
            "input_contract_version": "one" # string instead of int
        }
    }
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "error"
    assert "Serialization failed" in response["error"]

def test_getupdateid_no_patch_omitted():
    payload = {"rule_revisions": ["always."], "activate_at_height": 1}
    response = json.loads(getupdateid.execute(f"getupdateid {json.dumps(payload)}", None))
    assert response["status"] == "ok"
    assert "host_contract_patch" not in response["input_echo"]
