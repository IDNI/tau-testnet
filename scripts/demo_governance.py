#!/usr/bin/env python3
import json
import time
import socket
import argparse
import hashlib
import sys
import os
import re

# Ensure we can import from the main node repository
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from py_ecc.bls import G2Basic
from commands.sendtx import _get_signing_message_bytes
from consensus.serialization import compute_update_id


ACTIVATION_BUFFER_BLOCKS = 2

def sign(msg_bytes: bytes, sk_int: int) -> str:
    return G2Basic.Sign(sk_int, hashlib.sha256(msg_bytes).digest()).hex()

def _parse_privkey(sk_str: str) -> bytes:
    s = sk_str.strip()
    if s.lower().startswith('0x') or any(c in s for c in 'abcdefABCDEF'):
        h = s[2:] if s.lower().startswith('0x') else s
        raw = bytes.fromhex(h)
        if len(raw) != 32:
            raise ValueError(f"Invalid private key length: {len(raw)} bytes, expected 32.")
        return raw
    n = int(s, 10)
    if n < 0 or n >= 1 << (8 * 32):
        raise ValueError("Private key integer out of range for 32 bytes.")
    return n.to_bytes(32, 'big')

def _pk_from_sk(sk_bytes: bytes) -> str:
    return G2Basic.SkToPk(int.from_bytes(sk_bytes, 'big')).hex()

def rpc_command(cmd_str, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(cmd_str.encode('utf-8'))
        
        chunks = []
        while True:
            data = sock.recv(65536)
            if not data:
                break
            chunks.append(data)
            # Simple heuristic for json/newline completion just in case
            if b"\n" in data:
                break
    return b"".join(chunks).decode('utf-8')

def assert_success(resp_text: str, context: str):
    if "ERROR" in resp_text or "REJECTED" in resp_text or "VERDICT_REJECT" in resp_text:
        print(f"\n[FATAL] {context} failed!\nResponse: {resp_text.strip()}")
        sys.exit(1)


def _extract_prefixed_body(resp_text: str, prefix: str) -> str:
    body = resp_text.strip()
    if body.startswith(prefix):
        return body[len(prefix):].lstrip("\r\n")
    return body


def rpc_json_command(cmd_str, host, port, prefix=None):
    resp = rpc_command(cmd_str, host, port)
    body = _extract_prefixed_body(resp, prefix) if prefix else resp.strip()
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        print(f"\n[FATAL] Failed to parse JSON response for `{cmd_str.strip()}`.\nRaw response: {resp.strip()}")
        raise SystemExit(1) from exc


def _validate_update_id_hex(update_id: str) -> str:
    if not isinstance(update_id, str) or update_id.startswith("0x") or not re.fullmatch(r"[0-9a-f]{64}", update_id):
        raise ValueError("update_id must be exactly 64 lowercase hex characters with no 0x prefix")
    return update_id

def get_seq(pk, host, port):
    seq_resp = rpc_command(f"getsequence {pk}\r\n", host, port).strip()
    if seq_resp.startswith("SEQUENCE: "):
        return int(seq_resp.split(": ", 1)[1])
    return 0


def get_governance_state(host, port):
    return rpc_json_command("getgovernance\r\n", host, port)


def get_tau_state(host, port):
    resp = rpc_command("gettaustate\r\n", host, port)
    return _extract_prefixed_body(resp, "TAUSTATE:")

def submit_rule_update(host, port, privkey, activate_at, rule: list, patch=None):
    if not rule:
        raise ValueError("rule_revisions cannot be empty")
    if activate_at <= 0:
        raise ValueError("activate_at_height must be positive")
        
    sk_bytes = _parse_privkey(privkey)
    sk_int = int.from_bytes(sk_bytes, 'big')
    pk = _pk_from_sk(sk_bytes)
    seq = get_seq(pk, host, port)
    
    uid_bytes = compute_update_id(rule, activate_at, patch)
    uid_hex = uid_bytes.hex()
    print(f"[*] Computed canonical update_id: {uid_hex}")

    payload = {
        "tx_type": "consensus_rule_update",
        "sender_pubkey": pk,
        "sequence_number": seq,
        "expiration_time": int(time.time()) + 3600,
        "fee_limit": "0",
        "rule_revisions": rule,
        "activate_at_height": activate_at
    }
    if patch is not None:
        payload["host_contract_patch"] = patch

    # Use the exact node canonicalization path
    msg_bytes = _get_signing_message_bytes(payload)
    payload["signature"] = sign(msg_bytes, sk_int)
    
    blob = json.dumps(payload, separators=(",", ":"))
    print(f"[*] Submitting Governance Update: {rule}")
    resp = rpc_command(f"sendtx '{blob}'\r\n", host, port)
    print(f"[REPLY] {resp.strip()}")
    assert_success(resp, "Submit Consensus Rule Update")
    return uid_hex

def submit_vote(host, port, privkey, update_id, approve=True):
    if not approve:
        raise ValueError("approve=False is rejected in v1")
    update_id = _validate_update_id_hex(update_id)
        
    sk_bytes = _parse_privkey(privkey)
    sk_int = int.from_bytes(sk_bytes, 'big')
    pk = _pk_from_sk(sk_bytes)
    seq = get_seq(pk, host, port)
    
    payload = {
        "tx_type": "consensus_rule_vote",
        "sender_pubkey": pk,
        "sequence_number": seq,
        "expiration_time": int(time.time()) + 3600,
        "fee_limit": "0",
        "update_id": update_id,
        "approve": approve
    }
    
    msg_bytes = _get_signing_message_bytes(payload)
    payload["signature"] = sign(msg_bytes, sk_int)
    
    blob = json.dumps(payload, separators=(",", ":"))
    print(f"[*] Submitting Governance Vote for ID: {update_id[:16]}...")
    resp = rpc_command(f"sendtx '{blob}'\r\n", host, port)
    print(f"[REPLY] {resp.strip()}")
    assert_success(resp, "Submit Consensus Rule Vote")


def compute_target_activation(governance_state, *, extra_buffer=ACTIVATION_BUFFER_BLOCKS):
    next_block_height = int(governance_state["next_block_height"])
    validator_count = int(governance_state["active_validator_count"])
    min_activation = next_block_height + validator_count
    target_activation = min_activation + max(1, int(extra_buffer))
    return target_activation, min_activation


def _has_update(governance_state, field_name, update_id):
    return any(entry.get("update_id") == update_id for entry in governance_state.get(field_name, []))


def assert_lifecycle(governance_state, update_id, expected_status, context):
    actual_status = governance_state.get("lifecycle", {}).get(update_id)
    if actual_status != expected_status:
        print(
            f"\n[FATAL] {context} expected lifecycle `{expected_status}` for {update_id}, "
            f"got `{actual_status}`.\nState: {json.dumps(governance_state, indent=2, sort_keys=True)}"
        )
        sys.exit(1)

def run_e2e_scenario(host, port, privkey):
    print("\n=== E2E Governance Lifecycle Validation ===")

    governance_before = get_governance_state(host, port)
    target_activation, min_activation = compute_target_activation(governance_before)
    rule = "always ( o6[t]:bv[16] = { 0 }:bv[16] )."
    print(
        "[1] Staging new consensus rule update "
        f"(next_height={governance_before['next_block_height']}, "
        f"validators={governance_before['active_validator_count']}, "
        f"min_activation={min_activation}, target_activation={target_activation})..."
    )
    uid_hex = submit_rule_update(host, port, privkey, target_activation, [rule])
    
    # Mine Block 1 to include update
    print(f"\n[2] Mining Block 1 to include proposal...")
    resp = rpc_command("createblock\r\n", host, port)
    print(f"[BLOCK] {resp.strip()}")
    assert_success(resp, "Mine Proposal Block")

    governance_after_proposal = get_governance_state(host, port)
    assert_lifecycle(governance_after_proposal, uid_hex, "pending", "After proposal block")
    if not _has_update(governance_after_proposal, "pending_updates", uid_hex):
        print(f"\n[FATAL] Update {uid_hex} missing from pending_updates after proposal block.")
        sys.exit(1)
    
    # 2. Vote
    print(f"\n[3] Voting to approve (latches to scheduled)...")
    submit_vote(host, port, privkey, uid_hex, approve=True)
    
    # Mine Block 2 to include vote
    print(f"\n[4] Mining Block 2 to record vote and latch approval...")
    resp = rpc_command("createblock\r\n", host, port)
    print(f"[BLOCK] {resp.strip()}")
    assert_success(resp, "Mine Vote Block")

    governance_after_vote = get_governance_state(host, port)
    assert_lifecycle(governance_after_vote, uid_hex, "approved-and-scheduled", "After vote block")
    if _has_update(governance_after_vote, "pending_updates", uid_hex):
        print(f"\n[FATAL] Update {uid_hex} still pending after approval.")
        sys.exit(1)
    if not _has_update(governance_after_vote, "scheduled_updates", uid_hex):
        print(f"\n[FATAL] Update {uid_hex} missing from scheduled_updates after approval.")
        sys.exit(1)
    if not any(v.get("update_id") == uid_hex for v in governance_after_vote.get("votes", [])):
        print(f"\n[FATAL] No recorded vote found for approved update {uid_hex}.")
        sys.exit(1)
    
    # 3. Mine to activation boundary
    print("\n[5] Advancing chain to Activation Height delay...")
    current_height = int(governance_after_vote["head_number"])
    while current_height < target_activation:
        next_height = current_height + 1
        print(f"Mining Block {next_height}...")
        resp = rpc_command("createblock\r\n", host, port)
        print(f"[BLOCK] {resp.strip()}")
        assert_success(resp, f"Mine Delay Block {next_height}")
        current_height = int(get_governance_state(host, port)["head_number"])
        
    print("\n[6] Post-Activation Verification...")
    governance_after_activation = get_governance_state(host, port)
    assert_lifecycle(governance_after_activation, uid_hex, "activated", "After activation height")
    if _has_update(governance_after_activation, "scheduled_updates", uid_hex):
        print(f"\n[FATAL] Update {uid_hex} remained scheduled after activation.")
        sys.exit(1)
    if rule.strip() not in governance_after_activation.get("consensus_rules", ""):
        print(
            f"\n[FATAL] Activated consensus rules do not contain the expected revision.\n"
            f"State: {json.dumps(governance_after_activation, indent=2, sort_keys=True)}"
        )
        sys.exit(1)
    if governance_after_activation.get("active_consensus_id") != uid_hex[:16]:
        print(
            f"\n[FATAL] active_consensus_id did not move to the activated update.\n"
            f"Expected prefix: {uid_hex[:16]}\n"
            f"State: {json.dumps(governance_after_activation, indent=2, sort_keys=True)}"
        )
        sys.exit(1)

    print("[SUCCESS] Governance update lifecycle verified:")
    print(f"  - pending after proposal")
    print(f"  - approved-and-scheduled after vote")
    print(f"  - activated at/after height {governance_after_activation['head_number']}")
    print(f"  - active rules now include the submitted consensus revision")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="cmd", required=True)
    
    # Update command
    u = sub.add_parser("update")
    u.add_argument("--privkey", required=True)
    u.add_argument("--rule", required=True)
    u.add_argument("--activation", type=int, required=True)
    u.add_argument("--patch-json", help="Optional host contract patch as JSON string")
    u.add_argument("--host", default="127.0.0.1")
    u.add_argument("--port", type=int, default=65432)
    
    # Vote command
    v = sub.add_parser("vote")
    v.add_argument("--privkey", required=True)
    v.add_argument("--update-id", required=True)
    v.add_argument("--host", default="127.0.0.1")
    v.add_argument("--port", type=int, default=65432)

    # Mine block command
    m = sub.add_parser("mine")
    m.add_argument("--host", default="127.0.0.1")
    m.add_argument("--port", type=int, default=65432)

    # State command (extended inspection via metadata API if available)
    s = sub.add_parser("state")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=65432)
    s.add_argument("--include-taustate", action="store_true")
    
    # E2E test
    e2e = sub.add_parser("e2e")
    e2e.add_argument("--privkey", required=True)
    e2e.add_argument("--host", default="127.0.0.1")
    e2e.add_argument("--port", type=int, default=65432)

    args = parser.parse_args()
    
    if args.cmd == "update":
        patch_dict = json.loads(args.patch_json) if args.patch_json else None
        submit_rule_update(args.host, args.port, args.privkey, args.activation, [args.rule], patch_dict)
    elif args.cmd == "vote":
        submit_vote(args.host, args.port, args.privkey, args.update_id)
    elif args.cmd == "mine":
        resp = rpc_command("createblock\r\n", args.host, args.port)
        print(f"[BLOCK] {resp.strip()}")
        assert_success(resp, "Mine Block")
    elif args.cmd == "state":
        governance = get_governance_state(args.host, args.port)
        print(json.dumps(governance, indent=2, sort_keys=True))
        if args.include_taustate:
            print("\nTAUSTATE:")
            print(get_tau_state(args.host, args.port).strip())
    elif args.cmd == "e2e":
        run_e2e_scenario(args.host, args.port, args.privkey)
