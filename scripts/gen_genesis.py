#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path
from dataclasses import dataclass
from blake3 import blake3

# Ensure we can import from the main project
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from consensus.serialization import (
    compute_consensus_meta_hash,
    encode_pubkey48,
    canonical_json
)
from consensus.state import compute_consensus_state_hash
from chain_state import compute_accounts_hash
from block import BlockHeader, sha256_hex

def get_args():
    import argparse
    parser = argparse.ArgumentParser(description="Generate canonical genesis.json artifact.")
    parser.add_argument("--validator-key", type=str, required=True, help="96-character hex BLS public key, no 0x prefix")
    parser.add_argument("--genesis-rules-path", type=str, default="genesis.tau", help="Path to genesis.tau")
    parser.add_argument("--genesis-consensus-path", type=str, default="genesis_consensus.tau", help="Path to genesis_consensus.tau")
    parser.add_argument("--genesis-address", type=str, default="f427fbf4cb8cc5ebcfc50add98ba574b94c03b1e32626e2e50cf60ba5e0a6d0c42d3ed702c2e0eeef7fae29bc4f3d2f9", help="Genesis address")
    parser.add_argument("--genesis-balance", type=int, default=1000000, help="Genesis balance in AGRS")
    parser.add_argument("--network-id", type=str, default="tau-testnet-v2", help="Network ID")
    parser.add_argument("--out", type=str, default="data/genesis.json", help="Output path for genesis.json")
    return parser.parse_args()

def validate_validator_key(key: str) -> bytes:
    if not isinstance(key, str):
        raise ValueError("Validator key must be a string")
    if key.startswith("0x"):
        raise ValueError("Validator key must not have 0x prefix")
    if len(key) != 96:
        raise ValueError(f"Validator key must be exactly 96 chars, got {len(key)}")
    try:
        raw_bytes = bytes.fromhex(key)
    except ValueError:
        raise ValueError("Validator key contains non-hex characters")
    
    if key != key.lower():
        raise ValueError("Validator key must be strictly lowercase")
        
    return raw_bytes

def validate_consensus_rules(rules: str):
    try:
        import tau_native
        import tempfile
        import os
    except ImportError as e:
        print(f"[WARNING] tau_native not available to run static evaluation: {e}")
        return

    # To run a dummy evaluation, we initialize the native engine directly.
    try:
        print("[INFO] Running static test evaluation for consensus_rules...")
        clean_lines = [l.strip() for l in rules.splitlines() if l.strip() and not l.strip().startswith('#')]
        content = " ".join(clean_lines)
        
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            f.write(content)
            temp_path = f.name
            
        try:
            tau_ctx = tau_native.TauInterface(temp_path)
            print("[INFO] Checking constraints on consensus_rules by evaluating i10=0...")
            inputs = {"10": "0"}
            outputs = tau_ctx.communicate_multi(input_stream_values=inputs)
            
            if 6 not in outputs or outputs[6] != "0":
                raise ValueError(f"Consensus rule ABI violation: evaluating i10=0 (invalid proof) MUST yield o6=0 strictly! Got outputs: {outputs}")
            
            print("[INFO] Validated: consensus_rules static check passed for o6 mapping.")
        finally:
            os.remove(temp_path)
            
    except Exception as e:
        if isinstance(e, ValueError):
            raise
        print(f"[WARNING] Static test evaluation execution failed: {e}")

def main():
    args = get_args()

    active_validator_bytes = validate_validator_key(args.validator_key)
    
    with open(args.genesis_rules_path, "r", encoding="utf-8") as f:
        application_rules = f.read()

    with open(args.genesis_consensus_path, "r", encoding="utf-8") as f:
        consensus_rules = f.read()

    validate_consensus_rules(consensus_rules)

    # 1. Accounts Domain
    genesis_accounts = {
        args.genesis_address: args.genesis_balance
    }
    genesis_sequences = {
        args.genesis_address: 0
    }
    accounts_hash_bytes = compute_accounts_hash(genesis_accounts, genesis_sequences)

    # 2. Consensus Meta Domain
    consensus_meta = {
        "proof_scheme": "bls_header_sig",
        "fork_choice_scheme": "height_then_hash",
        "input_contract_version": 1,
        "active_validators": [args.validator_key],
        "pending_updates": [],
        "vote_records": [],
        "activation_schedule": [],
        "checkpoint_references": [],
        "mechanism_specific_metadata": {}
    }

    host_contract = {
        "proof_scheme": "bls_header_sig",
        "fork_choice_scheme": "height_then_hash",
        "input_contract_version": 1
    }

    consensus_meta_hash_bytes = compute_consensus_meta_hash(
        host_contract=host_contract,
        active_validators=[active_validator_bytes],
        pending_updates=[],
        vote_records=[],
        activation_schedule=[],
        checkpoint_references=[],
        mechanism_specific_metadata={}
    )

    # 3. State Hash
    state_hash_hex = compute_consensus_state_hash(
        consensus_rules_bytes=consensus_rules.encode("utf-8"),
        application_rules_bytes=application_rules.encode("utf-8"),
        accounts_hash=accounts_hash_bytes,
        consensus_meta_hash=consensus_meta_hash_bytes
    )

    # 4. Block 0 Payload
    block_0_header = {
        "block_number": 0,
        "previous_hash": "0" * 64,  # genesis parent
        "timestamp": 0,
        "merkle_root": "0" * 64, # empty txs
        "state_hash": state_hash_hex, 
        "proposer_pubkey": "0" * 96 # No proposer for genesis
    }

    block_0_header_obj = BlockHeader(
        block_number=0,
        previous_hash="0" * 64,
        timestamp=0,
        merkle_root="0" * 64,
        state_hash=state_hash_hex,
        proposer_pubkey="0" * 96
    )
    block_0_hash_hex = sha256_hex(block_0_header_obj.canonical_bytes())

    block_0 = {
        "header": block_0_header,
        "transactions": [],
        "consensus_proof": {},
        "hash": block_0_hash_hex
    }

    # 5. Build Final Artifact
    genesis_doc = {
        "genesis_version": 1,
        "network_id": args.network_id,
        "protocol_version": "2.0.0",
        "block_0": block_0,
        "consensus_rules": consensus_rules,
        "application_rules": application_rules,
        "accounts_state": genesis_accounts,
        "consensus_meta": consensus_meta
    }

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as f:
        # Save as readable JSON but the inner hashes are canonical binary guarantees.
        json.dump(genesis_doc, f, indent=2)

    print(f"✅ Generated genesis artifact: {args.out}")
    print(f"Networks ID     : {args.network_id}")
    print(f"Block 0 Hash    : {block_0_hash_hex}")
    print(f"State Hash      : {state_hash_hex}")
    print(f"Consensus Meta  : {consensus_meta_hash_bytes.hex()}")
    sys.exit(0)

if __name__ == "__main__":
    main()
