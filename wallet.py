#!/usr/bin/env python3
"""
Simple console wallet for Tau Testnet Alpha.

Features:
- Generate a new BLS keypair
- Send signed transactions
- Query account balance
- List transaction history
"""

import argparse
import socket
import json
import time
import secrets
import hashlib
from py_ecc.bls import G2Basic
from commands.sendtx import _get_signing_message_bytes
import config


def rpc_command(cmd_str, host, port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((host, port))
        sock.sendall(cmd_str.encode('utf-8'))
        data = sock.recv(65536)
    return data.decode('utf-8')


def _parse_privkey(sk_str: str) -> bytes:
    """
    Parse a private key string in decimal or hex format into raw private key bytes (32 bytes).
    Accepts:
      - Hex string of exactly 64 hex digits, with or without '0x' prefix.
      - Decimal integer string.
    """
    s = sk_str.strip()
    # Hex if '0x' prefix or contains hex letters
    if s.lower().startswith('0x') or any(c in s for c in 'abcdefABCDEF'):
        h = s[2:] if s.lower().startswith('0x') else s
        raw = bytes.fromhex(h)
        if len(raw) != 32:
            raise ValueError(f"Invalid private key length: {len(raw)} bytes, expected 32.")
        return raw
    # Otherwise decimal integer
    n = int(s, 10)
    if n < 0 or n >= 1 << (8 * 32):
        raise ValueError("Private key integer out of range for 32 bytes.")
    return n.to_bytes(32, 'big')


def cmd_new(args):
    ikm = secrets.token_bytes(32)
    sk = G2Basic.KeyGen(ikm)
    pk = G2Basic.SkToPk(sk)
    sk_int = int.from_bytes(sk, 'big')
    print(f"Private Key (int): {sk_int}")
    print(f"Private Key (hex): {sk.hex()}")
    print(f"Public Key (hex): {pk.hex()}")


def get_address(args):
    if getattr(args, 'privkey', None):
        raw_bytes = _parse_privkey(args.privkey)
        # Convert bytes to integer (the actual private key)
        private_key_int = int.from_bytes(raw_bytes, 'big')
        return G2Basic.SkToPk(private_key_int).hex()
    return args.address


def cmd_balance(args):
    addr = get_address(args)
    resp = rpc_command(f"getbalance {addr}\r\n", args.host, args.port)
    print(resp.strip())


def cmd_history(args):
    addr = get_address(args)
    resp = rpc_command(f"history {addr}\r\n", args.host, args.port)
    print(resp.strip())


def cmd_createblock(args):
    resp = rpc_command("createblock\r\n", args.host, args.port)
    print(resp.strip())


def cmd_send(args):
    raw_bytes = _parse_privkey(args.privkey)
    # Convert bytes to integer (the actual private key)
    private_key_int = int.from_bytes(raw_bytes, 'big')
    sender_pk = G2Basic.SkToPk(private_key_int).hex()
    
    # Get the current sequence number from the server
    seq_resp = rpc_command(f"getsequence {sender_pk}\r\n", args.host, args.port).strip()
    if seq_resp.startswith("SEQUENCE: "):
        seq = int(seq_resp.split(": ", 1)[1])
    else:
        # Fallback to history-based calculation if getsequence fails
        print(f"Warning: Could not get sequence number from server ({seq_resp}), falling back to history count")
        hist = rpc_command(f"history {sender_pk}\r\n", args.host, args.port).splitlines()
        seq = len(hist) - 1 if len(hist) > 1 else 0
    expiration = int(time.time()) + args.expiry
    
    # Build operations dictionary
    operations = {}
    
    # Handle rule (operation "0")
    if hasattr(args, 'rule') and args.rule:
        operations["0"] = args.rule
        print(f"Adding rule: {args.rule}")
    
    # Handle transfers (operation "1")
    transfers = []
    
    # Backwards compatibility: if --to and --amount are provided, use them
    if hasattr(args, 'to') and hasattr(args, 'amount') and args.to and args.amount is not None:
        transfers.append([sender_pk, args.to, str(args.amount)])
        print(f"Adding transfer: {args.amount} to {args.to}")
    
    # Add transfers from --transfer arguments
    if hasattr(args, 'transfer') and args.transfer:
        for transfer_str in args.transfer:
            try:
                # Parse transfer string in format "to_address:amount"
                to_addr, amount_str = transfer_str.split(':', 1)
                amount = int(amount_str)
                transfers.append([sender_pk, to_addr.strip(), str(amount)])
                print(f"Adding transfer: {amount} to {to_addr.strip()}")
            except ValueError as e:
                raise ValueError(f"Invalid transfer format '{transfer_str}'. Use 'to_address:amount'") from e
    
    if transfers:
        operations["1"] = transfers
    
    # Handle custom operations
    if hasattr(args, 'operation') and args.operation:
        for op_str in args.operation:
            try:
                # Parse operation string in format "op_number:data"
                op_num, op_data = op_str.split(':', 1)
                op_num = op_num.strip()
                op_data = op_data.strip()
                
                # Validate operation number
                if not op_num.isdigit():
                    raise ValueError(f"Operation number must be a digit, got '{op_num}'")
                
                operations[op_num] = op_data
                print(f"Adding custom operation {op_num}: {op_data}")
            except ValueError as e:
                raise ValueError(f"Invalid operation format '{op_str}'. Use 'op_number:data'") from e
    
    # Handle raw JSON operations (overrides other operation settings)
    if hasattr(args, 'operations_json') and args.operations_json:
        try:
            operations = json.loads(args.operations_json)
            print(f"Using raw JSON operations: {operations}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in --operations-json: {e}") from e
    
    # Ensure we have at least one operation
    if not operations:
        raise ValueError("No operations specified. Use --to/--amount, --rule, --transfer, --operation, or --operations-json")
    
    payload = {
        "sender_pubkey": sender_pk,
        "sequence_number": seq,
        "expiration_time": expiration,
        "operations": operations,
        "fee_limit": str(args.fee),
    }
    
    print(f"Transaction payload: {json.dumps(payload, indent=2)}")
    
    msg_bytes = _get_signing_message_bytes(payload)
    sig = G2Basic.Sign(private_key_int, hashlib.sha256(msg_bytes).digest())
    payload["signature"] = sig.hex()
    blob = json.dumps(payload, separators=(",", ":"))
    cmd = f"sendtx '{blob}'\r\n"
    resp = rpc_command(cmd, args.host, args.port)
    print(resp.strip())


def main():
    parser = argparse.ArgumentParser(prog="wallet", description="Tau Testnet Alpha Console Wallet")
    parser.add_argument("--host", default=config.HOST, help="Node host")
    parser.add_argument("--port", type=int, default=config.PORT, help="Node port")
    sub = parser.add_subparsers(dest="command", required=True)
    p_new = sub.add_parser("new", help="Generate new BLS keypair")
    p_new.set_defaults(func=cmd_new)
    p_bal = sub.add_parser("balance", help="Query account balance")
    gb = p_bal.add_mutually_exclusive_group(required=True)
    gb.add_argument("--privkey", "-k", help="Private key (hex or decimal)")
    gb.add_argument("--address", "-a", help="Public key hex")
    p_bal.set_defaults(func=cmd_balance)
    p_hist = sub.add_parser("history", help="List transaction history")
    gh = p_hist.add_mutually_exclusive_group(required=True)
    gh.add_argument("--privkey", "-k", help="Private key (hex or decimal)")
    gh.add_argument("--address", "-a", help="Public key hex")
    p_hist.set_defaults(func=cmd_history)
    p_send = sub.add_parser("send", help="Send a transaction")
    p_send.add_argument("--privkey", "-k", required=True, help="Private key (hex or decimal)")
    
    # Simple transfer options (backwards compatibility)
    p_send.add_argument("--to", "-t", help="Recipient public key hex (for simple transfers)")
    p_send.add_argument("--amount", "-m", type=int, help="Amount to send (for simple transfers)")
    
    # Multi-operation options
    p_send.add_argument("--rule", "-r", help="Rule to add as operation 0 (e.g., 'o2[t]=i1[t]')")
    p_send.add_argument("--transfer", action="append", help="Transfer in format 'to_address:amount' (can be used multiple times)")
    p_send.add_argument("--operation", "-o", action="append", help="Custom operation in format 'op_number:data' (can be used multiple times)")
    p_send.add_argument("--operations-json", help="Raw JSON operations object (overrides other operation options)")
    
    # Transaction metadata
    p_send.add_argument("--fee", "-f", default=0, type=int, help="Fee limit")
    p_send.add_argument("--expiry", "-e", default=3600, type=int, help="Expiration seconds from now")
    p_send.set_defaults(func=cmd_send)
    
    # Create block command
    p_createblock = sub.add_parser("createblock", help="Create a new block from mempool")
    p_createblock.set_defaults(func=cmd_createblock)
    
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()