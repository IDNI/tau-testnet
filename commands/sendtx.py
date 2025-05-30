import utils
import sbf_defs
import tau_manager
from db import add_mempool_tx
import json
import db
import chain_state
import time
import hashlib

# {
#   "sender_pubkey": "BLS_PUBLIC_KEY_HEX",
#   "sequence_number": 123, // Integer nonce
#   "expiration_time": 1678886400, // Unix timestamp
#   "operations": {
#     "0": "RULE_DATA_IF_ANY",
#     "1": [["FROM_KEY", "TO_KEY", "AMOUNT"], ...], // Transfers
#     // Other operation types can be added here.
#   },
#   "fee_limit": "10", // Placeholder for future fee model
#   "signature": "HEX_ENCODED_BLS_SIGNATURE"
# }

_PY_ECC_AVAILABLE = False
_PY_ECC_BLS = None
try:
    import py_ecc.bls as _bls_mod
    from py_ecc.bls import G2Basic
    _PY_ECC_BLS = _bls_mod
    _PY_ECC_AVAILABLE = True
    print("[INFO][sendtx] py_ecc.bls module loaded. BLS public key cryptographic validation enabled.")
except ModuleNotFoundError:
    print("[WARN][sendtx] py_ecc.bls module not found. BLS public key cryptographic validation will be skipped. Only format checks will be performed.")
except Exception as e:
    print(f"[WARN][sendtx] Error importing py_ecc.bls: {e}. BLS public key cryptographic validation will be skipped.")


def _validate_bls12_381_pubkey(key_hex: str, key_name: str) -> tuple[bool, str | None]:
    """
    Validates a BLS12-381 public key.
    Checks for 96-character hex format and, if py_ecc is available, cryptographic validity.
    Args:
        key_hex: The public key as a hexadecimal string.
        key_name: Descriptive name for the key (e.g., "from address", "to address") for error messages.
    Returns:
        A tuple (is_valid, error_message). error_message is None if is_valid is True.
    """
    if not (isinstance(key_hex, str) and len(key_hex) == 96):
        return False, f"Invalid {key_name}: Must be a 96-character hex string, got length {len(key_hex)}."
    
    try:
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 48: # BLS12-381 public keys (G1 compressed) are 48 bytes
             return False, f"Invalid {key_name}: Hex string decodes to {len(key_bytes)} bytes, expected 48."
    except ValueError:
        return False, f"Invalid {key_name}: Not a valid hexadecimal string."

    if not all(c in '0123456789abcdefABCDEF' for c in key_hex): # Stricter hex check after length
        return False, f"Invalid {key_name}: Contains non-hexadecimal characters."


    if _PY_ECC_AVAILABLE:
        try:
            G2Basic.AggregatePKs([key_bytes])
        except Exception as e:
            return False, f"Invalid {key_name} (cryptographic validation failed): {e}. Key: {key_hex[:10]}..."
        
    return True, None


def _encode_single_transfer_sbf(transfer_entry, sender_balance_for_tau: int):
    """
    Encodes a single [from_pubkey, to_pubkey, amount] transfer and sender's (capped) balance
    into a 16-bit SBF atom.
    from_pubkey and to_pubkey are BLS12-381 public key hex strings.
    amount is decimal string (0-15), sender_balance_for_tau is an int (0-15).
    The SBF pattern is: amount(4) + sender_balance(4) + from(4) + to(4).
    """
    if not (isinstance(transfer_entry, (list, tuple)) and len(transfer_entry) == 3):
        raise ValueError(f"Invalid transfer entry format: {transfer_entry}")
    from_addr_key, to_addr_key, amount_decimal_str = map(str, transfer_entry)

    # Helper to validate BLS key, get yID, and convert its numeric part to 4 bits
    def get_address_bits(addr_key_hex, addr_name):
        if not (isinstance(addr_key_hex, str) and len(addr_key_hex) == 96 and all(c in '0123456789abcdef' for c in addr_key_hex.lower())):
            raise ValueError(f"Invalid '{addr_name}' address: Must be a 96-character hex BLS12-381 public key: {addr_key_hex}")
        yid = db.get_string_id(addr_key_hex)
        try:
            id_num = int(yid[1:])
            bits = format((id_num - 1) % 16, '04b') 
            # print(f"  [INFO][sendtx] Mapped '{addr_name}' BLS key {addr_key_hex[:10]}... to yID {yid}, bits {bits}") # Less verbose
        except ValueError:
            raise ValueError(f"Could not parse numeric ID from yID '{yid}' for '{addr_name}' address ({addr_key_hex[:10]}...)")
        return bits

    from_bits = get_address_bits(from_addr_key, "from")
    to_bits = get_address_bits(to_addr_key, "to")

    try:
        amount_binary = utils.decimal_to_4bit_binary(amount_decimal_str)
    except ValueError as e:
        raise e 

    try:
        # Ensure sender_balance_for_tau is within 0-15 for 4-bit representation
        if not (0 <= sender_balance_for_tau <= 15):
            # This should ideally be caught before calling, but as a safeguard:
            raise ValueError(f"sender_balance_for_tau must be between 0 and 15, got {sender_balance_for_tau}")
        balance_binary = format(sender_balance_for_tau, '04b')
    except ValueError as e: # Should not happen if input is int, but good practice
        raise ValueError(f"Could not convert sender_balance_for_tau '{sender_balance_for_tau}' to 4-bit binary: {e}")

    # Construct the 16-bit pattern: amount(4) + balance(4) + from(4) + to(4)
    full_bit_pattern = amount_binary + balance_binary + from_bits + to_bits
    if len(full_bit_pattern) != 16: # Check for 16 bits
        raise AssertionError(f"Internal error: Generated bit pattern length is {len(full_bit_pattern)}, expected 16.")

    sbf_atom = utils.bits_to_sbf_atom(full_bit_pattern, length=16)
    print(f"  [DEBUG][sendtx] Encoded transfer+balance {[from_addr_key[:10]+'...', to_addr_key[:10]+'...', amount_decimal_str, sender_balance_for_tau]} to SBF: '{sbf_atom}' (Pattern: {full_bit_pattern})")
    return sbf_atom

def _decode_single_transfer_output(output_sbf_str, input_sbf_str):
    """
    Decodes Tau's output for a single transfer validation.
    Returns True if successful (echoed input), False otherwise.
    """
    output_sbf_str = output_sbf_str.strip()
    input_sbf_str = input_sbf_str.strip()

    if output_sbf_str == sbf_defs.FAIL_CODE_INVALID_COMMAND_SBF:
        print("  [DEBUG][sendtx] Tau rejected: Invalid command code.")
        return False
    elif output_sbf_str == sbf_defs.FAIL_CODE_SRC_EQ_DEST_SBF:
        print("  [DEBUG][sendtx] Tau rejected: Source == Destination.")
        return False
    elif output_sbf_str == sbf_defs.FAIL_CODE_ZERO_AMOUNT_SBF:
        print("  [DEBUG][sendtx] Tau rejected: Zero amount.")
        return False
    elif output_sbf_str == sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF: # Corrected constant name
        print("  [DEBUG][sendtx] Tau rejected: Insufficient funds (as per Tau's capped check).")
        return False
    elif output_sbf_str == sbf_defs.SBF_LOGICAL_ZERO: # Assuming SBF_ZERO is now SBF_LOGICAL_ZERO for generic 0
        print("  [DEBUG][sendtx] Tau rejected: Generic '0'.")
        return False
    elif output_sbf_str == input_sbf_str:
        print("  [DEBUG][sendtx] Tau accepted: Echoed input.")
        return True
    else:
        print(f"  [WARN][sendtx] Unexpected Tau output: '{output_sbf_str}' (Expected echo: '{input_sbf_str}' or known fail code)")
        return False

def _get_signing_message_bytes(payload: dict) -> bytes:
    """
    Construct canonical bytes over transaction fields for BLS signing/verifying.
    Only includes sender_pubkey, sequence_number, expiration_time, operations, and fee_limit.
    Uses sorted keys and compact JSON.
    """
    signing_dict = {
        "sender_pubkey": payload["sender_pubkey"],
        "sequence_number": payload["sequence_number"],
        "expiration_time": payload["expiration_time"],
        "operations": payload["operations"],
        "fee_limit": payload["fee_limit"],
    }
    return json.dumps(signing_dict, sort_keys=True, separators=(",", ":")).encode()

def _process_transfers_operation(transfers, sender_pubkey):
    """
    Process and validate transfers (operation "1").
    Returns (success, result_data, error_message).
    result_data contains the validated transfers and their SBF encodings.
    """
    if not isinstance(transfers, list):
        return False, None, "Transfers (key '1') must be a list."
    
    if not transfers:
        return True, {"transfers": [], "sbf_encodings": []}, None
    
    validated_transfers = []
    sbf_encodings = []
    
    print(f"  [INFO][sendtx] Processing {len(transfers)} transfers...")
    for i, transfer_entry in enumerate(transfers):
        print(f"    Processing transfer #{i+1}: {transfer_entry}")
        if not (isinstance(transfer_entry, (list, tuple)) and len(transfer_entry) == 3):
            return False, None, f"Transfer #{i+1} has invalid format: {transfer_entry}"
            
        from_addr_key, to_addr_key, amount_decimal_str = map(str, transfer_entry)

        # Crucial: from_addr_key must match sender_pubkey
        if from_addr_key != sender_pubkey:
            return False, None, (f"Transfer #{i+1} 'from' address "
                    f"{from_addr_key} does not match sender_pubkey {sender_pubkey}")

        # Validate address formats first (non-cryptographic part)
        is_valid_from, err_from = _validate_bls12_381_pubkey(from_addr_key, f"transfer #{i+1} 'from' address")
        if not is_valid_from:
            return False, None, err_from
        is_valid_to, err_to = _validate_bls12_381_pubkey(to_addr_key, f"transfer #{i+1} 'to' address")
        if not is_valid_to:
            return False, None, err_to

        try:
            amount_int = int(amount_decimal_str)
        except ValueError:
            print(f"  [ERROR][sendtx] Transfer #{i+1} has non-integer amount '{amount_decimal_str}'. Encoding will likely fail.")

        actual_sender_balance = chain_state.get_balance(from_addr_key)
        sender_balance_for_tau = min(actual_sender_balance, 15) 

        try:
            sbf_raw = _encode_single_transfer_sbf(transfer_entry, sender_balance_for_tau)
            validated_transfers.append((from_addr_key, to_addr_key, amount_int))
            sbf_encodings.append(sbf_raw)
        except ValueError as e:
            return False, None, f"Error processing transfer #{i+1}: {e}"
        except Exception as e:
            return False, None, f"Unexpected error during transfer #{i+1} processing: {e}"

    return True, {"transfers": validated_transfers, "sbf_encodings": sbf_encodings}, None

def _encode_operation_to_sbf(operation_data, operation_key):
    """
    Encode a generic operation to SBF format.
    For now, this is a placeholder that can be extended for different operation types.
    Returns the SBF-encoded string or raises an exception.
    """
    # This is a placeholder implementation
    # Different operation types would need different encoding logic
    if operation_key == "1":
        # This should not be called for transfers as they have special handling
        raise ValueError("Transfers should be handled by _process_transfers_operation")
    
    # For other operations, we might need different encoding strategies
    # For now, return a default SBF encoding or raise an error
    print(f"  [WARN][sendtx] Generic operation encoding not implemented for operation {operation_key}: {operation_data}")
    return "F"  # Return F as placeholder

def _build_combined_tau_input(operations, sender_pubkey):
    """
    Build the combined input string to send to Tau.
    Processes operations "0", "1", "2", "3", etc. up to the maximum operation key present.
    - Operation "0" (rules): sent as-is + \n
    - Other operations: SBF-encoded if present, "F\n" if missing
    Returns (success, tau_input_string, validated_transfers, error_message)
    """
    tau_input_parts = []
    validated_transfers = []
    
    # Find the maximum operation key present in the operations
    if not operations:
        return True, "", [], None
    
    # Convert operation keys to integers and find the maximum
    try:
        operation_int_keys = [int(key) for key in operations.keys() if key.isdigit()]
        if not operation_int_keys:
            return True, "", [], None
        max_operation = max(operation_int_keys)
    except ValueError:
        return False, None, None, "Invalid operation keys - must be numeric strings"
    
    # Process operations from 0 to max_operation
    operation_keys = [str(i) for i in range(max_operation + 1)]
    
    for op_key in operation_keys:
        if op_key == "0":
            # Handle rules - send as-is
            if op_key in operations:
                rule = operations[op_key]
                if isinstance(rule, str) and rule.strip():
                    tau_input_parts.append(f"{rule.strip()}")
                    print(f"  [DEBUG][sendtx] Added rule for operation {op_key}: {rule.strip()}")
                else:
                    tau_input_parts.append("F")
                    print(f"  [DEBUG][sendtx] Invalid or empty rule for operation {op_key}, using F")
            else:
                tau_input_parts.append("F")
                print(f"  [DEBUG][sendtx] No rule for operation {op_key}, using F")
                
        elif op_key == "1":
            # Handle transfers
            if op_key in operations:
                success, result_data, error_msg = _process_transfers_operation(operations[op_key], sender_pubkey)
                if not success:
                    return False, None, None, error_msg
                
                validated_transfers = result_data["transfers"]
                sbf_encodings = result_data["sbf_encodings"]
                
                if sbf_encodings:
                    # For multiple transfers, we'll send the first one for now
                    # This logic might need to be adjusted based on Tau's expectations
                    # If Tau can handle multiple transfers in one operation, this would need modification
                    tau_input_parts.append(sbf_encodings[0])
                    print(f"  [DEBUG][sendtx] Added SBF encoding for transfers: {sbf_encodings[0]}")
                    if len(sbf_encodings) > 1:
                        print(f"  [WARN][sendtx] Multiple transfers detected, only sending first one. This may need adjustment.")
                else:
                    tau_input_parts.append("F")
                    print(f"  [DEBUG][sendtx] No transfers for operation {op_key}, using F")
            else:
                tau_input_parts.append("F")
                print(f"  [DEBUG][sendtx] No transfers for operation {op_key}, using F")
                
        else:
            # Handle other operations (2, 3, etc.)
            if op_key in operations:
                try:
                    sbf_encoded = _encode_operation_to_sbf(operations[op_key], op_key)
                    tau_input_parts.append(sbf_encoded)
                    print(f"  [DEBUG][sendtx] Added SBF encoding for operation {op_key}: {sbf_encoded}")
                except Exception as e:
                    print(f"  [WARN][sendtx] Failed to encode operation {op_key}: {e}, using F")
                    tau_input_parts.append("F")
            else:
                tau_input_parts.append("F")
                print(f"  [DEBUG][sendtx] No data for operation {op_key}, using F")
    
    # Join with newlines to create the multi-line input
    tau_input_string = "\n".join(tau_input_parts)
    return True, tau_input_string, validated_transfers, None

def queue_transaction(json_blob: str) -> str:
    blob = json_blob.strip()
    if len(blob) >= 2 and ((blob[0] == '"' and blob[-1] == '"') or (blob[0] == "'" and blob[-1] == "'")):
        blob = blob[1:-1]
    try:
        payload = json.loads(blob)
    except Exception as e:
        raise ValueError(f"Invalid JSON payload: {e}")
    if not isinstance(payload, dict):
        raise ValueError("Transaction must be a JSON object.")

    # Parse and validate new top-level transaction fields (structural update phase)
    # sender_pubkey
    if 'sender_pubkey' not in payload:
        raise ValueError("Missing 'sender_pubkey' in transaction.")
    sender_pubkey = payload['sender_pubkey']
    is_valid_sender, err_sender = _validate_bls12_381_pubkey(sender_pubkey, "sender_pubkey")
    if not is_valid_sender:
        return f"FAILURE: Transaction invalid. {err_sender}"

    # sequence_number field must be present and integer (strict enforcement after signature)
    if 'sequence_number' not in payload:
        raise ValueError("Missing 'sequence_number' in transaction.")
    sequence_number = payload['sequence_number']
    if not isinstance(sequence_number, int):
        raise ValueError(f"'sequence_number' must be an integer. Got {type(sequence_number).__name__}.")

    # expiration_time
    if 'expiration_time' not in payload:
        raise ValueError("Missing 'expiration_time' in transaction.")
    expiration_time = payload['expiration_time']
    if not isinstance(expiration_time, int):
        raise ValueError(f"'expiration_time' must be an integer. Got {type(expiration_time).__name__}.")
    current_time = int(time.time())
    if current_time > expiration_time:
        return f"FAILURE: Transaction expired at {expiration_time}. Current time is {current_time}."

    # operations
    if 'operations' not in payload or not isinstance(payload['operations'], dict):
        raise ValueError("Missing or invalid 'operations' in transaction.")
    operations = payload['operations']

    # fee_limit (placeholder, not used yet)
    if 'fee_limit' not in payload:
        raise ValueError("Missing 'fee_limit' in transaction.")
    fee_limit = payload['fee_limit']
    if not isinstance(fee_limit, (int, str)):
        raise ValueError(f"'fee_limit' must be a string or integer. Got {type(fee_limit).__name__}.")

    # signature field must be present and a string
    if 'signature' not in payload:
        raise ValueError("Missing 'signature' in transaction.")
    signature = payload['signature']
    if not isinstance(signature, str):
        raise ValueError(f"'signature' must be a string. Got {type(signature).__name__}.")

    # BLS signature verification and strict sequence enforcement (Phase 2)
    if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
        msg_bytes = _get_signing_message_bytes(payload)
        msg_hash = hashlib.sha256(msg_bytes).digest()
        try:
            sig_bytes = bytes.fromhex(signature)
        except Exception:
            return "FAILURE: Invalid signature format."
        try:
            pubkey_bytes = bytes.fromhex(sender_pubkey)
        except Exception:
            return "FAILURE: Invalid signature (bad public key format)."
        try:
            if not G2Basic.Verify(pubkey_bytes, msg_hash, sig_bytes):
                return "FAILURE: Invalid signature."
        except Exception as e:
            print(f"[ERROR][sendtx] Signature verification error: {e}")
            return "FAILURE: Invalid signature."
        expected_seq = chain_state.get_sequence_number(sender_pubkey)
        if sequence_number != expected_seq:
            return f"FAILURE: Invalid sequence number: expected {expected_seq}, got {sequence_number}."
    else:
        print("[WARN][sendtx] BLS crypto not available; skipping signature verification and sequence enforcement.")

    # NEW MULTI-OPERATION PROCESSING APPROACH
    # Build combined input for all operations and send to Tau
    print(f"  [INFO][sendtx] Processing transaction with operations: {list(operations.keys())}")
    
    try:
        success, tau_input_string, validated_transfers, error_msg = _build_combined_tau_input(operations, sender_pubkey)
        if not success:
            return f"FAILURE: Transaction invalid. {error_msg}"
        
        print(f"  [DEBUG][sendtx] Sending combined input to Tau:\n{tau_input_string}")
        
        # Send the combined input to Tau
        tau_output = tau_manager.communicate_with_tau(tau_input_string.strip())
        
        # For now, we'll accept the transaction if Tau doesn't explicitly reject it
        # More sophisticated output parsing can be added later
        print(f"  [DEBUG][sendtx] Tau response: {tau_output}")
        
        # Check for explicit failure codes
        if tau_output in [sbf_defs.FAIL_CODE_INVALID_COMMAND_SBF, 
                         sbf_defs.FAIL_CODE_SRC_EQ_DEST_SBF,
                         sbf_defs.FAIL_CODE_ZERO_AMOUNT_SBF,
                         sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF,
                         sbf_defs.SBF_LOGICAL_ZERO]:
            return f"FAILURE: Transaction rejected by Tau logic. Output: {tau_output}"
        
        # If we have validated transfers, apply balance changes
        if validated_transfers:
            print(f"  [INFO][sendtx] Applying balance changes for {len(validated_transfers)} transfers...")
            for from_addr, to_addr, amt in validated_transfers:
                if not chain_state.update_balances_after_transfer(from_addr, to_addr, amt):
                    print(f"  [CRITICAL][sendtx] Balance update failed for transfer: {from_addr} to {to_addr} for {amt}")
                    return f"FAILURE: Transaction invalid. Could not apply transfer ({from_addr} -> {to_addr}, amount {amt})."
        
        # Transaction accepted, add to mempool
        db.add_mempool_tx(blob)
        if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
            chain_state.increment_sequence_number(sender_pubkey)
        
        print(f"  [INFO][sendtx] Transaction successfully queued in mempool")
        return "SUCCESS: Transaction queued."
        
    except Exception as e:
        print(f"  [ERROR][sendtx] Error during transaction processing: {e}")
        return f"ERROR: Could not process transaction: {e}"