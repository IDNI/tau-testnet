def _print_sbf_structure(label: str, sbf_string: str = "", *, transfer_details: dict = None):
    """
    Debug helper: prints the structure of an SBF string.
    If transfer_details are provided, it prints a detailed breakdown of a transfer SBF atom.
    Otherwise, it prints the atom-level structure of a generic SBF string.
    """
    if transfer_details:
        print(f"  [DEBUG][sendtx] {label}:")
        print(f"    - From Key : {transfer_details['from_key'][:10]}... (yID: {transfer_details['from_yid']}) -> bits: {transfer_details['from_bits']}")
        print(f"    - To Key   : {transfer_details['to_key'][:10]}... (yID: {transfer_details['to_yid']}) -> bits: {transfer_details['to_bits']}")
        print(f"    - Amount   : {transfer_details['amount_str']} -> bits: {transfer_details['amount_bits']}")
        print(f"    - Balance  : {transfer_details['balance_int']} -> bits: {transfer_details['balance_bits']}")
        print(f"    - Pattern  : {transfer_details['full_pattern']} (amount+balance+from+to)")
        print(f"    - SBF Atom : '{transfer_details['sbf_atom']}'")
    elif sbf_string:
        atoms = [a.strip() for a in sbf_string.split('&')]
        print(f"  [DEBUG][sendtx] {label} — {len(atoms)} atom(s):")
        for idx, atom in enumerate(atoms):
            print(f"      [{idx}] {atom}")
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
            # Use KeyValidate to check if the public key is valid
            G2Basic.KeyValidate(key_bytes)
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
    def get_address_info(addr_key_hex, addr_name):
        if not (isinstance(addr_key_hex, str) and len(addr_key_hex) == 96 and all(c in '0123456789abcdef' for c in addr_key_hex.lower())):
            raise ValueError(f"Invalid '{addr_name}' address: Must be a 96-character hex BLS12-381 public key: {addr_key_hex}")
        yid = db.get_string_id(addr_key_hex)
        try:
            id_num = int(yid[1:])
            bits = format((id_num - 1) % 16, '04b')
        except ValueError:
            raise ValueError(f"Could not parse numeric ID from yID '{yid}' for '{addr_name}' address ({addr_key_hex[:10]}...)")
        return yid, bits

    from_yid, from_bits = get_address_info(from_addr_key, "from")
    to_yid, to_bits = get_address_info(to_addr_key, "to")

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
    
    # Detailed debug printing
    _print_sbf_structure(
        "SBF Encoding Breakdown for Transfer",
        transfer_details={
            "from_key": from_addr_key, "from_yid": from_yid, "from_bits": from_bits,
            "to_key": to_addr_key, "to_yid": to_yid, "to_bits": to_bits,
            "amount_str": amount_decimal_str, "amount_bits": amount_binary,
            "balance_int": sender_balance_for_tau, "balance_bits": balance_binary,
            "full_pattern": full_bit_pattern,
            "sbf_atom": sbf_atom,
        }
    )
    return sbf_atom

def _decode_single_transfer_output(output_sbf_str, input_sbf_str):
    """
    Decodes Tau's output for a single transfer validation.
    Returns True if successful (echoed input), False otherwise.
    """
    output_sbf_str = output_sbf_str.strip()
    input_sbf_str = input_sbf_str.strip()
    # _print_sbf_structure("Tau output", output_sbf_str)
    # _print_sbf_structure("Expected input", input_sbf_str)

    if output_sbf_str == sbf_defs.FAIL_INVALID_SBF:
        print("  [DEBUG][sendtx] Tau rejected: Invalid command code.")
        return False
    elif output_sbf_str == sbf_defs.FAIL_SRC_EQ_DEST_SBF:
        print("  [DEBUG][sendtx] Tau rejected: Source == Destination.")
        return False
    elif output_sbf_str == sbf_defs.FAIL_ZERO_AMOUNT_SBF:
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

def _parse_json_blob(json_blob: str) -> tuple[str, dict]:
    blob = json_blob.strip()
    if len(blob) >= 2 and ((blob[0] == '"' and blob[-1] == '"') or (blob[0] == "'" and blob[-1] == "'")):
        blob = blob[1:-1]
    try:
        payload = json.loads(blob)
    except Exception as e:
        raise ValueError(f"Invalid JSON payload: {e}")
    if not isinstance(payload, dict):
        raise ValueError("Transaction must be a JSON object.")
    return blob, payload

def _validate_top_level_fields(payload: dict) -> tuple[str, int, int, dict, int | str, str] | str:
    if 'sender_pubkey' not in payload:
        raise ValueError("Missing 'sender_pubkey' in transaction.")
    sender_pubkey = payload['sender_pubkey']
    is_valid_sender, err_sender = _validate_bls12_381_pubkey(sender_pubkey, "sender_pubkey")
    if not is_valid_sender:
        return f"FAILURE: Transaction invalid. {err_sender}"

    if 'sequence_number' not in payload:
        raise ValueError("Missing 'sequence_number' in transaction.")
    sequence_number = payload['sequence_number']
    if not isinstance(sequence_number, int):
        raise ValueError(f"'sequence_number' must be an integer. Got {type(sequence_number).__name__}.")

    if 'expiration_time' not in payload:
        raise ValueError("Missing 'expiration_time' in transaction.")
    expiration_time = payload['expiration_time']
    if not isinstance(expiration_time, int):
        raise ValueError(f"'expiration_time' must be an integer. Got {type(expiration_time).__name__}.")
    current_time = int(time.time())
    if current_time > expiration_time:
        return f"FAILURE: Transaction expired at {expiration_time}. Current time is {current_time}."

    if 'operations' not in payload or not isinstance(payload['operations'], dict):
        raise ValueError("Missing or invalid 'operations' in transaction.")
    operations = payload['operations']

    if 'fee_limit' not in payload:
        raise ValueError("Missing 'fee_limit' in transaction.")
    fee_limit = payload['fee_limit']
    if not isinstance(fee_limit, (int, str)):
        raise ValueError(f"'fee_limit' must be a string or integer. Got {type(fee_limit).__name__}.")

    if 'signature' not in payload:
        raise ValueError("Missing 'signature' in transaction.")
    signature = payload['signature']
    if not isinstance(signature, str):
        raise ValueError(f"'signature' must be a string. Got {type(signature).__name__}.")

    return sender_pubkey, sequence_number, expiration_time, operations, fee_limit, signature

def _verify_signature_and_sequence(
    payload: dict, sender_pubkey: str, sequence_number: int, signature: str
) -> str | None:
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
        except Exception:
            return "FAILURE: Invalid signature."
        expected_seq = chain_state.get_sequence_number(sender_pubkey)
        if sequence_number != expected_seq:
            return f"FAILURE: Invalid sequence number: expected {expected_seq}, got {sequence_number}."
    else:
        print("[WARN][sendtx] BLS crypto not available; skipping signature verification and sequence enforcement.")
    return None

def _preprocess_transfers_phase(
    operations: dict, sender_pubkey: str
) -> tuple[list, list, bool, str | None]:
    print(f"  [INFO][sendtx] Processing transaction with operations: {list(operations.keys())}")
    all_validated_transfers: list = []
    transfer_sbf_encodings: list = []
    empty_transfer_list = False
    if "1" in operations:
        transfers_data = operations["1"]
        if transfers_data:
            success, result_data, error_msg = _process_transfers_operation(transfers_data, sender_pubkey)
            if not success:
                if error_msg.startswith("Error processing transfer #"):
                    return [], [], False, error_msg.replace(
                        "Error processing transfer #", "ERROR: Could not process transfer #", 1
                    )
                return [], [], False, f"FAILURE: Transaction invalid (transfer pre-processing). {error_msg}"
            all_validated_transfers = result_data["transfers"]
            transfer_sbf_encodings = result_data["sbf_encodings"]
            print(f"  [INFO][sendtx] Pre-processed {len(all_validated_transfers)} transfers from operations['1'].")
        else:
            print("  [INFO][sendtx] operations['1'] is present but empty. No transfers to pre-process.")
            empty_transfer_list = True
    else:
        print("  [INFO][sendtx] No operations['1'] key. No transfers to pre-process.")
    return all_validated_transfers, transfer_sbf_encodings, empty_transfer_list, None

def _process_operations_with_tau(
    operations: dict,
    blob: str,
    sender_pubkey: str,
    transfer_sbf_encodings: list,
    empty_transfer_list: bool,
    all_validated_transfers: list,
) -> str:
    try:
        if not operations:
            print("  [INFO][sendtx] No operations in payload. Queuing as is (likely for non-operational TX or empty ops).")
            db.add_mempool_tx(blob)
            if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
                chain_state.increment_sequence_number(sender_pubkey)
            return "SUCCESS: Transaction queued (no operations to process with Tau)."

        operation_int_keys = [int(k) for k in operations.keys() if k.isdigit()]
        if not operation_int_keys:
            print("  [INFO][sendtx] No numeric operation keys. Queuing as is.")
            db.add_mempool_tx(blob)
            if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
                chain_state.increment_sequence_number(sender_pubkey)
            return "SUCCESS: Transaction queued (no numeric operations to process with Tau)."

        max_operation_idx = max(operation_int_keys)
        start_idx = 0

        for current_op_idx in range(start_idx, max_operation_idx + 1):
            op_key_str = str(current_op_idx)
            tau_input_lines: list[str] = []
            print(f"  [INFO][sendtx] Preparing Tau step for operation index: {current_op_idx}")
            for i in range(current_op_idx + 1):
                if i < current_op_idx:
                    tau_input_lines.append(sbf_defs.SBF_LOGICAL_ZERO)
                else:
                    stream_key = str(i)
                    if stream_key == "0":
                        if stream_key in operations and isinstance(operations[stream_key], str) and operations[stream_key].strip():
                            rule_text = operations[stream_key].strip()
                            stmt = rule_text if rule_text.endswith('.') else rule_text + '.'
                            print(f"    [WARN][sendtx] Op {stream_key} (Rule): Rule processing is experimental. Rule: '{rule_text}'")
                            print(f"    [WARN][sendtx] Current Tau program may not support arbitrary rule syntax.")
                            current_data = stmt
                            print(f"    [DEBUG][sendtx] Op {stream_key} (Rule): Using rule statement '{current_data}' for i{i}")
                        else:
                            current_data = sbf_defs.SBF_LOGICAL_ZERO
                            print(f"    [DEBUG][sendtx] Op {stream_key} (Rule): Not present or invalid, using {current_data} for i{i}")
                    elif stream_key == "1":
                        if transfer_sbf_encodings:
                            current_data = transfer_sbf_encodings[0]
                            print(f"    [DEBUG][sendtx] Op {stream_key} (Transfer): Using SBF {current_data} for i{i}")
                        else:
                            current_data = sbf_defs.SBF_LOGICAL_ZERO
                            print(f"    [DEBUG][sendtx] Op {stream_key} (Transfer): No transfers, using {current_data} for i{i}")
                    else:
                        if stream_key in operations:
                            try:
                                current_data = _encode_operation_to_sbf(operations[stream_key], stream_key)
                                print(f"    [DEBUG][sendtx] Op {stream_key} (Custom): Encoded to {current_data} for i{i}")
                            except Exception as e:
                                print(f"    [WARN][sendtx] Op {stream_key} (Custom): Encoding failed ({e}), using {sbf_defs.SBF_LOGICAL_ZERO} for i{i}")
                                current_data = sbf_defs.SBF_LOGICAL_ZERO
                        else:
                            current_data = sbf_defs.SBF_LOGICAL_ZERO
                            print(f"    [DEBUG][sendtx] Op {stream_key} (Custom): Not present, using {current_data} for i{i}")
                    if current_data is not None:
                        tau_input_lines.append(current_data)

            tau_input = "\n".join(tau_input_lines)
            print(f"    [DEBUG][sendtx] Sending to Tau for Op Index {current_op_idx}:\n{tau_input}")
            tau_output = tau_manager.communicate_with_tau(
                input_sbf=tau_input.strip(),
                target_output_stream_index=current_op_idx,
            )
            print(f"    [DEBUG][sendtx] Tau response for Op Index {current_op_idx} (expected from o{current_op_idx}): {tau_output}")

            failure_reason = None
            if stream_key == "1" and not transfer_sbf_encodings and tau_output == sbf_defs.FAIL_INVALID_SBF:
                pass
            elif tau_output == sbf_defs.FAIL_INVALID_SBF:
                failure_reason = "Invalid command or generic failure (FAIL_INVALID_SBF)"
            elif tau_output == sbf_defs.FAIL_SRC_EQ_DEST_SBF:
                failure_reason = "Source equals Destination (FAIL_SRC_EQ_DEST_SBF)"
            elif tau_output == sbf_defs.FAIL_ZERO_AMOUNT_SBF:
                failure_reason = "Zero amount (FAIL_ZERO_AMOUNT_SBF)"
            elif tau_output == sbf_defs.FAIL_INSUFFICIENT_FUNDS_SBF:
                failure_reason = "Insufficient funds (FAIL_INSUFFICIENT_FUNDS_SBF)"

            if failure_reason:
                return f"FAILURE: Transaction rejected due to Tau validation: {failure_reason}"

        # Apply balance updates for validated transfers
        if all_validated_transfers:
            print(f"  [INFO][sendtx] All Tau steps successful. Applying balance changes for {len(all_validated_transfers)} pre-validated transfers...")
            for from_addr, to_addr, amt in all_validated_transfers:
                if not chain_state.update_balances_after_transfer(from_addr, to_addr, amt):
                    print(f"  [CRITICAL][sendtx] Balance update failed for transfer: {from_addr} to {to_addr} for {amt}. This might indicate a desync or logic error.")
                    return (f"FAILURE: Transaction invalid post-Tau. Could not apply transfer "
                            f"({from_addr} -> {to_addr}, amount {amt}).")

        db.add_mempool_tx(blob)
        if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
            chain_state.increment_sequence_number(sender_pubkey)

        print(f"  [INFO][sendtx] Transaction successfully queued in mempool")
        if empty_transfer_list:
            return "SUCCESS: Transaction queued (empty transfer list)."
        return "SUCCESS: Transaction queued."
    except Exception as e:
        print(f"  [ERROR][sendtx] Error during sequential transaction processing: {e}")
        return f"ERROR: Could not process transaction: {e}"

def queue_transaction(json_blob: str) -> str:
    blob, payload = _parse_json_blob(json_blob)
    top_level = _validate_top_level_fields(payload)
    if isinstance(top_level, str):
        return top_level
    sender_pubkey, sequence_number, expiration_time, operations, fee_limit, signature = top_level
    sig_error = _verify_signature_and_sequence(payload, sender_pubkey, sequence_number, signature)
    if sig_error:
        return sig_error
    all_validated_transfers, transfer_sbf_encodings, empty_transfer_list, prep_error = _preprocess_transfers_phase(operations, sender_pubkey)
    if prep_error:
        return prep_error
    return _process_operations_with_tau(
        operations, blob, sender_pubkey, transfer_sbf_encodings, empty_transfer_list, all_validated_transfers,
    )
