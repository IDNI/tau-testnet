import utils
import sbf_defs
import tau_manager
from db import add_mempool_tx
import json
import db
import chain_state
import time
import time

# Attempt to import py_ecc.bls for cryptographic validation of public keys
_PY_ECC_AVAILABLE = False
_PY_ECC_BLS = None
try:
    import py_ecc.bls
    _PY_ECC_BLS = py_ecc.bls
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


    if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
        try:
            # AggregatePKs validates G1 points. If the key is invalid, it should raise an error.
            _PY_ECC_BLS.AggregatePKs([key_bytes]) 
        except Exception as e:
            # Catching a broad exception as py_ecc might raise various errors for invalid points.
            return False, f"Invalid {key_name} (cryptographic validation failed): {e}. Key: {key_hex[:10]}..."
    else:
        # If py_ecc is not available, we rely on the format checks already performed.
        # A warning about skipped crypto validation is printed at module load.
        pass
        
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

    # sequence_number (placeholder logic; enforcement in later phase)
    if 'sequence_number' not in payload:
        raise ValueError("Missing 'sequence_number' in transaction.")
    sequence_number = payload['sequence_number']
    if not isinstance(sequence_number, int):
        raise ValueError(f"'sequence_number' must be an integer. Got {type(sequence_number).__name__}.")
    expected_seq = chain_state.get_sequence_number(sender_pubkey)
    if sequence_number != expected_seq:
        print(f"[WARN][sendtx] Sequence number mismatch for {sender_pubkey[:10]}...: expected {expected_seq}, got {sequence_number}.")

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

    # signature (parsed but not verified in this phase)
    if 'signature' not in payload:
        raise ValueError("Missing 'signature' in transaction.")
    signature = payload['signature']
    if not isinstance(signature, str):
        raise ValueError(f"'signature' must be a string. Got {type(signature).__name__}.")

    # If no transfers specified under operations, handle other ops via dynamic Tau input
    if '1' not in operations:
        # Build SBF input for other operation fields
        try:
            dynamic_sbf_input = utils.build_tau_input(operations)
            tau_manager.communicate_with_tau(dynamic_sbf_input)
        except Exception as e:
            print(f"  [WARN][sendtx] Dynamic Tau input failed: {e}")

        print("  [INFO][sendtx] No transfers (operations['1']) in payload. Queuing as is.")
        db.add_mempool_tx(blob)
        return "SUCCESS: Transaction queued (no transfers to validate via Tau)."
    
    transfers = operations['1']
    if not isinstance(transfers, list):
        raise ValueError("Transfers (key '1') must be a list.")
    if not transfers:
        print("  [INFO][sendtx] Empty list of transfers in payload. Queuing as is.")
        db.add_mempool_tx(blob)
        return f"SUCCESS: Transaction queued (empty transfer list)."

    validated_transfers_for_mempool = [] # Store original transfer data if all are fine

    print(f"  [INFO][sendtx] Validating {len(transfers)} transfers...")
    for i, transfer_entry in enumerate(transfers):
        print(f"    Validating transfer #{i+1}: {transfer_entry}")
        if not (isinstance(transfer_entry, (list, tuple)) and len(transfer_entry) == 3):
            return f"FAILURE: Transaction invalid. Transfer #{i+1} has invalid format: {transfer_entry}"
            
        from_addr_key, to_addr_key, amount_decimal_str = map(str, transfer_entry)

        # Crucial: from_addr_key must match sender_pubkey
        if from_addr_key != sender_pubkey:
            return (f"FAILURE: Transaction invalid. Transfer #{i+1} 'from' address "
                    f"{from_addr_key} does not match sender_pubkey {sender_pubkey}")

        # Validate address formats first (non-cryptographic part)
        is_valid_from, err_from = _validate_bls12_381_pubkey(from_addr_key, f"transfer #{i+1} 'from' address")
        if not is_valid_from:
            return f"FAILURE: Transaction invalid. {err_from}"
        is_valid_to, err_to = _validate_bls12_381_pubkey(to_addr_key, f"transfer #{i+1} 'to' address")
        if not is_valid_to:
            return f"FAILURE: Transaction invalid. {err_to}"

        try:
            amount_int = int(amount_decimal_str)
        except ValueError:
            # If amount_decimal_str is not even an integer, _encode_single_transfer_sbf will fail at decimal_to_4bit_binary.
            print(f"  [ERROR][sendtx] Transfer #{i+1} has non-integer amount '{amount_decimal_str}'. Encoding will likely fail.")
            # Let it proceed to encoding, which will raise an error if invalid format for 4-bit conversion.
            pass # Allow to proceed to encoding attempt

        actual_sender_balance = chain_state.get_balance(from_addr_key)

        # Prepare balance for Tau (capped 0-15 for 4 bits)
        sender_balance_for_tau = min(actual_sender_balance, 15) 

        try:
            # Encoding will fail here if amount_decimal_str is not valid for decimal_to_4bit_binary (e.g. >15, non-numeric)
            sbf_input = _encode_single_transfer_sbf(transfer_entry, sender_balance_for_tau)
            sbf_output = tau_manager.communicate_with_tau(sbf_input)
            is_valid_in_tau = _decode_single_transfer_output(sbf_output, sbf_input)

            if not is_valid_in_tau:
                 print(f"  [ERROR][sendtx] Transfer #{i+1} rejected by Tau.")
                 # The specific reason for Tau rejection is printed by _decode_single_transfer_output
                 return f"FAILURE: Transaction invalid. Transfer #{i+1} ({transfer_entry}) rejected by Tau logic."
            
            # If Tau validation is also successful, this transfer is provisionally OK.
            # We don't update balances yet, only after all transfers in the TX are validated.
            validated_transfers_for_mempool.append((from_addr_key, to_addr_key, amount_int))

        except ValueError as e: # Catch encoding errors, yID errors etc.
            print(f"  [ERROR][sendtx] Error processing transfer #{i+1} for Tau validation: {e}")
            return f"ERROR: Could not process transfer #{i+1}: {e}"
        except Exception as e:
            print(f"  [ERROR][sendtx] Unexpected error during Tau validation for transfer #{i+1}: {e}")
            return f"ERROR: Could not validate transaction with Tau: {e}"

    # If all transfers passed all validations (Python pre-check + Tau)
    # Now, commit all balance changes for this transaction
    print(f"  [INFO][sendtx] All {len(transfers)} transfers validated. Committing balance changes.")
    for from_addr, to_addr, amt in validated_transfers_for_mempool:
        if not chain_state.update_balances_after_transfer(from_addr, to_addr, amt):
            # This should ideally not happen if all prior checks were correct
            print(f"  [CRITICAL][sendtx] Balance update failed for a validated transfer: {from_addr} to {to_addr} for {amt}. Halting TX.")
            return f"FAILURE: Critical error during balance update for an already validated transfer."
    
    # All checks passed, all balances updated, now add to mempool
    db.add_mempool_tx(blob) 
    print(f"  [INFO][sendtx] Queued transaction in mempool: {blob[:100]}...")
    return f"SUCCESS: Transaction queued."