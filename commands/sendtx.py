import utils
import sbf_defs
import tau_manager
from db import add_mempool_tx
import json
import db
import chain_state

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
    into a 22-bit SBF atom.
    from_pubkey and to_pubkey are BLS12-381 public key hex strings.
    amount is decimal string, sender_balance_for_tau is an int (0-255).
    The SBF pattern is: from(3) + to(3) + amount(8) + sender_balance(8).
    """
    if not (isinstance(transfer_entry, (list, tuple)) and len(transfer_entry) == 3):
        raise ValueError(f"Invalid transfer entry format: {transfer_entry}")
    from_addr_key, to_addr_key, amount_decimal_str = map(str, transfer_entry)

    # Helper to validate BLS key, get yID, and convert its numeric part to 3 bits
    def get_address_bits(addr_key_hex, addr_name):
        if not (isinstance(addr_key_hex, str) and len(addr_key_hex) == 96 and all(c in '0123456789abcdef' for c in addr_key_hex.lower())):
            raise ValueError(f"Invalid '{addr_name}' address: Must be a 96-character hex BLS12-381 public key: {addr_key_hex}")
        yid = db.get_string_id(addr_key_hex)
        try:
            id_num = int(yid[1:])
            bits = format((id_num - 1) % 8, '03b') 
            # print(f"  [INFO][sendtx] Mapped '{addr_name}' BLS key {addr_key_hex[:10]}... to yID {yid}, bits {bits}") # Less verbose
        except ValueError:
            raise ValueError(f"Could not parse numeric ID from yID '{yid}' for '{addr_name}' address ({addr_key_hex[:10]}...)")
        return bits

    from_bits = get_address_bits(from_addr_key, "from")
    to_bits = get_address_bits(to_addr_key, "to")

    try:
        amount_binary = utils.decimal_to_8bit_binary(amount_decimal_str)
    except ValueError as e:
        raise e 

    try:
        # Ensure sender_balance_for_tau is within 0-255 for 8-bit representation
        if not (0 <= sender_balance_for_tau <= 255):
            # This should ideally be caught before calling, but as a safeguard:
            raise ValueError(f"sender_balance_for_tau must be between 0 and 255, got {sender_balance_for_tau}")
        balance_binary = format(sender_balance_for_tau, '08b')
    except ValueError as e: # Should not happen if input is int, but good practice
        raise ValueError(f"Could not convert sender_balance_for_tau '{sender_balance_for_tau}' to 8-bit binary: {e}")

    # Construct the 22-bit pattern: from(3) + to(3) + amount(8) + balance(8)
    full_bit_pattern = from_bits + to_bits + amount_binary + balance_binary
    if len(full_bit_pattern) != 22: 
        raise AssertionError(f"Internal error: Generated bit pattern length is {len(full_bit_pattern)}, expected 22.")

    sbf_atom = utils.bits_to_sbf_atom(full_bit_pattern, length=22)
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

    if '1' not in payload:
        # If no transfers, consider it valid for queuing (other ops might be present)
        # Or, require '1' if it's purely a transfer-focused transaction type.
        # For now, allowing it to pass if '1' is missing.
        print("  [INFO][sendtx] No transfers (key '1') in payload. Queuing as is.")
        db.add_mempool_tx(blob)
        return f"SUCCESS: Transaction queued (no transfers to validate via Tau)."

    transfers = payload['1']
    if not isinstance(transfers, list):
        raise ValueError("Transfers (key '1') must be a list.")
    if not transfers: # Empty list of transfers
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
            # If amount_decimal_str is not even an integer, _encode_single_transfer_sbf will fail at decimal_to_8bit_binary.
            print(f"  [ERROR][sendtx] Transfer #{i+1} has non-integer amount '{amount_decimal_str}'. Encoding will likely fail.")
            # Let it proceed to encoding, which will raise an error if invalid format for 8-bit conversion.
            pass # Allow to proceed to encoding attempt

        actual_sender_balance = chain_state.get_balance(from_addr_key)

        # Prepare balance for Tau (capped 0-255)
        sender_balance_for_tau = min(actual_sender_balance, 255) 

        try:
            # Encoding will fail here if amount_decimal_str is not valid for decimal_to_8bit_binary (e.g. >255, non-numeric)
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