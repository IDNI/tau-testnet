import hashlib
import json
import logging
import os
import time

import chain_state
import db
import tau_defs
import tau_manager
import utils
from db import add_mempool_tx
from network import bus as network_bus


logger = logging.getLogger(__name__)


def _canonicalize_transaction(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _compute_transaction_message_id(payload: dict) -> tuple[str, str]:
    canonical = _canonicalize_transaction(payload)
    tx_hash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return tx_hash, canonical

_PY_ECC_AVAILABLE = False
_PY_ECC_BLS = None
try:
    import py_ecc.bls as _bls_mod
    from py_ecc.bls import G2Basic
    _PY_ECC_BLS = _bls_mod
    _PY_ECC_AVAILABLE = True
    logger.info("py_ecc.bls module loaded. BLS public key validation enabled.")
except ModuleNotFoundError:
    logger.warning(
        "py_ecc.bls module not found. BLS public key validation will be skipped; only format checks run."
    )
except Exception as e:
    logger.warning("Error importing py_ecc.bls (%s). Skipping BLS public key validation.", e)


def _validate_bls12_381_pubkey(key_hex: str, key_name: str) -> tuple[bool, str | None]:
    """
    Validates a 48-byte BLS12-381 public key.
    Checks for 96-character hex format and, if py_ecc is available, cryptographic validity.
    Args:
        key_hex: The public key as a hexadecimal string.
        key_name: Descriptive name for the key (e.g., "sender_pubkey") for error messages.
    Returns:
        A tuple (is_valid, error_message). error_message is None if is_valid is True.
    """
    if not (isinstance(key_hex, str) and len(key_hex) == 96):
        return False, f"Invalid {key_name}: Must be a 96-character hex string representing 48 bytes, got length {len(key_hex)}."

    try:
        key_bytes = bytes.fromhex(key_hex)
        if len(key_bytes) != 48:
             return False, f"Invalid {key_name}: Hex string decodes to {len(key_bytes)} bytes, expected 48."
    except ValueError:
        return False, f"Invalid {key_name}: Not a valid hexadecimal string."

    if not all(c in '0123456789abcdefABCDEF' for c in key_hex):
        return False, f"Invalid {key_name}: Contains non-hexadecimal characters."

    if _PY_ECC_AVAILABLE:
        try:
            G2Basic.KeyValidate(key_bytes)
        except Exception as e:
            return False, f"Invalid {key_name} (cryptographic validation failed): {e}. Key: {key_hex[:10]}..."

    return True, None


def _parse_bitvector_string(bv_str: str) -> int:
    """Helper to parse a bitvector string from Tau's output (#b, #x, or decimal)."""
    bv_str = bv_str.strip()
    if bv_str.startswith('#b'):
        return int(bv_str[2:], 2)
    elif bv_str.startswith('#x'):
        return int(bv_str[2:], 16)
    else:
        return int(bv_str)


def _prepare_transfer_inputs(transfer_entry, sender_balance: int) -> dict:
    """
    Prepares a dictionary of integer inputs for a single transfer for Tau validation.
    Amounts and balances can be large (up to 32 bytes).
    """
    if not (isinstance(transfer_entry, (list, tuple)) and len(transfer_entry) == 3):
        raise ValueError(f"Invalid transfer entry format: {transfer_entry}")
    from_addr_key, to_addr_key, amount_decimal_str = map(str, transfer_entry)

    # Basic inline format check to catch obvious errors even if cryptographic
    # validation is patched in tests
    hex_chars = set('0123456789abcdefABCDEF')
    if not (isinstance(from_addr_key, str) and len(from_addr_key) == 96 and all(c in hex_chars for c in from_addr_key)):
        raise ValueError("Invalid 'from' address: Must be a 96-character hex BLS12-381 public key")
    if not (isinstance(to_addr_key, str) and len(to_addr_key) == 96 and all(c in hex_chars for c in to_addr_key)):
        raise ValueError("Invalid 'to' address: Must be a 96-character hex BLS12-381 public key")

    is_valid_from, err_from = _validate_bls12_381_pubkey(from_addr_key, "'from' address")
    if not is_valid_from:
        raise ValueError(err_from)
    is_valid_to, err_to = _validate_bls12_381_pubkey(to_addr_key, "'to' address")
    if not is_valid_to:
        raise ValueError(err_to)

    from_yid = db.get_string_id(from_addr_key)
    to_yid = db.get_string_id(to_addr_key)
    
    try:
        from_id = int(from_yid[1:])
        to_id = int(to_yid[1:])
    except (ValueError, IndexError):
        raise ValueError(f"Could not parse numeric ID from yID '{from_yid}' or '{to_yid}'")

    try:
        # Amount is now a 32-byte (256-bit) integer, represented as a string.
        amount = int(amount_decimal_str)
        if not (0 <= amount < (1 << 256)):
            raise ValueError("Amount must be a positive 256-bit integer.")
    except ValueError:
        raise ValueError(f"Invalid amount: '{amount_decimal_str}' is not a valid large integer.")

    if not isinstance(sender_balance, int) or sender_balance < 0:
        raise ValueError(f"Invalid sender balance: {sender_balance}")

    return {
        'amount': amount,
        'balance': sender_balance,
        'from_id': from_id,
        'to_id': to_id,
    }


def _decode_single_transfer_output(output_bv_str: str, expected_amount_int: int) -> bool:
    """
    Tau emits the original transfer amount on success and 0 on failure.
    """
    output_bv_str = output_bv_str.strip()
    if not output_bv_str:
        logger.warning("Received empty output from Tau.")
        return False

    try:
        output_val = _parse_bitvector_string(output_bv_str)
    except ValueError:
        logger.warning("Unexpected Tau output format: '%s'", output_bv_str)
        return False

    if output_val == 0:
        logger.debug("Tau rejected transfer (output was 0).")
        return False

    if output_val == expected_amount_int:
        logger.debug("Tau accepted transfer; echoed input amount.")
        return True

    logger.warning(
        "Unexpected Tau output value: '%s' (parsed as %s), expected %s",
        output_bv_str,
        output_val,
        expected_amount_int,
    )
    return False


def _get_signing_message_bytes(payload: dict) -> bytes:
    """
    Construct canonical bytes over transaction fields for BLS signing/verifying.
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
    result_data contains the validated transfers and their prepared Tau inputs.
    """
    if not isinstance(transfers, list):
        return False, None, "Transfers (key '1') must be a list."
    
    if not transfers:
        return True, {"transfers": [], "tau_inputs": []}, None
    
    validated_transfers = []
    tau_inputs = []
    remaining_balances: dict[str, int] = {}
    
    logger.info("Processing %s transfers...", len(transfers))
    for i, transfer_entry in enumerate(transfers):
        logger.debug("Processing transfer #%s: %s", i + 1, transfer_entry)
        if not (isinstance(transfer_entry, (list, tuple)) and len(transfer_entry) == 3):
            return False, None, f"Transfer #{i+1} has invalid format: {transfer_entry}"
            
        from_addr_key, to_addr_key, amount_decimal_str = map(str, transfer_entry)

        if from_addr_key != sender_pubkey:
            return False, None, f"Transfer #{i+1} 'from' address does not match sender_pubkey."

        if from_addr_key not in remaining_balances:
            remaining_balances[from_addr_key] = chain_state.get_balance(from_addr_key)
        available_balance = remaining_balances[from_addr_key]
        
        try:
            transfer_input_dict = _prepare_transfer_inputs(transfer_entry, available_balance)
            # Store the full integer amount for post-validation balance updates
            amount_int = transfer_input_dict['amount']
            validated_transfers.append((from_addr_key, to_addr_key, amount_int))
            tau_inputs.append(transfer_input_dict)
            remaining_balances[from_addr_key] = max(available_balance - amount_int, 0)
        except ValueError as e:
            return False, None, f"Error processing transfer #{i+1}: {e}"
        except Exception as e:
            return False, None, f"Unexpected error during transfer #{i+1} processing: {e}"

    return True, {"transfers": validated_transfers, "tau_inputs": tau_inputs}, None


def queue_transaction(json_blob: str, propagate: bool = True) -> str:
    blob = json_blob.strip()
    if len(blob) >= 2 and ((blob[0] == '"' and blob[-1] == '"') or (blob[0] == "'" and blob[-1] == "'")):
        blob = blob[1:-1]
    try:
        payload = json.loads(blob)
    except Exception as e:
        raise ValueError(f"Invalid JSON payload: {e}")
    if not isinstance(payload, dict):
        raise ValueError("Transaction must be a JSON object.")

    # --- Structural and Cryptographic Validation ---
    if 'sender_pubkey' not in payload:
        raise ValueError("Missing 'sender_pubkey' in transaction.")
    sender_pubkey = payload['sender_pubkey']
    is_valid_sender, err_sender = _validate_bls12_381_pubkey(sender_pubkey, "sender_pubkey")
    if not is_valid_sender:
        return f"FAILURE: Transaction invalid. {err_sender}"

    if 'sequence_number' not in payload:
        raise ValueError("Missing 'sequence_number' in transaction.")
    if not isinstance(payload.get('sequence_number'), int):
        raise ValueError("Missing or invalid 'sequence_number' in transaction.")
    sequence_number = payload['sequence_number']

    if 'expiration_time' not in payload or not isinstance(payload.get('expiration_time'), int):
        raise ValueError("Missing or invalid 'expiration_time' in transaction.")
    expiration_time = payload['expiration_time']
    current_time = int(time.time())
    if current_time > expiration_time:
        return f"FAILURE: Transaction expired at {expiration_time}. Current time is {current_time}."

    if 'operations' not in payload or not isinstance(payload['operations'], dict):
        raise ValueError("Missing or invalid 'operations' in transaction.")
    operations = payload['operations']
    
    if 'fee_limit' not in payload:
        raise ValueError("Missing 'fee_limit' in transaction.")

    if 'signature' not in payload:
        raise ValueError("Missing 'signature' in transaction.")
    if not isinstance(payload.get('signature'), str):
        raise ValueError("Missing or invalid 'signature' in transaction.")
    signature = payload['signature']

    if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
        msg_bytes = _get_signing_message_bytes(payload)
        msg_hash = hashlib.sha256(msg_bytes).digest()
        try:
            sig_bytes = bytes.fromhex(signature)
            pubkey_bytes = bytes.fromhex(sender_pubkey)
            if not G2Basic.Verify(pubkey_bytes, msg_hash, sig_bytes):
                return "FAILURE: Invalid signature."
        except Exception as e:
            return f"FAILURE: Invalid signature format or cryptographic error: {e}"
        
        expected_seq = chain_state.get_sequence_number(sender_pubkey)
        if sequence_number != expected_seq:
            return f"FAILURE: Invalid sequence number: expected {expected_seq}, got {sequence_number}."
    else:
        logger.warning("BLS crypto not available; skipping signature verification and sequence enforcement.")

    all_validated_transfers = []
    transfer_tau_inputs = []
    has_transfers = "1" in operations
    has_rules = "0" in operations
    empty_transfer_list = False

    if has_transfers:
        transfers_list = operations["1"]
        if not transfers_list:
            empty_transfer_list = True
        else:
            success, transfer_result, err_msg = _process_transfers_operation(transfers_list, sender_pubkey)
            if not success:
                return f"FAILURE: Transaction invalid. {err_msg}"
            all_validated_transfers = transfer_result["transfers"]
            transfer_tau_inputs = transfer_result["tau_inputs"]

    tau_force_test = os.environ.get("TAU_FORCE_TEST", "0") == "1"

    try:
        # --- Tau Validation Step ---
        if has_rules:
            rule_text = operations.get("0", "").strip()
            if rule_text:
                if tau_force_test:
                    logger.info("TAU_FORCE_TEST=1: skipping Tau rule validation.")
                else:
                    logger.info("Validating rule with Tau: '%s...'", rule_text[:50])
                    tau_output_rules = tau_manager.communicate_with_tau(
                        rule_text=rule_text, target_output_stream_index=0
                    )
                    if "Error" in tau_output_rules:
                        return f"FAILURE: Transaction rejected by Tau (rule validation). Output: {tau_output_rules}"
                    logger.info("Tau rule validation successful.")

        if has_transfers and all_validated_transfers:
            if tau_force_test:
                logger.info(
                    "TAU_FORCE_TEST=1: skipping Tau transfer validation for %s transfers.",
                    len(all_validated_transfers),
                )
            else:
                logger.info("Validating %s transfers with Tau...", len(all_validated_transfers))
                for i, (tau_input_dict, transfer_details) in enumerate(
                    zip(transfer_tau_inputs, all_validated_transfers)
                ):
                    logger.debug("Validating transfer #%s: %s", i + 1, transfer_details)

                    # Tau program expects inputs on separate streams for the single-pass validation
                    # i1: amount, i2: balance, i3: from_id, i4: to_id
                    tau_input_stream_values = {
                        1: str(tau_input_dict['amount']),
                        2: str(tau_input_dict['balance']),
                        3: str(tau_input_dict['from_id']),
                        4: str(tau_input_dict['to_id']),
                    }

                    logger.info(
                        "Sending Tau inputs for transfer #%s validation: %s",
                        i + 1,
                        tau_input_stream_values,
                    )
                    tau_output_transfer = tau_manager.communicate_with_tau(
                        target_output_stream_index=1,
                        input_stream_values=tau_input_stream_values,
                    )

                    expected_amount = transfer_details[2]
                    if not _decode_single_transfer_output(tau_output_transfer, expected_amount):
                        return (
                            f"FAILURE: Transaction rejected by Tau logic for transfer #{i+1} "
                            f"({transfer_details}). Tau output: {tau_output_transfer}"
                        )
                logger.info("All Tau transfer validations successful.")
        
        # --- Post-Tau Processing ---
        if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
            chain_state.increment_sequence_number(sender_pubkey)

        if all_validated_transfers:
            logger.info(
                "Applying balance changes for %s validated transfers...",
                len(all_validated_transfers),
            )
            for from_addr, to_addr, amt in all_validated_transfers:
                if not chain_state.update_balances_after_transfer(from_addr, to_addr, amt):
                    return (
                        "FAILURE: Transaction invalid. "
                        f"Could not apply transfer ({from_addr[:10]}... -> {to_addr[:10]}..., amount {amt})."
                    )

        tx_message_id, tx_canonical_blob = _compute_transaction_message_id(payload)
        db.add_mempool_tx(blob)
        logger.info("Transaction successfully queued in mempool.")
        if propagate:
            svc = network_bus.get()
            if svc:
                svc.broadcast_transaction(tx_canonical_blob, tx_message_id)
        if empty_transfer_list:
            return "SUCCESS: Transaction queued (empty transfer list)."
        return "SUCCESS: Transaction queued."

    except ValueError as e:
        return f"ERROR: Could not process transaction. {e}"
    except Exception as e:
        logger.critical("An unexpected error occurred in queue_transaction: %s", e)
        return f"FAILURE: An unexpected server error occurred."


def execute(raw_command: str, container):
    """
    Executes the sendtx command.
    Expected format: sendtx <json_payload>
    """
    prefix = 'sendtx '
    if not raw_command.lower().startswith(prefix):
        return "ERROR: Invalid sendtx format. Use sendtx '{\"0\":...}'.\r\n"
    
    json_blob = raw_command[len(prefix):].strip()
    logger.debug("Received sendtx payload: %s", json_blob)
    
    try:
        result_msg = queue_transaction(json_blob)
    except Exception as exc:
        logger.exception("sendtx queue failed")
        result_msg = f"ERROR: {exc}"
    
    return result_msg + "\r\n"
