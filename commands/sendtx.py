import hashlib
import json
import logging
import os
import time


import config
import chain_state
import db
import tau_admission
import tau_defs
import tau_manager
from tau_manager import parse_tau_output
import utils
from errors import TauCommunicationError
from consensus import fees
from consensus.fees import FeeRuleError
from consensus.lanes import classify_lane
from consensus.tx_signing import signing_message_bytes, verify_tx_signature
from consensus.rule_offers import (
    TX_TYPE_RULE_OFFER,
    TX_TYPE_RULE_OFFER_ACCEPT,
    TX_TYPE_RULE_OFFER_REJECT,
    RULE_OFFER_TX_TYPES,
)
from consensus.approvals import (
    APPROVAL_TX_TYPES,
    approval_slots_active,
    TX_TYPE_APPROVAL_REQUEST,
    TX_TYPE_TRANSFER_VOTE,
)

# Every transaction type the node will admit. Governance types are fee-exempt
# so validators never need funds to govern; the rule-sharing types are
# user-initiated and expensive, so they pay like a user_tx does.
KNOWN_TX_TYPES = frozenset(
    {"user_tx", "consensus_rule_update", "consensus_rule_vote"}
    | set(RULE_OFFER_TX_TYPES)
    | set(APPROVAL_TX_TYPES)
)
# `approval_request` pays: it parks a transfer and is the ONLY charge for it, so
# execution later is free and there is no second fee to drift. `transfer_vote` is
# exempt like a governance vote -- approver bots would otherwise all need funding
# and a fee strategy, and the vote is bounded by the request's declared approver
# set instead.
FEE_BEARING_TX_TYPES = frozenset(
    {"user_tx", TX_TYPE_APPROVAL_REQUEST} | set(RULE_OFFER_TX_TYPES)
)
from db import add_mempool_tx
from network import bus as network_bus
import api_response


logger = logging.getLogger(__name__)


def _qt_ok(tx_hash: str, message: str = "Transaction queued.", **extra) -> dict:
    out = {"ok": True, "tx_hash": tx_hash, "message": message}
    out.update(extra)
    return out


def _qt_err(code: str, message: str, **details) -> dict:
    out = {"ok": False, "code": code, "message": message}
    if details:
        out["details"] = details
    return out

# Matches the width the shipped rules actually declare for i1/i2 (bv[24]), not
# the 64 the host used to check against — a value in between was accepted here
# and then truncated mod 2^24 inside Tau. See tau_defs.TRANSFER_VALUE_BV_WIDTH.
_MAX_TAU_BV_VALUE = tau_defs.MAX_TRANSFER_VALUE


def _admission_i2(address: str) -> str:
    """i2 (sender balance) for the admission-time Tau steps.

    The head balance, clamped to the width the rules declare. Mirrors
    consensus.engine's parent-snapshot `_parent_bal` so admission and apply feed
    the same shape; admission's value is an estimate (the tx may be included
    several blocks later), exactly like the advisory i5 timestamp.
    """
    try:
        value = int(chain_state.get_balance(address))
    except (TypeError, ValueError):
        value = 0
    return str(max(0, min(value, tau_defs.MAX_TRANSFER_VALUE)))


def _validate_tau_bv_range(value: int, name: str) -> None:
    if value < 0 or value > _MAX_TAU_BV_VALUE:
        raise ValueError(
            f"{name} exceeds Tau bitvector width {tau_defs.TRANSFER_VALUE_BV_WIDTH} "
            f"(max {_MAX_TAU_BV_VALUE})."
        )


def _canonicalize_transaction(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def _compute_transaction_message_id(payload: dict) -> tuple[str, str]:
    # Keep mempool tx_hash aligned with block hashing (see block.compute_tx_hash).
    import block as block_module

    canonical = _canonicalize_transaction(payload)
    tx_hash = block_module.compute_tx_hash(payload)
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

    # i3/i4 now carry the FULL 384-bit pubkey (lowercase hex). The bv-shrink layer
    # interns equality-only address streams to a small bv automatically -- no
    # hand-rolled id interning here. (Rule 02 declares i3/i4 as bv[384].)
    from_addr_hex = from_addr_key.lower()
    to_addr_hex = to_addr_key.lower()

    try:
        # Amount is now a 32-byte (256-bit) integer, represented as a string.
        amount = int(amount_decimal_str)
        if not (0 <= amount < (1 << 256)):
            raise ValueError("Amount must be a positive 256-bit integer.")
    except ValueError:
        raise ValueError(f"Invalid amount: '{amount_decimal_str}' is not a valid large integer.")
    _validate_tau_bv_range(amount, "Amount")

    if not isinstance(sender_balance, int) or sender_balance < 0:
        raise ValueError(f"Invalid sender balance: {sender_balance}")
    _validate_tau_bv_range(sender_balance, "Sender balance")

    return {
        'amount': amount,
        'balance': sender_balance,
        'from_addr': from_addr_hex,
        'to_addr': to_addr_hex,
    }


def _decode_single_transfer_output(output_bv_str: str, expected_amount_int: int) -> bool:
    """
    Tau emits the original transfer amount on success and 0 on failure.
    Uses unified parsing helper.
    """
    try:
        output_val = parse_tau_output(output_bv_str)
    except Exception as e:
        logger.warning("Error parsing Tau output '%s': %s", output_bv_str, e)
        return False

    if output_val == 0:
        logger.debug("Tau rejected transfer (output was 0).")
        return False

    # Accept either explicit amount echo OR generic success flag (1)
    if output_val == expected_amount_int or output_val == 1:
        logger.debug("Tau accepted transfer (output=%s).", output_val)
        return True

    logger.warning(
        "Unexpected Tau output value: '%s' (parsed as %s), expected %s or 1",
        output_bv_str,
        output_val,
        expected_amount_int,
    )
    return False


def _approval_slot_feed(tip_view) -> tuple:
    """Approval slot indices to feed, or empty while the feature is inactive.

    Feeding them only when active keeps a pre-activation node byte-identical:
    nothing references the slots, so nothing is fed, so no evaluation changes.
    """
    if not approval_slots_active(tip_view):
        return ()
    return tau_defs.approval_slot_indices()


def _get_signing_message_bytes(payload: dict) -> bytes:
    """Canonical signing preimage. Kept as a module-level name because wallets,
    the CLI and a dozen tests import it from here; the implementation is
    `consensus.tx_signing.signing_message_bytes`, shared with block apply so the
    two paths cannot drift.
    """
    return signing_message_bytes(payload)


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
        logger.debug("Available balance for %s: %s", from_addr_key, available_balance)
        try:
            transfer_input_dict = _prepare_transfer_inputs(transfer_entry, available_balance)
            logger.debug("Transfer input dictionary: %s", transfer_input_dict)
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




def _test_mode_was_requested() -> bool:
    """True only when test/mock mode was asked for, not when it was fallen back to.

    `tau_manager` flips `tau_test_mode` on when the native interface fails to
    build, so reading that flag alone would turn a broken production node into a
    node that silently stops validating.
    """
    import os as _os
    if str(_os.environ.get("TAU_FORCE_TEST", "")).strip() in ("1", "true", "True"):
        return True
    if str(_os.environ.get("TAU_ENV", "")).strip() == "test":
        return True
    try:
        import config as _config
        env = getattr(getattr(_config, "settings", None), "env", None)
        if env == "test":
            return True
    except Exception:
        pass
    return False


def _genesis_baseline():
    """The context a FIRST rule is validated against, when nothing has accumulated.

    An empty baseline used to skip the check entirely, which is precisely the
    wrapper regression of validating nothing when there is nothing to validate
    against: the first rule on a fresh chain is the one least likely to have been
    seen before.
    """
    import os as _os
    try:
        import chain_state
        prior = chain_state.get_rules_state()
        if prior and str(prior).strip():
            return str(prior)
    except Exception:
        pass
    try:
        here = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
        with open(_os.path.join(here, "genesis.tau")) as fh:
            router = fh.read().strip()
        return f"always ( {router} )." if router else None
    except Exception:
        return None


def _preflight_prepared_rule(rule_text: str):
    """Validate the PREPARED rule against the live runtime baseline.

    Returns an error envelope to return to the caller, or None to continue.

    Admission stays node-local policy here: this can only reject a transaction
    that apply would have refused anyway, turning "admitted, then silently never
    applied" into a reason at submit time. It never admits anything new, and an
    operational failure is never reported as a rule rejection.
    """
    try:
        import tau_manager
        import tau_preflight
    except Exception:  # pragma: no cover - import-time environment problem
        return None

    # Applicability is narrow on purpose. Only an EXPLICIT request for test mode
    # means "no native evaluator is expected here"; a production node that wanted
    # native and has none is operationally unavailable, not exempt. And an empty
    # baseline is not a reason to skip: the first rule on a fresh chain is exactly
    # the one nobody has validated yet. It is validated against the genesis
    # context instead.
    if _test_mode_was_requested():
        return None
    if getattr(tau_manager, "tau_direct_interface", None) is None:
        logger.warning("Rule preflight: native evaluator expected but unavailable")
        return _qt_err(
            "ADMISSION_UNAVAILABLE",
            "Rule validation is temporarily unavailable; please resubmit.",
        )

    try:
        prepared = tau_manager._prepare_rule_for_tau(rule_text)
    except Exception as exc:
        # ShrinkTypeConflict and friends: this process cannot represent the rule.
        # Node-local, so reject with a distinct code rather than TX_REJECTED.
        logger.warning("Rule cannot be represented in this process: %s", exc)
        return _qt_err(
            "ADMISSION_UNAVAILABLE",
            f"This node cannot currently represent that rule: {exc}",
        )
    if prepared is None:
        return None

    # The interpreter's own composed spec -- deliberately the RUNTIME form, since
    # that is the representation the prepared rule has to be compatible with.
    baseline = tau_manager.last_known_tau_spec
    if not baseline:
        baseline = _genesis_baseline()
    if not baseline:
        logger.warning("Rule preflight: no baseline available to validate against")
        return _qt_err(
            "ADMISSION_UNAVAILABLE",
            "Rule validation is temporarily unavailable; please resubmit.",
        )

    result = tau_preflight.preflight_rule(
        baseline,
        prepared.runtime_text,
        context=tau_preflight.capture_context(
            tau_manager.get_evaluator_state(), mapping_epoch=None
        ),
    )
    if result.verdict == tau_preflight.REJECT:
        logger.warning("Rule preflight rejected the prepared text: %s", result.detail)
        return _qt_err(
            "TX_REJECTED",
            f"Transaction rejected by Tau (rule preflight). {result.detail}",
        )
    if result.verdict == tau_preflight.UNAVAILABLE:
        # "Could not validate" is not "validated". It is also not "invalid rule":
        # the caller gets a distinct operational code and can resubmit, and the
        # author is not blamed for a worker that would not spawn or a diagnostic
        # capture that could not be read. Returning the previous successful-looking
        # verdict instead would let an unvalidated rule into the mempool while
        # reporting that it passed.
        logger.warning("Rule preflight unavailable: %s", result.detail)
        return _qt_err(
            "ADMISSION_UNAVAILABLE",
            "Rule validation is temporarily unavailable; please resubmit.",
        )
    return None


def _admission_timestamp() -> int:
    """Advisory block timestamp for i5 at admission.

    Apply re-checks against the AUTHORITATIVE block timestamp, so this is a soft
    pre-check only: a tx may pass admission yet be rejected at inclusion near a
    time threshold (and vice versa). The chain tip's timestamp (deterministic
    across this node's view, no wall-clock skew); wall clock if unavailable.
    """
    try:
        head = db.get_canonical_head_block()
        if isinstance(head, dict):
            header = head.get("header")
            if isinstance(header, dict) and header.get("timestamp") is not None:
                return int(header.get("timestamp"))
    except Exception:
        pass
    return int(time.time())


class _AdmissionTau:
    """Where ONE request's Tau steps run.

    With worker-backed authority: a context of this request's own, rebuilt from
    the committed journal and disposed of when the request returns. Nothing one
    submission feeds can become the history another is judged against, and no
    address this request mentions is interned into the committed mapping.

    Otherwise -- mock and unit-test configurations, where no native evaluator
    holds a history worth protecting -- the in-process path, unchanged.

    The context is opened lazily: a request that never reaches a Tau step never
    pays for a replay.
    """

    def __init__(self, *, candidate_rules=()):
        import tau_admission
        self.isolated = tau_admission.enabled()
        self.budget = tau_admission.default_budget()
        self._candidates = tuple(c for c in candidate_rules if c)
        self._context = None

    def _ctx(self):
        if self._context is None:
            import tau_admission
            self._context = tau_admission.open_context(
                candidate_rules=self._candidates, budget=self.budget,
                label="admission",
            )
        return self._context

    def revise(self, rule_text: str) -> dict:
        return self._ctx().revise(rule_text)

    def step_multi(self, inputs: dict, *, source: str) -> dict:
        if not self.isolated:
            return tau_manager.communicate_with_tau_multi(
                input_stream_values=inputs, source=source, apply_rules_update=False,
            )
        return self._ctx().step(inputs)

    def close(self) -> None:
        context, self._context = self._context, None
        if context is not None:
            context.dispose()


def _routed_o5_composite(tip_view, sender_pubkey: str, action: str, body: str):
    """The o5 composite apply feeds for a routed policy rule -- not the rule.

    A routed rule never enters the specification as written: apply registers
    (or revokes) the sender's clause and feeds the regenerated composite, the
    neutral one when the registry ends up empty. Validating the raw text instead
    would admit or refuse something apply never runs.
    """
    from consensus.rule_offers import NEUTRAL_O5_CLAUSE_BODY, compose_stream_rule

    stream = tau_defs.USER_POLICY_STREAM_INDEX
    clauses = dict(tip_view.clauses_for_stream(stream))
    key = str(sender_pubkey or "").lower()
    if action == "revoke":
        clauses.pop(key, None)
    else:
        clauses[key] = body
    composite = compose_stream_rule(stream, clauses) if clauses else None
    return composite or "always ( %s )." % NEUTRAL_O5_CLAUSE_BODY


def _revision_refusal(receipt: dict):
    """The rejection envelope for a revision the context did not accept, or None.

    Every non-accepted outcome refuses, because apply refuses every one of them:
    an unsatisfiable rule evaluated into the no-revision branch used to be
    admitted here and then rejected at inclusion -- `sendtx` and the block
    disagreeing is exactly the failure this path exists to remove.
    """
    if receipt.get("accepted"):
        return None
    outcome = receipt.get("outcome") or "NOT_ACCEPTED"
    detail = ""
    try:
        from tau_native import strip_ansi
    except Exception:  # pragma: no cover - the binding's helpers are optional here
        def strip_ansi(text):
            return text
    for key in ("diagnostics", "deferred_diagnostics"):
        for line in str(receipt.get(key) or "").splitlines():
            if "rror" in line:
                # the engine colours its diagnostics; a client gets plain text
                detail = strip_ansi(line).strip()
                break
        if detail:
            break
    return _qt_err(
        "TX_REJECTED",
        f"Transaction rejected by Tau (rule validation). {detail or outcome}",
        outcome=outcome,
    )


def queue_transaction(json_blob: str, propagate: bool = True, *,
                      dry_run: bool = False, skip_tau_eval: bool = False) -> dict:
    """Validate a transaction and (unless dry_run) queue it in the mempool.

    `dry_run` returns the verdict just before the two mutations
    (db.add_mempool_tx, broadcast_transaction), so checktx (#26) answers "would
    this be admitted?" with byte-identical codes and details to what sendtx would
    have produced. It is a flag on this function rather than an extracted pure
    copy deliberately: there are 34 distinct error returns and three outer
    exception handlers here, so verdict parity is worth guaranteeing by
    construction instead of by test.

    `skip_tau_eval` additionally skips Tau steps 2/3/3b. Those are NOT
    side-effect-free — they intern addresses into SQLite, advance the live
    interpreter's logical time by up to 100 steps per call (up to 64 transfers
    per tx), can rebuild the interpreter from stdout, and on intern-width
    overflow re-exec the process. An unauthenticated, fee-free RPC must not
    reach them. The rule-compile step is unaffected: it already runs in a
    SIGKILL-able subprocess and is genuinely pure.
    """
    blob = json_blob.strip()
    if len(blob) >= 2 and ((blob[0] == '"' and blob[-1] == '"') or (blob[0] == "'" and blob[-1] == "'")):
        blob = blob[1:-1]
    try:
        payload = json.loads(blob)
    except Exception as e:
        return _qt_err("PARSE_ERROR", f"Invalid JSON payload: {e}")
    if not isinstance(payload, dict):
        return _qt_err("INVALID_PARAMS", "Transaction must be a JSON object.")

    # --- Structural and Cryptographic Validation ---
    if 'sender_pubkey' not in payload:
        return _qt_err("INVALID_PARAMS", "Missing 'sender_pubkey' in transaction.")
    sender_pubkey = payload['sender_pubkey']
    is_valid_sender, err_sender = _validate_bls12_381_pubkey(sender_pubkey, "sender_pubkey")
    if not is_valid_sender:
        return _qt_err("TX_INVALID", f"Transaction invalid. {err_sender}")

    if 'sequence_number' not in payload:
        return _qt_err("INVALID_PARAMS", "Missing 'sequence_number' in transaction.")
    if not isinstance(payload.get('sequence_number'), int):
        return _qt_err("INVALID_PARAMS", "Missing or invalid 'sequence_number' in transaction.")
    sequence_number = payload['sequence_number']

    if 'expiration_time' not in payload or not isinstance(payload.get('expiration_time'), int):
        return _qt_err("INVALID_PARAMS", "Missing or invalid 'expiration_time' in transaction.")
    expiration_time = payload['expiration_time']
    current_time = int(time.time())
    if current_time > expiration_time:
        return _qt_err(
            "TX_EXPIRED",
            f"Transaction expired at {expiration_time}. Current time is {current_time}.",
            expires_at=expiration_time,
            current=current_time,
        )

    # The height deadline is checked in full against the tip by
    # consensus.admission.validate_expire_at_height; this is the structural
    # half, alongside the other shape checks, so a malformed field is refused
    # before any state is read.
    expire_at_height = payload.get('expire_at_height')
    if not isinstance(expire_at_height, int) or isinstance(expire_at_height, bool):
        return _qt_err(
            "INVALID_PARAMS",
            "Missing or invalid 'expire_at_height': every transaction must name "
            "the height at which it expires.",
        )
    if expire_at_height <= 0:
        return _qt_err("INVALID_PARAMS", "'expire_at_height' must be a positive block height.")

    if 'fee_limit' not in payload:
        return _qt_err("INVALID_PARAMS", "Missing 'fee_limit' in transaction.")
    # All tx types (governance included) must carry a syntactically valid
    # fee_limit; only user_tx is charged. The payload field itself is never
    # rewritten — the BLS signature covers the original representation.
    fee_limit_int = fees.parse_fee_limit(payload['fee_limit'])
    if fee_limit_int is None:
        return _qt_err(
            "INVALID_PARAMS",
            "Invalid 'fee_limit': must be a non-negative integer (int or decimal string) <= 2**63-1.",
            fee_limit=str(payload.get('fee_limit'))[:64],
        )

    tx_type = payload.get("tx_type", "user_tx")
    if tx_type not in KNOWN_TX_TYPES:
        return _qt_err(
            "TX_REJECTED",
            f"Unknown or legacy tx_type explicitly rejected natively: {tx_type}",
            tx_type=tx_type,
        )

    if tx_type == "user_tx":
        if 'operations' not in payload or not isinstance(payload['operations'], dict):
            return _qt_err("INVALID_PARAMS", "Missing or invalid 'operations' in user_tx.")

    if 'signature' not in payload:
        return _qt_err("INVALID_PARAMS", "Missing 'signature' in transaction.")
    if not isinstance(payload.get('signature'), str):
        return _qt_err("INVALID_PARAMS", "Missing or invalid 'signature' in transaction.")
    signature = payload['signature']

    if not (_PY_ECC_AVAILABLE and _PY_ECC_BLS):
        return _qt_err("BLS_UNAVAILABLE", "BLS signatures are required but py_ecc is missing.")

    # One verifier, shared with block apply (consensus/tx_signing.py). G2Basic is
    # read from this module's globals at call time so the many tests that
    # patch("commands.sendtx.G2Basic") keep working.
    sig_ok, sig_reason = verify_tx_signature(payload, g2=globals().get("G2Basic"))
    if not sig_ok:
        return _qt_err("INVALID_SIGNATURE", f"Invalid signature: {sig_reason}")

    expected_seq = chain_state.get_sequence_number(sender_pubkey)

    # Adjust expected sequence if the sender has pending transactions in the mempool
    pending_seq = db.get_pending_sequence(sender_pubkey)
    if pending_seq is not None and pending_seq >= expected_seq:
        expected_seq = pending_seq + 1

    if sequence_number != expected_seq:
        return _qt_err(
            "INVALID_SEQUENCE",
            f"Invalid sequence number: expected {expected_seq}, got {sequence_number}.",
            expected=expected_seq,
            received=sequence_number,
        )

    all_validated_transfers = []
    transfer_tau_inputs = []
    empty_transfer_list = False
    # Admission-time fee estimate: sum over Tau steps of (o9 consensus fee
    # + o8 user custom fee). Best-effort anti-spam — the engine re-derives
    # the fee authoritatively at block application.
    estimated_fee_total = 0
    
    # 1. Structural Dispatch & Thin Admission Validations
    from consensus.admission import validate_mempool_admission
    from consensus.facade import TipAdmissionView
    tip_view = TipAdmissionView()
    
    admission_eval = validate_mempool_admission(payload, tip_view)
    if not admission_eval.is_valid:
        # Forward the admission layer's own code/details when it set them;
        # everything else still collapses to TX_REJECTED as before (issue #23).
        return _qt_err(
            admission_eval.code or "TX_REJECTED",
            admission_eval.error,
            **admission_eval.details,
        )

    if tx_type == "user_tx":
        operations = payload.get("operations", {})
        has_transfers = "1" in operations
        has_rules = "0" in operations
    else:
        has_transfers = False
        has_rules = False

    if has_transfers:
        transfers_list = operations["1"]
        if not transfers_list:
            empty_transfer_list = True
        else:
            success, transfer_result, err_msg = _process_transfers_operation(transfers_list, sender_pubkey)
            logger.debug("Transfer result: %s", transfer_result)
            if not success:
                return _qt_err("TX_INVALID", f"Transaction invalid. {err_msg}")
            all_validated_transfers = transfer_result["transfers"]
            transfer_tau_inputs = transfer_result["tau_inputs"]

    # --- Custom Input Parsing ---
    custom_tau_inputs: dict[int, list[str]] = {}
    if tx_type == "user_tx":
        for key, value in operations.items():
            if key.isdigit():
                idx = int(key)
                if idx in (0, 1):
                    continue
                # Reject ALL reserved streams uniformly: i2-i5 are transfer
                # context / clock, i6-i11 are consensus ABI inputs the node injects,
                # i12 is the sender pubkey the node sets at apply, i14/i15 are the
                # consensus stake/mode inputs fed at consensus evaluation, and i13
                # joins them only under tau_validator_set (the one mode that feeds
                # it). Matches the authoritative gate
                # (admission.validate_user_tx_reserved_domains) and the apply-time
                # check (consensus/engine.py). User custom inputs
                # start at i13. i12/i14/i15 are screened explicitly (not via
                # RESERVED_STREAMS, a consensus-shared constant the engine reads
                # elsewhere) so a crafted operations["12"] cannot spoof the
                # sender-pubkey stream i12-scoped o5/o8 policy rules rely on, and
                # operations["14"/"15"] cannot pin a conflicting bv width process-wide.
                # i18-i25 join under approval-slot activation: only the node may
                # write a co-signature slot, or a sender forges their own approval.
                if idx in tau_defs.RESERVED_STREAMS \
                        or idx in tau_defs.reserved_operation_keys(
                            tip_view.eligibility_mode,
                            approval_slots_active=approval_slots_active(tip_view),
                        ):
                    return _qt_err(
                        "TX_INVALID",
                        f"Invalid operation key '{key}'. Stream {idx} is reserved.",
                        stream=idx,
                    )

                normalized_val = []
                if isinstance(value, (str, int)):
                    normalized_val.append(str(value))
                elif isinstance(value, (list, tuple)):
                    for v in value:
                        if isinstance(v, (str, int)):
                            normalized_val.append(str(v))
                        else:
                            return _qt_err(
                                "TX_INVALID",
                                f"Invalid value type for stream {idx}. List items must be str or int.",
                                stream=idx,
                            )
                else:
                    return _qt_err(
                        "TX_INVALID",
                        f"Invalid value type for stream {idx}. Must be str, int.",
                        stream=idx,
                    )

                custom_tau_inputs[idx] = normalized_val

    tau_force_test = tau_manager.is_force_test_enabled()

    # The revision this request would make, if any, known BEFORE its context is
    # built so the representation is planned for it (see tau_admission).
    admission_candidate = None
    try:
        if not tau_admission.enabled():
            pass
        elif tx_type == TX_TYPE_RULE_OFFER_ACCEPT:
            admission_candidate = (admission_eval.data or {}).get("composite_rule")
        elif tx_type == "user_tx" and has_rules:
            _rule_value = operations.get("0")
            if isinstance(_rule_value, str) and _rule_value.strip():
                _action = (admission_eval.data or {}).get("o5_clause_action")
                admission_candidate = (
                    _routed_o5_composite(
                        tip_view, sender_pubkey, _action,
                        (admission_eval.data or {}).get("o5_clause_body") or "",
                    )
                    if _action else _rule_value.strip()
                )
    except Exception as e:
        logger.exception("Could not derive the admission candidate: %s", e)
        return _qt_err("INTERNAL_ERROR", "An unexpected server error occurred.")
    admission_tau = _AdmissionTau(
        candidate_rules=(admission_candidate,) if admission_candidate else ()
    )

    try:
        if tx_type in (TX_TYPE_RULE_OFFER, TX_TYPE_RULE_OFFER_ACCEPT):
            # Compile the COMPOSED rule, not the offered clause on its own.
            # What actually enters the specification is the composite for the
            # target stream with this acceptor's clause folded in, so that is
            # the only text whose compilability tells us anything. Admission
            # already built it (see consensus/admission._compose_with_clause).
            composite_rule = (admission_eval.data or {}).get("composite_rule")
            if (composite_rule and not tau_force_test and admission_tau.isolated
                    and tx_type == TX_TYPE_RULE_OFFER_ACCEPT):
                # Accepting folds the clause into the stream's composite, and
                # apply feeds that composite to an evaluator carrying the
                # committed type history. Validate it there -- a fresh process
                # has none, and passes text the block then refuses.
                refusal = _revision_refusal(admission_tau.revise(composite_rule))
                if refusal is not None:
                    return refusal
                logger.info(
                    "Rule offer composite validated for o%s (admission context).",
                    (admission_eval.data or {}).get("target_stream"),
                )
            elif composite_rule and not tau_force_test:
                if tau_manager.tau_ready.is_set() and not getattr(
                    tau_manager, "tau_test_mode", False
                ):
                    import tau_native
                    try:
                        # Same killable-subprocess gate as the op-"0" path
                        # below, and for the same reason: the in-process
                        # compile can hang inside native Tau with no status
                        # stamp for the watchdog (issue #24). apply_block
                        # re-compiles deterministically, so a rare skip here
                        # cannot let an invalid rule take effect.
                        compile_err = tau_native.compile_revisions_isolated_subprocess(
                            chain_state.get_rules_state(),
                            [composite_rule],
                            timeout=config.COMM_TIMEOUT,
                        )
                    except tau_native.RuleCompileTimeout as compile_exc:
                        logger.warning(
                            "Rule offer compile timed out at admission: %s", compile_exc
                        )
                        return _qt_err(
                            "ADMISSION_TIMEOUT",
                            (
                                f"Rule validation timed out after "
                                f"{config.COMM_TIMEOUT}s and was rejected."
                            ),
                            timeout_seconds=config.COMM_TIMEOUT,
                        )
                    except tau_native.NativeTauUnavailable as compile_exc:
                        logger.warning(
                            "Isolated rule offer compile unavailable; rejecting: %s",
                            compile_exc,
                        )
                        return _qt_err(
                            "ADMISSION_UNAVAILABLE",
                            "Rule validation is temporarily unavailable; please resubmit.",
                        )
                    if compile_err:
                        return _qt_err(
                            "TX_REJECTED",
                            f"Transaction rejected by Tau (rule validation). {compile_err}",
                        )
                    logger.info(
                        "Rule offer composite validated for o%s (isolated compile).",
                        (admission_eval.data or {}).get("target_stream"),
                    )

        elif tx_type == "user_tx":
            # --- Tau Validation (Deterministic Two-Step) ---

            # Step 1: Rule Validation (if present)
            if has_rules:
                rule_value = operations.get("0", "")
                if not isinstance(rule_value, str):
                    return _qt_err(
                        "TX_INVALID",
                        (
                            f"Invalid operation '0' (rule). "
                            f"Must be a string, got {type(rule_value).__name__}."
                        ),
                    )
                rule_text = rule_value.strip()
                if rule_text:
                    if tau_force_test:
                        logger.info("TAU_FORCE_TEST=1: skipping Tau rule validation.")
                    elif admission_tau.isolated:
                        # The revision apply will make -- the rule itself, or the
                        # composite a routed o5 rule becomes -- offered to an
                        # evaluator rebuilt from the committed journal, so it
                        # meets every type commitment the chain has made,
                        # superseded rules' included. This replaces both the
                        # fresh-process compile, which has no such history, and
                        # the preflight against the in-process mirror, whose
                        # representation is not the one the authority runs.
                        refusal = _revision_refusal(
                            admission_tau.revise(admission_candidate or rule_text)
                        )
                        if refusal is not None:
                            return refusal
                        logger.info("Tau rule validation successful (admission context).")
                    else:
                        # Deterministic gate: compile the rule against an
                        # isolated interpreter seeded from the current
                        # consensus rules. apply_block compiles the rule lazily
                        # at its activation height, so parse/overflow errors
                        # (e.g. a constant too wide for the target stream's
                        # bit-vector type) would otherwise not surface until
                        # then and the tx would slip into the mempool. The
                        # isolated compile surfaces them here without mutating
                        # live interpreter state.
                        if tau_manager.tau_ready.is_set() and not getattr(
                            tau_manager, "tau_test_mode", False
                        ):
                            import tau_native
                            try:
                                prior_spec = chain_state.get_rules_state()
                                # Compile the rule in a throwaway subprocess
                                # with a hard timeout. This killable subprocess
                                # is the SOLE op-"0" rule-validation path -- there
                                # is deliberately no in-process live fallback.
                                # The in-process compile can hang indefinitely
                                # inside native Tau with no status stamp for the
                                # watchdog to catch, and its state-restore is
                                # likewise unbounded and watchdog-blind: that was
                                # the indefinite-hang vector in issue #24.
                                # apply_block re-compiles every rule
                                # deterministically at its activation height, so
                                # a rare admission-time skip cannot let an invalid
                                # rule take effect.
                                # Shared bound with the consensus-revision path
                                # (consensus/admission.py), below the shipped
                                # client's socket timeout so the structured
                                # rejection below actually reaches the caller
                                # instead of the client giving up first.
                                compile_timeout = tau_native.admission_compile_timeout()
                                compile_err = tau_native.compile_revisions_isolated_subprocess(
                                    prior_spec,
                                    [rule_text],
                                    timeout=compile_timeout,
                                )
                            except tau_native.RuleCompileTimeout as compile_exc:
                                # Bounded rejection: the child overran the
                                # admission budget and was SIGKILLed. Return a
                                # distinct code instead of hanging sendtx.
                                logger.warning(
                                    "Rule compile timed out at admission: %s",
                                    compile_exc,
                                )
                                return _qt_err(
                                    "ADMISSION_TIMEOUT",
                                    (
                                        f"Rule validation timed out after "
                                        f"{compile_timeout}s and was rejected."
                                    ),
                                    timeout_seconds=compile_timeout,
                                )
                            except tau_native.NativeTauUnavailable as compile_exc:
                                # The isolated compile could not run (transient
                                # worker-spawn failure, e.g. EMFILE/ENOMEM). Do
                                # NOT fall back to the unbounded, watchdog-blind
                                # in-process live path; reject promptly so the
                                # client can resubmit. apply_block remains the
                                # correctness backstop.
                                logger.warning(
                                    "Isolated rule compile unavailable; rejecting: %s",
                                    compile_exc,
                                )
                                return _qt_err(
                                    "ADMISSION_UNAVAILABLE",
                                    "Rule validation is temporarily unavailable; please resubmit.",
                                )
                            # Any other (unexpected) exception propagates to the
                            # outer handler -> INTERNAL_ERROR.
                            if compile_err:
                                return _qt_err(
                                    "TX_REJECTED",
                                    f"Transaction rejected by Tau (rule validation). {compile_err}",
                                )
                            logger.info("Tau rule validation successful (isolated compile).")

                            # The canonical compile above runs in a FRESH process,
                            # which has no type commitments and does no shrinking,
                            # so it passes text the live process cannot type. Now
                            # validate what apply will actually feed: the PREPARED
                            # runtime rule against the runtime baseline.
                            preflight_err = _preflight_prepared_rule(rule_text)
                            if preflight_err is not None:
                                return preflight_err

            # Advisory block timestamp for i5 at admission (see
            # _admission_timestamp). Read once: every step of one request is
            # judged at the same moment.
            admission_ts = _admission_timestamp()

            # Step 2: Custom Input Validation (transfer-less user_tx only).
            # For txs WITH transfers the custom streams are merged into the
            # per-transfer step below (mirrors apply, where the custom-only
            # step runs only when there are no transfers), so o1/o5/o8/o9 see
            # i13+ together with the transfer fields. Keeping a separate custom
            # step for transfer txs would create an admission-only rejection
            # surface that apply never runs -> divergence and a wasted roundtrip.
            if admission_tau.isolated:
                # Apply's unified custom step, where apply runs it: after the
                # rule, before the fee query, whenever there are no transfers and
                # there is a rule or a custom input -- with i5, as apply feeds it.
                # A context replays apply's schedule, so a fee estimate that
                # depends on history sees the history the block will.
                if (not all_validated_transfers and (custom_tau_inputs or has_rules)
                        and not skip_tau_eval and not tau_force_test):
                    unified_inputs = dict(custom_tau_inputs)
                    unified_inputs[5] = str(admission_ts)
                    admission_tau.step_multi(unified_inputs, source=sender_pubkey)
            elif custom_tau_inputs and not all_validated_transfers and not skip_tau_eval:
                if tau_force_test:
                    logger.info("TAU_FORCE_TEST=1: skipping Tau custom input validation.")
                else:
                    logger.info("Validating custom inputs with Tau: %s", custom_tau_inputs.keys())
                    # Send custom inputs targeting o0 (general ack/output)
                    tau_output_custom = tau_manager.communicate_with_tau(
                        rule_text=None,
                        target_output_stream_index=0,
                        input_stream_values=custom_tau_inputs,
                        source=sender_pubkey,
                        apply_rules_update=False,
                    )
                    if "Error" in tau_output_custom:
                        return _qt_err(
                            "TX_REJECTED",
                            f"Transaction rejected by Tau (custom input validation). Output: {tau_output_custom}",
                        )
                    logger.info("Tau custom input validation successful.")

            # Step 3: Transfer Validation
            if has_transfers and all_validated_transfers and not skip_tau_eval:
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

                        tau_input_stream_values = {}
                        tau_input_stream_values[1] = str(tau_input_dict['amount'])
                        # i2: the sender's balance at the current HEAD, identical
                        # for every transfer in this tx — matching the engine,
                        # which feeds the parent-block snapshot frozen for the
                        # whole block (issue #20). Deliberately NOT the intra-tx
                        # decremented `tau_input_dict['balance']`: that is more
                        # accurate locally but diverges from what apply will feed,
                        # and agreeing with apply is what makes a balance-reading
                        # rule deterministic. Advisory in the same sense as i5 —
                        # the tx may land a few blocks later; apply is
                        # authoritative. `remaining_balances` still drives the
                        # affordability pre-check below.
                        tau_input_stream_values[2] = _admission_i2(sender_pubkey)
                        # i3/i4: full 384-bit from/to pubkeys. The bv-shrink layer
                        # interns these equality-only address streams to a small bv
                        # for evaluation; the canonical full-width rule text is hashed.
                        tau_input_stream_values[3] = "{ #x" + tau_input_dict['from_addr'] + " }:bv[384]"
                        tau_input_stream_values[4] = "{ #x" + tau_input_dict['to_addr'] + " }:bv[384]"
                        # i12: full 384-bit sender public key (bv[384]) for user-policy
                        # rules that scope on the real key.
                        tau_input_stream_values[12] = "{ #x" + sender_pubkey + " }:bv[384]"
                        # Custom input streams (i13+). Merged AFTER i12 and BEFORE
                        # i5, byte-identical to the apply-time overlay order in
                        # consensus/engine.py, so rules combining i13+ with the
                        # transfer fields (i1/i3/i4/i5/i12) are enforced the same
                        # at admission and apply. Keys 2-12 are rejected upstream,
                        # so custom keys can never clobber a reserved stream.
                        for k, v in custom_tau_inputs.items():
                            tau_input_stream_values[k] = v
                        # Approval slots (i18..i25). An ORDINARY transfer always
                        # feeds 0 on every slot, which equals no approver pubkey,
                        # so a co-signature policy clause keeps blocking until the
                        # parked-request path supplies real votes. Fed after the
                        # custom merge and before i5, byte-identically at apply.
                        # Reserved upstream, so a sender cannot pre-fill one.
                        for slot in _approval_slot_feed(tip_view):
                            tau_input_stream_values[slot] = "0"
                        # i5: advisory block timestamp (see admission_ts above) so
                        # time-lock o5 rules pre-check at admission; apply is
                        # authoritative.
                        tau_input_stream_values[5] = str(admission_ts)

                        logger.info(
                            "Sending Tau inputs for transfer #%s validation: %s",
                            i + 1,
                            tau_input_stream_values,
                        )
                        tau_outputs = admission_tau.step_multi(
                            tau_input_stream_values, source=sender_pubkey,
                        )

                        # --- Built-in Transfer Validation (o1) ---
                        o1_raw = tau_outputs.get(1)
                        expected_amount = transfer_details[2]
                        if not _decode_single_transfer_output(o1_raw or "0", expected_amount):
                            return _qt_err(
                                "TX_REJECTED",
                                (
                                    f"Transaction rejected by Tau logic for transfer #{i+1} "
                                    f"({transfer_details}). Tau output: {o1_raw}"
                                ),
                                transfer_index=i + 1,
                            )

                        # --- User Policy Check (o5) ---
                        o5_raw = tau_outputs.get(tau_defs.USER_POLICY_STREAM_INDEX)
                        if o5_raw is not None:
                            from tau_manager import parse_tau_output as _parse
                            policy_val = _parse(o5_raw)
                            if policy_val == tau_defs.USER_POLICY_BLOCK_VALUE:
                                return _qt_err(
                                    "TX_REJECTED",
                                    (
                                        f"Transaction rejected by user policy (o5) for transfer #{i+1} "
                                        f"({transfer_details}). Policy output: {o5_raw}"
                                    ),
                                    transfer_index=i + 1,
                                )

                        # --- Fee Estimation (o9 consensus + o8 custom) ---
                        # Same tau_outputs dict: zero extra roundtrips.
                        try:
                            estimated_fee_total += fees.parse_consensus_fee(
                                tau_outputs.get(tau_defs.CONSENSUS_FEE_STREAM_INDEX),
                                context=f"queue transfer #{i+1}",
                            ) + fees.parse_custom_fee(
                                tau_outputs.get(tau_defs.CUSTOM_FEE_STREAM_INDEX),
                                context=f"queue transfer #{i+1}",
                            )
                        except FeeRuleError as fee_exc:
                            # Voted consensus rules emit garbage on o9:
                            # the fee is undeterminable -> cannot admit.
                            return _qt_err(
                                "FEE_RULE_ERROR",
                                f"Consensus fee rule failure: {fee_exc}",
                            )
                    logger.info("All Tau transfer validations successful.")

            # Step 3b: Fee estimate for any fee-bearing tx with no transfers —
            # one fee-query step with the canonical mocked transfer inputs
            # (mirrors the engine's apply-time convention). Covers the
            # rule-sharing types, which are user-initiated and expensive and so
            # pay like a user_tx, unlike the fee-exempt governance types.
            if (
                tx_type in FEE_BEARING_TX_TYPES
                and not all_validated_transfers
                and not tau_force_test
                and not skip_tau_eval
                and (admission_tau.isolated or tau_manager.tau_ready.is_set())
            ):
                try:
                    # i2 is the sender's head balance here too, matching the
                    # engine's transfer-less fee-query step (issue #20).
                    fee_query_inputs = {1: "0", 2: _admission_i2(sender_pubkey),
                                        3: "0", 4: "0"}
                    fee_query_inputs[5] = str(admission_ts)
                    fee_query_inputs[12] = "{ #x" + sender_pubkey + " }:bv[384]"
                    # Custom streams (i13+) last, matching the apply-time
                    # fee-query overlay order in consensus/engine.py.
                    for k, v in custom_tau_inputs.items():
                        fee_query_inputs[k] = v
                    fee_outputs = admission_tau.step_multi(
                        fee_query_inputs, source=sender_pubkey,
                    )
                    estimated_fee_total += fees.parse_consensus_fee(
                        fee_outputs.get(tau_defs.CONSENSUS_FEE_STREAM_INDEX),
                        context="queue fee-query",
                    ) + fees.parse_custom_fee(
                        fee_outputs.get(tau_defs.CUSTOM_FEE_STREAM_INDEX),
                        context="queue fee-query",
                    )
                except FeeRuleError as fee_exc:
                    return _qt_err(
                        "FEE_RULE_ERROR",
                        f"Consensus fee rule failure: {fee_exc}",
                    )
                except Exception:
                    if admission_tau.isolated:
                        # A context that could not answer is not an estimate of
                        # zero: admitting on it would quote a fee the block then
                        # charges differently. Reported by the handlers below.
                        raise
                    logger.warning(
                        "Fee-query estimation failed; estimate stays %s (engine is authoritative).",
                        estimated_fee_total, exc_info=True,
                    )

        # Evaluation is over; the context goes before anything is queued.
        admission_tau.close()

        # --- Post-Tau Processing ---
        # Note: We do NOT increment sequence number or update balances here anymore.
        # This is now an ingestion-only phase. State mutation happens during mining.
        # if _PY_ECC_AVAILABLE and _PY_ECC_BLS:
        #     chain_state.increment_sequence_number(sender_pubkey)

        if all_validated_transfers:
            logger.info(
                "Validated %s transfers (dry-run). State will be updated upon mining.",
                len(all_validated_transfers),
            )
            # for from_addr, to_addr, amt in all_validated_transfers:
            #     if not chain_state.update_balances_after_transfer(from_addr, to_addr, amt):
            #         return (
            #             "FAILURE: Transaction invalid. "
            #             f"Could not apply transfer ({from_addr[:10]}... -> {to_addr[:10]}..., amount {amt})."
            #         )

        # --- Fee cap + best-effort funds check (user_tx only) ---
        # The engine re-derives and charges the fee authoritatively at
        # block application; this layer is anti-spam. The estimate can
        # diverge only for fee rules that violate the documented
        # determinism constraint (i2/i3/i4 are mocked at apply time).
        if tx_type in FEE_BEARING_TX_TYPES:
            if estimated_fee_total > fee_limit_int:
                return _qt_err(
                    "FEE_LIMIT_TOO_LOW",
                    f"required estimated fee {estimated_fee_total}, fee_limit {fee_limit_int}",
                    required_fee=estimated_fee_total,
                    fee_limit=fee_limit_int,
                )
            sum_amounts = sum(amt for _, _, amt in all_validated_transfers)
            sender_balance = chain_state.get_balance(sender_pubkey)
            if sender_balance < sum_amounts + estimated_fee_total:
                return _qt_err(
                    "INSUFFICIENT_FUNDS",
                    (
                        f"Sender balance {sender_balance} cannot cover transfers "
                        f"{sum_amounts} plus estimated fee {estimated_fee_total}."
                    ),
                    balance=sender_balance,
                    required=sum_amounts + estimated_fee_total,
                )

        tx_message_id, tx_canonical_blob = _compute_transaction_message_id(payload)

        # --- Evaluation ends here; everything below mutates state. -----------
        # A dry run returns the verdict now: before the mempool-capacity check
        # (a capacity fact about the node, not a verdict about this tx) and
        # before the two mutations.
        if dry_run:
            verdict = {
                "ok": True,
                "tx_hash": tx_message_id,
                "message": "Transaction would be admitted.",
                "admissible": True,
                "tx_type": tx_type,
                "tau_evaluated": not skip_tau_eval,
            }
            if not skip_tau_eval and tx_type == "user_tx":
                verdict["estimated_fee"] = str(estimated_fee_total)
            update_id = admission_eval.data.get("update_id")
            if update_id:
                verdict["update_id"] = update_id
            return verdict

        if db.count_mempool_txs() >= config.MAX_MEMPOOL_TXS:
            return _qt_err(
                "MEMPOOL_FULL",
                f"Mempool is full ({config.MAX_MEMPOOL_TXS} pending transactions). Please try again later.",
                current_count=db.count_mempool_txs(),
                limit=config.MAX_MEMPOOL_TXS
            )
        # Use canonical blob for storage to ensure consistency
        # Use milliseconds for received_at for better ordering resolution
        received_at = int(time.time() * 1000)
        db.add_mempool_tx(
            tx_canonical_blob, tx_message_id, received_at,
            fee_limit=fee_limit_int,
            estimated_fee=estimated_fee_total if tx_type in FEE_BEARING_TX_TYPES else 0,
            lane=classify_lane(payload),
        )
        logger.info("Transaction successfully queued in mempool.")
        if propagate:
            if network_bus is not None:
                svc = network_bus.get()
                if svc:
                    svc.broadcast_transaction(tx_canonical_blob, tx_message_id)
        msg = (
            "Transaction queued (empty transfer list)."
            if empty_transfer_list
            else "Transaction queued."
        )
        # Admission already derived the update_id for a consensus_rule_update
        # (via the same compute_update_id getupdateid uses) and returned it on
        # the result; hand it back so a wallet can track the proposal without a
        # second round trip (issue #23).
        extra = {}
        update_id = admission_eval.data.get("update_id")
        if update_id:
            extra["update_id"] = update_id
        return _qt_ok(tx_message_id, message=msg, **extra)

    except ValueError as e:
        return _qt_err("INVALID_PARAMS", f"Could not process transaction. {e}")
    except TauCommunicationError as e:
        logger.error("Tau rule validation failed: %s", e)
        return _qt_err("TX_REJECTED", f"Transaction rejected by Tau. {e}")
    except tau_admission.StepRefused as e:
        # The engine refused this request's own inputs, against committed state:
        # the same refusal wherever they run.
        return _qt_err("TX_REJECTED", f"Transaction rejected by Tau. {e}")
    except tau_admission.AdmissionTimeout as e:
        logger.warning("Admission evaluation timed out: %s", e)
        return _qt_err(
            "ADMISSION_TIMEOUT",
            f"Transaction evaluation timed out after {admission_tau.budget:g}s "
            f"and was rejected.",
            timeout_seconds=admission_tau.budget,
        )
    except tau_admission.AdmissionUnavailable as e:
        # Operational. Never answered from the in-process interpreter instead:
        # that is the shared evaluator an admission context exists to replace.
        logger.warning("Admission evaluation unavailable: %s", e)
        return _qt_err(
            "ADMISSION_UNAVAILABLE",
            "Transaction validation is temporarily unavailable; please resubmit.",
        )
    except Exception as e:
        logger.exception("An unexpected error occurred in queue_transaction: %s", e)
        return _qt_err("INTERNAL_ERROR", "An unexpected server error occurred.")
    finally:
        admission_tau.close()


def execute(raw_command: str, container):
    """
    Executes the sendtx command.
    Expected format: sendtx <json_payload>
    """
    prefix = 'sendtx '
    if not raw_command.lower().startswith(prefix):
        return api_response.error_response(
            "sendtx",
            "Invalid sendtx format. Use sendtx '{\"0\":...}'.",
            "INVALID_PARAMS",
        )

    if not _PY_ECC_AVAILABLE:
        logger.error("BLS library not available. Transaction rejected.")
        return api_response.error_response(
            "sendtx",
            "BLS signatures are required but py_ecc is missing.",
            "BLS_UNAVAILABLE",
        )

    json_blob = raw_command[len(prefix):].strip()
    logger.debug("Received sendtx payload: %s", json_blob)

    try:
        result = queue_transaction(json_blob)
    except Exception as exc:
        logger.exception("sendtx queue failed")
        return api_response.error_response("sendtx", str(exc), "INTERNAL_ERROR")

    if result.get("ok"):
        # Explicit allowlist, never dict(result): an internal key added to the
        # queue_transaction return must not leak into the wire envelope.
        data = {
            "message": result.get("message", "Transaction queued."),
            "tx_hash": result["tx_hash"],
        }
        if result.get("update_id"):
            data["update_id"] = result["update_id"]
        return api_response.success_response("sendtx", data)
    return api_response.error_response(
        "sendtx",
        result.get("message", "Transaction rejected."),
        result.get("code", "TX_REJECTED"),
        details=result.get("details"),
    )
