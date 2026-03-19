import logging
import os
import threading
import time

import config
import tau_defs
import utils
from errors import TauCommunicationError, TauEngineCrash
import tau_native
import tau_io_logger

logger = logging.getLogger(__name__)

# --- Rule sanitation -----------------------------------------------------------
DEFAULT_RULE_BV_WIDTH = 16
import re
_BV_TYPE_RE = re.compile(r":\s*bv(?:\s*\[\s*\d+\s*\])?")
_ADDRESS_LITERAL_BV384_RE = re.compile(
    r"(\{\s*#x[0-9a-fA-F]{96}\s*\})\s*:\s*bv\s*\[\s*384\s*\]"
)

def normalize_rule_bitvector_sizes(rule_text: str, default_width: int = DEFAULT_RULE_BV_WIDTH) -> str:
    """
    Normalize Tau rule text so that any bitvector type annotation `:bv` or
    `:bv[<n>]` becomes `:bv[<default_width>]`.
    """
    if not rule_text:
        return rule_text

    sentinel = ":__TAU_KEEP_BV384_ADDR__"
    protected = _ADDRESS_LITERAL_BV384_RE.sub(r"\1" + sentinel, rule_text)

    normalized, replacements = _BV_TYPE_RE.subn(f":bv[{int(default_width)}]", protected)
    if replacements:
        logger.debug(
            "normalize_rule_bitvector_sizes: rewrote %s ':bv' annotations to ':bv[%s]'",
            replacements,
            default_width,
        )
    return normalized.replace(sentinel, ":bv[384]")

# --- Global State ---
tau_process_lock = threading.Lock()
tau_comm_lock = threading.Lock()
tau_ready = threading.Event()
tau_process_ready = threading.Event()
restart_in_progress = threading.Event()
server_should_stop = threading.Event()

tau_test_mode = False
_rules_handler = None
_state_restore_callback = None
last_known_tau_spec: str | None = None
tau_direct_interface: tau_native.TauInterface | None = None


def set_rules_handler(handler):
    global _rules_handler
    _rules_handler = handler


def set_state_restore_callback(handler):
    global _state_restore_callback
    _state_restore_callback = handler


def start_and_manage_tau_process():
    global tau_ready, tau_process_ready, server_should_stop, tau_process_lock, tau_test_mode, restart_in_progress
    global tau_direct_interface, last_known_tau_spec

    server_should_stop.clear()
    tau_ready.clear()
    tau_process_ready.clear()
    restart_in_progress.clear()
    tau_test_mode = False
    last_known_tau_spec = None

    if os.environ.get("TAU_FORCE_TEST", "0") == "1":
        logger.warning("TAU_FORCE_TEST enabled. Running in TEST MODE without Tau Engine.")
        tau_test_mode = True
        tau_process_ready.set()
        tau_ready.set()
        while not server_should_stop.is_set():
            time.sleep(0.05)
        logger.info("Server shutdown requested, Tau manager exiting.")
        return

    logger.info("Direct Bindings Mode Enabled. Initializing Tau Native Interface...")
    try:
        tau_direct_interface = tau_native.TauInterface(config.TAU_PROGRAM_FILE)
        logger.info("Tau Native Interface initialized successfully.")
        tau_process_ready.set()

        if _state_restore_callback:
            try:
                logger.info("Invoking state restore callback (Direct Mode)...")
                _state_restore_callback()
                logger.info("State restore callback completed successfully.")
            except Exception as e:
                logger.error("State restore callback failed in Direct Mode: %s", e)
                pass

        tau_ready.set()
        
        while not server_should_stop.is_set():
            time.sleep(1)
            
        logger.info("Server shutdown requested, Tau manager exiting (Direct Mode).")
    except Exception as e:
        logger.critical(f"Failed to initialize Tau Native Interface: {e}")
        return


def communicate_with_tau(
    rule_text: str | None = None,
    target_output_stream_index: int = 0,
    input_stream_values: dict[int | str, str | list[str]] | None = None,
    source: str = "unknown",
    apply_rules_update: bool = True,
    wait_for_ready: bool = True,
):
    global tau_ready, tau_comm_lock, last_known_tau_spec, tau_direct_interface

    total_wait_time = 0.0
    while wait_for_ready:
        wait_step = config.CLIENT_WAIT_TIMEOUT * 2
        if not tau_ready.wait(timeout=wait_step):
            total_wait_time += wait_step
            logger.warning("communicate_with_tau: Timeout waiting for Tau readiness (total wait: %.1fs). Retrying...", total_wait_time)
            
            if total_wait_time > config.PROCESS_TIMEOUT + 60:
                 msg = f"Timed out ({total_wait_time}s) waiting for Tau to become ready."
                 filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                 raise TauEngineCrash(msg)

            if server_should_stop.is_set():
                raise TauEngineCrash("Server is stopping.")
            continue
        break

    try:
        tau_comm_lock.acquire()
    except Exception as e:
        raise TauCommunicationError("Failed to acquire communication lock")

    try:
        if tau_test_mode:
            if target_output_stream_index == 0:
                return tau_defs.ACK_RULE_PROCESSED
            elif target_output_stream_index == 1:
                if input_stream_values and 1 in input_stream_values:
                    v = input_stream_values[1]
                    if isinstance(v, (list, tuple)) and v:
                        return v[0]
                    return v
                return tau_defs.TRANSACTION_VALIDATION_SUCCESS
            return tau_defs.TAU_VALUE_ZERO

        if not tau_direct_interface:
             msg = "Direct Tau Interface used but not initialized."
             filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
             raise TauEngineCrash(msg)

        if rule_text:
            rule_text = rule_text.replace('\n', ' ')
            if rule_text.lstrip().startswith("always"):
                rule_text = normalize_rule_bitvector_sizes(rule_text)

        normalized_inputs = None
        if input_stream_values:
            normalized_inputs = {}
            for k, v in input_stream_values.items():
                if isinstance(v, (list, tuple)):
                    parts = []
                    for p in v:
                        p_str = str(p).replace('\n', ' ')
                        if p_str.lstrip().startswith("always"):
                            p_str = normalize_rule_bitvector_sizes(p_str)
                        parts.append(p_str)
                    normalized_inputs[k] = parts
                else:
                    v_str = str(v).replace('\n', ' ')
                    if v_str.lstrip().startswith("always"):
                        v_str = normalize_rule_bitvector_sizes(v_str)
                    normalized_inputs[k] = v_str

        try:
            output_val = tau_direct_interface.communicate(
                rule_text=rule_text,
                target_output_stream_index=target_output_stream_index,
                input_stream_values=normalized_inputs or input_stream_values,
                source=source,
                apply_rules_update=apply_rules_update
            )
        except Exception as ex:
            raise TauCommunicationError(f"Direct Tau communication failed: {ex}", last_state=last_known_tau_spec)

        current_full_spec = None
        if hasattr(tau_direct_interface, "get_current_spec"):
            try:
                current_full_spec = tau_direct_interface.get_current_spec()
            except Exception:
                pass

        if current_full_spec:
            last_known_tau_spec = current_full_spec
        elif rule_text is not None and target_output_stream_index == 0:
            last_known_tau_spec = rule_text

        if apply_rules_update and rule_text is not None and target_output_stream_index == 0 and _rules_handler and last_known_tau_spec:
            try:
                _rules_handler(last_known_tau_spec)
            except Exception as e:
                logger.error("Failed to save updated spec: %s", e)

        try:
            return utils.normalize_tau_atoms(str(output_val))
        except Exception:
            return output_val

    finally:
        tau_comm_lock.release()


def communicate_with_tau_multi(
    input_stream_values: dict[int | str, str | list[str]] | None = None,
    source: str = "unknown",
    apply_rules_update: bool = True,
    wait_for_ready: bool = True,
) -> dict[int, str]:
    global tau_direct_interface, tau_test_mode

    if tau_test_mode:
        result = {}
        if input_stream_values:
            stream_queues = {}
            for raw_idx, raw_value in input_stream_values.items():
                try:
                    idx = int(raw_idx)
                except (TypeError, ValueError):
                    continue
                if isinstance(raw_value, (list, tuple)):
                    stream_queues[idx] = raw_value[0] if raw_value else "0"
                else:
                    stream_queues[idx] = str(raw_value)
            if 1 in stream_queues:
                result[1] = stream_queues[1]
            else:
                result[1] = tau_defs.TRANSACTION_VALIDATION_SUCCESS
        else:
            result[1] = tau_defs.TRANSACTION_VALIDATION_SUCCESS
        return result

    if not tau_direct_interface:
        msg = "Direct Tau Interface used but not initialized."
        filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
        raise TauEngineCrash(msg)

    normalized_inputs = None
    if input_stream_values:
        normalized_inputs = {}
        for k, v in input_stream_values.items():
            if isinstance(v, (list, tuple)):
                parts = [str(p).replace('\n', ' ') for p in v]
                normalized_inputs[k] = parts
            else:
                v_str = str(v).replace('\n', ' ')
                if v_str.lstrip().startswith("always"):
                    v_str = normalize_rule_bitvector_sizes(v_str)
                normalized_inputs[k] = v_str

    try:
        result = tau_direct_interface.communicate_multi(
            rule_text=None,
            input_stream_values=normalized_inputs or input_stream_values,
            source=source,
            apply_rules_update=apply_rules_update,
        )
    except Exception as ex:
        raise TauCommunicationError(f"Direct Tau multi-output communication failed: {ex}", last_state=last_known_tau_spec)

    normalized_result = {}
    for idx, val in result.items():
        try:
            normalized_result[idx] = utils.normalize_tau_atoms(str(val))
        except Exception:
            normalized_result[idx] = str(val)
    return normalized_result


def reset_tau_state(rule_text: str, *, source: str = "unknown", apply_rules_update: bool = True) -> None:
    communicate_with_tau(
        rule_text=rule_text or "",
        target_output_stream_index=0,
        source=source,
        apply_rules_update=apply_rules_update,
        wait_for_ready=True,
    )


def get_tau_process_status():
    global tau_ready, tau_direct_interface
    if tau_direct_interface:
        if tau_ready.is_set():
            return "Running and Ready"
        return "Running, Not Ready (Initializing)"
    return "Not Running"


def get_recent_stderr():
    return []


def request_shutdown():
    global tau_direct_interface, last_known_tau_spec
    logger.info("Shutdown requested.")
    server_should_stop.set()
    last_known_tau_spec = None
    tau_direct_interface = None
    with tau_process_lock:
        tau_direct_interface = None
        tau_ready.clear()
        tau_process_ready.clear()


def kill_tau_process():
    global tau_ready, tau_process_ready, tau_direct_interface, restart_in_progress
    logger.warning("Resetting direct Tau interface after failure.")
    tau_ready.clear()
    tau_process_ready.clear()
    with tau_process_lock:
        tau_direct_interface = None
    try:
        recovered_interface = tau_native.TauInterface(config.TAU_PROGRAM_FILE)
        with tau_process_lock:
            tau_direct_interface = recovered_interface
        tau_process_ready.set()
        if _state_restore_callback:
            _state_restore_callback()
        tau_ready.set()
        restart_in_progress.clear()
    except Exception as e:
        logger.error("Failed to recover direct Tau interface: %s", e)
        with tau_process_lock:
            tau_direct_interface = None


def parse_tau_output(output_val: str) -> int:
    if not output_val:
        return 0
    val = output_val.strip()
    converted_val = 0
    try:
        if val.startswith("result:"):
             val = val[7:].strip()
             
        if val.startswith("#b"):
            converted_val = int(val[2:], 2)
        elif val.startswith("#x"):
            converted_val = int(val[2:], 16)
        else:
            converted_val = int(val)
    except Exception:
        converted_val = 0
    
    return converted_val


__all__ = [
    "communicate_with_tau",
    "communicate_with_tau_multi",
    "get_tau_process_status",
    "get_recent_stderr",
    "request_shutdown",
    "kill_tau_process",
    "parse_tau_output",
    "set_rules_handler",
    "set_state_restore_callback",
    "start_and_manage_tau_process",
    "reset_tau_state",
]
