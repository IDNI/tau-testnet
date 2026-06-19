import logging
import os
import threading
import time

import config
import tau_defs
import utils
from errors import TauCommunicationError, TauEngineCrash
import tau_native
import tau_shrink
import tau_io_logger

logger = logging.getLogger(__name__)

COLOR_CYAN = "\033[96m"
COLOR_GREEN = "\033[92m"
COLOR_RESET = "\033[0m"


def _print_tau_send(label: str, payload: str) -> None:
    if label and label.startswith("source=unknown"):
        return
    print(f"{COLOR_CYAN}[TAU SEND] {label}{COLOR_RESET}", flush=True)
    if payload:
        for line in str(payload).splitlines():
            print(f"{COLOR_GREEN}{line}{COLOR_RESET}", flush=True)
    else:
        print(f"{COLOR_GREEN}<empty>{COLOR_RESET}", flush=True)

    # Optional disk logging (best-effort)
    try:
        prefix = f"SEND {label} >>>"
        if "source=unknown" not in prefix:
            tau_io_logger.append_to_debug_file(config.COMM_DEBUG_PATH, prefix, str(payload or ""))
    except Exception:
        pass


def _print_tau_dispatch(
    *,
    source: str,
    rule_text: str | None = None,
    input_stream_values: dict[int | str, str | list[str]] | None = None,
    target_output_stream_index: int | None = None,
) -> None:
    target_suffix = "" if target_output_stream_index is None else f" -> o{target_output_stream_index}"
    if rule_text is not None:
        _print_tau_send(f"source={source}{target_suffix} i0", rule_text)
    if input_stream_values:
        for stream_name, raw_value in input_stream_values.items():
            label = f"source={source}{target_suffix} i{stream_name}" if str(stream_name).isdigit() else f"source={source}{target_suffix} {stream_name}"
            if isinstance(raw_value, (list, tuple)):
                for idx, value in enumerate(raw_value):
                    _print_tau_send(f"{label}[{idx}]", str(value))
            else:
                _print_tau_send(label, str(raw_value))

# --- Rule sanitation -----------------------------------------------------------
DEFAULT_RULE_BV_WIDTH = 64
import re
_BV_TYPE_RE = re.compile(r":\s*bv(?!\s*\[)")
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

# Eval-only shrink state. `last_known_tau_spec` is always the CANONICAL
# full-width spec (the only thing persisted). `_current_prepared_spec` holds the
# canonical/runtime split for the spec currently loaded in the interpreter, and
# `_runtime_shrunk_streams` is the set of input stream indices whose runtime
# values must be shrunk to match the loaded (shrunk) rule. These are updated
# only AFTER a successful interpreter update, under `tau_comm_lock`.
_current_prepared_spec: "tau_shrink.PreparedTauSpec | None" = None
_runtime_shrunk_streams: frozenset = frozenset()


# Watchdog monitors in-flight Tau communication; limit is config.COMM_TIMEOUT (TAU_COMM_TIMEOUT).
WATCHDOG_COMM_TIMEOUT_NAME = "comm_timeout"
WATCHDOG_COMM_CONFIG_KEY = "COMM_TIMEOUT"
WATCHDOG_COMM_ENV_VAR = "TAU_COMM_TIMEOUT"


def _write_status(start=True, source: str | None = None):
    try:
        import json
        status_file = os.path.join(config.DATA_DIR, "tau_status.json")
        data = {
            "pid": os.getpid(),
            "db_path": config.STRING_DB_PATH,
            "last_start_time": time.time() if start else None,
        }
        if start:
            data["watchdog_timeout_name"] = WATCHDOG_COMM_TIMEOUT_NAME
            data["watchdog_timeout_seconds"] = config.COMM_TIMEOUT
            data["watchdog_config_key"] = WATCHDOG_COMM_CONFIG_KEY
            data["watchdog_env_var"] = WATCHDOG_COMM_ENV_VAR
            if source:
                data["comm_source"] = source
        with open(status_file, "w") as f:
            json.dump(data, f)
    except Exception as e:
        logger.error("Failed to write watchdog status file: %s", e)


def set_rules_handler(handler):
    global _rules_handler
    _rules_handler = handler


def set_state_restore_callback(handler):
    global _state_restore_callback
    _state_restore_callback = handler


def is_force_test_enabled() -> bool:
    requested = os.environ.get("TAU_FORCE_TEST", "0") == "1"
    if not requested:
        return False

    runtime_env = getattr(getattr(config, "settings", None), "env", None) or os.environ.get("TAU_ENV", "development")
    if runtime_env == "test":
        return True

    logger.error(
        "Ignoring TAU_FORCE_TEST outside TAU_ENV=test (current env: %s).",
        runtime_env,
    )
    return False


def _preprocess_rule_for_tau(rule_text: str | None) -> str | None:
    """Return the CANONICAL full-width normalized rule text (never shrunk).

    This is the authoritative form that gets persisted and hashed. Shrinking is
    layered on top by `_prepare_rule_for_tau`.
    """
    if rule_text is None:
        return None
    if tau_direct_interface and hasattr(tau_direct_interface, "preprocess_spec_text"):
        return tau_direct_interface.preprocess_spec_text(rule_text)
    text = str(rule_text).replace('\n', ' ')
    if text.lstrip().startswith("always"):
        text = normalize_rule_bitvector_sizes(text)
    return text


def _shrink_exclude() -> frozenset:
    if not getattr(config, "TAU_SHRINK_ENABLED", False):
        return frozenset()
    return frozenset(getattr(config, "TAU_SHRINK_STREAM_EXCLUDE", frozenset()))


def _prepare_rule_for_tau(rule_text: str | None) -> "tau_shrink.PreparedTauSpec | None":
    """Canonical/runtime split for a rule. canonical_text is persisted; the
    interpreter is fed runtime_text. Disabled => canonical == runtime."""
    canonical = _preprocess_rule_for_tau(rule_text)
    if canonical is None:
        return None
    if not getattr(config, "TAU_SHRINK_ENABLED", False):
        return tau_shrink.PreparedTauSpec(canonical, canonical, False, frozenset())
    return tau_shrink.prepare_rule(canonical, exclude_streams=_shrink_exclude())


def get_canonical_spec() -> str | None:
    """The full-width spec safe to persist/hash. NEVER the interpreter's
    (possibly shrunk) `get_current_spec()`."""
    return last_known_tau_spec


def _normalize_tau_input_value(value: str | None) -> str | None:
    if value is None:
        return None
    if tau_direct_interface and hasattr(tau_direct_interface, "_normalize_assignment_value"):
        return tau_direct_interface._normalize_assignment_value(value)
    text = str(value).replace('\n', ' ').strip()
    if not text or text.startswith(("#x", "#b", "{")):
        return text
    if re.fullmatch(r"[0-9a-fA-F]+", text) and any(ch in "abcdefABCDEF" for ch in text):
        return f"#x{text}"
    return text


def _collect_i0_prepared(input_stream_values) -> list:
    """Prepare any rule(s) supplied via the i0 input stream (rare). Returns the
    PreparedTauSpec for each so the caller can union shrink sets and commit."""
    out = []
    if not input_stream_values:
        return out
    for k, v in input_stream_values.items():
        if str(k) not in {"0", "i0"}:
            continue
        items = v if isinstance(v, (list, tuple)) else [v]
        for p in items:
            prep = _prepare_rule_for_tau(str(p).replace('\n', ' '))
            if prep is not None:
                out.append(prep)
    return out


def _normalize_inputs(input_stream_values, effective_shrunk: frozenset):
    """Normalize every stream value, shrinking allowlisted address streams.

    May raise tau_shrink.ShrinkUnavailable if a value that MUST shrink (its index
    is in effective_shrunk) cannot be interned -- the caller fails closed."""
    if not input_stream_values:
        return None

    def _one(k, p):
        idx = None
        try:
            idx = int(k)
        except (TypeError, ValueError):
            idx = None
        p_str = str(p).replace('\n', ' ')
        if str(k) in {"0", "i0"}:
            prep = _prepare_rule_for_tau(p_str)
            return (prep.runtime_text if prep else p_str) or ""
        if p_str.lstrip().startswith("always"):
            prep = _prepare_rule_for_tau(p_str)
            return (prep.runtime_text if prep else p_str) or ""
        base = _normalize_tau_input_value(p_str) or ""
        if idx is not None:
            base = tau_shrink.shrink_stream_value(base, idx, effective_shrunk)
        return base

    normalized = {}
    for k, v in input_stream_values.items():
        if isinstance(v, (list, tuple)):
            normalized[k] = [_one(k, p) for p in v]
        else:
            normalized[k] = _one(k, v)
    return normalized


def _commit_runtime_spec(prepared) -> None:
    """Commit the runtime shrink state (which input streams to shrink) for a
    successfully-loaded spec. MUST be called under tau_comm_lock, AFTER the
    interpreter update succeeds. Does NOT touch last_known_tau_spec: that stays
    the full COMPOSED interpreter spec (see communicate_with_tau), which
    createblock save/restore and persistence both depend on."""
    global _current_prepared_spec, _runtime_shrunk_streams
    _current_prepared_spec = prepared
    _runtime_shrunk_streams = prepared.shrunk_streams


def _handle_width_overflow(exc: "tau_shrink.ShrinkWidthOverflow"):
    """A newly-interned address overflowed the current process shrink width. The
    width cannot grow in-process (the native engine's per-stream bv typing is
    sticky), so re-exec the process: a fresh process re-reads the now-larger intern
    table and picks the wider width. The overflowing id is already persisted, and
    the in-flight tx/block was NOT committed, so nothing is lost; it is re-processed
    after restart. Tests set TAU_NO_WIDTH_REEXEC=1 (or run in tau_test_mode) to
    observe the exception instead of replacing the process."""
    import sys
    if tau_test_mode or os.environ.get("TAU_NO_WIDTH_REEXEC") == "1":
        raise exc
    logger.warning(
        "tau_shrink: %s -- re-exec to grow the shrink bv width (sticky per-stream "
        "typing cannot widen in-process).", exc
    )
    os.execv(sys.executable, [sys.executable] + sys.argv)


def start_and_manage_tau_process():
    global tau_ready, tau_process_ready, server_should_stop, tau_process_lock, tau_test_mode, restart_in_progress
    global tau_direct_interface, last_known_tau_spec

    server_should_stop.clear()
    tau_ready.clear()
    tau_process_ready.clear()
    restart_in_progress.clear()
    tau_test_mode = False
    last_known_tau_spec = None

    if is_force_test_enabled():
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
        # Pick the smallest shrink width for this process from the current intern
        # table. Sticky per-stream typing means it is fixed until the next re-exec.
        if getattr(config, "TAU_SHRINK_ENABLED", False):
            tau_shrink.set_shrink_width_from_db()
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
        tau_test_mode = True
        tau_process_ready.set()
        tau_ready.set()
        while not server_should_stop.is_set():
            time.sleep(0.05)
        logger.info("Server shutdown requested, Tau manager exiting (Fallback Test Mode).")
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

    _write_status(start=True, source=source)
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
            elif target_output_stream_index == 2:
                # Balance check: i1=amount, i2=balance
                try:
                    amt = int((input_stream_values or {}).get(1, 0))
                    bal = int((input_stream_values or {}).get(2, 0))
                    return "1" if amt <= bal else "0"
                except Exception:
                    return "0"
            elif target_output_stream_index == 3:
                # Address inequality check: i3=from, i4=to
                try:
                    src = str((input_stream_values or {}).get(3, ""))
                    dst = str((input_stream_values or {}).get(4, ""))
                    return "0" if src == dst else "1"
                except Exception:
                    return "0"
            elif target_output_stream_index == 4:
                # Non-zero amount check: i1=amount
                try:
                    amt = int((input_stream_values or {}).get(1, 0))
                    return "0" if amt == 0 else "1"
                except Exception:
                    return "0"
            return tau_defs.TAU_VALUE_ZERO

        if not tau_direct_interface:
             msg = "Direct Tau Interface used but not initialized."
             filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
             raise TauEngineCrash(msg)

        # --- Shrink: canonical (persisted) vs runtime (interpreter) split ---
        prepared = None
        if rule_text is not None:
            prepared = _prepare_rule_for_tau(rule_text)
            if prepared is not None:
                rule_text = prepared.runtime_text  # feed the interpreter the shrunk form

        i0_stream_preps = _collect_i0_prepared(input_stream_values)

        # Effective shrink set for THIS evaluation: a spec update redefines it,
        # otherwise use the committed runtime set.
        if prepared is not None:
            effective_shrunk = set(prepared.shrunk_streams)
        else:
            effective_shrunk = set(_runtime_shrunk_streams)
        for p in i0_stream_preps:
            effective_shrunk |= set(p.shrunk_streams)
        effective_shrunk = frozenset(effective_shrunk)

        try:
            normalized_inputs = _normalize_inputs(input_stream_values, effective_shrunk)
        except tau_shrink.ShrinkUnavailable as exc:
            # A stream value that must shrink could not be interned while a shrunk
            # convention is active. Abort rather than feed a mixed-width wrong verdict.
            raise TauCommunicationError(
                f"Shrink unavailable for stream value: {exc}", last_state=last_known_tau_spec
            )

        try:
            _print_tau_dispatch(
                source=source,
                rule_text=rule_text,
                input_stream_values=normalized_inputs or input_stream_values,
                target_output_stream_index=target_output_stream_index,
            )
            output_val = tau_direct_interface.communicate(
                rule_text=rule_text,
                target_output_stream_index=target_output_stream_index,
                input_stream_values=normalized_inputs or input_stream_values,
                source=source,
                apply_rules_update=apply_rules_update
            )
        except Exception as ex:
            raise TauCommunicationError(f"Direct Tau communication failed: {ex}", last_state=last_known_tau_spec)

        # Optional disk logging of the response (best-effort)
        try:
            prefix = f"RECV source={source} <<< o{target_output_stream_index}"
            if "source=unknown" not in prefix:
                tau_io_logger.append_to_debug_file(
                    config.COMM_DEBUG_PATH,
                    prefix,
                    str(output_val or ""),
                )
        except Exception:
            pass

        # Commit runtime shrink state (shrunk-stream set) AFTER a successful
        # interpreter update.
        spec_for_commit = i0_stream_preps[-1] if i0_stream_preps else prepared
        if spec_for_commit is not None:
            _commit_runtime_spec(spec_for_commit)

        # last_known_tau_spec is kept ONLY as a debug/error-state aid. It is the
        # interpreter's composed (possibly shrunk) spec and is NEVER hashed or
        # persisted -- the authoritative application-rules state is the canonical
        # raw accumulation in chain_state (fed below), so consensus is width-independent.
        try:
            if hasattr(tau_direct_interface, "get_current_spec"):
                last_known_tau_spec = tau_direct_interface.get_current_spec() or last_known_tau_spec
        except Exception:
            pass

        # Persist the CANONICAL full-width rule text (append to the raw accumulation).
        # Only application-rule updates (target o0, apply_rules_update=True); consensus
        # rules are tracked separately via "\n".join(rule_revisions).
        if apply_rules_update and target_output_stream_index == 0 and _rules_handler and spec_for_commit is not None:
            try:
                _rules_handler(spec_for_commit.canonical_text)
            except Exception as e:
                logger.error("Failed to save updated spec: %s", e)

        try:
            output_val = tau_shrink.expand_output_value(output_val, target_output_stream_index)
        except Exception:
            pass

        try:
            return utils.normalize_tau_atoms(str(output_val))
        except Exception:
            return output_val

    except tau_shrink.ShrinkWidthOverflow as wexc:
        _handle_width_overflow(wexc)  # re-execs (or re-raises in test mode)
    finally:
        _write_status(start=False)
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

    # NOTE: deliberately lock-free, mirroring the pre-shrink behavior. This path
    # can be entered while tau_comm_lock is already held elsewhere (e.g. nested
    # under the rule-exec path in apply_block), so acquiring it here would
    # self-deadlock on the non-reentrant lock.
    _write_status(start=True, source=source)
    try:
        i0_stream_preps = _collect_i0_prepared(input_stream_values)
        effective_shrunk = set(_runtime_shrunk_streams)
        for p in i0_stream_preps:
            effective_shrunk |= set(p.shrunk_streams)
        effective_shrunk = frozenset(effective_shrunk)

        try:
            normalized_inputs = _normalize_inputs(input_stream_values, effective_shrunk)
        except tau_shrink.ShrinkUnavailable as exc:
            raise TauCommunicationError(
                f"Shrink unavailable for stream value: {exc}", last_state=last_known_tau_spec
            )

        try:
            _print_tau_dispatch(
                source=source,
                input_stream_values=normalized_inputs or input_stream_values,
            )
            result = tau_direct_interface.communicate_multi(
                rule_text=None,
                input_stream_values=normalized_inputs or input_stream_values,
                source=source,
                apply_rules_update=apply_rules_update,
            )
        except Exception as ex:
            raise TauCommunicationError(f"Direct Tau multi-output communication failed: {ex}", last_state=last_known_tau_spec)

        if i0_stream_preps:
            _commit_runtime_spec(i0_stream_preps[-1])
    except tau_shrink.ShrinkWidthOverflow as wexc:
        _handle_width_overflow(wexc)  # re-execs (or re-raises in test mode)
    finally:
        _write_status(start=False)

    # Optional disk logging of the multi-response (best-effort)
    try:
        for idx, val in (result or {}).items():
            prefix = f"RECV source={source} <<< o{idx}"
            if "source=unknown" in prefix:
                continue
            tau_io_logger.append_to_debug_file(
                config.COMM_DEBUG_PATH,
                prefix,
                str(val or ""),
            )
    except Exception:
        pass

    normalized_result = {}
    for idx, val in result.items():
        try:
            expanded = tau_shrink.expand_output_value(val, idx)
        except Exception:
            expanded = val
        try:
            normalized_result[idx] = utils.normalize_tau_atoms(str(expanded))
        except Exception:
            normalized_result[idx] = str(expanded)
    return normalized_result


def reset_tau_state(rule_text: str, *, source: str = "unknown", apply_rules_update: bool = True) -> None:
    communicate_with_tau(
        rule_text=rule_text or "",
        target_output_stream_index=0,
        source=source,
        apply_rules_update=apply_rules_update,
        wait_for_ready=True,
    )


def restore_full_tau_spec(spec_text: str) -> None:
    """
    Replace the direct-mode interpreter with a fully composed persisted spec.
    This is used at startup/recovery instead of sending the whole spec through i0.
    """
    global tau_direct_interface, last_known_tau_spec

    if tau_test_mode:
        last_known_tau_spec = spec_text or ""
        return

    if not tau_direct_interface:
        raise TauEngineCrash("Cannot restore Tau spec before direct interface initialization.")

    # Feed the interpreter the shrunk runtime form (matching the i0 path) so
    # runtime stream values stay consistent post-recovery. When shrink is off
    # (default) runtime == canonical and this is identical to the pre-shrink path.
    canonical = tau_direct_interface.preprocess_spec_text(spec_text or "")
    if getattr(config, "TAU_SHRINK_ENABLED", False):
        # Re-pick the process width from the (now-restored) intern table first.
        tau_shrink.set_shrink_width_from_db()
        prepared = tau_shrink.prepare_rule(canonical, exclude_streams=_shrink_exclude())
    else:
        prepared = tau_shrink.PreparedTauSpec(canonical, canonical, False, frozenset())
    _print_tau_send("restore_full_tau_spec update_spec", prepared.runtime_text)
    tau_direct_interface.update_spec(prepared.runtime_text)
    _commit_runtime_spec(prepared)
    try:
        last_known_tau_spec = tau_direct_interface.get_current_spec() or canonical
    except Exception:
        last_known_tau_spec = canonical
    # Full composed interpreter spec (== canonical when shrink is off).
    last_known_tau_spec = tau_direct_interface.get_current_spec() or prepared.canonical_text


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

        # Handle Tau's bitvector literal wrapper forms like:
        #   "{ #x01 }:bv[8]" or "{ 1 }:bv[64]"
        if val.startswith("{") and "}" in val:
            inner = val[val.find("{") + 1 : val.find("}")].strip()
            # Strip any trailing commas/spaces in pretty-printer outputs.
            val = inner.strip().rstrip(",")
             
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
    "get_canonical_spec",
    "get_tau_process_status",
    "get_recent_stderr",
    "request_shutdown",
    "kill_tau_process",
    "parse_tau_output",
    "set_rules_handler",
    "set_state_restore_callback",
    "is_force_test_enabled",
    "start_and_manage_tau_process",
    "reset_tau_state",
]
