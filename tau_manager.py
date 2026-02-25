import logging
import os
import queue
import re  # Added for regex matching
import select  # for non-blocking reads of subprocess pipes
import subprocess
import sys
import threading
import time
from collections import deque

# ANSI color codes for debug output
COLOR_BLUE = "\033[94m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_MAGENTA = "\033[95m"
COLOR_RESET = "\033[0m"

# Import shared state and config
import config
import tau_defs
import utils
from errors import TauCommunicationError, TauEngineCrash, TauEngineBug
import tau_native  # New module for direct bindings
import tau_io_logger



logger = logging.getLogger(__name__)

# --- Tau stdout prompt patterns -------------------------------------------------
# Tau prints prompts of the form:
#   i0[0]:tau :=
#   i1[0]:bv[16] :=
# and output "prompts" (the next line contains the value):
#   o0[0]:tau :=
#   o1[0]:bv :=
#
# IMPORTANT: Only `i*` prompts require *us* to write a value to stdin.
# `o*` prompts are *outputs*; we must never respond to them with input.
TAU_INPUT_PROMPT_RE = re.compile(r"^i(\d+)\[[^\]]*\]\s*(?::([^\s]+))?\s*(:=|=)\s*$")
TAU_OUTPUT_PROMPT_RE = re.compile(r"^o(\d+)\[[^\]]*\]\s*(?::[^\s]+)?\s*(:=|=)\s*$")
TAU_ANY_PROMPT_RE = re.compile(r"^(?:i|o)\d+\[[^\]]*\]\s*(?::[^\s]+)?\s*(:=|=)\s*$")

# --- Rule sanitation -----------------------------------------------------------
# Normalize all bitvector annotations to a default width (64-bit) before sending
# rules to Tau (e.g. :bv, :bv[1], :bv[16], :bv[128] -> :bv[64]).
#
# We intentionally scope this to type annotations (":bv") rather than replacing
# every "bv" substring in the rule text.
DEFAULT_RULE_BV_WIDTH = 16
_BV_TYPE_RE = re.compile(r":\s*bv(?:\s*\[\s*\d+\s*\])?")


def normalize_rule_bitvector_sizes(rule_text: str, default_width: int = DEFAULT_RULE_BV_WIDTH) -> str:
    """
    Normalize Tau rule text so that any bitvector type annotation `:bv` or
    `:bv[<n>]` becomes `:bv[<default_width>]`.

    Examples:
      - `{ #b0 }:bv` -> `{ #b0 }:bv[64]`
      - `{ #b0 }:bv[1]` -> `{ #b0 }:bv[64]`
      - `{ #b0 }:bv[128]` -> `{ #b0 }:bv[64]`
    """
    if not rule_text:
        return rule_text
    normalized, replacements = _BV_TYPE_RE.subn(f":bv[{int(default_width)}]", rule_text)
    if replacements:
        logger.debug(
            "normalize_rule_bitvector_sizes: rewrote %s ':bv' annotations to ':bv[%s]'",
            replacements,
            default_width,
        )
    return normalized

# --- Global State (accessible by this module) ---
tau_process: subprocess.Popen | None = None
tau_process_lock = threading.Lock()  # Protects tau_process, current_cidfile_path
tau_comm_lock = threading.Lock()     # Serializes High-Level IO exchanges
tau_ready = threading.Event()        # Signals when Tau is FULLY ready (restored & accepting clients)
tau_process_ready = threading.Event() # Signals when Tau process is up (but maybe not restored)
restart_in_progress = threading.Event() # Debounce flag for restarts

server_should_stop = threading.Event()  # Signals background threads to stop
# Using deque for lock-free-ish appends (GIL helps) or standard deque ops
tau_stderr_lines = deque(maxlen=100)  # Store recent stderr lines
tau_test_mode = False  # When True, simulate Tau responses without Docker
_rules_handler = None  # Callback for saving rules state
_state_restore_callback = None # Callback for restoring state on restart
current_cidfile_path: str | None = None # Path to current Docker CID file
last_known_tau_spec: str | None = None # Tracks the last valid spec seen from Tau
tau_direct_interface: tau_native.TauInterface | None = None # Instance of the direct binding interface


def set_rules_handler(handler):
    """Sets the callback function for handling rules state updates."""
    global _rules_handler
    _rules_handler = handler


def set_state_restore_callback(handler):
    """
    Sets the callback function for restoring state (rules) after a process restart.
    This callback is invoked after `tau_process_ready` is set but before `tau_ready` is set.
    """
    global _state_restore_callback
    _state_restore_callback = handler

def read_stderr():
    """
    Reads stderr from the Tau process, prints it live, and puts lines into a thread-safe deque.
    """
    # Access global state safely
    global tau_process, tau_stderr_lines, server_should_stop, tau_process_lock
    logger.info("[stderr_reader] Starting stderr reader thread.")
    try:
        # Check if process and stream exist at the start
        process_exists = False
        stderr_stream = None
        with tau_process_lock:  # Ensure we check the process state safely
            if tau_process and tau_process.stderr:
                process_exists = True
                stderr_stream = tau_process.stderr

        if process_exists and stderr_stream:
            for line in iter(stderr_stream.readline, ''):
                if server_should_stop.is_set():
                    logger.info("[stderr_reader] Stop signal received.")
                    break
                line_strip = line.strip()
                if line_strip:
                    # Print live stderr output
                    logger.info(f"{COLOR_YELLOW}[TAU_STDERR] %s{COLOR_RESET}", line_strip)
                    # Store in deque
                    tau_stderr_lines.append(line_strip)
                    # Log to io crash buffer
                    tau_io_logger.log_stderr(line_strip)
                # Add a small sleep if Tau is very chatty on stderr to prevent high CPU
                # time.sleep(0.001)
        else:
            # This is expected if the process fails to start
            logger.info("[stderr_reader] Tau process or stderr stream not available at thread start.")
    except ValueError:  # Can happen if stderr is closed
        logger.info("[stderr_reader] Tau process stderr stream closed.")
    except Exception as e:
        logger.error("[stderr_reader] Exception: %s", e)
    finally:
        logger.info("[stderr_reader] Stopping stderr reader thread.")


def start_and_manage_tau_process():
    """
    Starts the Tau Docker process in the background, waits for the ready signal,
    and monitors it. Runs in a loop attempting restarts until server_should_stop is set.
    """
    # Access global state safely
    global tau_process, tau_ready, tau_process_ready, server_should_stop, tau_process_lock, tau_test_mode, current_cidfile_path, restart_in_progress

    # Ensure previous stop signals from earlier runs are cleared when starting anew
    server_should_stop.clear()
    tau_ready.clear()
    tau_process_ready.clear()
    restart_in_progress.clear()
    tau_test_mode = False
    last_known_tau_spec = None

    # Fast path: allow forcing TEST MODE via environment (default disabled for tests)
    if os.environ.get("TAU_FORCE_TEST", "0") == "1":
        logger.warning("TAU_FORCE_TEST enabled. Running in TEST MODE without Docker.")
        tau_test_mode = True
        tau_process_ready.set()
        tau_ready.set()
        # Idle loop until shutdown requested
        while not server_should_stop.is_set():
            time.sleep(0.05)
        logger.info("Server shutdown requested, Tau manager exiting.")
        return

    # Direct Bindings Mode
    if config.settings.tau.use_direct_bindings:
        logger.info("Direct Bindings Mode Enabled. Initializing Tau Native Interface...")
        global tau_direct_interface
        try:
             tau_direct_interface = tau_native.TauInterface(config.TAU_PROGRAM_FILE)
             logger.info("Tau Native Interface initialized successfully.")
             tau_process_ready.set() # Signal that "process" (interface) is up

             # Invoke State Restore Callback (loads rules from DB or Disk)
             if _state_restore_callback:
                 try:
                     logger.info("Invoking state restore callback (Direct Mode)...")
                     _state_restore_callback()
                     logger.info("State restore callback completed successfully.")
                 except Exception as e:
                     logger.error("State restore callback failed in Direct Mode: %s", e)
                     # We proceed even if it fails? Or fail the init?
                     # In Docker mode we kill/retry. Here we probably just log error and proceed or exit.
                     # Let's retry/exit to be safe, but for now just logging as the user can restart.
                     pass

             tau_ready.set()

             
             # Loop until shutdown
             while not server_should_stop.is_set():
                 time.sleep(1)
             logger.info("Server shutdown requested, Tau manager exiting (Direct Mode).")
             return
        except Exception as e:
            logger.critical(f"Failed to initialize Tau Native Interface: {e}")
            # Ensure we don't block indefinitely if init fails, maybe retry or exit?
            # For now, let's treat it as a fatal error for the manager thread
            return

    failure_count = 0
    import tempfile 
    
    while not server_should_stop.is_set():
        logger.info("Starting Tau Docker process...")
        tau_ready.clear()  # Clear ready flag for new process
        tau_process_ready.clear()
        
        # Prepare CID file
        cid_file_fd, cid_file_path = tempfile.mkstemp(prefix="tau-cid-", suffix=".cid")
        os.close(cid_file_fd)
        if os.path.exists(cid_file_path):
             os.remove(cid_file_path) # docker requires it not to exist usually, or we overwrite

        # Make sure process logic is reset
        with tau_process_lock:
            tau_process = None
            current_cidfile_path = cid_file_path

        host_abs_path = os.path.abspath(config.TAU_PROGRAM_FILE)
        host_dir = os.path.dirname(host_abs_path)
        tau_filename = os.path.basename(host_abs_path)
        container_tau_file_path = f"{config.CONTAINER_WORKDIR}/{tau_filename}"

        docker_command = [
            'docker', 'run', '--rm', '-i',
            '--cidfile', cid_file_path,
            '-v', f"{host_dir}:{config.CONTAINER_WORKDIR}",
            config.TAU_DOCKER_IMAGE,
            # 'stdbuf', '-oL', '-eL',
            container_tau_file_path
        ]

        stderr_thread = None
        current_process = None  # Local variable for the Popen object
        ready_signal_found = False
        
        try:
            # Start the process
            logger.info(
                "Launching Tau via Docker (cidfile=%s, program=%s). ",
                cid_file_path,
                container_tau_file_path
            )
            logger.debug("Tau docker command: %s", " ".join(docker_command))
            current_process = subprocess.Popen(
                docker_command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding='utf-8',
                bufsize=1  # Line buffering
            )
            # Set the global process variable *only after* successful start
            with tau_process_lock:
                tau_process = current_process

            logger.info(
                "Tau process started (PID: %s). Waiting for ready signal: '%s'",
                current_process.pid,
                config.TAU_READY_SIGNAL,
            )

            # Start stderr reader thread for this process
            stderr_thread = threading.Thread(target=read_stderr, daemon=True)
            stderr_thread.start()

            # --- Wait for ready signal --- (with timeout)
            ready_signal_found = False
            stdout_stream = current_process.stdout
            if stdout_stream:
                start_time = time.monotonic()
                while time.monotonic() - start_time < config.PROCESS_TIMEOUT:
                    if server_should_stop.is_set():
                        logger.info("Server stopping during Tau startup wait.")
                        break
                    # Check if process exited while waiting
                    if current_process.poll() is not None:
                        logger.error("Tau process exited unexpectedly while waiting for ready signal.")
                        break  # Exit the loop

                    buf = bytearray()
                    fd_init = stdout_stream.fileno()
                    while True:
                        # Check strict timeout INSIDE read loop too
                        elapsed = time.monotonic() - start_time
                        if elapsed >= config.PROCESS_TIMEOUT:
                             break
                        if elapsed > 10 and elapsed % 10:
                            logger.warning("Tau process startup taking too long. %d seconds elapsed. PID: %s", elapsed, current_process.pid)
                        rlist, _, _ = select.select([fd_init], [], [], 0.1)
                        if not rlist:
                            # Re-check stop signal during idle waits
                            if server_should_stop.is_set():
                                break
                            continue

                        chunk = os.read(fd_init, 1)
                        if not chunk:  # EOF
                            break
                        buf += chunk
                        if chunk == b'\n':
                            break
                        if config.TAU_READY_SIGNAL.encode() in buf:
                            break
                    
                    # Check if we broke due to timeout/stop
                    if time.monotonic() - start_time >= config.PROCESS_TIMEOUT or server_should_stop.is_set():
                        break

                    line = buf.decode('utf-8', errors='replace')
                    if not line:
                        logger.error("Tau process stdout stream ended before sending ready signal.")
                        break
                    
                    logger.debug(f"{COLOR_BLUE}[TAU_STDOUT_INIT] %s{COLOR_RESET}", line.strip())
                    if config.TAU_READY_SIGNAL in line:
                        logger.info("Tau ready signal detected!")
                        
                        # 1. Signal process is UP (but state not restored yet)
                        tau_process_ready.set()
                        
                        # 2. Attempt State Restore (if configured)
                        restore_success = True
                        if _state_restore_callback:
                            try:
                                logger.info("Invoking state restore callback...")
                                _state_restore_callback()
                                logger.info("State restore callback completed successfully.")
                            except Exception as e:
                                logger.error("State restore callback failed: %s", e)
                                restore_success = False
                                # If restore fails, we DO NOT mark tau_ready.
                                # Kill the process to trigger a retry.
                                logger.error("State restore failed. Killing process to trigger retry.")
                                kill_tau_process()
                                break # Break from while loop to restart process
                        
                        # 3. Signal FULL readiness ONLY if restore succeeded
                        if restore_success:
                            tau_ready.set()
                            
                            # 4. Clear restart flag (we are back up)
                            restart_in_progress.clear()
                            
                            # Clear safe mode flag if it was set
                            if os.environ.get("TAU_FORCE_FRESH_START") == "1":
                                logger.info("Safe Mode restart successful. Clearing TAU_FORCE_FRESH_START flag.")
                                os.environ.pop("TAU_FORCE_FRESH_START", None)
                            
                            ready_signal_found = True
                            break
                # End of while loop

                if not ready_signal_found and current_process.poll() is None:
                    logger.error(
                        "Timeout waiting for Tau ready signal ('%s') after %s seconds.",
                        config.TAU_READY_SIGNAL,
                        config.PROCESS_TIMEOUT,
                    )
            else:
                if current_process.poll() is None:
                    logger.error("Tau process stdout stream not available.")
            # --- End of ready signal check ---

            # If ready, reset failures and monitor the process until it exits
            if ready_signal_found:
                logger.info("Tau process is ready and running. Monitoring...")
                failure_count = 0
                wait_result = current_process.wait()  # Wait for the process to exit naturally
                logger.info("Tau process exited with code %s.", wait_result)
            # If not ready (due to timeout, early exit, or error), the process should be handled below

        except FileNotFoundError:
            logger.error("'docker' command not found. Cannot start Tau process.")
            current_process = None
            failure_count += 1
        except Exception as e:
            logger.error("Failed to start or initially manage Tau process: %s", e)
            failure_count += 1

        finally:
            # --- Cleanup for this attempt ---
            with tau_process_lock:
                # If the process object we were tracking still exists...
                if current_process:
                    # Ensure it's terminated if it's still running
                    if current_process.poll() is None:
                        logger.info("Terminating potentially running Tau process after loop/error...")
                        try:
                            current_process.terminate() # SIGTERM to docker client
                            current_process.wait(timeout=2)
                        except Exception as term_e:
                            logger.warning("Error during cleanup termination: %s", term_e)
                            try:
                                current_process.kill()  # Force kill if terminate fails
                                current_process.wait(timeout=1)
                            except Exception as kill_e:
                                logger.error("Error during cleanup kill: %s", kill_e)
                    else:
                        logger.info(
                            "Tau process (%s) already exited before final cleanup.",
                            current_process.pid if hasattr(current_process, "pid") else "unknown PID",
                        )

                # Mark global state as not running / not ready
                if tau_process is current_process:
                    tau_process = None
                    tau_ready.clear()
                    tau_process_ready.clear()
                    # We DO NOT clear current_cidfile_path here immediately
                    # to allow external kill logic to find it if needed?
                    # But here we just killed it.
                
                # Now safe to clear global path if it matches
                if current_cidfile_path == cid_file_path:
                    current_cidfile_path = None


            # Make sure stderr thread finishes if it was started
            if stderr_thread and stderr_thread.is_alive():
                logger.info("Waiting for stderr reader thread to finish...")
                stderr_thread.join(timeout=1)
                if stderr_thread.is_alive():
                    logger.warning("Stderr reader thread did not exit cleanly.")
            
            # Robust cleanup: Ensure docker container is dead via CID file (run OUTSIDE tau_process_lock)
            if os.path.exists(cid_file_path):
                 try:
                     # Read CID to be sure (optional, but good for logging)
                     with open(cid_file_path, 'r') as f:
                         cid = f.read().strip()
                     
                     if cid:
                         # Attempt docker kill just in case terminate() didn't catch the container
                         # Use timeouts to avoid hanging
                         subprocess.run(['docker', 'kill', cid], capture_output=True, timeout=5)
                         subprocess.run(['docker', 'rm', cid], capture_output=True, timeout=5)
                     
                     os.remove(cid_file_path)
                 except Exception:
                     pass
            # --- End of Cleanup ---

        # Count a failure if not ready this iteration
        if not ready_signal_found:
            failure_count += 1

        # Fallback to test mode ONLY if allowed by config
        if failure_count >= 3 and not server_should_stop.is_set():
             # Only enable in 'test' environment
             env_safe = config.settings.env == 'test'
             if not tau_test_mode and env_safe:
                logger.warning(
                    "Enabling Tau TEST MODE after repeated startup failures. Tau responses will be simulated."
                )
                tau_test_mode = True
                tau_process_ready.set()
                tau_ready.set()
                restart_in_progress.clear() # Fix: clear restart flag in test mode

        # Restart logic (outside finally block)
        if not server_should_stop.is_set() and not tau_test_mode:
            logger.warning(
                "Tau process management loop finished for one instance. Waiting 5s before attempting restart."
            )
            time.sleep(5)

    logger.info("Server shutdown requested, Tau manager exiting.")


def communicate_with_tau(
    rule_text: str | None = None,
    target_output_stream_index: int = 0,
    input_stream_values: dict[int | str, str | list[str]] | None = None,
    source: str = "unknown",
    apply_rules_update: bool = True,
    wait_for_ready: bool = True,
):
    """
    Sends input to the persistent Tau process via stdin and reads the corresponding
    output from stdout, focusing on a specific output stream.

    Args:
        rule_text (str | None): Legacy single-stream payload written whenever Tau prompts
            the stream identified by target_output_stream_index. Primarily used for rule input (i0).
        target_output_stream_index (int): The index of the Tau output stream (e.g., 0 for o0, 1 for o1)
                                         from which to primarily parse the output.
        input_stream_values (dict | None): Optional mapping of Tau input stream indices to the
            exact value(s) that should be written when Tau prompts them. Each dict value can be
            a single string/int or an iterable of such values, which will be consumed in order.
        source (str): Identifier for the source of this communication (e.g., "node_A", "main").
                      Used for debug logging to distinguish interleaved commands.
        wait_for_ready (bool): If True (default), this function will block and wait for Tau to
                               be ready if it is currently restarting or down. It will also
                               automatically retry the operation after a crash/restart.
                               Set to False for internal calls (like state restoration) that
                               happen during the startup/init phase.

    Returns:
        str: The parsed Tau output line from Tau's stdout from the target output stream.

    Raises:
        TauEngineCrash: If Tau process is not running/ready (and wait_for_ready=False).
        TauCommunicationError: If communication fails or times out (and wait_for_ready=False).
    """
    global tau_process, tau_process_lock, tau_ready, tau_process_ready, tau_comm_lock, restart_in_progress, last_known_tau_spec
    
    logger.info(
        "communicate_with_tau(rule_text=%s, target_output=%s, input_stream_values=%s, source=%s, wait=%s)",
        rule_text[:50] + "..." if rule_text and len(rule_text) > 50 else rule_text,
        target_output_stream_index,
        input_stream_values,
        source,
        wait_for_ready
    )

    # Track total wait time to prevent infinite hangs
    total_wait_time = 0.0
    
    while True:
        # 0. Wait for Readiness (if requested)
        if wait_for_ready:
            wait_step = config.CLIENT_WAIT_TIMEOUT * 2
            if not tau_ready.wait(timeout=wait_step):
                total_wait_time += wait_step
                logger.warning("communicate_with_tau: Timeout waiting for Tau readiness (total wait: %.1fs). Retrying...", total_wait_time)
                
                
                if total_wait_time > config.PROCESS_TIMEOUT + 60:
                     msg = f"Timed out ({total_wait_time}s) waiting for Tau to become ready."
                     filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                     if filepath:
                         logger.error(f"Dumped Tau crash log to {filepath}")
                     raise TauEngineCrash(msg)

                if server_should_stop.is_set():
                    msg = "Server is stopping."
                    filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                    if filepath:
                         logger.error(f"Dumped Tau crash log to {filepath}")
                    raise TauEngineCrash(msg)
                # Loop back to check readiness again
                continue

        # 1. Acquire High-Level Comm Lock (Serialization)
        try:
            tau_comm_lock.acquire()
        except Exception as e:
            logger.error("Failed to acquire tau_comm_lock: %s", e)
            raise TauCommunicationError("Failed to acquire communication lock")

        # Flag to indicate if *this* call triggered a kill/restart
        _this_call_triggered_kill = False

        try:
            # DIRECT BINDINGS PATH
            if config.settings.tau.use_direct_bindings and not tau_test_mode:
                if not tau_direct_interface:
                     msg = "Direct Tau Interface used but not initialized."
                     filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                     if filepath:
                         logger.error(f"Dumped Tau crash log to {filepath}")
                     raise TauEngineCrash(msg)
                
                # Sanitize inputs: remove newlines (enforce single line)
                if rule_text:
                    rule_text = rule_text.replace('\n', ' ')

                # Normalize inputs (rule_text) similarly to _send_value_to_tau
                if rule_text and rule_text.lstrip().startswith("always"):
                    rule_text = normalize_rule_bitvector_sizes(rule_text)

                # Normalize values in input_stream_values
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
                    logger.error(f"Direct Tau communication failed: {ex}")
                    raise TauCommunicationError(
                        f"Direct Tau communication failed: {ex}",
                        last_state=last_known_tau_spec,
                    )

                current_full_spec = None
                if hasattr(tau_direct_interface, "get_current_spec"):
                    try:
                        current_full_spec = tau_direct_interface.get_current_spec()
                    except Exception:
                        current_full_spec = None

                if current_full_spec:
                    last_known_tau_spec = current_full_spec
                elif rule_text is not None and target_output_stream_index == 0:
                    # Fallback for diagnostics if direct interface didn't expose spec.
                    last_known_tau_spec = rule_text

                if (
                    apply_rules_update
                    and rule_text is not None
                    and target_output_stream_index == 0
                    and _rules_handler
                    and last_known_tau_spec
                ):
                    try:
                        _rules_handler(last_known_tau_spec)
                    except Exception as e:
                        logger.error("Failed to save updated spec: %s", e)

                try:
                    output_val = utils.normalize_tau_atoms(str(output_val))
                except Exception:
                    pass
                return output_val


            # Check if a restart is needed or in progress
            # Check if a restart is needed or in progress
            if restart_in_progress.is_set():
                 # If we are not waiting (internal call like restore) AND the process is physically up, proceed.
                 if not (not wait_for_ready and tau_process_ready.is_set()):
                     msg = "Tau process is restarting. Please retry later."
                     filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                     if filepath:
                         logger.error(f"Dumped Tau crash log to {filepath}")
                     raise TauEngineCrash(msg)
                 
            if not tau_process and not tau_test_mode:
                 msg = "Tau process is not initialized."
                 filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                 if filepath:
                     logger.error(f"Dumped Tau crash log to {filepath}")
                 raise TauEngineCrash(msg)

            # Prepare input queues (Rebuild every attempt as deque is consumed)
            stream_input_queues: dict[int, deque[str]] = {}
            if input_stream_values:
                for raw_idx, raw_value in input_stream_values.items():
                    if raw_value is None:
                        continue
                    try:
                        idx = int(raw_idx)
                    except (TypeError, ValueError):
                        logger.debug("communicate_with_tau: Skipping non-integer stream index %s", raw_idx)
                        continue

                    if isinstance(raw_value, (list, tuple)):
                        values = [str(v) for v in raw_value if v is not None]
                    else:
                        values = [str(raw_value)]

                    if not values:
                        continue
                    stream_input_queues[idx] = deque(values)

            # 2. Check Process Readiness (Check internal process-up signal)
            if not tau_process_ready.is_set() and not tau_test_mode:
                msg = "Tau process is not running (not signaled ready)."
                filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                if filepath:
                     logger.error(f"Dumped Tau crash log to {filepath}")
                raise TauEngineCrash(msg)

            # If in fake mode, synthesize minimal responses
            if tau_test_mode:
                if target_output_stream_index == 0:
                    return tau_defs.ACK_RULE_PROCESSED
                elif target_output_stream_index == 1:
                    # Emulate built-in transfer rule semantics: on success, o1 echoes i1.
                    # Fall back to generic success when no transfer amount was provided.
                    amount_q = stream_input_queues.get(1)
                    if amount_q:
                        return amount_q[0]
                    return tau_defs.TRANSACTION_VALIDATION_SUCCESS
                return tau_defs.TAU_VALUE_ZERO

            tau_output_line = tau_defs.TAU_VALUE_ZERO 

            # ----------------------------------------------------
            # INTERACTION LOOP
            # ----------------------------------------------------
            with tau_process_lock:
                # Double-check process status *after* acquiring lock
                if not tau_process or tau_process.poll() is not None:
                    tau_ready.clear() 
                    tau_process_ready.clear()
                    msg = "Tau process is not running."
                    filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                    if filepath:
                         logger.error(f"Dumped Tau crash log to {filepath}")
                    raise TauEngineCrash(msg)

                current_stdin = tau_process.stdin
                current_stdout = tau_process.stdout
                if not current_stdin or not current_stdout or current_stdin.closed or current_stdout.closed:
                    tau_ready.clear()
                    tau_process_ready.clear()
                    msg = "Tau process stdin/stdout pipes not available or closed."
                    filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                    if filepath:
                         logger.error(f"Dumped Tau crash log to {filepath}")
                    raise TauEngineCrash(msg)

                def _send_value_to_tau(stream_idx: int, value, reason: str):
                    """Helper that logs and writes a value to Tau's stdin."""
                    value_str = "" if value is None else str(value)
                    if value_str.lstrip().startswith("always"):
                        value_str = normalize_rule_bitvector_sizes(value_str)
                    logger.info(
                        f"{COLOR_MAGENTA}communicate_with_tau: Tau prompting on i%s. %s{COLOR_RESET}",
                        stream_idx,
                        reason,
                    )
                    for line_part in value_str.split('\n'):
                        logger.info(f"{COLOR_GREEN}Sending to Tau (stdin) >>> %s{COLOR_RESET}", line_part)
                    
                    if config.settings.tau.comm_debug_path:
                        try:
                            with open(config.settings.tau.comm_debug_path, "a") as debug_f:
                                prefix = f"[{source}] " if source else ""
                                debug_f.write(prefix + value_str + '\n')
                                debug_f.flush()
                        except Exception as e:
                            logger.error(f"Failed to write to comm_debug_path: {e}")

                    current_stdin.write(value_str + '\n')
                    current_stdin.flush()

                # State for the loop
                output_lines_read = []
                expect_stream_value_for = None  
                start_comm_time = time.monotonic()
                found_target_output = False  
                capturing_updated_spec = False
                updated_spec_lines: list[str] = []
                
                # Additional Diagnostics
                last_prompt_seen = "None"
                
                while True:
                    elapsed = time.monotonic() - start_comm_time 
                    if elapsed > config.COMM_TIMEOUT:
                        break
                    if 'waiting_for_next_i0' not in locals():
                        waiting_for_next_i0 = False
                    if elapsed > 10 and int(elapsed) % 10 == 0:
                        pid_val = tau_process.pid if tau_process else "unknown"
                        logger.warning("Tau process communication taking too long. %d seconds elapsed. PID: %s", elapsed, pid_val)

                    # Check if process died
                    if tau_process.poll() is not None:
                        exit_code = tau_process.poll()
                        stderr_lines = get_recent_stderr()
                        logger.error(
                            "communicate_with_tau: Tau process exited (code %s) while waiting for output.\n"
                            "Target stream: o%s\n"
                            "Recent stderr: %s",
                            exit_code,
                            target_output_stream_index,
                            "\n".join(stderr_lines)
                        )
                        tau_ready.clear()
                        tau_process_ready.clear()
                        msg = f"Tau process exited unexpectedly (code {exit_code})."
                        filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
                        if filepath:
                             logger.error(f"Dumped Tau crash log to {filepath}")
                        raise TauEngineCrash(msg)

                    # Read Loop
                    buf = bytearray()
                    fd = current_stdout.fileno()
                    
                    while True:
                        elapsed = time.monotonic() - start_comm_time
                        if elapsed >= config.COMM_TIMEOUT:
                             break
                        
                        rlist, _, _ = select.select([fd], [], [], 0.1)
                        if not rlist:
                            continue
                        chunk = os.read(fd, 1)
                        if not chunk:  # EOF
                            break
                        buf += chunk
                        if chunk == b'\n':
                            break
                        if b':=' in buf:  # prompt may arrive without newline
                            break
                    
                    # Check timeout again after read loop
                    if time.monotonic() - start_comm_time >= config.COMM_TIMEOUT:
                        if not restart_in_progress.is_set():
                            restart_in_progress.set()
                            _this_call_triggered_kill = True
                        raise TauCommunicationError(f"Timeout ({config.COMM_TIMEOUT}s) waiting for Tau stdout.")

                    line = buf.decode('utf-8', errors='replace')
                    line_strip = line.strip()

                    # Exit Logic: Execution Step
                    if line_strip.startswith("Execution step:"):
                        if capturing_updated_spec and updated_spec_lines:
                            updated_spec = "\n".join(updated_spec_lines).strip()
                            capturing_updated_spec = False
                            updated_spec_lines = []
                            if updated_spec and _rules_handler and apply_rules_update:
                                try:
                                    _rules_handler(updated_spec)
                                except Exception as e:
                                    logger.error("Failed to save updated spec: %s", e)
                                
                        break 

                    if line_strip == "":
                        continue

                    output_lines_read.append(line_strip)
                    logger.info(f"{COLOR_BLUE}[TAU_STDOUT] %s{COLOR_RESET}", line_strip)
                    tau_io_logger.log_stdout(line_strip)

                    if "(Error)" in line_strip:
                        msg = f"Tau failed: {line_strip}"
                        filepath = tau_io_logger.dump_crash_log("TauEngineBug", msg)
                        if filepath:
                             logger.error(f"Dumped Tau crash log to {filepath}")
                        raise TauEngineBug(msg)

                    # oN Prompt/Value Handling
                    if expect_stream_value_for is not None:
                        if expect_stream_value_for == target_output_stream_index:
                            tau_output_line = line_strip
                            found_target_output = True
                            waiting_for_next_i0 = True
                        expect_stream_value_for = None
                        continue

                    o_prompt_match = TAU_OUTPUT_PROMPT_RE.match(line_strip)
                    if o_prompt_match:
                        last_prompt_seen = f"o{o_prompt_match.group(1)} prompt"
                        expect_stream_value_for = int(o_prompt_match.group(1))
                        continue

                    # Spec Update Handling
                    updated_spec_match = re.match(r"^Updated\s*specification\:\s*(.*)$", line_strip)
                    if updated_spec_match:
                        inline = (updated_spec_match.group(1) or "").strip()
                        if inline:
                            last_known_tau_spec = inline
                            if _rules_handler and apply_rules_update:
                                try:
                                    _rules_handler(inline)
                                except Exception:
                                    pass
                            continue
                        capturing_updated_spec = True
                        updated_spec_lines = []
                        continue

                    if capturing_updated_spec:
                        if TAU_ANY_PROMPT_RE.match(line_strip):
                            updated_spec = "\n".join(updated_spec_lines).strip()
                            last_known_tau_spec = updated_spec
                            capturing_updated_spec = False
                            updated_spec_lines = []
                            if updated_spec and _rules_handler and apply_rules_update:
                                try:
                                    _rules_handler(updated_spec)
                                except Exception:
                                    pass
                        else:
                            updated_spec_lines.append(line_strip)
                            continue

                    # Input Prompt Handling
                    prompt_match = TAU_INPUT_PROMPT_RE.match(line_strip)
                    if prompt_match:
                        stream_idx = int(prompt_match.group(1))
                        last_prompt_seen = f"i{stream_idx} prompt"
                        param_type = prompt_match.group(2)
                        
                        stream_queue = stream_input_queues.get(stream_idx)
                        if stream_queue:
                            value_to_send = stream_queue.popleft()
                            if not stream_queue:
                                del stream_input_queues[stream_idx]
                            _send_value_to_tau(stream_idx, value_to_send, "Sending queued input")
                            continue

                        if stream_idx == target_output_stream_index and rule_text is not None:
                            _send_value_to_tau(stream_idx, normalize_rule_bitvector_sizes(rule_text), "Sending rule text")
                            if stream_idx == 0 and apply_rules_update:
                                last_known_tau_spec = rule_text
                            continue

                        fallback_value = "F" if stream_idx == 0 else tau_defs.TAU_VALUE_ZERO
                        if param_type and 'sbf' in param_type:
                            fallback_value = "0"
                        _send_value_to_tau(stream_idx, fallback_value, "Sending fallback")
                        continue

                    # Direct Assignment Handling
                    target_stream_name = f"o{target_output_stream_index}"
                    match = re.match(rf"^{re.escape(target_stream_name)}(?:\s*\[[^\]]*\])?\s*(?::[^\s]+)?\s*(?::=|=)\s*(.*)", line_strip)
                    if match:
                        tau_output_line = match.group(1).strip()
                        found_target_output = True
                        continue

                if not found_target_output and time.monotonic() - start_comm_time >= config.COMM_TIMEOUT:
                     if not restart_in_progress.is_set():
                         restart_in_progress.set()
                         _this_call_triggered_kill = True
                     raise TauCommunicationError(f"Timeout ({config.COMM_TIMEOUT}s) waiting for Tau output. Last prompt: {last_prompt_seen}", last_state=last_known_tau_spec)

            # Success!
            try:
                tau_output_line = utils.normalize_tau_atoms(tau_output_line)
            except Exception:
                pass
            return tau_output_line

        except (TauEngineCrash, TauCommunicationError) as e:
            if not wait_for_ready:
                # If caller doesn't want to wait (e.g. initial restore), we fail fast.
                if isinstance(e, TauCommunicationError):
                     if not hasattr(e, 'last_state') or e.last_state is None:
                         e.last_state = last_known_tau_spec
                     logger.critical("Tau failed (no-wait). triggering kill for safety.")
                     _this_call_triggered_kill = True
                raise e

            logger.warning("Tau communication failure (%s). Triggering Safe Mode and waiting for recovery...", e)
            
            # TRIGGER SAFE MODE
            os.environ["TAU_FORCE_FRESH_START"] = "1"
            
            if isinstance(e, TauCommunicationError):
                _this_call_triggered_kill = True

            # If this is a ProcessError, the process is already dead or dying.
            # If CommunicationError, we flag it for kill.
            
            # We must release the lock before waiting, which the finally block handles.
            # So we set a flag 'retry_needed' or just continue?
            # We can't continue from here essentially because we need 'finally' to run.
            # Python 'continue' in 'except' executes 'finally' then loops.
            time.sleep(1.0)
            continue

        except (OSError, ValueError) as e:
            logger.error("communicate_with_tau: IO Error: %s", e)
            tau_ready.clear()
            tau_process_ready.clear()
            raise TauCommunicationError(f"IO Error: {e}", last_state=last_known_tau_spec)
                
        finally:
            tau_comm_lock.release()
            if '_this_call_triggered_kill' in locals() and _this_call_triggered_kill:
                 logger.warning("Initiating Tau process kill due to communication timeout/error.")
                 kill_tau_process()


def reset_tau_state(rule_text: str, *, source: str = "unknown", apply_rules_update: bool = True) -> None:
    """
    Reset Tau state by sending a clear token followed by the provided spec.
    This keeps the process in sync with a known snapshot before applying new rules.
    """
    # Restore the snapshot (block until ready if needed)
    communicate_with_tau(
        rule_text=rule_text or "",
        target_output_stream_index=0,
        source=source,
        apply_rules_update=apply_rules_update,
        wait_for_ready=True,  # Ensure we block if Tau has crashed
    )


def get_tau_process_status():
    """Returns the status of the Tau process."""
    global tau_process, tau_ready, tau_process_lock, tau_direct_interface
    if config.settings.tau.use_direct_bindings:
        if tau_direct_interface:
            if tau_ready.is_set():
                return "Running and Ready"
            return "Running, Not Ready (Initializing)"
        return "Not Running"

    with tau_process_lock:
        if tau_process and tau_process.poll() is None:
            if tau_ready.is_set():
                return "Running and Ready"
            else:
                return "Running, Not Ready (Initializing)"
        else:
            return "Not Running"


def get_recent_stderr():
    """Returns a view of recent stderr lines."""
    global tau_stderr_lines
    # deque is iterable, returning list is safe snapshot
    return list(tau_stderr_lines)


def request_shutdown():
    """
    Signals all background threads and the main server loop to shut down.
    """
    global tau_direct_interface, last_known_tau_spec, tau_test_mode
    logger.info("Shutdown requested.")
    server_should_stop.set()
    last_known_tau_spec = None
    tau_direct_interface = None
    if config.settings.tau.use_direct_bindings:
        with tau_process_lock:
            tau_direct_interface = None
            tau_ready.clear()
            tau_process_ready.clear()
        return

    # Also attempt to terminate the process directly
    with tau_process_lock:
        if tau_process and tau_process.poll() is None:
            logger.info("Terminating Tau process...")
            tau_process.terminate()


def kill_tau_process():
    """
    Forcefully stops the Tau Docker container if it's running.
    This is a fallback for unclean shutdowns.
    """
    global tau_process, tau_ready, tau_process_ready, current_cidfile_path
    global tau_direct_interface, restart_in_progress

    if config.settings.tau.use_direct_bindings:
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
         return
    
    cid_to_kill = None
    
    # 1. Acquire lock only to capture state needed for kill
    with tau_process_lock:
        if current_cidfile_path and os.path.exists(current_cidfile_path):
             try:
                 with open(current_cidfile_path, 'r') as f:
                     cid_to_kill = f.read().strip()
             except Exception:
                 pass
    
    # 2. Run Docker kill commands OUTSIDE the lock
    if cid_to_kill:
         logger.warning("Force stopping Docker container %s...", cid_to_kill)
         try:
             # Add timeouts to prevent hanging
             subprocess.run(['docker', 'kill', cid_to_kill], capture_output=True, timeout=5)
             subprocess.run(['docker', 'rm', cid_to_kill], capture_output=True, timeout=5)
         except subprocess.TimeoutExpired:
             logger.error("Timeout while running docker kill/rm on %s", cid_to_kill)
         except Exception as e:
             logger.error("Error killing Docker container %s: %s", cid_to_kill, e)

    # 3. Re-acquire lock to clean up globals
    with tau_process_lock:
         # Double check if cid file still exists and matches
         if current_cidfile_path and os.path.exists(current_cidfile_path):
             try:
                 os.remove(current_cidfile_path)
             except Exception:
                 pass
             current_cidfile_path = None
             
         # Also kill Popen if needed (it might be dead by now)
         if tau_process and tau_process.poll() is None:
            logger.warning("Tau process Popen still alive. Forcefully killing object.")
            try:
                tau_process.kill()
            except Exception:
                pass

         # 3. Clear readiness flags immediately to stop new callers
         tau_ready.clear()
         tau_process_ready.clear()



def parse_tau_output(output_val: str) -> int:
    """
    Parses a Tau output string (decimal, binary #b..., hex #x...) into an integer.
    Examples:
      "123" -> 123
      "#b1111011" -> 123
      "#x7B" -> 123
      "#x7b" -> 123
    Returns the integer value. 
    If parsing fails, returns 0.
    """
    if not output_val:
        return 0
    val = output_val.strip()
    converted_val = 0
    try:
        # Some outputs might have extra text? sendtx handles "result: ..."
        # But here we just handle raw values or prefixed values.
        # User warned: "Tau can emit extra tokens".
        # Let's simple-strip known noise if any, but mostly focus on #b/#x
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

# Export for external use
__all__ = [
    "communicate_with_tau",
    "get_tau_process_status",
    "get_recent_stderr",
    "request_shutdown",
    "kill_tau_process",
    "parse_tau_output",
]
