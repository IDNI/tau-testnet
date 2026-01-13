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
from errors import TauCommunicationError, TauProcessError


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
# Some rules in the wild use an unsized bitvector annotation `:bv` instead of
# `:bv[64]` / `:bv[16]` / etc. Tau can be strict about typing, so we normalize
# unsized occurrences to a default width (64-bit) before sending rules to Tau.
#
# We intentionally scope this to type annotations (":bv") rather than replacing
# every "bv" substring in the rule text.
DEFAULT_RULE_BV_WIDTH = 64
_UNSIZED_BV_TYPE_RE = re.compile(r":\s*bv\b(?!\s*\[)")


def normalize_rule_bitvector_sizes(rule_text: str, default_width: int = DEFAULT_RULE_BV_WIDTH) -> str:
    """
    Normalize Tau rule text so that any unsized bitvector type annotation `:bv`
    becomes `:bv[<default_width>]`.

    Examples:
      - `{ #b0 }:bv` -> `{ #b0 }:bv[64]`
      - `x:t = y:bv[16]` (unchanged)
    """
    if not rule_text:
        return rule_text
    normalized, replacements = _UNSIZED_BV_TYPE_RE.subn(f":bv[{int(default_width)}]", rule_text)
    if replacements:
        logger.debug(
            "normalize_rule_bitvector_sizes: rewrote %s unsized ':bv' annotations to ':bv[%s]'",
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

    Returns:
        str: The parsed Tau output line from Tau's stdout from the target output stream.

    Raises:
        TauProcessError: If Tau process is not running/ready.
        TauCommunicationError: If communication fails or times out.
    """
    global tau_process, tau_process_lock, tau_ready, tau_process_ready, tau_comm_lock, restart_in_progress, last_known_tau_spec
    
    logger.info(
        "communicate_with_tau(rule_text=%s, target_output=%s, input_stream_values=%s)",
        rule_text,
        target_output_stream_index,
        input_stream_values,
    )

    # 1. Acquire High-Level Comm Lock (Serialization)
    # This prevents multiple threads from interleaving IO with Tau.
    try:
        tau_comm_lock.acquire()
    except Exception as e:
         raise TauCommunicationError(f"Failed to acquire communications lock: {e}")

    # Flag to indicate if *this* call triggered a kill/restart
    _this_call_triggered_kill = False

    try:
        # ----------------------------------------------------
        # PREPARATION
        # ----------------------------------------------------

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

        # 2. Check Process Readiness (Check internal process-up signal, not necessarily full 'readyfs')
        if not tau_process_ready.is_set() and not tau_test_mode:
            raise TauProcessError("Tau process is not running (not signaled ready).")

        # If in fake mode, synthesize minimal responses needed by tests
        if tau_test_mode:
            # For rule confirmations on o0, return non-zero ack
            if target_output_stream_index == 0:
                return tau_defs.ACK_RULE_PROCESSED
            # For transfer validation on o1, return success
            elif target_output_stream_index == 1:
                return tau_defs.TRANSACTION_VALIDATION_SUCCESS
            # For other streams, return logical zero by default
            return tau_defs.TAU_VALUE_ZERO

        tau_output_line = tau_defs.TAU_VALUE_ZERO # Initialize early!

        # ----------------------------------------------------
        # INTERACTION LOOP
        # ----------------------------------------------------
        with tau_process_lock:
            # Double-check process status *after* acquiring lock
            if not tau_process or tau_process.poll() is not None:
                tau_ready.clear() 
                tau_process_ready.clear()
                raise TauProcessError("Tau process is not running.")

            current_stdin = tau_process.stdin
            current_stdout = tau_process.stdout
            if not current_stdin or not current_stdout or current_stdin.closed or current_stdout.closed:
                tau_ready.clear()
                tau_process_ready.clear()
                raise TauProcessError("Tau process stdin/stdout pipes not available or closed.")

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
                            debug_f.write(value_str + '\n')
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
            error_count = 0  
            max_errors = 3
            
            # Additional Diagnostics
            last_prompt_seen = "None"
            
            try:
                while True:
                    elapsed = time.monotonic() - start_comm_time 
                    if elapsed > config.COMM_TIMEOUT:
                        break
                    # We may need to wait for Tau to prompt i0[...] := before returning
                    if 'waiting_for_next_i0' not in locals():
                        waiting_for_next_i0 = False
                    if elapsed > 10 and elapsed % 10:
                        logger.warning("Tau process communication taking too long. %d seconds elapsed. PID: %s", elapsed, current_process.pid)

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
                        raise TauProcessError(f"Tau process exited unexpectedly (code {exit_code}).")

                    # Read Loop
                    buf = bytearray()
                    fd = current_stdout.fileno()
                    
                    while True:
                        # Check strict timeout INSIDE read loop too
                        elapsed = time.monotonic() - start_comm_time
                        if elapsed >= config.COMM_TIMEOUT:
                             # TIMEOUT BREAK - handled below
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
                        # --- TIMEOUT DETECTED ---
                        # Set flag to indicate this call triggered the kill
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
                            if updated_spec and _rules_handler:
                                try:
                                    _rules_handler(updated_spec)
                                except Exception as e:
                                    logger.error("Failed to save updated spec: %s", e)
                        break # Return to caller

                    if line_strip == "":
                        continue

                    output_lines_read.append(line_strip)
                    logger.info(f"{COLOR_BLUE}[TAU_STDOUT] %s{COLOR_RESET}", line_strip)

                    # Error Handling
                    if "(Error)" in line_strip:
                        error_count += 1
                        logger.error("Tau Error (%s/%s): %s", error_count, max_errors, line_strip)
                        if "Syntax Error" in line_strip:
                            raise TauCommunicationError(f"Tau syntax error: {line_strip}")
                        if error_count >= max_errors:
                            raise TauCommunicationError(f"Too many errors ({error_count}). Last: {line_strip}")
                        continue

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
                            # Tracking state for error reporting
                            last_known_tau_spec = inline
                            if _rules_handler:
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
                            if updated_spec and _rules_handler:
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
                            # Optimistically update known spec if we sent a rule on i0 logic
                            # (Wait for echo confirmation usually, but this is a reasonable approximation for "last state used" context)
                            if stream_idx == 0:
                                last_known_tau_spec = rule_text
                            continue

                        fallback_value = "F" if stream_idx == 0 else tau_defs.TAU_VALUE_ZERO
                        # Special case: :sbf streams typically don't accept #b literals, expect decimal 0
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
                        break

                if not found_target_output and time.monotonic() - start_comm_time >= config.COMM_TIMEOUT:
                     # This case means the loop finished due to timeout, but no target output was found.
                     # The TimeoutError would have been raised earlier if it was within the read loop.
                     # This implies the process was alive but not producing expected output.
                     if not restart_in_progress.is_set():
                         restart_in_progress.set()
                         _this_call_triggered_kill = True
                     raise TauCommunicationError(f"Timeout ({config.COMM_TIMEOUT}s) waiting for Tau output. Last prompt: {last_prompt_seen}", last_state=last_known_tau_spec)

            except TauCommunicationError as e:
                # Log diagnostics for any TauCommunicationError (including timeouts)
                logger.critical(
                    "COMMUNICATION ERROR DETECTED.\n"
                    "Error: %s\n"
                    "Target Stream: o%s\n"
                    "Time Elapsed: %.2fs\n"
                    "Last Prompt Seen: %s\n"
                    "Waiting For Value: o%s\n"
                    "Last 20 Output Lines:\n%s\n"
                    "Recent Stderr:\n%s\n"
                    "Last Known Tau State:\n%s",
                    e,
                    target_output_stream_index,
                    time.monotonic() - start_comm_time,
                    last_prompt_seen,
                    expect_stream_value_for,
                    "\n".join(output_lines_read[-20:]),
                    "\n".join(get_recent_stderr()),
                    last_known_tau_spec if last_known_tau_spec else "N/A"
                )
                
                # Check if we should trigger Safe Mode for next restart
                # (Restart with Genesis + Predefined Rules)
                logger.warning("Setting TAU_FORCE_FRESH_START=1 to trigger Safe Mode (Genesis + Rules) on restart.")
                os.environ["TAU_FORCE_FRESH_START"] = "1"
                
                # If we construct a new error here, we ensure it carries the state
                if not hasattr(e, 'last_state') or e.last_state is None:
                     e.last_state = last_known_tau_spec

                raise e # Re-raise to be caught by outer block
            except (OSError, ValueError) as e:
                logger.error("communicate_with_tau: IO Error: %s", e)
                tau_ready.clear()
                tau_process_ready.clear()
                raise TauCommunicationError(f"IO Error: {e}", last_state=last_known_tau_spec)
                
    except TauCommunicationError as e:
        raise e
            
    finally:
        tau_comm_lock.release()
        # If this thread initiated a restart, trigger the kill AFTER releasing the lock.
        # This prevents deadlock where the restart logic (waiting for lock) blocks the killer (holding lock).
        if '_this_call_triggered_kill' in locals() and _this_call_triggered_kill:
             logger.warning("Initiating Tau process kill due to communication timeout/error.")
             kill_tau_process()

    # Normalize output atoms to canonical '&'-separated sorted form
    try:
        tau_output_line = utils.normalize_tau_atoms(tau_output_line)
    except Exception:
        pass
    return tau_output_line


def get_tau_process_status():
    """Returns the status of the Tau process."""
    global tau_process, tau_ready, tau_process_lock
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
    logger.info("Shutdown requested.")
    server_should_stop.set()
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
