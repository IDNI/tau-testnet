import subprocess
import threading
import time
import os
import select  # for non-blocking reads of subprocess pipes
import sys
import queue
import re  # Added for regex matching

# Import shared state and config
import config
import sbf_defs
import utils

# --- Global State (accessible by this module) ---
tau_process: subprocess.Popen | None = None
tau_process_lock = threading.Lock()
tau_ready = threading.Event()  # Signals when Tau process has printed the ready signal
server_should_stop = threading.Event()  # Signals background threads to stop
tau_stderr_lines = queue.Queue(maxsize=100)  # Store recent stderr lines

# A queue of inputs that should be sent when Tau prompts on a given iN stream.
# Key: stream index (int); Value: list[str] of inputs to send in FIFO order.
pending_inputs: dict[int, list[str]] = {}


def enqueue_input_for_stream(stream_idx: int, input_sbf: str):
    """
    Add an SBF string to be sent the next time Tau prompts on the given input stream.
    Ignores empty or whitespace-only strings.
    """
    global pending_inputs
    input_sbf = input_sbf.strip()
    if not input_sbf:
        return  # nothing to enqueue
    pending_inputs.setdefault(stream_idx, []).append(input_sbf)


def read_stderr():
    """
    Reads stderr from the Tau process, prints it live, and puts lines into a thread-safe queue.
    """
    # Access global state safely
    global tau_process, tau_stderr_lines, server_should_stop, tau_process_lock
    print("[INFO][stderr_reader] Starting stderr reader thread.")
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
                    print("[INFO][stderr_reader] Stop signal received.")
                    break
                line_strip = line.strip()
                if line_strip:
                    # Print live stderr output
                    print(f"\033[91m[TAU_STDERR_LIVE] {line_strip}\033[0m", file=sys.stderr)
                    # Store in queue (optional, keep for potential later inspection)
                    try:
                        tau_stderr_lines.put_nowait(line_strip)
                    except queue.Full:
                        try:
                            tau_stderr_lines.get_nowait()
                            tau_stderr_lines.put_nowait(line_strip)
                        except queue.Empty:
                            pass
                # Add a small sleep if Tau is very chatty on stderr to prevent high CPU
                # time.sleep(0.001)
        else:
            # This is expected if the process fails to start
            print("[INFO][stderr_reader] Tau process or stderr stream not available at thread start.")
    except ValueError:  # Can happen if stderr is closed
        print("[INFO][stderr_reader] Tau process stderr stream closed.")
    except Exception as e:
        print(f"[ERROR][stderr_reader] Exception: {e}")
    finally:
        print("[INFO][stderr_reader] Stopping stderr reader thread.")


def start_and_manage_tau_process():
    """
    Starts the Tau Docker process in the background, waits for the ready signal,
    and monitors it. Runs in a loop attempting restarts until server_should_stop is set.
    """
    # Access global state safely
    global tau_process, tau_ready, server_should_stop, tau_process_lock

    while not server_should_stop.is_set():
        print("[INFO][tau_manager] Starting Tau Docker process...")
        tau_ready.clear()  # Clear ready flag for new process
        # Make sure process is marked as None initially for this attempt
        with tau_process_lock:
            tau_process = None

        host_abs_path = os.path.abspath(config.TAU_PROGRAM_FILE)
        host_dir = os.path.dirname(host_abs_path)
        tau_filename = os.path.basename(host_abs_path)
        container_tau_file_path = f"{config.CONTAINER_WORKDIR}/{tau_filename}"

        docker_command = [
            'docker', 'run', '--rm', '-i',
            '-v', f"{host_dir}:{config.CONTAINER_WORKDIR}",
            config.TAU_DOCKER_IMAGE,
            # 'stdbuf', '-oL', '-eL',
            container_tau_file_path
        ]

        stderr_thread = None
        current_process = None  # Local variable for the Popen object
        try:
            # Start the process
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

            print(
                f"[INFO][tau_manager] Tau process started (PID: {current_process.pid}). Waiting for ready signal: '{config.TAU_READY_SIGNAL}'")

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
                        print("[INFO][tau_manager] Server stopping during Tau startup wait.")
                        break
                    # Check if process exited while waiting
                    if current_process.poll() is not None:
                        print("[ERROR][tau_manager] Tau process exited unexpectedly while waiting for ready signal.")
                        break  # Exit the loop

                    # Debug init: wait for newline or prompt without newline
                    buf = bytearray()
                    fd_init = stdout_stream.fileno()
                    # print(f"[DEBUG INIT] start init-read loop, fd={fd_init}")
                    while True:
                        # print(f"[DEBUG INIT] select on fd_init={fd_init}")
                        rlist, _, _ = select.select([fd_init], [], [], 0.1)
                        # print(f"[DEBUG INIT] select returned rlist={rlist}")
                        if not rlist:
                            continue
                        chunk = os.read(fd_init, 1)
                        # print(f"[DEBUG INIT] read chunk={chunk!r}")
                        if not chunk:  # EOF
                            # print("[DEBUG INIT] EOF on init read")
                            break
                        buf += chunk
                        if chunk == b'\n':
                            # print("[DEBUG INIT] newline detected on init")
                            break
                        if config.TAU_READY_SIGNAL.encode() in buf:
                            # print("[DEBUG INIT] ready signal bytes detected in buf")
                            break
                    line = buf.decode('utf-8', errors='replace')
                    if not line:
                        print("[ERROR] Tau process stdout stream ended before sending ready signal.")
                        break
                    print(f"\033[93m[TAU_STDOUT_INIT] {line.strip()}\033[0m")
                    if config.TAU_READY_SIGNAL in line:
                        print("[INFO][tau_manager] Tau ready signal detected!")
                        tau_ready.set()
                        ready_signal_found = True
                        break
                # End of while loop (either signal found, timeout, process exit, or server stop)

                if not ready_signal_found and current_process.poll() is None:
                    # Loop finished due to timeout
                    print(
                        f"[ERROR][tau_manager] Timeout waiting for Tau ready signal ('{config.TAU_READY_SIGNAL}') after {config.PROCESS_TIMEOUT} seconds.")
            else:
                if current_process.poll() is None:
                    print("[ERROR][tau_manager] Tau process stdout stream not available.")
            # --- End of ready signal check ---

            # If ready, monitor the process until it exits
            if ready_signal_found:
                print("[INFO][tau_manager] Tau process is ready and running. Monitoring...")
                wait_result = current_process.wait()  # Wait for the process to exit naturally
                print(f"[INFO][tau_manager] Tau process exited with code {wait_result}.")
            # If not ready (due to timeout, early exit, or error), the process should be handled below

        except FileNotFoundError:
            print(f"[ERROR][tau_manager] 'docker' command not found. Cannot start Tau process.")
            # No process to clean up, just wait before retry
            current_process = None
        except Exception as e:
            print(f"[ERROR][tau_manager] Failed to start or initially manage Tau process: {e}")
            # current_process might be None or a failed Popen object

        finally:
            # --- Cleanup for this attempt ---
            with tau_process_lock:
                # If the process object we were tracking still exists...
                if current_process:
                    # Ensure it's terminated if it's still running
                    if current_process.poll() is None:
                        print("[INFO][tau_manager] Terminating potentially running Tau process after loop/error...")
                        try:
                            current_process.terminate()
                            current_process.wait(timeout=2)  # Short wait for termination
                        except Exception as term_e:
                            print(f"[WARN][tau_manager] Error during cleanup termination: {term_e}")
                            try:
                                current_process.kill()  # Force kill if terminate fails
                                current_process.wait(timeout=1)
                            except Exception as kill_e:
                                print(f"[ERROR][tau_manager] Error during cleanup kill: {kill_e}")
                    else:
                        # Process already exited, just log if needed
                        print(
                            f"[INFO][tau_manager] Tau process ({current_process.pid if hasattr(current_process, 'pid') else 'unknown PID'}) already exited before final cleanup.")

                # Mark global state as not running / not ready
                if tau_process is current_process:
                    tau_process = None
                    tau_ready.clear()

            # Make sure stderr thread finishes if it was started
            if stderr_thread and stderr_thread.is_alive():
                print("[INFO][tau_manager] Waiting for stderr reader thread to finish...")
                stderr_thread.join(timeout=1)
                if stderr_thread.is_alive():
                    print("[WARN][tau_manager] Stderr reader thread did not exit cleanly.")
            # --- End of Cleanup ---

        # Restart logic (outside finally block)
        if not server_should_stop.is_set():
            print(
                "[WARN][tau_manager] Tau process management loop finished for one instance. Waiting 5s before attempting restart.")
            time.sleep(5)

    print("[INFO][tau_manager] Server shutdown requested or fatal error, Tau manager thread exiting.")


def communicate_with_tau(input_sbf: str, target_output_stream_index: int = 1):
    """
    Sends an SBF string to the persistent Tau process via stdin
    and reads the corresponding SBF output from stdout, focusing on a specific output stream.

    Args:
        input_sbf (str): The SBF string to send.
        target_output_stream_index (int): The index of the Tau output stream (e.g., 0 for o0, 1 for o1)
                                         from which to primarily parse the output.

    Returns:
        str: The parsed SBF output line from Tau's stdout from the target output stream.

    Raises:
        Exception: If Tau process is not running/ready or communication fails/times out.
        TimeoutError: If Tau does not respond within COMM_TIMEOUT.
    """
    global tau_process, tau_process_lock, tau_ready  # Include tau_ready

    # Quick check if ready before locking
    if not tau_ready.is_set():
        raise Exception("Tau process is not ready.")

    with tau_process_lock:
        # Double-check process status *after* acquiring lock
        if not tau_process or tau_process.poll() is not None:
            tau_ready.clear()  # Mark as not ready if it died
            raise Exception("Tau process is not running.")

        # Perform checks within the lock
        current_stdin = tau_process.stdin
        current_stdout = tau_process.stdout
        if not current_stdin or not current_stdout or current_stdin.closed or current_stdout.closed:
            tau_ready.clear()  # Mark as not ready
            raise Exception("Tau process stdin/stdout pipes not available or closed.")

        # Determine if this is a raw Tau rule input for stream i0 (detect by target index and presence of '=')
        rule_text = input_sbf.strip()
        is_rule = False
        if target_output_stream_index == 0:
            # Treat as rule only if the text looks like a Tau rule (contains '=' or ':=' and is not just logical zero)
            if rule_text and rule_text not in {sbf_defs.SBF_LOGICAL_ZERO, '0', 'F'} and ('=' in rule_text):
                is_rule = True

        try:
            if is_rule:
                # Rule (i0) is sent immediately
                rule_line = rule_text if rule_text.endswith('.') or rule_text == sbf_defs.SBF_LOGICAL_ZERO else rule_text + '.'
                print(f"  [DEBUG] communicate_with_tau: Sending rule immediately for i0: '{rule_line}'")
                current_stdin.write(rule_line + '\n')
                current_stdin.flush()
            else:
                # Non-rule step: write multi-line input block immediately (i0..ik)
                if input_sbf.strip():
                    print(
                        f"  [DEBUG] communicate_with_tau: Sending multiline input block for step {target_output_stream_index}:\n{input_sbf}")
                    current_stdin.write(input_sbf + '\n')
                    current_stdin.flush()
                else:
                    print(
                        f"  [DEBUG] communicate_with_tau: No data for i{target_output_stream_index}; awaiting prompt.")

        except (OSError, BrokenPipeError, ValueError) as e:  # ValueError for closed stream
            print(f"[ERROR] communicate_with_tau: Error writing to Tau stdin: {e}")
            tau_ready.clear()  # Mark as not ready
            # Manager thread will handle restart
            raise Exception(f"Failed to write to Tau process stdin: {e}") from e

        # Read stdout line by line
        sbf_output_line = sbf_defs.SBF_LOGICAL_ZERO  # Default if no specific oN output found
        output_lines_read = []
        expect_stream_value_for = None  # track which oN prompt we're waiting for
        start_comm_time = time.monotonic()
        found_target_output = False  # Renamed from found_o1_output
        error_count = 0  # Track repeated errors to prevent infinite loops
        max_errors = 3  # Maximum number of errors before giving up
        try:
            while time.monotonic() - start_comm_time < config.COMM_TIMEOUT:
                # We may need to wait for Tau to prompt i0[...] := before returning
                if 'waiting_for_next_i0' not in locals():
                    waiting_for_next_i0 = False
                # Check if process died while we are waiting for output
                if tau_process.poll() is not None:
                    print("[ERROR] communicate_with_tau: Tau process exited while waiting for output.")
                    tau_ready.clear()
                    raise Exception("Tau process exited unexpectedly during communication.")

                # Read either until newline or until prompt ':=' appears, with debug
                buf = bytearray()
                fd = current_stdout.fileno()
                print(f"[DEBUG] prompt-detect: start read loop, fd={fd}")
                while True:
                    # print(f"[DEBUG] prompt-detect: select on fd={fd}")
                    rlist, _, _ = select.select([fd], [], [], 0.1)
                    # print(f"[DEBUG] prompt-detect: select returned rlist={rlist}")
                    if not rlist:
                        continue
                    chunk = os.read(fd, 1)
                    # print(f"[DEBUG] prompt-detect: read chunk={chunk!r}")
                    if not chunk:  # EOF
                        print("[DEBUG] prompt-detect: EOF reached")
                        break
                    if chunk == b'\n':
                        print("[DEBUG] prompt-detect: newline detected")
                        break
                    buf += chunk
                    # print(f"[DEBUG] prompt-detect: buf now={buf!r}")
                    if b':=' in buf:  # prompt may arrive without newline
                        print("[DEBUG] prompt-detect: prompt ':=' detected inside buf")
                        break
                line = buf.decode('utf-8', errors='replace')
                print(f"[DEBUG] prompt-detect: final line='{line}'")

                line_strip = line.strip()
                if line_strip == "":
                    print("  [DEBUG] communicate_with_tau: Ignoring blank line from Tau.")
                    continue

                # If we've captured our oN value, hold until we see the next i0 prompt
                if waiting_for_next_i0:
                    if re.match(r"^i0\[\d+\]\s*(:=|=)\s*$", line_strip):
                        print("  [DEBUG] communicate_with_tau: Next i0 prompt observed; returning to caller.")
                        break  # safe to return, caller will handle new step
                    # Do NOT respond to prompts while waiting
                    if line_strip.startswith('i'):
                        continue

                output_lines_read.append(line_strip)
                print(f"\033[93m  [TAU_STDOUT_COMM] {line_strip}\033[0m")

                # ---- Handle Tau errors ------------------------------------
                if "(Error)" in line_strip:
                    error_count += 1
                    print(f"[ERROR] communicate_with_tau: Tau reported an error ({error_count}/{max_errors}): {line_strip}")
                    # If it's a syntax error, we should fail fast rather than loop
                    if "Syntax Error" in line_strip:
                        raise Exception(f"Tau syntax error: {line_strip}")
                    # If we've seen too many errors, give up to prevent infinite loops
                    if error_count >= max_errors:
                        raise Exception(f"Too many errors from Tau ({error_count}). Last error: {line_strip}")
                    # For other errors, continue reading to see if there's more context
                    continue

                # ---- Handle oN prompts and values ------------------------------------
                # If the previous line was an oN prompt, THIS line is its value.
                if expect_stream_value_for is not None:
                    # This line is the value for o{expect_stream_value_for}
                    if expect_stream_value_for == target_output_stream_index:
                        sbf_output_line = line_strip  # keep only our target
                        print(
                            f"  [DEBUG] communicate_with_tau: Captured value for o{target_output_stream_index}: '{sbf_output_line}'")
                        found_target_output = True
                        waiting_for_next_i0 = True  # wait for new i0 prompt
                    # In every case, stop expecting another line
                    expect_stream_value_for = None
                    continue

                # Detect 'oN[...] :=' prompts signalling the next line contains the value.
                o_prompt_match = re.match(r"^o(\d+)\[[^\]]+\]\s*(:=|=)\s*$", line_strip)
                if o_prompt_match:
                    expect_stream_value_for = int(o_prompt_match.group(1))
                    print(
                        f"  [DEBUG] communicate_with_tau: Saw o{expect_stream_value_for} prompt; expecting its value next.")
                    continue
                # ---------------------------------------------------------------------

                # Handle Tau input prompts (e.g., "i1[0] :=", "i2[0] :=")
                prompt_match = re.match(r"^i(\d+)\[[^\]]+\]\s*(:=|=)\s*$", line_strip)
                if prompt_match:
                    stream_idx = int(prompt_match.group(1))
                    # If we have queued data for this stream, send the next piece; else send logical zero
                    if pending_inputs.get(stream_idx):
                        next_input = pending_inputs[stream_idx].pop(0)
                        print(f"  [DEBUG] communicate_with_tau: Tau prompting on i{stream_idx}. "
                              f"Sending queued input: '{next_input}'")
                        current_stdin.write(next_input + '\n')
                        current_stdin.flush()
                    elif is_rule and stream_idx == target_output_stream_index:
                        # Tau is prompting for the rule on the target input stream
                        rule_line = rule_text if rule_text.endswith('.') else rule_text + '.'
                        print(
                            f"  [DEBUG] communicate_with_tau: Tau prompting on i{stream_idx}. Sending rule: '{rule_line}'")
                        current_stdin.write(rule_line + '\n')
                        current_stdin.flush()
                    else:
                        print(f"  [DEBUG] communicate_with_tau: Tau prompting on i{stream_idx}. "
                              f"No queued input; sending SBF_LOGICAL_ZERO.")
                        current_stdin.write(sbf_defs.SBF_LOGICAL_ZERO + '\n')
                        current_stdin.flush()
                    continue

                # Specifically look for o<target_output_stream_index> assignment
                # Regex to match "oN[<any_digits_or_t>] = <sbf_part>" or "oN = <sbf_part>"
                # Tau source uses '=', not ':=' for oN assignment. Example: o0[t] = fail_code_value
                # Use target_output_stream_index in the regex
                target_stream_name = f"o{target_output_stream_index}"
                match = re.match(rf"^{re.escape(target_stream_name)}(?:\s*\[\w+\])?\s*=\s*(.*)", line_strip)
                if match:
                    sbf_candidate = match.group(1).strip()
                    # This sbf_candidate is the direct value assigned to oN by Tau.
                    sbf_output_line = sbf_candidate
                    found_target_output = True  # Renamed
                    print(
                        f"  [DEBUG] communicate_with_tau: Extracted SBF output for {target_stream_name}: '{sbf_output_line}' from line '{line_strip}'")
                    break  # Found definitive oN output, stop reading further lines for this communication

            if not found_target_output:
                # Loop finished due to timeout without finding a clear oN assignment
                all_output = "\n".join(output_lines_read)
                print(
                    f"[ERROR] communicate_with_tau: Timeout ({config.COMM_TIMEOUT}s) or no '{target_stream_name} = <value>' line found. Output read:\n{all_output}")
                # Check if process died right at the end
                if tau_process and tau_process.poll() is not None:
                    tau_ready.clear()
                    raise Exception(
                        f"Tau process exited just before communication timeout or without {target_stream_name} output.")
                # Fallback to old heuristic if no oN assignment found, this might catch echoes or other formats
                # but is less reliable. Consider if this fallback is desirable or should raise error.
                # For now, let's try to use the last plausible line if any was identified by the old heuristic
                # This part is a bit speculative and might need removal if it causes issues.
                print(
                    f"[WARN] communicate_with_tau: No explicit '{target_stream_name} = <value>' line found. Applying old heuristic to all read lines.")
                temp_sbf_output = sbf_defs.SBF_LOGICAL_ZERO
                for read_line in reversed(output_lines_read):
                    if utils.sbf_output_heuristic_check(read_line, input_sbf, sbf_defs):
                        temp_sbf_output = read_line
                        print(f"  [DEBUG] communicate_with_tau: Fallback heuristic chose line: '{temp_sbf_output}'")
                        break
                sbf_output_line = temp_sbf_output
                if not found_target_output and sbf_output_line == sbf_defs.SBF_LOGICAL_ZERO:  # if still default after fallback
                    raise TimeoutError(
                        f"Timeout or no valid SBF output from Tau for {target_stream_name} after {config.COMM_TIMEOUT} seconds. Check Tau logs for errors. Read output: {all_output}")

        except (OSError, ValueError) as e:
            print(f"[ERROR] communicate_with_tau: Error reading Tau stdout: {e}")
            tau_ready.clear()
            raise Exception(f"Failed to read from Tau process stdout: {e}") from e

        # Normalize output atoms to canonical '&'-separated sorted form
        try:
            sbf_output_line = utils.normalize_sbf_atoms(sbf_output_line)
        except Exception:
            pass
        return sbf_output_line


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
    """Returns a list of recent stderr lines from the queue."""
    global tau_stderr_lines
    lines = []
    while not tau_stderr_lines.empty():
        try:
            lines.append(tau_stderr_lines.get_nowait())
        except queue.Empty:
            break
    return lines


def request_shutdown():
    """
    Signals all background threads and the main server loop to shut down.
    """
    print("[INFO][tau_manager] Shutdown requested.")
    server_should_stop.set()
    # Also attempt to terminate the process directly
    with tau_process_lock:
        if tau_process and tau_process.poll() is None:
            print("[INFO][tau_manager] Terminating Tau process...")
            tau_process.terminate()


def kill_tau_process():
    """
    Forcefully stops the Tau Docker container if it's running.
    This is a fallback for unclean shutdowns.
    """
    with tau_process_lock:
        if tau_process and tau_process.poll() is None:
            print("[WARN][tau_manager] Tau process did not exit cleanly. Forcefully stopping Docker container.")
            # Get the container ID associated with our process if possible.
            # This is a bit of a hack. A better way would be to label the container on run.
            # For now, we'll just kill the Popen object. This might leave the container running.
            # A better approach is to use the docker command to stop the container by name/label.
            # Let's try to terminate it more forcefully.
            try:
                # The docker process is the parent of the shell that runs tau.
                # Killing the Popen object should send SIGTERM to the docker process.
                tau_process.kill()
                print("[INFO][tau_manager] Sent kill signal to Tau process.")
            except Exception as e:
                print(f"[ERROR][tau_manager] Error killing Tau process: {e}")


# Export for external use
__all__ = [
    "enqueue_input_for_stream",
    "communicate_with_tau",
    "get_tau_process_status",
    "get_recent_stderr",
    "request_shutdown",
    "kill_tau_process",
]
