import collections
import datetime
import os
import threading

# Rolling buffer to hold the last N lines of IO
_MAX_IO_LINES = 5000
_io_buffer = collections.deque(maxlen=_MAX_IO_LINES)
_io_lock = threading.Lock()

def _format_lines(prefix: str, content: str) -> list[str]:
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    lines: list[str] = []
    for line in (content or "").splitlines() or ["<empty>"]:
        lines.append(f"[{timestamp}] {prefix} {line}")
    return lines

def _append(prefix: str, content: str):
    """Safely append a formatted line to the circular buffer."""
    with _io_lock:
        for line in _format_lines(prefix, content):
            _io_buffer.append(line)


def append_to_debug_file(debug_path: str | None, prefix: str, content: str) -> None:
    """
    Best-effort append of IO lines to `debug_path`.

    - If `debug_path` is falsy, does nothing.
    - Creates parent directories if needed.
    - Never raises (logging should not break consensus / networking).
    """
    if not debug_path:
        return

    try:
        parent = os.path.dirname(os.path.abspath(debug_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
    except Exception:
        # If debug_path has no dirname (e.g. "tau_input.log"), dirname becomes cwd.
        pass

    try:
        with _io_lock:
            lines = _format_lines(prefix, content)
        with open(debug_path, "a", encoding="utf-8") as f:
            for line in lines:
                f.write(line + "\n")
    except Exception:
        # Best-effort: never fail the caller.
        return

def log_stdin(content: str):
    _append("STDIN  >>>", content)

def log_stdout(content: str):
    _append("STDOUT <<<", content)

def log_stderr(content: str):
    _append("STDERR !!!", content)

def log_native_input(stream_name: str, content: str):
    _append(f"NATIVE IN  [{stream_name}] >>>", content)

def log_native_output(stream_name: str, content: str):
    _append(f"NATIVE OUT [{stream_name}] <<<", content)

def log_native_stdout(content: str):
    _append("NATIVE STDOUT <<<", content)

def dump_crash_log(error_type: str, error_message: str):
    """
    Dumps the contents of the rolling buffer to a file in the logs/ directory.
    Returns the path to the crash log file.
    """
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d_%H%M%S")
    crash_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    try:
        os.makedirs(crash_dir, exist_ok=True)
    except FileExistsError:
        pass
    
    filename = f"tau_crash_{timestamp}.log"
    filepath = os.path.join(crash_dir, filename)

    with _io_lock:
        lines = list(_io_buffer)
    
    try:
        with open(filepath, "w") as f:
            f.write(f"--- TAU ENGINE CRASH DUMP ---\n")
            f.write(f"Time: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n")
            f.write(f"Error Type: {error_type}\n")
            f.write(f"Error Message: {error_message}\n")
            f.write(f"--- IO HISTORY (last {len(lines)} lines) ---\n")
            for line in lines:
                f.write(line + "\n")
            f.write(f"--- END OF DUMP ---\n")
        return filepath
    except Exception as e:
        import logging
        logging.getLogger(__name__).error(f"Failed to write tau crash log to {filepath}: {e}")
        return None
