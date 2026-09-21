import ctypes
import json
import logging
import os
import re
import subprocess
import tempfile
import sys
import threading
from collections import deque

from errors import TauEngineBug, TauEngineCrash
import tau_io_logger

# Setup logging
logger = logging.getLogger(__name__)


def _step_io_debug_enabled() -> bool:
    """
    Per-step IO logging in communicate()/communicate_multi() (Input Key, Step
    Inputs, [MEM] tau.step, Step Outputs) is extremely verbose: each Tau step
    emits ~20 DEBUG lines, and the miner ticks roughly once per second. Gate
    those lines behind an opt-in env var so plain DEBUG level stays usable.

    Set TAU_DEBUG_STEP_IO=1 (or true/yes/on) to re-enable.
    """
    return os.environ.get("TAU_DEBUG_STEP_IO", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


# Global reference to the loaded tau module
tau = None

# ANSI color codes for debug output
COLOR_BLUE = "\033[94m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_MAGENTA = "\033[95m"
COLOR_RESET = "\033[0m"
_INPUT_STREAM_NAME_RE = re.compile(r"^i\d+$")
_HEX_LITERAL_RE = re.compile(r"^[0-9a-fA-F]+$")

def get_memory_rss_mb() -> float:
    try:
        with open("/proc/self/statm") as f:
            pages = int(f.read().split()[1])
            page_size = os.sysconf("SC_PAGE_SIZE")
            return (pages * page_size) / (1024 * 1024)
    except Exception:
        return 0.0

_native_tau_dir: "str | None" = None


def native_tau_dir() -> "str | None":
    """Directory the native `tau` module was actually imported from (the dir
    holding tau*.so), or None if not yet loaded / found via a non-file path.
    Propagated to the isolated-compile subprocess via PYTHONPATH so the child
    imports the SAME module instead of re-discovering it (which fails when the
    parent found tau via a runtime sys.path insert the child cannot inherit)."""
    return _native_tau_dir


def load_tau_module():
    """
    Attempts to locate and import the native `tau` module.
    It searches in likely build directories within a sibling `tau-lang` repository.
    """
    global tau, _native_tau_dir
    if tau is not None:
        return tau

    # Common build patterns in tau-lang
    # Assuming we are in <workspace>/tau-testnet and tau-lang is in <workspace>/tau-lang
    workspace_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tau_lang_dir = os.path.join(workspace_dir, "tau-lang")
    
    # Candidate build paths relative to tau-lang root
    candidate_paths = [
        "build/bindings/python/nanobind",
        "build/Release/bindings/python/nanobind",
        "build-Release/bindings/python/nanobind",
        "build/Debug/bindings/python/nanobind",
        "build-Debug/bindings/python/nanobind",
    ]

    found_path = None
    for rel_path in candidate_paths:
        full_path = os.path.join(tau_lang_dir, rel_path)
        if os.path.exists(full_path):
            found_path = full_path
            break
    
    if found_path:
        logger.info(f"Found native tau module at: {found_path}")
        sys.path.insert(0, found_path)
        try:
            import tau as tau_module
            tau = tau_module
            _native_tau_dir = found_path
            return tau
        except ImportError as e:
            import glob
            so_files = glob.glob(os.path.join(found_path, "tau*.so"))
            
            logger.error(f"Failed to import native tau module from {found_path}: {e}")
            if so_files:
                logger.error(f"Found extension modules in directory: {[os.path.basename(f) for f in so_files]}")
                logger.error(f"Current Python version running server: {sys.version_info.major}.{sys.version_info.minor}")
                logger.error(f"Current Python executable: {sys.executable}")
                logger.error("Hint: There may be a Python version mismatch between the compiled module and your runtime. "
                             "Try activating your virtual environment before running CMake in tau-lang.")
            raise
    else:
        # Fallback: check if it's already in pythonpath
        try:
            import tau as tau_module
            tau = tau_module
            mod_file = getattr(tau_module, "__file__", None)
            if mod_file:
                _native_tau_dir = os.path.dirname(os.path.abspath(mod_file))
            logger.info("Found native tau module in PYTHONPATH")
            return tau
        except ImportError:
            logger.error("Could not find native tau module in candidates or PYTHONPATH")
            raise ImportError("Native tau module not found. Ensure tau-lang is built and accessible.")

# FD 1 is process-global, so StdOutCapture's save/redirect/restore cycle is a
# process-wide critical section: two threads inside it at once leak each other's
# pipe write end into the saved fd, which ends with stdout wired to a closed pipe
# ("[Errno 9] Bad file descriptor" out of the next native call) or a reader
# blocking forever on a pipe whose write end still lives on fd 1. Reentrant so a
# nested capture on the same thread (e.g. interpreter rebuild inside a step)
# still works. This is a safety net for engine entries that do NOT go through
# `tau_manager.tau_comm_lock` (interpreter construction, update_spec); the
# whole-call serialization that keeps the stateful interpreter coherent lives in
# tau_manager.
_stdout_capture_lock = threading.RLock()


class StdOutCapture:
    """
    Context manager to capture C-level stdout AND stderr output.
    Required because nanobind/C++ prints directly to file descriptors,
    bypassing sys.stdout / sys.stderr.

    Both fds matter: the native engine routes its `(Error)` diagnostics to
    fd 2, so a capture of fd 1 alone silently loses every engine error and
    makes the rule-validation gates no-ops. `output` is the concatenation of
    both streams so callers can screen it with `tau_reports_error()`.

    Backed by temp files rather than pipes: a pipe's ~64 KiB kernel buffer
    deadlocks the engine mid-call as soon as it prints a large normalized
    spec, because nothing drains the read end until __exit__.

    Mutually exclusive across threads: `__enter__` holds `_stdout_capture_lock`
    until `__exit__`. Only usable as a context manager -- the fd bookkeeping is
    set up in `__enter__`, not in `__init__`, so it stays inside the lock.
    """

    # (fd, attribute holding the captured text)
    _CAPTURED_FDS = ((1, "stdout_output"), (2, "stderr_output"))

    def __init__(self):
        # FD 1/2 are used directly because C++ std::cout / boost::log write to
        # them regardless of any sys.stdout redirection by pytest/CaptureIO.
        self._saved = {}   # fd -> dup'd original fd
        self._files = {}   # fd -> temp file object
        self.output = ""
        self.stdout_output = ""
        self.stderr_output = ""

        # Load C standard library for flushing
        try:
            self.libc = ctypes.CDLL(None)
        except Exception:
            self.libc = None

    def _flush_all(self):
        for stream in (sys.stdout, sys.stderr):
            try:
                stream.flush()
            except Exception:
                pass
        if self.libc:
            self.libc.fflush(None)

    def __enter__(self):
        _stdout_capture_lock.acquire()
        try:
            self._flush_all()
            for fd, _attr in self._CAPTURED_FDS:
                tmp = tempfile.TemporaryFile(mode="w+b")
                self._files[fd] = tmp
                self._saved[fd] = os.dup(fd)
                os.dup2(tmp.fileno(), fd)
        except BaseException:
            # Never hold the lock if the redirect never took effect.
            self._restore_and_close()
            _stdout_capture_lock.release()
            raise
        return self

    def _restore_and_close(self):
        for fd, _attr in self._CAPTURED_FDS:
            saved = self._saved.pop(fd, None)
            if saved is not None:
                try:
                    os.dup2(saved, fd)
                except OSError:
                    pass
                try:
                    os.close(saved)
                except OSError:
                    pass
            tmp = self._files.pop(fd, None)
            if tmp is not None:
                try:
                    tmp.close()
                except OSError:
                    pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            self._flush_all()
            texts = []
            for fd, attr in self._CAPTURED_FDS:
                text = ""
                tmp = self._files.get(fd)
                saved = self._saved.get(fd)
                if tmp is not None:
                    try:
                        # Restore first so any read error still leaves the fd sane.
                        if saved is not None:
                            os.dup2(saved, fd)
                        tmp.seek(0)
                        text = tmp.read().decode("utf-8", errors="replace")
                    except Exception:
                        text = ""
                setattr(self, attr, text)
                texts.append(text)
            self.output = "".join(texts)
        finally:
            self._restore_and_close()
            _stdout_capture_lock.release()


# The native engine ALWAYS ANSI-colours its severity marker (see tau-lang
# src/logging.h: `"(" << LOG_ERROR_COLOR << "Error" << TC.CLEAR() << ") "`),
# so a literal `"(Error)" in output` screen never matches and every rule
# validation gate built on it silently passes. Match the marker with the
# escape sequences allowed anywhere inside it.
_TAU_ERROR_RE = re.compile(r"\(\s*(?:\x1b\[[0-9;]*m)*\s*Error\s*(?:\x1b\[[0-9;]*m)*\s*\)")

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*m")


def strip_ansi(text) -> str:
    """Drop ANSI colour escapes so captured engine output is greppable."""
    if not text:
        return ""
    return _ANSI_ESCAPE_RE.sub("", str(text))


def tau_reports_error(text) -> bool:
    """True when captured native output carries an engine `(Error)` marker."""
    if not text:
        return False
    return bool(_TAU_ERROR_RE.search(str(text)))


class TauInterface:
    def __init__(self, program_file):
        """
        Initialize the Tau Direct Interface.
        
        Args:
            program_file (str): Path to the .tau logic specification file.
        """
        self.tau = load_tau_module()
        self.program_file = program_file
        
        # Read the spec
        try:
            with open(program_file, "r", encoding="utf-8", errors="replace") as f:
                raw_spec = f.read()

            self.rule_text = self.preprocess_spec_text(raw_spec)

            # Initialize accumulated spec with the genesis content
            self.accumulated_spec = self.rule_text
                
        except Exception as e:
            logger.error(f"Failed to read/preprocess program file {program_file}: {e}")
            raise

        # Create interpreter
        logger.info(f"Initializing direct Tau interpreter with spec from {program_file}")
        self.interpreter = self._build_interpreter_from_spec(
            self.rule_text,
            reason=f"initial spec from {program_file}",
        )
             
        # Initial step might be needed to prime it?
        # In example, they loop: get_inputs -> step. 
        # State is maintained in the interpreter object.

    @staticmethod
    def _ensure_trailing_period(spec_text: str) -> str:
        text = (spec_text or "").strip()
        if text and not text.endswith("."):
            logger.debug("Appending missing '.' to spec for native interpreter compatibility.")
            text += "."
        return text

    @staticmethod
    def _strip_nonliteral_hash_comments(line: str) -> str:
        """
        Strip hash comments while preserving Tau bitvector literals.

        Tau formulas use '#b...' and '#x...' literals; those hashes must remain.
        Any other '#' sequence is treated as a comment start until end-of-line.
        """
        out = []
        i = 0
        while i < len(line):
            ch = line[i]
            if ch != "#":
                out.append(ch)
                i += 1
                continue

            nxt = line[i + 1] if i + 1 < len(line) else ""
            if nxt.lower() in ("b", "x"):
                out.append(ch)
                i += 1
                continue

            # Regular comment marker: ignore the remainder of this line.
            break
        return "".join(out)

    @staticmethod
    def _type_untyped_quantifiers(spec_text: str) -> str:
        """
        Tau "Updated specification" output may contain untyped quantifiers like:
            all b1 b1 != 0 || b1 != i10[t]:bv[16]
        Some Tau builds require explicit types on quantified variables.

        We patch these cases by inferring a bv width from nearby typed terms
        (e.g. i10[t]:bv[16]) and rewriting to:
            all b1:bv[16] ...
        """
        text = spec_text or ""
        if "all " not in text:
            return text

        # Identify candidate "all <var>" occurrences where <var> is not already typed.
        # This is intentionally conservative: one var per 'all' is the common pattern
        # in current engine outputs.
        quant_re = re.compile(r"\ball\s+([A-Za-z_]\w*)\b(?!\s*:)")

        def _infer_width(var_name: str, full_text: str) -> int | None:
            # Try to infer width from comparisons involving the var and a typed bv[n] term.
            # Examples:
            #   b1 != i10[t]:bv[16]
            #   i10[t]:bv[16] != b1
            # Also allow equality and (not-)less-than variants used by Tau pretty-printer.
            op = r"(?:!=|=|<|!<|<=|>=)"
            typed_term = r"(?:\b[A-Za-z_]\w*\[t\]\s*:\s*bv\[\s*(\d+)\s*\]|\{\s*[^}]+\s*\}\s*:\s*bv\[\s*(\d+)\s*\])"
            patterns = [
                re.compile(rf"\b{re.escape(var_name)}\b\s*{op}\s*{typed_term}"),
                re.compile(rf"{typed_term}\s*{op}\s*\b{re.escape(var_name)}\b"),
            ]
            for pat in patterns:
                m = pat.search(full_text)
                if not m:
                    continue
                # typed_term has two alternative capture groups; pick whichever matched.
                for g in m.groups():
                    if g and str(g).isdigit():
                        return int(g)
            return None

        def _rewrite(match: re.Match) -> str:
            var = match.group(1)
            width = _infer_width(var, text)
            if width is None:
                return match.group(0)
            return f"all {var}:bv[{width}]"

        rewritten = quant_re.sub(_rewrite, text)
        return rewritten

    @classmethod
    def preprocess_spec_text(cls, spec_text: str) -> str:
        """
        Normalize a full Tau spec for native interpreter consumption.

        - removes `tau ... = ...` binding lines
        - removes `#tau ...` directive lines
        - strips hash comments while preserving `#b...` / `#x...` literals
        - flattens everything to a single line
        - ensures a trailing period
        """
        clean_lines = []
        for raw_line in (spec_text or "").splitlines():
            line = raw_line.replace("\ufeff", "").replace("\x00", "")
            sline = line.strip()

            if not sline:
                continue

            lowered = sline.lower()
            if lowered.startswith("tau ") and "=" in sline:
                logger.info("Ignored tau binding line in spec: %s", sline)
                continue
            if lowered.startswith("#tau "):
                logger.info("Ignored tau directive line in spec: %s", sline)
                continue

            cleaned = cls._strip_nonliteral_hash_comments(line)
            if cleaned.strip():
                clean_lines.append(cleaned.strip())

        flattened = " ".join(clean_lines).strip()
        flattened = cls._type_untyped_quantifiers(flattened)
        return cls._ensure_trailing_period(flattened)

    @classmethod
    def _normalize_assignment_value(cls, value, *, allow_hex_literal: bool = True) -> str:
        text = str(value).replace("\n", " ").strip()
        if not allow_hex_literal:
            return text
        if not text or text.startswith(("#x", "#b", "{")):
            return text
        if _HEX_LITERAL_RE.fullmatch(text) and any(ch in "abcdefABCDEF" for ch in text):
            return f"#x{text}"
        return text

    @staticmethod
    def _fallback_value_for_stream(stream_name: str) -> str:
        # Docker mode sends "F" for i0 (rule stream), and 0 for all other inputs.
        # return "F" if stream_name == "i0" else "0"
        if stream_name == "i0":
            return "F"
        return "0"

    def _build_interpreter_from_spec(self, spec_text: str, *, reason: str):
        mem_before = get_memory_rss_mb()
        prepared = self.preprocess_spec_text(spec_text)
        interpreter = self.tau.get_interpreter(prepared)
        mem_after = get_memory_rss_mb()
        logger.debug(f"[MEM] _build_interpreter_from_spec ({reason}): {mem_before:.2f} MB -> {mem_after:.2f} MB (Diff: {mem_after - mem_before:.2f} MB)")
        
        if interpreter is None:
            msg = f"Failed to create Tau interpreter ({reason})."
            filepath = tau_io_logger.dump_crash_log("TauEngineCrash", msg)
            if filepath:
                 logger.error(f"Dumped Tau crash log to {filepath}")
            raise TauEngineCrash(msg)
        self.accumulated_spec = prepared
        self._last_spec_revision = interpreter.spec_revision
        return interpreter

    def _rebuild_interpreter_from_spec(self, spec_text: str, *, reason: str):
        mem_before = get_memory_rss_mb()
        new_interpreter = self._build_interpreter_from_spec(spec_text, reason=reason)
        old_interpreter = self.interpreter
        self.interpreter = new_interpreter
        del old_interpreter
        mem_after = get_memory_rss_mb()
        logger.debug(f"[MEM] _rebuild_interpreter_from_spec ({reason}): {mem_before:.2f} MB -> {mem_after:.2f} MB (Diff: {mem_after - mem_before:.2f} MB)")

    @staticmethod
    def _coerce_stream_name(raw_key) -> str | None:
        if isinstance(raw_key, str):
            key = raw_key.strip()
            if _INPUT_STREAM_NAME_RE.match(key):
                return key
            if key.isdigit():
                return f"i{int(key)}"
            return None
        try:
            return f"i{int(raw_key)}"
        except (TypeError, ValueError):
            return None

    def communicate(self,
                   rule_text=None,
                   target_output_stream_index=0,
                   input_stream_values=None,
                   source="unknown",
                   apply_rules_update=True):
        """
        Simulate the `communicate_with_tau` signature but using direct bindings.
        
        We assume that `communicate_with_tau` represents ONE discrete step of interaction
        where we might provide inputs and we expect outputs.
        
        However, calling 'step' advances the logical time. 
        The IPC version waits for prompts.
        
        Logic:
        1. Query `get_inputs_for_step`.
        2. Construct assignments dictionary based on `input_stream_values` and `rule_text`.
        3. Call `step`.
        4. Extract the target output.
        """
        
        # Keep signature parity with docker path.
        _ = source
        _ = apply_rules_update

        # 1. Get required inputs
        required_inputs = self.tau.get_inputs_for_step(self.interpreter)
        input_assignments = {}

        # Prepare per-stream queues to mimic prompt-driven Docker behavior.
        stream_input_queues: dict[str, deque[str]] = {}
        if input_stream_values:
            for raw_stream_idx, raw_value in input_stream_values.items():
                stream_name = self._coerce_stream_name(raw_stream_idx)
                if not stream_name:
                    logger.debug(
                        "Ignoring non-input stream key for native assignment: %r",
                        raw_stream_idx,
                    )
                    continue

                if isinstance(raw_value, (list, tuple)):
                    values = [
                        self._normalize_assignment_value(v)
                        for v in raw_value
                        if v is not None
                    ]
                else:
                    values = [self._normalize_assignment_value(raw_value)]

                if values:
                    stream_input_queues[stream_name] = deque(values)

        normalized_rule_text = None
        if rule_text is not None:
            normalized_rule_text = self._normalize_assignment_value(rule_text, allow_hex_literal=False)

        # We must loop to provide inputs since Tau asks for them lazily.
        captured_output = ""
        outputs = None
        
        for _ in range(100):
            required_inputs = self.tau.get_inputs_for_step(self.interpreter)
            input_assignments = {}

            # Fill every newly required input
            for input_obj in required_inputs:
                name = input_obj.name
                stream_queue = stream_input_queues.get(name)

                if stream_queue:
                    value_to_assign = stream_queue.popleft()
                    if not stream_queue:
                        del stream_input_queues[name]
                    reason = "Sending queued input"
                elif name == "i0" and normalized_rule_text is not None:
                    value_to_assign = normalized_rule_text
                    normalized_rule_text = None
                    reason = "Sending rule text"
                else:
                    value_to_assign = self._fallback_value_for_stream(name)
                    reason = "Sending fallback"

                input_assignments[input_obj] = value_to_assign
                tau_io_logger.log_native_input(name, value_to_assign)
                if _step_io_debug_enabled():
                    logger.debug(
                        "Input Key: %r (name=%s) -> Value: %s (%s)",
                        input_obj,
                        name,
                        value_to_assign,
                        reason,
                    )

            # Log Inputs
            if input_assignments and _step_io_debug_enabled():
                 logger.debug(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Inputs:{COLOR_RESET}")
                 for k, v in input_assignments.items():
                     val_str = str(v)
                     if "\n" in val_str:
                         logger.debug(f"  {k.name}:")
                         for line in val_str.splitlines():
                             logger.debug(f"{COLOR_GREEN}    >>> {line}{COLOR_RESET}")
                     else:
                         logger.debug(f"  {k.name}: {COLOR_GREEN}{val_str}{COLOR_RESET}")

            try:
                mem_before = get_memory_rss_mb()
                with StdOutCapture() as capture:
                    outputs = self.tau.step(self.interpreter, input_assignments)
                mem_after = get_memory_rss_mb()
                if _step_io_debug_enabled():
                    logger.debug(f"[MEM] tau.step: {mem_before:.2f} MB -> {mem_after:.2f} MB (Diff: {mem_after - mem_before:.2f} MB)")
                captured_output += capture.output
            except Exception as e:
                raise e

            if outputs is not None:
                break # We have outputs, step is fully finished
                
            if tau_reports_error(capture.output):
                break # Native engine reported a parsing/logic error, don't loop forever

        # Re-print accumulated captured output to real stdout so logs are visible
        if captured_output:
            print(captured_output, end='')
            tau_io_logger.log_native_stdout(captured_output)
            
            if tau_reports_error(captured_output):
                msg = f"Tau native step reported an error: {captured_output.strip()}"
                filepath = tau_io_logger.dump_crash_log("TauEngineBug", msg)
                if filepath:
                     logger.error(f"Dumped Tau crash log to {filepath}")
                raise TauEngineBug(msg)

        if outputs is None:
            msg = "Tau step failed (returned None after 100 iterations)"
            filepath = tau_io_logger.dump_crash_log("TauEngineBug", msg)
            if filepath:
                 logger.error(f"Dumped Tau crash log to {filepath}")
            raise TauEngineBug(msg)


        # Log Outputs
        if outputs:
             for k, v in outputs.items():
                 val_str = str(v)
                 tau_io_logger.log_native_output(k.name, val_str)
             if _step_io_debug_enabled():
                 logger.debug(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs:{COLOR_RESET}")
                 for k, v in outputs.items():
                     val_str = str(v)
                     if "\n" in val_str:
                         logger.debug(f"  {k.name}:")
                         for line in val_str.splitlines():
                             logger.debug(f"{COLOR_BLUE}    <<< {line}{COLOR_RESET}")
                     else:
                         logger.debug(f"  {k.name}: {COLOR_BLUE}{val_str}{COLOR_RESET}")
        elif _step_io_debug_enabled():
             logger.debug(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs: (None){COLOR_RESET}")
            
        # 3. Extract Output
        target_name = f"o{target_output_stream_index}"
        
        result_value = "0" # Default
        found = False
        
        for output_obj, value in outputs.items():
             if output_obj.name == target_name:
                 result_value = str(value)
                 found = True
        
        # 4. Process Spec Updates
        try:
            if self.interpreter.spec_revision != self._last_spec_revision:
                updated_spec = self.interpreter.current_spec()
                logger.info(
                    f"{COLOR_YELLOW}[TAU_DIRECT] Spec Replaced: {updated_spec}{COLOR_RESET}"
                )
                self._rebuild_interpreter_from_spec(
                    updated_spec,
                    reason="updated specification from step output",
                )
        except Exception as e:
            logger.error("Failed to process updated specification: %s", e)
            raise

        
        if not found:
            logger.debug(f"Warning: Target output {target_name} not found in step outputs: {[k.name for k in outputs.keys()]}")
            
        return result_value

    def communicate_multi(self,
                          rule_text=None,
                          input_stream_values=None,
                          source="unknown",
                          apply_rules_update=True) -> dict[int, str]:
        """
        Run one Tau step and return ALL actually-emitted output streams.

        Returns:
            dict[int, str]: Mapping of output stream index to its string value.
            Only outputs actually produced by Tau are included.
            Missing outputs are NOT synthesized — this is consensus-critical
            (missing o5 = no policy emitted vs o5 = "0" = explicit block).
        """
        # Keep signature parity with docker path.
        _ = source
        _ = apply_rules_update

        # 1. Get required inputs
        required_inputs = self.tau.get_inputs_for_step(self.interpreter)
        input_assignments = {}

        # Prepare per-stream queues to mimic prompt-driven Docker behavior.
        stream_input_queues: dict[str, deque[str]] = {}
        if input_stream_values:
            for raw_stream_idx, raw_value in input_stream_values.items():
                stream_name = self._coerce_stream_name(raw_stream_idx)
                if not stream_name:
                    continue

                if isinstance(raw_value, (list, tuple)):
                    values = [
                        self._normalize_assignment_value(v)
                        for v in raw_value
                        if v is not None
                    ]
                else:
                    values = [self._normalize_assignment_value(raw_value)]

                if values:
                    stream_input_queues[stream_name] = deque(values)

        normalized_rule_text = None
        if rule_text is not None:
            normalized_rule_text = self._normalize_assignment_value(rule_text, allow_hex_literal=False)

        captured_output = ""
        outputs = None

        for _ in range(100):
            required_inputs = self.tau.get_inputs_for_step(self.interpreter)
            input_assignments = {}

            for input_obj in required_inputs:
                name = input_obj.name
                stream_queue = stream_input_queues.get(name)

                if stream_queue:
                    value_to_assign = stream_queue.popleft()
                    if not stream_queue:
                        del stream_input_queues[name]
                elif name == "i0" and normalized_rule_text is not None:
                    value_to_assign = normalized_rule_text
                    normalized_rule_text = None
                else:
                    value_to_assign = self._fallback_value_for_stream(name)

                input_assignments[input_obj] = value_to_assign
                tau_io_logger.log_native_input(name, value_to_assign)

            try:
                mem_before = get_memory_rss_mb()
                with StdOutCapture() as capture:
                    outputs = self.tau.step(self.interpreter, input_assignments)
                mem_after = get_memory_rss_mb()
                if _step_io_debug_enabled():
                    logger.debug(f"[MEM] tau.step (multi): {mem_before:.2f} MB -> {mem_after:.2f} MB (Diff: {mem_after - mem_before:.2f} MB)")
                captured_output += capture.output
            except Exception as e:
                raise e

            if outputs is not None:
                break

            if tau_reports_error(capture.output):
                break

        # Re-print captured output for log visibility
        if captured_output:
            print(captured_output, end='')
            tau_io_logger.log_native_stdout(captured_output)

            if tau_reports_error(captured_output):
                msg = f"Tau native step reported an error: {captured_output.strip()}"
                filepath = tau_io_logger.dump_crash_log("TauEngineBug", msg)
                if filepath:
                    logger.error(f"Dumped Tau crash log to {filepath}")
                raise TauEngineBug(msg)

        if outputs is None:
            msg = "Tau step failed (returned None after 100 iterations)"
            filepath = tau_io_logger.dump_crash_log("TauEngineBug", msg)
            if filepath:
                logger.error(f"Dumped Tau crash log to {filepath}")
            raise TauEngineBug(msg)

        # Log Outputs
        if outputs:
            for k, v in outputs.items():
                val_str = str(v)
                tau_io_logger.log_native_output(k.name, val_str)
            if _step_io_debug_enabled():
                logger.debug(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs (multi):{COLOR_RESET}")
                for k, v in outputs.items():
                    val_str = str(v)
                    logger.debug(f"  {k.name}: {COLOR_BLUE}{val_str}{COLOR_RESET}")

        # Process Spec Updates
        try:
            if self.interpreter.spec_revision != self._last_spec_revision:
                updated_spec = self.interpreter.current_spec()
                logger.info(
                    f"{COLOR_YELLOW}[TAU_DIRECT] Spec Replaced: {updated_spec}{COLOR_RESET}"
                )
                self._rebuild_interpreter_from_spec(
                    updated_spec,
                    reason="updated specification from step output",
                )
        except Exception as e:
            logger.error("Failed to process updated specification: %s", e)
            raise

        # Build result: only actually emitted outputs, keyed by stream index
        result: dict[int, str] = {}
        if outputs:
            for output_obj, value in outputs.items():
                name = output_obj.name
                if name.startswith("o") and name[1:].isdigit():
                    result[int(name[1:])] = str(value)

        return result

    def get_current_spec(self):
        """Returns the full accumulated specification."""
        return self.accumulated_spec

    def update_spec(self, new_spec):
        self._rebuild_interpreter_from_spec(
            self.preprocess_spec_text(new_spec),
            reason="explicit update_spec request",
        )

    @classmethod
    def compile_revisions_isolated(
        cls,
        consensus_rules_text: str,
        revisions,
    ):
        """
        Compile each revision against an isolated, throwaway Tau interpreter
        built the SAME way the live interpreter is: the FIRST rule unit of
        `consensus_rules_text` seeds the interpreter (it is a single parseable
        spec -- the genesis i0->u conditional, or the active consensus formula),
        and every remaining unit is replayed through i0 so the genesis u-stream
        joins them. Returns None on success, or a string describing the first
        compile failure encountered.

        IMPORTANT: `consensus_rules_text` may be the raw newline accumulation
        from chain_state.get_rules_state() (genesis conditional + builtin units +
        prior rules). That blob is NOT a single parseable spec -- the genesis
        conditional has no trailing '.', so `get_interpreter(blob)` fails at the
        first ') always'. Seeding from unit[0] and replaying the rest via i0
        avoids that. For a single-unit consensus seed this is identical to the
        previous behavior.

        Used by mempool admission and sendtx to reject syntactically or
        semantically bad revisions before they reach `engine.apply_block` at the
        activation height. The throwaway interpreter is local to this call: no
        module-level state (`tau` global, live `tau_direct_interface`,
        `_application_rules_state`, etc.) is mutated.
        """
        tau_module = load_tau_module()

        units = [
            u for u in (consensus_rules_text or "").split("\n") if u.strip()
        ]
        if not units:
            # No baseline to revise against; admission falls back to its
            # cheap structural pass.
            return None

        seed_spec = cls.preprocess_spec_text(units[0])
        if not seed_spec:
            return None

        try:
            with StdOutCapture() as init_capture:
                interpreter = tau_module.get_interpreter(seed_spec)
        except Exception as e:
            return f"Failed to construct staging Tau interpreter: {e}"

        if interpreter is None:
            err = (init_capture.output or "").strip()
            return (
                f"Failed to construct staging Tau interpreter from current consensus rules: {err}"
                if err
                else "Failed to construct staging Tau interpreter from current consensus rules."
            )
        if tau_reports_error(init_capture.output):
            return f"Tau staging compile error: {init_capture.output.strip()}"

        # Replay the remaining accumulated units (joined via i0 -> u like the
        # live interpreter), then the candidate revisions, through i0.
        staged_inputs = list(units[1:]) + list(revisions or [])
        for rev in staged_inputs:
            if not isinstance(rev, str) or not rev.strip():
                continue

            prepared_rev = cls._normalize_assignment_value(rev, allow_hex_literal=False)

            captured_output = ""
            outputs = None
            rev_consumed = False

            # Bounded lazy-prompt loop matching communicate()'s shape: keep
            # feeding required inputs (rev for the first i0, fallbacks for
            # everything else) until tau.step yields outputs or we hit the
            # iteration cap. An engine error marker short-circuits.
            #
            # `get_inputs_for_step` is captured too: the engine defers type
            # errors to the *next* prompt, so a bv-width conflict introduced by
            # `rev` surfaces there rather than out of `step`.
            for _ in range(100):
                try:
                    with StdOutCapture() as prompt_capture:
                        required_inputs = tau_module.get_inputs_for_step(interpreter)
                    captured_output += prompt_capture.output
                except Exception as e:
                    return f"Tau staging compile error: {e}"

                if tau_reports_error(prompt_capture.output):
                    return f"Tau staging compile error: {prompt_capture.output.strip()}"

                assignments = {}
                consumed_this_iteration = False
                for input_obj in required_inputs:
                    name = input_obj.name
                    if name == "i0" and not rev_consumed:
                        assignments[input_obj] = prepared_rev
                        rev_consumed = True
                        consumed_this_iteration = True
                    else:
                        assignments[input_obj] = cls._fallback_value_for_stream(name)

                try:
                    with StdOutCapture() as capture:
                        outputs = tau_module.step(interpreter, assignments)
                    captured_output += capture.output
                except Exception as e:
                    return f"Tau staging compile error: {e}"

                if tau_reports_error(capture.output):
                    return f"Tau staging compile error: {capture.output.strip()}"

                if outputs is not None:
                    break

                if consumed_this_iteration:
                    # The engine refused the revision itself: it returned no
                    # outputs for the very step that fed it. Continuing would
                    # re-prompt i0, feed the benign "F" fallback, succeed, and
                    # report the malformed rule as clean.
                    detail = strip_ansi(captured_output).strip()
                    return (
                        f"Tau staging compile error: engine rejected revision: {detail}"
                        if detail
                        else "Tau staging compile error: engine rejected revision (no outputs)"
                    )

            if tau_reports_error(captured_output):
                return f"Tau staging compile error: {captured_output.strip()}"

        # Drain one more prompt so a type error deferred past the final
        # revision's step still surfaces instead of going unobserved.
        try:
            with StdOutCapture() as tail_capture:
                tau_module.get_inputs_for_step(interpreter)
        except Exception as e:
            return f"Tau staging compile error: {e}"
        if tau_reports_error(tail_capture.output):
            return f"Tau staging compile error: {tail_capture.output.strip()}"

        # `interpreter` falls out of scope here and is reclaimed; no live state touched.
        return None


_COMPILE_WORKER_MODULE = "tau_compile_worker"
_COMPILE_RESULT_SENTINEL = "__TAU_COMPILE_RESULT__"


class NativeTauUnavailable(Exception):
    """
    Raised by `compile_revisions_isolated_subprocess` when the isolated compile
    could not run at all (native bindings absent, worker un-spawnable). Distinct
    from a rule rejection.

    The op-"0" admission caller (`commands/sendtx.py`) maps this to a structured
    ``ADMISSION_UNAVAILABLE`` rejection and does NOT fall back to an in-process
    live compile: that fallback (plus its restore) is unbounded and watchdog-blind
    and was the indefinite-hang vector in issue #24. The activation-height compile
    in ``apply_block`` re-validates the rule deterministically, so a rare transient
    admission-time skip is safe.
    """


class RuleCompileTimeout(NativeTauUnavailable):
    """
    Raised by `compile_revisions_isolated_subprocess` when the isolated compile
    overran its wall-clock ``timeout`` (the child was SIGKILLed). Subclasses
    NativeTauUnavailable so existing ``except NativeTauUnavailable`` sites still
    catch it, but lets the caller emit a distinct ``ADMISSION_TIMEOUT`` code.
    """


def admission_compile_timeout() -> float:
    """Wall-clock ceiling for an isolated compile run on the admission path.

    Shared by every admission caller so the bound cannot drift between the
    user op-"0" path and the consensus-revision path. `admission_budget` sits
    below the shipped client's socket timeout, so the structured
    ADMISSION_TIMEOUT actually reaches the caller instead of the client giving
    up first; `comm_timeout` still caps it, so lowering that lowers this too.

    Imported lazily: this module is also loaded inside the compile worker child,
    which must not need the parent's config.
    """
    import config
    budget = getattr(config, "ADMISSION_BUDGET", None) or config.COMM_TIMEOUT
    return float(min(budget, config.COMM_TIMEOUT))


def compile_revisions_isolated_subprocess(
    consensus_rules_text: str,
    revisions,
    timeout: float,
):
    """
    Run `TauInterface.compile_revisions_isolated` in a throwaway child process
    with a hard wall-clock `timeout`.

    Returns:
        None        -- the revisions compiled successfully.
        str         -- a rejection reason (native crash, bad rule, or a worker
                       that died without reporting). The caller must reject the
                       transaction (TX_REJECTED).
    Raises:
        RuleCompileTimeout   -- the compile overran ``timeout`` (child SIGKILLed);
                       caller should reject with ADMISSION_TIMEOUT.
        NativeTauUnavailable -- the compile could not run (native bindings
                       absent / worker un-spawnable); caller should reject with
                       ADMISSION_UNAVAILABLE (NOT fall back to live validation).

    This is the watchdog-free path's safety net — the in-process classmethod can
    hang indefinitely inside native Tau with no status stamp for the server
    watchdog to catch, so we isolate it where we can SIGKILL it on timeout.
    """
    repo_root = os.path.dirname(os.path.abspath(__file__))
    request = json.dumps(
        {
            "consensus_rules_text": consensus_rules_text or "",
            "revisions": list(revisions or []),
        }
    )

    # The child re-imports the native tau module via load_tau_module(). The parent
    # may have loaded it from a runtime sys.path insert (sibling tau-lang build)
    # the child cannot inherit, so it would report "native tau unavailable" and the
    # caller would fall back to the (slower, mutating) live validation path on every
    # rule. Propagate the parent's resolved native dir + repo root via PYTHONPATH so
    # the child imports the SAME module deterministically.
    try:
        load_tau_module()
    except Exception:
        pass  # leave PYTHONPATH augmentation best-effort; worker still falls back
    child_env = dict(os.environ)
    extra_paths = [p for p in (native_tau_dir(), repo_root) if p]
    existing_pp = child_env.get("PYTHONPATH", "")
    child_env["PYTHONPATH"] = os.pathsep.join(
        extra_paths + ([existing_pp] if existing_pp else [])
    )

    try:
        proc = subprocess.run(
            [sys.executable, "-m", _COMPILE_WORKER_MODULE],
            input=request,
            capture_output=True,
            text=True,
            cwd=repo_root,
            timeout=timeout,
            env=child_env,
        )
    except subprocess.TimeoutExpired as exc:
        # subprocess.run already SIGKILLed the child on timeout.
        logger.warning(
            "Isolated rule compile timed out after %.1fs; rejecting transaction.",
            timeout,
        )
        raise RuleCompileTimeout(
            f"Rule compile timed out after {timeout:.0f}s."
        ) from exc
    except Exception as exc:
        # Could not spawn the worker at all (e.g. missing interpreter).
        logger.warning("Isolated rule compile worker failed to run: %s", exc)
        raise NativeTauUnavailable(str(exc)) from exc

    for line in (proc.stdout or "").splitlines():
        if line.startswith(_COMPILE_RESULT_SENTINEL):
            try:
                result = json.loads(line[len(_COMPILE_RESULT_SENTINEL):])
            except Exception as exc:
                return f"Rule compile worker returned unparseable result: {exc}"
            if result.get("ok"):
                return None
            if result.get("unavailable"):
                # Native bindings absent in the worker: degrade to the live
                # validation path rather than rejecting the transaction.
                logger.warning(
                    "Isolated rule compile worker reports native tau unavailable: %s",
                    result.get("error"),
                )
                raise NativeTauUnavailable(result.get("error") or "native tau unavailable")
            return result.get("error") or "Rule compile failed."

    # No sentinel: worker died before reporting (crash/OOM/killed). Reject.
    tail = (proc.stderr or proc.stdout or "").strip()[-500:]
    return f"Rule compile worker produced no result (exit={proc.returncode}). {tail}"

