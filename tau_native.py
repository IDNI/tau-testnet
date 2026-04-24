import ctypes
import logging
import os
import re
import sys
from collections import deque

from errors import TauEngineBug, TauEngineCrash
import tau_io_logger

# Setup logging
logger = logging.getLogger(__name__)

# Global reference to the loaded tau module
tau = None

# ANSI color codes for debug output
COLOR_BLUE = "\033[94m"
COLOR_YELLOW = "\033[93m"
COLOR_GREEN = "\033[92m"
COLOR_MAGENTA = "\033[95m"
COLOR_RESET = "\033[0m"
_INPUT_STREAM_NAME_RE = re.compile(r"^i\d+$")
_UPDATED_SPEC_LINE_RE = re.compile(r"^Updated\s*specification\:\s*(.*)$")
_HEX_LITERAL_RE = re.compile(r"^[0-9a-fA-F]+$")

def get_memory_rss_mb() -> float:
    try:
        with open("/proc/self/statm") as f:
            pages = int(f.read().split()[1])
            page_size = os.sysconf("SC_PAGE_SIZE")
            return (pages * page_size) / (1024 * 1024)
    except Exception:
        return 0.0

def load_tau_module():
    """
    Attempts to locate and import the native `tau` module.
    It searches in likely build directories within a sibling `tau-lang` repository.
    """
    global tau
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
            logger.info("Found native tau module in PYTHONPATH")
            return tau
        except ImportError:
            logger.error("Could not find native tau module in candidates or PYTHONPATH")
            raise ImportError("Native tau module not found. Ensure tau-lang is built and accessible.")

class StdOutCapture:
    """
    Context manager to capture C-level stdout/stderr output.
    Required because nanobind/C++ prints directly to file descriptors, 
    bypassing sys.stdout.
    """
    def __init__(self):
        # Always use FD 1 (STDOUT_FILENO) because C++ std::cout writes directly to it
        # regardless of whether sys.stdout has been redirected by pytest/CaptureIO.
        self._stdout_fd = 1
        self._saved_stdout_fd = os.dup(self._stdout_fd)
        self._r, self._w = os.pipe()
        self.output = ""
        
        # Load C standard library for flushing
        try:
            self.libc = ctypes.CDLL(None)
        except Exception:
            self.libc = None

    def __enter__(self):
        # Flush Python's stdout buffer before redirecting
        sys.stdout.flush()
        if self.libc:
            self.libc.fflush(None)
            
        # Redirect stdout to the write end of the pipe
        os.dup2(self._w, self._stdout_fd)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        # Flush Python's stdout
        sys.stdout.flush()
        
        # Flush C-level stdout to ensure buffered content goes to pipe
        if self.libc:
            self.libc.fflush(None)
            
        # Closing the write end signals EOF to the reader
        os.close(self._w)
        
        # Restore original stdout
        os.dup2(self._saved_stdout_fd, self._stdout_fd)
        os.close(self._saved_stdout_fd)
        
        # Read from the read end of the pipe
        with os.fdopen(self._r, 'r') as f:
            self.output = f.read()



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
        return interpreter

    def _rebuild_interpreter_from_spec(self, spec_text: str, *, reason: str):
        mem_before = get_memory_rss_mb()
        new_interpreter = self._build_interpreter_from_spec(spec_text, reason=reason)
        old_interpreter = self.interpreter
        self.interpreter = new_interpreter
        del old_interpreter
        mem_after = get_memory_rss_mb()
        logger.debug(f"[MEM] _rebuild_interpreter_from_spec ({reason}): {mem_before:.2f} MB -> {mem_after:.2f} MB (Diff: {mem_after - mem_before:.2f} MB)")

    def _extract_latest_updated_spec(self, captured_output: str) -> str | None:
        if not captured_output:
            return None

        latest_spec = None
        lines = captured_output.splitlines()
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            match = _UPDATED_SPEC_LINE_RE.match(line)
            if not match:
                i += 1
                continue

            block_lines = []
            inline_spec = (match.group(1) or "").strip()
            if inline_spec:
                block_lines.append(inline_spec)

            i += 1
            while i < len(lines):
                candidate = lines[i].strip()
                if not candidate:
                    if block_lines:
                        break
                    i += 1
                    continue
                if candidate.startswith("Execution step:"):
                    break
                if _UPDATED_SPEC_LINE_RE.match(candidate):
                    # Let the outer loop process a newer marker if present.
                    i -= 1
                    break
                block_lines.append(candidate)
                i += 1

            if block_lines:
                latest_spec = " ".join(block_lines)
            i += 1

        if not latest_spec:
            return None
        return self._ensure_trailing_period(latest_spec)

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
                logger.debug(
                    "Input Key: %r (name=%s) -> Value: %s (%s)",
                    input_obj,
                    name,
                    value_to_assign,
                    reason,
                )

            # Log Inputs
            if input_assignments:
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
                logger.debug(f"[MEM] tau.step: {mem_before:.2f} MB -> {mem_after:.2f} MB (Diff: {mem_after - mem_before:.2f} MB)")
                captured_output += capture.output
            except Exception as e:
                raise e

            if outputs is not None:
                break # We have outputs, step is fully finished
                
            if "(Error)" in capture.output:
                break # Native engine reported a parsing/logic error, don't loop forever

        # Re-print accumulated captured output to real stdout so logs are visible
        if captured_output:
            print(captured_output, end='')
            tau_io_logger.log_native_stdout(captured_output)
            
            if "(Error)" in captured_output:
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
             logger.debug(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs:{COLOR_RESET}")
             for k, v in outputs.items():
                 val_str = str(v)
                 tau_io_logger.log_native_output(k.name, val_str)
                 if "\n" in val_str:
                     logger.debug(f"  {k.name}:")
                     for line in val_str.splitlines():
                         logger.debug(f"{COLOR_BLUE}    <<< {line}{COLOR_RESET}")
                 else:
                     logger.debug(f"  {k.name}: {COLOR_BLUE}{val_str}{COLOR_RESET}")
        else:
             logger.debug(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs: (None){COLOR_RESET}")
            
        # 3. Extract Output
        target_name = f"o{target_output_stream_index}"
        
        result_value = "0" # Default
        found = False
        
        for output_obj, value in outputs.items():
             if output_obj.name == target_name:
                 result_value = str(value)
                 found = True
        
        # 4. Process Spec Updates from STDOUT (not 'u' stream)
        try:
            updated_spec = self._extract_latest_updated_spec(captured_output)
            if updated_spec:
                logger.info(
                    f"{COLOR_YELLOW}[TAU_DIRECT] Spec Replaced from STDOUT: {updated_spec}{COLOR_RESET}"
                )
                self._rebuild_interpreter_from_spec(
                    updated_spec,
                    reason="updated specification from step output",
                )
        except Exception as e:
            logger.error("Failed to process updated specification from stdout: %s", e)
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
                logger.debug(f"[MEM] tau.step (multi): {mem_before:.2f} MB -> {mem_after:.2f} MB (Diff: {mem_after - mem_before:.2f} MB)")
                captured_output += capture.output
            except Exception as e:
                raise e

            if outputs is not None:
                break

            if "(Error)" in capture.output:
                break

        # Re-print captured output for log visibility
        if captured_output:
            print(captured_output, end='')
            tau_io_logger.log_native_stdout(captured_output)

            if "(Error)" in captured_output:
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
            logger.debug(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs (multi):{COLOR_RESET}")
            for k, v in outputs.items():
                val_str = str(v)
                tau_io_logger.log_native_output(k.name, val_str)
                logger.debug(f"  {k.name}: {COLOR_BLUE}{val_str}{COLOR_RESET}")

        # Process Spec Updates from STDOUT
        try:
            updated_spec = self._extract_latest_updated_spec(captured_output)
            if updated_spec:
                logger.info(
                    f"{COLOR_YELLOW}[TAU_DIRECT] Spec Replaced from STDOUT: {updated_spec}{COLOR_RESET}"
                )
                self._rebuild_interpreter_from_spec(
                    updated_spec,
                    reason="updated specification from step output",
                )
        except Exception as e:
            logger.error("Failed to process updated specification from stdout: %s", e)
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

