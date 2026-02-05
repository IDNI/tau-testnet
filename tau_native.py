
import sys
import os
import logging
import importlib.util

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
            logger.error(f"Failed to import native tau module from {found_path}: {e}")
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
            with open(program_file, 'r') as f:
                raw_lines = f.readlines()
                
            # Preprocess to be compatible with native interpreter
            # 1. Remove `tau ... = ...` binding lines
            # 2. Add trailing period if missing and not empty
            
            clean_lines = []
            for line in raw_lines:
                sline = line.strip()
                if sline.startswith("tau ") and "=" in sline:
                    logger.info(f"Ignored tau binding line in spec: {sline}")
                    continue
                clean_lines.append(line)
                
            self.rule_text = "".join(clean_lines).strip()
            
            if self.rule_text and not self.rule_text.endswith("."):
                logger.debug("Appending missing '.' to spec for native interpreter compatibility.")
                self.rule_text += "."
            
            # Initialize accumulated spec with the genesis content
            self.accumulated_spec = self.rule_text
                
        except Exception as e:
            logger.error(f"Failed to read/preprocess program file {program_file}: {e}")
            raise

        # Create interpreter
        logger.info(f"Initializing direct Tau interpreter with spec from {program_file}")
        self.interpreter = self.tau.get_interpreter(self.rule_text)
        if self.interpreter is None:
             raise RuntimeError(f"Failed to create Tau interpreter from {program_file}")
             
        # Initial step might be needed to prime it?
        # In example, they loop: get_inputs -> step. 
        # State is maintained in the interpreter object.

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
        
        # 1. Get required inputs
        required_inputs = self.tau.get_inputs_for_step(self.interpreter)
        # required_inputs is a list of input objects (presumably with .name)
        
        input_assignments = {}
        
        # Helper to map our 0, 1, 2 indices to i0, i1, i2 names
        # We assume the spec uses 'i0', 'i1' etc.
        
        # Prepare available values
        available_values = {}
        
        # Map legacy rule_text argument to i0 if it's typically the rule stream
        if rule_text is not None:
            available_values['i0'] = rule_text
            
        if input_stream_values:
            for k, v in input_stream_values.items():
                if isinstance(v, (list, tuple)):
                    # If multiple values provided, take the first one? 
                    # Real usage usually sends one value per prompt.
                    val = str(v[0]) if v else "0" 
                else:
                    val = str(v)
                available_values[f"i{k}"] = val

        # Fill inputs
        for input_obj in required_inputs:
            name = input_obj.name # e.g. "i0"
            if name in available_values:
                input_assignments[input_obj] = available_values[name]
            else:
                # Default/Fallback
                # In IPC we send "0" or "F" if not specified but prompted
                # Here we must provide something
                input_assignments[input_obj] = "0" 
        
        # 2. Perform Step
        # Log Inputs
        if input_assignments:
             logger.info(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Inputs:{COLOR_RESET}")
             for k, v in input_assignments.items():
                 # Handle multi-line inputs for cleaner logging
                 val_str = str(v)
                 if "\n" in val_str:
                     logger.info(f"  {k.name}:")
                     for line in val_str.splitlines():
                         logger.info(f"{COLOR_GREEN}    >>> {line}{COLOR_RESET}")
                 else:
                     logger.info(f"  {k.name}: {COLOR_GREEN}{val_str}{COLOR_RESET}")
        else:
             logger.info(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Inputs: (None){COLOR_RESET}")

        outputs = self.tau.step(self.interpreter, input_assignments)
        
        if outputs is None:
            raise RuntimeError("Tau step failed (returned None)")

        # Log Outputs
        if outputs:
             logger.info(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs:{COLOR_RESET}")
             for k, v in outputs.items():
                 val_str = str(v)
                 if "\n" in val_str:
                     logger.info(f"  {k.name}:")
                     for line in val_str.splitlines():
                         logger.info(f"{COLOR_BLUE}    <<< {line}{COLOR_RESET}")
                 else:
                     logger.info(f"  {k.name}: {COLOR_BLUE}{val_str}{COLOR_RESET}")
        else:
             logger.info(f"{COLOR_MAGENTA}[TAU_DIRECT] Step Outputs: (None){COLOR_RESET}")
            
        # 3. Extract Output
        target_name = f"o{target_output_stream_index}"
        
        result_value = "0" # Default
        found = False
        
        # Check for update stream 'u' to track spec changes
        update_val = None
        
        for output_obj, value in outputs.items():
             if output_obj.name == target_name:
                 result_value = value
                 found = True
             if output_obj.name == 'u':
                 update_val = value
        
        if update_val:
            # Append normalized update to our accumulated spec
            # Ensure it ends with a dot for validity
            cleaned_update = update_val.strip()
            if not cleaned_update.endswith("."):
                cleaned_update += "."
            
            logger.info(f"{COLOR_YELLOW}[TAU_DIRECT] Spec Update Detected: {cleaned_update[:50]}...{COLOR_RESET}")
            # Append 
            self.accumulated_spec += "\n" + cleaned_update
        
        if not found:
            logger.debug(f"Warning: Target output {target_name} not found in step outputs: {[k.name for k in outputs.keys()]}")
            
        return result_value

    def get_current_spec(self):
        """Returns the full accumulated specification."""
        return self.accumulated_spec

    def update_spec(self, new_spec):
         # If we need to force update spec logic
         pass

