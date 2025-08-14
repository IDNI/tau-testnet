import re

# The SBF encoding helpers for the old 4-bit system have been removed,
# as the system now uses large bitvectors communicated directly as integers.

def normalize_sbf_atoms(sbf_string: str) -> str:
    """
    Normalizes an SBF atom string by sorting its components.
    Example: "x1 & x0'" becomes "x0' & x1".
    This is useful for consistent comparisons.
    """
    if not isinstance(sbf_string, str) or '&' not in sbf_string:
        return sbf_string
    
    parts = [part.strip() for part in sbf_string.split('&')]
    # Sort primarily by the numeric part of the variable
    parts.sort(key=lambda p: int(''.join(filter(str.isdigit, p))))
    return ' & '.join(parts)

def sbf_output_heuristic_check(line, input_sbf, sbf_defs):
    """
    A fallback heuristic to identify plausible Tau output lines.
    This is less critical now with the explicit `oN = <value>` parsing
    but can be kept for debugging or legacy reasons.
    """
    line = line.strip()
    # Simple check: Is it one of the known constant definitions?
    known_defs = [
        sbf_defs.SBF_LOGICAL_ZERO, sbf_defs.SBF_LOGICAL_ONE,
        getattr(sbf_defs, 'ACK_RULE_PROCESSED', None)
    ]
    if line in known_defs:
        return True
    # Is it an echo of the input?
    if line == input_sbf.strip():
        return True
    return False