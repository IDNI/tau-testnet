import re

def normalize_tau_atoms(tau_atom_string: str) -> str:
    """
    Normalizes a Tau atom string by sorting its components.
    Example: "x1 & x0'" becomes "x0' & x1".
    This is useful for consistent comparisons.
    """
    if not isinstance(tau_atom_string, str) or '&' not in tau_atom_string:
        return tau_atom_string
    
    parts = [part.strip() for part in tau_atom_string.split('&')]
    # Sort primarily by the numeric part of the variable
    parts.sort(key=lambda p: int(''.join(filter(str.isdigit, p))))
    return ' & '.join(parts)

def tau_output_heuristic_check(line, input_value, tau_defs):
    """
    A fallback heuristic to identify plausible Tau output lines.
    This is less critical now with the explicit `oN = <value>` parsing
    but can be kept for debugging or legacy reasons.
    """
    line = line.strip()
    # Simple check: Is it one of the known constant definitions?
    known_defs = [
        tau_defs.TAU_VALUE_ZERO, tau_defs.TAU_VALUE_ONE,
        getattr(tau_defs, 'ACK_RULE_PROCESSED', None)
    ]
    if line in known_defs:
        return True
    # Is it an echo of the input?
    if input_value and line == input_value.strip():
        return True
    return False


def bits_to_tau_literal(bit_pattern: str, length: int | None = None) -> str:
    """
    Converts a binary string (e.g. '1010') into a Tau bitvector literal ('1010').
    Optionally enforces/pads to a specific length.
    """
    cleaned = ''.join(ch for ch in bit_pattern if ch in ('0', '1'))
    if not cleaned:
        cleaned = "0"
    if length is not None:
        if len(cleaned) > length:
            cleaned = cleaned[-length:]
        else:
            cleaned = cleaned.rjust(length, '0')
    return f"#b{cleaned}"
