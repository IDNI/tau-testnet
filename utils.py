import re

def bits_to_sbf_atom(bit_string: str, length: int) -> str:
    """Converts a binary string of specified length to the SBF atom string format (e.g., x0 & x1' & ...)."""
    if len(bit_string) != length:
        raise ValueError(f"Bit string length {len(bit_string)} does not match specified length {length}.")
    if not all(c in '01' for c in bit_string):
        raise ValueError("Bit string contains invalid characters (must be 0 or 1).")

    parts = []
    for i, bit in enumerate(bit_string):
        var_num = i # 0-indexed for Tau variables (x0, x1, ...)
        if bit == '0':
            parts.append(f"x{var_num}'")
        else:
            parts.append(f"x{var_num}")
    sbf_result = " & ".join(parts)
    return sbf_result

def sbf_atom_to_bits(sbf_atom_str: str) -> str | None:
    """Converts an SBF atom string (e.g., x0 & x1' & x2) back to a bit string."""
    if not isinstance(sbf_atom_str, str):
        # print(f"[DEBUG][sbf_atom_to_bits] Input is not a string: {type(sbf_atom_str)}")
        return None

    # Handle Tau's potential output format like "... o1[1] := x0 & x1' ..."
    delimiter = ":="
    if delimiter in sbf_atom_str:
        sbf_atom_str = sbf_atom_str.split(delimiter, 1)[-1].strip()
    
    # Handle SBF constants like {x0'}:sbf by extracting the core part if needed
    # This is a basic attempt; more robust parsing might be needed for complex SBF literals.
    sbf_literal_match = re.match(r"\{([^}]+)\'\}:sbf", sbf_atom_str)
    if sbf_literal_match:
        # This is for simple cases like {x0'}:sbf -> x0 or {x123'}:sbf -> x123
        # It doesn't handle multi-variable SBF literals like {x0&x1'}:sbf directly for bit reconstruction.
        # For the purpose of the test mock, this is primarily to handle single-bit SBF constants.
        # If it's a complex literal, it likely won't be parsed into a multi-bit string by this logic.
        inner_content = sbf_literal_match.group(1)
        if inner_content == "x0" and sbf_atom_str.startswith("{x0'}") : # Specifically for {x0'}:sbf -> "0"
            return "0"
        # Add more specific constant SBF string mappings to bits if needed by the mock.
        # print(f"[DEBUG][sbf_atom_to_bits] SBF literal found: {sbf_atom_str}, inner: {inner_content}. Not converting to multi-bit string via this path.")
        # For now, if it's not {x0'}:sbf, it won't be parsed into bits by this SBF literal path.
        # Fall through to general parsing if it doesn't match simple cases.

    # Find all xN or xN' parts
    atoms = re.findall(r"x(\d+)('?)", sbf_atom_str)
    if not atoms:
        # print(f"[DEBUG][sbf_atom_to_bits] No SBF atoms (xN) found in: '{sbf_atom_str}'")
        # Check if it's a direct bit string (e.g. "0", "1", or longer for some edge cases)
        if all(c in '01' for c in sbf_atom_str) and len(sbf_atom_str) > 0:
            # print(f"[DEBUG][sbf_atom_to_bits] Interpreting as direct bit string: {sbf_atom_str}")
            return sbf_atom_str
        return None

    max_index = -1
    parsed_bits = {}

    for index_str, prime in atoms:
        index = int(index_str)
        if index > max_index:
            max_index = index
        
        bit_value = '1' if not prime else '0'
        
        if index in parsed_bits and parsed_bits[index] != bit_value:
            # This indicates an inconsistent SBF string like "x0 & x0'"
            # print(f"[WARN][sbf_atom_to_bits] Inconsistent SBF string: atom x{index} defined multiple ways.")
            return None # Or handle error as appropriate
        parsed_bits[index] = bit_value

    if max_index == -1: # Should not happen if atoms were found, but as a safeguard
        return None

    # Construct the full bit string up to the max_index found
    bit_list = ['0'] * (max_index + 1)
    for index, bit_val in parsed_bits.items():
        bit_list[index] = bit_val
    
    final_bits = "".join(bit_list)
    # print(f"[DEBUG][sbf_atom_to_bits] Converted SBF '{sbf_atom_str}' to bits '{final_bits}'")
    return final_bits

def decimal_to_8bit_binary(decimal_str: str) -> str:
    """Converts a decimal string (0-255) to an 8-bit binary string."""
    try:
        amount_int = int(decimal_str)
        if not (0 <= amount_int <= 255):
            raise ValueError(f"Amount '{amount_int}' out of range (must be 0-255 for 8 bits)")
        binary_str = format(amount_int, '08b')
        return binary_str
    except ValueError as e:
        # print(f"  [DEBUG] decimal_to_8bit_binary: Error converting '{decimal_str}': {e}")
        raise ValueError(f"Invalid amount '{decimal_str}': Must be a number between 0 and 255.")

# sbf_output_heuristic_check and normalize_sbf_atoms are likely specific to tau_manager
# and might not be needed in a generic utils.py if not used elsewhere.
# For now, keeping them if they were part of the original utils.py structure.

def sbf_output_heuristic_check(line_strip, input_sbf, sbf_defs):
    """
    Checks if a line plausibly looks like an expected SBF output atom or code.
    Args:
        line_strip (str): The stripped line from Tau's stdout.
        input_sbf (str): The original SBF sent as input.
        sbf_defs (module): The imported sbf_defs module.
    Returns:
        bool: True if the line matches the heuristic, False otherwise.
    """
    if not line_strip:
        return False

    delimiter = ":="
    if delimiter in line_strip:
        line_strip = line_strip.split(delimiter, 1)[-1].strip()

    atom_tokens = re.findall(r"x\d+'?", line_strip)
    if len(atom_tokens) >= 3: 
        return True
    
    # Collect all known SBF code values from sbf_defs module for checking
    known_codes = [getattr(sbf_defs, name) for name in dir(sbf_defs) 
                   if name.endswith("_SBF") and isinstance(getattr(sbf_defs, name), str)]
    known_codes.append(sbf_defs.SBF_LOGICAL_ZERO) # Add SBF_ZERO if it's used generically
    known_codes.append(input_sbf) # Check for echo

    if line_strip in known_codes:
        return True
        
    # Heuristic: if it contains common SBF structure elements and is short
    if ("x" in line_strip and ("&" in line_strip or "'" in line_strip)) and len(line_strip) < 80: # Arbitrary short length
        # This is a weak heuristic for unrecognised SBF strings that are not simple codes
        # print(f"[DEBUG][sbf_output_heuristic_check] Line '{line_strip}' passed weak SBF structure heuristic.")
        return True

    return False

def normalize_sbf_atoms(s: str) -> str:
    """
    Normalize a possibly space- or ampersand-separated list of SBF atoms:
    - Extract tokens x<id>'?
    - Sort by numeric id (0-indexed)
    - Join with ' & ' separator
    """
    atoms = re.findall(r"x(\d+)('?)", s)
    if atoms:
        try:
            # Sort by the integer value of the index
            sorted_atom_tuples = sorted(atoms, key=lambda t: int(t[0]))
            # Reconstruct the xN or xN' string
            sorted_atom_strings = [f"x{idx}{prime}" for idx, prime in sorted_atom_tuples]
        except Exception as e:
            # print(f"[DEBUG][normalize_sbf_atoms] Error sorting atoms: {e}. Original: '{s}'")
            return s # Return original on error
        return ' & '.join(sorted_atom_strings)
    return s