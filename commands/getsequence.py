def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return "ERROR: Usage: getsequence <address>\r\n"
    
    address = parts[1]
    seq = container.chain_state.get_sequence_number(address)
    return f"SEQUENCE: {seq}\r\n"
