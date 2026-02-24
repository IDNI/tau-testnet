import db

def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return "ERROR: Usage: getsequence <address>\r\n"
    
    address = parts[1]
    seq = container.chain_state.get_sequence_number(address)
    
    pending_seq = db.get_pending_sequence(address)
    if pending_seq is not None and pending_seq >= seq:
        seq = pending_seq + 1
        
    return f"SEQUENCE: {seq}\r\n"
