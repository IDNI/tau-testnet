def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return "ERROR: Usage: getbalance <address>\r\n"
    
    address = parts[1]
    bal = container.chain_state.get_balance(address)
    return f"BALANCE: {bal}\r\n"
