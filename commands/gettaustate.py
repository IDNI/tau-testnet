def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 1:
        return "ERROR: Usage: gettaustate\r\n"

    state = container.chain_state.get_rules_state()
    return f"TAUSTATE:\n{state}\r\n"
