import json
import logging

logger = logging.getLogger(__name__)

def execute(raw_command: str, container):
    parts = raw_command.split()
    if len(parts) != 2:
        return "ERROR: Usage: history <address>\r\n"
    
    history_addr = parts[1]
    items = []
    
    # Access db module via container
    db_module = container.db
    
    for entry in db_module.get_mempool_txs():
        if entry.startswith("json:"):
            try:
                payload = json.loads(entry[5:])
            except Exception:
                logger.debug("Skipping invalid mempool json entry for history")
                continue
            
            ops = payload.get("operations", {}).get("1", [])
            # Check if sender or any operation involves the address
            if payload.get("sender_pubkey") == history_addr or any(isinstance(op, (list, tuple)) and history_addr in op for op in ops):
                items.append(json.dumps(payload, separators=(",", ":"), sort_keys=True))
                
    if items:
        return "HISTORY:\n" + "\n".join(items) + "\r\n"
    else:
        return "HISTORY: empty\r\n"
