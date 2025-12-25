from typing import TYPE_CHECKING
import json

if TYPE_CHECKING:
    from app.container import ServiceContainer

def execute(cmd: str, container: 'ServiceContainer') -> str:
    """
    Returns a list of all known account addresses.
    Usage: getallaccounts
    """
    balances = container.chain_state._balances.copy() # Thread-safe copy if locked? Accessing _balances directly might be unsafe without lock, but chain_state exposes locking via methods? 
    # chain_state._balances is protected by _balance_lock in chain_state.py methods.
    # We should probably access it via a new public method in chain_state.py or just access it carefully.
    # Since we are adding this command, let's look at chain_state.py again. It exposes _balances but it's internal.
    # Ideally we should add `get_all_addresses()` to chain_state.py. But I cannot modify chain_state.py easily if I want to avoid side effects. 
    # Actually, I can just modify chain_state.py to add `get_all_addresses`.
    
    # For now, let's just access it under lock in the command if possible, or assume eventual consistency. 
    # Wait, the `execute` method in commands runs in the same process? Yes.
    # `chain_state` module is imported.
    
    # Let's try to access it via container.chain_state._balances
    # Safest is to add a method to chain_state.py.
    
    with container.chain_state._balance_lock:
        addresses = list(container.chain_state._balances.keys())
        
    return json.dumps(addresses)
