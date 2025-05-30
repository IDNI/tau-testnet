import threading

# Lock for thread-safe access to balances
_balance_lock = threading.Lock()

# In-memory balance table
# Maps full BLS public key hex strings to integer amounts
_balances = {}

# Lock for thread-safe access to sequence numbers
_sequence_lock = threading.Lock()

# In-memory sequence numbers table: maps address to sequence number
_sequence_numbers = {}

GENESIS_ADDRESS = "91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6"
GENESIS_BALANCE = 15
# Private Key (integer): 8054597235389493115102853815869281665959971363731141151742872399797457604361
# Private Key (hex, 32 bytes): 11cebd90117355080b392cb7ef2fbdeff1150a124d29058ae48b19bebecd4f09
# Public Key (hex, 48 bytes, G1 compressed): 91423993fe5c3a7e0c0d466d9a26f502adf9d39f370649d25d1a6c2500d277212e8aa23e0e10c887cb4b6340d2eebce6

# Private Key (integer): 3046806499649528081017455507187410877623448292955181009054900221062259370659
# Private Key (hex, 32 bytes): 06bc6e6e15a4b40df028da6901e471fa1facc5e9fad04408ab864c7ccb036aa3
# Public Key (hex, 48 bytes, G1 compressed): 893c8134a31379c394b4ed31e67daf9565b1d2022aa96d83ca88d013bc208672bcf73dae5cc105da1e277109584239b2

def init_chain_state():
    """Initializes the chain state with genesis balance."""
    with _balance_lock:
        _balances[GENESIS_ADDRESS] = GENESIS_BALANCE
    print(f"[INFO][chain_state] Chain state initialized. Genesis address {GENESIS_ADDRESS[:10]}... funded with {GENESIS_BALANCE} AGRS.")

def get_balance(address_hex: str) -> int:
    """Returns the balance of the given address. Returns 0 if address not found."""
    with _balance_lock:
        return _balances.get(address_hex, 0)

def update_balances_after_transfer(from_address_hex: str, to_address_hex: str, amount: int) -> bool:
    """
    Updates balances for a transfer. Assumes validation (including sufficient funds)
    has already occurred.
    Returns True if update was successful, False otherwise (e.g., an unexpected issue).
    """
    if amount <= 0:
        print(f"[WARN][chain_state] Attempted to update balance with non-positive amount: {amount}")
        return False # Should have been caught by Tau

    with _balance_lock:
        current_from_balance = _balances.get(from_address_hex, 0)
        
        # This check should be redundant if Python pre-validation + Tau validation occurred
        if current_from_balance < amount:
            print(f"[ERROR][chain_state] Insufficient funds for {from_address_hex[:10]}... to send {amount}. Has: {current_from_balance}. THIS SHOULD NOT HAPPEN IF PRE-VALIDATED.")
            return False

        current_to_balance = _balances.get(to_address_hex, 0)
        
        _balances[from_address_hex] = current_from_balance - amount
        _balances[to_address_hex] = current_to_balance + amount
        
        print(f"[INFO][chain_state] Balances updated: {from_address_hex[:10]}... now {_balances[from_address_hex]}, {to_address_hex[:10]}... now {_balances[to_address_hex]}")
        return True

def get_sequence_number(address_hex: str) -> int:
    """Returns the current sequence number for the given address (defaults to 0)."""
    with _sequence_lock:
        return _sequence_numbers.get(address_hex, 0)

def increment_sequence_number(address_hex: str):
    """Increments the sequence number for the given address."""
    with _sequence_lock:
        _sequence_numbers[address_hex] = _sequence_numbers.get(address_hex, 0) + 1
