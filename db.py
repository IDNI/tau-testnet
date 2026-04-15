import json
import logging
import os
import sqlite3
import threading
from typing import Dict, List, Optional
from contextlib import contextmanager

import config
import block as block_module
from errors import DatabaseError


logger = logging.getLogger(__name__)

# Internal SQLite connection and lock for thread-safety
_db_conn = None
_db_lock = threading.Lock()

def init_db():
    """Initializes the SQLite database, creating necessary tables."""
    global _db_conn
    data_dir = os.path.dirname(config.STRING_DB_PATH)
    try:
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(str(data_dir), exist_ok=True)

        conn = sqlite3.connect(config.STRING_DB_PATH, check_same_thread=False)
        conn.execute('PRAGMA foreign_keys = ON;')
        with conn:
            # Migration to Fork Choice schema: Check if block_hash is PK (or is missing)
            cur = conn.execute("PRAGMA table_info(blocks);")
            blocks_cols = {row[1]: row for row in cur.fetchall()}
            if blocks_cols and ("block_hash" not in blocks_cols or blocks_cols["block_hash"][5] != 1):
                logger.info("Migrating to Fork Choice schema (dropping old tables)...")
                conn.execute("DROP TABLE IF EXISTS blocks;")
                conn.execute("DROP TABLE IF EXISTS accounts;")
                conn.execute("DROP TABLE IF EXISTS chain_state;")
                conn.execute("DROP TABLE IF EXISTS mempool;")

            conn.execute('''
                CREATE TABLE IF NOT EXISTS tau_strings (
                    id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    text TEXT    NOT NULL UNIQUE
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS mempool (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_hash     TEXT    NOT NULL UNIQUE,
                    payload     TEXT    NOT NULL,
                    received_at INTEGER NOT NULL,
                    status      TEXT    NOT NULL DEFAULT 'pending', -- pending, reserved
                    reserved_at INTEGER NOT NULL DEFAULT 0,
                    batch_id    TEXT
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocks (
                    block_hash    TEXT PRIMARY KEY,
                    block_number  INTEGER NOT NULL,
                    previous_hash TEXT NOT NULL,
                    timestamp     INTEGER NOT NULL,
                    block_data    TEXT NOT NULL
                );
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_blocks_number ON blocks(block_number);')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_blocks_prev_hash ON blocks(previous_hash);')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS accounts (
                    address         TEXT PRIMARY KEY,
                    balance         INTEGER NOT NULL,
                    sequence_number INTEGER NOT NULL DEFAULT 0
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS chain_state (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS consensus_updates_v2 (
                    update_id TEXT PRIMARY KEY,
                    rule_revisions TEXT NOT NULL,
                    activate_at_height INTEGER NOT NULL,
                    host_contract_patch TEXT
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS consensus_votes_v2 (
                    update_id TEXT NOT NULL,
                    voter_pubkey TEXT NOT NULL,
                    PRIMARY KEY (update_id, voter_pubkey)
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS consensus_scheduled (
                    activation_height INTEGER NOT NULL,
                    update_id TEXT NOT NULL
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS consensus_archival (
                    update_id TEXT PRIMARY KEY
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS peers (
                    peer_id      TEXT PRIMARY KEY,
                    addrs_json   TEXT NOT NULL,
                    agent        TEXT,
                    network_id   TEXT,
                    genesis_hash TEXT,
                    head_number  INTEGER,
                    head_hash    TEXT,
                    last_seen    INTEGER
                );
            ''')
            


            # Migration: Check schema against requirements
            cur = conn.execute("PRAGMA table_info(mempool);")
            cols_info = {row[1]: row for row in cur.fetchall()}
            
            should_migrate = False
            if "tx_hash" not in cols_info: 
                should_migrate = True
            elif "reserved_at" in cols_info and cols_info["reserved_at"][3] == 0: 
                # Check 3rd index 'notnull': 0 means nullable (bad), 1 means NOT NULL (good)
                should_migrate = True
            
            if should_migrate:
                logger.info("Migrating mempool to new schema (dropping old table)...")
                conn.execute("DROP TABLE IF EXISTS mempool;")
                conn.execute('''
                    CREATE TABLE mempool (
                        id          INTEGER PRIMARY KEY AUTOINCREMENT,
                        tx_hash     TEXT    NOT NULL UNIQUE,
                        payload     TEXT    NOT NULL,
                        received_at INTEGER NOT NULL,
                        status      TEXT    NOT NULL DEFAULT 'pending', -- pending, reserved
                        reserved_at INTEGER NOT NULL DEFAULT 0,
                        batch_id    TEXT
                    );
                ''')

    except (sqlite3.Error, OSError) as exc:
        raise DatabaseError(f"Failed to initialize database at {config.STRING_DB_PATH}: {exc}") from exc

    _db_conn = conn
    logger.info("Database initialized at %s", config.STRING_DB_PATH)

@contextmanager
def get_db_connection():
    """Provides thread-safe access to the global SQLite connection."""
    global _db_conn
    if _db_conn is None:
        init_db()
    # Provide the connection inside the global db lock
    with _db_lock:
        yield _db_conn

def reset_mempool_reservations():
    """Unreserves all mempool transactions, returning them to the pending pool."""
    global _db_conn
    if _db_conn is None:
        init_db()
    with _db_lock:
        assert _db_conn is not None
        cur = _db_conn.cursor()
        cur.execute("UPDATE mempool SET status = 'pending', reserved_at = 0, batch_id = NULL")
        _db_conn.commit()

def get_string_id(text: str) -> str:
    """
    Returns a Tau-style ID ('y<id>') for the given text, inserting it if new.
    """
    global _db_conn
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT id FROM tau_strings WHERE text = ?', (text,))
        row = cur.fetchone()
        if row:
            id_num = row[0]
        else:
            cur.execute('INSERT INTO tau_strings(text) VALUES (?)', (text,))
            id_num = cur.lastrowid
            _db_conn.commit()
        return f'y{id_num}'

def get_text_by_id(yid: str) -> str:
    """
    Given a Tau-style ID ('y<id>'), returns the original text.
    Raises KeyError if ID not found.
    """
    global _db_conn
    if _db_conn is None:
        init_db()
    if not yid.startswith('y'):
        raise ValueError(f"Invalid Tau ID format: {yid}")
    try:
        id_num = int(yid[1:])
    except ValueError:
        raise ValueError(f"Invalid Tau ID format: {yid}")
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT text FROM tau_strings WHERE id = ?', (id_num,))
        row = cur.fetchone()
        if row:
            return row[0]
        else:
            raise KeyError(f"No text found for Tau ID: {yid}")

def add_mempool_tx(tx_data: str, tx_hash: str, received_at: int):
    """Adds data to the mempool. Prefixes with 'json:' if it looks like JSON."""
    if _db_conn is None:
        init_db()
    
    # Ensure canonical JSON payload (no 'json:' prefix needed if we are strict, but maintaining for now if callers depend on it)
    # Actually, the plan says "no json: prefix needed". Let's clean it up.
    # The caller is expected to provide canonical JSON. 
    # But wait, sendtx currently sends "json:..." or just raw string.
    # We will strip it here to be safe or assuming caller does it.
    # The plan says: "payload TEXT NOT NULL (canonical JSON string, no “json:” prefix needed)"
    
    payload = tx_data
    if payload.startswith("json:"):
        payload = payload[5:]

    with _db_lock:
        cur = _db_conn.cursor()
        # Idempotency: INSERT OR IGNORE
        cur.execute('''
            INSERT OR IGNORE INTO mempool (tx_hash, payload, received_at, status)
            VALUES (?, ?, ?, 'pending')
        ''', (tx_hash, payload, received_at))
        _db_conn.commit()
        
def count_mempool_txs() -> int:
    """Returns the number of pending transactions in the mempool."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute("SELECT COUNT(*) FROM mempool WHERE status='pending'")
        row = cur.fetchone()
        return row[0] if row else 0

def get_pending_sequence(sender_pubkey: str) -> Optional[int]:
    """
    Returns the highest sequence_number for a given sender currently in the mempool.
    Returns None if the sender has no pending transactions.
    """
    if _db_conn is None:
        init_db()
    
    max_seq = None
    with _db_lock:
        cur = _db_conn.cursor()
        # Only check 'pending' or 'reserved' (not yet mined) transactions
        cur.execute('SELECT payload FROM mempool')
        
        for (payload,) in cur.fetchall():
            try:
                data = json.loads(payload)
                if data.get('sender_pubkey') == sender_pubkey:
                    seq = data.get('sequence_number')
                    if seq is not None and isinstance(seq, int):
                        if max_seq is None or seq > max_seq:
                            max_seq = seq
            except Exception:
                continue
                
    return max_seq

def get_mempool_txs() -> list:
    """
    Deprecated: Use reserve_mempool_txs for mining.
    This just returns all payloads for legacy support / debugging.
    """
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT payload FROM mempool ORDER BY received_at')
        return [row[0] for row in cur.fetchall()]

def reserve_mempool_txs(limit: int = 1000, max_age_seconds: int = 60) -> List[Dict]:
    """
    Selects pending transactions from the mempool (FIFO by received_at)
    AND releases stale reservations (older than max_age_seconds).
    
    Returns a list of dicts: {'id': int, 'tx_hash': str, 'payload': str}
    """
    import uuid
    import time
    if _db_conn is None:
        init_db()
    
    batch_id = str(uuid.uuid4())
    reservations = []
    now_ms = int(time.time() * 1000)
    stale_threshold = now_ms - (max_age_seconds * 1000)
    
    with _db_lock:
        cur = _db_conn.cursor()
        
        # 1. Release stale reservations
        # Ensure we handle NULL reserved_at by checking for > 0 (assuming we only set it to non-null on reservation)
        # But for safety, checking (reserved_at IS NOT NULL AND reserved_at < ?) is better.
        cur.execute('''
            UPDATE mempool 
            SET status='pending', batch_id=NULL, reserved_at=0
            WHERE status='reserved' AND (reserved_at IS NULL OR reserved_at = 0 OR reserved_at < ?)
        ''', (stale_threshold,))
        released = cur.rowcount
        if released > 0:
            logger.info("Released %s stale mempool reservations", released)

        # 2. Select pending
        # We process in order of arrival (received_at)
        cur.execute('''
            SELECT id, tx_hash, payload FROM mempool 
            WHERE status = 'pending' 
            ORDER BY received_at ASC 
            LIMIT ?
        ''', (limit,))
        rows = cur.fetchall()
        
        if not rows:
            return []
            
        # 3. Mark reserved
        ids = [row[0] for row in rows]
        placeholders = ','.join(['?'] * len(ids))
        cur.execute(f'''
            UPDATE mempool 
            SET status = 'reserved', reserved_at = ?, batch_id = ? 
            WHERE id IN ({placeholders})
        ''', (now_ms, batch_id, *ids))
        
        _db_conn.commit()
        
        for row in rows:
            reservations.append({
                'id': row[0],
                'tx_hash': row[1],
                'payload': row[2]
            })
            
    return reservations

def unreserve_mempool_txs(tx_ids: list[int]):
    """
    Reverts specified reserved transactions back to 'pending' state.
    Used when block creation/execution fails for transient reasons (e.g. miner error),
    preserving the transactions for the next attempt.
    """
    if not tx_ids:
        return
        
    with _db_lock:
        try:
            placeholders = ','.join('?' for _ in tx_ids)
            # Set reserved_at=0 to align with NOT NULL schema
            _db_conn.execute(f'''
                UPDATE mempool 
                SET status='pending', batch_id=NULL, reserved_at=0
                WHERE id IN ({placeholders})
            ''', tx_ids)
            _db_conn.commit()
            logger.info("Unreserved %s transactions (returned to pending).", len(tx_ids))
        except Exception as e:
            logger.error("Failed to unreserve transactions: %s", e)

def remove_transactions(tx_ids: List[int]):
    """
    Permanently deletes specific transactions (e.g. processed ones) from the mempool.
    """
    if not tx_ids:
        return
    if _db_conn is None:
        init_db()
        
    with _db_lock:
        cur = _db_conn.cursor()
        placeholders = ','.join(['?'] * len(tx_ids))
        cur.execute(f'DELETE FROM mempool WHERE id IN ({placeholders})', tuple(tx_ids))
        _db_conn.commit()
        logger.debug("Removed %s transactions from mempool", len(tx_ids))

def remove_mempool_by_hashes(tx_hashes: List[str]) -> int:
    """
    Removes mempool transactions matching the provided tx_hash list.
    Returns the number of rows removed.
    """
    if not tx_hashes:
        return 0
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        placeholders = ",".join(["?"] * len(tx_hashes))
        cur.execute(f"DELETE FROM mempool WHERE tx_hash IN ({placeholders})", tuple(tx_hashes))
        _db_conn.commit()
        removed = cur.rowcount or 0
        logger.debug("Removed %s transactions from mempool by hash", removed)
        return removed

def clear_mempool():
    """Clears all transactions from the mempool."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('DELETE FROM mempool')
        _db_conn.commit()
        logger.info("Mempool cleared.")

def add_block(new_block: block_module.Block):
    """Adds a new block to the database."""
    if _db_conn is None:
        init_db()
    
    block_dict = new_block.to_dict()
    block_data_json = json.dumps(block_dict)

    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            'INSERT INTO blocks (block_hash, block_number, previous_hash, timestamp, block_data) VALUES (?, ?, ?, ?, ?)',
            (
                new_block.block_hash,
                new_block.header.block_number,
                new_block.header.previous_hash,
                new_block.header.timestamp,
                block_data_json,
            )
        )
        _db_conn.commit()
        logger.info("Added block #%s to database", new_block.header.block_number)

def get_canonical_head_block() -> Optional[Dict]:
    """Retrieves the canonical head block from the database."""
    return get_canonical_head()

def get_block_by_hash(block_hash: str) -> Optional[Dict]:
    """Return the block with the given hash as a parsed dict, or None if missing."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT block_data FROM blocks WHERE block_hash = ? LIMIT 1', (block_hash,))
        row = cur.fetchone()
    if not row:
        return None
    try:
        return json.loads(row[0])
    except json.JSONDecodeError:
        logger.debug("Stored block hash %s contains invalid JSON", block_hash, exc_info=True)
        return None

def get_genesis_hash() -> str:
    """Return the hash of block 0 if it exists, otherwise empty string."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT block_hash FROM blocks WHERE block_number = 0 LIMIT 1')
        row = cur.fetchone()
    if row:
        return row[0]
    return ""

def get_all_blocks() -> List[Dict]:
    """Returns all blocks ordered by block_number ascending as parsed dicts."""
    if _db_conn is None:
        init_db()
    out: List[Dict] = []
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT block_data FROM blocks ORDER BY block_number ASC')
        rows = cur.fetchall()
        for (block_json,) in rows:
            try:
                out.append(json.loads(block_json))
            except Exception:
                continue
    return out

def get_canonical_blocks_at_or_after_height(block_number: int) -> List[Dict]:
    """
    Returns canonical blocks with block_number >= the given number, ordered by block_number ASC.
    """
    head = get_canonical_head()
    if not head:
        return []
    head_hash = head.get('block_hash')
    if not head_hash:
        return []
        
    import config
    path = get_chain_path(head_hash, get_genesis_hash())
    path_hashes = set(path)
    path_hashes.add(get_genesis_hash())
    if not path_hashes:
        return []
        
    out: List[Dict] = []
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT block_data, block_hash FROM blocks WHERE block_number >= ? ORDER BY block_number ASC', (block_number,))
        rows = cur.fetchall()
        for block_json, b_hash in rows:
            if b_hash in path_hashes:
                try:
                    out.append(json.loads(block_json))
                except Exception:
                    continue
    return out

def load_chain_state() -> tuple[Dict[str, int], Dict[str, int], str, str, str, str, List[Dict], List[Dict], List[tuple[int, str]], List[str]]:
    """
    Loads the persisted chain state.
    Returns: (balances, sequence_numbers, application_rules, consensus_rules, active_consensus_id, canonical_head_hash, pending_updates, votes, scheduled, archival)
    """
    if _db_conn is None:
        init_db()
    
    balances: Dict[str, int] = {}
    sequences: Dict[str, int] = {}
    application_rules = ""
    consensus_rules = ""
    active_consensus_id = ""
    canonical_head_hash = ""
    pending_updates: List[Dict] = []
    votes: List[Dict] = []
    scheduled: List[tuple[int, str]] = []
    archival: List[str] = []

    with _db_lock:
        cur = _db_conn.execute('SELECT address, balance, sequence_number FROM accounts')
        for address, balance, seq in cur.fetchall():
            balances[address] = balance
            sequences[address] = seq
        
        cur = _db_conn.execute(
            'SELECT key, value FROM chain_state WHERE key IN (?, ?, ?, ?, ?)',
            ('current_rules', 'application_rules', 'consensus_rules', 'active_consensus_id', 'canonical_head_hash')
        )
        entries = dict(cur.fetchall())
        application_rules = entries.get('application_rules', entries.get('current_rules', ''))
        consensus_rules = entries.get('consensus_rules', '')
        active_consensus_id = entries.get('active_consensus_id', 'tau_poa_v1')
        canonical_head_hash = entries.get('canonical_head_hash', '')
        
        try:
            cur = _db_conn.execute('SELECT update_id, rule_revisions, activate_at_height, host_contract_patch FROM consensus_updates_v2')
            for row in cur.fetchall():
                pending_updates.append({
                    'update_id': row[0],
                    'rule_revisions': json.loads(row[1]),
                    'activate_at_height': row[2],
                    'host_contract_patch': json.loads(row[3]) if row[3] else None
                })
                
            cur = _db_conn.execute('SELECT update_id, voter_pubkey FROM consensus_votes_v2')
            for row in cur.fetchall():
                votes.append({
                    'update_id': row[0],
                    'voter_pubkey': row[1]
                })

            cur = _db_conn.execute('SELECT activation_height, update_id FROM consensus_scheduled')
            for row in cur.fetchall():
                scheduled.append((row[0], row[1]))

            cur = _db_conn.execute('SELECT update_id FROM consensus_archival')
            for row in cur.fetchall():
                archival.append(row[0])
        except sqlite3.OperationalError:
            pass # Pre-migration fallback ignored, we just clear legacy proposals
            
    return balances, sequences, application_rules, consensus_rules, active_consensus_id, canonical_head_hash, pending_updates, votes, scheduled, archival


def save_canonical_state_atomically(head_hash: str, head_num: int, balances: Dict[str, int], sequences: Dict[str, int], application_rules: str, consensus_rules: str, active_consensus_id: str, pending_updates: List[Dict], votes: List[Dict], scheduled: List[tuple[int, str]], archival: List[str]):
    """
    Saves the chain state to the database atomically with Full Replace semantics for accounts, and new v2 update tracking.
    """
    if _db_conn is None:
        init_db()
        
    with _db_lock:
        with _db_conn: # Transaction
            _db_conn.execute(
                'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                ('application_rules', application_rules)
            )
            _db_conn.execute(
                'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                ('consensus_rules', consensus_rules)
            )
            _db_conn.execute(
                'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                ('active_consensus_id', active_consensus_id)
            )
            _db_conn.execute(
                'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                ('canonical_head_hash', head_hash)
            )
            _db_conn.execute(
                'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                ('canonical_head_number', str(head_num))
            )

            _db_conn.execute('DELETE FROM accounts')
            for address, balance in balances.items():
                seq = sequences.get(address, 0)
                _db_conn.execute(
                    'INSERT INTO accounts (address, balance, sequence_number) VALUES (?, ?, ?)',
                    (address, balance, seq)
                )
                
            # Full Replace v2 arrays
            _db_conn.execute('DELETE FROM consensus_updates_v2')
            for p in pending_updates:
                _db_conn.execute(
                    'INSERT INTO consensus_updates_v2 (update_id, rule_revisions, activate_at_height, host_contract_patch) VALUES (?, ?, ?, ?)',
                    (p['update_id'], json.dumps(p['rule_revisions']), p['activate_at_height'], json.dumps(p['host_contract_patch']) if p['host_contract_patch'] else None)
                )
                
            _db_conn.execute('DELETE FROM consensus_votes_v2')
            for v in votes:
                _db_conn.execute(
                    'INSERT INTO consensus_votes_v2 (update_id, voter_pubkey) VALUES (?, ?)',
                    (v['update_id'], v['voter_pubkey'])
                )
                
            _db_conn.execute('DELETE FROM consensus_scheduled')
            for activation_height, update_id in scheduled:
                _db_conn.execute(
                    'INSERT INTO consensus_scheduled (activation_height, update_id) VALUES (?, ?)',
                    (activation_height, update_id)
                )
                
            _db_conn.execute('DELETE FROM consensus_archival')
            for uid in archival:
                _db_conn.execute(
                    'INSERT INTO consensus_archival (update_id) VALUES (?)',
                    (uid,)
                )

def get_candidate_heads() -> List[tuple[str, int]]:
    """
    Returns a list of (block_hash, block_number) for all blocks that do not have any known children.
    """
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('''
            SELECT block_hash, block_number 
            FROM blocks 
            WHERE block_hash NOT IN (
                SELECT previous_hash FROM blocks
            )
        ''')
        return cur.fetchall()

def get_canonical_head() -> Optional[Dict]:
    """
    Returns the block pointed to by canonical_head_hash, or None if not set.
    """
    if _db_conn is None:
        init_db()
    
    canonical_hash = None
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT value FROM chain_state WHERE key = ?', ('canonical_head_hash',))
        row = cur.fetchone()
        if row:
            canonical_hash = row[0]
            
    if not canonical_hash:
        return None
        
    return get_block_by_hash(canonical_hash)

def get_canonical_locator(max_entries: int = 32) -> List[str]:
    """
    Returns a list of block hashes representing the canonical chain, starting from
    the canonical head, with exponential backoff steps, ending at Genesis.
    """
    if _db_conn is None:
        init_db()

    genesis_hash = get_genesis_hash()
    canonical_hash = None
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT value FROM chain_state WHERE key = ?', ('canonical_head_hash',))
        row = cur.fetchone()
        if row:
            canonical_hash = row[0]

    import config
    if not canonical_hash:
        return [genesis_hash]

    locator = []
    step = 1
    current_hash = canonical_hash
    
    visited = set()
    with _db_lock:
        cur = _db_conn.cursor()
        while current_hash and len(locator) < max_entries:
            if current_hash in visited:
                break
            visited.add(current_hash)
            locator.append(current_hash)
            
            for _ in range(step):
                cur.execute('SELECT previous_hash FROM blocks WHERE block_hash = ?', (current_hash,))
                row = cur.fetchone()
                if not row or not row[0]:
                    # Check if genesis config hash
                    if current_hash != genesis_hash:
                        current_hash = None
                    break
                current_hash = row[0]
                if current_hash in visited:
                    break
                if current_hash == genesis_hash:
                    break
            
            if len(locator) > 10:
                step *= 2
                
    if genesis_hash not in locator and len(locator) < max_entries:
        locator.append(genesis_hash)
        
    return locator

def get_chain_path(start_hash: str, target_ancestor: str, max_depth: int = 2000) -> List[str]:
    """
    Walks backwards from start_hash to target_ancestor. Returns the path in chronological order
    (target_ancestor+1 ... start_hash). 
    Raises ValueError if target_ancestor is not found or path exceeds max_depth.
    """
    if _db_conn is None:
        init_db()
        
    path = []
    current_hash = start_hash
    visited = set()
    
    with _db_lock:
        cur = _db_conn.cursor()
        while current_hash != target_ancestor:
            if current_hash in visited:
                raise ValueError(f"Cycle detected in blockchain graph at {current_hash}")
            visited.add(current_hash)
            
            if len(path) > max_depth:
                raise ValueError(f"Ancestry search exceeded max_depth of {max_depth}")
                
            path.append(current_hash)
            
            cur.execute('SELECT previous_hash FROM blocks WHERE block_hash = ?', (current_hash,))
            row = cur.fetchone()
            if not row:
                raise ValueError(f"Block not found during ancestry walk: {current_hash} (searching for {target_ancestor})")
            
            if not row[0]:
                raise ValueError(f"Target ancestor {target_ancestor} not found in path from {start_hash}")
                
            current_hash = row[0]
            
    path.reverse()
    return path



# --- Peerstore DB-backed functions ---
from typing import Optional, Dict, List

def upsert_peer_basic(peer_id: str,
                      addrs: List[str],
                      agent: Optional[str] = None,
                      network_id: Optional[str] = None,
                      genesis_hash: Optional[str] = None,
                      head_number: Optional[int] = None,
                      head_hash: Optional[str] = None,
                      last_seen: Optional[int] = None) -> None:
    """
    Insert or update a peer entry with basic metadata. Addresses are stored as JSON array of strings.
    """
    global _db_conn
    if _db_conn is None:
        init_db()
    payload = {
        "agent": agent,
        "network_id": network_id,
        "genesis_hash": genesis_hash,
        "head_number": head_number,
        "head_hash": head_hash,
        "last_seen": last_seen,
    }
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('''
            INSERT INTO peers (peer_id, addrs_json, agent, network_id, genesis_hash, head_number, head_hash, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(peer_id) DO UPDATE SET
                addrs_json=excluded.addrs_json,
                agent=COALESCE(excluded.agent, peers.agent),
                network_id=COALESCE(excluded.network_id, peers.network_id),
                genesis_hash=COALESCE(excluded.genesis_hash, peers.genesis_hash),
                head_number=COALESCE(excluded.head_number, peers.head_number),
                head_hash=COALESCE(excluded.head_hash, peers.head_hash),
                last_seen=COALESCE(excluded.last_seen, peers.last_seen)
        ''', (peer_id, json.dumps(addrs), payload["agent"], payload["network_id"], payload["genesis_hash"],
              payload["head_number"], payload["head_hash"], payload["last_seen"]))
        _db_conn.commit()

def load_peers_basic() -> Dict[str, List[str]]:
    """
    Returns a mapping peer_id -> list(addrs as strings) from the database.
    """
    global _db_conn
    if _db_conn is None:
        init_db()
    out: Dict[str, List[str]] = {}
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT peer_id, addrs_json FROM peers')
        for pid, addrs_json in cur.fetchall():
            try:
                arr = json.loads(addrs_json) if addrs_json else []
                if isinstance(arr, list):
                    out[str(pid)] = [str(x) for x in arr]
            except Exception:
                continue
    return out
