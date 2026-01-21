import json
import logging
import os
import sqlite3
import threading
from typing import Dict, List, Optional

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
            os.makedirs(data_dir, exist_ok=True)

        conn = sqlite3.connect(config.STRING_DB_PATH, check_same_thread=False)
        conn.execute('PRAGMA foreign_keys = ON;')
        with conn:
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
                    block_number  INTEGER PRIMARY KEY,
                    block_hash    TEXT NOT NULL UNIQUE,
                    previous_hash TEXT NOT NULL,
                    timestamp     INTEGER NOT NULL,
                    block_data    TEXT NOT NULL
                );
            ''')
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
            # Migration to new schema: if old columns exist or table structure is wrong, drop and recreate.
            # Since mempool is transient, we can safely drop it.
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
            'INSERT INTO blocks (block_number, block_hash, previous_hash, timestamp, block_data) VALUES (?, ?, ?, ?, ?)',
            (
                new_block.header.block_number,
                new_block.block_hash,
                new_block.header.previous_hash,
                new_block.header.timestamp,
                block_data_json,
            )
        )
        _db_conn.commit()
        logger.info("Added block #%s to database", new_block.header.block_number)

def get_latest_block() -> Optional[Dict]:
    """Retrieves the latest block (highest block_number) from the database."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT block_data FROM blocks ORDER BY block_number DESC LIMIT 1')
        row = cur.fetchone()
        if row:
            return json.loads(row[0])
        else:
            return None

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

def get_blocks_after(block_number: int) -> List[Dict]:
    """
    Returns all blocks with block_number >= the given number, ordered by block_number ASC.
    """
    if _db_conn is None:
        init_db()
    out: List[Dict] = []
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT block_data FROM blocks WHERE block_number >= ? ORDER BY block_number ASC', (block_number,))
        rows = cur.fetchall()
        for (block_json,) in rows:
            try:
                out.append(json.loads(block_json))
            except Exception:
                continue
    return out

def load_chain_state() -> tuple[Dict[str, int], Dict[str, int], str, str]:
    """
    Loads the persisted chain state (balances, sequences, rules, last_block_hash).
    Returns: (balances, sequence_numbers, current_rules, last_processed_block_hash)
    """
    if _db_conn is None:
        init_db()
    
    balances: Dict[str, int] = {}
    sequences: Dict[str, int] = {}
    current_rules = ""
    last_processed_block_hash = ""

    with _db_lock:
        # Load accounts
        cur = _db_conn.execute('SELECT address, balance, sequence_number FROM accounts')
        for address, balance, seq in cur.fetchall():
            balances[address] = balance
            sequences[address] = seq
        
        # Load state
        cur = _db_conn.execute(
            'SELECT key, value FROM chain_state WHERE key IN (?, ?)',
            ('current_rules', 'last_processed_block_hash')
        )
        entries = dict(cur.fetchall())
        current_rules = entries.get('current_rules', '')
        last_processed_block_hash = entries.get('last_processed_block_hash', '')
        
    return balances, sequences, current_rules, last_processed_block_hash

def save_chain_state(balances: Dict[str, int], sequences: Dict[str, int], rules: str, last_block_hash: str):
    """
    Saves the chain state to the database atomically.
    """
    if _db_conn is None:
        init_db()
        
    with _db_lock:
        with _db_conn: # Transaction
            _db_conn.execute(
                'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                ('current_rules', rules)
            )
            _db_conn.execute(
                'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                ('last_processed_block_hash', last_block_hash)
            )
            for address, balance in balances.items():
                seq = sequences.get(address, 0)
                _db_conn.execute(
                    'INSERT OR REPLACE INTO accounts (address, balance, sequence_number) VALUES (?, ?, ?)',
                    (address, balance, seq)
                )

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
