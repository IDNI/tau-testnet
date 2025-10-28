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
                    id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    sbf  TEXT    NOT NULL
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

def add_mempool_tx(tx_data: str):
    """Adds data to the mempool. Prefixes with 'json:' if it looks like JSON."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        # Basic check to see if it might be JSON
        prefix = ""
        if tx_data.strip().startswith('{') and tx_data.strip().endswith('}'):
            prefix = "json:"
        cur = _db_conn.cursor()
        cur.execute('INSERT INTO mempool(sbf) VALUES(?)', (prefix + tx_data,))
        _db_conn.commit()

def get_mempool_txs() -> list:
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT sbf FROM mempool ORDER BY id')
        return [row[0] for row in cur.fetchall()]

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
