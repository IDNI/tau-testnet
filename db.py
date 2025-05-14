import sqlite3
import threading
import os

import config

# Internal SQLite connection and lock for thread-safety
_db_conn = None
_db_lock = threading.Lock()

def init_db():
    """
    Initializes the SQLite database, creating necessary tables.
    """
    global _db_conn
    # Ensure data directory exists
    data_dir = os.path.dirname(config.STRING_DB_PATH)
    if data_dir and not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
    # Connect with shared thread access
    conn = sqlite3.connect(config.STRING_DB_PATH, check_same_thread=False)
    print(f"  [INFO][db] Initialized with {config.STRING_DB_PATH}.")
    # Enable foreign keys if needed in future
    conn.execute('PRAGMA foreign_keys = ON;')
    # Create tau_strings table for mapping text to IDs
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

    _db_conn = conn

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

