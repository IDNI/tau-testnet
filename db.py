import json
import logging
import os
import sqlite3
import threading
from typing import Dict, List, Optional
from contextlib import contextmanager

import config
import block as block_module
from consensus.lanes import LANE_FAST, LANE_SLOW, classify_lane_payload
from errors import DatabaseError


logger = logging.getLogger(__name__)

# Internal SQLite connection and lock for thread-safety
_db_conn = None
_db_lock = threading.Lock()

# Expected on-disk schema version. Bump only with an explicit migration path;
# init_db refuses to start on mismatch instead of silently dropping tables.
SCHEMA_VERSION = 1

# Default upper bound on pending mempool rows; enforced at insert time in
# add_mempool_tx. Overridden at runtime by config.MAX_MEMPOOL_TXS
# (env: TAU_MAX_MEMPOOL_TXS) via _configured_mempool_max(); this constant is
# only the fallback when config is unavailable or unset.
MEMPOOL_MAX_TXS = 5000


def _configured_mempool_max() -> int:
    """Effective cap on pending mempool rows.

    Reads the live, env-synced config value (config.MAX_MEMPOOL_TXS, fed by
    TAU_MAX_MEMPOOL_TXS) so the DB-layer eviction honors the same limit as the
    soft admission pre-check in commands/sendtx.py. Falls back to the module
    default if config is missing or non-positive.
    """
    limit = getattr(config, "MAX_MEMPOOL_TXS", None)
    if isinstance(limit, int) and limit > 0:
        return limit
    return MEMPOOL_MAX_TXS


def _is_hash_hex(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        bytes.fromhex(value)
    except ValueError:
        return False
    return True


def _rewrite_genesis_hash(
    conn: sqlite3.Connection,
    old_hash: str,
    canonical_hash: str,
    block_payload: dict,
) -> bool:
    if not old_hash or not _is_hash_hex(canonical_hash):
        return False

    payload = dict(block_payload or {})
    payload["block_hash"] = canonical_hash
    if "hash" in payload:
        payload["hash"] = canonical_hash
    normalized_block_data = json.dumps(payload)

    existing = conn.execute(
        "SELECT 1 FROM blocks WHERE block_hash = ? LIMIT 1",
        (canonical_hash,),
    ).fetchone()

    if existing and old_hash != canonical_hash:
        conn.execute(
            "UPDATE blocks SET block_data = ? WHERE block_hash = ?",
            (normalized_block_data, canonical_hash),
        )
        conn.execute(
            "DELETE FROM blocks WHERE block_hash = ? AND block_number = 0",
            (old_hash,),
        )
    else:
        conn.execute(
            """
            UPDATE blocks
            SET block_hash = ?, previous_hash = ?, block_data = ?
            WHERE block_hash = ? AND block_number = 0
            """,
            (
                canonical_hash,
                payload.get("header", {}).get("previous_hash", "0" * 64),
                normalized_block_data,
                old_hash,
            ),
        )

    conn.execute(
        "UPDATE blocks SET previous_hash = ? WHERE previous_hash = ?",
        (canonical_hash, old_hash),
    )
    conn.execute(
        "UPDATE chain_state SET value = ? WHERE key = 'canonical_head_hash' AND value = ?",
        (canonical_hash, old_hash),
    )
    conn.execute(
        "UPDATE peers SET genesis_hash = ? WHERE genesis_hash = ?",
        (canonical_hash, old_hash),
    )
    conn.execute(
        "UPDATE peers SET head_hash = ? WHERE head_hash = ?",
        (canonical_hash, old_hash),
    )
    return True


def normalize_genesis_hash(old_hash: str, canonical_hash: str, block_payload: dict) -> bool:
    """Rewrite a legacy block-0 hash and local references to the canonical artifact hash."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        changed = _rewrite_genesis_hash(_db_conn, old_hash, canonical_hash, block_payload)
        if changed:
            _db_conn.commit()
            logger.info("Normalized legacy genesis hash %s to %s", old_hash, canonical_hash)
        return changed


def _normalize_legacy_genesis_row(conn: sqlite3.Connection) -> None:
    """
    Upgrade older databases that stored block 0 under the sentinel hash "GENESIS".
    Rewrites the row and all local references to the artifact hash when it is
    embedded in the stored block body. If not, load_genesis will repair it once
    data/genesis.json is available.
    """
    try:
        cur = conn.execute(
            "SELECT block_hash, block_data FROM blocks WHERE block_number = 0 LIMIT 1"
        )
        row = cur.fetchone()
    except sqlite3.Error:
        return

    if not row:
        return

    stored_hash, block_data_json = row
    if stored_hash != "GENESIS":
        return

    try:
        payload = json.loads(block_data_json)
    except Exception:
        logger.warning("Legacy genesis row found but block_data is invalid JSON; leaving untouched.")
        return

    canonical_hash = payload.get("block_hash") or payload.get("hash")
    if canonical_hash == "GENESIS" or not _is_hash_hex(canonical_hash):
        logger.info("Legacy genesis sentinel found without embedded artifact hash; deferring normalization.")
        return

    try:
        if _rewrite_genesis_hash(conn, "GENESIS", canonical_hash, payload):
            logger.info("Normalized legacy genesis sentinel hash to %s", canonical_hash)
    except sqlite3.Error:
        logger.warning("Failed to normalize legacy genesis row", exc_info=True)

def init_db():
    """Initializes the SQLite database, creating necessary tables."""
    global _db_conn
    data_dir = os.path.dirname(config.STRING_DB_PATH)
    try:
        if data_dir and not os.path.exists(data_dir):
            os.makedirs(str(data_dir), exist_ok=True)

        conn = sqlite3.connect(config.STRING_DB_PATH, check_same_thread=False, timeout=10.0)
        conn.execute('PRAGMA foreign_keys = ON;')
        conn.execute('PRAGMA journal_mode=WAL;')
        conn.execute('PRAGMA busy_timeout=5000;')
        with conn:
            # Legacy pre-Fork-Choice schema detector: refuse to start instead of wiping data.
            cur = conn.execute("PRAGMA table_info(blocks);")
            blocks_cols = {row[1]: row for row in cur.fetchall()}
            if blocks_cols and ("block_hash" not in blocks_cols or blocks_cols["block_hash"][5] != 1):
                raise DatabaseError(
                    f"Database schema at {config.STRING_DB_PATH} predates schema_version {SCHEMA_VERSION}; "
                    "manual migration required (or delete the DB to resync)."
                )

            conn.execute('''
                CREATE TABLE IF NOT EXISTS tau_strings (
                    id   INTEGER PRIMARY KEY AUTOINCREMENT,
                    text TEXT    NOT NULL UNIQUE
                );
            ''')
            # The shrink layer's OWN id space, deliberately not `tau_strings`.
            # That table's autoincrement is shared with
            # TauConsensusEngine._encode_yid (proposer, parent hash, claims json),
            # and the parent hash is unique per block -- so the sequence grows at
            # least one id per block no matter how many addresses exist. Interning
            # addresses there made the shrink bv width track the BLOCK count: a
            # node with 7 addresses drifted to bv[16], and past ~254 rows every
            # newly-seen address raised ShrinkWidthOverflow and re-exec'd the
            # process. Here ids are dense -- one per distinct interned value.
            #
            # Additive table: SCHEMA_VERSION stays put (a bump makes init_db
            # refuse to start and forces every live node to delete its DB).
            # Shrink ids are node-local and eval-only -- never in persisted spec,
            # block data or the state hash -- so an upgrading node just re-interns
            # lazily into this empty table, with new (denser) ids. Its old
            # `bv<width>:<hex>` rows in tau_strings become inert.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tau_shrink_ids (
                    id  INTEGER PRIMARY KEY AUTOINCREMENT,
                    key TEXT    NOT NULL UNIQUE
                );
            ''')
            conn.execute('''
                CREATE TABLE IF NOT EXISTS mempool (
                    id            INTEGER PRIMARY KEY AUTOINCREMENT,
                    tx_hash       TEXT    NOT NULL UNIQUE,
                    payload       TEXT    NOT NULL,
                    received_at   INTEGER NOT NULL,
                    status        TEXT    NOT NULL DEFAULT 'pending', -- pending, reserved
                    reserved_at   INTEGER NOT NULL DEFAULT 0,
                    batch_id      TEXT,
                    fee_limit     INTEGER NOT NULL DEFAULT 0,
                    estimated_fee INTEGER NOT NULL DEFAULT 0
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
                    address           TEXT PRIMARY KEY,
                    balance           INTEGER NOT NULL,
                    sequence_number   INTEGER NOT NULL DEFAULT 0,
                    -- Block timestamp of this account's previous transfer, 0 if
                    -- it has never sent one (issue #21). Deliberately NOT part
                    -- of compute_accounts_hash: it is derived from the accepted
                    -- transfer history, so any node whose value diverged must
                    -- already have accepted a different transfer set, which
                    -- diverges balance/sequence and trips the existing accounts
                    -- hash. Including it would be a coordinated fork for at most
                    -- one block of earlier detection.
                    last_transfer_ts  INTEGER NOT NULL DEFAULT 0
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
                    host_contract_patch TEXT,
                    proposer_pubkey TEXT
                );
            ''')
            cur = conn.execute("PRAGMA table_info(accounts);")
            account_cols = {row[1] for row in cur.fetchall()}
            if account_cols and "last_transfer_ts" not in account_cols:
                # Additive: existing rows default to 0, which reads as "never
                # sent", so a cooldown rule admits the first send after upgrade.
                conn.execute(
                    "ALTER TABLE accounts ADD COLUMN last_transfer_ts INTEGER NOT NULL DEFAULT 0;"
                )
            cur = conn.execute("PRAGMA table_info(consensus_updates_v2);")
            consensus_update_cols = {row[1] for row in cur.fetchall()}
            if "proposer_pubkey" not in consensus_update_cols:
                conn.execute("ALTER TABLE consensus_updates_v2 ADD COLUMN proposer_pubkey TEXT;")
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
            # Rule sharing. Additive tables: SCHEMA_VERSION stays put, since a
            # bump makes init_db refuse to start and forces every live node to
            # delete its database.
            #
            # The consensus-bound part of an offer is (offer_id, offerer,
            # recipient, expire_at_height) plus membership of the resolved set.
            # `rule_text` and `status` are node-local durability for the RPC
            # surface: they are re-derivable by replay and are NOT folded into
            # consensus_meta_hash, mirroring how governance update payloads are
            # persisted.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rule_offers_v1 (
                    offer_id           TEXT PRIMARY KEY,
                    offerer_pubkey     TEXT NOT NULL,
                    recipient_pubkey   TEXT NOT NULL,
                    rule_text          TEXT NOT NULL,
                    expire_at_height   INTEGER NOT NULL,
                    status             TEXT NOT NULL DEFAULT 'offered'
                );
            ''')
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rule_offers_recipient_status "
                "ON rule_offers_v1(recipient_pubkey, status);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_rule_offers_offerer_status "
                "ON rule_offers_v1(offerer_pubkey, status);"
            )
            # The accepted-clause registry: this IS the per-user specification,
            # and its root is bound into the state hash. One clause per
            # (acceptor, target stream); accepting again replaces it.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS rule_clauses_v1 (
                    acceptor_pubkey TEXT NOT NULL,
                    target_stream   INTEGER NOT NULL,
                    clause_body     TEXT NOT NULL,
                    PRIMARY KEY (acceptor_pubkey, target_stream)
                );
            ''')
            # Co-signature approval requests: parked transfers awaiting votes.
            # The book root (including which approvers have voted) is bound into
            # consensus_meta_hash, so this must be written in the same
            # transaction as accounts -- see save_canonical_state_atomically.
            #
            # `voted_json` is hash-bound state, not colour: it decides whether
            # the parked transfer executes. `status` on a resolved row and the
            # decline reasons are node-local.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS approval_requests_v1 (
                    request_id         TEXT PRIMARY KEY,
                    sender_pubkey      TEXT NOT NULL,
                    recipient_pubkey   TEXT NOT NULL,
                    amount             INTEGER NOT NULL,
                    expire_at_height   INTEGER NOT NULL,
                    approvers_json     TEXT NOT NULL DEFAULT '{}',
                    custom_inputs_json TEXT NOT NULL DEFAULT '{}',
                    voted_json         TEXT NOT NULL DEFAULT '{}',
                    declined_json      TEXT NOT NULL DEFAULT '[]',
                    status             INTEGER NOT NULL DEFAULT 0
                );
            ''')
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_requests_sender_status "
                "ON approval_requests_v1(sender_pubkey, status);"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_approval_requests_expiry "
                "ON approval_requests_v1(expire_at_height);"
            )
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
            # tx_index maps a transaction hash to the block(s) that contain it,
            # so gettxstatus can answer "confirmed" without scanning block bodies.
            # Keyed on (tx_hash, block_hash): a tx may appear in more than one
            # fork block; canonicality is resolved at query time, so the index
            # needs no maintenance across reorgs.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS tx_index (
                    tx_hash      TEXT NOT NULL,
                    block_hash   TEXT NOT NULL,
                    block_number INTEGER NOT NULL,
                    PRIMARY KEY (tx_hash, block_hash)
                );
            ''')
            conn.execute('CREATE INDEX IF NOT EXISTS idx_tx_index_hash ON tx_index(tx_hash);')
            # mempool_dropped records txs that leave the mempool WITHOUT being
            # mined (expired, evicted under cap pressure, or rejected at apply),
            # so gettxstatus can distinguish "expired/evicted/rejected" from
            # "never seen". Self-pruning (24h TTL + row cap) on insert.
            conn.execute('''
                CREATE TABLE IF NOT EXISTS mempool_dropped (
                    tx_hash    TEXT PRIMARY KEY,
                    reason     TEXT NOT NULL,
                    dropped_at INTEGER NOT NULL
                );
            ''')

            # Backfill tx_index for databases created before it existed: if the
            # index is empty but blocks exist, populate it once from stored block
            # bodies. Idempotent (INSERT OR IGNORE); runs only on the first init
            # after upgrade.
            have_index = conn.execute("SELECT 1 FROM tx_index LIMIT 1;").fetchone()
            have_blocks = conn.execute("SELECT 1 FROM blocks LIMIT 1;").fetchone()
            if not have_index and have_blocks:
                for b_hash, b_num, b_data in conn.execute(
                    "SELECT block_hash, block_number, block_data FROM blocks;"
                ).fetchall():
                    try:
                        b = json.loads(b_data)
                    except (ValueError, TypeError):
                        continue
                    tx_hashes = b.get("tx_ids")
                    if not tx_hashes:
                        tx_hashes = [
                            block_module.compute_tx_hash(tx)
                            for tx in (b.get("transactions") or [])
                        ]
                    for th in tx_hashes:
                        conn.execute(
                            "INSERT OR IGNORE INTO tx_index (tx_hash, block_hash, block_number) VALUES (?, ?, ?);",
                            (th, b_hash, b_num),
                        )



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
                raise DatabaseError(
                    f"Database schema at {config.STRING_DB_PATH} predates schema_version {SCHEMA_VERSION}; "
                    "manual migration required (or delete the DB to resync)."
                )
            else:
                # Additive fee-model columns (existing rows default to 0 =
                # lowest priority; harmless on live nodes).
                for fee_col in ("fee_limit", "estimated_fee"):
                    if fee_col not in cols_info:
                        conn.execute(
                            f"ALTER TABLE mempool ADD COLUMN {fee_col} INTEGER NOT NULL DEFAULT 0;"
                        )

            # Lane separation. `lane` is a materialised cache of the pure
            # function consensus.lanes.classify_lane, used only for indexing
            # and quotas; `sender_pubkey` turns get_pending_sequence from a
            # full-table scan with a json.loads per row into an index lookup.
            cols_info = {row[1] for row in conn.execute("PRAGMA table_info(mempool);").fetchall()}
            lane_added = "lane" not in cols_info
            if lane_added:
                conn.execute(
                    "ALTER TABLE mempool ADD COLUMN lane INTEGER NOT NULL DEFAULT 0;"
                )
            sender_added = "sender_pubkey" not in cols_info
            if sender_added:
                conn.execute("ALTER TABLE mempool ADD COLUMN sender_pubkey TEXT;")
            if lane_added or sender_added:
                # One-shot backfill. DEFAULT 0 alone would misfile every
                # pre-existing rule transaction into the fast lane, letting it
                # keep competing with transfers for the same slots.
                _backfill_mempool_lanes(conn)

            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_mempool_pending_order
                ON mempool(status, estimated_fee DESC, received_at ASC);
            ''')
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_mempool_lane_order
                ON mempool(status, lane, estimated_fee DESC, received_at ASC);
            ''')
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_mempool_sender ON mempool(sender_pubkey);"
            )

            conn.execute('CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);')
            row = conn.execute('SELECT version FROM schema_version LIMIT 1').fetchone()
            if row is None:
                conn.execute('INSERT INTO schema_version (version) VALUES (?)', (SCHEMA_VERSION,))
            elif row[0] != SCHEMA_VERSION:
                raise DatabaseError(
                    f"DB schema_version {row[0]} != expected {SCHEMA_VERSION}; refusing to start."
                )

            _normalize_legacy_genesis_row(conn)

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

def get_shrink_id(key: str) -> int:
    """Interns a shrink key (`bv<width>:<hex>`) to its dense node-local id.

    Its own autoincrement, separate from get_string_id: ids here count distinct
    interned VALUES, so the shrink bv width follows the address count and not the
    block count (see the tau_shrink_ids comment in init_db). Returns the raw int,
    not the `y<id>` form -- a shrunk id is fed to the interpreter as a bare bv
    constant, never as a yid.
    """
    global _db_conn
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT id FROM tau_shrink_ids WHERE key = ?', (key,))
        row = cur.fetchone()
        if row:
            return int(row[0])
        cur.execute('INSERT INTO tau_shrink_ids(key) VALUES (?)', (key,))
        id_num = int(cur.lastrowid)
        _db_conn.commit()
        return id_num

def get_max_shrink_id() -> int:
    """Largest assigned shrink id (0 if none). Used to pick the smallest bv
    shrink width that covers the ids in use.

    Scoped to the shrink id space on purpose. This used to read `MAX(id)` from
    `tau_strings`, whose sequence the per-block consensus yids of
    TauConsensusEngine._encode_yid also draw from -- so the width grew with the
    chain instead of with the address count. tau_shrink_ids has no such sharing:
    its MAX is exactly the largest id the shrink layer has handed out.
    """
    global _db_conn
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT MAX(id) FROM tau_shrink_ids')
        row = cur.fetchone()
        return int(row[0]) if row and row[0] is not None else 0

def get_shrink_key_by_id(id_num: int) -> Optional[str]:
    """The `bv<width>:<hex>` key behind a dense shrink id, or None if unassigned.

    Diagnostics only (the leaked-shrunk-id output guard). The eval path is
    one-way: it interns values and never expands ids back.
    """
    global _db_conn
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT key FROM tau_shrink_ids WHERE id = ?', (int(id_num),))
        row = cur.fetchone()
        return row[0] if row else None

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

def _slow_lane_cap(total_cap: int) -> int:
    """How many pending slow-lane transactions the mempool will hold.

    A fraction of the total cap rather than an absolute count, so it tracks
    however the operator sized the mempool. At least 1, so the slow lane is
    never completely closed.
    """
    fraction = getattr(config, "MEMPOOL_RULE_LANE_MAX_FRACTION", 0.1)
    try:
        fraction = float(fraction)
    except (TypeError, ValueError):
        fraction = 0.1
    fraction = min(max(fraction, 0.0), 1.0)
    return max(1, int(total_cap * fraction))


def _sender_of_payload(payload: str) -> Optional[str]:
    """Sender public key from a mempool payload, or None if unreadable."""
    try:
        sender = json.loads(payload).get("sender_pubkey")
    except (ValueError, TypeError, AttributeError):
        return None
    return sender if isinstance(sender, str) else None


def _backfill_mempool_lanes(conn) -> None:
    """Populate `lane`/`sender_pubkey` for rows written before the columns
    existed. Exception-safe: this runs inside init_db, so a failure here must
    not stop the node from starting -- a mis-filed row costs a quota slot, not
    correctness.
    """
    try:
        rows = conn.execute("SELECT id, payload FROM mempool").fetchall()
    except sqlite3.Error:
        logger.warning("Could not read mempool for lane backfill", exc_info=True)
        return
    for row_id, payload in rows:
        try:
            conn.execute(
                "UPDATE mempool SET lane = ?, sender_pubkey = ? WHERE id = ?",
                (classify_lane_payload(payload), _sender_of_payload(payload), row_id),
            )
        except sqlite3.Error:
            logger.warning("Skipping lane backfill for mempool row %s", row_id, exc_info=True)
    if rows:
        logger.info("Backfilled transaction lanes for %d mempool rows", len(rows))


def _head_block_number_locked(cur) -> Optional[int]:
    """Canonical tip height on an OPEN cursor. None when there is no head yet.

    `_db_lock` is a plain Lock, so the prune cannot call get_canonical_head():
    it takes the same lock and would deadlock. Two reads on the caller's cursor
    instead.
    """
    cur.execute("SELECT value FROM chain_state WHERE key = ?", ("canonical_head_hash",))
    row = cur.fetchone()
    if not row or not row[0]:
        return None
    cur.execute("SELECT block_number FROM blocks WHERE block_hash = ? LIMIT 1", (row[0],))
    row = cur.fetchone()
    if not row or row[0] is None:
        return None
    try:
        return int(row[0])
    except (TypeError, ValueError):
        return None

def add_mempool_tx(tx_data: str, tx_hash: str, received_at: int,
                   fee_limit: int = 0, estimated_fee: int = 0,
                   lane: int | None = None):
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

    # Derived here as well as passed in, so any caller that predates lanes
    # still files its row correctly rather than defaulting into the fast lane.
    row_lane = classify_lane_payload(payload) if lane is None else int(lane)
    row_sender = _sender_of_payload(payload)

    with _db_lock:
        cur = _db_conn.cursor()

        # Prune expired pending txs (expiration_time is epoch seconds inside the JSON payload).
        # Record their hashes as 'expired' first so gettxstatus can report them.
        import time as _time
        now_s = int(_time.time())
        now_ms = int(_time.time() * 1000)
        try:
            # Collect victims' hashes first (for the dropped-tx audit), then
            # delete. Both use json_extract; a malformed-JSON row raises
            # OperationalError, handled by the Python fallback below.
            expired_hashes = [
                r[0] for r in cur.execute(
                    "SELECT tx_hash FROM mempool WHERE status='pending' "
                    "AND CAST(json_extract(payload, '$.expiration_time') AS INTEGER) < ?",
                    (now_s,),
                ).fetchall()
            ]
            cur.execute(
                "DELETE FROM mempool WHERE status='pending' "
                "AND CAST(json_extract(payload, '$.expiration_time') AS INTEGER) < ?",
                (now_s,),
            )
        except sqlite3.Error:
            # JSON1 unavailable OR a non-JSON payload: Python-side fallback.
            expired_ids = []
            expired_hashes = []
            for row in cur.execute("SELECT id, tx_hash, payload FROM mempool WHERE status='pending'").fetchall():
                try:
                    exp = json.loads(row[2]).get("expiration_time")
                    if isinstance(exp, int) and exp < now_s:
                        expired_ids.append(row[0])
                        expired_hashes.append(row[1])
                except (ValueError, TypeError):
                    continue
            if expired_ids:
                marks = ",".join("?" for _ in expired_ids)
                cur.execute(f"DELETE FROM mempool WHERE id IN ({marks})", tuple(expired_ids))
        _record_dropped_locked(cur, expired_hashes, "expired", now_ms)

        # The same prune by HEIGHT. A transaction is dead once the next block
        # would be at or past its expire_at_height: block apply refuses it from
        # there on, so holding it only wastes a mempool slot. Rows written
        # before heights existed have no such field and json_extract returns
        # NULL, which fails the comparison and leaves them to the clock prune.
        by_height_hashes = []
        try:
            next_height = int((_head_block_number_locked(cur) or 0)) + 1
        except Exception:
            next_height = None
        if next_height is not None:
            try:
                by_height_hashes = [
                    r[0] for r in cur.execute(
                        "SELECT tx_hash FROM mempool WHERE status='pending' "
                        "AND CAST(json_extract(payload, '$.expire_at_height') AS INTEGER) <= ?",
                        (next_height,),
                    ).fetchall()
                ]
                cur.execute(
                    "DELETE FROM mempool WHERE status='pending' "
                    "AND CAST(json_extract(payload, '$.expire_at_height') AS INTEGER) <= ?",
                    (next_height,),
                )
            except sqlite3.Error:
                by_height_ids = []
                by_height_hashes = []
                for row in cur.execute(
                    "SELECT id, tx_hash, payload FROM mempool WHERE status='pending'"
                ).fetchall():
                    try:
                        exp = json.loads(row[2]).get("expire_at_height")
                    except (ValueError, TypeError):
                        continue
                    if isinstance(exp, int) and not isinstance(exp, bool) and exp <= next_height:
                        by_height_ids.append(row[0])
                        by_height_hashes.append(row[1])
                if by_height_ids:
                    marks = ",".join("?" for _ in by_height_ids)
                    cur.execute(f"DELETE FROM mempool WHERE id IN ({marks})", tuple(by_height_ids))
            if by_height_hashes:
                _record_dropped_locked(cur, by_height_hashes, "expired", now_ms)

        # Cap the pending mempool; evict oldest pending only (never reserved — the miner holds them).
        # Count pending-only (matching count_mempool_txs / the soft sendtx pre-check) so the
        # configured limit means the same thing on both the soft and hard paths.
        cap = _configured_mempool_max()
        def _evict(overflow: int, lane: Optional[int]) -> None:
            """Drop `overflow` oldest pending rows, optionally within one lane."""
            if overflow <= 0:
                return
            lane_clause = "" if lane is None else " AND lane = ?"
            params = (lane, overflow) if lane is not None else (overflow,)
            evicted_hashes = [
                r[0] for r in cur.execute(
                    "SELECT tx_hash FROM mempool WHERE status='pending'"
                    + lane_clause + " ORDER BY received_at ASC LIMIT ?",
                    params,
                ).fetchall()
            ]
            if not evicted_hashes:
                return
            cur.execute(
                "DELETE FROM mempool WHERE id IN ("
                "SELECT id FROM mempool WHERE status='pending'" + lane_clause
                + " ORDER BY received_at ASC LIMIT ?)",
                params,
            )
            _record_dropped_locked(cur, evicted_hashes, "evicted", now_ms)

        # Quota-first eviction. The slow lane gets a bounded share of the
        # mempool, and overflow inside it is evicted from ITS OWN rows. Plain
        # global FIFO would let a burst of rule transactions evict queued,
        # fee-paying transfers -- the exact starvation the lanes exist to
        # prevent.
        slow_cap = _slow_lane_cap(cap)
        slow_pending = cur.execute(
            "SELECT COUNT(*) FROM mempool WHERE status='pending' AND lane = ?",
            (LANE_SLOW,),
        ).fetchone()[0]
        if row_lane == LANE_SLOW and slow_pending >= slow_cap:
            _evict(slow_pending - slow_cap + 1, LANE_SLOW)
        elif slow_pending > slow_cap:
            # Cap lowered under an existing backlog: trim it before considering
            # the global cap, so the slow lane cannot hold the fast lane out.
            _evict(slow_pending - slow_cap, LANE_SLOW)

        pending = cur.execute("SELECT COUNT(*) FROM mempool WHERE status='pending'").fetchone()[0]
        if pending >= cap:
            overflow = pending - cap + 1
            # Prefer trimming the slow lane if it is over quota; otherwise fall
            # back to global oldest-first, matching the historical behaviour.
            slow_pending = cur.execute(
                "SELECT COUNT(*) FROM mempool WHERE status='pending' AND lane = ?",
                (LANE_SLOW,),
            ).fetchone()[0]
            slow_excess = min(overflow, max(0, slow_pending - slow_cap))
            _evict(slow_excess, LANE_SLOW)
            _evict(overflow - slow_excess, None)

        # Idempotency: INSERT OR IGNORE
        cur.execute('''
            INSERT OR IGNORE INTO mempool (tx_hash, payload, received_at, status, fee_limit, estimated_fee, lane, sender_pubkey)
            VALUES (?, ?, ?, 'pending', ?, ?, ?, ?)
        ''', (tx_hash, payload, received_at, int(fee_limit), int(estimated_fee),
              int(row_lane), row_sender))
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
        # Narrowed by the indexed sender_pubkey column instead of scanning the
        # whole table and json.loads-ing every row. That scan ran once per
        # sendtx while holding the single global DB lock, and cost tens of
        # milliseconds at a full mempool -- more with large rule payloads.
        #
        # Rows written before the column existed have it NULL; they are picked
        # up by the fallback below so the answer stays correct on an upgraded
        # database whose backfill could not run.
        rows = cur.execute(
            'SELECT payload FROM mempool WHERE sender_pubkey = ?',
            (sender_pubkey,),
        ).fetchall()
        legacy = cur.execute(
            'SELECT payload FROM mempool WHERE sender_pubkey IS NULL'
        ).fetchall()

        # Deliberately covers every status: a tx already reserved for a block,
        # or awaiting validation, still owns its sequence number. A future
        # status that is NOT admission-validated must be excluded here, or it
        # would bump a sender's expected sequence number.
        for (payload,) in list(rows) + list(legacy):
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


def get_min_pending_sequence(sender_pubkey: str) -> Optional[int]:
    """Lowest sequence number this sender has waiting in the mempool.

    Used by the block builder to detect a sequence GAP: lane quotas can leave a
    sender's lower-numbered transaction behind while including a higher one,
    which the engine then hard-rejects for a sequence mismatch.
    """
    if _db_conn is None:
        init_db()

    min_seq = None
    with _db_lock:
        cur = _db_conn.cursor()
        rows = cur.execute(
            'SELECT payload FROM mempool WHERE sender_pubkey = ? OR sender_pubkey IS NULL',
            (sender_pubkey,),
        ).fetchall()
        for (payload,) in rows:
            try:
                data = json.loads(payload)
                if data.get('sender_pubkey') != sender_pubkey:
                    continue
                seq = data.get('sequence_number')
                if isinstance(seq, int) and (min_seq is None or seq < min_seq):
                    min_seq = seq
            except Exception:
                continue
    return min_seq

# --- Dropped-tx audit (issue #11: gettxstatus) ---
_DROPPED_TTL_MS = 24 * 60 * 60 * 1000  # keep drop records ~24h
_DROPPED_MAX_ROWS = 5000


def _record_dropped_locked(cur, tx_hashes, reason: str, now_ms: int) -> None:
    """Record dropped tx hashes with the given reason, then self-prune. Uses the
    provided cursor (caller already holds _db_lock)."""
    if not tx_hashes:
        return
    for th in tx_hashes:
        cur.execute(
            "INSERT OR REPLACE INTO mempool_dropped (tx_hash, reason, dropped_at) VALUES (?, ?, ?)",
            (th, reason, now_ms),
        )
    # TTL prune, then cap to the newest rows.
    cur.execute("DELETE FROM mempool_dropped WHERE dropped_at < ?", (now_ms - _DROPPED_TTL_MS,))
    cur.execute(
        "DELETE FROM mempool_dropped WHERE tx_hash IN ("
        "SELECT tx_hash FROM mempool_dropped ORDER BY dropped_at DESC, tx_hash "
        "LIMIT -1 OFFSET ?)",
        (_DROPPED_MAX_ROWS,),
    )


def record_dropped_txs(tx_hashes, reason: str) -> None:
    """Public: record txs that left the mempool without being mined (e.g.
    rejected at block apply). Acquires the db lock."""
    if not tx_hashes:
        return
    if _db_conn is None:
        init_db()
    import time as _time
    now_ms = int(_time.time() * 1000)
    with _db_lock:
        cur = _db_conn.cursor()
        _record_dropped_locked(cur, list(tx_hashes), reason, now_ms)
        _db_conn.commit()


def get_dropped_tx(tx_hash: str) -> Optional[Dict]:
    """Return {'reason', 'dropped_at'} for a dropped tx, or None."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            "SELECT reason, dropped_at FROM mempool_dropped WHERE tx_hash = ? LIMIT 1",
            (tx_hash,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {"reason": row[0], "dropped_at": row[1]}


def get_tx_block_locations(tx_hash: str) -> List[Dict]:
    """Return [{'block_hash', 'block_number'}] for every block containing tx_hash
    (may span fork blocks). Canonicality is resolved separately."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            "SELECT block_hash, block_number FROM tx_index WHERE tx_hash = ? "
            "ORDER BY block_number ASC",
            (tx_hash,),
        )
        return [{"block_hash": r[0], "block_number": r[1]} for r in cur.fetchall()]


def get_canonical_confirmation(block_hash: str, block_number: int) -> tuple[bool, int]:
    """Return (is_canonical, canonical_head_number). A block is canonical iff
    walking back from the canonical head by (head_number - block_number) steps
    lands on `block_hash`. Uses the blocks table's indexed columns (no JSON
    parse). Returns (False, -1) if there is no canonical head."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        head_hash_row = cur.execute(
            "SELECT value FROM chain_state WHERE key = 'canonical_head_hash'"
        ).fetchone()
        head_num_row = cur.execute(
            "SELECT value FROM chain_state WHERE key = 'canonical_head_number'"
        ).fetchone()
        if not head_hash_row or not head_hash_row[0]:
            return (False, -1)
        head_hash = head_hash_row[0]
        try:
            head_number = int(head_num_row[0]) if head_num_row else -1
        except (ValueError, TypeError):
            head_number = -1
        if head_number < block_number:
            return (False, head_number)
        # Walk back from the head to the target height.
        current = head_hash
        steps = head_number - block_number
        visited = set()
        for _ in range(steps):
            if not current or current in visited:
                return (False, head_number)
            visited.add(current)
            row = cur.execute(
                "SELECT previous_hash FROM blocks WHERE block_hash = ? LIMIT 1",
                (current,),
            ).fetchone()
            if not row:
                return (False, head_number)
            current = row[0]
        return (current == block_hash, head_number)


def get_mempool_entry(tx_hash: str) -> Optional[Dict]:
    """Single-row variant of get_mempool_entries, keyed by tx_hash."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            "SELECT tx_hash, payload, received_at, status, fee_limit, estimated_fee "
            "FROM mempool WHERE tx_hash = ? LIMIT 1",
            (tx_hash,),
        )
        row = cur.fetchone()
    if not row:
        return None
    return {
        "tx_hash": row[0],
        "payload": row[1],
        "received_at": row[2],
        "status": row[3],
        "fee_limit": row[4],
        "estimated_fee": row[5],
    }


def get_mempool_txs_for_address(address: str) -> List[Dict]:
    """Return pending/reserved mempool txs that touch `address` as sender or as a
    party in any operations["1"] transfer triple. Each entry carries per-tx
    amount_out (sum sent by address) and amount_in (sum received by address).
    Expired-but-unpruned rows are skipped (they can never apply)."""
    if _db_conn is None:
        init_db()
    import time as _time
    now_s = int(_time.time())
    out: List[Dict] = []
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            "SELECT tx_hash, payload, status, received_at, fee_limit, estimated_fee "
            "FROM mempool ORDER BY received_at ASC"
        )
        rows = cur.fetchall()
    for tx_hash, payload, status, received_at, fee_limit, estimated_fee in rows:
        try:
            data = json.loads(payload)
        except Exception:
            continue
        exp = data.get("expiration_time")
        if isinstance(exp, int) and exp < now_s:
            continue  # expired but not yet pruned; excluded from pending view
        sender = data.get("sender_pubkey")
        transfers = (data.get("operations") or {}).get("1") or []
        amount_out = 0
        amount_in = 0
        touches = (sender == address)
        if isinstance(transfers, list):
            for tr in transfers:
                if not (isinstance(tr, (list, tuple)) and len(tr) == 3):
                    continue
                frm, to, amt = tr
                try:
                    amt_i = int(amt)
                except (ValueError, TypeError):
                    continue
                if frm == address:
                    amount_out += amt_i
                    touches = True
                if to == address:
                    amount_in += amt_i
                    touches = True
        if not touches:
            continue
        out.append({
            "tx_hash": tx_hash,
            "status": status,
            "received_at": received_at,
            "fee_limit": fee_limit,
            "estimated_fee": estimated_fee,
            "sender_pubkey": sender,
            "sequence_number": data.get("sequence_number"),
            "tx_type": data.get("tx_type", "user_tx"),
            "expiration_time": exp,
            "amount_out": amount_out,
            "amount_in": amount_in,
        })
    return out


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


def get_mempool_entries() -> List[Dict]:
    """
    Returns rich mempool rows for inspection: tx_hash, payload, received_at, status.
    Ordered by received_at ASC (FIFO).
    """
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            'SELECT tx_hash, payload, received_at, status, fee_limit, estimated_fee '
            'FROM mempool ORDER BY received_at ASC'
        )
        return [
            {
                "tx_hash": row[0],
                "payload": row[1],
                "received_at": row[2],
                "status": row[3],
                "fee_limit": row[4],
                "estimated_fee": row[5],
            }
            for row in cur.fetchall()
        ]

def reserve_mempool_txs(limit: int = 1000, max_age_seconds: int = 60,
                        slow_limit: int | None = None) -> List[Dict]:
    """
    Selects pending transactions from the mempool AND releases stale
    reservations (older than max_age_seconds).

    Selection is LANE-AWARE. The fast lane (coin transfers) is filled first,
    then the slow lane (rule-bearing transactions) up to `slow_limit`. Without
    a quota a burst of rule work occupies the whole block and every queued
    transfer waits for it -- and fee priority cannot fix that, because a rule
    emits its own o8 user fee and can therefore price itself to the front of
    the queue. Ordering WITHIN each lane is unchanged, so the existing
    determinism and fee-priority properties still hold.

    `slow_limit=None` means no cap, preserving the pre-lane behaviour for
    callers that have no per-block budget of their own.

    Returns a list of dicts: {'id': int, 'tx_hash': str, 'payload': str},
    fast-lane rows first, at most `limit` in total.
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

        # 2. Select pending, fast lane first.
        # Fee priority: highest admission-time fee estimate first (declared
        # fee_limit alone is free to inflate, so it only tie-breaks), then
        # arrival order, then id for full determinism.
        _LANE_ORDER = (
            "ORDER BY estimated_fee DESC, fee_limit DESC, received_at ASC, id ASC"
        )

        def _select(lane: int, count: int):
            if count <= 0:
                return []
            return cur.execute(
                "SELECT id, tx_hash, payload FROM mempool "
                "WHERE status = 'pending' AND lane = ? " + _LANE_ORDER + " LIMIT ?",
                (lane, count),
            ).fetchall()

        fast_rows = _select(LANE_FAST, limit)
        slow_budget = limit - len(fast_rows)
        if slow_limit is not None:
            slow_budget = min(slow_budget, int(slow_limit))
        slow_rows = _select(LANE_SLOW, slow_budget)

        # Fast lane first so the block body puts transfers ahead of rule work.
        # Selection is proposer-local policy -- validators replay the stored
        # body order -- so this cannot fork; it is the same kind of choice as
        # fee ordering. commands/createblock then restores per-sender sequence
        # order within the slots each sender occupies.
        rows = list(fast_rows) + list(slow_rows)

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
        # Index every tx hash in this block (same transaction as the block row)
        # so gettxstatus can resolve "confirmed". tx_ids is authoritative;
        # fall back to computing from the transaction bodies if it is absent.
        # Defensive getattr: some callers/tests pass block-like objects without
        # these attributes.
        tx_hashes = getattr(new_block, "tx_ids", None) or [
            block_module.compute_tx_hash(tx)
            for tx in (getattr(new_block, "transactions", None) or [])
        ]
        for th in tx_hashes:
            cur.execute(
                'INSERT OR IGNORE INTO tx_index (tx_hash, block_hash, block_number) VALUES (?, ?, ?)',
                (th, new_block.block_hash, new_block.header.block_number),
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

def _parse_block_data_rows(rows) -> List[Dict]:
    """JSON-decode block_data blobs. Callers must not hold `_db_lock`."""
    out: List[Dict] = []
    for (block_json,) in rows:
        try:
            out.append(json.loads(block_json))
        except Exception:
            continue
    return out


def get_all_blocks() -> List[Dict]:
    """Returns all blocks ordered by block_number ascending as parsed dicts."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT block_data FROM blocks ORDER BY block_number ASC')
        rows = cur.fetchall()
    return _parse_block_data_rows(rows)


def get_block_count() -> int:
    """Number of rows in `blocks` (canonical and stale forks)."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute('SELECT COUNT(*) FROM blocks')
        row = cur.fetchone()
    return int(row[0] if row else 0)


def get_recent_blocks(limit: int) -> List[Dict]:
    """Highest-numbered `limit` blocks, returned in ascending block_number order.

    Uses SQL LIMIT so a `getblocks N` poller does not parse the whole chain
    under `_db_lock`. Forks are included, matching `get_all_blocks()`.
    """
    if limit < 1:
        return []
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            'SELECT block_data FROM blocks ORDER BY block_number DESC LIMIT ?',
            (int(limit),),
        )
        rows = cur.fetchall()
    blocks = _parse_block_data_rows(rows)
    blocks.reverse()
    return blocks

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

def load_last_transfer_ts() -> Dict[str, int]:
    """Per-account timestamp of the previous transfer (issue #21).

    Loaded separately rather than widening load_chain_state's 10-tuple, which
    every caller unpacks positionally. Absent rows read as 0 = "never sent", so
    a cooldown rule admits the first send after an upgrade.
    """
    if _db_conn is None:
        init_db()
    out: Dict[str, int] = {}
    with _db_lock:
        cur = _db_conn.execute(
            'SELECT address, last_transfer_ts FROM accounts WHERE last_transfer_ts > 0'
        )
        for address, ts in cur.fetchall():
            out[address] = int(ts or 0)
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
            cur = _db_conn.execute('SELECT update_id, rule_revisions, activate_at_height, host_contract_patch, proposer_pubkey FROM consensus_updates_v2')
            for row in cur.fetchall():
                pending_updates.append({
                    'update_id': row[0],
                    'rule_revisions': json.loads(row[1]),
                    'activate_at_height': row[2],
                    'host_contract_patch': json.loads(row[3]) if row[3] else None,
                    'proposer_pubkey': row[4],
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


def get_chain_state_value(key: str, default: str = "") -> str:
    if _db_conn is None:
        init_db()

    with _db_lock:
        cur = _db_conn.execute(
            "SELECT value FROM chain_state WHERE key = ? LIMIT 1",
            (key,),
        )
        row = cur.fetchone()
    if not row:
        return default
    return row[0] if row[0] is not None else default


def set_chain_state_value(key: str, value: str) -> None:
    if _db_conn is None:
        init_db()

    with _db_lock:
        with _db_conn:
            _db_conn.execute(
                "INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)",
                (key, value),
            )


def save_canonical_state_atomically(head_hash: str, head_num: int, balances: Dict[str, int], sequences: Dict[str, int], application_rules: str, consensus_rules: str, active_consensus_id: str, pending_updates: List[Dict], votes: List[Dict], scheduled: List[tuple[int, str]], archival: List[str], active_validators: List[str] | None = None, quorum_policy: str | None = None, eligibility_mode: str | None = None, fee_beneficiary: str | None = None, last_transfer_ts: Dict[str, int] | None = None, rule_offers: List[Dict] | None = None, rule_clauses: List[Dict] | None = None, max_rule_txs_per_block: int | None = None, approval_requests: List[Dict] | None = None, approval_slots_active: bool | None = None):
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
            if active_validators is not None:
                _db_conn.execute(
                    'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                    ('active_validators', json.dumps(sorted(active_validators)))
                )
            if quorum_policy is not None:
                # Persist the (possibly governance-activated) quorum policy so a
                # node reloading from disk reproduces the same approval threshold
                # as a freshly-rebuilt or freshly-synced peer. Stored verbatim,
                # including "" (genesis did not pin) — get_chain_state_value
                # returns its default only when the row is absent.
                _db_conn.execute(
                    'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                    ('quorum_policy', quorum_policy)
                )
            if eligibility_mode is not None:
                # Persist the (possibly governance-activated) eligibility mode so a
                # node reloading from disk reproduces the same proposer-eligibility
                # regime as a freshly-rebuilt or freshly-synced peer. Stored
                # verbatim, including "" (genesis did not pin).
                _db_conn.execute(
                    'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                    ('eligibility_mode', eligibility_mode)
                )
            if fee_beneficiary is not None:
                # Same reasoning as eligibility_mode: a node reloading from disk
                # must route the levy exactly as a freshly-synced peer does, or
                # the two compute different balances. Stored verbatim, including
                # "" (no beneficiary pinned -> credit the proposer).
                _db_conn.execute(
                    'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                    ('fee_beneficiary', fee_beneficiary)
                )

            _db_conn.execute('DELETE FROM accounts')
            # Persist a row for EVERY account that has a balance OR a sequence
            # number. Iterating balances.items() alone dropped "sequence-only"
            # accounts — validators who submitted a governance tx (proposal or
            # vote) but hold no funds, so they exist in `sequences` (seq
            # incremented) but never in `balances`. compute_consensus_state_hash's
            # accounts_hash keys on balances∪sequences, so losing those rows on
            # persist made a node reload a state with a SMALLER account set than
            # a from-genesis replay reconstructs. The node would then mine the
            # next block against that reduced state, producing a state hash that
            # every follower's replay rejected (Bug A / Phase 9B: the
            # mine-vs-replay divergence at the first post-restart block).
            # The key union must cover every per-account map, or an account
            # present in only one of them is dropped on restart (Bug A above).
            _lts = last_transfer_ts or {}
            for address in set(balances.keys()) | set(sequences.keys()) | set(_lts.keys()):
                _db_conn.execute(
                    'INSERT INTO accounts (address, balance, sequence_number, last_transfer_ts) '
                    'VALUES (?, ?, ?, ?)',
                    (address, int(balances.get(address, 0)), int(sequences.get(address, 0)),
                     int(_lts.get(address, 0)))
                )
                
            # Full Replace v2 arrays
            _db_conn.execute('DELETE FROM consensus_updates_v2')
            for p in pending_updates:
                _db_conn.execute(
                    'INSERT INTO consensus_updates_v2 (update_id, rule_revisions, activate_at_height, host_contract_patch, proposer_pubkey) VALUES (?, ?, ?, ?, ?)',
                    (
                        p['update_id'],
                        json.dumps(p['rule_revisions']),
                        p['activate_at_height'],
                        json.dumps(p['host_contract_patch']) if p['host_contract_patch'] else None,
                        p.get('proposer_pubkey'),
                    )
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

            # Rule sharing, same full-replace semantics and same transaction as
            # accounts. Both must be written here: the offer book and clause
            # registry are bound into consensus_meta_hash, so a node whose
            # in-memory managers disagree with disk computes a different state
            # hash after a restart than a peer replaying from genesis.
            if rule_offers is not None:
                _db_conn.execute('DELETE FROM rule_offers_v1')
                for offer in rule_offers:
                    _db_conn.execute(
                        'INSERT OR REPLACE INTO rule_offers_v1 '
                        '(offer_id, offerer_pubkey, recipient_pubkey, rule_text, '
                        'expire_at_height, status) VALUES (?, ?, ?, ?, ?, ?)',
                        (
                            offer['offer_id'],
                            offer.get('offerer_pubkey', ''),
                            offer.get('recipient_pubkey', ''),
                            offer.get('rule_text', ''),
                            int(offer.get('expire_at_height', 0)),
                            offer.get('status', 'offered'),
                        )
                    )

            if rule_clauses is not None:
                _db_conn.execute('DELETE FROM rule_clauses_v1')
                for clause in rule_clauses:
                    _db_conn.execute(
                        'INSERT OR REPLACE INTO rule_clauses_v1 '
                        '(acceptor_pubkey, target_stream, clause_body) VALUES (?, ?, ?)',
                        (
                            clause['acceptor_pubkey'],
                            int(clause['target_stream']),
                            clause['clause_body'],
                        )
                    )

            # Approval requests, same full-replace semantics and same
            # transaction as accounts, for the same reason: the request book root
            # is bound into consensus_meta_hash, so a node whose in-memory
            # manager disagrees with disk computes a different state hash after a
            # restart than a peer replaying from genesis.
            if approval_requests is not None:
                _db_conn.execute('DELETE FROM approval_requests_v1')
                for req in approval_requests:
                    _db_conn.execute(
                        'INSERT OR REPLACE INTO approval_requests_v1 '
                        '(request_id, sender_pubkey, recipient_pubkey, amount, '
                        'expire_at_height, approvers_json, custom_inputs_json, '
                        'voted_json, declined_json, status) '
                        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
                        (
                            req['request_id'],
                            req.get('sender_pubkey', ''),
                            req.get('recipient_pubkey', ''),
                            int(req.get('amount', 0)),
                            int(req.get('expire_at_height', 0)),
                            req.get('approvers_json', '{}'),
                            req.get('custom_inputs_json', '{}'),
                            req.get('voted_json', '{}'),
                            req.get('declined_json', '[]'),
                            int(req.get('status', 0)),
                        )
                    )

            if approval_slots_active is not None:
                # One-way activation flag. Persisted so a restart does not
                # silently un-reserve i18..i25 and let a sender write their own
                # approval slots.
                _db_conn.execute(
                    'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                    ('approval_slots_active', '1' if approval_slots_active else '0')
                )

            if max_rule_txs_per_block is not None:
                # Governance-activated value; persisted verbatim so a reload
                # reproduces the same per-block budget as a from-genesis replay.
                _db_conn.execute(
                    'INSERT OR REPLACE INTO chain_state (key, value) VALUES (?, ?)',
                    ('max_rule_txs_per_block', str(int(max_rule_txs_per_block)))
                )


def load_approval_requests() -> List[Dict]:
    """All approval-request rows, open and resolved. Ordered by id so a reload is
    deterministic."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.execute(
            'SELECT request_id, sender_pubkey, recipient_pubkey, amount, '
            'expire_at_height, approvers_json, custom_inputs_json, voted_json, '
            'declined_json, status FROM approval_requests_v1 ORDER BY request_id'
        )
        return [
            {
                "request_id": r[0],
                "sender_pubkey": r[1],
                "recipient_pubkey": r[2],
                "amount": int(r[3]),
                "expire_at_height": int(r[4]),
                "approvers_json": r[5],
                "custom_inputs_json": r[6],
                "voted_json": r[7],
                "declined_json": r[8],
                "status": int(r[9]),
            }
            for r in cur.fetchall()
        ]


def load_rule_offers() -> List[Dict]:
    """Rows of the persisted offer book, newest-status agnostic.

    Deliberately a standalone loader rather than another element of
    load_chain_state's already-wide tuple return.
    """
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            'SELECT offer_id, offerer_pubkey, recipient_pubkey, rule_text, '
            'expire_at_height, status FROM rule_offers_v1'
        )
        return [
            {
                'offer_id': row[0],
                'offerer_pubkey': row[1],
                'recipient_pubkey': row[2],
                'rule_text': row[3],
                'expire_at_height': int(row[4] or 0),
                'status': row[5],
            }
            for row in cur.fetchall()
        ]


def load_rule_clauses() -> List[Dict]:
    """Rows of the persisted accepted-clause registry."""
    if _db_conn is None:
        init_db()
    with _db_lock:
        cur = _db_conn.cursor()
        cur.execute(
            'SELECT acceptor_pubkey, target_stream, clause_body FROM rule_clauses_v1'
        )
        return [
            {
                'acceptor_pubkey': row[0],
                'target_stream': int(row[1]),
                'clause_body': row[2],
            }
            for row in cur.fetchall()
        ]

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
