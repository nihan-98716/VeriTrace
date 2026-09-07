import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), "veritrace.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
    private_key TEXT,
    revoked_at REAL
);

CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    original_filename TEXT,
    created_at REAL
);

CREATE TABLE IF NOT EXISTS ledger_records (
    record_hash TEXT PRIMARY KEY,
    file_id TEXT NOT NULL,
    prev_record_hash TEXT,
    file_content_hash TEXT NOT NULL,
    action_type TEXT NOT NULL,        -- CREATE | MODIFY | TRANSFER
    actor_id TEXT NOT NULL,
    declared_transformation TEXT,     -- NULL if not declared
    timestamp REAL NOT NULL,
    metadata TEXT,
    signature TEXT NOT NULL,
    FOREIGN KEY(file_id) REFERENCES files(id),
    FOREIGN KEY(actor_id) REFERENCES users(id)
);
"""

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.executescript(SCHEMA)
    # Ensure private_key column exists for existing databases
    try:
        conn.execute("ALTER TABLE users ADD COLUMN private_key TEXT")
        conn.commit()
    except Exception:
        pass
    conn.close()
