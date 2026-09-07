# VERITRACE — Database Schema

## SQLite Database (`backend/db.py`)

VERITRACE uses SQLite as its database. The database stores users, registered files, and the cryptographically linked ledger records.

```python
import sqlite3
import os

DB_PATH = os.path.join(
    os.path.dirname(__file__),
    "veritrace.db"
)

SCHEMA = """

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    public_key TEXT NOT NULL,
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
    conn.commit()
    conn.close()
```

---

## 1. `users` Table

Stores the users/custodians who perform actions on files.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT | Unique user ID and primary key |
| `name` | TEXT | Name of the user/custodian |
| `public_key` | TEXT | Ed25519 public key used to verify signatures |
| `revoked_at` | REAL | Timestamp indicating when a key was revoked; `NULL` if not revoked |

Example:

```text
users
┌──────────┬──────────┬─────────────┬────────────┐
│ id       │ name     │ public_key  │ revoked_at │
├──────────┼──────────┼─────────────┼────────────┤
│ U001     │ Reporter │ ABC123...   │ NULL       │
│ U002     │ Editor   │ XYZ789...   │ NULL       │
└──────────┴──────────┴─────────────┴────────────┘
```

---

## 2. `files` Table

Stores information about every file registered in VERITRACE.

| Column | Type | Description |
|---|---|---|
| `id` | TEXT | Unique file ID and primary key |
| `original_filename` | TEXT | Original name of the uploaded file |
| `created_at` | REAL | Timestamp when the file was registered |

Example:

```text
files
┌────────┬──────────────────┬────────────┐
│ id     │ original_filename│ created_at │
├────────┼──────────────────┼────────────┤
│ F001   │ evidence.jpg     │ 172...     │
└────────┴──────────────────┴────────────┘
```

---

## 3. `ledger_records` Table

This is the most important table in the database.

It stores the complete cryptographic custody history of each file.

Every action creates a new ledger record.

```text
CREATE
   ↓
TRANSFER
   ↓
MODIFY
   ↓
TRANSFER
   ↓
...
```

Each record is linked to the previous record using `prev_record_hash`.

| Column | Type | Description |
|---|---|---|
| `record_hash` | TEXT | Unique hash of the ledger record; primary key |
| `file_id` | TEXT | ID of the file associated with the record |
| `prev_record_hash` | TEXT | Hash of the previous ledger record |
| `file_content_hash` | TEXT | SHA-256 hash of the file content |
| `action_type` | TEXT | `CREATE`, `MODIFY`, or `TRANSFER` |
| `actor_id` | TEXT | User who performed the action |
| `declared_transformation` | TEXT | Optional declared transformation such as compression |
| `timestamp` | REAL | Time when the record was created |
| `metadata` | TEXT | Additional metadata stored with the record |
| `signature` | TEXT | Ed25519 digital signature of the record |

---

## 4. Relationship Between Tables

The tables are connected using foreign keys.

```text
┌────────────────────┐
│       users        │
├────────────────────┤
│ id (PK)            │
│ name               │
│ public_key         │
│ revoked_at         │
└─────────┬──────────┘
          │
          │ actor_id
          │
          ▼
┌────────────────────┐
│  ledger_records    │
├────────────────────┤
│ record_hash (PK)   │
│ file_id (FK)       │
│ prev_record_hash   │
│ file_content_hash  │
│ action_type        │
│ actor_id (FK)      │
│ declared_transform │
│ timestamp          │
│ metadata           │
│ signature          │
└─────────┬──────────┘
          │
          │ file_id
          │
          ▼
┌────────────────────┐
│       files        │
├────────────────────┤
│ id (PK)            │
│ original_filename  │
│ created_at         │
└────────────────────┘
```

---

## 5. How the Ledger Chain Is Stored

Suppose a file goes through three actions:

```text
Reporter uploads file
        ↓
CREATE
        ↓
Editor receives file
        ↓
TRANSFER
        ↓
Editor modifies file
        ↓
MODIFY
```

The database stores:

```text
Record 1
action = CREATE
prev_record_hash = NULL
file_content_hash = HASH_A
record_hash = RECORD_HASH_1

        ↓

Record 2
action = TRANSFER
prev_record_hash = RECORD_HASH_1
file_content_hash = HASH_A
record_hash = RECORD_HASH_2

        ↓

Record 3
action = MODIFY
prev_record_hash = RECORD_HASH_2
file_content_hash = HASH_B
record_hash = RECORD_HASH_3
```

The important relationship is:

```text
Record 1
   │
   └── record_hash
            ↓
       Record 2.prev_record_hash
            │
            └── record_hash
                     ↓
                Record 3.prev_record_hash
```

This creates the hash-linked custody history.

---

## 6. Database Initialization

The application calls:

```python
init_db()
```

when the Flask backend starts.

This executes the schema and creates the tables if they do not already exist.

The SQLite database file is:

```text
backend/veritrace.db
```

The database requires no separate database server, making it suitable for the hackathon MVP.
