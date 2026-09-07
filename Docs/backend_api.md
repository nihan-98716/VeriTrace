# VERITRACE — Backend API

## Backend API (`backend/app.py`)

```python
from flask import Flask, request, jsonify
from flask_cors import CORS
import os, uuid, json, time

from db import get_db, init_db
from crypto_engine import (
    generate_keypair, pubkey_to_str, pubkey_from_str,
    hash_file_bytes, create_record, verify_chain
)

app = Flask(__name__)
CORS(app)

init_db()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Demo-only: keep private keys in memory, keyed by user_id.
# Never do this in a real product — this is fine for a 24h hackathon demo.
PRIVATE_KEYS = {}


@app.route("/api/users/register", methods=["POST"])
def register_user():
    name = request.json.get("name")
    user_id = str(uuid.uuid4())

    priv, pub = generate_keypair()
    PRIVATE_KEYS[user_id] = priv

    conn = get_db()
    conn.execute(
        "INSERT INTO users (id, name, public_key, revoked_at) VALUES (?, ?, ?, NULL)",
        (user_id, name, pubkey_to_str(pub))
    )
    conn.commit()
    conn.close()

    return jsonify({"user_id": user_id, "name": name})


@app.route("/api/files/upload", methods=["POST"])
def upload_file():
    actor_id = request.form["actor_id"]
    uploaded = request.files["file"]
    file_bytes = uploaded.read()

    file_id = str(uuid.uuid4())

    saved_path = os.path.join(
        UPLOAD_DIR,
        f"{file_id}_{uploaded.filename}"
    )

    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    content_hash = hash_file_bytes(file_bytes)
    priv = PRIVATE_KEYS[actor_id]

    record = create_record(
        file_id=file_id,
        file_content_hash=content_hash,
        prev_record_hash=None,
        action_type="CREATE",
        actor_id=actor_id,
        private_key=priv,
        metadata={"filename": uploaded.filename}
    )

    conn = get_db()
    conn.execute(
        "INSERT INTO files (id, original_filename, created_at) VALUES (?, ?, ?)",
        (file_id, uploaded.filename, time.time())
    )

    _insert_record(conn, record)
    conn.commit()
    conn.close()

    return jsonify({
        "file_id": file_id,
        "record_hash": record["record_hash"]
    })


@app.route("/api/files/<file_id>/action", methods=["POST"])
def file_action(file_id):
    """
    Handles both MODIFY (re-upload same file_id) and
    TRANSFER (custody change, same content, new actor).
    """

    actor_id = request.form["actor_id"]
    action_type = request.form["action_type"]  # MODIFY | TRANSFER
    declared_transformation = request.form.get("declared_transformation")
    uploaded = request.files.get("file")

    conn = get_db()

    prev = conn.execute(
        """
        SELECT * FROM ledger_records
        WHERE file_id=?
        ORDER BY timestamp DESC
        LIMIT 1
        """,
        (file_id,)
    ).fetchone()

    if uploaded:
        file_bytes = uploaded.read()
        content_hash = hash_file_bytes(file_bytes)
    else:
        # TRANSFER: content unchanged
        content_hash = prev["file_content_hash"]

    priv = PRIVATE_KEYS[actor_id]

    record = create_record(
        file_id=file_id,
        file_content_hash=content_hash,
        prev_record_hash=prev["record_hash"],
        action_type=action_type,
        actor_id=actor_id,
        private_key=priv,
        declared_transformation=declared_transformation
    )

    _insert_record(conn, record)
    conn.commit()
    conn.close()

    return jsonify({"record_hash": record["record_hash"]})


@app.route("/api/files/<file_id>/verify", methods=["POST"])
def verify_file(file_id):
    """
    POST the CURRENT file bytes here — the file is hashed fresh
    and compared against the latest record's declared hash.
    """

    uploaded = request.files["file"]
    current_hash = hash_file_bytes(uploaded.read())

    conn = get_db()

    rows = conn.execute(
        """
        SELECT * FROM ledger_records
        WHERE file_id=?
        ORDER BY timestamp ASC
        """,
        (file_id,)
    ).fetchall()

    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    public_keys = {
        u["id"]: pubkey_from_str(u["public_key"])
        for u in users
    }

    records = [dict(r) for r in rows]

    result = verify_chain(
        records,
        public_keys,
        current_hash
    )

    return jsonify(result)


@app.route("/api/files/<file_id>/history", methods=["GET"])
def file_history(file_id):
    conn = get_db()

    rows = conn.execute(
        """
        SELECT * FROM ledger_records
        WHERE file_id=?
        ORDER BY timestamp ASC
        """,
        (file_id,)
    ).fetchall()

    conn.close()

    return jsonify([dict(r) for r in rows])


def _insert_record(conn, record):
    conn.execute(
        """
        INSERT INTO ledger_records
        (
            record_hash, file_id, prev_record_hash,
            file_content_hash, action_type, actor_id,
            declared_transformation, timestamp, metadata, signature
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            record["record_hash"],
            record["file_id"],
            record["prev_record_hash"],
            record["file_content_hash"],
            record["action_type"],
            record["actor_id"],
            record.get("declared_transformation"),
            record["timestamp"],
            json.dumps(record["metadata"]),
            record["signature"]
        )
    )


if __name__ == "__main__":
    app.run(debug=True, port=5000)
```

## API Summary

| Method | Route | Purpose |
|---|---|---|
| `POST` | `/api/users/register` | Create a user + keypair |
| `POST` | `/api/files/upload` | Register a new file and create record #1 (`CREATE`) |
| `POST` | `/api/files/<id>/action` | Create a `MODIFY` or `TRANSFER` record |
| `POST` | `/api/files/<id>/verify` | Upload current file and get `VERIFIED`, `TAMPERED`, or `UNKNOWN_PROVENANCE` |
| `GET` | `/api/files/<id>/history` | Get the full custody timeline |
