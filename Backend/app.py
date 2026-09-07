from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import uuid
import time

from db import get_db, init_db
from crypto_engine import generate_keypair, pubkey_to_str, hash_file_bytes

app = Flask(__name__)
CORS(app)

init_db()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

PRIVATE_KEYS = {}


@app.route("/api/users/register", methods=["POST"])
def register_user():
    data = request.get_json() or {}
    name = data.get("name")

    if not name:
        return jsonify({"error": "name is required"}), 400

    user_id = str(uuid.uuid4())

    private_key, public_key = generate_keypair()
    PRIVATE_KEYS[user_id] = private_key

    conn = get_db()

    conn.execute(
        """
        INSERT INTO users (id, name, public_key, revoked_at)
        VALUES (?, ?, ?, NULL)
        """,
        (user_id, name, pubkey_to_str(public_key))
    )

    conn.commit()
    conn.close()

    return jsonify({
        "user_id": user_id,
        "name": name
    })


@app.route("/api/users", methods=["GET"])
def list_users():
    conn = get_db()

    rows = conn.execute(
        "SELECT id, name FROM users WHERE revoked_at IS NULL"
    ).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/files/upload", methods=["POST"])
def upload_file():
    actor_id = request.form.get("actor_id")
    uploaded = request.files.get("file")

    if not actor_id or not uploaded:
        return jsonify({
            "error": "actor_id and file are required"
        }), 400

    if actor_id not in PRIVATE_KEYS:
        return jsonify({
            "error": "unknown actor_id"
        }), 400

    file_bytes = uploaded.read()
    file_id = str(uuid.uuid4())

    filename = uploaded.filename or "uploaded_file"
    saved_path = os.path.join(
        UPLOAD_DIR,
        f"{file_id}_{filename}"
    )

    with open(saved_path, "wb") as file:
        file.write(file_bytes)

    content_hash = hash_file_bytes(file_bytes)

    conn = get_db()

    conn.execute(
        """
        INSERT INTO files (id, original_filename, created_at)
        VALUES (?, ?, ?)
        """,
        (file_id, filename, time.time())
    )

    conn.commit()
    conn.close()

    return jsonify({
        "file_id": file_id,
        "filename": filename,
        "content_hash": content_hash
    })


@app.route("/api/files", methods=["GET"])
def list_files():
    conn = get_db()

    rows = conn.execute(
        """
        SELECT id, original_filename, created_at
        FROM files
        ORDER BY created_at DESC
        """
    ).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


@app.route("/api/files/<file_id>/verify", methods=["POST"])
def verify_file(file_id):
    uploaded = request.files.get("file")

    if not uploaded:
        return jsonify({
            "error": "file is required"
        }), 400

    file_bytes = uploaded.read()
    current_hash = hash_file_bytes(file_bytes)

    conn = get_db()

    file_row = conn.execute(
        "SELECT * FROM files WHERE id=?",
        (file_id,)
    ).fetchone()

    conn.close()

    if file_row is None:
        return jsonify({
            "valid": False,
            "status": "UNKNOWN_PROVENANCE"
        })

    return jsonify({
        "file_id": file_id,
        "current_hash": current_hash,
        "status": "HASH_COMPUTED"
    })


@app.route("/api/files/<file_id>/history", methods=["GET"])
def file_history(file_id):
    conn = get_db()

    rows = conn.execute(
        """
        SELECT *
        FROM ledger_records
        WHERE file_id=?
        ORDER BY timestamp ASC
        """,
        (file_id,)
    ).fetchall()

    conn.close()

    return jsonify([dict(row) for row in rows])


if __name__ == "__main__":
    app.run(
        debug=True,
        port=5000
    )
