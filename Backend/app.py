from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os, uuid, json, time, io

from db import get_db, init_db
from crypto_engine import (
    generate_keypair, pubkey_to_str, pubkey_from_str,
    hash_file_bytes, create_record, verify_chain
)
from ela import compute_ela

app = Flask(__name__)
CORS(app)
init_db()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

PRIVATE_KEYS = {}


@app.route("/api/users/register", methods=["POST"])
def register_user():
    name = request.json.get("name")
    if not name:
        return jsonify({"error": "name is required"}), 400
    user_id = str(uuid.uuid4())
    priv, pub = generate_keypair()
    PRIVATE_KEYS[user_id] = priv

    conn = get_db()
    conn.execute("INSERT INTO users (id, name, public_key, revoked_at) VALUES (?, ?, ?, NULL)",
                 (user_id, name, pubkey_to_str(pub)))
    conn.commit()
    conn.close()
    return jsonify({"user_id": user_id, "name": name})


@app.route("/api/users", methods=["GET"])
def list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, name FROM users WHERE revoked_at IS NULL").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files/upload", methods=["POST"])
def upload_file():
    actor_id = request.form.get("actor_id")
    uploaded = request.files.get("file")
    if not actor_id or not uploaded:
        return jsonify({"error": "actor_id and file are required"}), 400
    if actor_id not in PRIVATE_KEYS:
        return jsonify({"error": "unknown actor_id — register first"}), 400

    file_bytes = uploaded.read()
    file_id = str(uuid.uuid4())
    saved_path = os.path.join(UPLOAD_DIR, f"{file_id}_{uploaded.filename}")
    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    content_hash = hash_file_bytes(file_bytes)
    priv = PRIVATE_KEYS[actor_id]

    record = create_record(
        file_id=file_id, file_content_hash=content_hash,
        prev_record_hash=None, action_type="CREATE",
        actor_id=actor_id, private_key=priv,
        metadata={"filename": uploaded.filename}
    )

    conn = get_db()
    conn.execute("INSERT INTO files (id, original_filename, created_at) VALUES (?, ?, ?)",
                 (file_id, uploaded.filename, time.time()))
    _insert_record(conn, record)
    conn.commit()
    conn.close()

    return jsonify({"file_id": file_id, "record_hash": record["record_hash"]})


@app.route("/api/files", methods=["GET"])
def list_files():
    conn = get_db()
    rows = conn.execute("SELECT * FROM files ORDER BY created_at DESC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files/<file_id>/action", methods=["POST"])
def file_action(file_id):
    """Handles both MODIFY (re-upload same file_id) and TRANSFER (custody change,
    same content, new actor)."""
    actor_id = request.form.get("actor_id")
    action_type = request.form.get("action_type")
    declared_transformation = request.form.get("declared_transformation")
    uploaded = request.files.get("file")

    if not actor_id or not action_type:
        return jsonify({"error": "actor_id and action_type are required"}), 400
    if actor_id not in PRIVATE_KEYS:
        return jsonify({"error": "unknown actor_id — register first"}), 400
    if action_type not in ("MODIFY", "TRANSFER"):
        return jsonify({"error": "action_type must be MODIFY or TRANSFER"}), 400

    conn = get_db()
    prev = conn.execute(
        "SELECT * FROM ledger_records WHERE file_id=? ORDER BY timestamp DESC LIMIT 1",
        (file_id,)
    ).fetchone()

    if prev is None:
        conn.close()
        return jsonify({"error": "file not found"}), 404

    if uploaded:
        file_bytes = uploaded.read()
        content_hash = hash_file_bytes(file_bytes)
        # Save updated file
        saved_path = os.path.join(UPLOAD_DIR, f"{file_id}_latest_{uploaded.filename}")
        with open(saved_path, "wb") as f:
            f.write(file_bytes)
    else:
        content_hash = prev["file_content_hash"]  # TRANSFER: content unchanged

    priv = PRIVATE_KEYS[actor_id]
    record = create_record(
        file_id=file_id, file_content_hash=content_hash,
        prev_record_hash=prev["record_hash"], action_type=action_type,
        actor_id=actor_id, private_key=priv,
        declared_transformation=declared_transformation
    )
    _insert_record(conn, record)
    conn.commit()
    conn.close()
    return jsonify({"record_hash": record["record_hash"]})


@app.route("/api/files/<file_id>/verify", methods=["POST"])
def verify_file(file_id):
    """POST the CURRENT file bytes here — this is what makes the live tamper
    demo work: judge uploads a possibly-altered file, we hash it fresh and
    compare against what the chain says it should be."""
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "file is required"}), 400
    current_hash = hash_file_bytes(uploaded.read())

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM ledger_records WHERE file_id=? ORDER BY timestamp ASC",
        (file_id,)
    ).fetchall()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    public_keys = {u["id"]: pubkey_from_str(u["public_key"]) for u in users}
    # metadata is stored as a JSON string in SQLite — deserialize back to dict
    # so _canonical_bytes produces the same bytes that were signed at creation time
    records = []
    for r in rows:
        rec = dict(r)
        if isinstance(rec.get("metadata"), str):
            try:
                rec["metadata"] = json.loads(rec["metadata"])
            except (json.JSONDecodeError, TypeError):
                rec["metadata"] = {}
        records.append(rec)
    result = verify_chain(records, public_keys, current_hash)
    return jsonify(result)


@app.route("/api/files/<file_id>/history", methods=["GET"])
def file_history(file_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT lr.*, u.name as actor_name FROM ledger_records lr "
        "LEFT JOIN users u ON lr.actor_id = u.id "
        "WHERE lr.file_id=? ORDER BY lr.timestamp ASC",
        (file_id,)
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files/<file_id>/ela", methods=["POST"])
def ela_analysis(file_id):
    """POST a file to get the ELA heatmap as a PNG image.
    This is a supporting/heuristic signal only — never the verdict."""
    uploaded = request.files.get("file")
    if not uploaded:
        return jsonify({"error": "file is required"}), 400
    try:
        image_bytes = uploaded.read()
        ela_bytes = compute_ela(image_bytes)
        return send_file(
            io.BytesIO(ela_bytes),
            mimetype="image/png",
            as_attachment=False
        )
    except Exception as e:
        return jsonify({"error": f"ELA failed: {str(e)}"}), 422


def _insert_record(conn, record):
    conn.execute("""
        INSERT INTO ledger_records
        (record_hash, file_id, prev_record_hash, file_content_hash, action_type,
         actor_id, declared_transformation, timestamp, metadata, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        record["record_hash"], record["file_id"], record["prev_record_hash"],
        record["file_content_hash"], record["action_type"], record["actor_id"],
        record.get("declared_transformation"), record["timestamp"],
        json.dumps(record["metadata"]), record["signature"]
    ))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
