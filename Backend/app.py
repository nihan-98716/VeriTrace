from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
import os, uuid, json, time, io
import sys
from typing import Optional

SECURITY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "security"))
if SECURITY_DIR not in sys.path:
    sys.path.insert(0, SECURITY_DIR)

from db import get_db, init_db
from crypto_engine import (
    generate_keypair, pubkey_to_str, pubkey_from_str,
    privkey_to_str, privkey_from_str,
    hash_file_bytes, create_record, verify_chain
)
from ela import compute_ela

app = Flask(__name__)
CORS(app)
init_db()

UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Demo keys cached in memory and persisted in SQLite db so restarts/reloads never lose credentials
PRIVATE_KEYS = {}


def _get_private_key(actor_id: str):
    """Retrieve private key from memory cache, SQLite db, or recover for demo custodian."""
    if not actor_id:
        return None
    if actor_id in PRIVATE_KEYS:
        return PRIVATE_KEYS[actor_id]

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (actor_id,)).fetchone()
    if not user:
        conn.close()
        return None

    # Load from SQLite if saved
    if "private_key" in user.keys() and user["private_key"]:
        try:
            priv = privkey_from_str(user["private_key"])
            PRIVATE_KEYS[actor_id] = priv
            conn.close()
            return priv
        except Exception:
            pass

    # If the user existed in SQLite before private keys were persisted,
    # generate a valid keypair and update the database so they can sign immediately!
    priv, pub = generate_keypair()
    PRIVATE_KEYS[actor_id] = priv
    try:
        conn.execute(
            "UPDATE users SET private_key=?, public_key=? WHERE id=?",
            (privkey_to_str(priv), pubkey_to_str(pub), actor_id)
        )
        conn.commit()
    except Exception:
        pass
    conn.close()
    return priv


@app.route("/api/users/register", methods=["POST"])
def register_user():
    name = request.json.get("name")
    if not name:
        return jsonify({"error": "name is required"}), 400
    user_id = str(uuid.uuid4())
    priv, pub = generate_keypair()
    PRIVATE_KEYS[user_id] = priv

    conn = get_db()
    conn.execute("INSERT INTO users (id, name, public_key, private_key, revoked_at) VALUES (?, ?, ?, ?, NULL)",
                 (user_id, name, pubkey_to_str(pub), privkey_to_str(priv)))
    conn.commit()
    conn.close()
    return jsonify({"user_id": user_id, "name": name, "public_key": pubkey_to_str(pub)})



@app.route("/api/users", methods=["GET"])
def list_users():
    conn = get_db()
    rows = conn.execute("SELECT id, name, public_key FROM users WHERE revoked_at IS NULL").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/files/upload", methods=["POST"])
def upload_file():
    actor_id = request.form.get("actor_id")
    uploaded = request.files.get("file")
    if not actor_id or not uploaded:
        return jsonify({"error": "actor_id and file are required"}), 400
    priv = _get_private_key(actor_id)
    if priv is None:
        return jsonify({"error": "unknown actor_id — register first"}), 400

    file_bytes = uploaded.read()
    file_id = str(uuid.uuid4())
    saved_path = os.path.join(UPLOAD_DIR, f"{file_id}_{uploaded.filename}")
    with open(saved_path, "wb") as f:
        f.write(file_bytes)

    content_hash = hash_file_bytes(file_bytes)

    record = create_record(
        file_id=file_id, file_content_hash=content_hash,
        prev_record_hash=None, action_type="CREATE",
        actor_id=actor_id, private_key=priv,
        metadata={"filename": uploaded.filename},
        file_bytes=file_bytes, filename=uploaded.filename,
        request_tsa=True
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
    files_list = []
    for r in rows:
        fdict = dict(r)
        # Check if modified/tampered or latest file exists on disk
        _, latest_name = _resolve_file_bytes(fdict["id"], None)
        if latest_name:
            fdict["latest_resolved_filename"] = latest_name
        files_list.append(fdict)
    conn.close()
    return jsonify(files_list)


def is_image_file(filename: str = None, file_bytes: bytes = None) -> bool:
    """Accurately determines whether a file is an image based on extension and magic bytes.
    Rejects text files, documents, and non-image formats."""
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in (".txt", ".md", ".json", ".csv", ".xml", ".pdf", ".docx", ".html", ".js", ".py", ".c", ".cpp"):
            return False
        if ext in (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff", ".tif", ".ico"):
            return True
    if file_bytes:
        if (file_bytes.startswith(b"\x89PNG\r\n\x1a\n") or
            file_bytes.startswith(b"\xff\xd8\xff") or
            (file_bytes.startswith(b"RIFF") and b"WEBP" in file_bytes[:16]) or
            file_bytes.startswith(b"BM") or
            file_bytes.startswith(b"GIF8")):
            return True
    return False


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
    priv = _get_private_key(actor_id)
    if priv is None:
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

    action_meta = {}
    if action_type == "TRANSFER":
        # TRANSFER: custody changes hands, but file content MUST remain identical
        if uploaded:
            uploaded_bytes = uploaded.read()
            uploaded_hash = hash_file_bytes(uploaded_bytes)
            if uploaded_hash != prev["file_content_hash"]:
                conn.close()
                return jsonify({
                    "error": "Cannot alter file content during a TRANSFER action. "
                             "A TRANSFER only reassigns custodianship while preserving identical file content. "
                             "To record modified or edited file content, select MODIFY."
                }), 400
        content_hash = prev["file_content_hash"]
    elif action_type == "MODIFY":
        if not uploaded:
            conn.close()
            return jsonify({"error": "MODIFY requires uploading the new file version."}), 400
        file_bytes = uploaded.read()
        content_hash = hash_file_bytes(file_bytes)
        # Clean older _latest_ or _redacted_ files for this file_id
        for fname in os.listdir(UPLOAD_DIR):
            if fname.startswith(f"{file_id}_latest_") or fname.startswith(f"{file_id}_redacted_"):
                try:
                    os.remove(os.path.join(UPLOAD_DIR, fname))
                except Exception:
                    pass
        saved_path = os.path.join(UPLOAD_DIR, f"{file_id}_latest_{uploaded.filename}")
        with open(saved_path, "wb") as f:
            f.write(file_bytes)
        action_meta = {"filename": uploaded.filename}

    record = create_record(
        file_id=file_id, file_content_hash=content_hash,
        prev_record_hash=prev["record_hash"], action_type=action_type,
        actor_id=actor_id, private_key=priv,
        declared_transformation=declared_transformation,
        metadata=action_meta,
        request_tsa=True
    )
    _insert_record(conn, record)
    conn.commit()
    conn.close()
    return jsonify({"record_hash": record["record_hash"]})


def _resolve_original_file(file_id: str) -> tuple:
    """Helper to return (file_bytes, filename) of the original genesis file from disk."""
    try:
        for fname in os.listdir(UPLOAD_DIR):
            if fname.startswith(f"{file_id}_") and not (
                fname.startswith(f"{file_id}_latest_") or
                fname.startswith(f"{file_id}_tampered_") or
                fname.startswith(f"{file_id}_redacted_")
            ):
                with open(os.path.join(UPLOAD_DIR, fname), "rb") as f_orig:
                    return f_orig.read(), fname[len(f"{file_id}_"):]
    except Exception:
        pass
    return None, None


def _resolve_original_bytes(file_id: str) -> Optional[bytes]:
    """Helper to return original genesis file bytes from disk for differential analysis."""
    return _resolve_original_file(file_id)[0]


def _resolve_file_bytes(file_id: str, uploaded) -> tuple:
    """Helper to return (file_bytes, filename) from uploaded file or latest/tampered file on disk."""
    if uploaded:
        file_bytes = uploaded.read()
        filename = uploaded.filename
        return file_bytes, filename

    # Look for latest modified, tampered, or redacted file versions first (takes priority for evaluation)
    candidates = []
    for fname in os.listdir(UPLOAD_DIR):
        if (fname.startswith(f"{file_id}_latest_") or
            fname.startswith(f"{file_id}_tampered_") or
            fname.startswith(f"{file_id}_redacted_")):
            cand = os.path.join(UPLOAD_DIR, fname)
            if os.path.isfile(cand):
                candidates.append((os.path.getmtime(cand), cand))

    target_path = None
    if candidates:
        candidates.sort(key=lambda x: x[0], reverse=True)
        target_path = candidates[0][1]

    # If no modified/tampered/redacted file exists, fall back to genesis file
    if not target_path:
        for fname in os.listdir(UPLOAD_DIR):
            if fname.startswith(f"{file_id}_"):
                cand = os.path.join(UPLOAD_DIR, fname)
                if os.path.isfile(cand):
                    target_path = cand
                    break

    if not target_path or not os.path.exists(target_path):
        return None, None

    with open(target_path, "rb") as f:
        file_bytes = f.read()

    # Extract original filename
    base_name = os.path.basename(target_path)
    if base_name.startswith(f"{file_id}_latest_"):
        filename = base_name[len(f"{file_id}_latest_"):]
    elif base_name.startswith(f"{file_id}_tampered_"):
        filename = base_name[len(f"{file_id}_tampered_"):]
    elif base_name.startswith(f"{file_id}_redacted_"):
        filename = base_name[len(f"{file_id}_redacted_"):]
    elif base_name.startswith(f"{file_id}_"):
        filename = base_name[len(f"{file_id}_"):]
    else:
        filename = base_name

    return file_bytes, filename


@app.route("/api/files/<file_id>/verify", methods=["POST"])
def verify_file(file_id):
    """POST a file to test tamper, OR omit file to automatically verify the original photo in chain verification."""
    # For chain verification, always use the original file as target
    file_bytes, filename = _resolve_original_file(file_id)
    if not file_bytes:
        uploaded = request.files.get("file")
        file_bytes, filename = _resolve_file_bytes(file_id, uploaded)

    if file_bytes is None:
        return jsonify({"error": "No file uploaded and no registered file found for this ID"}), 400

    current_hash = hash_file_bytes(file_bytes)

    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM ledger_records WHERE file_id=? ORDER BY timestamp ASC",
        (file_id,)
    ).fetchall()
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()

    public_keys = {u["id"]: pubkey_from_str(u["public_key"]) for u in users}
    revoked_at_map = {u["id"]: u["revoked_at"] for u in users}   # None if not revoked
    actor_names = {u["id"]: u["name"] for u in users}

    # metadata is stored as a JSON string in SQLite — deserialize back to dict
    records = []
    for r in rows:
        rec = dict(r)
        if isinstance(rec.get("metadata"), str):
            try:
                rec["metadata"] = json.loads(rec["metadata"])
            except (json.JSONDecodeError, TypeError):
                rec["metadata"] = {}
        records.append(rec)

    # Resolve original genesis file bytes for differential analysis
    orig_bytes = _resolve_original_bytes(file_id)

    result = verify_chain(records, public_keys, current_hash, revoked_at_map,
                          current_file_bytes=file_bytes, filename=filename,
                          original_file_bytes=orig_bytes)

    result["verified_filename"] = filename
    result["current_hash"] = current_hash
    result["is_image"] = is_image_file(filename, file_bytes)

    # Strictly suppress NLP assessment and document segments for image files
    if result["is_image"]:
        result["semantic_assessment"] = None
        result["tampered_segments"] = []

    # Annotate with human-readable actor name so the frontend can display it
    if not result.get("valid") and "actor_id" in result:
        result["actor_name"] = actor_names.get(result["actor_id"], result["actor_id"])

    # On success, include the ordered list of unique actors for display
    if result.get("valid"):
        seen, unique_actors = set(), []
        for rec in records:
            if rec["actor_id"] not in seen:
                seen.add(rec["actor_id"])
                unique_actors.append({
                    "id": rec["actor_id"],
                    "name": actor_names.get(rec["actor_id"], rec["actor_id"])
                })
        result["unique_actors"] = unique_actors

    return jsonify(result)


@app.route("/api/files/<file_id>/history", methods=["GET"])
def file_history(file_id):
    conn = get_db()
    rows = conn.execute(
        "SELECT lr.*, u.name as actor_name, u.public_key as actor_public_key FROM ledger_records lr "
        "LEFT JOIN users u ON lr.actor_id = u.id "
        "WHERE lr.file_id=? ORDER BY lr.timestamp ASC",
        (file_id,)
    ).fetchall()
    conn.close()

    parsed_rows = []
    for r in rows:
        rec = dict(r)
        if isinstance(rec.get("metadata"), str):
            try:
                rec["metadata"] = json.loads(rec["metadata"])
            except (json.JSONDecodeError, TypeError):
                rec["metadata"] = {}
        
        # Populate TSA certification and certificate info for UI rendering
        rfc_info = rec.get("rfc3161") or (isinstance(rec.get("metadata"), dict) and rec["metadata"].get("rfc3161"))
        if rfc_info:
            rec["tsa_certified_utc"] = rfc_info.get("certified_utc")
            rec["tsa_certified_ist"] = rfc_info.get("certified_ist")
            rec["tsa_cert_info"] = rfc_info.get("cert_info")
            rec["tsa_url"] = rfc_info.get("tsa_url")
            rec["tsa_serial"] = rfc_info.get("token_serial")
            rec["tsa_policy"] = rfc_info.get("tsa_policy")

        parsed_rows.append(rec)

    return jsonify(parsed_rows)


@app.route("/api/files/<file_id>", methods=["GET"])
def get_file_detail(file_id):
    """Return metadata for a single registered file including hop count."""
    conn = get_db()
    f = conn.execute("SELECT * FROM files WHERE id=?", (file_id,)).fetchone()
    if not f:
        conn.close()
        return jsonify({"error": "file not found"}), 404
    hop_count = conn.execute(
        "SELECT COUNT(*) as cnt FROM ledger_records WHERE file_id=?", (file_id,)
    ).fetchone()["cnt"]
    conn.close()
    result = dict(f)
    result["hop_count"] = hop_count
    return jsonify(result)


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Return system-wide statistics for the dashboard hero widget."""
    conn = get_db()
    total_files = conn.execute("SELECT COUNT(*) as cnt FROM files").fetchone()["cnt"]
    total_records = conn.execute(
        "SELECT COUNT(*) as cnt FROM ledger_records"
    ).fetchone()["cnt"]
    total_custodians = conn.execute(
        "SELECT COUNT(*) as cnt FROM users WHERE revoked_at IS NULL"
    ).fetchone()["cnt"]
    conn.close()
    return jsonify({
        "total_files": total_files,
        "total_records": total_records,
        "total_custodians": total_custodians
    })


@app.route("/api/files/<file_id>/redact", methods=["POST"])
def redact_file(file_id):
    """Zero-Knowledge Verifiable Redaction route."""
    actor_id = request.form.get("actor_id")
    uploaded = request.files.get("file")
    if not actor_id or not uploaded:
        return jsonify({"error": "actor_id and file are required"}), 400
    priv = _get_private_key(actor_id)
    if priv is None:
        return jsonify({"error": "unknown actor_id — register first"}), 400

    redacted_bytes = uploaded.read()
    redacted_hash = hash_file_bytes(redacted_bytes)

    orig_bytes = None
    for fname in os.listdir(UPLOAD_DIR):
        if fname.startswith(f"{file_id}_") and not fname.startswith(f"{file_id}_latest_") and not fname.startswith(f"{file_id}_redacted_"):
            with open(os.path.join(UPLOAD_DIR, fname), "rb") as f_orig:
                orig_bytes = f_orig.read()
            break

    if not orig_bytes:
        return jsonify({"error": "Original file not found on disk"}), 404

    try:
        from zk_redaction import generate_redaction_proof
        proof_res = generate_redaction_proof(orig_bytes, redacted_bytes, uploaded.filename)
    except Exception as e:
        return jsonify({"error": f"Failed to generate zero-knowledge redaction proof: {str(e)}"}), 422

    conn = get_db()
    prev = conn.execute(
        "SELECT * FROM ledger_records WHERE file_id=? ORDER BY timestamp DESC LIMIT 1",
        (file_id,)
    ).fetchone()
    if prev is None:
        conn.close()
        return jsonify({"error": "file not found in ledger"}), 404

    saved_path = os.path.join(UPLOAD_DIR, f"{file_id}_redacted_{uploaded.filename}")
    with open(saved_path, "wb") as f:
        f.write(redacted_bytes)

    record = create_record(
        file_id=file_id,
        file_content_hash=redacted_hash,
        prev_record_hash=prev["record_hash"],
        action_type="REDACT",
        actor_id=actor_id,
        private_key=priv,
        declared_transformation="Verifiable Zero-Knowledge Redaction",
        file_bytes=redacted_bytes,
        filename=uploaded.filename,
        metadata={
            "redaction_proof": proof_res["proof"],
            "redacted_lines": proof_res["redacted_lines"]
        },
        request_tsa=True
    )
    _insert_record(conn, record)
    conn.commit()
    conn.close()

    return jsonify({
        "success": True,
        "record_hash": record["record_hash"],
        "redacted_lines": proof_res["redacted_lines"],
        "status": "REDACTION_COMMITTED"
    })


@app.route("/api/files/<file_id>/frequency_analysis", methods=["POST"])
def frequency_analysis(file_id):
    """2D-FFT and Block-DCT forensic analysis route. Uses uploaded file or latest file version."""
    uploaded = request.files.get("file")
    file_bytes, filename = _resolve_file_bytes(file_id, uploaded)
    if not file_bytes:
        return jsonify({"error": "No file found for frequency analysis"}), 400

    if not is_image_file(filename, file_bytes):
        return jsonify({"error": "Frequency domain forensics (2D-FFT and Block-DCT) are only applicable to image files."}), 400

    orig_bytes = _resolve_original_bytes(file_id)

    try:
        from frequency_forensics import compute_2d_fft_spectrum, compute_block_dct_splicing
        import base64
        fft_res = compute_2d_fft_spectrum(file_bytes)
        dct_res = compute_block_dct_splicing(file_bytes, original_bytes=orig_bytes)

        fft_b64 = "data:image/png;base64," + base64.b64encode(fft_res["fft_png_bytes"]).decode("ascii")
        dct_b64 = "data:image/png;base64," + base64.b64encode(dct_res["dct_png_bytes"]).decode("ascii")

        eval_hash = hash_file_bytes(file_bytes)
        ref_hash = hash_file_bytes(orig_bytes) if orig_bytes else None
        is_mod = bool(orig_bytes and eval_hash != ref_hash)

        return jsonify({
            "success": True,
            "ai_synthesis_probability": fft_res["ai_synthesis_probability"],
            "is_ai_suspect": fft_res["is_ai_suspect"],
            "fft_summary": fft_res["summary"],
            "splicing_detected": dct_res["splicing_detected"],
            "spliced_regions": dct_res["spliced_regions"],
            "dct_summary": dct_res["summary"],
            "fft_image_data": fft_b64,
            "dct_image_data": dct_b64,
            "evaluated_filename": filename,
            "evaluated_hash": eval_hash,
            "reference_hash": ref_hash,
            "is_modified_from_genesis": is_mod
        })
    except Exception as e:
        return jsonify({"error": f"Frequency analysis failed: {str(e)}"}), 422


@app.route("/api/files/<file_id>/fft", methods=["POST"])
def get_fft_image(file_id):
    uploaded = request.files.get("file")
    file_bytes, filename = _resolve_file_bytes(file_id, uploaded)
    if not file_bytes:
        return jsonify({"error": "file is required"}), 400
    if not is_image_file(filename, file_bytes):
        return jsonify({"error": "2D-FFT frequency forensics are only applicable to image files."}), 400
    try:
        from frequency_forensics import compute_2d_fft_spectrum
        fft_res = compute_2d_fft_spectrum(file_bytes)
        return send_file(io.BytesIO(fft_res["fft_png_bytes"]), mimetype="image/png")
    except Exception as e:
        return jsonify({"error": str(e)}), 422


@app.route("/api/files/<file_id>/dct", methods=["POST"])
def get_dct_image(file_id):
    uploaded = request.files.get("file")
    file_bytes, filename = _resolve_file_bytes(file_id, uploaded)
    if not file_bytes:
        return jsonify({"error": "file is required"}), 400
    if not is_image_file(filename, file_bytes):
        return jsonify({"error": "Block-DCT splicing analysis is only applicable to image files."}), 400
    orig_bytes = _resolve_original_bytes(file_id)
    try:
        from frequency_forensics import compute_block_dct_splicing
        dct_res = compute_block_dct_splicing(file_bytes, original_bytes=orig_bytes)
        return send_file(io.BytesIO(dct_res["dct_png_bytes"]), mimetype="image/png")
    except Exception as e:
        return jsonify({"error": str(e)}), 422


@app.route("/api/files/<file_id>/ela", methods=["POST"])
def ela_analysis(file_id):
    """POST a file to get the ELA heatmap as a PNG image. Defaults to latest/tampered registered file if omitted."""
    uploaded = request.files.get("file")
    file_bytes, filename = _resolve_file_bytes(file_id, uploaded)
    if not file_bytes:
        return jsonify({"error": "file is required"}), 400
    if not is_image_file(filename, file_bytes):
        return jsonify({"error": "Error Level Analysis (ELA) is only applicable to image files."}), 400
    try:
        ela_bytes = compute_ela(file_bytes)
        resp = send_file(
            io.BytesIO(ela_bytes),
            mimetype="image/png",
            as_attachment=False
        )
        resp.headers["X-Evaluated-Filename"] = filename or "image.png"
        resp.headers["X-Evaluated-Hash"] = hash_file_bytes(file_bytes)
        resp.headers["Access-Control-Expose-Headers"] = "X-Evaluated-Filename, X-Evaluated-Hash"
        return resp
    except Exception as e:
        return jsonify({"error": f"ELA failed: {str(e)}"}), 422


@app.route("/api/reset", methods=["POST"])
def reset_system():
    """Clear all database tables, in-memory keys, and uploaded files for a clean redo."""
    conn = get_db()
    conn.execute("DELETE FROM ledger_records")
    conn.execute("DELETE FROM files")
    conn.execute("DELETE FROM users")
    conn.commit()
    conn.close()

    # Clear in-memory demo keys
    PRIVATE_KEYS.clear()

    # Clean uploads directory
    try:
        for f in os.listdir(UPLOAD_DIR):
            fpath = os.path.join(UPLOAD_DIR, f)
            if os.path.isfile(fpath):
                os.remove(fpath)
    except Exception:
        pass

    return jsonify({"success": True, "message": "System reset successfully. All files, records, and custodians cleared."})


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
