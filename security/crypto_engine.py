import os
import hashlib
import json
import time
import base64
import hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric import mldsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

DEFAULT_MASTER_KEY_SEED = b"veritrace_default_master_key_seed_2026_veritrace_system"


def get_server_master_key() -> bytes:
    """
    Retrieves or derives the 256-bit (32-byte) Server Master Key (KEK).
    Reads from environment variable `VERITRACE_MASTER_KEY` if present,
    otherwise falls back to a deterministic 32-byte seed.
    """
    env_key = os.environ.get("VERITRACE_MASTER_KEY")
    if env_key:
        return hashlib.sha256(env_key.encode("utf-8")).digest()
    return hashlib.sha256(DEFAULT_MASTER_KEY_SEED).digest()


def encrypt_private_key_envelope(private_key, user_id: str) -> str:
    """
    Encrypts a private key object (or plaintext key string) using AES-256-GCM 
    and appends a Row-Level HMAC-SHA256 integrity tag bound to user_id.
    """
    if isinstance(private_key, str):
        raw_payload = private_key
    else:
        raw_payload = privkey_to_str(private_key)

    master_key = get_server_master_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(master_key)
    
    ciphertext = aesgcm.encrypt(nonce, raw_payload.encode("utf-8"), None)
    
    enc_b64 = base64.b64encode(ciphertext).decode("ascii")
    nonce_b64 = base64.b64encode(nonce).decode("ascii")
    
    # Compute Row-Level HMAC Integrity tag bound to user_id
    hmac_tag = hmac.new(
        master_key,
        f"{user_id}:{enc_b64}:{nonce_b64}".encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    
    envelope = {
        "v": 1,
        "alg": "AES-256-GCM",
        "ciphertext": enc_b64,
        "nonce": nonce_b64,
        "hmac": hmac_tag
    }
    return json.dumps(envelope)


def decrypt_private_key_envelope(envelope_or_pem_str: str, user_id: str):
    """
    Decrypts an AES-256-GCM envelope JSON string and verifies row HMAC integrity.
    If the string is legacy un-encrypted PEM/JSON, loads it cleanly for backward compatibility.
    """
    if not envelope_or_pem_str:
        return None

    # Check if string is an AES-256-GCM envelope JSON
    try:
        data = json.loads(envelope_or_pem_str)
        if isinstance(data, dict) and data.get("alg") == "AES-256-GCM" and "ciphertext" in data:
            master_key = get_server_master_key()
            enc_b64 = data["ciphertext"]
            nonce_b64 = data["nonce"]
            recorded_hmac = data.get("hmac", "")
            
            # 1. Verify Anti-Tamper HMAC
            calculated_hmac = hmac.new(
                master_key,
                f"{user_id}:{enc_b64}:{nonce_b64}".encode("utf-8"),
                hashlib.sha256
            ).hexdigest()
            
            if not hmac.compare_digest(calculated_hmac, recorded_hmac):
                raise ValueError(f"CRITICAL SECURITY FAILURE: Private key for user '{user_id}' has been tampered with or modified in the database!")
            
            # 2. Decrypt AES-256-GCM Payload
            aesgcm = AESGCM(master_key)
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(enc_b64)
            
            raw_payload_bytes = aesgcm.decrypt(nonce, ciphertext, None)
            raw_payload_str = raw_payload_bytes.decode("utf-8")
            return privkey_from_str(raw_payload_str)
    except (json.JSONDecodeError, TypeError):
        pass

    # Legacy un-encrypted PEM or JSON string fallback
    return privkey_from_str(envelope_or_pem_str)



def generate_keypair(algo="ed25519"):
    """
    Generate keypair for user.
    algo: "ed25519", "mldsa65" (PQC ML-DSA-65), or "hybrid" (both Ed25519 + ML-DSA-65).
    """
    if algo == "mldsa65":
        priv = mldsa.MLDSA65PrivateKey.generate()
        pub = priv.public_key()
        return priv, pub
    elif algo == "hybrid":
        ed_priv = Ed25519PrivateKey.generate()
        ml_priv = mldsa.MLDSA65PrivateKey.generate()
        priv = {"ed25519": ed_priv, "mldsa65": ml_priv}
        pub = {"ed25519": ed_priv.public_key(), "mldsa65": ml_priv.public_key()}
        return priv, pub
    else:
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        return priv, pub


def pubkey_to_str(public_key) -> str:
    """Serializes public key(s) to JSON string or hex string."""
    if isinstance(public_key, dict):
        return json.dumps({k: pubkey_to_str(v) for k, v in public_key.items()})
    elif isinstance(public_key, mldsa.MLDSA65PublicKey):
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return json.dumps({"algo": "mldsa65", "key": raw.hex()})
    elif isinstance(public_key, Ed25519PublicKey):
        raw = public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        return raw.hex()
    return str(public_key)


def pubkey_from_str(pub_str: str):
    """Deserializes public key(s) from string."""
    try:
        data = json.loads(pub_str)
        if isinstance(data, dict):
            if data.get("algo") == "mldsa65":
                return mldsa.MLDSA65PublicKey.from_public_bytes(bytes.fromhex(data["key"]))
            return {k: pubkey_from_str(v) for k, v in data.items()}
    except (json.JSONDecodeError, TypeError):
        pass
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(pub_str))


def privkey_to_str(private_key) -> str:
    """Serializes private key (Ed25519, ML-DSA-65, or hybrid) to PEM string or JSON."""
    if isinstance(private_key, dict):
        return json.dumps({k: privkey_to_str(v) for k, v in private_key.items()})
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode("ascii")


def privkey_from_str(priv_str: str):
    """Deserializes private key from PEM string or JSON."""
    if not priv_str:
        return None
    try:
        data = json.loads(priv_str)
        if isinstance(data, dict):
            return {k: privkey_from_str(v) for k, v in data.items()}
    except (json.JSONDecodeError, TypeError):
        pass
    return serialization.load_pem_private_key(priv_str.encode("ascii"), password=None)


def hash_file_bytes(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def _canonical_bytes(record: dict) -> bytes:
    """Deterministic serialization so signing/verifying agree byte-for-byte."""
    signable = {}
    for k, v in record.items():
        if k in ("record_hash", "signature", "mldsa_signature", "algo", "rfc3161"):
            continue
        if k == "metadata" and isinstance(v, dict):
            v = {mk: mv for mk, mv in v.items() if mk != "rfc3161"}
        signable[k] = v
    return json.dumps(signable, sort_keys=True).encode()


def create_record(file_id, file_content_hash, prev_record_hash, action_type,
                   actor_id, private_key, metadata=None,
                   declared_transformation=None, file_bytes=None, filename=None,
                   request_tsa=False):
    metadata = metadata or {}
    
    # Granular Merkle segment hashing and text preservation if file bytes are provided
    if file_bytes and filename:
        try:
            from document_forensics import compute_document_merkle_tree
            doc_info = compute_document_merkle_tree(file_bytes, filename)
            metadata["merkle_root"] = doc_info["merkle_root"]
            metadata["segments"] = doc_info["segments"]
            
            # For text files, store raw content in genesis record to support semantic diffing
            ext = filename.lower().split('.')[-1] if '.' in filename else ''
            if ext in ('txt', 'md', 'py', 'csv', 'json', 'html', 'css', 'log', ''):
                metadata["raw_text"] = file_bytes.decode("utf-8", errors="ignore")
        except Exception:
            pass

    record = {
        "file_id": file_id,
        "file_content_hash": file_content_hash,
        "prev_record_hash": prev_record_hash,     # None for the first record
        "action_type": action_type,               # CREATE | MODIFY | TRANSFER | REDACT
        "actor_id": actor_id,
        "declared_transformation": declared_transformation,
        "timestamp": time.time(),
        "metadata": metadata,
    }
    signable = _canonical_bytes(record)
    
    if isinstance(private_key, dict):
        ed_sig = private_key["ed25519"].sign(signable)
        ml_sig = private_key["mldsa65"].sign(signable)
        record["signature"] = ed_sig.hex()
        record["mldsa_signature"] = ml_sig.hex()
    elif isinstance(private_key, mldsa.MLDSA65PrivateKey):
        ml_sig = private_key.sign(signable)
        record["signature"] = ml_sig.hex()
        record["algo"] = "mldsa65"
    else:
        ed_sig = private_key.sign(signable)
        record["signature"] = ed_sig.hex()

    record["record_hash"] = hashlib.sha256(signable).hexdigest()
    
    # Optional RFC 3161 TSA external notarization
    if request_tsa:
        try:
            from tsa_client import request_timestamp_token
            tsa_meta = request_timestamp_token(record["record_hash"])
            if tsa_meta.get("success"):
                record["rfc3161"] = tsa_meta
                record["metadata"]["rfc3161"] = tsa_meta
        except Exception:
            pass
            
    return record


def verify_record_signature(record: dict, public_key) -> bool:
    signable = _canonical_bytes(record)
    try:
        if isinstance(public_key, dict):
            # Hybrid mode: verify BOTH Ed25519 and ML-DSA-65
            if "signature" not in record or "mldsa_signature" not in record:
                return False
            public_key["ed25519"].verify(bytes.fromhex(record["signature"]), signable)
            public_key["mldsa65"].verify(bytes.fromhex(record["mldsa_signature"]), signable)
            return True
        elif isinstance(public_key, mldsa.MLDSA65PublicKey):
            public_key.verify(bytes.fromhex(record["signature"]), signable)
            return True
        elif isinstance(public_key, Ed25519PublicKey):
            public_key.verify(bytes.fromhex(record["signature"]), signable)
            return True
    except InvalidSignature:
        return False
    return False


def verify_chain(records: list, public_keys: dict, current_file_hash: str,
                  revoked_at_map: dict = None, current_file_bytes: bytes = None,
                  filename: str = None, original_file_bytes: bytes = None) -> dict:
    """
    records            : list of ledger record dicts, ORDERED oldest -> newest
    public_keys        : {actor_id: Ed25519PublicKey / Hybrid}
    current_file_hash  : SHA-256 hex of the file AS RECEIVED right now
    revoked_at_map     : optional {actor_id: revoked_at_float_or_None}
    current_file_bytes : bytes of candidate file for Merkle/ZK/Semantic checks
    original_file_bytes: optional original file bytes for semantic diff
    """
    if not records:
        return {"valid": False, "reason": "no custody history found",
                "status": "UNKNOWN_PROVENANCE"}

    prev_hash = None
    for i, r in enumerate(records):
        # Pillar 2: verify hash-chain linkage
        if r["prev_record_hash"] != prev_hash:
            return {
                "valid": False, "broken_at": i, "actor_id": r["actor_id"],
                "reason": (
                    f"prev_record_hash mismatch at hop {i} — chain link broken "
                    f"or record was tampered"
                ),
                "status": "TAMPERED"
            }

        # Verify signer identity is in the public-key registry
        pubkey = public_keys.get(r["actor_id"])
        if pubkey is None:
            return {
                "valid": False, "broken_at": i, "actor_id": r["actor_id"],
                "reason": f"unknown signer at hop {i}: actor_id={r['actor_id']}",
                "status": "TAMPERED"
            }

        # Key revocation: reject records signed after the actor's key was revoked
        if revoked_at_map is not None:
            revoked_at = revoked_at_map.get(r["actor_id"])
            if revoked_at is not None and r["timestamp"] > revoked_at:
                return {
                    "valid": False, "broken_at": i, "actor_id": r["actor_id"],
                    "reason": (
                        f"hop {i}: record was signed after actor key was revoked "
                        f"(key revoked at epoch {revoked_at:.0f}, "
                        f"record timestamp epoch {r['timestamp']:.0f})"
                    ),
                    "status": "TAMPERED"
                }

        # Pillar 1+2: Digital signature verification (Ed25519 / ML-DSA-65 / Hybrid)
        if not verify_record_signature(r, pubkey):
            return {
                "valid": False, "broken_at": i, "actor_id": r["actor_id"],
                "reason": f"invalid digital signature at hop {i}",
                "status": "TAMPERED"
            }

        # Pillar 2b: In a TRANSFER action, the file content must NOT be modified
        if r.get("action_type") == "TRANSFER" and i > 0:
            prev_content = records[i - 1]["file_content_hash"]
            if r["file_content_hash"] != prev_content:
                return {
                    "valid": False, "broken_at": i, "actor_id": r["actor_id"],
                    "reason": f"unauthorized file content alteration during TRANSFER at hop {i} (content changed without declared MODIFY)",
                    "expected_hash": prev_content,
                    "current_hash": r["file_content_hash"],
                    "status": "TAMPERED"
                }

        # Validate RFC 3161 TSA external certified timestamp if present
        rfc_info = r.get("rfc3161") or (isinstance(r.get("metadata"), dict) and r["metadata"].get("rfc3161"))
        if rfc_info and rfc_info.get("tst_token_b64"):
            try:
                from tsa_client import verify_timestamp_token
                tst_res = verify_timestamp_token(rfc_info["tst_token_b64"], r["record_hash"])
                if tst_res.get("valid"):
                    r["tsa_certified_utc"] = tst_res.get("certified_utc")
                    r["tsa_certified_ist"] = tst_res.get("certified_ist")
                    r["tsa_cert_info"] = tst_res.get("cert_info")
                    r["tsa_serial"] = tst_res.get("serial_number")
                    r["tsa_policy"] = tst_res.get("tsa_policy")
                    r["tsa_verified"] = True
            except Exception:
                pass
        elif rfc_info and (rfc_info.get("certified_utc") or rfc_info.get("certified_ist")):
            r["tsa_certified_utc"] = rfc_info.get("certified_utc")
            r["tsa_certified_ist"] = rfc_info.get("certified_ist")
            r["tsa_cert_info"] = rfc_info.get("cert_info")
            r["tsa_serial"] = rfc_info.get("token_serial")
            r["tsa_policy"] = rfc_info.get("tsa_policy")

        prev_hash = r["record_hash"]

    latest = records[-1]
    meta = latest.get("metadata") or {}

    # Feature 2: Zero-Knowledge Verifiable Redaction Check
    if (latest.get("action_type") == "REDACT" or "redaction_proof" in meta) and current_file_bytes:
        try:
            from zk_redaction import verify_redaction_proof
            proof_dict = meta.get("redaction_proof")
            if proof_dict:
                orig_root = records[0].get("metadata", {}).get("merkle_root") or proof_dict.get("orig_root")
                redact_res = verify_redaction_proof(proof_dict, current_file_bytes, orig_root)
                if redact_res.get("valid"):
                    return {
                        "valid": True,
                        "status": "VERIFIED_REDACTED",
                        "hops": len(records),
                        "message": redact_res.get("message"),
                        "redacted_segments": redact_res.get("redacted_segments")
                    }
        except Exception:
            pass

    # Determine if file is an image or non-text binary
    is_img = False
    if filename:
        ext = os.path.splitext(filename)[1].lower()
        if ext in (".png", ".jpg", ".jpeg", ".webp", ".bmp", ".gif", ".tiff", ".tif", ".ico"):
            is_img = True
    if not is_img and current_file_bytes:
        if (current_file_bytes.startswith(b"\x89PNG") or
            current_file_bytes.startswith(b"\xff\xd8\xff") or
            (current_file_bytes.startswith(b"RIFF") and b"WEBP" in current_file_bytes[:16]) or
            current_file_bytes.startswith(b"BM") or
            current_file_bytes.startswith(b"GIF8")):
            is_img = True

    # Pillar 3: current file must match the last recorded content state
    if latest["file_content_hash"] != current_file_hash:
        # Find if the submitted file matches an EARLIER hop (e.g. stale version, rollback attack)
        matched_earlier_hop = None
        for idx in range(len(records) - 2, -1, -1):
            if records[idx]["file_content_hash"] == current_file_hash:
                matched_earlier_hop = idx
                break

        # Check where the content was supposed to advance past the submitted file
        if matched_earlier_hop is not None:
            broken_hop_idx = matched_earlier_hop + 1
            tamper_type = "HISTORICAL_ROLLBACK"
            reason_msg = (
                f"Stale / Historical version: current file matches historical state at hop #{matched_earlier_hop + 1} ({records[matched_earlier_hop]['action_type']}), "
                f"but lacks the authorized update at hop #{broken_hop_idx + 1} ({records[broken_hop_idx]['action_type']})"
            )
            broken_actor = records[broken_hop_idx]["actor_id"]
            expected_h = records[broken_hop_idx]["file_content_hash"]
        else:
            broken_hop_idx = len(records) - 1
            tamper_type = "EXTERNAL_MODIFICATION"
            broken_actor = latest["actor_id"]
            expected_h = latest["file_content_hash"]
            reason_msg = (
                f"Current file hash does not match ledger state at final custody hop #{len(records)} ({latest['action_type']}) — "
                f"silent external modification detected outside the verified chain of custody"
            )

        # Segment and Semantic NLP analysis (strictly disabled for image files)
        tampered_segments = []
        semantic_assessment = None
        if not is_img:
            # Look for segments in latest or genesis metadata
            base_segments = meta.get("segments") or records[0].get("metadata", {}).get("segments")
            if isinstance(base_segments, dict) and current_file_bytes and filename:
                try:
                    from document_forensics import analyze_tampered_segments
                    tampered_segments = analyze_tampered_segments(base_segments, current_file_bytes, filename)
                except Exception:
                    pass

            # Semantic NLP Tamper Assessment
            if current_file_bytes and filename:
                try:
                    from semantic_assessor import assess_document_tampering
                    orig_b = original_file_bytes
                    if not orig_b:
                        raw_text = records[0].get("metadata", {}).get("raw_text")
                        if raw_text:
                            orig_b = raw_text.encode("utf-8")
                    if orig_b:
                        semantic_assessment = assess_document_tampering(orig_b, current_file_bytes, filename)
                except Exception:
                    pass

        if tampered_segments:
            reason_msg += f" (Altered parts: {', '.join(tampered_segments)})"

        return {
            "valid": False,
            "broken_at": broken_hop_idx,
            "actor_id": broken_actor,
            "tamper_type": tamper_type,
            "reason": reason_msg,
            "tampered_segments": tampered_segments,
            "semantic_assessment": semantic_assessment,
            "expected_hash": expected_h,
            "current_hash": current_file_hash,
            "status": "TAMPERED"
        }

    # For VERIFIED chains, assess semantic impact if document was modified from genesis original
    sem_eval = None
    if not is_img and current_file_bytes and original_file_bytes and (current_file_bytes != original_file_bytes):
        try:
            from semantic_assessor import assess_document_tampering
            sem_eval = assess_document_tampering(original_file_bytes, current_file_bytes, filename)
        except Exception:
            pass

    return {
        "valid": True,
        "status": "VERIFIED",
        "hops": len(records),
        "semantic_assessment": sem_eval
    }
