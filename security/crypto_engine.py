import hashlib
import json
import time
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature


def generate_keypair():
    """Call once per user at registration. Store public key in DB,
    give the private key back to the 'user' (for demo: keep server-side
    in a dict keyed by user_id)."""
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def pubkey_to_str(public_key: Ed25519PublicKey) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return raw.hex()


def pubkey_from_str(hex_str: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_str))


def hash_file_bytes(file_bytes: bytes) -> str:
    return hashlib.sha256(file_bytes).hexdigest()


def _canonical_bytes(record: dict) -> bytes:
    """Deterministic serialization so signing/verifying agree byte-for-byte."""
    signable = {k: v for k, v in record.items()
                if k not in ("record_hash", "signature")}
    return json.dumps(signable, sort_keys=True).encode()


def create_record(file_id, file_content_hash, prev_record_hash, action_type,
                   actor_id, private_key, metadata=None,
                   declared_transformation=None):
    record = {
        "file_id": file_id,
        "file_content_hash": file_content_hash,
        "prev_record_hash": prev_record_hash,     # None for the first record
        "action_type": action_type,               # CREATE | MODIFY | TRANSFER
        "actor_id": actor_id,
        "declared_transformation": declared_transformation,
        "timestamp": time.time(),
        "metadata": metadata or {},
    }
    signable = _canonical_bytes(record)
    signature = private_key.sign(signable)
    record["record_hash"] = hashlib.sha256(signable).hexdigest()
    record["signature"] = signature.hex()
    return record


def verify_record_signature(record: dict, public_key: Ed25519PublicKey) -> bool:
    signable = _canonical_bytes(record)
    try:
        public_key.verify(bytes.fromhex(record["signature"]), signable)
        return True
    except InvalidSignature:
        return False


def verify_chain(records: list, public_keys: dict, current_file_hash: str,
                  revoked_at_map: dict = None) -> dict:
    """
    records          : list of ledger record dicts, ORDERED oldest -> newest
    public_keys      : {actor_id: Ed25519PublicKey}
    current_file_hash: SHA-256 hex of the file AS RECEIVED right now
    revoked_at_map   : optional {actor_id: revoked_at_float_or_None}
                       Used to reject records signed after a key was revoked.
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

        # Pillar 1+2: Ed25519 signature verification
        if not verify_record_signature(r, pubkey):
            return {
                "valid": False, "broken_at": i, "actor_id": r["actor_id"],
                "reason": f"invalid Ed25519 signature at hop {i}",
                "status": "TAMPERED"
            }

        prev_hash = r["record_hash"]

    # Pillar 3: current file must match the last recorded content state
    latest = records[-1]
    if latest["file_content_hash"] != current_file_hash:
        return {
            "valid": False,
            "broken_at": len(records) - 1,
            "actor_id": latest["actor_id"],
            "reason": (
                "current file hash does not match the last recorded hash — "
                "silent modification outside the custody platform detected"
            ),
            "expected_hash": latest["file_content_hash"],
            "current_hash": current_file_hash,
            "status": "TAMPERED"
        }

    return {"valid": True, "status": "VERIFIED", "hops": len(records)}
