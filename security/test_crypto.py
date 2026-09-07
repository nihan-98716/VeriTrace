"""
Standalone test for crypto_engine.py
Run: python test_crypto.py
Expected: all 3 assertions pass + tamper is caught
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from crypto_engine import (
    generate_keypair, pubkey_to_str, pubkey_from_str,
    hash_file_bytes, create_record, verify_chain
)

# ── Setup ──────────────────────────────────────────────────────────────────
priv1, pub1 = generate_keypair()
priv2, pub2 = generate_keypair()

actor1 = "user-alice"
actor2 = "user-bob"

file_bytes_v1 = b"Hello, VERITRACE! This is the original content."
file_bytes_v2 = b"Hello, VERITRACE! This is the MODIFIED content."
file_id = "file-001"

# ── Create 3-hop chain ─────────────────────────────────────────────────────
r1 = create_record(
    file_id=file_id,
    file_content_hash=hash_file_bytes(file_bytes_v1),
    prev_record_hash=None,
    action_type="CREATE",
    actor_id=actor1,
    private_key=priv1,
    metadata={"filename": "document.txt"}
)

r2 = create_record(
    file_id=file_id,
    file_content_hash=hash_file_bytes(file_bytes_v1),
    prev_record_hash=r1["record_hash"],
    action_type="TRANSFER",
    actor_id=actor2,
    private_key=priv2,
)

r3 = create_record(
    file_id=file_id,
    file_content_hash=hash_file_bytes(file_bytes_v2),
    prev_record_hash=r2["record_hash"],
    action_type="MODIFY",
    actor_id=actor2,
    private_key=priv2,
)

records = [r1, r2, r3]
public_keys = {actor1: pub1, actor2: pub2}

# ── Test 1: clean chain verifies ───────────────────────────────────────────
result = verify_chain(records, public_keys, hash_file_bytes(file_bytes_v2))
assert result["valid"] == True, f"Expected VERIFIED, got: {result}"
assert result["status"] == "VERIFIED"
assert result["hops"] == 3
print("[PASS] Test 1: 3-hop chain verifies correctly")

# ── Test 2: tampered hash detected ────────────────────────────────────────
tampered_bytes = b"I secretly changed this."
result2 = verify_chain(records, public_keys, hash_file_bytes(tampered_bytes))
assert result2["valid"] == False
assert result2["status"] == "TAMPERED"
print("[PASS] Test 2: tampered file hash correctly detected as TAMPERED")

# ── Test 3: flipped signature detected ────────────────────────────────────
import copy
records_bad = copy.deepcopy(records)
# Flip the last char of the signature in record 2
bad_sig = records_bad[1]["signature"]
records_bad[1]["signature"] = bad_sig[:-1] + ("0" if bad_sig[-1] != "0" else "1")

result3 = verify_chain(records_bad, public_keys, hash_file_bytes(file_bytes_v2))
assert result3["valid"] == False
assert result3["status"] == "TAMPERED"
print("[PASS] Test 3: flipped signature correctly detected as TAMPERED")

# ── Test 4: empty records returns UNKNOWN_PROVENANCE ──────────────────────
result4 = verify_chain([], public_keys, hash_file_bytes(file_bytes_v1))
assert result4["status"] == "UNKNOWN_PROVENANCE"
print("[PASS] Test 4: empty records returns UNKNOWN_PROVENANCE")

print("\n[ALL TESTS PASSED] crypto_engine.py is solid.")
