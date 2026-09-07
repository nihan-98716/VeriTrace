"""
VeriTrace Live Demonstration Script: test.txt vs tamper.txt
Run: python demo_tamper_check.py
"""
import sys
import os

SECURITY_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "security"))
if SECURITY_DIR not in sys.path:
    sys.path.insert(0, SECURITY_DIR)

from crypto_engine import (
    generate_keypair, pubkey_to_str, hash_file_bytes,
    create_record, verify_chain
)

print("=" * 65)
print("     VERITRACE LIVE TAMPER DETECT & SEGMENT LOCALIZATION DEMO")
print("=" * 65)

# Step 1: Read both files
test_path = os.path.join(os.path.dirname(__file__), "test.txt")
tamper_path = os.path.join(os.path.dirname(__file__), "tamper.txt")

with open(test_path, "rb") as f:
    test_bytes = f.read()

with open(tamper_path, "rb") as f:
    tamper_bytes = f.read()

# Step 2: Register user (Alice) and generate Hybrid PQC keys
actor_id = "user-alice"
priv_key, pub_key = generate_keypair(algo="hybrid")
public_keys = {actor_id: pub_key}

# Step 3: Register original file (test.txt) in the chain of custody
file_id = "doc-test-101"
test_hash = hash_file_bytes(test_bytes)

print(f"\n[1] Registering Original File: 'test.txt'")
print(f"    File Hash (SHA-256): {test_hash}")
print(f"    Signer / Custodian : {actor_id} (Ed25519 + ML-DSA-65 Hybrid PQC Signed)")

r1 = create_record(
    file_id=file_id,
    file_content_hash=test_hash,
    prev_record_hash=None,
    action_type="CREATE",
    actor_id=actor_id,
    private_key=priv_key,
    file_bytes=test_bytes,
    filename="test.txt"
)

records = [r1]

print("\n" + "-" * 65)
# Step 4: Verify the original file (test.txt)
print("[2] VERIFYING ORIGINAL FILE ('test.txt'):")
res_orig = verify_chain(
    records,
    public_keys,
    test_hash,
    current_file_bytes=test_bytes,
    filename="test.txt"
)

print(f"    Status: {res_orig['status']}")
print(f"    Valid : {res_orig['valid']}")
if res_orig['valid']:
    print("    [SUCCESS] File integrity is 100% authentic.")

print("\n" + "-" * 65)
# Step 5: Verify the tampered file (tamper.txt) against the registered chain
tamper_hash = hash_file_bytes(tamper_bytes)
print("[3] VERIFYING TAMPERED FILE ('tamper.txt') AGAINST REGISTERED CHAIN:")
print(f"    Current File Hash: {tamper_hash}")

res_tamper = verify_chain(
    records,
    public_keys,
    tamper_hash,
    current_file_bytes=tamper_bytes,
    filename="tamper.txt"
)

print(f"    Status: {res_tamper['status']}")
print(f"    Valid : {res_tamper['valid']}")
if "reason" in res_tamper:
    print(f"    Reason: {res_tamper['reason']}")

if "tampered_segments" in res_tamper and res_tamper["tampered_segments"]:
    print("\n    GRANULAR ALTERATION LOCALIZATION:")
    for segment in res_tamper["tampered_segments"]:
        print(f"       [ALTERED] Segment Identified: {segment}")

print("=" * 65)
