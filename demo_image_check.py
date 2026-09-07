"""
VeriTrace Image Forensics: original.jpeg vs tampered.jpeg
Computes SHA-256 Hashes, Cryptographic Verification, and Error Level Analysis (ELA) Heatmaps.
Run: python demo_image_check.py
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
from ela import compute_ela

print("=" * 65)
print("     VERITRACE IMAGE FORENSICS & ELA HEATMAP DEMO")
print("=" * 65)

orig_path = os.path.join(os.path.dirname(__file__), "original.jpeg")
tamp_path = os.path.join(os.path.dirname(__file__), "tampered.jpeg")

if not os.path.exists(orig_path) or not os.path.exists(tamp_path):
    print("Error: original.jpeg or tampered.jpeg not found.")
    sys.exit(1)

with open(orig_path, "rb") as f:
    orig_bytes = f.read()

with open(tamp_path, "rb") as f:
    tamp_bytes = f.read()

# 1. SHA-256 Hash Comparison
orig_hash = hash_file_bytes(orig_bytes)
tamp_hash = hash_file_bytes(tamp_bytes)

print(f"\n[1] SHA-256 FINGERPRINTS:")
print(f"    original.jpeg : {orig_hash}")
print(f"    tampered.jpeg : {tamp_hash}")

# 2. Register original.jpeg in Chain of Custody
actor_id = "forensic-investigator"
priv_key, pub_key = generate_keypair(algo="hybrid")

r1 = create_record(
    file_id="img-001",
    file_content_hash=orig_hash,
    prev_record_hash=None,
    action_type="CREATE",
    actor_id=actor_id,
    private_key=priv_key,
    file_bytes=orig_bytes,
    filename="original.jpeg"
)

records = [r1]
public_keys = {actor_id: pub_key}

print("\n" + "-" * 65)
print("[2] CRYPTOGRAPHIC VERIFICATION OF original.jpeg:")
res_orig = verify_chain(records, public_keys, orig_hash, current_file_bytes=orig_bytes, filename="original.jpeg")
print(f"    Status: {res_orig['status']}")
print(f"    Valid : {res_orig['valid']}")

print("\n" + "-" * 65)
print("[3] CRYPTOGRAPHIC VERIFICATION OF tampered.jpeg AGAINST CHAIN:")
res_tamp = verify_chain(records, public_keys, tamp_hash, current_file_bytes=tamp_bytes, filename="tampered.jpeg")
print(f"    Status: {res_tamp['status']}")
print(f"    Valid : {res_tamp['valid']}")
if "reason" in res_tamp:
    print(f"    Reason: {res_tamp['reason']}")

if "tampered_segments" in res_tamp and res_tamp["tampered_segments"]:
    print("\n    GRANULAR ALTERATION LOCALIZATION:")
    for segment in res_tamp["tampered_segments"]:
        print(f"       [ALTERED] Segment Identified: {segment}")

# 3. Compute ELA Heatmaps
print("\n" + "-" * 65)
print("[4] GENERATING FORENSIC ELA HEATMAPS...")

try:
    ela_orig = compute_ela(orig_bytes)
    ela_tamp = compute_ela(tamp_bytes)

    ela_orig_path = os.path.join(os.path.dirname(__file__), "ela_original_heatmap.png")
    ela_tamp_path = os.path.join(os.path.dirname(__file__), "ela_tampered_heatmap.png")

    with open(ela_orig_path, "wb") as f:
        f.write(ela_orig)

    with open(ela_tamp_path, "wb") as f:
        f.write(ela_tamp)

    print(f"    Saved Original ELA Heatmap: {ela_orig_path}")
    print(f"    Saved Tampered ELA Heatmap: {ela_tamp_path}")
    print("    [NOTE] Bright regions in the tampered heatmap indicate re-compressed or edited pixel areas.")
except Exception as e:
    print(f"    ELA Analysis Failed: {e}")

print("=" * 65)
