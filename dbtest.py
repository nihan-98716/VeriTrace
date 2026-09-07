import sqlite3
import os
from security.crypto_engine import decrypt_private_key_envelope

db_path = "db/veritrace.db"

print("=== DATABASE RECORD INSPECTION ===")

if not os.path.exists(db_path):
    print("DB file empty or not yet created. Register a key first!")
else:
    conn = sqlite3.connect(db_path)

    query = """
        SELECT user_id, encrypted_private_key, key_hmac
        FROM users
    """

    for user_id, encrypted_key, hmac_tag in conn.execute(query):
        print(f"User ID: {user_id}")
        print("Raw Encrypted Key stored in DB:")
        print(f"  {encrypted_key[:50]}... (AES-256-GCM Envelope)")

        if hmac_tag:
            print("HMAC Tag stored in DB:")
            print(f"  {hmac_tag[:30]}...")

        print("-----------------------------------------------")

        # Decrypt envelope (crypto_engine handles json envelope or (encrypted_key, hmac_tag))
        try:
            if hmac_tag:
                decrypted_key = decrypt_private_key_envelope(encrypted_key, hmac_tag, user_id)
            else:
                decrypted_key = decrypt_private_key_envelope(encrypted_key, user_id)
            
            key_repr = str(decrypted_key)
            print("Decrypted Private Key (In-Memory Only):")
            print(f"  {key_repr[:60]}...")
        except Exception as e:
            print(f"Decryption failed: {e}")

        print()

    conn.close()